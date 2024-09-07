/**
 * Demo Router: Stateless forwarding (with PcapPlusPlus)
 *
 * The egress port of an incoming packet is directly determined by the `port`
 * header field of the packet.
 */

#include <cstdint>
#include <linux/if_ether.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/ProtocolType.h>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/SystemUtils.h>
#include <vector>

#include "lib/logger.hpp"
#include "lib/net.hpp"

struct DemoHeader {
    uint8_t port; // egress port
    uint8_t type; // packet type. This has no effect on stateless forwarding.
};

struct UserData {
    std::vector<pcpp::PcapLiveDevice *> *intfs;
};

/**
 * Validate the given packet. Returns true if the packet is okay, false
 * otherwise.
 */
static inline bool validate_and_populate_headers(DemoHeader &demo,
                                                 const pcpp::Packet &packet) {
    if (packet.getFirstLayer()->getProtocol() != pcpp::Ethernet) {
        warn("The first protocol is not Ethernet");
        return false;
    }
    auto eth_layer = static_cast<pcpp::EthLayer *>(packet.getFirstLayer());
    auto ethertype = pcpp::netToHost16(eth_layer->getEthHeader()->etherType);
    if (ethertype != 0xdead) {
        warn("Ethertype does not match 0xdead (57005)");
        return false;
    }
    auto eth_payload_len = eth_layer->getLayerPayloadSize();
    if (eth_payload_len < sizeof(demo)) {
        warn("The Ethernet payload is too short.");
        return false;
    }
    memcpy(&demo, eth_layer->getLayerPayload(), sizeof(demo));
    return true;
}

bool onPacketArrivesBlocking(pcpp::RawPacket *raw_packet,
                             pcpp::PcapLiveDevice *dev,
                             void *user_data) {
    // Populate the user data.
    auto data = static_cast<UserData *>(user_data);
    const std::vector<pcpp::PcapLiveDevice *> &intfs = *data->intfs;

    // Parse the received packet.
    pcpp::Packet packet(raw_packet);
    info("----------------------------------------");
    info("Received a demo packet from " + dev->getName());

    DemoHeader demo;
    if (!validate_and_populate_headers(demo, packet)) {
        warn("Drop ill-formed packet");
        return false; // continue capturing.
    }

    // Use the demo header to determine the egress port.
    // Since it's only 1 byte, no need to convert endianness.
    if (demo.port >= intfs.size()) {
        warn("Drop packet destined to non-existent port");
        return false; // continue capturing.
    }

    // Response
    info("Sending out the packet");
    if (!intfs.at(demo.port)->sendPacket(*raw_packet, /*checkMtu=*/false)) {
        error("Failed to send packet");
    }

    return false; // Don't stop capturing.
}

int main() {
    std::vector<pcpp::PcapLiveDevice *> intfs = open_interfaces();
    if (intfs.empty()) {
        error("No interfaces available");
    }

    UserData user_data{
        .intfs = &intfs,
    };

    // Read from the first interface
    pcpp::PcapLiveDevice *dev = intfs.at(0); // receiving device
    info("Reading packets from " + dev->getName());
    dev->startCaptureBlockingMode(onPacketArrivesBlocking,
                                  /*userCookie=*/&user_data, /*timeout=*/0);

    info("Bye");
    close_interfaces(intfs);
    return 0;
}
