/**
 * Demo Router: Stateful forwarding (with PcapPlusPlus)
 *
 * The egress port of an incoming packet is directly determined by the `port`
 * header field of the packet.
 * Packets of type 0 are always allowed. Packets of type 1 are only allowed if
 * another type-0 packet has egressed through the same port.
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
    uint8_t type; // packet type. 0: init, 1: follow-up
};

struct UserData {
    std::vector<pcpp::PcapLiveDevice *> *intfs;
    bool seen_pkt;
};

/**
 * Validate the given packet. Returns true if the packet is okay, false
 * otherwise.
 */
static inline bool validate_packet(const pcpp::Packet &packet) {
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
    if (eth_payload_len < sizeof(DemoHeader)) {
        warn("Ethernet payload len < DemoHeader size");
        return false;
    }
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

    if (!(data->seen_pkt)) {
        data->seen_pkt = true;
    }

    if (!validate_packet(packet)) {
        warn("Drop ill-formed packet");
        return false; // continue capturing.
    }

    // Read the demo header
    DemoHeader demo;
    memcpy(&demo, packet.getFirstLayer()->getLayerPayload(), sizeof(demo));
    demo.port = pcpp::netToHost16(demo.port);

    // Derive the output port.
    uint16_t out_port = demo.port;
    if (out_port >= intfs.size()) {
        warn("Drop packet destined to non-existent port");
        return false; // continue capturing.
    }

    // Response
    info("Forward packet to the specified egress port");
    if (!intfs.at(out_port)->sendPacket(*raw_packet, /*checkMtu=*/false)) {
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
        .seen_pkt = false,
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
