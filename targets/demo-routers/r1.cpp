/**
 * Demo Router 1: Stateless forwarding
 *
 * The egress port of an incoming packet is directly determined by the `seed`
 * header field of the packet.
 */

#include <arpa/inet.h>
#include <cstdint>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string>
#include <sys/ioctl.h>
#include <unistd.h>
#include <vector>

#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/ProtocolType.h>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/SystemUtils.h>

#include "lib/logger.hpp"
#include "lib/net.hpp"

using namespace std;

struct DemoHeader {
    uint16_t seed; // egress port
    uint16_t len;  // payload length
};

struct UserData {
    vector<pcpp::PcapLiveDevice *> *intfs;
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
        warn("Ethertype does not match 0xdead (57005): " +
             to_string(ethertype));
        return false;
    }
    auto eth_payload_len = eth_layer->getLayerPayloadSize();
    if (eth_payload_len < sizeof(DemoHeader)) {
        warn("Ethernet payload len: " + to_string(eth_payload_len) +
             " < DemoHeader size: " + to_string(sizeof(DemoHeader)));
        return false;
    }
    return true;
}

bool onPacketArrivesBlocking(pcpp::RawPacket *raw_packet,
                             pcpp::PcapLiveDevice *dev,
                             void *user_data) {
    // Populate the user data.
    auto data = static_cast<UserData *>(user_data);
    const vector<pcpp::PcapLiveDevice *> &intfs = *data->intfs;

    // Parse the received packet.
    pcpp::Packet packet(raw_packet);
    info("----------------------------------------");
    info("Read " + to_string(raw_packet->getRawDataLen()) + " bytes from " +
         dev->getName());

    if (!validate_packet(packet)) {
        warn("Drop ill-formed packet");
        return false; // continue capturing.
    }

    // Read the demo header
    DemoHeader demo;
    memcpy(&demo, packet.getFirstLayer()->getLayerPayload(), sizeof(demo));
    demo.seed = pcpp::netToHost16(demo.seed);
    demo.len = pcpp::netToHost16(demo.len);
    info("Demo:: seed: " + to_string(demo.seed) +
         ", len: " + to_string(demo.len));

    // Derive the output port.
    uint16_t out_port = demo.seed;
    if (out_port >= intfs.size()) {
        warn("Drop packet destined to non-existent port");
        return false; // continue capturing.
    }

    // Response
    info("Forward packet to egress port " + to_string(out_port) + ": " +
         intfs.at(out_port)->getName());
    if (!intfs.at(out_port)->sendPacket(*raw_packet,
                                        /*checkMtu=*/false)) {
        error("Failed to send packet");
    }

    return false; // Don't stop capturing.
}

int main() {
    vector<pcpp::PcapLiveDevice *> intfs = open_interfaces();
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
