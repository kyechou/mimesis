/**
 * Demo Router: Stateless forwarding (with PcapPlusPlus)
 *
 * The egress port of an incoming packet is directly determined by the `port`
 * header field of the packet.
 */

#include <cstdint>
#include <linux/if_ether.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/ProtocolType.h>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/SystemUtils.h>
#include <vector>

#include "lib/logger.hpp"
#include "lib/net.hpp"

struct UserData {
    std::vector<pcpp::PcapLiveDevice *> *intfs;
};

int dst_ip_matching(uint32_t dst_addr) {
    // TODO: Do we need a htonl conversion for the IP address?

    // 10.1.2.0/24 -> intf 0
    uint32_t lb = (10ul << 24) + (1ul << 16) + (2ul << 8);
    uint32_t mask = 24;
    if (dst_addr >= lb && dst_addr < lb + (1ul << (32 - mask))) {
        return 0;
    }

    // 10.1.0.0/16 -> intf 1
    lb = (10ul << 24) + (1ul << 16);
    mask = 16;
    if (dst_addr >= lb && dst_addr < lb + (1ul << (32 - mask))) {
        return 1;
    }

    // 10.2.0.0/16 -> intf 2
    lb = (10ul << 24) + (2ul << 16);
    mask = 16;
    if (dst_addr >= lb && dst_addr < lb + (1ul << (32 - mask))) {
        return 2;
    }

    // 10.0.0.0/8  -> intf 3
    lb = (10ul << 24);
    mask = 8;
    if (dst_addr >= lb && dst_addr < lb + (1ul << (32 - mask))) {
        return 3;
    }

    return -1;
}

/**
 * Validate the given packet. Returns true if the packet is okay, false
 * otherwise.
 */
static inline bool validate_and_populate_headers(const pcpp::Packet &packet) {
    if (packet.getFirstLayer()->getProtocol() != pcpp::Ethernet) {
        warn("The first protocol is not Ethernet");
        return false;
    }
    auto eth_layer = static_cast<pcpp::EthLayer *>(packet.getFirstLayer());
    auto ethertype = pcpp::netToHost16(eth_layer->getEthHeader()->etherType);
    if (ethertype != 0x0800) {
        warn("Ethertype does not match 0x0800 (IPv4)");
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
	
	pcpp::IPv4Address dstIP = packet.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();
    if (!validate_and_populate_headers(packet)) {
        warn("Drop ill-formed packet");
        return false; // continue capturing.
    }
    
    int eg_intf = dst_ip_matching(dstIP.toInt());
    if (eg_intf == -1) {
    	return false;
    }

    // Response
    info("Sending out the packet");
    if (!intfs.at(eg_intf)->sendPacket(*raw_packet, /*checkMtu=*/false)) {
        error("Failed to send packet");
    }

    return false; // Don't stop capturing.
}

int main() {
    std::vector<pcpp::PcapLiveDevice *> intfs = open_interfaces();
    if (intfs.empty()) {
        error("No interfaces available");
    }
    
    if (intfs.size() < 4) {
    	error("Total number of interfaces < 4");
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
