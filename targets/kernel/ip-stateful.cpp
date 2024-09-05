/**
 * Stateful IP forwarding
 *
 * Initial rules
 *  - srcIP 10.0.0.0/8, dstIP *  -> drop
 *  - srcIP *, dstIP 10.0.0.0/8  -> intf 0 (src_mac 00:00:00:00:00:00)
 *  - srcIP *, dstIP 11.0.0.0/8  -> intf 1 (src_mac 00:00:00:00:00:01)
 *  - (otherwise) -> drop
 *
 * Once a packet is forwarded to intf 0, the rules is updated as
 *  - srcIP *, dstIP 10.0.0.0/8  -> intf 0 (src_mac 00:00:00:00:00:00)
 *  - srcIP *, dstIP 11.0.0.0/8  -> intf 1 (src_mac 00:00:00:00:00:01)
 *  - (otherwise) -> drop
 */

#include <cstdint>
#include <cstring>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "lib/logger.hpp"
#include "lib/net.hpp"

struct Headers {
    struct ethhdr *eth;
    struct iphdr *ip;
};

int dst_ip_matching(uint32_t dst_addr) {
    // TODO: Do we need a htonl conversion for the IP address?

    // 10.0.0.0/8 -> intf 0
    uint32_t lb = (10ul << 24);
    uint32_t mask = 8;
    if (dst_addr >= lb && dst_addr < lb + (1ul << (32 - mask))) {
        return 0;
    }

    // 11.0.0.0/8 -> intf 1
    lb = (11ul << 24);
    mask = 8;
    if (dst_addr >= lb && dst_addr < lb + (1ul << (32 - mask))) {
        return 1;
    }

    return -1;
}

/**
 * Returns true if the packet is okay, false otherwise.
 */
static inline bool validate_and_populate_headers(Headers &hdrs,
                                                 const uint8_t *const buffer,
                                                 const ssize_t len) {
    if (static_cast<unsigned long>(len) < sizeof(hdrs)) {
        warn("The received packet buffer is too short.");
        return false;
    }
    hdrs.eth = (struct ethhdr *)buffer;
    hdrs.ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    auto ethertype = ntohs(hdrs.eth->h_proto);
    if (ethertype != 0x0800) {
        warn("Ethertype does not match 0x0800 (IPv4)");
        return false;
    }
    return true;
}

int main() {
    std::vector<int> intf_fds = open_intf_fds();
    if (intf_fds.empty()) {
        error("No interfaces available");
    } else if (intf_fds.size() < 4) {
        error("Total number of interfaces < 4");
    }

    Headers hdrs;
    uint8_t buffer[ETH_FRAME_LEN];
    bool seen_a_pkt_to_10_8 = false; // State variable

    while (1) {
        // Read from the first interface
        ssize_t len = read(intf_fds[0], buffer, sizeof(buffer));
        if (len < 0) {
            close_intf_fds(intf_fds);
            error("Failed to receive packets");
        } else if (len == 0) {
            break; // EOF. Connection terminated. (socket closed)
        }

        info("----------------------------------------");
        info("Received a packet from fd " + std::to_string(intf_fds[0]));

        if (!validate_and_populate_headers(hdrs, buffer, len)) {
            warn("Drop ill-formed packet");
            continue;
        }

        // Stateful rule
        if (!seen_a_pkt_to_10_8) {
            // Filter out the packet if the src IP falls within 10/8
            uint32_t lb = (10ul << 24);
            uint32_t mask = 8;
            if (hdrs.ip->saddr >= lb &&
                hdrs.ip->saddr < lb + (1ul << (32 - mask))) {
                continue;
            }
        }

        int eg_intf = dst_ip_matching(hdrs.ip->daddr);
        if (eg_intf == -1) {
            continue;
        } else if (eg_intf == 0) {
            seen_a_pkt_to_10_8 = true;
        }

        memset(hdrs.eth->h_source, 0, ETH_ALEN);
        hdrs.eth->h_source[ETH_ALEN - 1] = eg_intf;

        // Response
        info("Sending out the packet");
        write(intf_fds[eg_intf], buffer, len);
    }

    close_intf_fds(intf_fds);
    return 0;
}
