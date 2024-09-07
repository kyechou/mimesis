/**
 * Stateless IP forwarding
 *
 * Forward packets based on destination IP addresses.
 *  - dstIP 10.1.2.0/24 -> intf 0 (src_mac 00:00:00:00:00:00)
 *  - dstIP 10.1.0.0/16 -> intf 1 (src_mac 00:00:00:00:00:01)
 *  - dstIP 10.2.0.0/16 -> intf 2 (src_mac 00:00:00:00:00:02)
 *  - dstIP 10.0.0.0/8  -> intf 3 (src_mac 00:00:00:00:00:03)
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
    info("Total interfaces: " + std::to_string(intf_fds.size()));

    Headers hdrs;
    uint8_t buffer[ETH_FRAME_LEN];

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

        // Static forwarding based on IP destination addresses.
        int eg_intf = dst_ip_matching(hdrs.ip->daddr);
        if (eg_intf == -1) {
            continue;
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
