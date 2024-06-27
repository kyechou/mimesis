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

#include "lib/logger.hpp"
#include "lib/usernet.hpp"

using namespace std;

struct Packet {
    struct ethhdr eth;
    struct iphdr ip;
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

int main() {
    uint32_t max_intfs = num_interfaces();
    uint8_t intf = 0;
    Packet ingress_pkt;
    memset(&ingress_pkt, 0, sizeof(ingress_pkt));
    info("Total interfaces: " + std::to_string(max_intfs));
    if (max_intfs < 4) {
        error("Total number of interfaces < 4");
    }

    while (1) {
        user_recv(&intf, &ingress_pkt, sizeof(ingress_pkt));

        if (intf >= max_intfs) {
            continue;
        }

        int eg_intf = dst_ip_matching(ingress_pkt.ip.daddr);
        if (eg_intf == -1) {
            continue;
        }

        memset(ingress_pkt.eth.h_source, 0, ETH_ALEN);
        ingress_pkt.eth.h_source[ETH_ALEN - 1] = eg_intf;
        user_send(eg_intf, &ingress_pkt, sizeof(ingress_pkt));
    }

    info("Bye");
    return 0;
}
