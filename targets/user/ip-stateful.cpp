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

#include "lib/logger.hpp"
#include "lib/usernet.hpp"

using namespace std;

struct Packet {
    struct ethhdr eth;
    struct iphdr ip;
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

int main() {
    uint32_t max_intfs = num_interfaces();
    uint8_t intf = 0;
    Packet ingress_pkt;
    memset(&ingress_pkt, 0, sizeof(ingress_pkt));
    info("Total interfaces: " + std::to_string(max_intfs));
    if (max_intfs < 4) {
        error("Total number of interfaces < 4");
    }

    // State variable
    bool seen_a_pkt_to_10_8 = false;

    while (1) {
        user_recv(&intf, &ingress_pkt, sizeof(ingress_pkt));

        // Stateful rule
        if (!seen_a_pkt_to_10_8) {
            // Filter out the packet if the src IP falls within 10/8
            uint32_t lb = (10ul << 24);
            uint32_t mask = 8;
            if (ingress_pkt.ip.saddr >= lb &&
                ingress_pkt.ip.saddr < lb + (1ul << (32 - mask))) {
                continue;
            }
        }

        int eg_intf = dst_ip_matching(ingress_pkt.ip.daddr);
        if (eg_intf == -1) {
            continue;
        } else if (eg_intf == 0) {
            seen_a_pkt_to_10_8 = true;
        }

        memset(ingress_pkt.eth.h_source, 0, ETH_ALEN);
        ingress_pkt.eth.h_source[ETH_ALEN - 1] = eg_intf;
        user_send(eg_intf, &ingress_pkt, sizeof(ingress_pkt));
    }

    info("Bye");
    return 0;
}
