/**
 * Stateless L2 forwarding
 *
 * Forward (echo) packets based on the L2 destination addresses.
 * Interface 0 -- 00:00:00:00:00:00
 * Interface 1 -- 00:00:00:00:00:01
 * Interface 2 -- 00:00:00:00:00:02
 *          ...
 * Interface N -- 00:00:00:00:00:0N
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

int main() {
    uint32_t max_intfs = num_interfaces();
    uint32_t intf = 0;
    Packet ingress_pkt, egress_pkt;
    memset(&ingress_pkt, 0, sizeof(ingress_pkt));
    info("Total interfaces: " + std::to_string(max_intfs));

    while (1) {
        user_recv(&intf, &ingress_pkt, sizeof(ingress_pkt));

        if (intf >= max_intfs) {
            continue;
        }

        unsigned char *dst_eth = ingress_pkt.eth.h_dest;
        uint32_t lower_32_bits_dst_eth =
            (static_cast<uint32_t>(dst_eth[2]) << 24) +
            (static_cast<uint32_t>(dst_eth[3]) << 16) +
            (static_cast<uint32_t>(dst_eth[4]) << 8) +
            (static_cast<uint32_t>(dst_eth[5]));

        if (lower_32_bits_dst_eth >= max_intfs) {
            continue;
        }

        memcpy(&egress_pkt, &ingress_pkt, sizeof(ingress_pkt));
        memcpy(egress_pkt.eth.h_dest, ingress_pkt.eth.h_source, ETH_ALEN);
        memcpy(egress_pkt.eth.h_source, ingress_pkt.eth.h_dest, ETH_ALEN);
        user_send(lower_32_bits_dst_eth, &egress_pkt, sizeof(egress_pkt));
    }

    info("Bye");
    return 0;
}
