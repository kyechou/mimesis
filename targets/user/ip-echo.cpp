/**
 * Stateless IP Echo
 *
 * Echo back the incoming packet and reverse the L2 and L3 addresses.
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

        memcpy(&egress_pkt, &ingress_pkt, sizeof(ingress_pkt));
        memcpy(egress_pkt.eth.h_dest, ingress_pkt.eth.h_source, ETH_ALEN);
        memcpy(egress_pkt.eth.h_source, ingress_pkt.eth.h_dest, ETH_ALEN);
        egress_pkt.ip.saddr = ingress_pkt.ip.daddr;
        egress_pkt.ip.daddr = ingress_pkt.ip.saddr;
        user_send(intf, &egress_pkt, sizeof(egress_pkt));
    }

    info("Bye");
    return 0;
}
