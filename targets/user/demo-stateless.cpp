/**
 * Demo Router: Stateless forwarding
 *
 * The egress port of an incoming packet is directly determined by the `port`
 * header field of the packet.
 */

#include <cstdint>
#include <cstring>
#include <linux/if_ether.h>
#include <string>

#include "lib/logger.hpp"
#include "lib/usernet.hpp"

using namespace std;

struct Packet {
    uint8_t port; // egress port
};

int main() {
    uint8_t max_intfs = num_interfaces();
    uint8_t intf = 0;
    Packet ingress_pkt;
    memset(&ingress_pkt, 0, sizeof(ingress_pkt));
    info("Total interfaces: " + std::to_string(max_intfs));

    while (1) {
        user_recv(&intf, &ingress_pkt, sizeof(ingress_pkt));

        if (ingress_pkt.port >= max_intfs) {
            continue;
        }

        uint8_t egress = ingress_pkt.port; // all output in network order
        user_send(egress, &ingress_pkt, sizeof(ingress_pkt));
    }

    info("Bye");
    return 0;
}
