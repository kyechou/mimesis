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

struct DemoHeader {
    uint8_t version;
    uint8_t port; // egress port
};

struct Packet {
    struct DemoHeader demo; // simplified demo protocol
};

int main() {
    uint32_t max_intfs = num_interfaces();
    uint32_t intf = 0;
    Packet ingress_pkt;
    memset(&ingress_pkt, 0, sizeof(ingress_pkt));
    info("Total interfaces: " + std::to_string(max_intfs));

    while (1) {
        user_recv(&intf, &ingress_pkt, sizeof(ingress_pkt));

        if (intf >= max_intfs) {
            continue; // drop the incoming packet
        }

        if (ingress_pkt.demo.version != 3) {
            continue;
        }

        uint16_t egress = ingress_pkt.demo.port; // all output in network order
        user_send(egress, &ingress_pkt, sizeof(ingress_pkt));
    }

    info("Bye");
    return 0;
}
