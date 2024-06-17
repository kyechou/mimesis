/**
 * Demo Router 1: Stateless forwarding
 *
 * The egress port of an incoming packet is directly determined by the `seed`
 * header field of the packet.
 */

#include <cstdint>
#include <cstring>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <string>

#include "lib/logger.hpp"
#include "lib/usernet.hpp"

using namespace std;

struct DemoHeader {
    uint16_t seed; // egress port
    uint16_t len;  // payload length
};

struct Packet {
    struct ethhdr eth;
    DemoHeader demo; // simplified demo L3 protocol
    char payload[64];
};

int main() {
    uint32_t max_intfs = num_interfaces();
    uint32_t intf = 0;
    Packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    while (1) {
        user_recv(&intf, &pkt, sizeof(pkt));

        if (intf >= max_intfs) {
            error("Invalid ingress interface: " + std::to_string(intf));
        }

        uint16_t egress = ntohs(pkt.demo.seed);
        user_send(egress, &pkt, sizeof(pkt));
    }

    info("Bye");
    return 0;
}
