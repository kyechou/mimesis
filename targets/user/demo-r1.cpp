/**
 * Demo Router 1: Stateless forwarding
 *
 * The egress port of an incoming packet is directly determined by the `seed`
 * header field of the packet.
 */

#include <cstdint>
#include <netinet/in.h>
#include <string>

#include "lib/logger.hpp"
#include "lib/usernet.hpp"

using namespace std;

struct DemoHeader {
    uint16_t seed; // egress port
    uint16_t len;  // payload length
};

int main(int argc, char **argv) {
    if (argc != 2) {
        error("Invalid number of arguments.");
    }

    uint32_t max_intfs = stoul(argv[1]);
    uint32_t interface;
    DemoHeader pkt = {.seed = 0, .len = 0};

    while (1) {
        user_recv(&interface, &pkt, sizeof(pkt));

        if (interface >= max_intfs) {
            error("Invalid interface upon reception: " +
                  std::to_string(interface));
        }

        uint16_t egress = ntohs(pkt.seed);
        user_send(egress, &pkt, sizeof(pkt));
    }

    info("Bye");
    return 0;
}
