/**
 * Demo Router: Stateful forwarding
 *
 * The egress port of an incoming packet is directly determined by the `port`
 * header field of the packet.
 * Packets of type 0 are always allowed. Packets of type 1 are only allowed if
 * another type-0 packet has egressed through the same port.
 */

#include <cstdint>
#include <cstring>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "lib/logger.hpp"
#include "lib/net.hpp"

struct DemoHeader {
    uint8_t port; // egress port
    uint8_t type; // packet type. 0: init, 1: follow-up
};

struct Headers {
    struct ethhdr *eth;
    struct DemoHeader *demo;
};

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
    hdrs.demo = (struct DemoHeader *)(buffer + sizeof(struct ethhdr));
    auto ethertype = ntohs(hdrs.eth->h_proto);
    if (ethertype != 0xdead) {
        warn("Ethertype does not match 0xdead (57005)");
        return false;
    }
    return true;
}

int main() {
    std::vector<int> intf_fds = open_intf_fds();
    if (intf_fds.empty()) {
        error("No interfaces available");
    }
    info("Total interfaces: " + std::to_string(intf_fds.size()));

    Headers hdrs;
    uint8_t buffer[ETH_FRAME_LEN];
    std::vector<bool> port_to_type0_map(intf_fds.size(), false);

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
        info("Received a demo packet from fd " + std::to_string(intf_fds[0]));

        if (!validate_and_populate_headers(hdrs, buffer, len)) {
            warn("Drop ill-formed packet");
            continue;
        }

        // Use the demo header to determine the egress port.
        // Since it's only 1 byte, no need to convert endianness.
        if (hdrs.demo->port >= intf_fds.size()) {
            warn("Drop packet destined to non-existent port");
            continue;
        }

        // Response
        if (hdrs.demo->type == 0) {
            // Type-0 packets are always allowed.
            // Mark the egress port as initialized.
            port_to_type0_map.at(hdrs.demo->port) = true;
        } else if (hdrs.demo->type == 1) {
            // Type-1 packets are only allowed if the egress port has been
            // initialized.
            if (!port_to_type0_map.at(hdrs.demo->port)) {
                // Port not initialized with a type-0 packet yet.
                continue;
            }
        } else {
            warn("Unknown packet type. Ignore the packet.");
            continue;
        }

        info("Sending out the packet");
        write(intf_fds[hdrs.demo->port], buffer, len);
    }

    close_intf_fds(intf_fds);
    return 0;
}
