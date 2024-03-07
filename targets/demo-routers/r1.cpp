/**
 * Demo Router 1: Stateless forwarding
 *
 * The egress port of an incoming packet is directly determined by the `seed`
 * header field of the packet.
 */

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <unistd.h>
#include <vector>

#include "lib/logger.hpp"
#include "lib/net.hpp"

using namespace std;

struct Header {
    uint16_t seed; // egress port
    uint16_t len;  // payload length
};

#define PAYLOAD_LEN 128u

struct Packet {
    Header hdr;
    char payload[PAYLOAD_LEN];
};

string to_string(const Packet &pkt) {
    stringstream ss;
    ss << "[Packet] seed: " << pkt.hdr.seed << ", len: " << pkt.hdr.len;
    return ss.str();
}

int main() {
    vector<Interface> interfaces = open_existing_interfaces();
    if (interfaces.empty()) {
        error("No interfaces available");
    }

    Packet pkt;
    int first_intf_fd = interfaces.at(0).fd;

    while (1) {
        // Read from the first interface
        info("Reading a packet from " + interfaces.at(0).if_name);
        ssize_t nread = read(first_intf_fd, &pkt, sizeof(pkt));
        if (nread < 0) {
            close_interface_fds(interfaces);
            error("Failed to read from " + interfaces.at(0).if_name, errno);
        }
        info("Read " + to_string(nread) + " bytes - " + to_string(pkt));

        // Validate packet
        info("Validating packet");
        if (static_cast<unsigned long>(nread) < sizeof(Header) ||
            static_cast<unsigned long>(nread) != sizeof(Header) + pkt.hdr.len) {
            warn("Drop ill-formed packet");
            continue;
        }

        uint16_t out_port = pkt.hdr.seed;
        if (out_port >= interfaces.size()) {
            warn("Drop packet to non-existent port");
            continue;
        }

        // Response
        info("Forward packet to egress port " + to_string(out_port));
        write(interfaces[out_port].fd, &pkt, nread);
    }

    info("Bye");
    close_interface_fds(interfaces);
    return 0;
}
