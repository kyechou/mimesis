/**
 * Demo Router 1
 *
 * This implements simple stateless forwarding. The egress port is directly
 * determined by the `seed` header field from the input packet.
 */

#include <cstdint>
#include <fcntl.h> // read
#include <iostream>
#include <linux/if_tun.h> // TUNSETIFF
#include <net/if.h>       // struct ifreq
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/ioctl.h> // ioctl
#include <unistd.h>
#include <vector>

#define PAYLOAD_LEN 200

struct Header {
    uint16_t seed; // egress port
    uint16_t len;  // payload length
};

struct Packet {
    Header hdr;
    char payload[PAYLOAD_LEN];
};

static inline void cleanup_tapfds(std::vector<int> &tapfds) {
    for (int &fd : tapfds) {
        if (fd > 0) {
            close(fd);
            fd = 0;
        }
    }
}

int main(int argc, char **argv) {
    int num_intfs = 0;
    constexpr int max_intfs = 128;

    // Set the number of interfaces.
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <num_intfs>" << std::endl;
        return -1;
    }
    num_intfs = atoi(argv[1]);
    if (num_intfs < 1 || num_intfs > max_intfs) {
        std::cerr << "The number of interfaces should be in [1.." << max_intfs
                  << "]" << std::endl;
        return -1;
    }

    // Create tap interfaces.
    std::vector<int> tapfds(num_intfs);
    struct ifreq ifr;

    for (int i = 0; i < num_intfs; ++i) {
        if ((tapfds[i] = open("/dev/net/tun", O_RDWR)) < 0) {
            std::cerr << "Failed to open /dev/net/tun" << std::endl;
            cleanup_tapfds(tapfds);
            return -1;
        }
        std::string ifname = "demo-r1-eth" + std::to_string(i);
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
        strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
        if (ioctl(tapfds[i], TUNSETIFF, &ifr) < 0) {
            std::cerr << "ioctl() failed" << std::endl;
            cleanup_tapfds(tapfds);
            return -1;
        }
    }

    Packet pkt;

    while (1) {
        // Read from the first interface
        ssize_t nread = read(tapfds[0], &pkt, sizeof(pkt));
        if (nread < 0) {
            std::cerr << "Failed to read from tapfds[0]" << std::endl;
            cleanup_tapfds(tapfds);
            return -1;
        }

        // Validate packet
        if (static_cast<unsigned long>(nread) < sizeof(Header) ||
            static_cast<unsigned long>(nread) != sizeof(Header) + pkt.hdr.len) {
            std::cerr << "Drop ill-formed packet" << std::endl;
            continue;
        }

        uint16_t out_port = pkt.hdr.seed;
        if (out_port >= num_intfs) {
            std::cerr << "Drop packet to non-existent port" << std::endl;
            continue;
        }

        // Response
        write(tapfds[out_port], &pkt, nread);
    }

    cleanup_tapfds(tapfds);
    return 0;
}
