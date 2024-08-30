/**
 * demo-stateless
 *
 * The egress port of an incoming packet is directly determined by the `seed`
 * header field of the packet.
 */

#include <cstdint>
#include <fcntl.h> // read
#include <iostream>
#include <linux/if_tun.h> // TUNSETIFF
#include <net/if.h>       // struct ifreq
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h> // ioctl
#include <sys/stat.h>  // read
#include <unistd.h>
#include <vector>

#define PAYLOAD_LEN 128u

struct Header {
    uint8_t seed; // egress port
    uint16_t len;
};

struct Packet {
    Header hdr;
    char payload[PAYLOAD_LEN];
};

static inline void close_tapfds(std::vector<int> &tapfds) {
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
    	
    	// I am just setting the default num_intfs to 8, need to check if this is fine
    	
    	num_intfs=8;
    
        // std::cerr << "Usage: " << argv[0] << " <num_intfs>" << std::endl;
        // return -1;
    }
    else
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
            close_tapfds(tapfds);
            return -1;
        }
        std::string ifname = "demo-stateless" + std::to_string(i);
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
        strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
        if (ioctl(tapfds[i], TUNSETIFF, &ifr) < 0) {
            std::cerr << "ioctl() failed" << std::endl;
            close_tapfds(tapfds);
            return -1;
        }
    }

    Packet pkt;
    // Whether a type-0 packet has been seen at a given egress port.
    std::vector<bool> port_to_type0_map(num_intfs, false);
    while (1) {
        // Read from the first interface
        ssize_t nread = read(tapfds[0], &pkt, sizeof(pkt));
        if (nread < 0) {
            std::cerr << "Failed to read from tapfds[0]" << std::endl;
            close_tapfds(tapfds);
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
        std::cout << "Sending packet out" << std::endl;
        write(tapfds[out_port], &pkt, nread);
    }

    close_tapfds(tapfds);
    return 0;
}
