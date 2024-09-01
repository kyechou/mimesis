/**
 * Demo Router: Stateless forwarding
 *
 * The egress port of an incoming packet is determined by the `ip.daddr`
 * header field of the packet.
 * Packets of type 0 are always allowed. Packets of type 1 are only allowed if
 * another type-0 packet has egressed through the same port.
 */

#include <cstdint>
#include <cstring>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <string>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "lib/logger.hpp"
#include "lib/net.hpp"

struct DemoHeader {
    uint8_t type; // packet type. 0: init, 1: follow-up
};

struct Headers {
    struct ethhdr eth;
    struct iphdr ip;
    struct DemoHeader demo;
};

int dst_ip_matching(uint32_t dst_addr) {
    // TODO: Do we need a htonl conversion for the IP address?

    // 10.1.2.0/24 -> intf 0
    uint32_t lb = (10ul << 24) + (1ul << 16) + (2ul << 8);
    uint32_t mask = 24;
    if (dst_addr >= lb && dst_addr < lb + (1ul << (32 - mask))) {
        return 0;
    }

    // 10.1.0.0/16 -> intf 1
    lb = (10ul << 24) + (1ul << 16);
    mask = 16;
    if (dst_addr >= lb && dst_addr < lb + (1ul << (32 - mask))) {
        return 1;
    }

    // 10.2.0.0/16 -> intf 2
    lb = (10ul << 24) + (2ul << 16);
    mask = 16;
    if (dst_addr >= lb && dst_addr < lb + (1ul << (32 - mask))) {
        return 2;
    }

    // 10.0.0.0/8  -> intf 3
    lb = (10ul << 24);
    mask = 8;
    if (dst_addr >= lb && dst_addr < lb + (1ul << (32 - mask))) {
        return 3;
    }

    return -1;
}

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
    memcpy(&hdrs, buffer, sizeof(hdrs));
    auto ethertype = ntohs(hdrs.eth.h_proto);
    if (ethertype != 0x0800) {
        warn("Ethertype does not match 0x0800 (IPv4)");
        return false;
    }
    return true;
}

int main() {
    std::vector<int> intf_fds = open_intf_fds();
    if (intf_fds.empty()) {
        error("No interfaces available");
    }

    Headers hdrs;
    uint8_t buffer[ETH_FRAME_LEN];
    std::vector<bool> port_to_type0_map(intf_fds.size(), false);
    
    if (intf_fds.size() < 4) {
    	error("Total number of interfaces < 4");
    }

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

        // Response
        
        int eg_intf = dst_ip_matching(hdrs.ip.daddr);
        if (eg_intf == -1) {
        	continue;
        }
        
        if (hdrs.demo.type == 0){
        	port_to_type0_map.at(eg_intf) = true;
        } else if( hdrs.demo.type == 1) {
        	if(!port_to_type0_map.at(eg_intf)){
        		continue;
        	}
        } else {
        	std::cerr << "Unknown packet type " << hdrs.demo.type << std::endl;
            continue;
        }
        
        info("Sending out the packet");
        write(intf_fds[eg_intf], buffer, len);
    }

    close_intf_fds(intf_fds);
    return 0;
}
