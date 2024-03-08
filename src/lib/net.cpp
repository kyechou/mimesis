#include "lib/net.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <string>
#include <sys/ioctl.h>
#include <unistd.h>

#include "lib/logger.hpp"

using namespace std;

Interface open_interface(const string &if_name, unsigned int if_index) {
    Interface intf;
    struct ifreq ifr;

    // We support all raw packets for now (ETH_P_ALL). It is possible to change
    // it to `ETH_P_IP` for sending/receiving only IP packets. Remember to make
    // it consistent with the `sockaddr_ll` structure below for `bind()`.
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        error("socket()", errno);
    }

    // Get the interface index if it's not provided.
    if (if_index == 0) {
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, if_name.c_str(), IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
            close(sock);
            error("Failed to get the interface index of " + if_name, errno);
        }
        if_index = ifr.ifr_ifindex;
    }

    // Get the Ethernet address of the interface.
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name.c_str(), IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
        close(sock);
        error("Failed to get the mac address of " + if_name, errno);
    }
    memcpy(intf.hw_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    // Bind the socket fd to the interface.
    struct sockaddr_ll saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = if_index;
    saddr.sll_pkttype = PACKET_HOST;
    if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        close(sock);
        error("bind()", errno);
    }

    intf.fd = sock;
    intf.if_name = if_name;
    return intf;
}

vector<Interface> open_existing_interfaces(bool tap_only) {
    vector<Interface> interfaces;
    struct if_nameindex *intfs = if_nameindex();
    if (!intfs) {
        error("if_nameindex()", errno);
    }

    for (auto intf = intfs; intf->if_index != 0 || intf->if_name != nullptr;
         ++intf) {
        string if_name{intf->if_name};
        if (if_name.starts_with("lo") || if_name.starts_with("sit")) {
            continue;
        }
        if (tap_only && !if_name.starts_with("tap")) {
            continue;
        }
        interfaces.push_back(open_interface(if_name, intf->if_index));
    }

    if_freenameindex(intfs);
    return interfaces;
}

void close_interface_fds(const vector<Interface> &interfaces) {
    for (const auto &[fd, if_name, hw_addr] : interfaces) {
        close(fd);
    }
}
