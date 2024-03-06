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

int open_existing_interface(const string &if_name) {
    // We support IP packets for now (ETH_P_IP). It is possible to change it to
    // `ETH_P_ALL` for sending/receiving all raw packets. Remember to make it
    // consistent with the `sockaddr_ll` structure below for `bind()`.
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        error("socket()", errno);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name.c_str(), IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
        close(sock);
        error(if_name, errno);
    }

    struct sockaddr_ll saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = ifr.ifr_ifindex;
    saddr.sll_pkttype = PACKET_HOST;

    if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        close(sock);
        error("bind()", errno);
    }

    return sock;
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
        int fd = open_existing_interface(if_name);
        interfaces.push_back({fd, if_name});
    }

    if_freenameindex(intfs);
    return interfaces;
}

void close_interface_fds(const vector<Interface> &interfaces) {
    for (const auto &[fd, if_name] : interfaces) {
        close(fd);
    }
}
