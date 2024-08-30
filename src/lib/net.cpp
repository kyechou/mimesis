#include "lib/net.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>

#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/PcapLiveDeviceList.h>

#include "lib/logger.hpp"

using namespace std;

vector<pcpp::PcapLiveDevice *> open_interfaces(bool tap_only) {
    vector<pcpp::PcapLiveDevice *> res;
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

        pcpp::PcapLiveDevice *dev =
            pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(
                if_name);
        if (!dev) {
            error("Failed to get interface: " + if_name);
        }
        if (!dev->open()) {
            close_interfaces(res);
            error("Failed to open interface: " + if_name);
        }
        res.push_back(dev);
    }

    if_freenameindex(intfs);
    return res;
}

int open_intf_fd(const std::string &if_name) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        warn("socket() failed");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name.c_str(), IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
        close(sock);
        warn("ioctl(): failed to get the ifindex");
        return -1;
    }

    struct sockaddr_ll saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = ifr.ifr_ifindex;
    saddr.sll_pkttype = PACKET_HOST;

    if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        close(sock);
        warn("bind() failed");
        return -1;
    }

    return sock;
}

std::vector<int> open_intf_fds(bool tap_only) {
    std::vector<int> res;
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

        int fd = open_intf_fd(if_name);
        if (fd == -1) {
            close_intf_fds(res);
            error("Failed to open interface: " + if_name, errno);
        }
        res.push_back(fd);
    }

    if_freenameindex(intfs);
    return res;
}

unordered_map<string, pcpp::PcapLiveDevice *>
open_interfaces_as_map(bool tap_only) {
    unordered_map<string, pcpp::PcapLiveDevice *> res;
    auto interfaces = open_interfaces(tap_only);
    for (auto interface : interfaces) {
        res.insert({interface->getName(), interface});
    }
    return res;
}

void close_interfaces(const vector<pcpp::PcapLiveDevice *> &interfaces) {
    for (auto &dev : interfaces) {
        if (dev) {
            dev->close();
        }
    }
}

void close_intf_fds(const std::vector<int> &intf_fds) {
    for (int fd : intf_fds) {
        if (fd >= 0) {
            close(fd);
        }
    }
}
