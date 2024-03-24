#include "lib/net.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <string>
#include <sys/ioctl.h>
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
        dev->close();
    }
}
