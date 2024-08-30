#ifndef MIMESIS_SRC_LIBS_NET_HPP
#define MIMESIS_SRC_LIBS_NET_HPP

#include <string>
#include <unordered_map>
#include <vector>

#include <pcapplusplus/PcapLiveDevice.h>

/**
 * @brief Open all existing interfaces, except for loopback and SIT devices.
 *
 * @param tap_only If true, open only interfaces whose name starts with "tap".
 * @return Opened interfaces.
 */
std::vector<pcpp::PcapLiveDevice *> open_interfaces(bool tap_only = false);

/**
 * @brief Open the interface with name `if_name` as a raw socket and return the
 * socket fd.
 *
 * @param if_name Name of the interface to open as a raw socket.
 * @return The socket fd of the opened interface, or -1 if the function fails.
 */
int open_intf_fd(const std::string &if_name);

/**
 * @brief Open all existing interfaces as raw sockets, except for loopback and
 * SIT devices.
 *
 * @param tap_only If true, open only interfaces whose name starts with "tap".
 * @return Raw socket fds of the opened interfaces.
 */
std::vector<int> open_intf_fds(bool tap_only = false);

/**
 * @brief Open all existing interfaces, except for loopback and SIT devices.
 *
 * @param tap_only If true, open only interfaces whose name starts with "tap".
 * @return Opened interfaces indexed by their names.
 */
std::unordered_map<std::string, pcpp::PcapLiveDevice *>
open_interfaces_as_map(bool tap_only = false);

/**
 * @brief Close the given interfaces.
 */
void close_interfaces(const std::vector<pcpp::PcapLiveDevice *> &interfaces);

/**
 * @brief Close the given interfaces.
 */
void close_intf_fds(const std::vector<int> &intf_fds);

#endif // MIMESIS_SRC_LIBS_NET_HPP
