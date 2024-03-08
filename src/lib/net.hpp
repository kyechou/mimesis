#ifndef MIMESIS_SRC_LIBS_NET_HPP
#define MIMESIS_SRC_LIBS_NET_HPP

#include <vector>

#include <PcapLiveDevice.h>

/**
 * @brief Open all existing interfaces, except for loopback and SIT devices.
 *
 * @param tap_only If true, open only interfaces whose name starts with "tap".
 * @return Opened interfaces.
 */
std::vector<pcpp::PcapLiveDevice *> open_interfaces(bool tap_only = false);

/**
 * @brief Close the given interfaces.
 */
void close_interfaces(const std::vector<pcpp::PcapLiveDevice *> &interfaces);

#endif // MIMESIS_SRC_LIBS_NET_HPP
