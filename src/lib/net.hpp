#ifndef MIMESIS_SRC_LIBS_NET_HPP
#define MIMESIS_SRC_LIBS_NET_HPP

#include <linux/if_ether.h>
#include <string>
#include <vector>

struct Interface {
    int fd;
    std::string if_name;
    unsigned char hw_addr[ETH_ALEN];
};

/**
 * @brief Bind an fd to the given existing interface.
 *
 * @param if_name Name of the interface to be opened.
 * @param if_index Interface index of `if_name`. If it's not provided, it will
 *                 be automatically derived from `if_name`.
 * @return The file descriptor bound to the device.
 */
Interface open_interface(const std::string &if_name, unsigned int if_index = 0);

/**
 * @brief Open a file descriptor for each existing interface, except for
 * loopback and SIT devices.
 *
 * @param tap_only True to open only interfaces whose name starts with "tap".
 * @return A map of file descriptors to the corresponding interface names.
 */
std::vector<Interface> open_existing_interfaces(bool tap_only = false);

/**
 * @brief Close the given interface file descriptors.
 */
void close_interface_fds(const std::vector<Interface> &interfaces);

#endif // MIMESIS_SRC_LIBS_NET_HPP
