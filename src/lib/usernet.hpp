#ifndef MIMESIS_SRC_LIBS_USERNET_HPP
#define MIMESIS_SRC_LIBS_USERNET_HPP

#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Receives a packet frame by the NF from the interface.
 */
void user_recv(uint32_t *intf, void *buffer, uint32_t len);

/**
 * Sends a packet frame by the NF to the interface.
 */
void user_send(uint32_t intf, void *buffer, uint32_t len);

/**
 * @brief Count the existing interfaces on the system, except for loopback and
 * SIT devices.
 *
 * @param tap_only If true, count only the interfaces whose name starts with
 * "tap".
 * @return The number of interfaces.
 */
size_t num_interfaces(bool tap_only = false);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // MIMESIS_SRC_LIBS_USERNET_HPP
