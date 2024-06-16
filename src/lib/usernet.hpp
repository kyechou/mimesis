#ifndef MIMESIS_SRC_LIBS_USERNET_HPP
#define MIMESIS_SRC_LIBS_USERNET_HPP

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Receives a packet frame by the NF from the interface.
 */
void user_recv(uint32_t *interface, void *buffer, uint32_t len);

/**
 * Sends a packet frame by the NF to the interface.
 */
void user_send(uint32_t interface, void *buffer, uint32_t len);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // MIMESIS_SRC_LIBS_USERNET_HPP
