#include "usernet.hpp"

#include "lib/logger.hpp"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void user_recv(uint32_t *interface [[maybe_unused]],
               void *buffer [[maybe_unused]],
               uint32_t len [[maybe_unused]]) {
    *interface = 0;
    info("Userspace NF receiving a packet frame");
}

void user_send(uint32_t interface [[maybe_unused]],
               void *buffer [[maybe_unused]],
               uint32_t len [[maybe_unused]]) {
    info("Userspace NF sending a packet frame");
}

#ifdef __cplusplus
}
#endif // __cplusplus
