#include "usernet.hpp"

#include <cstring>
#include <net/if.h>
#include <string>

#include "lib/logger.hpp"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void user_recv(uint32_t *interface, void *buffer, uint32_t len) {
    *interface = 0;
    memset(buffer, 0, len);
    info("NF receiving a packet from " + std::to_string(*interface));
}

void user_send(uint32_t interface, void *buffer, uint32_t len) {
    memset(buffer, 0, len);
    info("NF sending a packet to " + std::to_string(interface));
}

size_t num_interfaces(bool tap_only) {
    size_t count = 0;
    struct if_nameindex *intfs = if_nameindex();

    if (!intfs) {
        error("if_nameindex()", errno);
    }

    for (auto intf = intfs; intf->if_index != 0 || intf->if_name != nullptr;
         ++intf) {
        std::string if_name{intf->if_name};
        if (if_name.starts_with("lo") || if_name.starts_with("sit")) {
            continue;
        }
        if (tap_only && !if_name.starts_with("tap")) {
            continue;
        }
        ++count;
    }

    if_freenameindex(intfs);
    return count;
}

#ifdef __cplusplus
}
#endif // __cplusplus
