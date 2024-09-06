/**
 * Hello, world. (Echo Server)
 *
 * This echos whatever packets received back to the interface they came from.
 */

#include <cstdint>
#include <cstring>
#include <linux/if_ether.h>

#include "lib/logger.hpp"
#include "lib/usernet.hpp"

int main() {
    uint8_t intf = 0;
    uint8_t buffer[ETH_FRAME_LEN];
    memset(buffer, 0, sizeof(buffer));

    while (1) {
        user_recv(&intf, buffer, sizeof(buffer));
        info("Hello, world. Echoing back a received packet");
        user_send(intf, buffer, sizeof(buffer));
    }

    return 0;
}
