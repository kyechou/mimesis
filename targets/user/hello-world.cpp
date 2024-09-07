/**
 * Hello, world. (Echo Server)
 *
 * This echos whatever packets received back to the interface they came from.
 */

#include <cstdint>
#include <cstring>
#include <linux/if_ether.h>
#include <netinet/ip.h>

#include "lib/logger.hpp"
#include "lib/usernet.hpp"

struct Headers {
    struct ethhdr eth;
    struct iphdr ip;
};

int main() {
    uint8_t intf = 0;
    Headers buffer;
    memset(&buffer, 0, sizeof(buffer));

    while (1) {
        user_recv(&intf, &buffer, sizeof(buffer));
        info("Hello, world. Echoing back a received packet");
        user_send(intf, &buffer, sizeof(buffer));
    }

    return 0;
}
