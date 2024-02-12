#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>   // read
#include <fcntl.h>      // read

#define __USE_MISC
#include <net/if.h>     // struct ifreq
#include <sys/ioctl.h>  // ioctl
#include <linux/if_tun.h> // TUNSETIFF
#undef __USE_MISC

#include "protocol.h"

static inline void cleanup_tapfds(int numintfs, int *tapfds)
{
    for (int i = 0; i < numintfs; ++i) {
        if (tapfds[i] > 0) {
            close(tapfds[i]);
            tapfds[i] = 0;
        }
    }
    free(tapfds);
}

int main(int argc, char **argv)
{
    int numintfs = 5, *tapfds;
    struct ifreq ifr;

    /* setting up the number of tap interfaces to be created */
    if (argc == 2) {
        numintfs = atoi(argv[1]);
        if (numintfs > 26) {
            fputs("error: too many interfaces\n", stderr);
            return -1;
        }
    } else if (argc > 2) {
        fprintf(stderr, "Usage: %s [<num_intfs>]\n", argv[0]);
        return -1;
    }

    /* create tap interfaces */
    tapfds = (int *)calloc(numintfs, sizeof(int));
    for (int i = 0; i < numintfs; ++i) {
        if ((tapfds[i] = open("/dev/net/tun", O_RDWR)) < 0) {
            fputs("error: failed to open /dev/net/tun\n", stderr);
            goto _error;
        }
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
        strncpy(ifr.ifr_name, "demotap", IFNAMSIZ - 1);
        ifr.ifr_name[7] = 'A' + i;
        ifr.ifr_name[8] = '\0';
        if (ioctl(tapfds[i], TUNSETIFF, &ifr) < 0) {
            fputs("error: failed to set up interface\n", stderr);
            goto _error;
        }
    }

    struct DemoProto packet;

    while (1) {
        /* read/recv from the first interface */
        int nread = read(tapfds[0], &packet, sizeof(packet));
        if (nread < 0) {
            fputs("error: failed to read from tapfds[0]\n", stderr);
            goto _error;
        }

        /* validate packet */
        const int headerLen = 3 * sizeof(int);
        if (nread < headerLen || nread - headerLen != packet.len) {
            fputs("warning: invalid packet\n", stderr);
            continue; // ignore (i.e., drop)
        }

        /* response */
        int out_port_idx;
        if (packet.type == 0) {
            out_port_idx = (packet.seed + packet.type) % numintfs;
        } else if (packet.type == 1) {
            out_port_idx = (packet.seed + packet.type) % numintfs;
        } else {
            fputs("warning: unknown packet type\n", stderr);
            continue; // drop
        }
        write(tapfds[out_port_idx], &packet, nread);
    }

    cleanup_tapfds(numintfs, tapfds);
    return 0;

_error:
    cleanup_tapfds(numintfs, tapfds);
    return -1;
}
