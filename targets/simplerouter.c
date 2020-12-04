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

#define BUFLEN 128U

struct DemoProto {
    // -- type --
    // 0: boost hash
    // 1: splitmix64
    // *: drop
    int  type;
    int  seed;
    int  len; // length of msg
    char msg[BUFLEN - 3 * sizeof(int)];
};

/*
static size_t djb2(const char *s, size_t len)
{
    size_t hash = 5381;
    for (size_t i = 0; i < len; ++i) {
        int c = s[i];
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash;
}

static size_t hash1(size_t seed, size_t val)    // boost hash
{
    seed ^= val + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    return seed;
}

static size_t hash2(size_t seed, size_t val)    // splitmix64
{
    val += seed;
    val = (val ^ (val >> 30)) * 0xbf58476d1ce4e5b9ULL;
    val = (val ^ (val >> 27)) * 0x94d049bb133111ebULL;
    val = val ^ (val >> 31);
    return val;
}
*/

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
    int numintfs = 3, *tapfds;
    struct ifreq ifr;

    /* setting up the number of tap interfaces to be created */
    if (argc == 2) {
        numintfs = atoi(argv[1]);
        if (numintfs > 26) {
            fputs("error: too many interfaces\n", stderr);
            return -1;
        }
    } else if (argc > 2) {
        fputs("Usage: ./simplerouter [<num_intfs>]\n", stderr);
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
            out_port_idx = packet.seed % numintfs;
            fputs("WRITE: type 0\n", stderr);
        } else if (packet.type == 1) {
            out_port_idx = packet.seed % numintfs;
            fputs("WRITE: type 1\n", stderr);
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
