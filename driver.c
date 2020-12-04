#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <klee/klee.h>

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

int forwarded = 0;

ssize_t read(int fd, void *buf, size_t count)
{
#pragma unused(fd)
    fputs("################ READ ################\n", stderr);
    fprintf(stderr, "forwarded: %d\n", forwarded);
    static int loopcount = 0;
    fprintf(stderr, "loopcount: %d\n", loopcount);

    if (klee_is_symbolic(((int *)buf)[0])) {
        fputs("buf is already symbolic\n", stderr);
        if (forwarded == 0) {
            // not yet forwarded; assume that dropping packets does not affect
            // the program state
            klee_silent_exit(0); // will not generate a test file
        } else {
            fputs("forwarded sym_pkt\n", stderr);
            exit(0);
            klee_report_error(NULL, 0, "forwarded sym_pkt", "");
        }
    } else {
        fputs("buf is NOT yet symbolic\n", stderr);
    }

    ssize_t nread;
    void *packet_buf = malloc(count);

    klee_make_symbolic(&nread, sizeof(nread), "sym_packet_length");
    klee_assume((size_t)nread <= count);
    //klee_make_symbolic(buf, count, "sym_packet_buffer");
    klee_make_symbolic(packet_buf, count, "sym_packet_buffer");
    memcpy(buf, packet_buf, count);
    free(packet_buf);
    memset(buf + nread, 0, count - nread);

    ++loopcount;
    return nread;
}

ssize_t write(int fd, const void *buf, size_t count)
{
#pragma unused(fd)
#pragma unused(buf)
    fputs("################ WRITE ################\n", stderr);
    fprintf(stderr, "forwarded: %d\n", forwarded);

    ++forwarded;

    // log all constraints on buf (TODO)
    klee_print_range("[write] fd", fd);
    klee_print_range("[write] count", count);
    klee_print_range("[write] buf[0]", ((int *)buf)[0]);

    //if (forwarded > 0) {
    //    exit(0);
    //    klee_abort();
    //}

    return count;
}
