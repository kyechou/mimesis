#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <klee/klee.h>

#include "protocol.h"

#define DEBUG 0
#ifndef DEPTH_LIMIT
#define DEPTH_LIMIT 2
#endif
#define DRIVER_OUTPUT_PREFIX "__MIMESIS_DRIVER__  "

int read_count = 0;
int write_count = 0;
int last_write_count = 0;

static inline void *make_symbolic_memcpy(void *dest, size_t size, const char *name)
{
    void *buf = malloc(size);
    klee_make_symbolic(buf, size, name);
    memcpy(dest, buf, size);
    free(buf);
    return dest + size;
}

ssize_t read(int fd, void *buf, size_t count)
{
#pragma unused(fd)

    ++read_count;

    if (DEBUG) {
        fputs("################ READ ################\n", stderr);
        fprintf(stderr, "read_count:  %d\n", read_count);
        fprintf(stderr, "write_count: %d (%d)\n", write_count, last_write_count);
    }

    if (read_count > 1) {
        if (write_count == last_write_count) { // packet dropped; silently exit
            klee_silent_exit(0); // will not generate a test file
        }
        last_write_count = write_count;
    }

    ssize_t nread;
    klee_make_symbolic(&nread, sizeof(nread), "total_packet_length");
    klee_assume((size_t)nread <= count);
    void *start = buf;
    start = make_symbolic_memcpy(start, sizeof(int), "DemoProto.type");
    start = make_symbolic_memcpy(start, sizeof(int), "DemoProto.seed");
    start = make_symbolic_memcpy(start, sizeof(int), "DemoProto.len");
    //start = make_symbolic_memcpy(start, PAYLOAD_LEN, "DemoProto.msg");

    //memset(buf + nread, 0, count - nread); // NONONONONO (TODO: explain)

    return nread;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    ++write_count;

    if (DEBUG) {
        fputs("################ WRITE ################\n", stderr);
        fprintf(stderr, "read_count:  %d\n", read_count);
        fprintf(stderr, "write_count: %d (%d)\n", write_count, last_write_count);
    }

    // record the egress interface and output packet
    const struct DemoProto *packet = buf;

    fprintf(stderr, DRIVER_OUTPUT_PREFIX "Depth: %d\n", write_count);
    klee_print_range(DRIVER_OUTPUT_PREFIX "fd ", fd);
    klee_print_range(DRIVER_OUTPUT_PREFIX "out.type ", packet->type);
    klee_print_range(DRIVER_OUTPUT_PREFIX "out.seed ", packet->seed);
    klee_print_range(DRIVER_OUTPUT_PREFIX "out.len ", packet->len);
    //klee_print_expr

    if (write_count >= DEPTH_LIMIT) { // reached depth limit; end this path
        exit(0);
    }
    return count;
}
