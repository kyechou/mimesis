#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <klee/klee.h>

ssize_t read(int fd, void *buf, size_t count)
{
#pragma unused(fd)
    ssize_t nread;
    static int loopcount = 0;

    if (klee_is_symbolic(((int *)buf)[0])) {
        if (++loopcount > 10) {
            klee_abort();
        }
        klee_silent_exit(0);
    } else if (loopcount != 0) {
        klee_report_error("driver.c", 40, "IS NOT SYMBOLIC", "suffix");
    }

    klee_make_symbolic(&nread, sizeof(nread), "nread");
    klee_assume((size_t)nread <= count);
    klee_make_symbolic(buf, count, "read_pkt_buffer");
    memset(buf + nread, 0, count - nread);

    return nread;
}

ssize_t write(int fd, const void *buf, size_t count)
{
//#pragma unused(fd)
//#pragma unused(buf)
//#pragma unused(count)

    fputs("YAY\n", stdout);

    klee_print_range("write fd", fd);
    klee_print_range("write buf[0]", ((int *)buf)[0]);
    klee_print_range("write count", count);

    // log all constraints on buf

    klee_report_error("driver.c", 40, "message", "suffix");
    klee_abort();
}
