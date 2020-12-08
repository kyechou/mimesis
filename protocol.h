#pragma once

#define BUFLEN 512U
#define PAYLOAD_LEN (BUFLEN - 3 * sizeof(int))

struct DemoProto {
    // -- type --
    // 0: boost hash
    // 1: splitmix64
    // *: drop
    int  type;
    int  seed;
    int  len; // length of msg
    char msg[PAYLOAD_LEN];
};
