#ifndef MIMESIS_SRC_SENDER_HPP
#define MIMESIS_SRC_SENDER_HPP

#include <cstdint>

struct Header {
    uint16_t seed; // egress port
    uint16_t len;  // payload length
};

#define PAYLOAD_LEN 128u

struct Packet {
    Header hdr;
    char payload[PAYLOAD_LEN];
};

#endif // MIMESIS_SRC_SENDER_HPP
