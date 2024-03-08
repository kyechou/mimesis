#ifndef MIMESIS_SRC_SENDER_HPP
#define MIMESIS_SRC_SENDER_HPP

#include <cstdint>

struct DemoHeader {
    uint16_t seed; // egress port
    uint16_t len;  // payload length
};

#endif // MIMESIS_SRC_SENDER_HPP
