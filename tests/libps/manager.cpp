#include <cstdint>
#include <gtest/gtest.h>
#include <linux/if_ether.h>
#include <string>

#include "libps/manager.hpp"

struct DemoHeader {
    uint16_t seed; // egress port
    uint16_t len;  // payload length
};

class ManagerTests : public testing::Test {
protected:
    const std::string var_name = "ingress_packet";

    void SetUp() override {
        // Initialize libps
        ps::Manager::get().init();

        // Register symbolic variable
        auto hdr_len = sizeof(struct ethhdr) + sizeof(struct DemoHeader);
        ps::Manager::get().register_symbolic_variable(var_name, hdr_len * 8);
    }

    void TearDown() override { ps::Manager::get().reset(); }
};
