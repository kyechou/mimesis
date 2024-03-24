#include <gtest/gtest.h>

#include "libps/PacketSet.hpp"

TEST(PacketSet_tests, ctor) {
    PacketSet ps;
    EXPECT_EQ(ps.to_string(), "(Unimplemented)");
}
