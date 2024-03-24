#include <gtest/gtest.h>

#include "libps/PacketSet.hpp"

TEST(PacketSet_tests, constructor_test) {
    PacketSet ps;
    EXPECT_EQ(ps.to_string(), "(Unimplemented)");
}
