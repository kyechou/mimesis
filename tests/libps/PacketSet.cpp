#include <gtest/gtest.h>
#include <klee/Expr.h>
#include <string>

#include "libps/PacketSet.hpp"

TEST(PacketSet, ctor) {
    PacketSet ps;
    EXPECT_EQ(ps.to_string(), "(Unimplemented)");

    auto expr = klee::ConstantExpr::create(42, 32);
    std::string expr_str;
    expr->toString(expr_str);
    EXPECT_EQ(expr_str, "42");
}
