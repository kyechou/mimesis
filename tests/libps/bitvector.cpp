#include "gtest/gtest.h"
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <linux/if_ether.h>
#include <set>
#include <string>
#include <sylvan_obj.hpp>

#include "libps/bitvector.hpp"
#include "libps/manager.hpp"

class BitVectorTests : public testing::Test {
protected:
    const size_t nbits = 4;
    const std::string var_name = "byte";

    void SetUp() override {
        // Initialize libps
        ps::Manager::get().init(/*n_workers=*/1,
                                /*memory_cap=*/1UL * 1024 * 1024 * 1024,
                                /*table_ratio=*/1,
                                /*initial_ratio=*/5);

        ps::Manager::get().register_symbolic_variable(var_name, nbits);
    }

    void TearDown() override { ps::Manager::get().reset(); }
};

TEST_F(BitVectorTests, ctors_and_getters) {
    {
        ps::BitVector bv(var_name);
        EXPECT_EQ(bv.width(), nbits);
        EXPECT_FALSE(bv.empty());
        EXPECT_FALSE(bv.is_constant());
        EXPECT_EQ(bv.num_var_bits(), nbits);
        EXPECT_EQ(bv.num_bdd_boolean_vars(), nbits);
        EXPECT_EQ(bv.bdd_boolean_vars(), (std::set<uint32_t>{0, 1, 2, 3}));
        const std::string bv_str = "4-bits bit-vector\n"
                                   "-- bit 0: [\n"
                                   "  node(1,0,0,~0),\n"
                                   "],[1,]\n"
                                   "-- bit 1: [\n"
                                   "  node(1,1,0,~0),\n"
                                   "],[1,]\n"
                                   "-- bit 2: [\n"
                                   "  node(1,2,0,~0),\n"
                                   "],[1,]\n"
                                   "-- bit 3: [\n"
                                   "  node(1,3,0,~0),\n"
                                   "],[1,]";
        EXPECT_EQ(bv.to_string(), bv_str);
    }

    {
        ps::BitVector bv(var_name, 0, 2);
        EXPECT_EQ(bv.width(), 2);
        EXPECT_FALSE(bv.empty());
        EXPECT_FALSE(bv.is_constant());
        EXPECT_EQ(bv.num_var_bits(), 2);
        EXPECT_EQ(bv.num_bdd_boolean_vars(), 2);
        EXPECT_EQ(bv.bdd_boolean_vars(), (std::set<uint32_t>{0, 1}));
        const std::string bv_str = "2-bits bit-vector\n"
                                   "-- bit 0: [\n"
                                   "  node(1,0,0,~0),\n"
                                   "],[1,]\n"
                                   "-- bit 1: [\n"
                                   "  node(1,1,0,~0),\n"
                                   "],[1,]";
        EXPECT_EQ(bv.to_string(), bv_str);
        bv[0] = bv[1];
        EXPECT_EQ(bv.num_var_bits(), 2);
        EXPECT_EQ(bv.num_bdd_boolean_vars(), 1);
        EXPECT_EQ(bv.bdd_boolean_vars(), (std::set<uint32_t>{1}));
    }

    {
        ps::BitVector bv(nbits, sylvan::Bdd(0u));
        EXPECT_EQ(bv.width(), nbits);
        EXPECT_FALSE(bv.empty());
        EXPECT_FALSE(bv.is_constant());
        EXPECT_EQ(bv.num_var_bits(), nbits);
        EXPECT_EQ(bv.num_bdd_boolean_vars(), 1);
        EXPECT_EQ(bv.bdd_boolean_vars(), (std::set<uint32_t>{0}));
        const std::string bv_str = "4-bits bit-vector\n"
                                   "-- bit 0: [\n"
                                   "  node(1,0,0,~0),\n"
                                   "],[1,]\n"
                                   "-- bit 1: [\n"
                                   "  node(1,0,0,~0),\n"
                                   "],[1,]\n"
                                   "-- bit 2: [\n"
                                   "  node(1,0,0,~0),\n"
                                   "],[1,]\n"
                                   "-- bit 3: [\n"
                                   "  node(1,0,0,~0),\n"
                                   "],[1,]";
        EXPECT_EQ(bv.to_string(), bv_str);
    }

    {
        ps::BitVector bv(nbits, true);
        EXPECT_EQ(bv.width(), nbits);
        EXPECT_FALSE(bv.empty());
        EXPECT_TRUE(bv.is_constant());
        EXPECT_EQ(bv.num_var_bits(), 0);
        EXPECT_EQ(bv.num_bdd_boolean_vars(), 0);
        EXPECT_EQ(bv.bdd_boolean_vars(), (std::set<uint32_t>{}));
        EXPECT_EQ(bv.zext_value(), (1UL << nbits) - 1);
        const std::string bv_str = "4-bits bit-vector\n"
                                   "-- bit 0: [\n"
                                   "],[~0,]\n"
                                   "-- bit 1: [\n"
                                   "],[~0,]\n"
                                   "-- bit 2: [\n"
                                   "],[~0,]\n"
                                   "-- bit 3: [\n"
                                   "],[~0,]";
        EXPECT_EQ(bv.to_string(), bv_str);
    }

    {
        ps::BitVector bv1(
            llvm::APInt(/*numBits=*/32, /*val=*/9527, /*isSigned=*/false));
        ps::BitVector bv2(/*width=*/32, /*value=*/27ul);
        EXPECT_EQ(bv1.width(), 32);
        EXPECT_FALSE(bv1.empty());
        EXPECT_TRUE(bv1.is_constant());
        EXPECT_EQ(bv1.num_var_bits(), 0);
        EXPECT_EQ(bv1.num_bdd_boolean_vars(), 0);
        EXPECT_EQ(bv1.bdd_boolean_vars(), (std::set<uint32_t>{}));
        EXPECT_EQ(bv1.zext_value(), 9527);
        bv1 -= bv2;
        EXPECT_EQ(bv1.zext_value(), 9500);
        bv1 += bv2;
        EXPECT_EQ(bv1.zext_value(), 9527);
    }
}

TEST_F(BitVectorTests, setters) {
    ps::BitVector bv(var_name);
    EXPECT_EQ(bv.width(), nbits);
    EXPECT_FALSE(bv.empty());
    EXPECT_FALSE(bv.is_constant());
    EXPECT_EQ(bv.num_var_bits(), nbits);
    EXPECT_EQ(bv.num_bdd_boolean_vars(), nbits);
    EXPECT_EQ(bv.bdd_boolean_vars(), (std::set<uint32_t>{0, 1, 2, 3}));
    EXPECT_EQ(bv.to_string(), "4-bits bit-vector\n"
                              "-- bit 0: [\n"
                              "  node(1,0,0,~0),\n"
                              "],[1,]\n"
                              "-- bit 1: [\n"
                              "  node(1,1,0,~0),\n"
                              "],[1,]\n"
                              "-- bit 2: [\n"
                              "  node(1,2,0,~0),\n"
                              "],[1,]\n"
                              "-- bit 3: [\n"
                              "  node(1,3,0,~0),\n"
                              "],[1,]");

    bv.set(0, bv[0] & bv[1] | bv[2] & (~bv[3]));
    bv.set(1, bv[0] & bv[1]);
    bv.set(2, sylvan::Bdd::bddOne());
    bv.set(3, sylvan::Bdd::bddZero());
    EXPECT_EQ(bv.width(), nbits);
    EXPECT_FALSE(bv.empty());
    EXPECT_FALSE(bv.is_constant());
    EXPECT_EQ(bv.num_var_bits(), 2);
    EXPECT_EQ(bv.num_bdd_boolean_vars(), nbits);
    EXPECT_EQ(bv.bdd_boolean_vars(), (std::set<uint32_t>{0, 1, 2, 3}));
    EXPECT_EQ(bv.to_string(), "4-bits bit-vector\n"
                              "-- bit 0: [\n"
                              "  node(1,3,0,~0),\n"
                              "  node(2,2,0,~1),\n"
                              "  node(3,1,2,~0),\n"
                              "  node(4,0,2,3),\n"
                              "],[4,]\n"
                              "-- bit 1: [\n"
                              "  node(1,3,0,~0),\n"
                              "  node(2,2,0,~1),\n"
                              "  node(3,1,0,2),\n"
                              "  node(4,1,0,~0),\n"
                              "  node(5,0,3,4),\n"
                              "],[5,]\n"
                              "-- bit 2: [\n"
                              "],[~0,]\n"
                              "-- bit 3: [\n"
                              "],[0,]");

    bv.clear();
    EXPECT_EQ(bv.width(), 0);
    EXPECT_TRUE(bv.empty());
    EXPECT_TRUE(bv.is_constant());
    EXPECT_EQ(bv.num_var_bits(), 0);
    EXPECT_EQ(bv.num_bdd_boolean_vars(), 0);
    EXPECT_EQ(bv.bdd_boolean_vars(), (std::set<uint32_t>{}));
    EXPECT_EQ(bv.zext_value(), 0);
    EXPECT_EQ(bv.to_string(), "0-bits bit-vector");
}

TEST_F(BitVectorTests, relational_ops) {
    ps::BitVector bv(var_name);
    ps::BitVector bv_3(/*width=*/nbits, /*value=*/3ul);
    ps::BitVector bv_10(/*width=*/nbits, /*value=*/10ul);
    ps::BitVector bv_13(/*width=*/nbits, /*value=*/13ul);
    ps::BitVector res;

    EXPECT_TRUE((bv == bv).identical_to(ps::BitVector(true)));
    EXPECT_TRUE((bv != bv).identical_to(ps::BitVector(false)));

    // ult
    res = (bv < bv_3);
    EXPECT_EQ(res.num_bdd_boolean_vars(), nbits);
    EXPECT_EQ(res.to_string(), "1-bits bit-vector\n"
                               "-- bit 0: [\n"
                               "  node(1,3,0,~0),\n"
                               "  node(2,2,1,~0),\n"
                               "  node(3,1,2,~0),\n"
                               "  node(4,0,2,3),\n"
                               "],[~4,]");
    EXPECT_TRUE((bv_3 < bv_10).identical_to(ps::BitVector(true)));
    EXPECT_TRUE((bv_13 < bv_10).identical_to(ps::BitVector(false)));

    // ule
    res = (bv <= bv_3);
    EXPECT_EQ(res.num_bdd_boolean_vars(), 2);
    EXPECT_EQ(res.to_string(), "1-bits bit-vector\n"
                               "-- bit 0: [\n"
                               "  node(1,3,0,~0),\n"
                               "  node(2,2,1,~0),\n"
                               "],[~2,]");
    EXPECT_TRUE((bv_3 <= bv_3).identical_to(ps::BitVector(true)));

    // ugt
    res = (bv > bv_3);
    EXPECT_EQ(res.num_bdd_boolean_vars(), 2);
    EXPECT_EQ(res.to_string(), "1-bits bit-vector\n"
                               "-- bit 0: [\n"
                               "  node(1,3,0,~0),\n"
                               "  node(2,2,1,~0),\n"
                               "],[2,]");
    EXPECT_TRUE((bv_3 > bv_10).identical_to(ps::BitVector(false)));
    EXPECT_TRUE((bv_13 > bv_10).identical_to(ps::BitVector(true)));

    // uge
    res = (bv >= bv_3);
    EXPECT_EQ(res.num_bdd_boolean_vars(), nbits);
    EXPECT_EQ(res.to_string(), "1-bits bit-vector\n"
                               "-- bit 0: [\n"
                               "  node(1,3,0,~0),\n"
                               "  node(2,2,1,~0),\n"
                               "  node(3,1,2,~0),\n"
                               "  node(4,0,2,3),\n"
                               "],[4,]");
    EXPECT_TRUE((bv_3 >= bv_3).identical_to(ps::BitVector(true)));

    // slt
    res = bv.slt(bv_3);
    EXPECT_EQ(res.num_bdd_boolean_vars(), nbits);
    EXPECT_EQ(res.to_string(), "1-bits bit-vector\n"
                               "-- bit 0: [\n"
                               "  node(1,3,0,~0),\n"
                               "  node(2,2,0,~1),\n"
                               "  node(3,1,2,~1),\n"
                               "  node(4,0,2,3),\n"
                               "],[~4,]");
    EXPECT_TRUE(bv_3.slt(bv_10).identical_to(ps::BitVector(false)));

    // sle
    res = bv.sle(bv_3);
    EXPECT_EQ(res.num_bdd_boolean_vars(), 2);
    EXPECT_EQ(res.to_string(), "1-bits bit-vector\n"
                               "-- bit 0: [\n"
                               "  node(1,3,0,~0),\n"
                               "  node(2,2,0,~1),\n"
                               "],[~2,]");
    EXPECT_TRUE(bv_13.sle(bv_10).identical_to(ps::BitVector(true)));

    // sgt
    res = bv.sgt(bv_3);
    EXPECT_EQ(res.num_bdd_boolean_vars(), 2);
    EXPECT_EQ(res.to_string(), "1-bits bit-vector\n"
                               "-- bit 0: [\n"
                               "  node(1,3,0,~0),\n"
                               "  node(2,2,0,~1),\n"
                               "],[2,]");
    EXPECT_TRUE(bv_3.sgt(bv_10).identical_to(ps::BitVector(true)));

    // sge
    res = bv.sge(bv_3);
    EXPECT_EQ(res.num_bdd_boolean_vars(), nbits);
    EXPECT_EQ(res.to_string(), "1-bits bit-vector\n"
                               "-- bit 0: [\n"
                               "  node(1,3,0,~0),\n"
                               "  node(2,2,0,~1),\n"
                               "  node(3,1,2,~1),\n"
                               "  node(4,0,2,3),\n"
                               "],[4,]");
    EXPECT_TRUE(bv_13.sge(bv_10).identical_to(ps::BitVector(false)));
}

TEST_F(BitVectorTests, bitwise_logical_ops) {
    //
}

TEST_F(BitVectorTests, shift_ops) {
    //
}

TEST_F(BitVectorTests, negation) {
    //
}

TEST_F(BitVectorTests, arithmetic_ops) {
    //
}

TEST_F(BitVectorTests, casting) {
    //
}

TEST_F(BitVectorTests, concat) {
    //
}

TEST_F(BitVectorTests, extract) {
    //
}

TEST_F(BitVectorTests, select) {
    //
}
