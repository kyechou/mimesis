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
        EXPECT_EQ(bv.num_nodes(), 4);
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
        EXPECT_EQ(bv.num_nodes(), 2);
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
        EXPECT_EQ(bv.num_nodes(), 1);
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
        EXPECT_EQ(bv.num_nodes(), 0);
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
        EXPECT_EQ(bv1.num_nodes(), 0);
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
    EXPECT_EQ(bv.num_nodes(), 4);
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
    EXPECT_EQ(bv.num_nodes(), 7);
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
    EXPECT_EQ(bv.num_nodes(), 0);
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
    ps::BitVector bv(var_name);
    ps::BitVector one_mask(/*width=*/nbits, true);
    ps::BitVector zero_mask(/*width=*/nbits, false);
    ps::BitVector bv_3(/*width=*/nbits, /*value=*/3ul);
    ps::BitVector res;

    // and
    EXPECT_TRUE((bv & bv).identical_to(bv));
    EXPECT_TRUE((bv & one_mask).identical_to(bv));
    EXPECT_TRUE((bv & zero_mask).identical_to(zero_mask));
    EXPECT_TRUE((bv_3 & one_mask).identical_to(bv_3));
    EXPECT_TRUE((bv_3 & zero_mask).identical_to(zero_mask));
    res = bv & bv_3;
    EXPECT_EQ(res.num_bdd_boolean_vars(), 2);
    EXPECT_EQ(res.to_string(), "4-bits bit-vector\n"
                               "-- bit 0: [\n"
                               "  node(1,0,0,~0),\n"
                               "],[1,]\n"
                               "-- bit 1: [\n"
                               "  node(1,1,0,~0),\n"
                               "],[1,]\n"
                               "-- bit 2: [\n"
                               "],[0,]\n"
                               "-- bit 3: [\n"
                               "],[0,]");

    // or
    EXPECT_TRUE((bv | bv).identical_to(bv));
    EXPECT_TRUE((bv | one_mask).identical_to(one_mask));
    EXPECT_TRUE((bv | zero_mask).identical_to(bv));
    EXPECT_TRUE((bv_3 | one_mask).identical_to(one_mask));
    EXPECT_TRUE((bv_3 | zero_mask).identical_to(bv_3));
    res = bv | bv_3;
    EXPECT_EQ(res.num_bdd_boolean_vars(), 2);
    EXPECT_EQ(res.to_string(), "4-bits bit-vector\n"
                               "-- bit 0: [\n"
                               "],[~0,]\n"
                               "-- bit 1: [\n"
                               "],[~0,]\n"
                               "-- bit 2: [\n"
                               "  node(1,2,0,~0),\n"
                               "],[1,]\n"
                               "-- bit 3: [\n"
                               "  node(1,3,0,~0),\n"
                               "],[1,]");

    // xor
    EXPECT_TRUE((bv ^ bv).identical_to(zero_mask));
    EXPECT_TRUE((bv ^ one_mask).identical_to(~bv));
    EXPECT_TRUE((bv ^ zero_mask).identical_to(bv));
    EXPECT_TRUE((bv_3 ^ one_mask).identical_to(~bv_3));
    EXPECT_TRUE((bv_3 ^ zero_mask).identical_to(bv_3));
    res = bv ^ bv_3;
    bv[1] = ~bv[1];
    bv[0] = ~bv[0];
    EXPECT_TRUE(res.identical_to(bv));
    EXPECT_EQ(res.num_bdd_boolean_vars(), nbits);
    EXPECT_EQ(res.to_string(), "4-bits bit-vector\n"
                               "-- bit 0: [\n"
                               "  node(1,0,0,~0),\n"
                               "],[~1,]\n"
                               "-- bit 1: [\n"
                               "  node(1,1,0,~0),\n"
                               "],[~1,]\n"
                               "-- bit 2: [\n"
                               "  node(1,2,0,~0),\n"
                               "],[1,]\n"
                               "-- bit 3: [\n"
                               "  node(1,3,0,~0),\n"
                               "],[1,]");
}

TEST_F(BitVectorTests, shift_ops) {
    ps::BitVector bv(var_name);
    ps::BitVector bv_0(/*width=*/nbits, /*value=*/0ul);
    ps::BitVector bv_1(/*width=*/nbits, /*value=*/1ul);
    ps::BitVector bv_2(/*width=*/nbits, /*value=*/2ul);
    ps::BitVector bv_3(/*width=*/nbits, /*value=*/3ul);
    ps::BitVector bv_4(/*width=*/nbits, /*value=*/4ul);
    ps::BitVector bv_8(/*width=*/nbits, /*value=*/8ul);
    ps::BitVector res;

    // shl (<<)
    EXPECT_TRUE((bv << bv_0).identical_to(bv));
    EXPECT_TRUE((bv << bv_4).identical_to(bv_0));
    EXPECT_TRUE(((bv << bv_4) >> bv_4).identical_to(bv_0));
    EXPECT_TRUE((bv_2 << bv_1).identical_to(bv_4));
    res = bv << bv_2;
    EXPECT_EQ(res.num_bdd_boolean_vars(), 2);
    EXPECT_EQ(res.to_string(), "4-bits bit-vector\n"
                               "-- bit 0: [\n"
                               "],[0,]\n"
                               "-- bit 1: [\n"
                               "],[0,]\n"
                               "-- bit 2: [\n"
                               "  node(1,0,0,~0),\n"
                               "],[1,]\n"
                               "-- bit 3: [\n"
                               "  node(1,1,0,~0),\n"
                               "],[1,]");
    // lshr (>>)
    EXPECT_TRUE((bv >> bv_0).identical_to(bv));
    EXPECT_TRUE((bv >> bv_4).identical_to(bv_0));
    EXPECT_TRUE(((bv >> bv_4) << bv_4).identical_to(bv_0));
    EXPECT_TRUE((bv_3 >> bv_1).identical_to(bv_1));
    res = bv >> bv_2;
    EXPECT_EQ(res.num_bdd_boolean_vars(), 2);
    EXPECT_EQ(res.to_string(), "4-bits bit-vector\n"
                               "-- bit 0: [\n"
                               "  node(1,2,0,~0),\n"
                               "],[1,]\n"
                               "-- bit 1: [\n"
                               "  node(1,3,0,~0),\n"
                               "],[1,]\n"
                               "-- bit 2: [\n"
                               "],[0,]\n"
                               "-- bit 3: [\n"
                               "],[0,]");
    // ashr
    EXPECT_TRUE(bv.ashr(bv_0).identical_to(bv));
    EXPECT_TRUE(
        bv.ashr(bv_4).identical_to(ps::BitVector(nbits, bv[nbits - 1])));
    EXPECT_TRUE((bv.ashr(bv_4) << bv_4).identical_to(bv_0));
    EXPECT_TRUE(bv_8.ashr(bv_3).identical_to(~bv_0));
    EXPECT_TRUE(bv_8.ashr(bv_4).identical_to(~bv_0));
    res = bv.ashr(bv_2);
    EXPECT_EQ(res.num_bdd_boolean_vars(), 2);
    EXPECT_EQ(res.to_string(), "4-bits bit-vector\n"
                               "-- bit 0: [\n"
                               "  node(1,2,0,~0),\n"
                               "],[1,]\n"
                               "-- bit 1: [\n"
                               "  node(1,3,0,~0),\n"
                               "],[1,]\n"
                               "-- bit 2: [\n"
                               "  node(1,3,0,~0),\n"
                               "],[1,]\n"
                               "-- bit 3: [\n"
                               "  node(1,3,0,~0),\n"
                               "],[1,]");
}

TEST_F(BitVectorTests, negation) {
    ps::BitVector bv(var_name);
    ps::BitVector bv_0(/*width=*/nbits, /*value=*/0ul);
    ps::BitVector bv_1(/*width=*/nbits, /*value=*/1ul);
    ps::BitVector bv_2(/*width=*/nbits, /*value=*/2ul);
    ps::BitVector bv_4(/*width=*/nbits, /*value=*/4ul);
    ps::BitVector bv_8(/*width=*/nbits, /*value=*/8ul);
    ps::BitVector bv_7(/*width=*/nbits, /*value=*/7ul);
    ps::BitVector bv_b(/*width=*/nbits, /*value=*/0xbul);
    ps::BitVector bv_d(/*width=*/nbits, /*value=*/0xdul);
    ps::BitVector bv_e(/*width=*/nbits, /*value=*/0xeul);
    ps::BitVector bv_f(/*width=*/nbits, /*value=*/0xful);
    EXPECT_TRUE((~~bv).identical_to(bv));
    EXPECT_TRUE((~bv ^ bv).identical_to(bv_f));
    EXPECT_TRUE((~bv_0).identical_to(bv_f));
    EXPECT_TRUE((~bv_1).identical_to(bv_e));
    EXPECT_TRUE((~bv_2).identical_to(bv_d));
    EXPECT_TRUE((~bv_4).identical_to(bv_b));
    EXPECT_TRUE((~bv_8).identical_to(bv_7));
}

TEST_F(BitVectorTests, arithmetic_ops) {
    ps::BitVector bv(var_name);
    ps::BitVector bv_0(/*width=*/nbits, /*value=*/0ul);
    ps::BitVector bv_1(/*width=*/nbits, /*value=*/1ul);
    ps::BitVector bv_2(/*width=*/nbits, /*value=*/2ul);
    ps::BitVector bv_3(/*width=*/nbits, /*value=*/3ul);
    ps::BitVector bv_4(/*width=*/nbits, /*value=*/4ul);
    ps::BitVector bv_8(/*width=*/nbits, /*value=*/8ul);
    ps::BitVector bv_b(/*width=*/nbits, /*value=*/0xbul);
    ps::BitVector bv_c(/*width=*/nbits, /*value=*/0xcul);
    ps::BitVector bv_d(/*width=*/nbits, /*value=*/0xdul);
    ps::BitVector bv_e(/*width=*/nbits, /*value=*/0xeul);
    ps::BitVector bv_f(/*width=*/nbits, /*value=*/0xful);

    // add (+)
    EXPECT_TRUE((bv + bv_0).identical_to(bv));
    EXPECT_TRUE((bv + bv).identical_to(bv << bv_1));
    EXPECT_TRUE((bv + bv + bv + bv).identical_to(bv << bv_2));
    EXPECT_TRUE((bv_1 + bv_2).identical_to(bv_3));
    EXPECT_TRUE((bv_2 + bv_2).identical_to(bv_4));
    EXPECT_TRUE((bv_3 + bv_8).identical_to(bv_b));
    EXPECT_TRUE((bv_8 + bv_8).identical_to(bv_0));
    EXPECT_TRUE((bv_2 + bv_e).identical_to(bv_0));
    EXPECT_TRUE((bv_8 + bv_b).identical_to(bv_3));
    EXPECT_TRUE((bv_d + bv_f).identical_to(bv_c));

    // sub (-)
    EXPECT_TRUE((bv - bv_0).identical_to(bv));
    EXPECT_TRUE((bv - bv).identical_to(bv_0));
    EXPECT_TRUE((bv_0 - bv).identical_to(~bv + bv_1));
    EXPECT_TRUE((bv_3 - bv_1).identical_to(bv_2));
    EXPECT_TRUE((bv_e - bv_4).identical_to(bv_2 - bv_8));
    EXPECT_TRUE((bv_e - bv_f).identical_to(bv_f));

    // NOTE: mul (*), div (/), and rem (%) are not implemented yet.
}

TEST_F(BitVectorTests, casting) {
    ps::BitVector bv(var_name, 0, 2);
    ps::BitVector bv_3(/*width=*/nbits, /*value=*/3ul);
    ps::BitVector bv_c(/*width=*/nbits, /*value=*/0xcul);

    // zext
    EXPECT_TRUE(bv.zext(3).identical_to(bv.concat(ps::BitVector(false))));
    EXPECT_TRUE(bv.zext(4).identical_to(bv.concat(ps::BitVector(2, false))));
    EXPECT_EQ(bv_3.zext(8).zext_value(), 3);

    // sext
    EXPECT_TRUE(bv.sext(3).identical_to(bv.concat(ps::BitVector(1, bv[1]))));
    EXPECT_TRUE(bv.sext(4).identical_to(bv.concat(ps::BitVector(2, bv[1]))));
    EXPECT_EQ(bv_3.sext(8).zext_value(), 3);
    EXPECT_EQ(bv_c.sext(8).zext_value(), 0xfc);
}

TEST_F(BitVectorTests, concat) {
    ps::BitVector bv(var_name);
    ps::BitVector bv_01(var_name, 0, 2);
    ps::BitVector bv_23(var_name, 2, 2);
    EXPECT_TRUE(bv_01.concat(bv_23).identical_to(bv));
}

TEST_F(BitVectorTests, extract) {
    ps::BitVector bv(var_name);
    ps::BitVector bv_01(var_name, 0, 2);
    ps::BitVector bv_23(var_name, 2, 2);
    EXPECT_TRUE(bv.extract(0, 2).identical_to(bv_01));
    EXPECT_TRUE(bv.extract(2, 2).identical_to(bv_23));
}

TEST_F(BitVectorTests, select) {
    ps::BitVector bv1(var_name);
    ps::BitVector bv2(nbits, true);
    ps::BitVector bv3(var_name, 0, 1);
    ps::BitVector bv_true(true);
    ps::BitVector bv_false(false);
    ps::BitVector res;

    for (size_t i = 0; i < nbits; ++i) {
        for (size_t j = 0; j < i; ++j) {
            bv2[i] &= bv1[j];
        }
    }

    EXPECT_TRUE(ps::BitVector::select(bv_true, bv1, bv2).identical_to(bv1));
    EXPECT_TRUE(ps::BitVector::select(bv_true, bv2, bv1).identical_to(bv2));
    EXPECT_TRUE(ps::BitVector::select(bv_false, bv1, bv2).identical_to(bv2));
    EXPECT_TRUE(ps::BitVector::select(bv_false, bv2, bv1).identical_to(bv1));
    res = ps::BitVector::select(bv3, bv1, bv2);
    EXPECT_TRUE(res.identical_to((bv1 & ps::BitVector(nbits, bv1[0])) |
                                 ps::BitVector(nbits, 1ul)));

    const std::string new_var_name = var_name + "_n";
    ps::Manager::get().register_symbolic_variable(new_var_name, nbits);
    ps::BitVector nbv(var_name);
    res = ps::BitVector::select(bv3, bv1, nbv);
    ps::BitVector expected(nbits, false);
    for (size_t i = 0; i < nbits; ++i) {
        expected[i] = (bv3[0] & bv1[i]) | (~bv3[0] & nbv[i]);
    }
    EXPECT_TRUE(res.identical_to(expected));
}
