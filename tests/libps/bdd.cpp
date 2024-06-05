#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <linux/if_ether.h>
#include <string>
#include <sylvan_obj.hpp>

#include "libps/bdd.hpp"
#include "libps/manager.hpp"
#include "util.hpp"

class BddTests : public testing::Test {
protected:
    const size_t nbits = 8;
    sylvan::Bdd bdd_0;
    sylvan::Bdd bdd_1;
    sylvan::Bdd bdd_2;
    sylvan::Bdd bdd_3;
    sylvan::Bdd vars_cube, diamond, train, wildcard;

    void SetUp() override {
        // Initialize libps
        ps::Manager::get().init(/*n_workers=*/1,
                                /*memory_cap=*/1UL * 1024 * 1024 * 1024,
                                /*table_ratio=*/1,
                                /*initial_ratio=*/5);

        // BDD variables
        bdd_0 = sylvan::Bdd::bddVar(0);
        bdd_1 = sylvan::Bdd::bddVar(1);
        bdd_2 = sylvan::Bdd::bddVar(2);
        bdd_3 = sylvan::Bdd::bddVar(3);
        //   0
        //    \
        //     1
        //      \
        //       2
        //        \
        //         3
        //          \
        //           T
        vars_cube = bdd_0 & bdd_1 & bdd_2 & bdd_3;
        //     0
        //   ~/ \
        //   1   2
        //    \ /
        //     3
        //     |
        //     T
        diamond = ((bdd_0 & bdd_2) | (~bdd_0 & bdd_1)) & bdd_3;
        //         0
        //       ~/
        //       1
        //     ~/
        //     2
        //   ~/
        //   3
        //    \
        //     T
        train = ~bdd_0 & ~bdd_1 & ~bdd_2 & bdd_3;
        //   0
        //    \
        //     3
        //      \
        //       T
        wildcard = bdd_0 & bdd_3;
    }

    void TearDown() override { ps::Manager::get().reset(); }
};

TEST_F(BddTests, bit_variables_in_bdd) {
    std::set<uint32_t> all_vars{0, 1, 2, 3};
    std::set<uint32_t> vars_03{0, 3};
    EXPECT_EQ(ps::Bdd::variables(vars_cube), all_vars);
    EXPECT_EQ(ps::Bdd::variables(diamond), all_vars);
    EXPECT_EQ(ps::Bdd::variables(train), all_vars);
    EXPECT_EQ(ps::Bdd::variables(wildcard), vars_03);
}

TEST_F(BddTests, num_of_unique_bit_variables_in_bdd) {
    EXPECT_EQ(ps::Bdd::num_vars(vars_cube), 4);
    EXPECT_EQ(ps::Bdd::num_vars(diamond), 4);
    EXPECT_EQ(ps::Bdd::num_vars(train), 4);
    EXPECT_EQ(ps::Bdd::num_vars(wildcard), 2);
}

TEST_F(BddTests, num_of_true_paths) {
    EXPECT_EQ(ps::Bdd::num_true_paths(vars_cube), 1);
    EXPECT_EQ(ps::Bdd::num_true_paths(diamond), 2);
    EXPECT_EQ(ps::Bdd::num_true_paths(train), 1);
    EXPECT_EQ(ps::Bdd::num_true_paths(wildcard), 1);
}

TEST_F(BddTests, num_of_sat_assignments) {
    EXPECT_EQ(ps::Bdd::num_sat_assignments(vars_cube), 1);
    EXPECT_EQ(ps::Bdd::num_sat_assignments(diamond), 4);
    EXPECT_EQ(ps::Bdd::num_sat_assignments(train), 1);
    EXPECT_EQ(ps::Bdd::num_sat_assignments(wildcard), 1);
    EXPECT_EQ(ps::Bdd::num_sat_assignments(vars_cube, vars_cube), 1);
    EXPECT_EQ(ps::Bdd::num_sat_assignments(diamond, vars_cube), 4);
    EXPECT_EQ(ps::Bdd::num_sat_assignments(train, vars_cube), 1);
    EXPECT_EQ(ps::Bdd::num_sat_assignments(wildcard, vars_cube), 4);
}

TEST_F(BddTests, print_string) {
    const std::string vars_cube_str = "[\n"
                                      "  node(1,3,0,~0),\n"
                                      "  node(2,2,0,1),\n"
                                      "  node(3,1,0,2),\n"
                                      "  node(4,0,0,3),\n"
                                      "],[4,]";
    const std::string vars_cube_oneline_str =
        "4,[(1,3,0,0,1),(2,2,0,5,0),(3,1,0,9,0),(4,0,0,10,0),]";
    const std::string vars_cube_dot_str =
        "digraph \"DD\" {\n"
        "graph [dpi = 300];\n"
        "center = true;\n"
        "edge [dir = forward];\n"
        "root [style=invis];\n"
        "root -> 11 [style=solid dir=both arrowtail=none];\n"
        "11 [label=\"0\"];\n"
        "0 [shape=box, style=filled, label=\"F\"];\n"
        "10 [label=\"1\"];\n"
        "9 [label=\"2\"];\n"
        "5 [label=\"3\"];\n"
        "5 -> 0 [style=dashed];\n"
        "5 -> 0 [style=solid dir=both arrowtail=dot];\n"
        "9 -> 0 [style=dashed];\n"
        "9 -> 5 [style=solid dir=both arrowtail=none];\n"
        "10 -> 0 [style=dashed];\n"
        "10 -> 9 [style=solid dir=both arrowtail=none];\n"
        "11 -> 0 [style=dashed];\n"
        "11 -> 10 [style=solid dir=both arrowtail=none];\n"
        "}\n";
    EXPECT_EQ(ps::Bdd::to_string(vars_cube), vars_cube_str);
    EXPECT_EQ(ps::Bdd::to_string_oneline(vars_cube), vars_cube_oneline_str);
    EXPECT_EQ(ps::Bdd::to_dot_string(vars_cube), vars_cube_dot_str);

    const std::string diamond_str = "[\n"
                                    "  node(1,3,0,~0),\n"
                                    "  node(2,1,0,1),\n"
                                    "  node(3,2,0,1),\n"
                                    "  node(4,0,2,3),\n"
                                    "],[4,]";
    const std::string diamond_oneline_str =
        "4,[(1,3,0,0,1),(2,1,0,5,0),(3,2,0,5,0),(4,0,15,9,0),]";
    const std::string diamond_dot_str =
        "digraph \"DD\" {\n"
        "graph [dpi = 300];\n"
        "center = true;\n"
        "edge [dir = forward];\n"
        "root [style=invis];\n"
        "root -> 16 [style=solid dir=both arrowtail=none];\n"
        "16 [label=\"0\"];\n"
        "15 [label=\"1\"];\n"
        "0 [shape=box, style=filled, label=\"F\"];\n"
        "5 [label=\"3\"];\n"
        "5 -> 0 [style=dashed];\n"
        "5 -> 0 [style=solid dir=both arrowtail=dot];\n"
        "15 -> 0 [style=dashed];\n"
        "15 -> 5 [style=solid dir=both arrowtail=none];\n"
        "9 [label=\"2\"];\n"
        "9 -> 0 [style=dashed];\n"
        "9 -> 5 [style=solid dir=both arrowtail=none];\n"
        "16 -> 15 [style=dashed];\n"
        "16 -> 9 [style=solid dir=both arrowtail=none];\n"
        "}\n";
    EXPECT_EQ(ps::Bdd::to_string(diamond), diamond_str);
    EXPECT_EQ(ps::Bdd::to_string_oneline(diamond), diamond_oneline_str);
    EXPECT_EQ(ps::Bdd::to_dot_string(diamond), diamond_dot_str);

    const std::string train_str = "[\n"
                                  "  node(1,3,0,~0),\n"
                                  "  node(2,2,1,0),\n"
                                  "  node(3,1,2,0),\n"
                                  "  node(4,0,3,0),\n"
                                  "],[4,]";
    const std::string train_oneline_str =
        "4,[(1,3,0,0,1),(2,2,5,0,0),(3,1,20,0,0),(4,0,21,0,0),]";
    const std::string train_dot_str =
        "digraph \"DD\" {\n"
        "graph [dpi = 300];\n"
        "center = true;\n"
        "edge [dir = forward];\n"
        "root [style=invis];\n"
        "root -> 22 [style=solid dir=both arrowtail=none];\n"
        "22 [label=\"0\"];\n"
        "21 [label=\"1\"];\n"
        "20 [label=\"2\"];\n"
        "5 [label=\"3\"];\n"
        "0 [shape=box, style=filled, label=\"F\"];\n"
        "5 -> 0 [style=dashed];\n"
        "5 -> 0 [style=solid dir=both arrowtail=dot];\n"
        "20 -> 5 [style=dashed];\n"
        "20 -> 0 [style=solid dir=both arrowtail=none];\n"
        "21 -> 20 [style=dashed];\n"
        "21 -> 0 [style=solid dir=both arrowtail=none];\n"
        "22 -> 21 [style=dashed];\n"
        "22 -> 0 [style=solid dir=both arrowtail=none];\n"
        "}\n";
    EXPECT_EQ(ps::Bdd::to_string(train), train_str);
    EXPECT_EQ(ps::Bdd::to_string_oneline(train), train_oneline_str);
    EXPECT_EQ(ps::Bdd::to_dot_string(train), train_dot_str);

    const std::string wildcard_str = "[\n"
                                     "  node(1,3,0,~0),\n"
                                     "  node(2,0,0,1),\n"
                                     "],[2,]";
    const std::string wildcard_oneline_str = "2,[(1,3,0,0,1),(2,0,0,5,0),]";
    const std::string wildcard_dot_str =
        "digraph \"DD\" {\n"
        "graph [dpi = 300];\n"
        "center = true;\n"
        "edge [dir = forward];\n"
        "root [style=invis];\n"
        "root -> 23 [style=solid dir=both arrowtail=none];\n"
        "23 [label=\"0\"];\n"
        "0 [shape=box, style=filled, label=\"F\"];\n"
        "5 [label=\"3\"];\n"
        "5 -> 0 [style=dashed];\n"
        "5 -> 0 [style=solid dir=both arrowtail=dot];\n"
        "23 -> 0 [style=dashed];\n"
        "23 -> 5 [style=solid dir=both arrowtail=none];\n"
        "}\n";
    EXPECT_EQ(ps::Bdd::to_string(wildcard), wildcard_str);
    EXPECT_EQ(ps::Bdd::to_string_oneline(wildcard), wildcard_oneline_str);
    EXPECT_EQ(ps::Bdd::to_dot_string(wildcard), wildcard_dot_str);
}

TEST_F(BddTests, file_io) {
    // TODO: Implement the tests.

    // Test `to_dot_file` via `to_dot_string`.
    EXPECT_EQ(ps::Bdd::to_dot_string(vars_cube),
              util::get_testdata_str("ps_bdd_vars_cube.dot"));
    EXPECT_EQ(ps::Bdd::to_dot_string(diamond),
              util::get_testdata_str("ps_bdd_diamond.dot"));
    EXPECT_EQ(ps::Bdd::to_dot_string(train),
              util::get_testdata_str("ps_bdd_train.dot"));
    EXPECT_EQ(ps::Bdd::to_dot_string(wildcard),
              util::get_testdata_str("ps_bdd_wildcard.dot"));

    // Test `to_ascii_file` via `to_string`.
    EXPECT_EQ(ps::Bdd::to_string(vars_cube) + "\n",
              util::get_testdata_str("ps_bdd_vars_cube.txt"));
    EXPECT_EQ(ps::Bdd::to_string(diamond) + "\n",
              util::get_testdata_str("ps_bdd_diamond.txt"));
    EXPECT_EQ(ps::Bdd::to_string(train) + "\n",
              util::get_testdata_str("ps_bdd_train.txt"));
    EXPECT_EQ(ps::Bdd::to_string(wildcard) + "\n",
              util::get_testdata_str("ps_bdd_wildcard.txt"));

    // Test `to_binary_file` via `to_byte_vector`.
    EXPECT_EQ(ps::Bdd::to_byte_vector(vars_cube),
              util::get_testdata_byte_vector("ps_bdd_vars_cube.bin"));
    EXPECT_EQ(ps::Bdd::to_byte_vector(diamond),
              util::get_testdata_byte_vector("ps_bdd_diamond.bin"));
    EXPECT_EQ(ps::Bdd::to_byte_vector(train),
              util::get_testdata_byte_vector("ps_bdd_train.bin"));
    EXPECT_EQ(ps::Bdd::to_byte_vector(wildcard),
              util::get_testdata_byte_vector("ps_bdd_wildcard.bin"));

    // Test `from_binary_file`.
    EXPECT_EQ(vars_cube, ps::Bdd::from_binary_file(
                             util::get_testdata_path("ps_bdd_vars_cube.bin")));
    EXPECT_EQ(diamond, ps::Bdd::from_binary_file(
                           util::get_testdata_path("ps_bdd_diamond.bin")));
    EXPECT_EQ(train, ps::Bdd::from_binary_file(
                         util::get_testdata_path("ps_bdd_train.bin")));
    EXPECT_EQ(wildcard, ps::Bdd::from_binary_file(
                            util::get_testdata_path("ps_bdd_wildcard.bin")));
}
