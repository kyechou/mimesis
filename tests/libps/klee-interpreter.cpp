#include <cstdint>
#include <gtest/gtest.h>
#include <klee/Common.h>
#include <klee/Expr.h>
#include <klee/util/Ref.h>
#include <linux/if_ether.h>
#include <llvm/Support/raw_ostream.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "libps/bdd.hpp"
#include "libps/bitvector.hpp"
#include "libps/klee-interpreter.hpp"
#include "libps/manager.hpp"

struct DemoHeader {
    uint16_t seed; // egress port
    uint16_t len;  // payload length
};

class KleeInterpreterTests : public testing::Test {
protected:
    llvm::raw_ostream *out = nullptr;
    const std::string var_name = "ingress_packet";
    klee::ArrayPtr array;
    klee::UpdateListPtr ul;

    void SetUp() override {
        // Output streams
        out = new llvm::raw_fd_ostream(/*fd=*/STDOUT_FILENO,
                                       /*shouldClose=*/false);
        klee::klee_message_stream = out;
        klee::klee_warning_stream = out;

        // Initialize libps
        ps::Manager::get().init();

        // Create symbolic variable
        auto hdr_len = sizeof(struct ethhdr) + sizeof(struct DemoHeader);
        array = klee::Array::create(var_name, hdr_len);
        ul = klee::UpdateList::create(array, 0);
        ps::Manager::get().register_symbolic_variable(var_name, hdr_len * 8);
    }

    void TearDown() override {
        // Output streams
        delete out;
        out = nullptr;
        klee::klee_message_stream = nullptr;
        klee::klee_warning_stream = nullptr;
        // libps
        ps::Manager::get().reset();
    }

    /**
     * Recreates the first conditional expression we encountered in demo-r1.
     */
    klee::ref<klee::Expr> create_r1_cond() {
        // (Ule
        //  (ZExt w64
        //      (Extract w16 0
        //          (And w64
        //              (Or w64
        //                  (LShr w64
        //                      N0:(ZExt w64
        //                          (Extract w16 0
        //                              (Extract w32 0
        //                                  (ZExt w64
        //                                      (ReadLSB w48 0xc
        //                                          ingress_packet)))))
        //                      0x8)
        //                  (Shl w64 N0 0x8))
        //              0xffff)))
        //  0x5ff)
        klee::ref<klee::Expr> expr, n0;
        std::vector<klee::ref<klee::Expr>> read_exprs;
        for (int i = 0x11; i >= 0xc; --i) { // Read 6 bytes
            auto e = klee::ReadExpr::create(
                ul, klee::ConstantExpr::create(i, klee::Expr::Int32));
            read_exprs.push_back(e);
        }
        expr = klee::ConcatExpr::createN(read_exprs.size(), read_exprs.data());
        expr = klee::ZExtExpr::create(expr, klee::Expr::Int64);
        expr = klee::ExtractExpr::create(expr, 0, klee::Expr::Int32);
        expr = klee::ExtractExpr::create(expr, 0, klee::Expr::Int16);
        n0 = klee::ZExtExpr::create(expr, klee::Expr::Int64);
        expr = klee::LShrExpr::create(
            n0, klee::ConstantExpr::create(0x8, klee::Expr::Int64));
        expr = klee::OrExpr::create(
            expr, klee::ShlExpr::create(
                      n0, klee::ConstantExpr::create(0x8, klee::Expr::Int64)));
        expr = klee::AndExpr::create(
            expr, klee::ConstantExpr::create(0xffff, klee::Expr::Int64));
        expr = klee::ExtractExpr::create(expr, 0, klee::Expr::Int16);
        expr = klee::ZExtExpr::create(expr, klee::Expr::Int64);
        expr = klee::UleExpr::create(
            expr, klee::ConstantExpr::create(0x5ff, klee::Expr::Int64));
        return expr;
    }

    /**
     * Recreates the first symbolic array index we encountered in demo-r1.
     */
    klee::ref<klee::Expr> create_sym_index() {
        // (Extract w32 0
        //     (And w64
        //         (Add w64
        //             0xffffffffffff7923
        //             (And w64
        //                 (Or w64
        //                     (LShr w64
        //                         N0:(ZExt w64
        //                             (Extract w16 0
        //                                 (Extract w32 0
        //                                     (ZExt w64
        //                                         (ReadLSB w48 0xc
        //                                             ingress_packet)))))
        //                         0x8)
        //                     (Shl w64 N0 0x8))
        //                 0xffff))
        //         0xff))
        klee::ref<klee::Expr> expr, n0;
        std::vector<klee::ref<klee::Expr>> read_exprs;
        for (int i = 0x11; i >= 0xc; --i) { // Read 6 bytes
            auto e = klee::ReadExpr::create(
                ul, klee::ConstantExpr::create(i, klee::Expr::Int32));
            read_exprs.push_back(e);
        }
        expr = klee::ConcatExpr::createN(read_exprs.size(), read_exprs.data());
        expr = klee::ZExtExpr::create(expr, klee::Expr::Int64);
        expr = klee::ExtractExpr::create(expr, 0, klee::Expr::Int32);
        expr = klee::ExtractExpr::create(expr, 0, klee::Expr::Int16);
        n0 = klee::ZExtExpr::create(expr, klee::Expr::Int64);
        expr = klee::LShrExpr::create(
            n0, klee::ConstantExpr::create(0x8, klee::Expr::Int64));
        expr = klee::OrExpr::create(
            expr, klee::ShlExpr::create(
                      n0, klee::ConstantExpr::create(0x8, klee::Expr::Int64)));
        expr = klee::AndExpr::create(
            expr, klee::ConstantExpr::create(0xffff, klee::Expr::Int64));
        expr =
            klee::AddExpr::create(klee::ConstantExpr::create(
                                      0xffffffffffff7923ull, klee::Expr::Int64),
                                  expr);
        expr = klee::AndExpr::create(
            expr, klee::ConstantExpr::create(0xff, klee::Expr::Int64));
        expr = klee::ExtractExpr::create(expr, 0, klee::Expr::Int32);
        return expr;
    }
};

TEST_F(KleeInterpreterTests, demo_r1_first_conditional) {
    klee::ref<klee::Expr> expr = create_r1_cond();
    ps::BitVector bv = ps::KleeInterpreter::translate(expr);
    EXPECT_EQ(bv.width(), 1);
    EXPECT_EQ(bv.to_string(), "1-bits bit-vector\n"
                              "-- bit 0: [\n"
                              "  node(1,143,0,~0),\n"
                              "  node(2,142,1,~0),\n"
                              "  node(3,141,2,~0),\n"
                              "  node(4,140,3,~0),\n"
                              "  node(5,139,4,~0),\n"
                              "  node(6,138,5,~0),\n"
                              "  node(7,137,5,6),\n"
                              "],[~7,]");
    EXPECT_EQ(bv.num_bdd_boolean_vars(), 7);
    EXPECT_EQ(bv.num_nodes(), 7);
    EXPECT_EQ(bv.num_assignments(), 128);
    EXPECT_EQ(bv.num_valid_values(), 2);
    EXPECT_EQ(ps::Bdd::num_true_paths(bv[0]), 2);
    EXPECT_EQ(ps::Bdd::num_sat_assignments(bv[0]), 3);
    EXPECT_EQ(ps::Bdd::num_sat_assignments(
                  bv[0], ps::Manager::get().get_all_variables()),
              9223372036854775808UL);
}

TEST_F(KleeInterpreterTests, demo_r1_symbolic_array_index) {
    klee::ref<klee::Expr> expr = create_sym_index();
    ps::BitVector bv = ps::KleeInterpreter::translate(expr);
    EXPECT_EQ(bv.width(), 32);
    EXPECT_EQ(bv.to_string(), "32-bits bit-vector\n"
                              "-- bit 0: [\n"
                              "  node(1,128,0,~0),\n"
                              "],[~1,]\n"
                              "-- bit 1: [\n"
                              "  node(1,129,0,~0),\n"
                              "  node(2,128,1,~1),\n"
                              "],[~2,]\n"
                              "-- bit 2: [\n"
                              "  node(1,130,0,~0),\n"
                              "  node(2,129,1,~1),\n"
                              "  node(3,128,2,~1),\n"
                              "],[3,]\n"
                              "-- bit 3: [\n"
                              "  node(1,131,0,~0),\n"
                              "  node(2,130,1,~1),\n"
                              "  node(3,129,1,2),\n"
                              "  node(4,128,3,2),\n"
                              "],[4,]\n"
                              "-- bit 4: [\n"
                              "  node(1,132,0,~0),\n"
                              "  node(2,131,1,~1),\n"
                              "  node(3,130,1,2),\n"
                              "  node(4,129,1,3),\n"
                              "  node(5,128,4,3),\n"
                              "],[5,]\n"
                              "-- bit 5: [\n"
                              "  node(1,133,0,~0),\n"
                              "  node(2,132,1,~1),\n"
                              "  node(3,131,1,2),\n"
                              "  node(4,130,1,3),\n"
                              "  node(5,129,1,4),\n"
                              "  node(6,128,5,4),\n"
                              "],[~6,]\n"
                              "-- bit 6: [\n"
                              "  node(1,134,0,~0),\n"
                              "  node(2,133,1,~1),\n"
                              "  node(3,132,2,~1),\n"
                              "  node(4,131,2,3),\n"
                              "  node(5,130,2,4),\n"
                              "  node(6,129,2,5),\n"
                              "  node(7,128,6,5),\n"
                              "],[7,]\n"
                              "-- bit 7: [\n"
                              "  node(1,135,0,~0),\n"
                              "  node(2,134,1,~1),\n"
                              "  node(3,133,1,2),\n"
                              "  node(4,132,3,2),\n"
                              "  node(5,131,3,4),\n"
                              "  node(6,130,3,5),\n"
                              "  node(7,129,3,6),\n"
                              "  node(8,128,7,6),\n"
                              "],[8,]\n"
                              "-- bit 8: [\n"
                              "],[0,]\n"
                              "-- bit 9: [\n"
                              "],[0,]\n"
                              "-- bit 10: [\n"
                              "],[0,]\n"
                              "-- bit 11: [\n"
                              "],[0,]\n"
                              "-- bit 12: [\n"
                              "],[0,]\n"
                              "-- bit 13: [\n"
                              "],[0,]\n"
                              "-- bit 14: [\n"
                              "],[0,]\n"
                              "-- bit 15: [\n"
                              "],[0,]\n"
                              "-- bit 16: [\n"
                              "],[0,]\n"
                              "-- bit 17: [\n"
                              "],[0,]\n"
                              "-- bit 18: [\n"
                              "],[0,]\n"
                              "-- bit 19: [\n"
                              "],[0,]\n"
                              "-- bit 20: [\n"
                              "],[0,]\n"
                              "-- bit 21: [\n"
                              "],[0,]\n"
                              "-- bit 22: [\n"
                              "],[0,]\n"
                              "-- bit 23: [\n"
                              "],[0,]\n"
                              "-- bit 24: [\n"
                              "],[0,]\n"
                              "-- bit 25: [\n"
                              "],[0,]\n"
                              "-- bit 26: [\n"
                              "],[0,]\n"
                              "-- bit 27: [\n"
                              "],[0,]\n"
                              "-- bit 28: [\n"
                              "],[0,]\n"
                              "-- bit 29: [\n"
                              "],[0,]\n"
                              "-- bit 30: [\n"
                              "],[0,]\n"
                              "-- bit 31: [\n"
                              "],[0,]");
    EXPECT_EQ(bv.num_bdd_boolean_vars(), 8);
    EXPECT_EQ(bv.num_nodes(), 36);
    EXPECT_EQ(bv.num_assignments(), 256);
    EXPECT_EQ(bv.num_valid_values(), 256);
}
