#include <cstdint>
#include <gtest/gtest.h>
#include <klee/Common.h>
#include <klee/Constraints.h>
#include <klee/Expr.h>
#include <klee/Solver.h>
#include <klee/SolverFactory.h>
#include <linux/if_ether.h>
#include <llvm/Support/raw_ostream.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "libps/manager.hpp"
#include "libps/packetset.hpp"

struct DemoHeader {
    uint16_t seed; // egress port
    uint16_t len;  // payload length
};

class PacketSetTests : public testing::Test {
protected:
    llvm::raw_ostream *out = nullptr;
    klee::SolverPtr solver;
    klee::ConstraintManager constraints;

    const std::string var_name = "ingress_packet";
    klee::ArrayPtr array;
    klee::UpdateListPtr ul;

    void SetUp() override {
        // Output streams
        out = new llvm::raw_fd_ostream(/*fd=*/STDOUT_FILENO,
                                       /*shouldClose=*/false);
        klee::klee_message_stream = out;
        klee::klee_warning_stream = out;

        // Solver
        auto factory = klee::DefaultSolverFactory::create(".");
        klee::SolverPtr endSolver = factory->createEndSolver();
        solver = factory->decorateSolver(endSolver);

        // Initialize libps
        ps::Manager::get().init(/*n_workers=*/1,
                                /*memory_cap=*/1UL * 1024 * 1024 * 1024,
                                /*table_ratio=*/1,
                                /*initial_ratio=*/5);

        // Symbolic variables
        create_symbolic_variable();
    }

    void TearDown() override {
        delete out;
        out = nullptr;
        klee::klee_message_stream = nullptr;
        klee::klee_warning_stream = nullptr;
    }

    void create_symbolic_variable() {
        auto hdr_len = sizeof(struct ethhdr) + sizeof(struct DemoHeader);
        array = klee::Array::create(var_name, hdr_len);
        ul = klee::UpdateList::create(array, 0);
        ps::Manager::get().register_symbolic_variable(var_name, hdr_len * 8);
    }

    /**
     * This function tries to recreate the first condition expression we
     * encountered in demo-r1.
     */
    klee::ref<klee::Expr> create_expr_1() {
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
};

TEST_F(PacketSetTests, ctor) {
    auto expr = create_expr_1();
    auto not_expr = klee::Expr::createIsZero(expr);
    ps::PacketSet ps(expr);
    ps::PacketSet not_ps(not_expr);
    EXPECT_EQ(ps, ~not_ps);
    EXPECT_EQ(~ps, not_ps);
    EXPECT_EQ(ps.to_string(), "[\n"
                              "  node(1,143,0,~0),\n"
                              "  node(2,142,1,~0),\n"
                              "  node(3,141,2,~0),\n"
                              "  node(4,140,3,~0),\n"
                              "  node(5,139,4,~0),\n"
                              "  node(6,138,5,~0),\n"
                              "  node(7,137,5,6),\n"
                              "],[~7,]");
    EXPECT_EQ(ps.num_paths(), 2);
    EXPECT_EQ(ps.size(), 9223372036854775808UL);
    ps.to_dot_file("ps.dot");

    klee::Query q(/*_constraints=*/{}, expr);
    bool result;
    solver->mayBeTrue(q, result);
    EXPECT_TRUE(result);
}
