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
        // (Ule (ZExt w64 (Extract w16 0 (And w64 (Or w64 (LShr w64 N0:(ZExt w64
        // (Extract w16 0 (Extract w32 0 (ZExt w64 (ReadLSB w48 0xc
        // v0_ingress_packet_0)))))
        //                                                           0x8)
        //                                                 (Shl w64 N0 0x8))
        //                                         0xffff)))
        //       0x5ff)
        // (ZExt w64 (Extract w16 0 (And w64 (Or w64 (LShr w64 N0:(ZExt w64
        // (Extract w16 0 (Extract w32 0 (ZExt w64 (ReadLSB w48 0xc
        // v0_ingress_packet_0)))))
        //                                                      0x8)
        //                                            (Shl w64 N0 0x8))
        //                                    0xffff)))
        // [info] ZExt width: 64
        // (Extract w16 0 (And w64 (Or w64 (LShr w64 N0:(ZExt w64 (Extract w16 0
        // (Extract w32 0 (ZExt w64 (ReadLSB w48 0xc v0_ingress_packet_0)))))
        //                                            0x8)
        //                                  (Shl w64 N0 0x8))
        //                          0xffff))
        // [info] Extract offset: 0, width: 16
        // (And w64 (Or w64 (LShr w64 N0:(ZExt w64 (Extract w16 0 (Extract w32 0
        // (ZExt w64 (ReadLSB w48 0xc v0_ingress_packet_0)))))
        //                             0x8)
        //                   (Shl w64 N0 0x8))
        //           0xffff)
        // (Or w64 (LShr w64 N0:(ZExt w64 (Extract w16 0 (Extract w32 0 (ZExt
        // w64 (ReadLSB w48 0xc v0_ingress_packet_0)))))
        //                    0x8)
        //          (Shl w64 N0 0x8))
        // (LShr w64 (ZExt w64 (Extract w16 0 (Extract w32 0 (ZExt w64 (ReadLSB
        // w48 0xc v0_ingress_packet_0)))))
        //            0x8)
        // (ZExt w64 (Extract w16 0 (Extract w32 0 (ZExt w64 (ReadLSB w48 0xc
        // v0_ingress_packet_0))))) [info] ZExt width: 64 (Extract w16 0
        // (Extract w32 0 (ZExt w64 (ReadLSB w48 0xc v0_ingress_packet_0))))
        // [info] Extract offset: 0, width: 16 (Extract w32 0 (ZExt w64 (ReadLSB
        // w48 0xc v0_ingress_packet_0))) [info] Extract offset: 0, width: 32
        // (ZExt w64 (ReadLSB w48 0xc v0_ingress_packet_0))
        // [info] ZExt width: 64
        // (ReadLSB w48 0xc v0_ingress_packet_0)

        // TODO: Use variable `array` to create predicates and packet sets.
        // See ReadExpr::createTempRead()
        // https://mailman.ic.ac.uk/pipermail/klee-dev/2016-December/001523.html

        std::vector<klee::ref<klee::Expr>> read_exprs;
        for (int i = 0x11; i >= 0xc; --i) { // Read 6 bytes
            auto e = klee::ReadExpr::create(
                ul, klee::ConstantExpr::create(i, klee::Expr::Int32));
            read_exprs.push_back(e);
        }
        auto concat =
            klee::ConcatExpr::createN(read_exprs.size(), read_exprs.data());

        concat->dump();
        return concat;
    }
};

TEST_F(PacketSetTests, ctor) {
    auto expr = create_expr_1();
    ps::PacketSet ps(expr);

    // ps::PacketSet ps;
    // EXPECT_EQ(ps.to_string(), "(Unimplemented)");
    //
    // auto expr = klee::ConstantExpr::create(42, 32);
    // std::string expr_str;
    // expr->toString(expr_str);
    // EXPECT_EQ(expr_str, "42");
    //
    // klee::Query q(/*_constraints=*/{}, expr);
    // bool result;
    // solver->mayBeTrue(q, result);
    // EXPECT_TRUE(result);
}
