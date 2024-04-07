#include <gtest/gtest.h>
#include <klee/Common.h>
#include <klee/Constraints.h>
#include <klee/Expr.h>
#include <klee/Solver.h>
#include <klee/SolverFactory.h>
#include <llvm/Support/raw_ostream.h>
#include <string>
#include <unistd.h>

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

    void SetUp() override {
        out = new llvm::raw_fd_ostream(/*fd=*/STDOUT_FILENO,
                                       /*shouldClose=*/false);
        klee::klee_message_stream = out;
        klee::klee_warning_stream = out;

        auto factory = klee::DefaultSolverFactory::create(".");
        klee::SolverPtr endSolver = factory->createEndSolver();
        solver = factory->decorateSolver(endSolver);
    }

    void TearDown() override {
        delete out;
        out = nullptr;
        klee::klee_message_stream = nullptr;
        klee::klee_warning_stream = nullptr;
    }
};

// (Ule (ZExt w64 (Extract w16 0 (And w64 (Or w64 (LShr w64 N0:(ZExt w64
// (Extract w16 0 (Extract w32 0 (ZExt w64 (ReadLSB w48 0xc
// v0_ingress_packet_0)))))
//                                                           0x8)
//                                                 (Shl w64 N0 0x8))
//                                         0xffff)))
//       0x5ff)

TEST_F(PacketSetTests, ctor) {
    ps::Manager::get().init(/*n_workers=*/1,
                            /*memory_cap=*/1UL * 1024 * 1024 * 1024,
                            /*table_ratio=*/1,
                            /*initial_ratio=*/5);
    const std::string var_name = "packet";
    ps::Manager::get().register_symbolic_variable(
        var_name, /*nbits=*/sizeof(struct DemoHeader) * 8);

    klee::ArrayPtr array =
        klee::Array::create(var_name, sizeof(struct DemoHeader));
    klee::UpdateListPtr update_list = klee::UpdateList::create(array, 0);

    // TODO: Use variable `array` to create predicates and packet sets.
    // See ReadExpr::createTempRead()
    // https://mailman.ic.ac.uk/pipermail/klee-dev/2016-December/001523.html

    // auto array = Array::create(sname, size, nullptr, nullptr, name);
    // auto ul = UpdateList::create(array, 0);
    //
    // std::vector<ref<Expr>> result;
    // result.reserve(size);
    // for (unsigned i = 0; i < size; ++i) {
    //     result.push_back(ReadExpr::create(ul, ConstantExpr::alloc(i,
    //     Expr::Int32)));
    // }

    // auto [start_idx, len] = ps::Manager::get().get_variable_offset(var_name);

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
