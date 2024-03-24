#include <gtest/gtest.h>
#include <klee/Common.h>
#include <klee/Expr.h>
#include <klee/Solver.h>
#include <klee/SolverFactory.h>
#include <string>
#include <unistd.h>

#include "libps/PacketSet.hpp"

class PacketSetTests : public testing::Test {
private:
    klee::SolverPtr solver;
    llvm::raw_ostream *out = nullptr;

protected:
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

TEST_F(PacketSetTests, ctor) {
    PacketSet ps;
    EXPECT_EQ(ps.to_string(), "(Unimplemented)");

    auto expr = klee::ConstantExpr::create(42, 32);
    std::string expr_str;
    expr->toString(expr_str);
    EXPECT_EQ(expr_str, "42");
}
