#include <gtest/gtest.h>
#include <klee/Common.h>
#include <klee/Constraints.h>
#include <klee/Expr.h>
#include <klee/Solver.h>
#include <klee/SolverFactory.h>
#include <llvm/Support/raw_ostream.h>
#include <string>
#include <unistd.h>

#include "libps/packetset.hpp"

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

TEST_F(PacketSetTests, ctor) {
    ps::PacketSet ps;
    EXPECT_EQ(ps.to_string(), "(Unimplemented)");

    auto expr = klee::ConstantExpr::create(42, 32);
    std::string expr_str;
    expr->toString(expr_str);
    EXPECT_EQ(expr_str, "42");

    klee::Query q(/*_constraints=*/{}, expr);
    bool result;
    solver->mayBeTrue(q, result);
    EXPECT_TRUE(result);
}
