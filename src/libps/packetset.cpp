#include "libps/packetset.hpp"

#include <iostream>
#include <klee/Expr.h>
#include <klee/util/Ref.h>
#include <llvm/Support/Casting.h>
#include <string>
#include <sylvan_obj.hpp>

#include "lib/logger.hpp"

namespace ps {

PacketSet::PacketSet() : bdd(sylvan::Bdd::bddZero()) {}

PacketSet::PacketSet(const sylvan::Bdd &from) : bdd(from) {}

PacketSet::PacketSet(const klee::ref<klee::Expr> &expr) {
    auto transform_func_it = klee_expr_transform_map.find(expr->getKind());
    if (transform_func_it == klee_expr_transform_map.end()) {
        error("Invalid klee expr kind " + std::to_string(expr->getKind()));
    }
    bdd = transform_func_it->second(expr);
}

PacketSet::PacketSet(const std::set<klee::ref<klee::Expr>> &exprs)
    : bdd(sylvan::Bdd::bddOne()) {
    std::cout << "Number of constraints: " << exprs.size() << std::endl;
    std::cout << "Constructing a packet set from constraints:" << std::endl;

    for (const auto &e : exprs) {
        std::cout << e << std::endl;
        PacketSet ps(e);
        bdd *= ps.bdd;
    }
}

PacketSet PacketSet::universe() {
    return sylvan::Bdd::bddOne();
}

PacketSet PacketSet::empty_set() {
    return sylvan::Bdd::bddZero();
}

// PacketSet PacketSet::intersect(const PacketSet &ps [[maybe_unused]]) const {
//     return *this;
// }

bool PacketSet::empty() const {
    return bdd.isZero();
}

std::string PacketSet::to_string() const {
    // TODO: Implement
    // bdd.GetBDD();
    return "(Unimplemented)";
}

sylvan::Bdd bdd_from_klee_constant_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ConstantExpr> &ce = llvm::cast<klee::ConstantExpr>(e);
    if (ce->isZero()) {
        return sylvan::Bdd::bddZero(); // empty set
    } else {
        return sylvan::Bdd::bddOne(); // universe
    }
}

sylvan::Bdd bdd_from_klee_read_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ReadExpr> &re = llvm::cast<klee::ReadExpr>(e);
    const klee::ref<klee::Expr> &index = re->getIndex();
    const klee::ref<klee::ConstantExpr> &cidx =
        llvm::dyn_cast<klee::ConstantExpr>(index);

    if (!cidx) {
        // TODO(FUTURE): Consider `klee::ExecutionState::toConstant` to
        // concretize the index value
        index->dump();
        error("Non-constant array indices are not currently handled "
              "(consider concretization).");
    }

    error("TODO: Implement");
    // cidx->getAPValue().isSignedIntN(0);
    // re->getUpdates();
    return {};
}

sylvan::Bdd bdd_from_klee_select_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SelectExpr> &se = llvm::cast<klee::SelectExpr>(e);
    se->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_concat_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ConcatExpr> &ce = llvm::cast<klee::ConcatExpr>(e);
    ce->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_extract_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ExtractExpr> &ee = llvm::cast<klee::ExtractExpr>(e);
    ee->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_zext_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ZExtExpr> &zee = llvm::cast<klee::ZExtExpr>(e);
    zee->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_sext_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SExtExpr> &see = llvm::cast<klee::SExtExpr>(e);
    see->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_add_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::AddExpr> &add = llvm::cast<klee::AddExpr>(e);
    add->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_sub_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SubExpr> &sub = llvm::cast<klee::SubExpr>(e);
    sub->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_mul_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::MulExpr> &mul = llvm::cast<klee::MulExpr>(e);
    mul->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_udiv_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::UDivExpr> &udiv = llvm::cast<klee::UDivExpr>(e);
    udiv->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_sdiv_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SDivExpr> &sdiv = llvm::cast<klee::SDivExpr>(e);
    sdiv->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_urem_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::URemExpr> &urem = llvm::cast<klee::URemExpr>(e);
    urem->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_srem_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SRemExpr> &srem = llvm::cast<klee::SRemExpr>(e);
    srem->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_and_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::AndExpr> &ande = llvm::cast<klee::AndExpr>(e);
    ande->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_or_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::OrExpr> &ore = llvm::cast<klee::OrExpr>(e);
    ore->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_xor_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::XorExpr> &xore = llvm::cast<klee::XorExpr>(e);
    xore->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_not_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::NotExpr> &not_ex = llvm::cast<klee::NotExpr>(e);
    not_ex->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_shl_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ShlExpr> &shl = llvm::cast<klee::ShlExpr>(e);
    shl->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_lshr_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::LShrExpr> &lshr = llvm::cast<klee::LShrExpr>(e);
    lshr->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_ashr_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::AShrExpr> &ashr = llvm::cast<klee::AShrExpr>(e);
    ashr->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_eq_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::EqExpr> &eq = llvm::cast<klee::EqExpr>(e);
    eq->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_ne_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::NeExpr> &ne = llvm::cast<klee::NeExpr>(e);
    ne->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_ult_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::UltExpr> &ult = llvm::cast<klee::UltExpr>(e);
    ult->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_ule_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::UleExpr> &ule = llvm::cast<klee::UleExpr>(e);
    info("bdd_from_klee_ule_expr: Unsigned Less than or Equal to");
    ule->dump();

    // TODO

    return {};
}

sylvan::Bdd bdd_from_klee_ugt_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::UgtExpr> &ugt = llvm::cast<klee::UgtExpr>(e);
    ugt->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_uge_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::UgeExpr> &uge = llvm::cast<klee::UgeExpr>(e);
    uge->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_slt_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SltExpr> &slt = llvm::cast<klee::SltExpr>(e);
    slt->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_sle_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SleExpr> &sle = llvm::cast<klee::SleExpr>(e);
    sle->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_sgt_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SgtExpr> &sgt = llvm::cast<klee::SgtExpr>(e);
    sgt->dump();
    return {};
}

sylvan::Bdd bdd_from_klee_sge_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SgeExpr> &sge = llvm::cast<klee::SgeExpr>(e);
    sge->dump();
    return {};
}

} // namespace ps

// See third_party/sylvan/sylvan/examples/simple.cpp

// Maybe useful functions:
//
// mtbdd_satcount(bdd, number_of_vars): compute the number of minterms
// (assignments that lead to True) for a function with <number_of_vars>
// variables; we don’t need to know the exact variables that may be in the BDD,
// just how many there are.
//
// sylvan_pathcount(bdd): compute the number of distinct paths to True.
//
// mtbdd_nodecount(bdd): compute the number of nodes (and leaves) in the BDD.
//
// mtbdd_nodecount_more(array, length): compute the number of nodes (and leaves)
// in the array of BDDs.
