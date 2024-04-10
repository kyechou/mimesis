#include "libps/packetset.hpp"

#include <cstdint>
#include <iostream>
#include <klee/Expr.h>
#include <klee/util/Ref.h>
#include <llvm/ADT/APInt.h>
#include <llvm/Support/Casting.h>
#include <string>
#include <sylvan_obj.hpp>

#include "lib/logger.hpp"
#include "libps/bitvector.hpp"

namespace ps {

PacketSet::PacketSet() : bdd(sylvan::Bdd::bddZero()) {}

PacketSet::PacketSet(const sylvan::Bdd &from) : bdd(from) {}

PacketSet::PacketSet(const BitVector &bv) {
    assert(bv.width() == 1);
    this->bdd = bv[0];
}

PacketSet::PacketSet(const klee::ref<klee::Expr> &expr)
    : PacketSet(bv_from_klee_expr(expr)) {}

PacketSet::PacketSet(const std::set<klee::ref<klee::Expr>> &exprs)
    : bdd(sylvan::Bdd::bddOne()) {
    std::cout << "Number of constraints: " << exprs.size() << std::endl;
    std::cout << "Constructing a packet set from constraints:" << std::endl;

    for (const auto &e : exprs) {
        std::cout << e << std::endl;
        PacketSet ps(e);
        this->bdd *= ps.bdd;
    }
}

PacketSet PacketSet::universe() {
    return sylvan::Bdd::bddOne();
}

PacketSet PacketSet::empty_set() {
    return sylvan::Bdd::bddZero();
}

bool PacketSet::empty() const {
    return this->bdd.isZero();
}

std::string PacketSet::to_string() const {
    // TODO: Implement
    // this->bdd.GetBDD();
    return "(Unimplemented)";
}

BitVector bv_from_klee_expr(const klee::ref<klee::Expr> &e) {
    auto transform_func_it = klee_expr_transform_map.find(e->getKind());
    if (transform_func_it == klee_expr_transform_map.end()) {
        error("Invalid klee expr kind: " + std::to_string(e->getKind()));
    }
    return transform_func_it->second(e);
}

BitVector bv_from_klee_constant_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ConstantExpr> &ce = llvm::cast<klee::ConstantExpr>(e);
    return ce->getAPValue();
}

BitVector bv_from_klee_read_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ReadExpr> &re = llvm::cast<klee::ReadExpr>(e);
    re->dump();
    const klee::ref<klee::Expr> &index = re->getIndex();

    if (!llvm::isa<klee::ConstantExpr>(index)) {
        // Consider `klee::ExecutionState::toConstant` to concretize the index
        // value, or construct a BDD for the symbolic index and see how many
        // possible values it can be (sat count?)
        index->dump();
        error("Symbolic array indices are not currently supported (consider "
              "concretization).");
    }

    const uint64_t array_idx =
        llvm::cast<klee::ConstantExpr>(index)->getZExtValue();

    // Evaluate the read expression.
    // See `klee::ExprEvaluator::evalRead` for reference.
    const klee::UpdateListPtr &ul = re->getUpdates();

    for (klee::UpdateNodePtr un = ul->getHead(); un; un = un->getNext()) {
        const klee::ref<klee::Expr> &ui = un->getIndex();
        if (auto cui = llvm::dyn_cast<klee::ConstantExpr>(ui)) {
            if (cui->getZExtValue() == array_idx) {
                return bv_from_klee_expr(un->getValue());
            }
        } else {
            // update node index is symbolic, which may or may not be
            // `array_idx`. This is not supported for now. Consider exploring
            // the possible values in the future.
            ui->dump();
            error("Symbolic array update node index are not currently "
                  "supported (consider concretization)");
        }
    }

    // Return the concrete byte directly if this is a concrete array.
    if (ul->getRoot()->isConstantArray() &&
        array_idx < ul->getRoot()->getSize()) {
        return bv_from_klee_constant_expr(
            ul->getRoot()->getConstantValues()[array_idx]);
    }

    // Get the indexed byte from the symbolic array.
    return BitVector(/*var_name=*/ul->getRoot()->getName(),
                     /*offset=*/array_idx * 8, /*width=*/8);
}

BitVector bv_from_klee_select_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SelectExpr> &se = llvm::cast<klee::SelectExpr>(e);
    se->dump();
    // TODO: Implement
    info("---> Select");
    return {};
}

BitVector bv_from_klee_concat_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ConcatExpr> &ce = llvm::cast<klee::ConcatExpr>(e);
    ce->dump();
    BitVector left = bv_from_klee_expr(ce->getLeft());
    BitVector right = bv_from_klee_expr(ce->getRight());
    return left.concat(right);
}

BitVector bv_from_klee_extract_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ExtractExpr> &ee = llvm::cast<klee::ExtractExpr>(e);
    ee->dump();
    BitVector src = bv_from_klee_expr(ee->getExpr());
    info("Extract offset: " + std::to_string(ee->getOffset()) +
         ", width: " + std::to_string(ee->getWidth()));
    return src.extract(ee->getOffset(), ee->getWidth());
}

BitVector bv_from_klee_zext_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ZExtExpr> &zee = llvm::cast<klee::ZExtExpr>(e);
    zee->dump();
    // TODO: Implement
    info("ZExt width: " + std::to_string(zee->getWidth()));
    return bv_from_klee_expr(zee->getSrc());
}

BitVector bv_from_klee_sext_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SExtExpr> &see = llvm::cast<klee::SExtExpr>(e);
    see->dump();
    // TODO: Implement
    return {};
}

BitVector bv_from_klee_add_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::AddExpr> &add = llvm::cast<klee::AddExpr>(e);
    add->dump();
    // TODO: Implement
    return {};
}

BitVector bv_from_klee_sub_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SubExpr> &sub = llvm::cast<klee::SubExpr>(e);
    sub->dump();
    // TODO: Implement
    return {};
}

BitVector bv_from_klee_mul_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::MulExpr> &mul = llvm::cast<klee::MulExpr>(e);
    mul->dump();
    // TODO: Implement
    return {};
}

BitVector bv_from_klee_udiv_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::UDivExpr> &udiv = llvm::cast<klee::UDivExpr>(e);
    udiv->dump();
    // TODO: Implement
    return {};
}

BitVector bv_from_klee_sdiv_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SDivExpr> &sdiv = llvm::cast<klee::SDivExpr>(e);
    sdiv->dump();
    // TODO: Implement
    return {};
}

BitVector bv_from_klee_urem_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::URemExpr> &urem = llvm::cast<klee::URemExpr>(e);
    urem->dump();
    // TODO: Implement
    return {};
}

BitVector bv_from_klee_srem_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SRemExpr> &srem = llvm::cast<klee::SRemExpr>(e);
    srem->dump();
    // TODO: Implement
    return {};
}

BitVector bv_from_klee_and_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::AndExpr> &ande = llvm::cast<klee::AndExpr>(e);
    ande->dump();
    BitVector left = bv_from_klee_expr(ande->getLeft());
    BitVector right = bv_from_klee_expr(ande->getRight());
    return left.bv_and(right);
}

BitVector bv_from_klee_or_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::OrExpr> &ore = llvm::cast<klee::OrExpr>(e);
    ore->dump();
    BitVector left = bv_from_klee_expr(ore->getLeft());
    BitVector right = bv_from_klee_expr(ore->getRight());
    return left.bv_or(right);
}

BitVector bv_from_klee_xor_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::XorExpr> &xore = llvm::cast<klee::XorExpr>(e);
    xore->dump();
    BitVector left = bv_from_klee_expr(xore->getLeft());
    BitVector right = bv_from_klee_expr(xore->getRight());
    return left.bv_or(right);
}

BitVector bv_from_klee_not_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::NotExpr> &not_ex = llvm::cast<klee::NotExpr>(e);
    not_ex->dump();
    BitVector src = bv_from_klee_expr(not_ex->getExpr());
    return src.bv_not();
}

BitVector bv_from_klee_shl_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ShlExpr> &shl = llvm::cast<klee::ShlExpr>(e);
    shl->dump();
    BitVector left = bv_from_klee_expr(shl->getLeft());

    if (!llvm::isa<klee::ConstantExpr>(shl->getRight())) {
        // Consider `klee::ExecutionState::toConstant` to concretize the shift
        // distance.
        shl->getRight()->dump();
        error("Symbolic shl distances are not currently supported (consider "
              "concretization).");
    }

    const uint64_t dist =
        llvm::cast<klee::ConstantExpr>(shl->getRight())->getZExtValue();
    return left.shl(dist);
}

BitVector bv_from_klee_lshr_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::LShrExpr> &lshr = llvm::cast<klee::LShrExpr>(e);
    lshr->dump();
    BitVector left = bv_from_klee_expr(lshr->getLeft());

    if (!llvm::isa<klee::ConstantExpr>(lshr->getRight())) {
        // Consider `klee::ExecutionState::toConstant` to concretize the shift
        // distance.
        lshr->getRight()->dump();
        error("Symbolic lshr distances are not currently supported (consider "
              "concretization).");
    }

    const uint64_t dist =
        llvm::cast<klee::ConstantExpr>(lshr->getRight())->getZExtValue();
    return left.lshr(dist);
}

BitVector bv_from_klee_ashr_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::AShrExpr> &ashr = llvm::cast<klee::AShrExpr>(e);
    ashr->dump();
    BitVector left = bv_from_klee_expr(ashr->getLeft());

    if (!llvm::isa<klee::ConstantExpr>(ashr->getRight())) {
        // Consider `klee::ExecutionState::toConstant` to concretize the shift
        // distance.
        ashr->getRight()->dump();
        error("Symbolic ashr distances are not currently supported (consider "
              "concretization).");
    }

    const uint64_t dist =
        llvm::cast<klee::ConstantExpr>(ashr->getRight())->getZExtValue();
    return left.ashr(dist);
}

BitVector bv_from_klee_eq_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::EqExpr> &eq = llvm::cast<klee::EqExpr>(e);
    eq->dump();
    // TODO: Implement
    return {};
}

BitVector bv_from_klee_ne_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::NeExpr> &ne = llvm::cast<klee::NeExpr>(e);
    ne->dump();
    // TODO: Implement
    return {};
}

BitVector bv_from_klee_ult_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::UltExpr> &ult = llvm::cast<klee::UltExpr>(e);
    ult->dump();
    // TODO: Implement
    return {};
}

BitVector bv_from_klee_ule_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::UleExpr> &ule = llvm::cast<klee::UleExpr>(e);
    ule->dump();
    BitVector left = bv_from_klee_expr(ule->getLeft());
    BitVector right = bv_from_klee_expr(ule->getRight());
    info("left  bool vars: " + std::to_string(left.num_bdd_boolean_vars()));
    info("right bool vars: " + std::to_string(right.num_bdd_boolean_vars()));
    return left.ule(right);
}

BitVector bv_from_klee_ugt_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::UgtExpr> &ugt = llvm::cast<klee::UgtExpr>(e);
    ugt->dump();
    // TODO: Implement
    return {};
}

BitVector bv_from_klee_uge_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::UgeExpr> &uge = llvm::cast<klee::UgeExpr>(e);
    uge->dump();
    // TODO: Implement
    return {};
}

BitVector bv_from_klee_slt_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SltExpr> &slt = llvm::cast<klee::SltExpr>(e);
    slt->dump();
    // TODO: Implement
    return {};
}

BitVector bv_from_klee_sle_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SleExpr> &sle = llvm::cast<klee::SleExpr>(e);
    sle->dump();
    // TODO: Implement
    return {};
}

BitVector bv_from_klee_sgt_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SgtExpr> &sgt = llvm::cast<klee::SgtExpr>(e);
    sgt->dump();
    // TODO: Implement
    return {};
}

BitVector bv_from_klee_sge_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SgeExpr> &sge = llvm::cast<klee::SgeExpr>(e);
    sge->dump();
    // TODO: Implement
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
