#include "libps/packetset.hpp"

#include <iostream>
#include <klee/Expr.h>
#include <klee/util/Ref.h>
#include <llvm/ADT/APInt.h>
#include <llvm/Support/Casting.h>
#include <string>
#include <sylvan_obj.hpp>
#include <variant>

#include "lib/logger.hpp"
#include "libps/manager.hpp"

namespace ps {

PacketSet::PacketSet() : bdd(sylvan::Bdd::bddZero()) {}

PacketSet::PacketSet(const sylvan::Bdd &from) : bdd(from) {}

PacketSet::PacketSet(const klee::ref<klee::Expr> &expr)
    : bdd(bdd_from_klee_expr(expr)) {}

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

llvm::APInt apint_from_klee_constant_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ConstantExpr> &ce = llvm::cast<klee::ConstantExpr>(e);
    return ce->getAPValue();
}

sylvan::Bdd bdd_from_klee_expr(const klee::ref<klee::Expr> &e) {
    auto transform_func_it = klee_expr_transform_map.find(e->getKind());
    if (transform_func_it == klee_expr_transform_map.end()) {
        error("Invalid klee expr kind: " + std::to_string(e->getKind()));
    }
    return transform_func_it->second(e);
}

sylvan::Bdd bdd_from_klee_constant_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ConstantExpr> &ce = llvm::cast<klee::ConstantExpr>(e);
    if (ce->isZero()) {
        return sylvan::Bdd::bddZero(); // empty set
    } else {
        return sylvan::Bdd::bddOne(); // universe
    }
}

/**
 * See `klee::ExprEvaluator::visitRead` and `klee::ExprEvaluator::evalRead`.
 */
sylvan::Bdd bdd_from_klee_read_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ReadExpr> &re = llvm::cast<klee::ReadExpr>(e);
    re->dump();
    const klee::ref<klee::Expr> &index = re->getIndex();
    const klee::ref<klee::ConstantExpr> &concrete_idx =
        llvm::dyn_cast<klee::ConstantExpr>(index);

    if (!concrete_idx) {
        // Consider `klee::ExecutionState::toConstant` to concretize the index
        // value, or construct a BDD for the symbolic index and see how many
        // possible values it can be (sat count?)
        index->dump();
        error("Non-constant array indices are not currently supported "
              "(consider concretization).");
    }

    // Evaluate the read expression.
    // See `klee::ExprEvaluator::evalRead` for reference.
    const klee::UpdateListPtr &ul = re->getUpdates();

    for (klee::UpdateNodePtr un = ul->getHead(); un; un = un->getNext()) {
        const klee::ref<klee::Expr> &ui = un->getIndex();
        if (auto cui = llvm::dyn_cast<klee::ConstantExpr>(ui)) {
            if (cui->getZExtValue() == concrete_idx->getZExtValue()) {
                return bdd_from_klee_expr(un->getValue());
            }
        } else {
            // update node index is symbolic, which may or may not be
            // `concrete_idx`. We are not supporting this for now. Consider
            // explore the possible values in the future.
            ui->dump();
            error("Non-constant array update node index are not currently "
                  "supported (consider concretization)");
        }
    }

    // Return the concrete byte directly if this is a concrete array.
    if (ul->getRoot()->isConstantArray() &&
        concrete_idx->getZExtValue() < ul->getRoot()->getSize()) {
        // TODO: We may not want to convert the ConstantExpr to Bdd here, but
        // return the ConstantExpr directly instead.
        return bdd_from_klee_constant_expr(
            ul->getRoot()->getConstantValues()[concrete_idx->getZExtValue()]);
    }

    // TODO: Get the symbolic bit-vector byte.
    // auto [start_idx, len] = ps::Manager::get().get_variable_offset(var_name);
    auto [start_idx, len] =
        ps::Manager::get().get_variable_offset(ul->getRoot()->getName());
    info(ul->getRoot()->getName() + " :: starting bit-index: " +
         std::to_string(start_idx) + ", len: " + std::to_string(len));
    info("Concrete array (byte) index: " +
         std::to_string(concrete_idx->getZExtValue()));

    return {};
}

sylvan::Bdd bdd_from_klee_select_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SelectExpr> &se = llvm::cast<klee::SelectExpr>(e);
    se->dump();
    info("---> Select");
    return {};
}

sylvan::Bdd bdd_from_klee_concat_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ConcatExpr> &ce = llvm::cast<klee::ConcatExpr>(e);
    ce->dump();
    info("Concat width: " + std::to_string(ce->getWidth()));
    info("Concat left width: " + std::to_string(ce->getLeft()->getWidth()));
    info("Concat right width: " + std::to_string(ce->getRight()->getWidth()));
    bdd_from_klee_expr(ce->getLeft());
    bdd_from_klee_expr(ce->getRight());
    // error("TODO: Implement");
    return {};
}

sylvan::Bdd bdd_from_klee_extract_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ExtractExpr> &ee = llvm::cast<klee::ExtractExpr>(e);
    ee->dump();
    info("Extract offset: " + std::to_string(ee->getOffset()) +
         ", width: " + std::to_string(ee->getWidth()));
    return bdd_from_klee_expr(ee->getExpr());
}

sylvan::Bdd bdd_from_klee_zext_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ZExtExpr> &zee = llvm::cast<klee::ZExtExpr>(e);
    zee->dump();
    info("ZExt width: " + std::to_string(zee->getWidth()));
    return bdd_from_klee_expr(zee->getSrc());
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

/**
 * And, Or, Xor, Not may be used as (1) Boolean logical operations or (2)
 * bit-vector, bitwise operations.
 * IIRC, BDD operations are all Boolean logical operations, so we need to
 * implement the bitwise operations ourselves by recursively applying the
 * transformation.
 */

sylvan::Bdd bdd_from_klee_and_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::AndExpr> &ande = llvm::cast<klee::AndExpr>(e);
    ande->dump();

    // Construct the left and right operands.
    sylvan::Bdd left_bdd = bdd_from_klee_expr(ande->getLeft());
    sylvan::Bdd right_bdd = bdd_from_klee_expr(ande->getRight());

    // TODO: Make sure the bitwidths of both operands are consistent.

    // TODO: Apply the binary transformation recursively.
    // return bdd_apply(klee::Expr::Kind::And, left, right); // recursive call

    return {};
}

sylvan::Bdd bdd_from_klee_or_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::OrExpr> &ore = llvm::cast<klee::OrExpr>(e);
    ore->dump();

    // Construct the left and right operands.
    sylvan::Bdd left_bdd = bdd_from_klee_expr(ore->getLeft());
    sylvan::Bdd right_bdd = bdd_from_klee_expr(ore->getRight());

    // TODO: Make sure the bitwidths of both operands are consistent.

    // TODO: Apply the binary transformation recursively.
    // return bdd_apply(klee::Expr::Kind::Or, left, right); // recursive call

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

/**
 * Logical shift right (zero fill)
 * E.g., `lshr i32 0b100, 1` yields 0b010
 * See https://llvm.org/docs/LangRef.html#lshr-instruction
 */
sylvan::Bdd bdd_from_klee_lshr_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::LShrExpr> &lshr = llvm::cast<klee::LShrExpr>(e);
    lshr->dump();

    // Construct the left and right operands.
    sylvan::Bdd left_bdd = bdd_from_klee_expr(lshr->getLeft());
    const klee::ref<klee::Expr> &shift_dist = lshr->getRight();
    const klee::ref<klee::ConstantExpr> &cshift_dist =
        llvm::dyn_cast<klee::ConstantExpr>(shift_dist);
    // sylvan::Bdd right_bdd = bdd_from_klee_expr(lshr->getRight());

    // Here we only support the right operand (op2) to be concrete for now.
    if (!cshift_dist) {
        // TODO(FUTURE): Consider `klee::ExecutionState::toConstant` to
        // concretize the value
        shift_dist->dump();
        error("Non-constant lshr distances are not currently handled "
              "(consider concretization).");
    }

    // TODO
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
    ule->dump();

    // Construct the left and right operands.
    std::variant<llvm::APInt, sylvan::Bdd> left, right;
    unsigned int left_bitwidth [[maybe_unused]] = 0,
                               right_bitwidth [[maybe_unused]] = 0;

    if (ule->getLeft()->getKind() == klee::Expr::Kind::Constant) {
        left = apint_from_klee_constant_expr(ule->getLeft());
        auto &apint = std::get<llvm::APInt>(left);
        left_bitwidth = apint.getBitWidth();
    } else {
        left = bdd_from_klee_expr(ule->getLeft());
        auto &bdd = std::get<sylvan::Bdd>(left);

        // DEBUG
        info("left bdd node count: " + std::to_string(bdd.NodeCount()));
    }

    if (ule->getRight()->getKind() == klee::Expr::Kind::Constant) {
        right = apint_from_klee_constant_expr(ule->getRight());
    } else {
        right = bdd_from_klee_expr(ule->getRight());
    }

    // TODO: Make sure the bitwidths of both operands are consistent.

    // if (left.max() <= right.min()) {
    //     return T(1);
    // } else if (left.min() > right.max()) {
    //     return T(0);
    // }

    // TODO: Apply the binary transformation recursively.
    // return bdd_apply(klee::Expr::Kind::Ule, left, right); // recursive call
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
