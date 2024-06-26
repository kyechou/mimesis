#include "libps/klee-interpreter.hpp"

#include <cstdint>
#include <klee/Expr.h>
#include <klee/util/Ref.h>
#include <llvm/ADT/APInt.h>
#include <llvm/Support/Casting.h>
#include <string>
#include <sylvan_obj.hpp>

#include "lib/logger.hpp"
#include "libps/bitvector.hpp"

namespace ps {

BitVector KleeInterpreter::translate(const klee::ref<klee::Expr> &e,
                                     const sylvan::Bdd &constraint) {
    if (!e) {
        return {};
    }

    switch (e->getKind()) {
    case klee::Expr::Constant:
        return translate_constant_expr(e);
    case klee::Expr::Read:
        return translate_read_expr(e, constraint);
    case klee::Expr::Select:
        return translate_select_expr(e, constraint);
    case klee::Expr::Concat:
        return translate_concat_expr(e, constraint);
    case klee::Expr::Extract:
        return translate_extract_expr(e, constraint);
    case klee::Expr::Not:
        return translate_not_expr(e, constraint);
    case klee::Expr::ZExt:
    case klee::Expr::SExt:
        return translate_cast_expr(e, constraint);
    case klee::Expr::Add:
    case klee::Expr::Sub:
    case klee::Expr::Mul:
    case klee::Expr::UDiv:
    case klee::Expr::SDiv:
    case klee::Expr::URem:
    case klee::Expr::SRem:
    case klee::Expr::And:
    case klee::Expr::Or:
    case klee::Expr::Xor:
    case klee::Expr::Shl:
    case klee::Expr::LShr:
    case klee::Expr::AShr:
    case klee::Expr::Eq:
    case klee::Expr::Ne:
    case klee::Expr::Ult:
    case klee::Expr::Ule:
    case klee::Expr::Ugt:
    case klee::Expr::Uge:
    case klee::Expr::Slt:
    case klee::Expr::Sle:
    case klee::Expr::Sgt:
    case klee::Expr::Sge:
        return translate_binary_expr(e, constraint);
    default:
        error("Invalid klee expr kind: " + std::to_string(e->getKind()));
        return {};
    }
}

BitVector
KleeInterpreter::translate_constant_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ConstantExpr> &ce = llvm::cast<klee::ConstantExpr>(e);
    return ce->getAPValue();
}

BitVector KleeInterpreter::translate_read_expr_concrete_index(
    const klee::ref<klee::ReadExpr> &e,
    const uint64_t index,
    const sylvan::Bdd &constraint) {
    // Evaluate the read expression.
    // See `klee::ExprEvaluator::evalRead` for reference.
    const klee::UpdateListPtr &ul = e->getUpdates();

    for (klee::UpdateNodePtr un = ul->getHead(); un; un = un->getNext()) {
        const klee::ref<klee::Expr> &ui = un->getIndex();
        if (auto cui = llvm::dyn_cast<klee::ConstantExpr>(ui)) {
            if (cui->getZExtValue() == index) {
                return translate(un->getValue(), constraint);
            }
        } else {
            // update node index is symbolic, which may or may not be
            // `index`. This is not supported for now. Consider exploring
            // the possible values in the future.
            error("Symbolic array update node index are not currently "
                  "supported (consider concretization)");
        }
    }

    // Return the concrete byte directly if this is a concrete array.
    if (ul->getRoot()->isConstantArray() && index < ul->getRoot()->getSize()) {
        return translate_constant_expr(
            ul->getRoot()->getConstantValues()[index]);
    }

    // Get the indexed byte from the symbolic array.
    return BitVector(/*var_name=*/ul->getRoot()->getName(),
                     /*offset=*/index * 8, /*width=*/8)
        .constrain(constraint);
}

BitVector KleeInterpreter::translate_read_expr(const klee::ref<klee::Expr> &e,
                                               const sylvan::Bdd &constraint) {
    const klee::ref<klee::ReadExpr> &re = llvm::cast<klee::ReadExpr>(e);
    const klee::ref<klee::Expr> &index = re->getIndex();

    if (auto cidx = llvm::dyn_cast<klee::ConstantExpr>(index)) {
        return translate_read_expr_concrete_index(re, cidx->getZExtValue(),
                                                  constraint);
    }

    // Symbolic array index.
    //
    // Here we explicitly enumerate all possible concrete values of the symbolic
    // index, evaluate the contrained content for each value, and then aggregate
    // the results together with a chain of `select` (`ite`) operations.
    //
    // Alternatively, we can trade soundness for performance by concretizing
    // the index to only a subset of all possible values.

    BitVector index_bv = translate(index, constraint);
    auto index_values = index_bv.valid_values();
    BitVector result;

    for (const auto &[ap_idx, constraint] : index_values) {
        BitVector content = translate_read_expr_concrete_index(
            re, ap_idx.getZExtValue(), constraint);
        if (result.empty()) {
            result = content;
        } else {
            result = ps::BitVector::select(constraint, content, result);
        }
    }

    // // Debugging use only.
    // warn("Symbolic array index:");
    // index->dump();
    // warn("Symbolic array read result:");
    // info(" --> # varbits: " + std::to_string(result.num_var_bits()));
    // info(" --> # bdd var: " + std::to_string(result.num_bdd_boolean_vars()));
    // info(" --> # nodes:   " + std::to_string(result.num_nodes()));
    // info(" --> # assign:  " + std::to_string(result.num_assignments()));
    // info(" --> # values:  " + std::to_string(result.num_valid_values()));

    return result;
}

BitVector
KleeInterpreter::translate_select_expr(const klee::ref<klee::Expr> &e,
                                       const sylvan::Bdd &constraint) {
    const klee::ref<klee::SelectExpr> &se = llvm::cast<klee::SelectExpr>(e);
    return BitVector::select(translate(se->getCondition(), constraint),
                             translate(se->getTrue(), constraint),
                             translate(se->getFalse(), constraint));
}

BitVector
KleeInterpreter::translate_concat_expr(const klee::ref<klee::Expr> &e,
                                       const sylvan::Bdd &constraint) {
    const klee::ref<klee::ConcatExpr> &ce = llvm::cast<klee::ConcatExpr>(e);
    BitVector left = translate(ce->getLeft(), constraint);
    BitVector right = translate(ce->getRight(), constraint);
    return left.concat(right);
}

BitVector
KleeInterpreter::translate_extract_expr(const klee::ref<klee::Expr> &e,
                                        const sylvan::Bdd &constraint) {
    const klee::ref<klee::ExtractExpr> &ee = llvm::cast<klee::ExtractExpr>(e);
    BitVector src = translate(ee->getExpr(), constraint);
    return src.extract(ee->getOffset(), ee->getWidth());
}

BitVector KleeInterpreter::translate_not_expr(const klee::ref<klee::Expr> &e,
                                              const sylvan::Bdd &constraint) {
    const klee::ref<klee::NotExpr> &not_ex = llvm::cast<klee::NotExpr>(e);
    return translate(not_ex->getExpr(), constraint).bv_not();
}

BitVector KleeInterpreter::translate_cast_expr(const klee::ref<klee::Expr> &e,
                                               const sylvan::Bdd &constraint) {
    const klee::ref<klee::CastExpr> &cast = llvm::cast<klee::CastExpr>(e);
    BitVector src = translate(cast->getSrc(), constraint);
    klee::Expr::Width width = cast->getWidth();

    switch (cast->getKind()) {
    case klee::Expr::ZExt:
        return src.zext(width);
    case klee::Expr::SExt:
        return src.sext(width);
    default:
        error("Invalid cast expr kind: " + std::to_string(e->getKind()));
        return {};
    }
}

BitVector
KleeInterpreter::translate_binary_expr(const klee::ref<klee::Expr> &e,
                                       const sylvan::Bdd &constraint) {
    const klee::ref<klee::BinaryExpr> &bin = llvm::cast<klee::BinaryExpr>(e);
    BitVector left = translate(bin->getLeft(), constraint);
    BitVector right = translate(bin->getRight(), constraint);

    switch (bin->getKind()) {
    case klee::Expr::Add:
        return left.add(right);
    case klee::Expr::Sub:
        return left.sub(right);
    case klee::Expr::Mul:
        return left.mul(right);
    case klee::Expr::UDiv:
        return left.udiv(right);
    case klee::Expr::SDiv:
        return left.sdiv(right);
    case klee::Expr::URem:
        return left.urem(right);
    case klee::Expr::SRem:
        return left.srem(right);
    case klee::Expr::And:
        return left.bv_and(right);
    case klee::Expr::Or:
        return left.bv_or(right);
    case klee::Expr::Xor:
        return left.bv_xor(right);
    case klee::Expr::Shl:
        return left.shl(right);
    case klee::Expr::LShr:
        return left.lshr(right);
    case klee::Expr::AShr:
        return left.ashr(right);
    case klee::Expr::Eq:
        return left.eq(right);
    case klee::Expr::Ne:
        return left.ne(right);
    case klee::Expr::Ult:
        return left.ult(right);
    case klee::Expr::Ule:
        return left.ule(right);
    case klee::Expr::Ugt:
        return left.ugt(right);
    case klee::Expr::Uge:
        return left.uge(right);
    case klee::Expr::Slt:
        return left.slt(right);
    case klee::Expr::Sle:
        return left.sle(right);
    case klee::Expr::Sgt:
        return left.sgt(right);
    case klee::Expr::Sge:
        return left.sge(right);
    default:
        error("Invalid binary expr kind: " + std::to_string(e->getKind()));
        return {};
    }
}

} // namespace ps
