#include "libps/klee-interpreter.hpp"

#include <cstdint>
#include <klee/Expr.h>
#include <klee/util/Ref.h>
#include <llvm/ADT/APInt.h>
#include <llvm/Support/Casting.h>
#include <string>

#include "lib/logger.hpp"
#include "libps/bitvector.hpp"

namespace ps {

BitVector KleeInterpreter::translate(const klee::ref<klee::Expr> &e) {
    switch (e->getKind()) {
    case klee::Expr::Constant:
        return translate_constant_expr(e);
    case klee::Expr::Read:
        return translate_read_expr(e);
    case klee::Expr::Select:
        return translate_select_expr(e);
    case klee::Expr::Concat:
        return translate_concat_expr(e);
    case klee::Expr::Extract:
        return translate_extract_expr(e);
    case klee::Expr::Not:
        return translate_not_expr(e);
    case klee::Expr::ZExt:
    case klee::Expr::SExt:
        return translate_cast_expr(e);
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
        return translate_binary_expr(e);
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

BitVector KleeInterpreter::translate_read_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ReadExpr> &re = llvm::cast<klee::ReadExpr>(e);
    const klee::ref<klee::Expr> &index = re->getIndex();

    if (!llvm::isa<klee::ConstantExpr>(index)) {
        // Consider `klee::ExecutionState::toConstant` to concretize the index
        // value, or construct a BDD for the symbolic index and see how many
        // possible values it can be (sat count?)
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
                return translate(un->getValue());
            }
        } else {
            // update node index is symbolic, which may or may not be
            // `array_idx`. This is not supported for now. Consider exploring
            // the possible values in the future.
            error("Symbolic array update node index are not currently "
                  "supported (consider concretization)");
        }
    }

    // Return the concrete byte directly if this is a concrete array.
    if (ul->getRoot()->isConstantArray() &&
        array_idx < ul->getRoot()->getSize()) {
        return translate_constant_expr(
            ul->getRoot()->getConstantValues()[array_idx]);
    }

    // Get the indexed byte from the symbolic array.
    return BitVector(/*var_name=*/ul->getRoot()->getName(),
                     /*offset=*/array_idx * 8, /*width=*/8);
}

BitVector
KleeInterpreter::translate_select_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SelectExpr> &se = llvm::cast<klee::SelectExpr>(e);
    return BitVector::select(translate(se->getCondition()),
                             translate(se->getTrue()),
                             translate(se->getFalse()));
}

BitVector
KleeInterpreter::translate_concat_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ConcatExpr> &ce = llvm::cast<klee::ConcatExpr>(e);
    BitVector left = translate(ce->getLeft());
    BitVector right = translate(ce->getRight());
    return left.concat(right);
}

BitVector
KleeInterpreter::translate_extract_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ExtractExpr> &ee = llvm::cast<klee::ExtractExpr>(e);
    BitVector src = translate(ee->getExpr());
    return src.extract(ee->getOffset(), ee->getWidth());
}

BitVector KleeInterpreter::translate_not_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::NotExpr> &not_ex = llvm::cast<klee::NotExpr>(e);
    return translate(not_ex->getExpr()).bv_not();
}

BitVector KleeInterpreter::translate_cast_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::CastExpr> &cast = llvm::cast<klee::CastExpr>(e);
    BitVector src = translate(cast->getSrc());
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
KleeInterpreter::translate_binary_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::BinaryExpr> &bin = llvm::cast<klee::BinaryExpr>(e);
    BitVector left = translate(bin->getLeft());
    BitVector right = translate(bin->getRight());

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
