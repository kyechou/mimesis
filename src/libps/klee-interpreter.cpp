#include "libps/klee-interpreter.hpp"

#include <cstdint>
#include <functional>
#include <klee/Expr.h>
#include <klee/util/Ref.h>
#include <llvm/ADT/APInt.h>
#include <llvm/Support/Casting.h>
#include <string>
#include <unordered_map>

#include "lib/logger.hpp"
#include "libps/bitvector.hpp"

namespace ps {

const std::unordered_map<
    klee::Expr::Kind,
    std::function<BitVector(const klee::ref<klee::Expr> &)>>
    KleeInterpreter::klee_expr_transform_map = {
        {klee::Expr::Constant, translate_constant_expr},
        {klee::Expr::Read,     translate_read_expr    },
        {klee::Expr::Select,   translate_select_expr  },
        {klee::Expr::Concat,   translate_concat_expr  },
        {klee::Expr::Extract,  translate_extract_expr },
        {klee::Expr::ZExt,     translate_zext_expr    },
        {klee::Expr::SExt,     translate_sext_expr    },
        {klee::Expr::Add,      translate_add_expr     },
        {klee::Expr::Sub,      translate_sub_expr     },
        {klee::Expr::Mul,      translate_mul_expr     },
        {klee::Expr::UDiv,     translate_udiv_expr    },
        {klee::Expr::SDiv,     translate_sdiv_expr    },
        {klee::Expr::URem,     translate_urem_expr    },
        {klee::Expr::SRem,     translate_srem_expr    },
        {klee::Expr::And,      translate_and_expr     },
        {klee::Expr::Or,       translate_or_expr      },
        {klee::Expr::Xor,      translate_xor_expr     },
        {klee::Expr::Not,      translate_not_expr     },
        {klee::Expr::Shl,      translate_shl_expr     },
        {klee::Expr::LShr,     translate_lshr_expr    },
        {klee::Expr::AShr,     translate_ashr_expr    },
        {klee::Expr::Eq,       translate_eq_expr      },
        {klee::Expr::Ne,       translate_ne_expr      },
        {klee::Expr::Ult,      translate_ult_expr     },
        {klee::Expr::Ule,      translate_ule_expr     },
        {klee::Expr::Ugt,      translate_ugt_expr     },
        {klee::Expr::Uge,      translate_uge_expr     },
        {klee::Expr::Slt,      translate_slt_expr     },
        {klee::Expr::Sle,      translate_sle_expr     },
        {klee::Expr::Sgt,      translate_sgt_expr     },
        {klee::Expr::Sge,      translate_sge_expr     },
};

BitVector KleeInterpreter::translate(const klee::ref<klee::Expr> &e) {
    auto transform_func_it = klee_expr_transform_map.find(e->getKind());
    if (transform_func_it == klee_expr_transform_map.end()) {
        error("Invalid klee expr kind: " + std::to_string(e->getKind()));
    }
    return transform_func_it->second(e);
}

BitVector
KleeInterpreter::translate_constant_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ConstantExpr> &ce = llvm::cast<klee::ConstantExpr>(e);
    ce->dump();
    return ce->getAPValue();
}

BitVector KleeInterpreter::translate_read_expr(const klee::ref<klee::Expr> &e) {
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
                return translate(un->getValue());
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
    se->dump();
    return BitVector::select(translate(se->getCondition()),
                             translate(se->getTrue()),
                             translate(se->getFalse()));
}

BitVector
KleeInterpreter::translate_concat_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ConcatExpr> &ce = llvm::cast<klee::ConcatExpr>(e);
    ce->dump();
    BitVector left = translate(ce->getLeft());
    BitVector right = translate(ce->getRight());
    return left.concat(right);
}

BitVector
KleeInterpreter::translate_extract_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ExtractExpr> &ee = llvm::cast<klee::ExtractExpr>(e);
    ee->dump();
    return translate(ee->getExpr()).extract(ee->getOffset(), ee->getWidth());
}

BitVector KleeInterpreter::translate_zext_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ZExtExpr> &zee = llvm::cast<klee::ZExtExpr>(e);
    zee->dump();
    return translate(zee->getSrc()).zext(zee->getWidth());
}

BitVector KleeInterpreter::translate_sext_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SExtExpr> &see = llvm::cast<klee::SExtExpr>(e);
    see->dump();
    return translate(see->getSrc()).sext(see->getWidth());
}

BitVector KleeInterpreter::translate_add_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::AddExpr> &add = llvm::cast<klee::AddExpr>(e);
    add->dump();
    return translate(add->getLeft()).add(translate(add->getRight()));
}

BitVector KleeInterpreter::translate_sub_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SubExpr> &sub = llvm::cast<klee::SubExpr>(e);
    sub->dump();
    return translate(sub->getLeft()).sub(translate(sub->getRight()));
}

BitVector KleeInterpreter::translate_mul_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::MulExpr> &mul = llvm::cast<klee::MulExpr>(e);
    mul->dump();
    return translate(mul->getLeft()).mul(translate(mul->getRight()));
}

BitVector KleeInterpreter::translate_udiv_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::UDivExpr> &udiv = llvm::cast<klee::UDivExpr>(e);
    udiv->dump();
    BitVector remainder;
    return translate(udiv->getLeft())
        .udiv(translate(udiv->getRight()), remainder);
}

BitVector KleeInterpreter::translate_sdiv_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SDivExpr> &sdiv = llvm::cast<klee::SDivExpr>(e);
    sdiv->dump();
    BitVector remainder;
    return translate(sdiv->getLeft())
        .sdiv(translate(sdiv->getRight()), remainder);
}

BitVector KleeInterpreter::translate_urem_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::URemExpr> &urem = llvm::cast<klee::URemExpr>(e);
    urem->dump();
    BitVector remainder;
    translate(urem->getLeft()).udiv(translate(urem->getRight()), remainder);
    return remainder;
}

BitVector KleeInterpreter::translate_srem_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SRemExpr> &srem = llvm::cast<klee::SRemExpr>(e);
    srem->dump();
    BitVector remainder;
    translate(srem->getLeft()).udiv(translate(srem->getRight()), remainder);
    return remainder;
}

BitVector KleeInterpreter::translate_and_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::AndExpr> &ande = llvm::cast<klee::AndExpr>(e);
    ande->dump();
    BitVector left = translate(ande->getLeft());
    BitVector right = translate(ande->getRight());
    return left.bv_and(right);
}

BitVector KleeInterpreter::translate_or_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::OrExpr> &ore = llvm::cast<klee::OrExpr>(e);
    ore->dump();
    BitVector left = translate(ore->getLeft());
    BitVector right = translate(ore->getRight());
    return left.bv_or(right);
}

BitVector KleeInterpreter::translate_xor_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::XorExpr> &xore = llvm::cast<klee::XorExpr>(e);
    xore->dump();
    BitVector left = translate(xore->getLeft());
    BitVector right = translate(xore->getRight());
    return left.bv_xor(right);
}

BitVector KleeInterpreter::translate_not_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::NotExpr> &not_ex = llvm::cast<klee::NotExpr>(e);
    not_ex->dump();
    return translate(not_ex->getExpr()).bv_not();
}

BitVector KleeInterpreter::translate_shl_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::ShlExpr> &shl = llvm::cast<klee::ShlExpr>(e);
    shl->dump();
    BitVector left = translate(shl->getLeft());

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

BitVector KleeInterpreter::translate_lshr_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::LShrExpr> &lshr = llvm::cast<klee::LShrExpr>(e);
    lshr->dump();
    BitVector left = translate(lshr->getLeft());

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

BitVector KleeInterpreter::translate_ashr_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::AShrExpr> &ashr = llvm::cast<klee::AShrExpr>(e);
    ashr->dump();
    BitVector left = translate(ashr->getLeft());

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

BitVector KleeInterpreter::translate_eq_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::EqExpr> &eq = llvm::cast<klee::EqExpr>(e);
    eq->dump();
    // TODO: Implement
    return {};
}

BitVector KleeInterpreter::translate_ne_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::NeExpr> &ne = llvm::cast<klee::NeExpr>(e);
    ne->dump();
    // TODO: Implement
    return {};
}

BitVector KleeInterpreter::translate_ult_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::UltExpr> &ult = llvm::cast<klee::UltExpr>(e);
    ult->dump();
    // TODO: Implement
    return {};
}

BitVector KleeInterpreter::translate_ule_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::UleExpr> &ule = llvm::cast<klee::UleExpr>(e);
    ule->dump();
    BitVector left = translate(ule->getLeft());
    BitVector right = translate(ule->getRight());
    // info("left  bool vars: " + std::to_string(left.num_bdd_boolean_vars()));
    // info("right bool vars: " + std::to_string(right.num_bdd_boolean_vars()));
    return left.ule(right);
}

BitVector KleeInterpreter::translate_ugt_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::UgtExpr> &ugt = llvm::cast<klee::UgtExpr>(e);
    ugt->dump();
    // TODO: Implement
    return {};
}

BitVector KleeInterpreter::translate_uge_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::UgeExpr> &uge = llvm::cast<klee::UgeExpr>(e);
    uge->dump();
    // TODO: Implement
    return {};
}

BitVector KleeInterpreter::translate_slt_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SltExpr> &slt = llvm::cast<klee::SltExpr>(e);
    slt->dump();
    // TODO: Implement
    return {};
}

BitVector KleeInterpreter::translate_sle_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SleExpr> &sle = llvm::cast<klee::SleExpr>(e);
    sle->dump();
    // TODO: Implement
    return {};
}

BitVector KleeInterpreter::translate_sgt_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SgtExpr> &sgt = llvm::cast<klee::SgtExpr>(e);
    sgt->dump();
    // TODO: Implement
    return {};
}

BitVector KleeInterpreter::translate_sge_expr(const klee::ref<klee::Expr> &e) {
    const klee::ref<klee::SgeExpr> &sge = llvm::cast<klee::SgeExpr>(e);
    sge->dump();
    // TODO: Implement
    return {};
}

} // namespace ps
