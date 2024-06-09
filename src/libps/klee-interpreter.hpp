#ifndef LIBPS_KLEE_INTERPRETER_HPP
#define LIBPS_KLEE_INTERPRETER_HPP

#include <klee/Expr.h>
#include <klee/util/Ref.h>

#include "libps/bitvector.hpp"

namespace ps {

class KleeInterpreter {
private:
    static BitVector translate_constant_expr(const klee::ref<klee::Expr> &e);
    static BitVector translate_read_expr_concrete_index(
        const klee::ref<klee::ReadExpr> &e,
        const uint64_t index,
        const sylvan::Bdd &constraint = sylvan::Bdd::bddOne());
    static BitVector translate_read_expr(const klee::ref<klee::Expr> &e);
    static BitVector translate_select_expr(const klee::ref<klee::Expr> &e);
    static BitVector translate_concat_expr(const klee::ref<klee::Expr> &e);
    static BitVector translate_extract_expr(const klee::ref<klee::Expr> &e);
    static BitVector translate_not_expr(const klee::ref<klee::Expr> &e);
    static BitVector translate_cast_expr(const klee::ref<klee::Expr> &e);
    static BitVector translate_binary_expr(const klee::ref<klee::Expr> &e);

public:
    static BitVector translate(const klee::ref<klee::Expr> &e);
};

} // namespace ps

#endif // LIBPS_KLEE_INTERPRETER_HPP
