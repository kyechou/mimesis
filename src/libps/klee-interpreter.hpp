#ifndef LIBPS_KLEE_INTERPRETER_HPP
#define LIBPS_KLEE_INTERPRETER_HPP

#include <klee/Expr.h>
#include <klee/util/Ref.h>

#include "libps/bitvector.hpp"

namespace ps {

class KleeInterpreter {
private:
    static BitVector translate_constant_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_read_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_select_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_concat_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_extract_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_not_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_cast_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_binary_expr(const klee::ref<klee::Expr> &);

public:
    static BitVector translate(const klee::ref<klee::Expr> &);
};

} // namespace ps

#endif // LIBPS_KLEE_INTERPRETER_HPP
