#ifndef LIBPS_KLEE_INTERPRETER_HPP
#define LIBPS_KLEE_INTERPRETER_HPP

#include <functional>
#include <klee/Expr.h>
#include <klee/util/Ref.h>
#include <unordered_map>

#include "libps/bitvector.hpp"

namespace ps {

class KleeInterpreter {
private:
    static const std::unordered_map<
        klee::Expr::Kind,
        std::function<BitVector(const klee::ref<klee::Expr> &)>>
        klee_expr_transform_map;

    static BitVector translate_constant_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_read_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_select_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_concat_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_extract_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_zext_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_sext_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_add_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_sub_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_mul_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_udiv_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_sdiv_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_urem_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_srem_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_and_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_or_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_xor_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_not_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_shl_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_lshr_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_ashr_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_eq_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_ne_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_ult_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_ule_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_ugt_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_uge_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_slt_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_sle_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_sgt_expr(const klee::ref<klee::Expr> &);
    static BitVector translate_sge_expr(const klee::ref<klee::Expr> &);

public:
    static BitVector translate(const klee::ref<klee::Expr> &);
};

} // namespace ps

#endif // LIBPS_KLEE_INTERPRETER_HPP
