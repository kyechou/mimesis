#ifndef LIBPS_PACKETSET_HPP
#define LIBPS_PACKETSET_HPP

#include <functional>
#include <klee/Expr.h>
#include <klee/util/Ref.h>
#include <llvm/ADT/APInt.h>
#include <set>
#include <string>
#include <sylvan_obj.hpp>
#include <unordered_map>

#include "libps/bitvector.hpp"

namespace ps {

class PacketSet {
private:
    sylvan::Bdd bdd;

public:
    /**
     * Construct the empty packet set by default.
     */
    PacketSet();
    PacketSet(const PacketSet &) = default;
    PacketSet(const sylvan::Bdd &);
    PacketSet(const klee::ref<klee::Expr> &);
    PacketSet(const std::set<klee::ref<klee::Expr>> &);

    /**
     * Construct the universe packet set that contains all packets.
     */
    static PacketSet universe();

    /**
     * Construct the empty packet set that contains no packet.
     */
    static PacketSet empty_set();

    bool empty() const;
    std::string to_string() const;
};

BitVector bv_from_klee_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_constant_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_read_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_select_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_concat_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_extract_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_zext_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_sext_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_add_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_sub_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_mul_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_udiv_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_sdiv_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_urem_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_srem_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_and_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_or_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_xor_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_not_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_shl_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_lshr_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_ashr_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_eq_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_ne_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_ult_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_ule_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_ugt_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_uge_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_slt_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_sle_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_sgt_expr(const klee::ref<klee::Expr> &);
BitVector bv_from_klee_sge_expr(const klee::ref<klee::Expr> &);

const std::unordered_map<
    klee::Expr::Kind,
    std::function<BitVector(const klee::ref<klee::Expr> &)>>
    klee_expr_transform_map = {
        {klee::Expr::Constant, bv_from_klee_constant_expr},
        {klee::Expr::Read,     bv_from_klee_read_expr    },
        {klee::Expr::Select,   bv_from_klee_select_expr  },
        {klee::Expr::Concat,   bv_from_klee_concat_expr  },
        {klee::Expr::Extract,  bv_from_klee_extract_expr },
        {klee::Expr::ZExt,     bv_from_klee_zext_expr    },
        {klee::Expr::SExt,     bv_from_klee_sext_expr    },
        {klee::Expr::Add,      bv_from_klee_add_expr     },
        {klee::Expr::Sub,      bv_from_klee_sub_expr     },
        {klee::Expr::Mul,      bv_from_klee_mul_expr     },
        {klee::Expr::UDiv,     bv_from_klee_udiv_expr    },
        {klee::Expr::SDiv,     bv_from_klee_sdiv_expr    },
        {klee::Expr::URem,     bv_from_klee_urem_expr    },
        {klee::Expr::SRem,     bv_from_klee_srem_expr    },
        {klee::Expr::And,      bv_from_klee_and_expr     },
        {klee::Expr::Or,       bv_from_klee_or_expr      },
        {klee::Expr::Xor,      bv_from_klee_xor_expr     },
        {klee::Expr::Not,      bv_from_klee_not_expr     },
        {klee::Expr::Shl,      bv_from_klee_shl_expr     },
        {klee::Expr::LShr,     bv_from_klee_lshr_expr    },
        {klee::Expr::AShr,     bv_from_klee_ashr_expr    },
        {klee::Expr::Eq,       bv_from_klee_eq_expr      },
        {klee::Expr::Ne,       bv_from_klee_ne_expr      },
        {klee::Expr::Ult,      bv_from_klee_ult_expr     },
        {klee::Expr::Ule,      bv_from_klee_ule_expr     },
        {klee::Expr::Ugt,      bv_from_klee_ugt_expr     },
        {klee::Expr::Uge,      bv_from_klee_uge_expr     },
        {klee::Expr::Slt,      bv_from_klee_slt_expr     },
        {klee::Expr::Sle,      bv_from_klee_sle_expr     },
        {klee::Expr::Sgt,      bv_from_klee_sgt_expr     },
        {klee::Expr::Sge,      bv_from_klee_sge_expr     },
};

} // namespace ps

#endif // LIBPS_PACKETSET_HPP
