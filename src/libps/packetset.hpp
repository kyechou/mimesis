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

llvm::APInt apint_from_klee_constant_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_constant_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_read_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_select_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_concat_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_extract_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_zext_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_sext_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_add_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_sub_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_mul_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_udiv_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_sdiv_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_urem_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_srem_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_and_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_or_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_xor_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_not_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_shl_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_lshr_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_ashr_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_eq_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_ne_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_ult_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_ule_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_ugt_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_uge_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_slt_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_sle_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_sgt_expr(const klee::ref<klee::Expr> &);
sylvan::Bdd bdd_from_klee_sge_expr(const klee::ref<klee::Expr> &);

const std::unordered_map<
    klee::Expr::Kind,
    std::function<sylvan::Bdd(const klee::ref<klee::Expr> &)>>
    klee_expr_transform_map = {
        {klee::Expr::Constant, bdd_from_klee_constant_expr},
        {klee::Expr::Read,     bdd_from_klee_read_expr    },
        {klee::Expr::Select,   bdd_from_klee_select_expr  },
        {klee::Expr::Concat,   bdd_from_klee_concat_expr  },
        {klee::Expr::Extract,  bdd_from_klee_extract_expr },
        {klee::Expr::ZExt,     bdd_from_klee_zext_expr    },
        {klee::Expr::SExt,     bdd_from_klee_sext_expr    },
        {klee::Expr::Add,      bdd_from_klee_add_expr     },
        {klee::Expr::Sub,      bdd_from_klee_sub_expr     },
        {klee::Expr::Mul,      bdd_from_klee_mul_expr     },
        {klee::Expr::UDiv,     bdd_from_klee_udiv_expr    },
        {klee::Expr::SDiv,     bdd_from_klee_sdiv_expr    },
        {klee::Expr::URem,     bdd_from_klee_urem_expr    },
        {klee::Expr::SRem,     bdd_from_klee_srem_expr    },
        {klee::Expr::And,      bdd_from_klee_and_expr     },
        {klee::Expr::Or,       bdd_from_klee_or_expr      },
        {klee::Expr::Xor,      bdd_from_klee_xor_expr     },
        {klee::Expr::Not,      bdd_from_klee_not_expr     },
        {klee::Expr::Shl,      bdd_from_klee_shl_expr     },
        {klee::Expr::LShr,     bdd_from_klee_lshr_expr    },
        {klee::Expr::AShr,     bdd_from_klee_ashr_expr    },
        {klee::Expr::Eq,       bdd_from_klee_eq_expr      },
        {klee::Expr::Ne,       bdd_from_klee_ne_expr      },
        {klee::Expr::Ult,      bdd_from_klee_ult_expr     },
        {klee::Expr::Ule,      bdd_from_klee_ule_expr     },
        {klee::Expr::Ugt,      bdd_from_klee_ugt_expr     },
        {klee::Expr::Uge,      bdd_from_klee_uge_expr     },
        {klee::Expr::Slt,      bdd_from_klee_slt_expr     },
        {klee::Expr::Sle,      bdd_from_klee_sle_expr     },
        {klee::Expr::Sgt,      bdd_from_klee_sgt_expr     },
        {klee::Expr::Sge,      bdd_from_klee_sge_expr     },
};

} // namespace ps

#endif // LIBPS_PACKETSET_HPP
