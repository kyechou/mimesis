#include "libps/bitvector.hpp"

#include <cstdint>
#include <functional>
#include <llvm/ADT/APInt.h>
#include <set>
#include <string>
#include <sylvan_int.h>
#include <sylvan_mtbdd.h>
#include <sylvan_mtbdd_int.h>
#include <sylvan_obj.hpp>
#include <vector>

#include "lib/logger.hpp"
#include "libps/manager.hpp"

namespace ps {

BitVector::BitVector(const std::string &var_name) {
    auto [var_offset, nbits] = Manager::get().get_variable_offset(var_name);
    this->bv.reserve(nbits);
    for (size_t i = 0; i < nbits; ++i) {
        this->bv.push_back(sylvan::Bdd::bddVar(var_offset + i));
    }
}

BitVector::BitVector(const std::string &var_name,
                     const size_t offset,
                     const size_t width) {
    auto [var_offset, nbits] = Manager::get().get_variable_offset(var_name);
    assert(offset + width <= nbits);
    this->bv.reserve(width);
    for (size_t i = 0; i < width; ++i) {
        this->bv.push_back(sylvan::Bdd::bddVar(var_offset + offset + i));
    }
}

BitVector::BitVector(const size_t width, const sylvan::Bdd &bit_val)
    : bv(width, bit_val) {}

BitVector::BitVector(const size_t width, const bool bit_val)
    : bv(width, (bit_val ? sylvan::Bdd::bddOne() : sylvan::Bdd::bddZero())) {}

BitVector::BitVector(const llvm::APInt &value) {
    this->bv.reserve(value.getBitWidth());
    for (size_t i = 0; i < value.getBitWidth(); ++i) {
        this->bv.push_back(value[i] ? sylvan::Bdd::bddOne()
                                    : sylvan::Bdd::bddZero());
    }
}

BitVector::BitVector(const size_t width, const uint64_t value) {
    assert(width <= 64);
    this->bv.reserve(width);
    for (size_t i = 0; i < width; ++i) {
        this->bv.push_back((value & (1UL << i)) ? sylvan::Bdd::bddOne()
                                                : sylvan::Bdd::bddZero());
    }
}

void BitVector::clear() {
    this->bv.clear();
}

void BitVector::set(const size_t i, const sylvan::Bdd &bit_val) {
    assert(i < this->bv.size());
    this->bv[i] = bit_val;
}

sylvan::Bdd &BitVector::operator[](const size_t i) {
    assert(i < this->bv.size());
    return this->bv[i];
}

const sylvan::Bdd &BitVector::operator[](const size_t i) const {
    assert(i < this->bv.size());
    return this->bv[i];
}

size_t BitVector::width() const {
    return this->bv.size();
}

bool BitVector::empty() const {
    return this->bv.empty();
}

bool BitVector::is_constant() const {
    for (const sylvan::Bdd &bdd : this->bv) {
        if (!bdd.isConstant()) {
            return false;
        }
    }
    return true;
}

size_t BitVector::num_var_bits() const {
    size_t res = 0;
    for (const sylvan::Bdd &bdd : this->bv) {
        if (!bdd.isConstant()) {
            res++;
        }
    }
    return res;
}

size_t BitVector::num_bdd_boolean_vars() const {
    return this->bdd_boolean_vars().size();
}

std::set<uint32_t> BitVector::bdd_boolean_vars() const {
    std::set<uint32_t> vars;
    std::function<void(const sylvan::BDD)> collect_bdd_vars_recursive;
    collect_bdd_vars_recursive =
        [&vars, &collect_bdd_vars_recursive](const sylvan::BDD bdd) -> void {
        sylvan::mtbddnode_t n = sylvan::MTBDD_GETNODE(bdd);
        if (sylvan::mtbddnode_getmark(n)) {
            return;
        }
        sylvan::mtbddnode_setmark(n, 1);

        if (sylvan::mtbdd_isleaf(bdd)) {
            return;
        }
        vars.insert(sylvan::mtbddnode_getvariable(n));
        collect_bdd_vars_recursive(sylvan::mtbddnode_getlow(n));
        collect_bdd_vars_recursive(sylvan::mtbddnode_gethigh(n));
    };

    std::function<void(const sylvan::BDD)> unmark_bddnodes_recursive;
    unmark_bddnodes_recursive =
        [&unmark_bddnodes_recursive](const sylvan::BDD bdd) -> void {
        sylvan::mtbddnode_t n = sylvan::MTBDD_GETNODE(bdd);
        if (!sylvan::mtbddnode_getmark(n)) {
            return;
        }
        sylvan::mtbddnode_setmark(n, 0);
        if (sylvan::mtbdd_isleaf(bdd)) {
            return;
        }
        unmark_bddnodes_recursive(sylvan::mtbddnode_getlow(n));
        unmark_bddnodes_recursive(sylvan::mtbddnode_gethigh(n));
    };

    for (const sylvan::Bdd &bdd : this->bv) {
        collect_bdd_vars_recursive(bdd.GetBDD());
        unmark_bddnodes_recursive(bdd.GetBDD());
    }
    return vars;
}

uint64_t BitVector::zext_value(size_t width) const {
    assert(width <= 64);
    uint64_t value = 0;

    if (width > this->width()) {
        width = this->width();
    }

    for (size_t i = 0; i < width; ++i) {
        const sylvan::Bdd &bit_bdd = this->bv[i];
        if (!bit_bdd.isConstant()) {
            error("Trying to get zext value from a symbolic bit-vector.");
        }
        if (bit_bdd.isOne()) {
            value |= (1 << i);
        }
    }

    return value;
}

BitVector
BitVector::map1(const BitVector &src,
                std::function<sylvan::Bdd(const sylvan::Bdd &)> func) {
    BitVector res;
    res.bv.reserve(src.width());
    for (size_t i = 0; i < src.width(); ++i) {
        res.bv.push_back(func(src[i]));
    }
    return res;
}

BitVector BitVector::map2(
    const BitVector &first,
    const BitVector &second,
    std::function<sylvan::Bdd(const sylvan::Bdd &, const sylvan::Bdd &)> func) {
    assert(first.width() == second.width());
    BitVector res;
    res.bv.reserve(first.width());
    for (size_t i = 0; i < first.width(); ++i) {
        res.bv.push_back(func(first[i], second[i]));
    }
    return res;
}

BitVector BitVector::eq(const BitVector &other) const {
    BitVector res(/*width=*/1, true);
    sylvan::Bdd &res_bdd = res[0];

    if (this->width() != other.width()) {
        res_bdd = sylvan::Bdd::bddZero();
        return res;
    }

    for (size_t i = 0; i < this->width(); ++i) {
        res_bdd &= this->bv[i].Xnor(other[i]);
        if (res_bdd.isZero()) {
            // The i-th bits can never be equal. Return false.
            break;
        }
    }

    return res;
}

BitVector BitVector::ne(const BitVector &other) const {
    return this->eq(other).bv_not();
}

static inline sylvan::Bdd bdd_lt(const sylvan::Bdd &a, const sylvan::Bdd &b) {
    return (!a) & b;
}

BitVector BitVector::ult(const BitVector &other) const {
    assert(this->width() == other.width());
    assert(this->width() > 0);
    BitVector res(/*width=*/1, bdd_lt(this->bv[0], other[0]));
    sylvan::Bdd &res_bdd = res[0];
    for (size_t i = 1; i < this->width(); ++i) {
        res_bdd &= this->bv[i].Xnor(other[i]);
        res_bdd |= bdd_lt(this->bv[i], other[i]);
    }
    return res;
}

BitVector BitVector::ule(const BitVector &other) const {
    assert(this->width() == other.width());
    BitVector res(/*width=*/1, true);
    sylvan::Bdd &res_bdd = res[0];
    for (size_t i = 0; i < this->width(); ++i) {
        res_bdd &= this->bv[i].Xnor(other[i]);
        res_bdd |= bdd_lt(this->bv[i], other[i]);
    }
    return res;
}

BitVector BitVector::ugt(const BitVector &other) const {
    return other.ult(*this);
}

BitVector BitVector::uge(const BitVector &other) const {
    return other.ule(*this);
}

BitVector BitVector::slt(const BitVector &other) const {
    assert(this->width() == other.width());
    assert(this->width() > 0);
    BitVector res(/*width=*/1, true);
    sylvan::Bdd &res_bdd = res[0];
    res_bdd = (this->bv.back() & (~other.bv.back())) |
              (this->bv.back() & other.bv.back() & this->ugt(other)[0]) |
              (~this->bv.back() & ~other.bv.back() & this->ult(other)[0]);
    return res;
}

BitVector BitVector::sle(const BitVector &other) const {
    assert(this->width() == other.width());
    BitVector res(/*width=*/1, true);
    sylvan::Bdd &res_bdd = res[0];

    if (this->empty()) { // Both bit-vectors are empty.
        res_bdd = sylvan::Bdd::bddOne();
        return res;
    }

    res_bdd = (this->bv.back() & (~other.bv.back())) |
              (this->bv.back() & other.bv.back() & this->uge(other)[0]) |
              (~this->bv.back() & ~other.bv.back() & this->ule(other)[0]);
    return res;
}

BitVector BitVector::sgt(const BitVector &other) const {
    return other.slt(*this);
}

BitVector BitVector::sge(const BitVector &other) const {
    return other.sle(*this);
}

BitVector BitVector::operator==(const BitVector &other) const {
    return this->eq(other);
}

BitVector BitVector::operator!=(const BitVector &other) const {
    return this->ne(other);
}

BitVector BitVector::operator<(const BitVector &other) const {
    return this->ult(other);
}

BitVector BitVector::operator<=(const BitVector &other) const {
    return this->ule(other);
}

BitVector BitVector::operator>(const BitVector &other) const {
    return this->ugt(other);
}

BitVector BitVector::operator>=(const BitVector &other) const {
    return this->uge(other);
}

BitVector BitVector::bv_and(const BitVector &other) const {
    assert(this->width() == other.width());
    BitVector res;
    res.bv.reserve(this->width());
    for (size_t i = 0; i < this->width(); ++i) {
        res.bv.push_back(this->bv[i] & other[i]);
    }
    return res;
}

BitVector BitVector::bv_or(const BitVector &other) const {
    assert(this->width() == other.width());
    BitVector res;
    res.bv.reserve(this->width());
    for (size_t i = 0; i < this->width(); ++i) {
        res.bv.push_back(this->bv[i] | other[i]);
    }
    return res;
}

BitVector BitVector::bv_xor(const BitVector &other) const {
    assert(this->width() == other.width());
    BitVector res;
    res.bv.reserve(this->width());
    for (size_t i = 0; i < this->width(); ++i) {
        res.bv.push_back(this->bv[i] ^ other[i]);
    }
    return res;
}

BitVector BitVector::operator&(const BitVector &other) const {
    return this->bv_and(other);
}

BitVector BitVector::operator|(const BitVector &other) const {
    return this->bv_or(other);
}

BitVector BitVector::operator^(const BitVector &other) const {
    return this->bv_xor(other);
}

BitVector BitVector::shl(const BitVector &distance) const {
    if (!distance.is_constant()) {
        error("Symbolic shl distance is not currently supported.");
    }
    const uint64_t dist = distance.zext_value();
    BitVector res(this->width(), false);
    size_t from_idx = (dist > this->width()) ? this->width() : dist;
    for (size_t i = from_idx; i < this->width(); ++i) {
        res.bv[i] = this->bv[i - dist];
    }
    return res;
}

BitVector BitVector::lshr(const BitVector &distance) const {
    if (!distance.is_constant()) {
        error("Symbolic lshr distance is not currently supported.");
    }
    const uint64_t dist = distance.zext_value();
    BitVector res(this->width(), false);
    size_t to_idx = (dist > this->width()) ? 0 : this->width() - dist;
    for (size_t i = 0; i < to_idx; ++i) {
        res.bv[i] = this->bv[i + dist];
    }
    return res;
}

BitVector BitVector::ashr(const BitVector &distance) const {
    if (!distance.is_constant()) {
        error("Symbolic ashr distance is not currently supported.");
    }
    const uint64_t dist = distance.zext_value();
    BitVector res(this->width(),
                  this->empty() ? sylvan::Bdd::bddZero() : this->bv.back());
    size_t to_idx = (dist > this->width()) ? 0 : this->width() - dist;
    for (size_t i = 0; i < to_idx; ++i) {
        res.bv[i] = this->bv[i + dist];
    }
    return res;
}

BitVector BitVector::operator<<(const BitVector &distance) const {
    return this->shl(distance);
}

BitVector BitVector::operator>>(const BitVector &distance) const {
    return this->lshr(distance);
}

BitVector BitVector::bv_not() const {
    BitVector res;
    res.bv.reserve(this->width());
    for (size_t i = 0; i < this->width(); ++i) {
        res.bv.push_back(~this->bv[i]);
    }
    return res;
}

BitVector BitVector::operator~() const {
    return this->bv_not();
}

BitVector BitVector::add(const BitVector &other [[maybe_unused]]) const {
    // TODO: Implement.
    error("Unimplemented");
    return {};
}

BitVector BitVector::sub(const BitVector &other [[maybe_unused]]) const {
    // TODO: Implement.
    error("Unimplemented");
    return {};
}

BitVector BitVector::mul(const BitVector &other [[maybe_unused]]) const {
    error("Unimplemented");
    return {};
}

BitVector BitVector::udiv(const BitVector &divisor [[maybe_unused]],
                          BitVector &remainder [[maybe_unused]]) const {
    error("Unimplemented");
    return {};
}

BitVector BitVector::udiv(const BitVector &divisor) const {
    BitVector remainder;
    return this->udiv(divisor, remainder);
}

BitVector BitVector::urem(const BitVector &divisor) const {
    BitVector remainder;
    this->udiv(divisor, remainder);
    return remainder;
}

BitVector BitVector::sdiv(const BitVector &divisor [[maybe_unused]],
                          BitVector &remainder [[maybe_unused]]) const {
    error("Unimplemented");
    return {};
}

BitVector BitVector::sdiv(const BitVector &divisor) const {
    BitVector remainder;
    return this->sdiv(divisor, remainder);
}

BitVector BitVector::srem(const BitVector &divisor) const {
    BitVector remainder;
    this->sdiv(divisor, remainder);
    return remainder;
}

BitVector BitVector::operator+(const BitVector &other) const {
    return this->add(other);
}

BitVector BitVector::operator-(const BitVector &other) const {
    return this->sub(other);
}

BitVector BitVector::operator*(const BitVector &other) const {
    return this->mul(other);
}

BitVector BitVector::operator/(const BitVector &other) const {
    BitVector remainder;
    return this->udiv(other, remainder);
}

BitVector BitVector::operator%(const BitVector &other) const {
    BitVector remainder;
    this->udiv(other, remainder);
    return remainder;
}

BitVector &BitVector::operator+=(const BitVector &other) {
    *this = this->add(other);
    return *this;
}

BitVector &BitVector::operator-=(const BitVector &other) {
    *this = this->sub(other);
    return *this;
}

BitVector &BitVector::operator*=(const BitVector &other) {
    *this = this->mul(other);
    return *this;
}

BitVector &BitVector::operator/=(const BitVector &other) {
    BitVector remainder;
    *this = this->udiv(other, remainder);
    return *this;
}

BitVector &BitVector::operator%=(const BitVector &other) {
    BitVector remainder;
    this->udiv(other, remainder);
    return *this = remainder;
}

BitVector BitVector::zext(const size_t width) const {
    assert(this->width() < width);
    BitVector res(*this);
    res.bv.reserve(width);
    res.bv.insert(res.bv.end(), width - this->width(), sylvan::Bdd::bddZero());
    return res;
}

BitVector BitVector::sext(const size_t width) const {
    assert(this->width() < width && !this->empty());
    BitVector res(*this);
    res.bv.reserve(width);
    res.bv.insert(res.bv.end(), width - this->width(), this->bv.back());
    return res;
}

BitVector BitVector::concat(const BitVector &other) const {
    BitVector res(*this);
    res.bv.reserve(this->width() + other.width());
    res.bv.insert(res.bv.end(), other.bv.begin(), other.bv.end());
    return res;
}

BitVector BitVector::extract(const size_t offset, const size_t width) const {
    assert(offset + width <= this->width());
    BitVector res;
    res.bv.reserve(width);
    auto start = this->bv.begin() + offset;
    auto end = this->bv.begin() + offset + width;
    res.bv.insert(res.bv.end(), start, end);
    return res;
}

BitVector BitVector::select(const BitVector &condition,
                            const BitVector &true_result,
                            const BitVector &false_result) {
    assert(condition.width() == 1);
    assert(true_result.width() == false_result.width());
    BitVector res;
    res.bv.reserve(true_result.width());
    for (size_t i = 0; i < true_result.width(); ++i) {
        res.bv.push_back((condition[0] & true_result[i]) |
                         (~condition[0] & false_result[i]));
    }
    return res;
}

BitVector BitVector::ite(const BitVector &condition,
                         const BitVector &true_result,
                         const BitVector &false_result) {
    return BitVector::select(condition, true_result, false_result);
}

} // namespace ps
