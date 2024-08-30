#include "libps/bitvector.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <llvm/ADT/APInt.h>
#include <set>
#include <string>
#include <sylvan_int.h>
#include <sylvan_mtbdd.h>
#include <sylvan_obj.hpp>
#include <vector>

#include "lib/logger.hpp"
#include "libps/bdd.hpp"
#include "libps/manager.hpp"

namespace ps {

bool APIntLess::operator()(const llvm::APInt &a, const llvm::APInt &b) const {
    return a.ult(b);
}

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

BitVector::BitVector(const bool bool_val)
    : bv(1, (bool_val ? sylvan::Bdd::bddOne() : sylvan::Bdd::bddZero())) {}

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

std::set<uint32_t> BitVector::bdd_boolean_vars() const {
    std::set<uint32_t> vars;
    for (const sylvan::Bdd &bdd : this->bv) {
        vars.merge(Bdd::variables(bdd));
    }
    return vars;
}

size_t BitVector::num_bdd_boolean_vars() const {
    return this->bdd_boolean_vars().size();
}

size_t BitVector::num_nodes() const {
    std::vector<sylvan::BDD> c_bdds;
    c_bdds.reserve(this->bv.size());

    for (const sylvan::Bdd &bdd : this->bv) {
        c_bdds.push_back(bdd.GetBDD());
    }

    return Bdd::num_nodes_more(c_bdds.data(), c_bdds.size());
}

uint64_t BitVector::num_assignments() const {
    size_t num_bdd_vars = this->num_bdd_boolean_vars();
    if (num_bdd_vars >= sizeof(uint64_t) * 8) {
        error("The number of BDD variables (" + std::to_string(num_bdd_vars) +
              ") exceeds the type range of " +
              std::to_string(sizeof(uint64_t)) + " bytes.");
    }
    return 1 << num_bdd_vars;
}

std::map<llvm::APInt, sylvan::Bdd, APIntLess> BitVector::valid_values() const {
    std::map<llvm::APInt, sylvan::Bdd, APIntLess> values;
    const std::vector<sylvan::Bdd> &bv = this->bv;

    if (bv.empty()) {
        return {};
    }

    std::function<void(size_t bit_pos, llvm::APInt value,
                       const sylvan::Bdd &constraint)>
        valid_values_rec;
    valid_values_rec = [&valid_values_rec, &values,
                        &bv](const size_t bit_pos, llvm::APInt value,
                             const sylvan::Bdd &constraint) -> void {
        // terminal condition
        if (bit_pos >= bv.size()) {
            auto res = values.insert({value, constraint});
            if (!res.second) {
                error("Duplicate bit-vector value.");
            }
            return;
        }

        const sylvan::Bdd &bdd = bv.at(bit_pos).Constrain(constraint);

        if (bdd.isConstant()) {
            value.setBitVal(bit_pos, bdd.isOne());
            valid_values_rec(bit_pos + 1, value, constraint);
        } else {
            // "0" case
            value.clearBit(bit_pos);
            valid_values_rec(bit_pos + 1, value,
                             constraint & bdd.Xnor(sylvan::Bdd::bddZero()));
            // "1" case
            value.setBit(bit_pos);
            valid_values_rec(bit_pos + 1, value,
                             constraint & bdd.Xnor(sylvan::Bdd::bddOne()));
        }
    };

    valid_values_rec(
        0,
        llvm::APInt(/*numBits=*/this->width(), /*val=*/0, /*isSigned=*/false),
        sylvan::Bdd::bddOne());
    return values;
}

size_t BitVector::num_valid_values() const {
    return this->valid_values().size();
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
            error("Trying to get zext_value from a symbolic bit-vector.");
        }
        if (bit_bdd.isOne()) {
            value |= (1ul << i);
        }
    }

    return value;
}

llvm::APInt BitVector::uint_value() const {
    size_t width = this->width();
    llvm::APInt value(/*numBits=*/width, /*val=*/0, /*isSigned=*/false);

    for (size_t i = 0; i < width; ++i) {
        const sylvan::Bdd &bit_bdd = this->bv[i];
        if (!bit_bdd.isConstant()) {
            error("Trying to get uint_value from a symbolic bit-vector.");
        }
        value.setBitVal(i, bit_bdd.isOne());
    }
    return value;
}

bool BitVector::identical_to(const BitVector &other) const {
    return this->bv == other.bv;
}

std::string BitVector::to_string() const {
    std::string res = std::to_string(this->width()) + "-bits bit-vector";
    for (size_t i = 0; i < this->width(); ++i) {
        res += "\n-- bit " + std::to_string(i) + ": " +
               Bdd::to_string(this->bv[i]);
    }
    return res;
}

void BitVector::to_dot_file(const std::filesystem::path &fp) const {
    char *line;
    size_t line_len = 256;
    FILE *out = fopen(fp.c_str(), "w");
    if (!out) {
        error("Failed to open " + fp.string(), errno);
    }
    fprintf(out, "digraph \"DD\" {\n"
                 "graph [dpi = 300];\n"
                 "center = true;\n"
                 "edge [dir = forward];\n"
                 "root [style=invis];\n");
    line = static_cast<char *>(malloc(line_len));
    if (!line) {
        fclose(out);
        error("malloc() failed", errno);
    }
    for (const sylvan::Bdd &bdd : this->bv) {
        char *buf;
        size_t len;
        FILE *ss = open_memstream(&buf, &len);
        if (!ss) {
            free(line);
            fclose(out);
            error("open_memstream failed", errno);
        }
        Bdd::to_dot_file(bdd, ss);
        if (fseek(ss, 0, SEEK_SET) == -1) {
            fclose(ss);
            free(buf);
            free(line);
            fclose(out);
            error("fseek() failed", errno);
        }

        // Skip the first 5 lines.
        for (int i = 0; i < 5; ++i) {
            getline(&line, &line_len, ss);
        }
        // Merge and append the remaining lines.
        while (getline(&line, &line_len, ss) > 0) {
            if (line[0] == '}' && line[1] == '\n') {
                break;
            }
            fputs(line, out);
        }

        fclose(ss);
        free(buf);
    }
    free(line);
    fprintf(out, "}\n");
    fclose(out);
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

BitVector BitVector::add(const BitVector &other) const {
    assert(this->width() == other.width());
    BitVector res;
    sylvan::Bdd carry = sylvan::Bdd::bddZero();
    res.bv.reserve(this->width());

    for (size_t i = 0; i < this->width(); ++i) {
        res.bv.push_back(this->bv[i] ^ other.bv[i] ^ carry);
        carry =
            (this->bv[i] & other.bv[i]) | ((this->bv[i] | other.bv[i]) & carry);
    }

    return res;
}

BitVector BitVector::sub(const BitVector &other) const {
    assert(this->width() == other.width());
    BitVector res;
    sylvan::Bdd borrow = sylvan::Bdd::bddZero();
    res.bv.reserve(this->width());

    for (size_t i = 0; i < this->width(); ++i) {
        res.bv.push_back(this->bv[i] ^ other.bv[i] ^ borrow);
        borrow = (this->bv[i] & other.bv[i] & borrow) |
                 (~this->bv[i] & (other.bv[i] | borrow));
    }

    return res;
}

BitVector BitVector::mul(const BitVector &other) const {
    // NOTE: Here we assume a fixed bit-width for multiplication. I.e., an m-bit
    // multiplicand (this) multiplied by an n-bit multiplier (other) will result
    // in an m-bit product.
    // To allow dynamic bit-width, where the product contains (m + n) bits,
    // simply modify `max_width`.
    size_t max_width = this->width(); // + other.width();
    BitVector multiplicand = this->zext(max_width);
    BitVector product(max_width, false);

    for (size_t i = 0; i < other.width(); ++i) {
        BitVector bit_pos(llvm::APInt(sizeof(other.width()) * 8, i));
        product =
            select(other.bv[i], product + (multiplicand << bit_pos), product);
    }

    return product;
}

BitVector BitVector::udiv(const BitVector &divisor,
                          BitVector &remainder) const {
    assert(this->width() == divisor.width());
    assert(!divisor.is_constant() || divisor.zext_value() != 0);

    size_t width = this->width();
    BitVector quotient(width, false);
    remainder = *this; // `remainder` will be the running dividend.

    if (width == 0) {
        return quotient;
    }

    if (this->identical_to(divisor)) {
        quotient.set(0, sylvan::Bdd::bddOne());
        remainder = BitVector(width, false);
        return quotient;
    }

    for (int64_t i = width - 1; i >= 0; --i) {
        BitVector bit_pos(llvm::APInt(sizeof(width) * 8, i));
        sylvan::Bdd c = ((remainder >> bit_pos) >= divisor).bv.at(0);
        quotient.bv[i] = c; // ite(c, 1, 0)
        remainder = select(c, remainder - (divisor << bit_pos), remainder);
    }

    return quotient;
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
    error("Unimplemented sdiv");
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
    assert(this->width() <= width);
    if (this->width() == width) {
        return *this; // same width, no need to extend
    }
    BitVector res(*this);
    res.bv.reserve(width);
    res.bv.insert(res.bv.end(), width - this->width(), sylvan::Bdd::bddZero());
    return res;
}

BitVector BitVector::sext(const size_t width) const {
    assert(this->width() <= width);
    if (this->width() == width) {
        return *this; // same width, no need to extend
    }
    BitVector res(*this);
    res.bv.reserve(width);
    res.bv.insert(res.bv.end(), width - this->width(),
                  (this->empty() ? sylvan::Bdd::bddZero() : this->bv.back()));
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

BitVector BitVector::select(const sylvan::Bdd &condition,
                            const BitVector &true_result,
                            const BitVector &false_result) {
    assert(true_result.width() == false_result.width());
    BitVector res;
    res.bv.reserve(true_result.width());
    for (size_t i = 0; i < true_result.width(); ++i) {
        res.bv.push_back(condition.Ite(true_result[i], false_result[i]));
    }
    return res;
}

BitVector BitVector::select(const BitVector &condition,
                            const BitVector &true_result,
                            const BitVector &false_result) {
    assert(condition.width() == 1);
    return select(condition[0], true_result, false_result);
}

BitVector BitVector::ite(const sylvan::Bdd &condition,
                         const BitVector &true_result,
                         const BitVector &false_result) {
    return BitVector::select(condition, true_result, false_result);
}

BitVector BitVector::ite(const BitVector &condition,
                         const BitVector &true_result,
                         const BitVector &false_result) {
    return BitVector::select(condition, true_result, false_result);
}

BitVector BitVector::constrain(const sylvan::Bdd &constraint) const {
    BitVector res(this->width(), false);
    for (size_t i = 0; i < this->width(); ++i) {
        res.bv[i] = this->bv[i].Constrain(constraint);
    }
    return res;
}

} // namespace ps
