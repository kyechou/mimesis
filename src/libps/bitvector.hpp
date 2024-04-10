#ifndef LIBPS_BITVECTOR_HPP
#define LIBPS_BITVECTOR_HPP

#include <cstdint>
#include <functional>
#include <llvm/ADT/APInt.h>
#include <set>
#include <string>
#include <sylvan_obj.hpp>
#include <vector>

namespace ps {

class BitVector {
private:
    std::vector<sylvan::Bdd> bv;

public:
    /**
     * Create a bit-vector representing the symbolic variable `var_name`.
     * Note that `var_name` must have been registered with the manager.
     */
    BitVector(const std::string &var_name);
    /**
     * Create a bit-vector extracted from the symbolic variable `var_name`,
     * starting at `offset` with `width` number of bits. The `offset` is defined
     * with respect to the variable, rather than the BDD index. I.e., `offset` =
     * 0 means starting from the beginning of the variable.
     */
    BitVector(const std::string &var_name, size_t offset, size_t width);
    /**
     * Create a bit-vector with `width` number of bits, each of which
     * initialized as `bit_val`.
     */
    BitVector(size_t width, const sylvan::Bdd &bit_val);
    /**
     * Create a concrete bit-vector with `width` number of bits, each of which
     * initialized as `bit_val`.
     */
    BitVector(size_t width, bool bit_val);
    /**
     * Construct a concrete bit-vector from the APInt `value`.
     */
    BitVector(const llvm::APInt &value);
    /**
     * Construct a concrete bit-vector from `value`.
     * `width` must be no greater than 64.
     */
    BitVector(size_t width, uint64_t value);

    BitVector() = default;
    BitVector(const BitVector &) = default;
    BitVector(BitVector &&) = default;
    BitVector &operator=(const BitVector &) = default;
    BitVector &operator=(BitVector &&) = default;
    ~BitVector() = default;

    /**
     * Clear the bit-vector. Post-condition: empty() == true.
     */
    void clear();
    /**
     * Set the BDD at index `i` to `bit_val`. `i` must be less than the current
     * bit-width.
     */
    void set(size_t i, const sylvan::Bdd &bit_val);
    /**
     * Get the BDD at index `i`. `i` must be less than the current bit-width.
     */
    sylvan::Bdd &operator[](size_t i);
    /**
     * Get the BDD at index `i`. `i` must be less than the current bit-width.
     */
    const sylvan::Bdd &operator[](size_t i) const;
    /**
     * Returns the current bit-width.
     */
    size_t width() const;
    /**
     * True if the bit-vector contains nothing, bit-width = 0.
     */
    bool empty() const;
    /**
     * True if all bit BDDs are constant (either 0 or 1).
     */
    bool is_constant() const;
    /**
     * Returns the number of variable bits, i.e., the number of bit BDDs that
     * are not constant (neither 0 nor 1).
     */
    size_t num_var_bits() const;
    /**
     * Returns the number of unique Boolean variables in all bit BDDs. Not
     * thread-safe!
     */
    size_t num_bdd_boolean_vars() const;
    /**
     * Returns the unique Boolean variables in all bit BDDs. Not thread-safe!
     */
    std::set<uint32_t> bdd_boolean_vars() const;
    /**
     * Returns the concrete value as zero-extended 64-bit unsigned integer if
     * the bit-vector is constant. Otherwise, abort with an error message.
     * `width` must be no greater than 64.
     *
     * Bits with smaller bit-vector indices are interpreted as less significant.
     * For example, bv:[1,0,1,1,0] is interpreted as 13.
     */
    uint64_t zext_value(size_t width = 64) const;

    /**
     * Apply `func` to each bit BDD of `src` sequentially and create a new
     * bit-vector from the resulting BDDs.
     */
    static BitVector map1(const BitVector &src,
                          std::function<sylvan::Bdd(const sylvan::Bdd &)> func);
    /**
     * Apply `func` to each pair of bit BDDs of `first` and `second`
     * respectively and create a new bit-vector from the resulting BDDs.
     */
    static BitVector map2(const BitVector &first,
                          const BitVector &second,
                          std::function<sylvan::Bdd(const sylvan::Bdd &,
                                                    const sylvan::Bdd &)> func);

    // Relational operators
    BitVector eq(const BitVector &other) const;
    BitVector ne(const BitVector &other) const;
    BitVector ult(const BitVector &other) const;
    BitVector ule(const BitVector &other) const;
    BitVector ugt(const BitVector &other) const;
    BitVector uge(const BitVector &other) const;
    BitVector slt(const BitVector &other) const;
    BitVector sle(const BitVector &other) const;
    BitVector sgt(const BitVector &other) const;
    BitVector sge(const BitVector &other) const;
    BitVector operator==(const BitVector &other) const;
    BitVector operator!=(const BitVector &other) const;
    BitVector operator<(const BitVector &other) const;
    BitVector operator<=(const BitVector &other) const;
    BitVector operator>(const BitVector &other) const;
    BitVector operator>=(const BitVector &other) const;

    // Bitwise binary operators
    BitVector bv_and(const BitVector &other) const;
    BitVector bv_or(const BitVector &other) const;
    BitVector bv_xor(const BitVector &other) const;
    BitVector operator&(const BitVector &other) const;
    BitVector operator|(const BitVector &other) const;
    BitVector operator^(const BitVector &other) const;

    // Bitwise shift (The bit-width remains the same.)
    BitVector shl(const size_t distance) const;
    BitVector lshr(const size_t distance) const;
    BitVector ashr(const size_t distance) const;
    BitVector operator<<(const size_t distance) const;
    BitVector operator>>(const size_t distance) const;

    // Bitwise negation
    BitVector bv_not() const;
    BitVector operator~() const;

    // Arithmetic operators
    BitVector add(const BitVector &other) const;
    BitVector sub(const BitVector &other) const;
    BitVector mul(const BitVector &other) const;
    BitVector udiv(const BitVector &divisor, BitVector &remainder) const;
    BitVector sdiv(const BitVector &divisor, BitVector &remainder) const;
    BitVector operator+(const BitVector &other) const;
    BitVector operator-(const BitVector &other) const;
    BitVector operator*(const BitVector &other) const;
    BitVector operator/(const BitVector &other) const;
    BitVector operator%(const BitVector &other) const;
    BitVector &operator+=(const BitVector &other);
    BitVector &operator-=(const BitVector &other);
    BitVector &operator*=(const BitVector &other);
    BitVector &operator/=(const BitVector &other);
    BitVector &operator%=(const BitVector &other);

    // Conversion/Cast operators
    BitVector zext(const size_t ext_dist) const;
    BitVector sext(const size_t ext_dist) const;

    // Others (Read, Concat, Extract, Select/Ite)
    BitVector read(const BitVector &index) const;
    BitVector concat(const BitVector &other) const;
    BitVector extract(const size_t offset, const size_t width) const;
    static BitVector select(const BitVector &condition,
                            const BitVector &true_result,
                            const BitVector &false_result);
    static BitVector ite(const BitVector &condition,
                         const BitVector &true_result,
                         const BitVector &false_result);
};

} // namespace ps

// Maybe useful functions in sylvan:
//
// mtbdd_satcount(bdd, number_of_vars): compute the number of minterms
// (assignments that lead to True) for a function with <number_of_vars>
// variables; we don’t need to know the exact variables that may be in the BDD,
// just how many there are.
//
// sylvan_pathcount(bdd): compute the number of distinct paths to True.
//
// mtbdd_nodecount(bdd): compute the number of nodes (and leaves) in the BDD.
//
// mtbdd_nodecount_more(array, length): compute the number of nodes (and leaves)
// in the array of BDDs.

#endif // LIBPS_BITVECTOR_HPP
