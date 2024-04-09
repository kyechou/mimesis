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
     * TODO: Describe
     */
    BitVector(llvm::APInt);
    /**
     * TODO: Describe
     */
    BitVector(size_t width, uint64_t value);
    BitVector(const BitVector &) = default;
    BitVector(BitVector &&) = default;
    BitVector &operator=(const BitVector &) = default;
    BitVector &operator=(BitVector &&) = default;
    ~BitVector() = default;

    // TODO: Take a look at APInt's methods and see what we can borrow.
    // APInt is like a concrete/constant BitVector.

    /**
     * TODO: Describe the functions below.
     */

    void set(size_t i, const sylvan::Bdd &bit_val);
    sylvan::Bdd &operator[](size_t i); // Consider disabling this.
    const sylvan::Bdd &operator[](size_t i) const;
    size_t width() const;
    bool empty() const;
    bool is_constant() const;
    size_t num_var_bits() const;
    size_t num_bdd_boolean_vars() const;
    std::set<uint32_t> bdd_boolean_vars() const;
    uint64_t zext_value(size_t width = 64) const;

    static BitVector map1(const BitVector &src,
                          std::function<sylvan::Bdd(const sylvan::Bdd &)> func);
    static BitVector map2(const BitVector &first,
                          const BitVector &second,
                          std::function<sylvan::Bdd(const sylvan::Bdd &,
                                                    const sylvan::Bdd &)> func);

    // Relational operators
    // Bitwise binary operators
    // Bitwise shift
    // Bitwise negation
    // Arithmetic operators
    // Conversion/Cast operators
    // Read, Concat
    // Extraction
    // Select/Ite
};

} // namespace  ps

#endif // LIBPS_BITVECTOR_HPP
