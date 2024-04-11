#ifndef LIBPS_BDD_HPP
#define LIBPS_BDD_HPP

#include <cstdint>
#include <filesystem>
#include <set>
#include <string>
#include <sylvan_obj.hpp>

namespace ps {

/**
 * These are helper functions complementing the sylvan::Bdd class.
 *
 * This class should have no private members and no variables. All methods
 * should be public, static, and stateless.
 */
class Bdd {
public:
    /**
     * Returns the unique variables in the given BDD. Not thread-safe!
     */
    static std::set<uint32_t> variables(const sylvan::Bdd &);
    /**
     * Returns the number of unique variables in the given BDD. Not thread-safe!
     */
    static size_t variable_count(const sylvan::Bdd &);

    // TODO:
    // sylvan_pathcount
    // sylvan_satcount (need vars)
    // mtbdd_satcount (need vars)
    // size_t sylvan_serialize_add(BDD bdd);
    // size_t sylvan_serialize_get(BDD bdd);
    // BDD sylvan_serialize_get_reversed(size_t value);
    // void sylvan_serialize_reset(void);
    // void sylvan_serialize_totext(FILE *out);
    // void sylvan_serialize_tofile(FILE *out);
    // void sylvan_serialize_fromfile(FILE *in);
    // void sylvan_fprint(FILE *f, BDD bdd)
    // void sylvan_print(BDD bdd)

    /**
     * Returns an ASCII string representation of the BDD.
     *
     * [
     *   node(id, var, low, high), -- for a normal node (no complement on high)
     *   node(id, var, low, ~high), -- for a normal node (complement on high)
     *   leaf(id, type, "value"), -- for a leaf (with value between "")
     * ],[dd1, dd2, dd3, ...,] -- and each the stored decision diagram.
     */
    static std::string to_string(const sylvan::Bdd &);
    /**
     * Writes the given BDD as a .dot file.
     *
     * See `mtbdd_printdot`, `mtbdd_fprintdot`, and `mtbdd_fprintdot_nc`
     */
    static void to_dot_file(const sylvan::Bdd &, const std::filesystem::path &);
    /**
     * Writes the given BDD in ASCII form to the given file path.
     *
     * [
     *   node(id, var, low, high), -- for a normal node (no complement on high)
     *   node(id, var, low, ~high), -- for a normal node (complement on high)
     *   leaf(id, type, "value"), -- for a leaf (with value between "")
     * ],[dd1, dd2, dd3, ...,] -- and each the stored decision diagram.
     */
    static void to_ascii_file(const sylvan::Bdd &,
                              const std::filesystem::path &);
    /**
     * Writes the given BDD in the internal binary form to the given file path.
     *
     * (See `mtbdd_writer_tobinary`)
     */
    static void to_binary_file(const sylvan::Bdd &,
                               const std::filesystem::path &);
};

} // namespace ps

#endif // LIBPS_BDD_HPP
