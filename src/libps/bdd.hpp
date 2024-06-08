#ifndef LIBPS_BDD_HPP
#define LIBPS_BDD_HPP

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <sylvan_obj.hpp>
#include <vector>

namespace ps {

/**
 * These are helper functions complementing the sylvan::Bdd class.
 */
class Bdd {
public:
    /**
     * Returns the unique variables in the given BDD.
     */
    static std::set<uint32_t> variables(const sylvan::Bdd &);
    /**
     * Returns the number of unique variables in the given BDD. Not thread-safe!
     */
    static size_t num_vars(const sylvan::Bdd &);
    /**
     * Returns the number of unique nodes (excluding the leaves) in the given
     * BDDs.
     */
    static size_t num_nodes_more(const sylvan::BDD *bdds, size_t count);
    /**
     * Returns the number of nodes (excluding the leaves) in the given BDD.
     *
     * Note that since we are operating with ROBDDs here, the number of nodes
     * will be the same as the number of unique nodes.
     */
    static size_t num_nodes(const sylvan::Bdd &);
    /**
     * Returns the number of paths that lead to True.
     */
    static size_t num_true_paths(const sylvan::Bdd &);
    /**
     * Returns the number of assignments that satisfy the BDD.
     */
    static size_t num_sat_assignments(
        const sylvan::Bdd &bdd,
        const std::optional<sylvan::BddSet> variables = std::nullopt);
    static size_t num_sat_assignments(const sylvan::Bdd &bdd,
                                      const size_t num_vars);

    /**
     * Write the given BDD into an ASCII string for debugging purposes only.
     * The string cannot be turned back into a BDD.
     *
     * ASCII (`mtbdd_writer_totext`) format of a BDD:
     * [
     *   node(id, var, low, high), -- for a normal node (no complement on high)
     *   node(id, var, low, ~high), -- for a normal node (complement on high)
     *   leaf(id, type, "value"), -- for a leaf (with value between "")
     * ],[dd1, dd2, dd3, ...,] -- and each the stored decision diagram.
     */
    static std::string to_string(const sylvan::Bdd &);
    /**
     * Write the given BDD into a one-line string for debugging purposes only.
     * The string cannot be turned back into a BDD.
     *
     * NOTE: Avoid using this function. There seems to be some inconsistencies
     * in terms of the keys from the Sylvan library.
     *
     * One-line (`sylvan_fprint`) format of a BDD:
     * [(<key>,<level>,<key_low>,<key_high>,<complement_high>),...]
     */
    static std::string to_string_oneline(const sylvan::Bdd &);
    /**
     * Write the given BDD into a dot-format string for debugging purposes only.
     * The string cannot be turned back into a BDD.
     */
    static std::string to_dot_string(const sylvan::Bdd &);
    /**
     * Write the given BDD into a vector of bytes in the binary format.
     */
    static std::vector<std::byte> to_byte_vector(const sylvan::Bdd &);
    /**
     * Output the given BDD as a dot file for debugging purposes only.
     * The file cannot be turned back into a BDD.
     */
    static void to_dot_file(const sylvan::Bdd &, FILE *);
    /**
     * Output the given BDD as a dot file for debugging purposes only.
     * The file cannot be turned back into a BDD.
     */
    static void to_dot_file(const sylvan::Bdd &, const std::filesystem::path &);
    /**
     * Output the given BDD as an ASCII file for debugging purposes only.
     * The file cannot be turned back into a BDD.
     *
     * ASCII (`mtbdd_writer_totext`) format of a BDD:
     * [
     *   node(id, var, low, high), -- for a normal node (no complement on high)
     *   node(id, var, low, ~high), -- for a normal node (complement on high)
     *   leaf(id, type, "value"), -- for a leaf (with value between "")
     * ],[dd1, dd2, dd3, ...,] -- and each the stored decision diagram.
     */
    static void to_ascii_file(const sylvan::Bdd &, FILE *);
    /**
     * Output the given BDD as an ASCII file for debugging purposes only.
     * The file cannot be turned back into a BDD.
     *
     * ASCII (`mtbdd_writer_totext`) format of a BDD:
     * [
     *   node(id, var, low, high), -- for a normal node (no complement on high)
     *   node(id, var, low, ~high), -- for a normal node (complement on high)
     *   leaf(id, type, "value"), -- for a leaf (with value between "")
     * ],[dd1, dd2, dd3, ...,] -- and each the stored decision diagram.
     */
    static void to_ascii_file(const sylvan::Bdd &,
                              const std::filesystem::path &);
    /**
     * Output the given BDD as a binary file, which can be later turned back
     * into a BDD with `ps::Bdd::from_binary_file`.
     */
    static void to_binary_file(const sylvan::Bdd &, FILE *);
    /**
     * Output the given BDD as a binary file, which can be later turned back
     * into a BDD with `ps::Bdd::from_binary_file`.
     */
    static void to_binary_file(const sylvan::Bdd &,
                               const std::filesystem::path &);
    /**
     * Convert the given file previously output by `ps::Bdd::to_binary_file`
     * into a BDD.
     */
    static sylvan::Bdd from_binary_file(FILE *);
    /**
     * Convert the given file previously output by `ps::Bdd::to_binary_file`
     * into a BDD.
     */
    static sylvan::Bdd from_binary_file(const std::filesystem::path &);
};

} // namespace ps

#endif // LIBPS_BDD_HPP
