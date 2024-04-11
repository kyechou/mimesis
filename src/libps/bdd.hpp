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

    /**
     * ASCII (`mtbdd_writer_totext`) format of a BDD:
     * [
     *   node(id, var, low, high), -- for a normal node (no complement on high)
     *   node(id, var, low, ~high), -- for a normal node (complement on high)
     *   leaf(id, type, "value"), -- for a leaf (with value between "")
     * ],[dd1, dd2, dd3, ...,] -- and each the stored decision diagram.
     *
     * `sylvan_fprint` format:
     * [(<key>,<level>,<key_low>,<key_high>,<complement_high>),...]
     */

    static std::string to_string(const sylvan::Bdd &);
    static std::string to_string_oneline(const sylvan::Bdd &);
    static std::string to_dot_string(const sylvan::Bdd &);
    static void to_dot_file(const sylvan::Bdd &, FILE *);
    static void to_dot_file(const sylvan::Bdd &, const std::filesystem::path &);
    static void to_ascii_file(const sylvan::Bdd &, FILE *);
    static void to_ascii_file(const sylvan::Bdd &,
                              const std::filesystem::path &);
    static void to_binary_file(const sylvan::Bdd &,
                               const std::filesystem::path &);
};

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

} // namespace ps

#endif // LIBPS_BDD_HPP
