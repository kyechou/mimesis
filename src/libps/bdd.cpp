#include "libps/bdd.hpp"

#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <istream>
#include <ostream>
#include <set>
#include <sstream>
#include <string>
#include <sylvan.h>
#include <sylvan_bdd.h>
#include <sylvan_int.h>
#include <sylvan_mtbdd.h>
#include <sylvan_mtbdd_int.h>
#include <sylvan_obj.hpp>
#include <vector>

#include "lib/logger.hpp"

namespace ps {

std::set<uint32_t> Bdd::variables(const sylvan::Bdd &bdd) {
    std::set<uint32_t> res;
    // Support := the cube of all variables that appear in the BDD nodes.
    sylvan::Bdd vars_cube = bdd.Support();
    while (!vars_cube.isTerminal()) {
        res.insert(vars_cube.TopVar());
        assert(vars_cube.Else() == sylvan::Bdd::bddZero());
        vars_cube = vars_cube.Then();
    }
    return res;
}

size_t Bdd::num_vars(const sylvan::Bdd &bdd) {
    return Bdd::variables(bdd).size();
}

size_t Bdd::num_nodes_more(const sylvan::BDD *bdds, size_t num_bdds) {
    std::function<size_t(const sylvan::BDD &)> nodecount_mark_no_leaves;
    nodecount_mark_no_leaves =
        [&nodecount_mark_no_leaves](const sylvan::BDD &bdd) -> size_t {
        // do not count true/false leaf
        if (bdd == sylvan::mtbdd_true || bdd == sylvan::mtbdd_false) {
            return 0;
        }
        sylvan::mtbddnode_t n = sylvan::MTBDD_GETNODE(bdd);
        if (sylvan::mtbddnode_getmark(n) || sylvan::mtbddnode_isleaf(n)) {
            return 0;
        }
        sylvan::mtbddnode_setmark(n, 1);
        return 1 + nodecount_mark_no_leaves(sylvan::mtbddnode_getlow(n)) +
               nodecount_mark_no_leaves(sylvan::mtbddnode_gethigh(n));
    };

    std::function<void(const sylvan::BDD &)> unmark_rec;
    unmark_rec = [&unmark_rec](const sylvan::BDD &bdd) -> void {
        if (bdd == sylvan::mtbdd_true || bdd == sylvan::mtbdd_false) {
            return;
        }
        sylvan::mtbddnode_t n = sylvan::MTBDD_GETNODE(bdd);
        if (!sylvan::mtbddnode_getmark(n) || sylvan::mtbddnode_isleaf(n)) {
            return;
        }
        sylvan::mtbddnode_setmark(n, 0);
        unmark_rec(sylvan::mtbddnode_getlow(n));
        unmark_rec(sylvan::mtbddnode_gethigh(n));
    };

    size_t num_nodes = 0;
    for (size_t i = 0; i < num_bdds; i++) {
        num_nodes += nodecount_mark_no_leaves(bdds[i]);
    }
    for (size_t i = 0; i < num_bdds; i++) {
        unmark_rec(bdds[i]);
    }
    return num_nodes;
}

size_t Bdd::num_nodes(const sylvan::Bdd &bdd) {
    sylvan::BDD c_bdd = bdd.GetBDD();
    return num_nodes_more(&c_bdd, 1);
}

size_t Bdd::num_true_paths(const sylvan::Bdd &bdd) {
    double pathcount = sylvan::sylvan_pathcount_RUN(bdd.GetBDD(), 0);
    return pathcount;
}

size_t Bdd::num_sat_assignments(const sylvan::Bdd &bdd,
                                const std::optional<sylvan::BddSet> variables) {
    if (variables.has_value()) {
        return bdd.SatCount(*variables);
    } else {
        return bdd.SatCount(bdd.Support());
    }
}

size_t Bdd::num_sat_assignments(const sylvan::Bdd &bdd, const size_t num_vars) {
    return bdd.SatCount(num_vars);
}

namespace {

/**
 * Sylvan's internal API
 *
 * third_party/sylvan/sylvan/src/sylvan_sl.h
 * third_party/sylvan/sylvan/src/sylvan_sl.c
 * third_party/sylvan/sylvan/src/sylvan_mt.c
 * third_party/sylvan/sylvan/src/sylvan_mtbdd.c
 */

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* A SL_DEPTH of 6 means 32 bytes per bucket, of 14 means 64 bytes per bucket.
   However, there is a very large performance drop with only 6 levels. */
#ifndef SL_DEPTH
#define SL_DEPTH 14
#endif

typedef struct {
    sylvan::BDD dd;
    _Atomic(uint32_t) next[SL_DEPTH];
} __sl_bucket;

struct __sylvan_skiplist {
    __sl_bucket *buckets;
    size_t size;
    _Atomic(size_t) next;
};

/**
 * Return the assigned number of the given dd,
 * or 0 if not found.
 * third_party/sylvan/sylvan/src/sylvan_sl.c:68
 */
uint64_t __sylvan_skiplist_get(sylvan::sylvan_skiplist_t l, sylvan::MTBDD dd) {
    if (dd == sylvan::mtbdd_false || dd == sylvan::mtbdd_true)
        return 0;

    uint32_t loc = 0, k = SL_DEPTH - 1;
    for (;;) {
        /* invariant: [loc].dd < dd */
        /* note: this is always true for loc==0 */
        __sl_bucket *e = ((struct __sylvan_skiplist *)l)->buckets + loc;
        uint32_t loc_next =
            atomic_load_explicit(e->next + k, memory_order_acquire) &
            0x7fffffff;
        if (loc_next != 0 &&
            ((struct __sylvan_skiplist *)l)->buckets[loc_next].dd == dd) {
            /* found */
            return loc_next;
        } else if (loc_next != 0 &&
                   ((struct __sylvan_skiplist *)l)->buckets[loc_next].dd < dd) {
            /* go right */
            loc = loc_next;
        } else if (k > 0) {
            /* go down */
            k--;
        } else {
            return 0;
        }
    }
}

/**
 * Give the number of assigned nodes. (numbers 1,2,...,N)
 * third_party/sylvan/sylvan/src/sylvan_sl.c:156
 */
size_t __sylvan_skiplist_count(sylvan::sylvan_skiplist_t l) {
    return ((struct __sylvan_skiplist *)l)->next - 1;
}

/**
 * Get the MTBDD assigned to the number <index>, with the index 1,...,count.
 * third_party/sylvan/sylvan/src/sylvan_sl.c:162
 */
sylvan::MTBDD __sylvan_skiplist_getr(sylvan::sylvan_skiplist_t l,
                                     uint64_t index) {
    return ((struct __sylvan_skiplist *)l)->buckets[index].dd;
}

/**
 * Convert a leaf (possibly complemented) to a string representation.
 * If it does not fit in <buf> of size <buflen>, returns a freshly allocated
 * char* array.
 * third_party/sylvan/sylvan/src/sylvan_mt.c:196
 */
char *__sylvan_mt_to_str(int complement [[maybe_unused]],
                         uint32_t type,
                         uint64_t value,
                         char *buf,
                         size_t buflen) {
    assert(type < /*cl_registry_count*/ 3);
    if (type == 0) {
        size_t required = (size_t)snprintf(NULL, 0, "%" PRId64, (int64_t)value);
        char *ptr = buf;
        if (buflen < required) {
            ptr = (char *)malloc(required);
            buflen = required;
        }
        if (ptr != NULL)
            snprintf(ptr, buflen, "%" PRId64, (int64_t)value);
        return ptr;
    } else if (type == 1) {
        size_t required = (size_t)snprintf(NULL, 0, "%f", *(double *)&value);
        char *ptr = buf;
        if (buflen < required) {
            ptr = (char *)malloc(required);
            buflen = required;
        }
        if (ptr != NULL)
            snprintf(ptr, buflen, "%f", *(double *)&value);
        return ptr;
    } else if (type == 2) {
        int32_t num = (int32_t)(value >> 32);
        uint32_t denom = value & 0xffffffff;
        size_t required =
            (size_t)snprintf(NULL, 0, "%" PRId32 "/%" PRIu32, num, denom);
        char *ptr = buf;
        if (buflen < required) {
            ptr = (char *)malloc(required);
            buflen = required;
        }
        if (ptr != NULL)
            snprintf(ptr, buflen, "%" PRId32 "/%" PRIu32, num, denom);
        return ptr;
    } else {
        return NULL;
    }
}

/**
 * Write a leaf in binary form (calls write_binary callback of type).
 * third_party/sylvan/sylvan/src/sylvan_mt.c:246
 */
int __sylvan_mt_write_binary(uint32_t type,
                             uint64_t value [[maybe_unused]],
                             std::ostream &out [[maybe_unused]]) {
    assert(type < /*cl_registry_count*/ 3);
    // NOTE: Here we assume the leaf type does not have special write_binary_cb,
    // so nothing needs to be done. If that's not the case, see the original
    // function `sylvan_mt_write_binary` to implement it properly.
    return 0;
}

/**
 * Read a leaf in binary form (calls read_binary callback of type).
 * third_party/sylvan/sylvan/src/sylvan_mt.c:255
 */
int __sylvan_mt_read_binary(uint32_t type,
                            uint64_t *value [[maybe_unused]],
                            std::istream &in [[maybe_unused]]) {
    assert(type < /*cl_registry_count*/ 3);
    // NOTE: Here we assume the leaf type does not have special read_binary_cb,
    // so nothing needs to be done. If that's not the case, see the original
    // function `sylvan_mt_read_binary` to implement it properly.
    return 0;
}

/**
 * Obtain the textual representation of a leaf.
 * The returned result is either equal to the given <buf> (if the results fits)
 * or to a newly allocated array (with malloc).
 * third_party/sylvan/sylvan/src/sylvan_mtbdd.c:3003
 */
char *__mtbdd_leaf_to_str(sylvan::MTBDD leaf, char *buf, size_t buflen) {
    sylvan::mtbddnode_t n = sylvan::MTBDD_GETNODE(leaf);
    uint32_t type = sylvan::mtbddnode_gettype(n);
    uint64_t value = sylvan::mtbddnode_getvalue(n);
    int complement = sylvan::MTBDD_HASMARK(leaf) ? 1 : 0;
    return __sylvan_mt_to_str(complement, type, value, buf, buflen);
}

/**
 * Write a text representation of a leaf to the given file.
 * third_party/sylvan/sylvan/src/sylvan_mtbdd.c:2978
 */
void __mtbdd_print_leaf(std::ostream &out, sylvan::MTBDD leaf) {
    char buf[64];
    char *ptr = __mtbdd_leaf_to_str(leaf, buf, 64);
    if (ptr != NULL) {
        out << ptr;
        if (ptr != buf) {
            free(ptr);
        }
    }
}

#ifdef __cplusplus
}
#endif // __cplusplus

/**
 * Reimplementation of `mtbdd_writer_totext` from sylvan_mtbdd.c, but print to
 * `std::ostream` instead of `FILE *`.
 * third_party/sylvan/sylvan/src/sylvan_mtbdd.c:3302
 */
void my_mtbdd_writer_totext(std::ostream &out,
                            sylvan::MTBDD *dds,
                            int count,
                            int indent = 0) {
    std::string ind(indent, ' ');
    sylvan::sylvan_skiplist_t sl = sylvan::mtbdd_writer_start();

    for (int i = 0; i < count; ++i) {
        sylvan::mtbdd_writer_add_RUN(sl, dds[i]);
    }

    // mtbdd_writer_writetext
    // third_party/sylvan/sylvan/src/sylvan_mtbdd.c:3278
    {
        out << "[\n";
        size_t nodecount = __sylvan_skiplist_count(sl);
        for (size_t i = 1; i <= nodecount; i++) {
            sylvan::MTBDD dd = __sylvan_skiplist_getr(sl, i);
            sylvan::mtbddnode_t n = sylvan::MTBDD_GETNODE(dd);
            if (sylvan::mtbddnode_isleaf(n)) {
                /* serialize leaf, does not support customs yet */
                out << ind << "  leaf(" << i << ","
                    << sylvan::mtbddnode_gettype(n) << ",\"";
                __mtbdd_print_leaf(out, sylvan::MTBDD_STRIPMARK(dd));
                out << "\"),\n";
            } else {
                sylvan::MTBDD low =
                    __sylvan_skiplist_get(sl, sylvan::mtbddnode_getlow(n));
                sylvan::MTBDD high = sylvan::mtbddnode_gethigh(n);
                high = sylvan::MTBDD_TRANSFERMARK(
                    high,
                    __sylvan_skiplist_get(sl, sylvan::MTBDD_STRIPMARK(high)));
                out << ind << "  node(" << i << ","
                    << sylvan::mtbddnode_getvariable(n) << "," << low
                    << (sylvan::MTBDD_HASMARK(high) ? ",~" : ",")
                    << sylvan::MTBDD_STRIPMARK(high) << "),\n";
            }
        }
        out << ind << "]";
    }

    out << ",[";

    for (int i = 0; i < count; i++) {
        uint64_t v = sylvan::mtbdd_writer_get(sl, dds[i]);
        out << (sylvan::MTBDD_HASMARK(v) ? "~" : "")
            << sylvan::MTBDD_STRIPMARK(v) << ",";
    }

    out << "]";
    sylvan::mtbdd_writer_end(sl);
}

/**
 * Reimplementation of `mtbdd_writer_tobinary` from sylvan_mtbdd.c, but print to
 * `std::ostream` instead of `FILE *`.
 * third_party/sylvan/sylvan/src/sylvan_mtbdd.c:3257
 */
std::ostream &
my_mtbdd_writer_tobinary(std::ostream &out, sylvan::MTBDD *dds, int count) {
    sylvan::sylvan_skiplist_t sl = sylvan::mtbdd_writer_start();

    for (int i = 0; i < count; ++i) {
        sylvan::mtbdd_writer_add_RUN(sl, dds[i]);
    }

    // mtbdd_writer_writebinary
    // third_party/sylvan/sylvan/src/sylvan_mtbdd.c:3220
    {
        size_t nodecount = __sylvan_skiplist_count(sl);
        out.write((const char *)&nodecount, sizeof(nodecount));
        for (size_t i = 1; i <= nodecount; i++) {
            sylvan::MTBDD dd = __sylvan_skiplist_getr(sl, i);
            sylvan::mtbddnode_t n = sylvan::MTBDD_GETNODE(dd);
            if (sylvan::mtbddnode_isleaf(n)) {
                /* write leaf */
                out.write((const char *)n, sizeof(*n));
                uint32_t type = sylvan::mtbddnode_gettype(n);
                uint64_t value = sylvan::mtbddnode_getvalue(n);
                __sylvan_mt_write_binary(type, value, out);
            } else {
                struct sylvan::mtbddnode node;
                sylvan::MTBDD low =
                    __sylvan_skiplist_get(sl, sylvan::mtbddnode_getlow(n));
                sylvan::MTBDD high = sylvan::mtbddnode_gethigh(n);
                high = sylvan::MTBDD_TRANSFERMARK(
                    high,
                    __sylvan_skiplist_get(sl, sylvan::MTBDD_STRIPMARK(high)));
                sylvan::mtbddnode_makenode(
                    &node, sylvan::mtbddnode_getvariable(n), low, high);
                out.write((const char *)&node, sizeof(node));
            }
        }
    }

    out.write((const char *)&count, sizeof(count));

    for (int i = 0; i < count; i++) {
        uint64_t v = sylvan::mtbdd_writer_get(sl, dds[i]);
        out.write((const char *)&v, sizeof(v));
    }

    sylvan::mtbdd_writer_end(sl);
    return out;
}

/**
 * Reimplementation of `mtbdd_reader_frombinary` from sylvan_mtbdd.c, but read
 * from `std::istream` instead of `FILE *`.
 * third_party/sylvan/sylvan/src/sylvan_mtbdd.c:3384
 */
std::istream &
my_mtbdd_reader_frombinary(std::istream &in, sylvan::MTBDD *dds, int count) {
    uint64_t *arr = nullptr;

    // mtbdd_reader_readbinary
    // third_party/sylvan/sylvan/src/sylvan_mtbdd.c:3330
    {
        size_t nodecount;
        if (!in.read((char *)&nodecount, sizeof(nodecount))) {
            return in;
        }

        arr = new uint64_t[nodecount + 1];
        arr[0] = 0;
        for (size_t i = 1; i <= nodecount; i++) {
            struct sylvan::mtbddnode node;
            if (!in.read((char *)&node, sizeof(node))) {
                delete[] arr;
                return in;
            }

            if (sylvan::mtbddnode_isleaf(&node)) {
                /* serialize leaf */
                uint32_t type = sylvan::mtbddnode_gettype(&node);
                uint64_t value = sylvan::mtbddnode_getvalue(&node);
                __sylvan_mt_read_binary(type, &value, in);
                arr[i] = sylvan::mtbdd_makeleaf(type, value);
            } else {
                sylvan::MTBDD low = arr[sylvan::mtbddnode_getlow(&node)];
                sylvan::MTBDD high = sylvan::mtbddnode_gethigh(&node);
                high = sylvan::MTBDD_TRANSFERMARK(
                    high, arr[sylvan::MTBDD_STRIPMARK(high)]);
                arr[i] = sylvan::mtbdd_makenode(
                    sylvan::mtbddnode_getvariable(&node), low, high);
            }
        }
    }

    int actual_count;
    if (!in.read((char *)&actual_count, sizeof(actual_count)) ||
        actual_count != count) {
        delete[] arr;
        return in;
    }

    for (int i = 0; i < count; i++) {
        uint64_t v;
        if (!in.read((char *)&v, sizeof(v))) {
            delete[] arr;
            return in;
        }
        dds[i] = sylvan::mtbdd_reader_get(arr, v);
    }

    delete[] arr;
    return in;
}

} // namespace

std::string Bdd::to_string(const sylvan::Bdd &bdd, int indent) {
    sylvan::BDD c_bdd = bdd.GetBDD();
    std::stringstream ss;
    my_mtbdd_writer_totext(ss, &c_bdd, /*count=*/1, indent);
    return ss.str();
}

std::string Bdd::to_string_oneline(const sylvan::Bdd &bdd) {
    char *buf;
    size_t len;
    FILE *out = open_memstream(&buf, &len);
    if (!out) {
        error("open_memstream failed", errno);
    }
    sylvan::sylvan_fprint(out, bdd.GetBDD());
    fclose(out);
    std::string res(buf);
    free(buf);
    return res;
}

std::string Bdd::to_dot_string(const sylvan::Bdd &bdd) {
    char *buf;
    size_t len;
    FILE *out = open_memstream(&buf, &len);
    if (!out) {
        error("open_memstream failed", errno);
    }
    to_dot_file(bdd, out);
    fclose(out);
    std::string res(buf);
    free(buf);
    return res;
}

std::vector<char> Bdd::to_byte_vector(const sylvan::Bdd &bdd) {
    sylvan::BDD c_bdd = bdd.GetBDD();
    std::stringstream ss;
    if (!my_mtbdd_writer_tobinary(ss, &c_bdd, /*count=*/1)) {
        error("Failed to serialize bdd");
    }
    std::string str = ss.str();
    std::vector<char> res(reinterpret_cast<char *>(str.data()),
                          reinterpret_cast<char *>(str.data()) + str.size());
    return res;
}

sylvan::Bdd Bdd::from_byte_vector(const std::vector<char> &bytes) {
    std::stringstream ss(std::string(bytes.data(), bytes.size()));
    sylvan::BDD c_bdd{sylvan::sylvan_false};
    if (!my_mtbdd_reader_frombinary(ss, &c_bdd, /*count=*/1)) {
        error("Failed to deserialize bdd");
    }
    return sylvan::Bdd(c_bdd);
}

void Bdd::to_dot_file(const sylvan::Bdd &bdd, FILE *out) {
    sylvan::mtbdd_fprintdot(out, bdd.GetBDD());
}

void Bdd::to_dot_file(const sylvan::Bdd &bdd, const std::filesystem::path &fp) {
    FILE *out = fopen(fp.c_str(), "w");
    if (!out) {
        error("Failed to open " + fp.string(), errno);
    }
    to_dot_file(bdd, out);
    fclose(out);
}

void Bdd::to_ascii_file(const sylvan::Bdd &bdd, FILE *out) {
    sylvan::BDD c_bdd = bdd.GetBDD();
    sylvan::mtbdd_writer_totext_RUN(out, &c_bdd, 1);
}

void Bdd::to_ascii_file(const sylvan::Bdd &bdd,
                        const std::filesystem::path &fp) {
    FILE *out = fopen(fp.c_str(), "w");
    if (!out) {
        error("Failed to open " + fp.string(), errno);
    }
    to_ascii_file(bdd, out);
    fclose(out);
}

void Bdd::to_binary_file(const sylvan::Bdd &bdd, FILE *out) {
    sylvan::BDD c_bdd = bdd.GetBDD();
    sylvan::mtbdd_writer_tobinary_RUN(out, &c_bdd, /*count=*/1);
}

void Bdd::to_binary_file(const sylvan::Bdd &bdd,
                         const std::filesystem::path &fp) {
    FILE *out = fopen(fp.c_str(), "w");
    if (!out) {
        error("Failed to open " + fp.string(), errno);
    }
    to_binary_file(bdd, out);
    fclose(out);
}

sylvan::Bdd Bdd::from_binary_file(FILE *in) {
    sylvan::BDD c_bdd{sylvan::sylvan_false};
    sylvan::mtbdd_reader_frombinary_RUN(in, &c_bdd, /*count=*/1);
    return sylvan::Bdd(c_bdd);
}

sylvan::Bdd Bdd::from_binary_file(const std::filesystem::path &fp) {
    FILE *in = fopen(fp.c_str(), "r");
    if (!in) {
        error("Failed to open " + fp.string(), errno);
    }
    sylvan::Bdd bdd = from_binary_file(in);
    fclose(in);
    return bdd;
}

} // namespace ps
