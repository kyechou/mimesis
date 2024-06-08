#include "libps/bdd.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <set>
#include <string>
#include <sylvan.h>
#include <sylvan_bdd.h>
#include <sylvan_int.h>
#include <sylvan_mtbdd.h>
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

std::string Bdd::to_string(const sylvan::Bdd &bdd) {
    char *buf;
    size_t len;
    FILE *out = open_memstream(&buf, &len);
    if (!out) {
        error("open_memstream failed", errno);
    }
    to_ascii_file(bdd, out);
    fclose(out);
    std::string res(buf);
    free(buf);
    res.pop_back(); // Remove the trailing newline.
    return res;
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

std::vector<std::byte> Bdd::to_byte_vector(const sylvan::Bdd &bdd) {
    char *buf;
    size_t len;
    FILE *out = open_memstream(&buf, &len);
    if (!out) {
        error("open_memstream failed", errno);
    }
    to_binary_file(bdd, out);
    fclose(out);
    std::vector<std::byte> res(reinterpret_cast<std::byte *>(buf),
                               reinterpret_cast<std::byte *>(buf) + len);
    free(buf);
    return res;
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
