#include "libps/bdd.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <set>
#include <sylvan.h>
#include <sylvan_int.h>
#include <sylvan_mtbdd.h>
#include <sylvan_obj.hpp>

#include "lib/logger.hpp"

namespace ps {

std::set<uint32_t> Bdd::variables(const sylvan::Bdd &bdd) {
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

    collect_bdd_vars_recursive(bdd.GetBDD());
    unmark_bddnodes_recursive(bdd.GetBDD());
    return vars;
}

size_t Bdd::variable_count(const sylvan::Bdd &bdd) {
    return Bdd::variables(bdd).size();
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

void Bdd::to_binary_file(const sylvan::Bdd &bdd [[maybe_unused]],
                         const std::filesystem::path &fp [[maybe_unused]]) {
    // TODO: See `mtbdd_writer_tobinary`
    error("Not yet implemented");
}

} // namespace ps
