#include "libps/bdd.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
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
    FILE *in = fopen(fp.c_str(), "w");
    if (!in) {
        error("Failed to open " + fp.string(), errno);
    }
    sylvan::Bdd bdd = from_binary_file(in);
    fclose(in);
    return bdd;
}

} // namespace ps
