#include "libps/bdd.hpp"

#include <cstdint>
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

std::string Bdd::to_string(const sylvan::Bdd &bdd [[maybe_unused]]) {
    // See `mtbdd_writer_totext`
    error("(Unimplemented)");
    return {};
}

} // namespace ps
