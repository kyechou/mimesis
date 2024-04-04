#include "libps/PacketSet.hpp"

#include <iostream>

#include <sylvan.h>
#include <sylvan_common.h>
#include <sylvan_mtbdd.h>

PacketSet::PacketSet() {
    std::cout << "Constructing an empty packet set" << std::endl;
}

PacketSet::PacketSet(const std::set<klee::ref<klee::Expr>> &constraints
                     [[maybe_unused]]) {
    std::cout << "Number of constraints: " << constraints.size() << std::endl;
    std::cout << "Constructing a packet set from constraints:" << std::endl;
    for (const auto &c : constraints) {
        std::cout << c << std::endl;
    }

    lace_start(/*n_workers=*/1, /*dqsize=*/0);
    sylvan::sylvan_set_limits(/*memory_cap=*/512 * 1024 * 1024, // 512 MB
                              /*table_ratio=*/1, /*initial_ratio=*/5);
    sylvan::sylvan_init_package();
    sylvan::sylvan_init_mtbdd();

    // do stuff

    sylvan::sylvan_stats_report(stdout);
    sylvan::sylvan_quit();
    lace_stop();
}

PacketSet PacketSet::intersect(const PacketSet &ps [[maybe_unused]]) const {
    return *this;
}

PacketSet PacketSet::intersect(const klee::ref<klee::Expr> &condition
                               [[maybe_unused]]) const {
    return *this;
}

bool PacketSet::empty() const {
    return true;
}

std::string PacketSet::to_string() const {
    return "(Unimplemented)";
}
