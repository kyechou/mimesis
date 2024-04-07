#include "libps/packetset.hpp"

#include <iostream>
#include <sylvan_obj.hpp>

namespace ps {

PacketSet::PacketSet() : bdd(sylvan::Bdd::bddZero()) {}

PacketSet::PacketSet(const sylvan::Bdd &from) : bdd(from) {}

PacketSet::PacketSet(const klee::ref<klee::Expr> &expr) {
    // TODO: Implement
    expr->getKind();
}

PacketSet::PacketSet(const std::set<klee::ref<klee::Expr>> &exprs)
    : bdd(sylvan::Bdd::bddOne()) {
    std::cout << "Number of constraints: " << exprs.size() << std::endl;
    std::cout << "Constructing a packet set from constraints:" << std::endl;

    for (const auto &e : exprs) {
        std::cout << e << std::endl;
        PacketSet ps(e);
        bdd *= ps.bdd;
    }
}

PacketSet PacketSet::universe() {
    return sylvan::Bdd::bddOne();
}

PacketSet PacketSet::empty_set() {
    return sylvan::Bdd::bddZero();
}

// PacketSet PacketSet::intersect(const PacketSet &ps [[maybe_unused]]) const {
//     return *this;
// }
//
// PacketSet PacketSet::intersect(const klee::ref<klee::Expr> &condition
//                                [[maybe_unused]]) const {
//     return *this;
// }

bool PacketSet::empty() const {
    return bdd.isZero();
}

std::string PacketSet::to_string() const {
    // TODO: Implement
    // bdd.GetBDD();
    return "(Unimplemented)";
}

} // namespace ps

// See third_party/sylvan/sylvan/examples/simple.cpp

// Maybe useful functions:
//
// mtbdd_satcount(bdd, number_of_vars): compute the number of minterms
// (assignments that lead to True) for a function with <number_of_vars>
// variables; we don’t need to know the exact variables that may be in the BDD,
// just how many there are.
//
// sylvan_pathcount(bdd): compute the number of distinct paths to True.
//
// mtbdd_nodecount(bdd): compute the number of nodes (and leaves) in the BDD.
//
// mtbdd_nodecount_more(array, length): compute the number of nodes (and leaves)
// in the array of BDDs.
