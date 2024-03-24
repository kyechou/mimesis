#include "libps/PacketSet.hpp"

#include <iostream>

PacketSet::PacketSet() {
    std::cout << "Constructing an empty packet set" << std::endl;
}

PacketSet::PacketSet(const std::set<klee::ref<klee::Expr>> &constraints
                     [[maybe_unused]]) {
    std::cout << "Constructing a packet set from constraints:" << std::endl;
    for (const auto &c : constraints) {
        std::cout << c << std::endl;
    }
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
