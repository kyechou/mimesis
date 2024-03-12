#include "libps/PacketSet.hpp"

#include <iostream>

PacketSet::PacketSet() {
    std::cout << "Constructing an empty packet set" << std::endl;
}

PacketSet::PacketSet(const std::set<klee::ref<klee::Expr>> &constraints) {
    std::cout << "Constructing a packet set from constraints:" << std::endl;
    for (const auto &c : constraints) {
        std::cout << c << std::endl;
    }
}

void PacketSet::testfn() const {
    std::cout << "testfn" << std::endl;
}
