#include "packet_set.hpp"

// using namespace std;

PacketSet::PacketSet() {}

PacketSet::PacketSet(const std::set<klee::ref<klee::Expr>> &constraints
                     [[maybe_unused]]) {}
