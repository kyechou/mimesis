#ifndef MIMESIS_SRC_PACKET_SET_HPP
#define MIMESIS_SRC_PACKET_SET_HPP

#include <klee/Expr.h>
#include <klee/util/Ref.h>
#include <set>

class PacketSet {
private:
    ;

public:
    // std::set<klee::ref<klee::Expr>>

    PacketSet();
    PacketSet(const std::set<klee::ref<klee::Expr>> &);
};

#endif // MIMESIS_SRC_PACKET_SET_HPP
