#ifndef MIMESIS_SRC_PACKET_SET_HPP
#define MIMESIS_SRC_PACKET_SET_HPP

#include <klee/Expr.h>
#include <klee/util/Ref.h>
#include <set>

class PacketSet {
private:
    ;

public:
    PacketSet();
    PacketSet(const std::set<klee::ref<klee::Expr>> &);

    void testfn() const;
};

#endif // MIMESIS_SRC_PACKET_SET_HPP
