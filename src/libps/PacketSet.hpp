#ifndef MIMESIS_SRC_PACKETSET_HPP
#define MIMESIS_SRC_PACKETSET_HPP

#include <klee/Expr.h>
#include <klee/util/Ref.h>
#include <set>
#include <string>

class PacketSet {
private:
    ;

public:
    PacketSet();
    PacketSet(const PacketSet &) = default;
    PacketSet(const std::set<klee::ref<klee::Expr>> &);

    PacketSet intersect(const PacketSet &) const;
    PacketSet intersect(const klee::ref<klee::Expr> &) const;

    bool empty() const;
    std::string to_string() const;
};

#endif // MIMESIS_SRC_PACKETSET_HPP
