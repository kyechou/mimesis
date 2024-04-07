#ifndef LIBPS_PACKETSET_HPP
#define LIBPS_PACKETSET_HPP

#include <klee/Expr.h>
#include <klee/util/Ref.h>
#include <set>
#include <string>
#include <sylvan_obj.hpp>

namespace ps {

class PacketSet {
private:
    sylvan::Bdd bdd;

public:
    /**
     * Construct the empty packet set.
     */
    PacketSet();
    PacketSet(const PacketSet &) = default;
    PacketSet(const sylvan::Bdd &);
    PacketSet(const klee::ref<klee::Expr> &);
    PacketSet(const std::set<klee::ref<klee::Expr>> &);

    /**
     * Construct the universe packet set that contains all packets.
     */
    static PacketSet universe();

    /**
     * Construct the empty packet set.
     */
    static PacketSet empty_set();

    // PacketSet intersect(const PacketSet &) const;
    // PacketSet intersect(const klee::ref<klee::Expr> &) const;

    bool empty() const;
    std::string to_string() const;
};

} // namespace ps

#endif // LIBPS_PACKETSET_HPP
