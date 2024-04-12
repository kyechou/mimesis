#ifndef LIBPS_PACKETSET_HPP
#define LIBPS_PACKETSET_HPP

#include <filesystem>
#include <klee/Expr.h>
#include <klee/util/Ref.h>
#include <set>
#include <string>
#include <sylvan_obj.hpp>

#include "libps/bitvector.hpp"

namespace ps {

class PacketSet {
private:
    sylvan::Bdd bdd;

public:
    /**
     * Construct the empty packet set by default.
     */
    PacketSet();
    PacketSet(const sylvan::Bdd &);
    PacketSet(const BitVector &);
    PacketSet(const klee::ref<klee::Expr> &);
    PacketSet(const std::set<klee::ref<klee::Expr>> &);

    /**
     * Construct the universe packet set that contains all packets.
     */
    static PacketSet universe();
    /**
     * Construct the empty packet set that contains no packet.
     */
    static PacketSet empty_set();

    bool empty() const;
    size_t size() const;
    /**
     * Returns the number of paths that lead to True in the BDD.
     */
    size_t num_paths() const;
    std::string to_string() const;
    void to_dot_file(const std::filesystem::path &) const;
    PacketSet intersection(const PacketSet &) const;
    PacketSet set_union(const PacketSet &) const;
    PacketSet difference(const PacketSet &) const;
    PacketSet complement() const;
    PacketSet operator&(const PacketSet &) const;
    PacketSet operator|(const PacketSet &) const;
    PacketSet operator-(const PacketSet &) const;
    PacketSet operator~() const;
    PacketSet &operator&=(const PacketSet &);
    PacketSet &operator|=(const PacketSet &);
    PacketSet &operator-=(const PacketSet &);
};

} // namespace ps

#endif // LIBPS_PACKETSET_HPP
