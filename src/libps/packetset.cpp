#include "libps/packetset.hpp"

#include <klee/Expr.h>
#include <klee/util/Ref.h>
#include <string>
#include <sylvan_obj.hpp>

#include "libps/bdd.hpp"
#include "libps/bitvector.hpp"
#include "libps/klee-interpreter.hpp"

namespace ps {

PacketSet::PacketSet() : bdd(sylvan::Bdd::bddZero()) {}

PacketSet::PacketSet(const sylvan::Bdd &from) : bdd(from) {}

PacketSet::PacketSet(const BitVector &bv) {
    assert(bv.width() == 1);
    this->bdd = bv[0];
}

PacketSet::PacketSet(const klee::ref<klee::Expr> &expr)
    : PacketSet(KleeInterpreter::translate(expr)) {}

PacketSet::PacketSet(const std::set<klee::ref<klee::Expr>> &exprs)
    : bdd(sylvan::Bdd::bddOne()) {
    for (const auto &e : exprs) {
        PacketSet ps(e);
        this->bdd &= ps.bdd;
    }
}

PacketSet PacketSet::universe() {
    return sylvan::Bdd::bddOne();
}

PacketSet PacketSet::empty_set() {
    return sylvan::Bdd::bddZero();
}

bool PacketSet::empty() const {
    return this->bdd.isZero();
}

size_t PacketSet::size() const {
    return Bdd::num_sat_assignments(this->bdd);
}

size_t PacketSet::num_paths() const {
    return Bdd::num_true_paths(this->bdd);
}

std::string PacketSet::to_string() const {
    return Bdd::to_string(this->bdd);
}

void PacketSet::to_dot_file(const std::filesystem::path &fp) const {
    Bdd::to_dot_file(this->bdd, fp);
}

} // namespace ps
