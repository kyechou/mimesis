#include "libps/model.hpp"

#include <memory>
#include <sylvan_obj.hpp>

#include "lib/logger.hpp"
#include "libps/bdd.hpp"
#include "libps/bitvector.hpp"
#include "libps/klee-interpreter.hpp"

namespace ps {

sylvan::Bdd TableEntry::cumulative_constraint() const {
    auto parent = parent_entry();
    if (parent) {
        return parent->cumulative_constraint() & _constraint_at_current_depth;
    } else {
        return _constraint_at_current_depth;
    }
}

std::shared_ptr<TableEntry> TableEntry::parent_entry() const {
    assert(_current_table);
    return _current_table->parent_entry();
}

std::string TableEntry::to_string() const {
    std::string res = "=== Table Entry ===\n";
    res += "-> depth:    " + std::to_string(_current_table->depth()) + "\n";
    res += "-> in intf:  " + _in_intf.to_string() + "\n";
    res += "-> in pkt:   " + _in_pkt.to_string() + "\n";
    res += "-> out intf: " + _eg_intf.to_string() + "\n";
    res += "-> out pkt:  " + _eg_pkt.to_string() + "\n";
    res += "-> path con: " + ps::Bdd::to_string(_constraint_at_current_depth);
    res += "\n";
    return res;
}

bool SingleStateTable::insert(const std::shared_ptr<TableEntry> &entry) {
    for (const auto &e : _table) {
        assert((e->constraint() & entry->constraint()).isZero());
    }
    return _table.insert(entry).second;
}

Model::Model() {
    _root_table = std::make_shared<SingleStateTable>(/*depth=*/1,
                                                     /*parent_entry=*/nullptr);
    _model[1] = {_root_table};
}

bool Model::insert(int depth,
                   const klee::ref<klee::Expr> &in_intf,
                   const klee::ref<klee::Expr> &in_pkt,
                   const klee::ref<klee::Expr> &eg_intf,
                   const klee::ref<klee::Expr> &eg_pkt,
                   const klee::ref<klee::Expr> &path_constraints) {
    BitVector pc_bv = KleeInterpreter::translate(path_constraints);
    assert(pc_bv.width() == 1);
    sylvan::Bdd pc = pc_bv[0];

    if (depth == 1) {
        auto current_table = _root_table;
        auto entry = std::make_shared<TableEntry>(
            KleeInterpreter::translate(in_intf, pc),
            KleeInterpreter::translate(in_pkt, pc),
            KleeInterpreter::translate(eg_intf, pc),
            KleeInterpreter::translate(eg_pkt, pc), pc, current_table.get());
        bool res [[maybe_unused]] = current_table->insert(entry);
        // if (res) {
        //     info("Insert symbolic entry: " + entry->to_string());
        // } else {
        //     warn("Failed to insert entry: " + entry->to_string());
        // }
    } else {
        // TODO: Implement.
        error("Not implemented yet");
    }

    return true;
}

} // namespace ps
