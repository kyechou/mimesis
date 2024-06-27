#include "libps/model.hpp"

#include <memory>
#include <queue>
#include <string>
#include <sylvan_obj.hpp>
#include <tuple>
#include <utility>

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

int TableEntry::depth() const {
    assert(_current_table);
    return _current_table->depth();
}

std::string TableEntry::to_string() const {
    std::string res = "=== Table Entry ===\n";
    res += "-> depth:    " + std::to_string(depth()) + "\n";
    res += "-> in intf:  " + _in_intf.to_string() + "\n";
    res += "-> in pkt:   " + _in_pkt.to_string() + "\n";
    res += "-> out intf: " + _eg_intf.to_string() + "\n";
    res += "-> out pkt:  " + _eg_pkt.to_string() + "\n";
    res += "-> path con: " + ps::Bdd::to_string(_constraint_at_current_depth);
    res += "\n";
    return res;
}

sylvan::Bdd SingleStateTable::cumulative_parent_constraint() const {
    if (_parent_entry) {
        return _parent_entry->cumulative_constraint();
    } else {
        return sylvan::Bdd::bddOne();
    }
}

bool SingleStateTable::insert(const std::shared_ptr<TableEntry> &entry) {
    for (const auto &e : _table) {
        assert((e->constraint() & entry->constraint()).isZero());
    }
    return _table.insert(entry).second;
}

Model::Model() {
    _root_table = std::make_shared<SingleStateTable>(/*parent_entry=*/nullptr);
    _model[1] = {_root_table};
}

bool Model::insert(int depth,
                   const klee::ref<klee::Expr> &in_intf,
                   const klee::ref<klee::Expr> &in_pkt,
                   const klee::ref<klee::Expr> &eg_intf,
                   const klee::ref<klee::Expr> &eg_pkt,
                   const klee::ref<klee::Expr> &path_constraint,
                   llvm::raw_ostream *os) {
    BitVector pc_bv = KleeInterpreter::translate(path_constraint);
    assert(pc_bv.width() == 1);
    sylvan::Bdd pc = pc_bv[0];
    SingleStateTable *current_table = _root_table.get();

    // Find the single state table where the current trace/entry belongs.
    while (current_table->depth() < depth) {
        // Find the parent entry at the current table's depth
        std::shared_ptr<TableEntry> parent(nullptr);
        for (const auto &entry : *current_table) {
            if (pc.Leq(entry->constraint())) { // Leq: is a subset of
                parent = entry;
                break;
            }
        }
        if (!parent) {
            error("No matching parent entry at depth " +
                  std::to_string(current_table->depth()));
        }

        // Create a child table if it doesn't already exist.
        if (!parent->child_table()) {
            assert(current_table->depth() == depth - 1);
            auto child_table =
                std::make_shared<SingleStateTable>(/*parent_entry=*/parent);
            _model[child_table->depth()].insert(child_table);
            parent->set_child_table(child_table.get());
        }

        current_table = parent->child_table();
    }

    // Insert the new entry to the current table
    auto entry = std::make_shared<TableEntry>(
        KleeInterpreter::translate(in_intf, pc),
        KleeInterpreter::translate(in_pkt, pc),
        KleeInterpreter::translate(eg_intf, pc),
        KleeInterpreter::translate(eg_pkt, pc),
        pc.Constrain(current_table->cumulative_parent_constraint()),
        current_table);
    if (os) {
        *os << "Model insert: " << entry->to_string();
    }
    return current_table->insert(entry);
}

std::set<std::shared_ptr<TableEntry>>
Model::query(int depth, const klee::ref<klee::Expr> &constraint) const {
    assert(depth <= (int)_model.size());
    BitVector initial_constraint = KleeInterpreter::translate(constraint);
    assert(initial_constraint.width() == 1);

    // Do a BFS with constraint to build the response tree of symbolic entries.
    std::set<std::shared_ptr<TableEntry>> res;
    std::queue<std::tuple<SingleStateTable * /*next table*/,
                          sylvan::Bdd /*constraint*/,
                          std::shared_ptr<TableEntry> /*parent entry in res*/>>
        q;
    q.push(std::make_tuple(_root_table.get(), initial_constraint[0], nullptr));

    while (!q.empty()) {
        auto [current_table, constraint, parent_entry] = q.front();
        q.pop();

        for (const auto &entry : *current_table) {
            if (entry->constraint().Disjoint(constraint)) {
                continue;
            }

            // Make a new entry for the response.
            sylvan::Bdd real_cons = entry->constraint() & constraint;
            auto new_entry = std::make_shared<TableEntry>(
                entry->in_intf().constrain(real_cons),
                entry->in_pkt().constrain(real_cons),
                entry->eg_intf().constrain(real_cons),
                entry->eg_pkt().constrain(real_cons), real_cons, current_table);
            // Populate the returning response.
            if (parent_entry) {
                parent_entry->add_next_entry(new_entry);
            } else {
                res.insert(new_entry);
            }
            // Add child table to the queue.
            if (entry->child_table()) {
                q.push(std::make_tuple(entry->child_table(), real_cons,
                                       new_entry));
            }
        }
    }

    return res;
}

} // namespace ps
