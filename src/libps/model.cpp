#include "libps/model.hpp"

#include <cassert>
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
    if (_parent_entry) {
        return _parent_entry->cumulative_constraint() &
               _constraint_at_current_depth;
    } else {
        return _constraint_at_current_depth;
    }
}

std::string TableEntry::to_string(int indent) const {
    std::string ind(indent, ' ');
    std::string res = ind + "====[ Table Entry ]====\n";
    res += ind + "--> depth:    " + std::to_string(_depth) + "\n";
    res += ind + "--> in intf:  " + _in_intf.to_string(indent + 4) + "\n";
    res += ind + "--> in pkt:   " + _in_pkt.to_string(indent + 4) + "\n";
    res += ind + "--> out intf: " + _eg_intf.to_string(indent + 4) + "\n";
    res += ind + "--> out pkt:  " + _eg_pkt.to_string(indent + 4) + "\n";
    res += ind + "--> path con: " +
           ps::Bdd::to_string(_constraint_at_current_depth, indent + 4);
    return res;
}

std::string SingleStateTable::to_string() const {
    std::string res = "##### SS Table #####\n";
    res += "==> depth: " + std::to_string(_depth) + "\n";
    if (_parent_entry) {
        res += "==> parent entry:\n" + _parent_entry->to_string(4) + "\n";
    } else {
        res += "==> parent entry: (null)\n";
    }
    res += "==> table entries:";
    for (const auto &entry : _table) {
        res += "\n" + entry->to_string(4);
    }
    return res;
}

sylvan::Bdd SingleStateTable::cumulative_parent_constraint() const {
    if (_parent_entry) {
        return _parent_entry->cumulative_constraint();
    } else {
        return sylvan::Bdd::bddOne();
    }
}

sylvan::Bdd SingleStateTable::universe() const {
    sylvan::Bdd universe = sylvan::Bdd::bddZero(); // Empty set
    for (const auto &entry : _table) {
        universe |= entry->constraint();
    }
    return universe;
}

bool SingleStateTable::all_entries_are_disjoint() const {
    sylvan::Bdd universe = sylvan::Bdd::bddZero(); // Empty set
    for (const auto &entry : _table) {
        if (!universe.Disjoint(entry->constraint())) {
            warn("At least two table entries are not disjoint.");
            return false;
        }
        universe |= entry->constraint();
    }
    return true;
}

bool SingleStateTable::all_entries_are_viable() const {
    sylvan::Bdd parent_universe = _parent_entry
                                      ? _parent_entry->cumulative_constraint()
                                      : sylvan::Bdd::bddOne();
    for (const auto &entry : _table) {
        if (parent_universe.Disjoint(entry->constraint())) {
            warn("A table entry is not viable (can never be reached).");
            return false;
        }
    }
    return true;
}

bool SingleStateTable::entries_cover_entire_parent() const {
    sylvan::Bdd parent_universe = _parent_entry
                                      ? _parent_entry->cumulative_constraint()
                                      : sylvan::Bdd::bddOne();
    if (!parent_universe.Leq(this->universe())) {
        // parent's constraint is not a subset of this table's universe.
        warn("An SS table does not completely cover the parent entry.");
        return false;
    }
    return true;
}

bool SingleStateTable::insert(const std::shared_ptr<TableEntry> &entry) {
    for (const auto &e : _table) {
        assert((e->constraint() & entry->constraint()).isZero());
    }
    return _table.insert(entry).second;
}

std::string Model::to_string() const {
    std::string res = "Model:";
    for (const auto &[depth, tables] : _model) {
        for (const auto &table : tables) {
            assert(table);
            res += "\n\n" + table->to_string();
        }
    }
    return res;
}

bool Model::validate() const {
    for (const auto &[depth, tables] : _model) {
        for (const auto &table : tables) {
            if (!table->all_entries_are_disjoint() ||
                !table->all_entries_are_viable() ||
                !table->entries_cover_entire_parent()) {
                return false;
            }
        }
    }
    return true;
}

bool Model::insert(int depth,
                   const klee::ref<klee::Expr> &in_intf,
                   const klee::ref<klee::Expr> &in_pkt,
                   const klee::ref<klee::Expr> &eg_intf,
                   const klee::ref<klee::Expr> &eg_pkt,
                   const klee::ref<klee::Expr> &path_constraint) {
    BitVector pc_bv = KleeInterpreter::translate(path_constraint);
    assert(pc_bv.width() == 1);
    sylvan::Bdd pc = pc_bv[0];

    // Check if the path constraint is unsat. (should not happen)
    if (pc.isZero()) {
        warn("Skipping table entry: path constraint is unsat");
        return false;
    }

    // Create the root table if it doesn't already exist.
    if (!_root_table) {
        _root_table = std::make_shared<SingleStateTable>();
        _model[1] = {_root_table};
    }

    // Find the single state table where the current trace/entry belongs.
    std::shared_ptr<SingleStateTable> current_table = _root_table;

    while (current_table->depth() < depth) {
        // Find the parent entry at the current table's depth
        std::shared_ptr<TableEntry> parent_entry(nullptr);
        for (const auto &entry : *current_table) {
            if (pc.Leq(entry->constraint())) { // Leq: is a subset of
                parent_entry = entry;
                break;
            }
        }
        if (!parent_entry) {
            error("No matching parent entry at depth " +
                  std::to_string(current_table->depth()));
        }

        // Create a child table if it doesn't already exist.
        if (!parent_entry->child_table()) {
            assert(current_table->depth() == depth - 1);
            auto child_table = std::make_shared<SingleStateTable>(parent_entry);
            _model[child_table->depth()].insert(child_table);
            parent_entry->set_child_table(child_table);
        }

        current_table = parent_entry->child_table();
    }

    // Insert the new entry to the current table
    auto entry = std::make_shared<TableEntry>(
        current_table->depth(), KleeInterpreter::translate(in_intf, pc),
        KleeInterpreter::translate(in_pkt, pc),
        KleeInterpreter::translate(eg_intf, pc),
        KleeInterpreter::translate(eg_pkt, pc),
        pc.Constrain(current_table->cumulative_parent_constraint()),
        current_table->parent_entry());
    return current_table->insert(entry);
}

void Model::finalize() {
    // TODO: merge duplicate tables.
    // TODO: remove unreachable entries.
    // TODO: Add default drop rules for uncovered space.
}

std::set<std::shared_ptr<TableEntry>>
Model::query(const int max_depth,
             const klee::ref<klee::Expr> &constraint) const {
    assert(max_depth <= (int)_model.size());
    BitVector initial_constraint = KleeInterpreter::translate(constraint);
    assert(initial_constraint.width() == 1);

    // Do a BFS with constraint to build the response tree of symbolic entries.
    std::set<std::shared_ptr<TableEntry>> res;
    std::queue<std::tuple<std::shared_ptr<SingleStateTable> /*next table*/,
                          sylvan::Bdd /*constraint*/,
                          std::shared_ptr<TableEntry> /*parent entry in res*/>>
        q;

    if (_root_table && _root_table->depth() <= max_depth) {
        q.push(std::make_tuple(_root_table, initial_constraint[0], nullptr));
    }

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
                current_table->depth(), entry->in_intf().constrain(real_cons),
                entry->in_pkt().constrain(real_cons),
                entry->eg_intf().constrain(real_cons),
                entry->eg_pkt().constrain(real_cons), real_cons,
                current_table->parent_entry());
            // Populate the returning response.
            if (parent_entry) {
                parent_entry->add_next_entry(new_entry);
            } else {
                res.insert(new_entry);
            }
            // Add child table to the queue.
            if (entry->child_table() &&
                entry->child_table()->depth() <= max_depth) {
                q.push(std::make_tuple(
                    entry->child_table(),
                    real_cons.Constrain(entry->cumulative_constraint()),
                    new_entry));
            }
        }
    }

    return res;
}

} // namespace ps
