#ifndef LIBPS_MODEL_HPP
#define LIBPS_MODEL_HPP

#include <klee/Expr.h>
#include <klee/util/Ref.h>
#include <llvm/Support/raw_ostream.h>
#include <map>
#include <memory>
#include <set>
#include <sylvan_obj.hpp>

#include "libps/bitvector.hpp"

namespace ps {

class SingleStateTable;

class TableEntry {
private:
    BitVector _in_intf, _in_pkt;
    BitVector _eg_intf, _eg_pkt;
    sylvan::Bdd _constraint_at_current_depth;
    SingleStateTable *_current_table = nullptr;
    SingleStateTable *_child_table = nullptr;

    // This is only used for query results.
    std::set<std::shared_ptr<TableEntry>> _next_entries;

public:
    TableEntry(const BitVector &in_intf,
               const BitVector &in_pkt,
               const BitVector &eg_intf,
               const BitVector &eg_pkt,
               const sylvan::Bdd &constraint_at_current_depth,
               SingleStateTable *const current_table)
        : _in_intf(in_intf), _in_pkt(in_pkt), _eg_intf(eg_intf),
          _eg_pkt(eg_pkt),
          _constraint_at_current_depth(constraint_at_current_depth),
          _current_table(current_table) {}

    BitVector in_intf() const { return _in_intf; }
    BitVector in_pkt() const { return _in_pkt; }
    BitVector eg_intf() const { return _eg_intf; }
    BitVector eg_pkt() const { return _eg_pkt; }
    sylvan::Bdd constraint() const { return _constraint_at_current_depth; }
    sylvan::Bdd cumulative_constraint() const;
    SingleStateTable *current_table() const { return _current_table; }
    SingleStateTable *child_table() const { return _child_table; }
    const decltype(_next_entries) &next_entries() const {
        return _next_entries;
    }
    std::shared_ptr<TableEntry> parent_entry() const;
    int depth() const;
    std::string to_string() const;

    void set_child_table(SingleStateTable *const child_table) {
        _child_table = child_table;
    }

    void add_next_entry(const std::shared_ptr<TableEntry> &e) {
        _next_entries.insert(e);
    }
};

class SingleStateTable {
private:
    int _depth = 0;
    std::shared_ptr<TableEntry> _parent_entry;
    std::set<std::shared_ptr<TableEntry>> _table;

public:
    SingleStateTable(std::shared_ptr<TableEntry> parent_entry)
        : _depth(parent_entry ? parent_entry->depth() + 1 : 1),
          _parent_entry(parent_entry) {}

    int depth() const { return _depth; }
    std::shared_ptr<TableEntry> parent_entry() const { return _parent_entry; }
    sylvan::Bdd cumulative_parent_constraint() const;
    bool insert(const std::shared_ptr<TableEntry> &entry);

    typedef decltype(_table)::iterator iterator;
    typedef decltype(_table)::const_iterator const_iterator;
    typedef decltype(_table)::reverse_iterator reverse_iterator;
    typedef decltype(_table)::const_reverse_iterator const_reverse_iterator;
    iterator begin() { return _table.begin(); }
    const_iterator begin() const { return _table.begin(); }
    iterator end() { return _table.end(); }
    const_iterator end() const { return _table.end(); }
    reverse_iterator rbegin() { return _table.rbegin(); }
    const_reverse_iterator rbegin() const { return _table.rbegin(); }
    reverse_iterator rend() { return _table.rend(); }
    const_reverse_iterator rend() const { return _table.rend(); }
};

class Model {
private:
    std::map<int /*depth*/, std::set<std::shared_ptr<SingleStateTable>>> _model;
    std::shared_ptr<SingleStateTable> _root_table; // === *_model.at(1).begin()

public:
    // Default constructor: create the root table for depth 1.
    Model();

    bool insert(int depth,
                const klee::ref<klee::Expr> &in_intf,
                const klee::ref<klee::Expr> &in_pkt,
                const klee::ref<klee::Expr> &eg_intf,
                const klee::ref<klee::Expr> &eg_pkt,
                const klee::ref<klee::Expr> &path_constraint,
                llvm::raw_ostream *os = nullptr);
    // void finalize();
    // void export_to();
    // void import_from();
    std::set<std::shared_ptr<TableEntry>>
    query(int depth, const klee::ref<klee::Expr> &constraint) const;
};

} // namespace ps

#endif // LIBPS_MODEL_HPP
