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
    int _depth = 0;
    BitVector _in_intf, _in_pkt;
    BitVector _eg_intf, _eg_pkt;
    sylvan::Bdd _constraint_at_current_depth;
    std::shared_ptr<TableEntry> _parent_entry;
    std::shared_ptr<SingleStateTable> _child_table;

    // This is only used for query results.
    std::set<std::shared_ptr<TableEntry>> _next_entries;

    template <class Archive>
    friend void serialize(Archive &ar, TableEntry &entry);

public:
    TableEntry() = default;
    TableEntry(const int &depth,
               const BitVector &in_intf,
               const BitVector &in_pkt,
               const BitVector &eg_intf,
               const BitVector &eg_pkt,
               const sylvan::Bdd &constraint_at_current_depth,
               const std::shared_ptr<TableEntry> &parent_entry)
        : _depth(depth), _in_intf(in_intf), _in_pkt(in_pkt), _eg_intf(eg_intf),
          _eg_pkt(eg_pkt),
          _constraint_at_current_depth(constraint_at_current_depth),
          _parent_entry(parent_entry) {}

    int depth() const { return _depth; }
    BitVector in_intf() const { return _in_intf; }
    BitVector in_pkt() const { return _in_pkt; }
    BitVector eg_intf() const { return _eg_intf; }
    BitVector eg_pkt() const { return _eg_pkt; }
    sylvan::Bdd constraint() const { return _constraint_at_current_depth; }
    sylvan::Bdd cumulative_constraint() const;
    const decltype(_parent_entry) &parent_entry() const {
        return _parent_entry;
    }
    const decltype(_child_table) &child_table() const { return _child_table; }
    const decltype(_next_entries) &next_entries() const {
        return _next_entries;
    }
    std::string to_string(int indent = 0) const;

    void set_child_table(const std::shared_ptr<SingleStateTable> &child_table) {
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

    template <class Archive>
    friend void serialize(Archive &ar, SingleStateTable &sstable);

public:
    SingleStateTable(std::shared_ptr<TableEntry> parent_entry = nullptr)
        : _depth(parent_entry ? parent_entry->depth() + 1 : 1),
          _parent_entry(parent_entry) {}

    int depth() const { return _depth; }
    std::shared_ptr<TableEntry> parent_entry() const { return _parent_entry; }
    std::string to_string() const;
    sylvan::Bdd cumulative_parent_constraint() const;
    sylvan::Bdd universe() const;
    bool all_entries_are_disjoint() const;
    bool all_entries_are_viable() const;
    bool entries_cover_entire_parent() const;
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

    template <class Archive>
    friend void serialize(Archive &ar, Model &model);

public:
    Model() = default; // Empty model

    std::string to_string() const;
    bool validate() const;
    // Returns the number of entries inserted.
    // 1: success,
    // 0: no need to insert (path constraint is unsat),
    // -1: insertion failure.
    int insert(int depth,
               const klee::ref<klee::Expr> &in_intf,
               const klee::ref<klee::Expr> &in_pkt,
               const klee::ref<klee::Expr> &eg_intf,
               const klee::ref<klee::Expr> &eg_pkt,
               const klee::ref<klee::Expr> &path_constraint);
    void finalize();
    std::set<std::shared_ptr<TableEntry>>
    query(const int max_depth, const klee::ref<klee::Expr> &constraint) const;
};

} // namespace ps

#endif // LIBPS_MODEL_HPP
