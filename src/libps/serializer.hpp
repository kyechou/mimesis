#ifndef LIBPS_SERIALIZATION_HPP
#define LIBPS_SERIALIZATION_HPP

#include <cereal/cereal.hpp>
#include <cereal/types/map.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/set.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/utility.hpp>
#include <cereal/types/vector.hpp>
#include <filesystem>
#include <sylvan_obj.hpp>

#include "libps/bdd.hpp"
#include "libps/manager.hpp"
#include "libps/model.hpp"

namespace cereal {

template <class Archive>
void save(Archive &ar, const sylvan::Bdd &bdd) {
    ar(cereal::make_nvp("bdd", ps::Bdd::to_byte_vector(bdd)));
}

template <class Archive>
void load(Archive &ar, sylvan::Bdd &bdd) {
    std::vector<char> bytes;
    ar(cereal::make_nvp("bdd", bytes));
    bdd = ps::Bdd::from_byte_vector(bytes);
}

} // namespace cereal

namespace ps {

template <class Archive>
void serialize(Archive &ar, BitVector &bv) {
    ar(cereal::make_nvp("bv", bv.bv));
}

template <class Archive>
void serialize(Archive &ar, TableEntry &entry) {
    ar(cereal::make_nvp("depth", entry._depth),
       cereal::make_nvp("in_intf", entry._in_intf),
       cereal::make_nvp("in_pkt", entry._in_pkt),
       cereal::make_nvp("eg_intf", entry._eg_intf),
       cereal::make_nvp("eg_pkt", entry._eg_pkt),
       cereal::make_nvp("constraint_at_current_depth",
                        entry._constraint_at_current_depth),
       cereal::make_nvp("parent_entry", entry._parent_entry),
       cereal::make_nvp("child_table", entry._child_table));
}

template <class Archive>
void serialize(Archive &ar, SingleStateTable &sstable) {
    ar(cereal::make_nvp("depth", sstable._depth),
       cereal::make_nvp("parent_entry", sstable._parent_entry),
       cereal::make_nvp("table_entries", sstable._table));
}

template <class Archive>
void serialize(Archive &ar, Model &model) {
    ar(cereal::make_nvp("model", model._model),
       cereal::make_nvp("root_table", model._root_table));
}

template <class Archive>
void serialize(Archive &ar, Manager &manager) {
    ar(cereal::make_nvp("initialized", manager._initialized),
       cereal::make_nvp("starting_bddnode_index",
                        manager._starting_bddnode_index),
       cereal::make_nvp("variables", manager._variables),
       cereal::make_nvp("klee_var_name_to_orig_name",
                        manager._klee_var_name_to_orig_name));
}

class Serializer {
public:
    static void export_model(const Manager &manager,
                             const Model &model,
                             const std::filesystem::path &fn);
    static Model import_model(Manager &manager,
                              const std::filesystem::path &fn);
};

} // namespace ps

#endif // LIBPS_SERIALIZATION_HPP
