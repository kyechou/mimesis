#ifndef LIBPS_MANAGER_HPP
#define LIBPS_MANAGER_HPP

#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <sylvan_obj.hpp>
#include <unordered_map>
#include <utility>

namespace ps {

class Manager {
private:
    bool _initialized = false;
    uint32_t _starting_bddnode_index = 0;
    std::unordered_map<std::string, std::pair<uint32_t, uint32_t>> _variables;
    std::unordered_map<std::string, std::string> _klee_var_name_to_orig_name;

    Manager() = default;

public:
    // Disable the copy/move constructors and the assignment operators
    Manager(const Manager &) = delete;
    Manager(Manager &&) = delete;
    Manager &operator=(const Manager &) = delete;
    Manager &operator=(Manager &&) = delete;
    ~Manager();

    /**
     * Get the libps manager singleton.
     */
    static Manager &get();

    /**
     * See the following functions for parameter definitions.
     * - lace_start
     * - sylvan::sylvan_set_limits
     */
    void init(size_t n_workers = 1,
              size_t memory_cap = 1UL << 30, // 1 GiB
              int table_ratio = 1,
              int initial_ratio = 5);

    /**
     * Reset the manager to the uninitialized state as if the object was just
     * constructed.
     */
    void reset();
    /**
     * All symbolic variables must be registered before being used to create
     * BDDs.
     */
    void register_symbolic_variable(
        const std::string &var_name,
        uint32_t nbits,
        const std::optional<std::string> &klee_var_name = std::nullopt);
    /**
     * Returns the bit offset information (starting bit, number of bits) of the
     * symbolic variable `var_name`.
     */
    std::pair<uint32_t, uint32_t>
    get_variable_offset(const std::string &var_name) const;
    /**
     * Returns a set of all BDD Boolean variables.
     */
    sylvan::BddSet get_all_variables() const;
    /**
     * Suspend the lace worker threads. (They busy-wait while idling.)
     */
    void suspend_threads() const;
    /**
     * Resume the lace worker threads if suspended.
     */
    void resume_threads() const;
    /**
     * Write sylvan stats report to `out`.
     */
    std::string report_stats() const;
};

} // namespace ps

#endif // LIBPS_MANAGER_HPP
