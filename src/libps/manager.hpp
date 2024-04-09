#ifndef LIBPS_MANAGER_HPP
#define LIBPS_MANAGER_HPP

#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <utility>

namespace ps {

class Manager {
private:
    bool _initialized = false;
    std::unordered_map<std::string, std::pair<uint32_t, uint32_t>> _variables;

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
    void init(size_t n_workers,
              size_t memory_cap,
              int table_ratio,
              int initial_ratio);
    /**
     * All symbolic variables must be registered before being used to create
     * BDDs.
     */
    void register_symbolic_variable(const std::string &var_name,
                                    uint32_t nbits);
    /**
     * Returns the bit offset information (starting bit, number of bits) of the
     * symbolic variable `var_name`.
     */
    std::pair<uint32_t, uint32_t>
    get_variable_offset(const std::string &var_name) const;
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
    void report_stats(FILE *out) const;
};

} // namespace ps

#endif // LIBPS_MANAGER_HPP
