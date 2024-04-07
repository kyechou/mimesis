#include "libps/manager.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <sylvan.h>
#include <sylvan_common.h>
#include <sylvan_obj.hpp>

#include "lib/logger.hpp"

namespace ps {

Manager &Manager::get() {
    static Manager instance;
    return instance;
}

void Manager::init(size_t n_workers,
                   size_t memory_cap,
                   int table_ratio,
                   int initial_ratio) {
    lace_start(n_workers, /*dqsize=*/0);
    sylvan::sylvan_set_limits(memory_cap, table_ratio, initial_ratio);
    sylvan::sylvan_init_package();
    sylvan::Sylvan::initBdd();
    _initialized = true;
}

Manager::~Manager() {
    if (!_initialized) {
        warn("libps is not initialized");
        return;
    }

    sylvan::sylvan_quit();
    lace_stop();
}

void Manager::register_symbolic_variable(const std::string &var_name,
                                         uint32_t nbits) {
    if (!_initialized) {
        warn("libps is not initialized");
        return;
    }

    auto res = _variables.insert({
        var_name, {_starting_bddnode_index, nbits}
    });

    if (!res.second) {
        error("Attempting to register symbolic variable '" + var_name +
              "' more than once");
    }

    _starting_bddnode_index += nbits;
}

std::pair<uint32_t, uint32_t>
Manager::get_variable_offset(const std::string &var_name) const {
    auto it = _variables.find(var_name);
    if (it == _variables.end()) {
        error("Variable '" + var_name + "' not found");
    }
    return it->second;
}

void Manager::suspend_threads() const {
    lace_suspend();
}

void Manager::resume_threads() const {
    lace_resume();
}

void Manager::report_stats(FILE *out) const {
    if (!_initialized) {
        warn("libps is not initialized");
        return;
    }

    sylvan::sylvan_stats_report(out);
    if (fflush(out) != 0) {
        error("fflush() failed", errno);
    }
}

} // namespace ps
