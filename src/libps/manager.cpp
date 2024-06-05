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

Manager::~Manager() {
    if (_initialized) {
        this->reset();
    }
}

void Manager::init(size_t n_workers,
                   size_t memory_cap,
                   int table_ratio,
                   int initial_ratio) {
    if (_initialized) {
        this->reset();
    }

    lace_start(n_workers, /*dqsize=*/0);
    sylvan::sylvan_set_limits(memory_cap, table_ratio, initial_ratio);
    sylvan::sylvan_init_package();
    sylvan::Sylvan::initBdd();
    _initialized = true;
}

void Manager::reset() {
    if (!_initialized) {
        warn("libps is not initialized");
        return;
    }

    _initialized = false;
    _variables.clear();
    sylvan::sylvan_quit();
    lace_stop();
}

void Manager::register_symbolic_variable(const std::string &var_name,
                                         uint32_t nbits) {
    if (!_initialized) {
        warn("libps is not initialized");
        return;
    }

    static uint32_t starting_bddnode_index = 0;
    auto res = _variables.insert({
        var_name, {starting_bddnode_index, nbits}
    });

    if (!res.second) {
        error("Attempting to register symbolic variable '" + var_name +
              "' more than once");
    }

    starting_bddnode_index += nbits;
}

std::pair<uint32_t, uint32_t>
Manager::get_variable_offset(const std::string &var_name) const {
    auto it = _variables.find(var_name);
    if (it == _variables.end()) {
        error("Variable '" + var_name + "' not found");
    }
    return it->second;
}

sylvan::BddSet Manager::get_all_variables() const {
    sylvan::BddSet res;
    for (const auto &[_, var_info] : this->_variables) {
        const uint32_t offset = var_info.first;
        const uint32_t width = var_info.second;
        for (uint32_t i = offset; i < offset + width; ++i) {
            res.add(i);
        }
    }
    return res;
}

void Manager::suspend_threads() const {
    if (!_initialized) {
        warn("libps is not initialized");
        return;
    }

    lace_suspend();
}

void Manager::resume_threads() const {
    if (!_initialized) {
        warn("libps is not initialized");
        return;
    }

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
