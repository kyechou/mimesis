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
    _starting_bddnode_index = 0;
    _variables.clear();
    sylvan::sylvan_quit();
    lace_stop();
}

void Manager::register_symbolic_variable(
    const std::string &var_name,
    uint32_t nbits,
    const std::optional<std::string> &klee_var_name) {
    if (!_initialized) {
        warn("libps is not initialized");
        return;
    }

    auto res = _variables.insert({
        var_name, {_starting_bddnode_index, nbits}
    });

    if (res.second) {
        _starting_bddnode_index += nbits;
    }

    if (klee_var_name) {
        _klee_var_name_to_orig_name[*klee_var_name] = var_name;
    }
}

std::pair<uint32_t, uint32_t>
Manager::get_variable_offset(const std::string &var_name) const {
    std::string real_var_name = var_name;

    if (auto it = _klee_var_name_to_orig_name.find(var_name);
        it != _klee_var_name_to_orig_name.end()) {
        real_var_name = it->second;
    }

    if (auto it = _variables.find(real_var_name); it != _variables.end()) {
        return it->second;
    }

    error("Variable '" + real_var_name + "' not found");
    return {};
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

std::string Manager::report_stats() const {
    if (!_initialized) {
        warn("libps is not initialized");
        return {};
    }

    char *buf;
    size_t len;
    FILE *out = open_memstream(&buf, &len);
    if (!out) {
        error("open_memstream failed", errno);
    }
    sylvan::sylvan_stats_report(out);
    fclose(out);
    std::string res(buf);
    free(buf);
    return res;
}

} // namespace ps
