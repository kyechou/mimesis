#pragma once

#include <chrono>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#define _STATS_START(op) Stats::get().start(op)
#define _STATS_STOP(op) Stats::get().stop(op)
#define _STATS_RESET() Stats::get().reset()
#define _STATS_LOGRESULTS(model_name) Stats::get().log_results(model_name)

class Invariant;

class Stats {
public:
    using clock = std::chrono::high_resolution_clock;
    enum class Op {
        __OP_START__,
        ALL,
        MODEL_IMPORT,
        QUERY,
        // CONCRETE_QUERY,
        // SYMBOLIC_QUERY,
        __OP_END__,
    };
    class OpHasher {
    public:
        size_t operator()(const Op &op) const {
            return std::hash<int>()(static_cast<int>(op));
        }
    };

private:
    const std::vector<Op> _all_ops = {
        Op::ALL, Op::MODEL_IMPORT, Op::QUERY,
        // Op::CONCRETE_QUERY,
        // Op::SYMBOLIC_QUERY,
    };
    const std::unordered_map<Op, std::string, OpHasher> _op_str = {
        {Op::ALL,          "Everything"       },
        {Op::MODEL_IMPORT, "Import model"     },
        {Op::QUERY,        "Process one query"},
        // {Op::CONCRETE_QUERY, "Process one concrete query"},
        // {Op::SYMBOLIC_QUERY, "Process one symbolic query"},
    };
    std::unordered_map<Op, clock::time_point, OpHasher> _start_ts;
    std::unordered_map<Op, std::chrono::microseconds, OpHasher> _time = {
        {Op::ALL,          {}},
        {Op::MODEL_IMPORT, {}},
        {Op::QUERY,        {}},
        // {Op::CONCRETE_QUERY, {}},
        // {Op::SYMBOLIC_QUERY, {}},
    };
    std::unordered_map<Op, long /* KiB */, OpHasher> _max_rss = {
        {Op::ALL,          0},
        {Op::MODEL_IMPORT, 0},
        {Op::QUERY,        0},
        // {Op::CONCRETE_QUERY, 0},
        // {Op::SYMBOLIC_QUERY, 0},
    };
    std::unordered_map<Op, long /* KiB */, OpHasher> _curr_rss = {
        {Op::ALL,          0},
        {Op::MODEL_IMPORT, 0},
        {Op::QUERY,        0},
        // {Op::CONCRETE_QUERY, 0},
        // {Op::SYMBOLIC_QUERY, 0},
    };

    Stats() = default;

    long get_peak_rss() const;
    long get_current_rss() const;
    std::pair<long, long> get_rss() const;

public:
    Stats(const Stats &) = delete;
    Stats(Stats &&) = delete;
    Stats &operator=(const Stats &) = delete;
    Stats &operator=(Stats &&) = delete;

    static Stats &get();

    void start(Op);
    void stop(Op);
    void reset();
    void log_results(const std::string &model_name) const;
};
