#include "lib/stats.hpp"

#include <cassert>
#include <chrono>
#include <fstream>
#include <string>
#include <sys/resource.h>
#include <unistd.h>

#include "lib/logger.hpp"

using namespace std;
using namespace std::chrono;

long Stats::get_peak_rss() const {
    struct rusage ru;

    if (getrusage(RUSAGE_SELF, &ru) < 0) {
        error("getrusage() failed");
    }

    return ru.ru_maxrss; // KiB
}

long Stats::get_current_rss() const {
    static const string fn = "/proc/self/statm";
    static const long page_size = getpagesize() / 1024; // KiB per page
    ifstream ifs(fn);

    if (!ifs) {
        error("Failed to open " + fn);
    }

    long dummy, current_page_count;
    ifs >> dummy >> current_page_count;
    return current_page_count * page_size; // KiB
}

pair<long, long> Stats::get_rss() const {
    static const string fn = "/proc/self/status";
    ifstream ifs(fn);

    if (!ifs) {
        error("Failed to open " + fn);
    }

    string line;
    long maxrss = 0, currrss = 0;

    while (getline(ifs, line)) {
        if (line.starts_with("VmHWM:")) {
            maxrss = stol(line.substr(6));
        } else if (line.starts_with("VmRSS:")) {
            currrss = stol(line.substr(6));
            break;
        }
    }

    return {maxrss, currrss}; // KiB, KiB
}

Stats &Stats::get() {
    static Stats instance;
    return instance;
}

void Stats::start(Op op) {
    if (_start_ts.count(op) > 0) {
        error("Multiple starting time point for op: " + _op_str.at(op));
    }

    _start_ts[op] = clock::now();
}

void Stats::stop(Op op) {
    auto it = _start_ts.find(op);

    if (it == _start_ts.end()) {
        error("No starting time point found for op: " + _op_str.at(op));
    }

    auto duration = duration_cast<microseconds>(clock::now() - it->second);
    _start_ts.erase(it);

    auto [maxrss, currrss] = this->get_rss();
    _time.at(op) = std::move(duration);
    _max_rss.at(op) = maxrss;
    _curr_rss.at(op) = currrss;
}

void Stats::reset() {
    _start_ts.clear();

    for (const Op &op : _all_ops) {
        _time.at(op) = microseconds{};
        _max_rss.at(op) = 0;
        _curr_rss.at(op) = 0;
    }
}

void Stats::log_results(const std::string &model_name) const {
    // model_name, total_time_usec, import_model_time, query_time, memory_kb
    std::cout << model_name << "," << _time.at(Op::ALL).count() << ","
              << _time.at(Op::MODEL_IMPORT).count() << ","
              << _time.at(Op::QUERY).count() << "," << _max_rss.at(Op::ALL)
              << std::endl;
}
