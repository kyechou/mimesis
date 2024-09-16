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

    if (op < Op::__OP_TYPE_DIVIDER__) {
        auto [maxrss, currrss] = this->get_rss();
        _time.at(op) = std::move(duration);
        _max_rss.at(op) = maxrss;
        _curr_rss.at(op) = currrss;
    } else if (op > Op::__OP_TYPE_DIVIDER__ && op < Op::TIMEOUT) {
    } else {
        error("Invalid op: " + to_string(static_cast<int>(op)));
    }
}

void Stats::reset() {
    _start_ts.clear();

    for (const Op &op : _all_ops) {
        if (op < Op::__OP_TYPE_DIVIDER__) {
            _time.at(op) = microseconds{};
            _max_rss.at(op) = 0;
            _curr_rss.at(op) = 0;
        } else if (op > Op::__OP_TYPE_DIVIDER__) {
        }
    }
}

void Stats::log_results(Op op) const {
    const auto &time = _time.at(op).count();
    const auto &max_rss = _max_rss.at(op);
    const auto &cur_rss = _curr_rss.at(op);

    if (op == Op::MAIN_PROC) {
        info("====================");
        info("Time: " + to_string(time) + " usec");
        info("Peak memory: " + to_string(max_rss) + " KiB");
        info("Current memory: " + to_string(cur_rss) + " KiB");
    } else if (op == Op::CHECK_INVARIANT) {
        const string filename = "invariant.stats.csv";
        ofstream ofs(filename);
        if (!ofs) {
            error("Failed to open " + filename);
        }

        ofs << "Time (usec), Peak memory (KiB), Current memory (KiB)" << endl
            << time << ", " << max_rss << ", " << cur_rss << endl;
    } else if (op == Op::CHECK_EC) {
        const string filename = to_string(getpid()) + ".stats.csv";
        ofstream ofs(filename);
        if (!ofs) {
            error("Failed to open " + filename);
        }

        ofs << "Time (usec), Peak memory (KiB), Current memory (KiB)" << endl
            << time << ", " << max_rss << ", " << cur_rss << endl;
        ofs << "Overall concretization (usec), " << "Emulation startup (usec), "
            << "Rewind (usec), " << "Emulation reset (usec), "
            << "Replay packets (usec), " << "Rewind injection count, "
            << "Packet latency (usec), " << "Drop latency (usec), "
            << "Timeout value (usec)" << endl;
    } else {
        error("Invalid op: " + to_string(static_cast<int>(op)));
    }
}
