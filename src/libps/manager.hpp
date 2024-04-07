#ifndef LIBPS_MANAGER_HPP
#define LIBPS_MANAGER_HPP

#include <cstdio>

namespace ps {

class Manager {
private:
    Manager();

public:
    // Disable the copy/move constructors and the assignment operators
    Manager(const Manager &) = delete;
    Manager(Manager &&) = delete;
    Manager &operator=(const Manager &) = delete;
    Manager &operator=(Manager &&) = delete;
    ~Manager();

    static Manager &get();

    void report_stats(FILE *out) const;
};

} // namespace ps

#endif // LIBPS_MANAGER_HPP
