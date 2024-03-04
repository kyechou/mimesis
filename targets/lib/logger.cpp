#include "lib/logger.hpp"

#include <cstdlib>
#include <iostream>
#include <string.h>

using namespace std;

void debug(const string &msg) {
    cerr << "[debug] " << msg << endl;
}

void info(const string &msg) {
    cerr << "[info] " << msg << endl;
}

void warn(const string &msg) {
    cerr << "[warning] " << msg << endl;
}

void error(const string &msg) {
    cerr << "[error] " << msg << endl;
    exit(-1);
}

void error(const string &msg, int err_num) {
    locale_t locale = newlocale(LC_ALL_MASK, "", 0);
    string err_str = strerror_l(err_num, locale);
    freelocale(locale);
    cerr << "[error] " << msg << ": " << err_str << endl;
    exit(err_num);
}
