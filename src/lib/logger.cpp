#include "lib/logger.hpp"

#include <cstdlib>
#include <iostream>
#include <string.h>

using namespace std;

void debug(const string &msg, ostream &os) {
    os << "[debug] " << msg << endl;
}

void info(const string &msg, ostream &os) {
    os << "[info] " << msg << endl;
}

void warn(const string &msg, ostream &os) {
    os << "[warning] " << msg << endl;
}

void error(const string &msg, ostream &os) {
    os << "[error] " << msg << endl;
    exit(-1);
}

void error(const string &msg, int errnum, ostream &os) {
    locale_t locale = newlocale(LC_ALL_MASK, "", 0);
    string err_str = strerror_l(errnum, locale);
    freelocale(locale);
    os << "[error] " << msg << ": " << err_str << endl;
    exit(errnum);
}
