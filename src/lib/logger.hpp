#ifndef MIMESIS_SRC_LIBS_LOGGER_HPP
#define MIMESIS_SRC_LIBS_LOGGER_HPP

#include <string>

void debug(const std::string &msg);
void info(const std::string &msg);
void warn(const std::string &msg);
void error(const std::string &msg);
void error(const std::string &msg, int errnum);

#endif // MIMESIS_SRC_LIBS_LOGGER_HPP
