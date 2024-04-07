#ifndef MIMESIS_SRC_LIBS_LOGGER_HPP
#define MIMESIS_SRC_LIBS_LOGGER_HPP

#include <iostream>
#include <ostream>
#include <string>

void debug(const std::string &msg, std::ostream &os = std::cout);
void info(const std::string &msg, std::ostream &os = std::cout);
void warn(const std::string &msg, std::ostream &os = std::cout);
void error(const std::string &msg, std::ostream &os = std::cout);
void error(const std::string &msg, int errnum, std::ostream &os = std::cout);

#endif // MIMESIS_SRC_LIBS_LOGGER_HPP
