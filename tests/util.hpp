#ifndef TESTS_UTIL_HPP
#define TESTS_UTIL_HPP

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace util {

std::filesystem::path get_testdata_dir();
std::filesystem::path get_testdata_path(const std::filesystem::path &fn);
std::string get_testdata_str(const std::filesystem::path &fn);
std::vector<std::byte>
get_testdata_byte_vector(const std::filesystem::path &fn);

} // namespace util

#endif // TESTS_UTIL_HPP
