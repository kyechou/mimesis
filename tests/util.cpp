#include "util.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include "lib/logger.hpp"

namespace util {

std::filesystem::path get_testdata_dir() {
    // Get the data directory from the environment variable.
    char *data_dir = getenv("DATA_DIR");
    if (data_dir == nullptr) {
        error("No environment variable 'DATA_DIR' is set.");
    }

    // Check if the path is a directory.
    std::filesystem::path fp(data_dir);
    if (!std::filesystem::is_directory(fp)) {
        error("'" + fp.string() + "' is not an existent directory.");
    }

    return fp;
}

std::filesystem::path get_testdata_path(const std::filesystem::path &fn) {
    std::filesystem::path abs_path;

    if (fn.is_relative()) {
        std::filesystem::path dir = get_testdata_dir();
        abs_path = dir / fn;
    } else {
        abs_path = fn;
    }

    return abs_path;
}

std::string get_testdata_str(const std::filesystem::path &fn) {
    std::filesystem::path fp = get_testdata_path(fn);
    std::ifstream fin(fp);
    if (!fin) {
        error("Failed to open " + fp.string(), errno);
    }
    std::stringstream buffer;
    buffer << fin.rdbuf();
    return buffer.str();
}

std::vector<char> get_testdata_as_bytes(const std::filesystem::path &fn) {
    std::filesystem::path fp = get_testdata_path(fn);
    std::ifstream fin(fp, std::ios::binary | std::ios::ate);
    if (!fin) {
        error("Failed to open " + fp.string(), errno);
    }

    auto size = fin.tellg();
    std::vector<char> res(size);
    fin.seekg(0);
    if (!fin.read(reinterpret_cast<char *>(res.data()), size)) {
        error("Failed to read " + std::to_string(size) + " bytes from " +
              fp.string());
    }
    return res;
}

} // namespace util
