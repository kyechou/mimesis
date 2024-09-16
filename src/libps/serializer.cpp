#include "libps/serializer.hpp"

#include <cereal/archives/binary.hpp>
#include <cereal/archives/json.hpp>
#include <fstream>

#include "lib/logger.hpp"
#include "libps/model.hpp"

namespace ps {

void Serializer::export_model(const Manager &manager,
                              const Model &model,
                              const std::filesystem::path &fn) {
    assert(manager.is_initialized());
    std::ofstream out(fn);
    if (fn.extension() == ".json") {
        cereal::JSONOutputArchive archive(out);
        archive(CEREAL_NVP(manager), CEREAL_NVP(model));
    } else {
        cereal::BinaryOutputArchive archive(out);
        archive(CEREAL_NVP(manager), CEREAL_NVP(model));
    }
}

Model Serializer::import_model(Manager &manager,
                               const std::filesystem::path &fn) {
    assert(manager.is_initialized());
    Model model;
    { // RAII
        std::ifstream in(fn);
        if (!in) {
            error("Failed to open file: " + fn.string());
        }
        if (fn.extension() == ".json") {
            cereal::JSONInputArchive archive(in);
            archive(CEREAL_NVP(manager), CEREAL_NVP(model));
        } else {
            cereal::BinaryInputArchive archive(in);
            archive(CEREAL_NVP(manager), CEREAL_NVP(model));
        }
    }
    return model;
}

} // namespace ps
