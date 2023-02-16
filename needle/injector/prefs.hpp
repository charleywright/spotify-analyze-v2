#pragma once

#include <filesystem>
#include <unordered_map>
#include <optional>
#include "flags.h"
#include "log.hpp"

namespace prefs
{
    bool find_file(const flags::args &args);
    void read();
    void write();

    template<typename T>
    std::optional<T> get(const logg::string &key);
    std::optional<logg::string> get(const logg::string &key);

    inline std::filesystem::path file_path;
    inline std::unordered_map<logg::string, logg::string> prefs;
    inline std::unordered_map<logg::string, logg::string> original_prefs;
}
