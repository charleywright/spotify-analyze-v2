#pragma once

#include <filesystem>
#include <unordered_map>
#include <optional>
#include "flags.h"
#include "log.hpp"

namespace prefs
{
    bool find_file(const flags::args &args);
    bool platform_find_file();
    void read();
    void write();
    void set_str(const logg::string &key, const logg::string &value);
    void set_int(const logg::string &key, std::int64_t value);
    void set_bool(const logg::string &key, bool value);

    void process_args(const flags::args &args);

    template<typename T>
    std::optional<T> get(const logg::string &key);
    std::optional<logg::string> get(const logg::string &key);

    inline std::filesystem::path file_path;
    inline std::unordered_map<logg::string, logg::string> prefs;
    inline std::unordered_map<logg::string, logg::string> original_prefs;
    inline bool preserve_new_prefs = false;
}
