#pragma once
#include "log.hpp"
#include "flags.h"
#include <filesystem>
#include <vector>

namespace process
{
    void generate_args(const flags::args &args);
    void spawn_and_wait();

    inline std::vector<logg::string> process_args;
    inline std::filesystem::path lib_to_inject;
    inline std::filesystem::path our_process_path;
    inline std::filesystem::path our_process_dir;
}
