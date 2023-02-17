#pragma once
#include "log.hpp"
#include "flags.h"
#include <filesystem>

namespace process
{
    void generate_args(const flags::args &args);
    void spawn_and_wait();

    inline logg::string process_args;
    inline std::filesystem::path lib_to_inject;
}
