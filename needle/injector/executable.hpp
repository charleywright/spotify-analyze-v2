#pragma once
#include <filesystem>
#include "flags.h"

namespace executable
{
    bool find(const flags::args &args);

    inline std::filesystem::path path;
}
