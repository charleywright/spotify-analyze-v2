#pragma once
#include <filesystem>
#include "flags.h"

namespace executable
{
    bool find(const flags::args &args);
    bool platform_find();

    inline std::filesystem::path path;
}
