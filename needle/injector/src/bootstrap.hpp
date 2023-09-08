#pragma once

#include "platform.hpp"
#include "scan.hpp"

namespace bootstrap
{
    void bootstrap(platform target, const std::string &exec, const flags::args &args, const scan_result &result);
}
