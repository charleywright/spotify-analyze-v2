#pragma once

#include "platform.hpp"
#include "scan.hpp"

namespace bootstrap
{
    void bootstrap(platform target, const std::string &exec, const std::vector<std::string_view> &bootstrapper_args, const scan_result &result);
}
