#pragma once

#include "platform.hpp"
#include "sigscanner/sigscanner.hpp"
#include <filesystem>
#include "flags.h"

struct scan_result
{
    sigscanner::offset shn_addr1 = 0;
    sigscanner::offset shn_addr2 = 0;
    sigscanner::offset server_public_key = 0;
    bool success = false;
};

scan_result scan_binary(platform target, const std::filesystem::path &binary_path, const flags::args &args);
