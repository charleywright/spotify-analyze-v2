#pragma once

#include "platform.hpp"
#include "sigscanner/sigscanner.hpp"
#include <filesystem>

struct scan_result
{
    sigscanner::offset shn_encrypt = 0;
    sigscanner::offset shn_decrypt = 0;
    sigscanner::offset server_public_key = 0;
    bool success = false;
};

scan_result scan_binary(platform target, const std::filesystem::path& binary_path);
