#pragma once

#include <string_view>

enum class platform
{
    UNKNOWN = 0,
    LINUX,
    WINDOWS,
    ANDROID,
    IOS
};

inline platform get_platform(const std::string_view target)
{
  if (target == "linux")
    return platform::LINUX;
  if (target == "windows")
    return platform::WINDOWS;
  if (target == "android")
    return platform::ANDROID;
  if (target == "ios")
    return platform::IOS;
  return platform::UNKNOWN;
}
