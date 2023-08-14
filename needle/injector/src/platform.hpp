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

inline const char *platform_str(const platform target)
{
  switch (target)
  {
    case platform::UNKNOWN:
      return "unknown";
    case platform::LINUX:
      return "linux";
    case platform::WINDOWS:
      return "windows";
    case platform::ANDROID:
      return "android";
    case platform::IOS:
      return "ios";
    default:
      return "unknown";
  }
}
