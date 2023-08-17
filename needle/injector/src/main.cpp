#include "flags.h"
#include <filesystem>
#include "platform.hpp"
#include "scan.hpp"
#include "bootstrap.hpp"
#include "fmt/core.h"

std::string executable_name;

void print_help()
{
  fmt::print("Usage: {} --target <target> --exec <path or name> [--binary <path>] [-- <bootstrap options>]\n"
             "\n"
             "--target: linux/windows/android/ios\n"
             "\n"
             "--exec: path or name of the executable to inject frida into\n"
             "  Linux: Probably '/opt/spotify/spotify'\n"
             "  Windows: Probably '%%APPDATA%%/Spotify/Spotify.exe'\n"
             "  Android: Probably 'com.spotify.music'\n"
             "  iOS: Probably 'Spotify'\n"
             "\n"
             "--binary: path to the binary to scan for offsets\n"
             "  Linux: Optional, should be the same as --exec\n"
             "  Windows: Optional, should be the same as --exec\n"
             "  Android: Required, path to liborbit-jni-spotify.so. Must be correct architecture and version\n"
             "  iOS: Required, path to Spotify in Spotify.app\n"
             "\n"
             "Arguments can be terminated with -- then arguments for the bootstrap script may follow.\n"
             "These arguments influence how and what frida will inject into. They follow a key-value\n"
             "format and should use valid JSON values. These are the allowed options, all optional:\n"
             "  shannonLogCallStacks=true       - Log a call stack for SPIRC packet encryption\n"
             "  shannonLogInvalidCalls=true     - Log calls deemed to not be SPIRC related with return address\n"
             "  shannonDisableSafeCallers=true  - Disable safe callers detection. Parsing will probably break\n", executable_name);
}

int main(int argc, char **argv)
{
  executable_name = std::filesystem::path(argv[0]).filename().string();
  const flags::args args(argc, argv);

  if (args.get<bool>("help") || args.get<bool>("h"))
  {
    print_help();
    return 0;
  }

  const auto target_str = args.get<std::string>("target");
  if (!target_str)
  {
    fmt::print(stderr, "Error: Missing --target\n");
    print_help();
    return 1;
  }

  platform target = get_platform(*target_str);
  if (target == platform::UNKNOWN)
  {
    fmt::print(stderr, "Error: {} is not a valid target\n", *target_str);
    print_help();
    return 1;
  }

  const auto exec = args.get<std::string>("exec");
  if (!exec)
  {
    fmt::print(stderr, "Error: Missing --exec\n");
    print_help();
    return 1;
  }
  std::string executable = *exec;
  if (target != platform::ANDROID && target != platform::IOS)
  {
    if (!std::filesystem::exists(*exec))
    {
      fmt::print(stderr, "Error: Executable {} does not exist\n", *exec);
      print_help();
      return 1;
    } else
    {
      executable = std::filesystem::canonical(executable).string();
    }
  }

  const auto binary = args.get<std::string>("binary");
  const std::filesystem::path binary_path = (binary ? *binary : *exec);
  if (target == platform::ANDROID || target == platform::IOS)
  {
    if (!binary)
    {
      fmt::print(stderr, "Error: Missing --binary\n");
      print_help();
      return 1;
    }
    if (!std::filesystem::exists(binary_path))
    {
      fmt::print(stderr, "Error: Binary {} does not exist\n", binary_path.string());
      return 1;
    }
  }

  fmt::print("Target: {}\n", *target_str);
  fmt::print("Executable: {}\n", *exec);
  fmt::print("Binary: {}\n", binary_path.string());

  scan_result offsets = scan_binary(target, binary_path);
  if (!offsets.success)
  {
    fmt::print(stderr, "Error: Failed to find offsets\n");
    return 1;
  }

  fmt::print("Using offsets:\n");
  fmt::print("- shn_addr1:  {:#012x}\n", offsets.shn_addr1);
  fmt::print("- shn_addr2:  {:#012x}\n", offsets.shn_addr2);
  fmt::print("- server_key: {:#012x}\n", offsets.server_public_key);

  bootstrap::bootstrap(target, executable, args.skipped(), offsets);
}
