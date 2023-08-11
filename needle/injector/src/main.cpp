#include "flags.h"
#include <cstdio>
#include <filesystem>
#include <string>
#include "platform.hpp"
#include "scan.hpp"

std::string executable_name;

void print_help()
{
  std::printf("Usage: %s --target <target> --exec <path or name> [--binary <path>]\n"
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
              "  iOS: Required, path to Spotify in Spotify.app\n",
              executable_name.c_str());
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
    std::fprintf(stderr, "Error: Missing --target\n\n");
    print_help();
    return 1;
  }

  platform target = get_platform(*target_str);
  if (target == platform::UNKNOWN)
  {
    std::fprintf(stderr, "Error: %.*s is not a valid target\n\n", static_cast<int>(target_str->size()), target_str->data());
    print_help();
    return 1;
  }

  const auto exec = args.get<std::string>("exec");
  if (!exec)
  {
    std::fprintf(stderr, "Error: Missing --exec\n\n");
    print_help();
    return 1;
  }
  const std::filesystem::path exec_path = *exec;
  if (!std::filesystem::exists(exec_path))
  {
    std::fprintf(stderr, "Error: Executable %s does not exist\n\n", exec_path.string().c_str());
    print_help();
    return 1;
  }

  const auto binary = args.get<std::string>("binary");
  const std::filesystem::path binary_path = (binary ? *binary : *exec);
  if (target == platform::ANDROID || target == platform::IOS)
  {
    if (!binary)
    {
      std::fprintf(stderr, "Error: Missing --binary\n\n");
      print_help();
      return 1;
    }
    if (!std::filesystem::exists(binary_path))
    {
      std::fprintf(stderr, "Error: Binary %s does not exist\n\n", binary_path.string().c_str());
      return 1;
    }
  }

  std::printf("Target: %s\n", target_str->c_str());
  std::printf("Executable: %s\n", exec_path.string().c_str());
  std::printf("Binary: %s\n", binary_path.string().c_str());

  scan_result offsets = scan_binary(target, binary_path);
  if (!offsets.success)
  {
    std::fprintf(stderr, "Error: Failed to find offsets\n");
    return 1;
  }

  const std::string binary_filename = binary_path.filename().string();
  std::printf("Using offsets:\n");
  std::printf("- shn_addr1:  0x%012lx\n", offsets.shn_addr1);
  std::printf("- shn_addr2:  0x%012lx\n", offsets.shn_addr2);
  std::printf("- server_key: 0x%012lx\n", offsets.server_public_key);
}
