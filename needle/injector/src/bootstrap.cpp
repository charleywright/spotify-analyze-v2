#include "bootstrap.hpp"
#include <filesystem>
#include <fmt/core.h>
#include <sstream>

std::filesystem::path locate_bootstrap_script()
{
  const std::string script_name = "bootstrap.js";
  const int max_depth = 5;

  std::filesystem::path script_location = std::filesystem::canonical(".") / script_name;
  for (int i = 0; i < max_depth; i++)
  {
    if (std::filesystem::exists(script_location))
    {
      return std::filesystem::canonical(script_location);
    }
    script_location = script_location.parent_path().parent_path() / script_name;
  }

  return "";
}

void bootstrap::bootstrap(platform target, const std::string &exec, const flags::args &args, const scan_result &result)
{
  const std::filesystem::path bootstrap_script = locate_bootstrap_script();
  if (bootstrap_script.empty())
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to find bootstrap.js script\n");
    return;
  }

  fmt::print("Found bootstrap script at {}\n", bootstrap_script.string());

  /*
   * Yes this is a truly horrible idea but this is a developer-focussed tool
   * that should never be in an environment where exploits would cause damage
   */
  std::stringstream command;
  command << "node " << bootstrap_script \
  << " --platform " << platform_str(target) \
  << " --exec \"" << exec << '"';
  if (args.get<bool>("enable-debug"))
  {
    command << " --enable-debug";
  }
  command << " -- " << fmt::format("serverKey={:#x} shnAddr1={:#x} shnAddr2={:#x}", result.server_public_key, result.shn_addr1, result.shn_addr2);
  for (const auto &bootstrapper_arg: args.skipped())
  {
    command << ' ' << bootstrapper_arg;
  }
  const std::string command_str = command.str();
  fmt::print("Running command `{}`\n", command_str);
  std::fflush(stderr);
  std::fflush(stdout);
  std::system(command_str.c_str());
}
