#include "kill.hpp"
#include "fmt/core.h"

#if defined(NEEDLE_TARGET_LINUX)

#include <filesystem>
#include <fstream>
#include <csignal>
#include <vector>
#include <thread>
#include <chrono>

using namespace std::chrono_literals;

std::vector<std::size_t> find_proc_pids(const std::string &process_name)
{
  std::vector<std::size_t> pids;
  for (const auto &entry: std::filesystem::directory_iterator("/proc"))
  {
    if (entry.is_directory())
    {
      if (entry.path().filename().string().find_first_not_of("0123456789") != std::string::npos)
      {
        continue;
      }

      std::string cmdline;
      std::ifstream stream(entry.path() / "cmdline");
      std::getline(stream, cmdline);
      if (cmdline.find(process_name) == 0)
      {
        pids.emplace_back(std::stoul(entry.path().filename()));
      }
    }
  }
  return pids;
}

void process::kill_all(const std::string &process_name)
{
  std::vector<std::size_t> pids = find_proc_pids(process_name);
  for (const auto &pid: pids)
  {
    kill(pid, SIGTERM);
  }

  std::this_thread::sleep_for(500ms);

  for (const auto &pid: pids)
  {
    kill(pid, SIGKILL);
  }
}

#elif defined(NEEDLE_TARGET_WINDOWS)

#else
#error "kill::kill_process not implemented for platform"
#endif
