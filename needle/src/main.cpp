#include "hooking/hooking.hpp"
#include "entry/entry.hpp"
#include "logger.hpp"

#include <thread>

// TODO: Could we start our own thread, then use a hook to signal when to shut down? (Maybe when a specific file is written as the app shuts down?)
void entry::entrypoint()
{
  if (!hooking::hook())
  {
    logger::error("[ERROR] Failed to install hooks\n");
    return;
  }

  logger::info("Installed hooks\n");

  while(true)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::this_thread::yield();
  }
  // TODO: If a persistent thread is added, add a socket to allow communication (add/remove hooks, look at memory, breakpoints etc)
}
