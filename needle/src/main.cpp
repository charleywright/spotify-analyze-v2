#include <cstdio>
#include "hooking/hooking.hpp"
#include "entry/entry.hpp"

// TODO: Could we start our own thread, then use a hook to signal when to shut down? (Maybe when a specific file is written as the app shuts down?)
void entry::entrypoint()
{
  if (!hooking::hook())
  {
    fprintf(stderr, "[ERROR] Failed to install hooks\n");
    return;
  }

  printf("Installed hooks\n");
  // TODO: If a persistent thread is added, add a socket to allow communication (add/remove hooks, look at memory, breakpoints etc)
}
