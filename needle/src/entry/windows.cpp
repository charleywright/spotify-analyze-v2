#ifdef _WIN32
#include <windows.h>
#include <processthreadsapi.h>
#include "entry.hpp"

static HINSTANCE g_instance = nullptr;

extern "C" __declspec(dllexport) BOOL WINAPI
DllMain(HINSTANCE
        instance,
        DWORD reason, LPVOID
        reserved)
{
  if (reason == DLL_PROCESS_ATTACH)
  {
    g_instance = instance;
    CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        entry::entrypoint();
        FreeLibraryAndExitThread(g_instance, 0);
    }, nullptr, 0, nullptr);
  }
  return true;
}
#endif
