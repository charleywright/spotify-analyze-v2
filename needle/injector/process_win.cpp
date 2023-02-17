#ifdef _WIN32

#include "process.hpp"
#include "executable.hpp"
#include "log.hpp"
#include <thread>

#include <Windows.h>

using namespace std::chrono_literals;

void process::spawn_and_wait()
{
  STARTUPINFO info;
  ZeroMemory(&info, sizeof(info));
  info.cb = sizeof(info);

  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(pi));

  CreateProcess(LOGG_PATH(executable::path), process::process_args.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &info, &pi);
  logg::log("Created process\n");
  std::this_thread::sleep_for(100ms);

  LPTHREAD_START_ROUTINE lla_addr = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));
  logg::string dll_path_str = LOGG_PATH(process::lib_to_inject);
  LPVOID filename_ptr = VirtualAllocEx(pi.hProcess, nullptr, dll_path_str.size(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  WriteProcessMemory(pi.hProcess, filename_ptr, dll_path_str.c_str(), dll_path_str.size(), nullptr);
  HANDLE dll_thread = CreateRemoteThread(pi.hProcess, nullptr, 0, lla_addr, filename_ptr, 0, nullptr);
  WaitForSingleObject(dll_thread, INFINITE);
  CloseHandle(dll_thread);
  VirtualFreeEx(pi.hProcess, filename_ptr, 0, MEM_RELEASE);
  logg::log("Injected DLL into process %lu\n", pi.dwProcessId);
  fflush(stdout);

  WaitForSingleObject(pi.hProcess, INFINITE);
}

#endif
