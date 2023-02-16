#include "flags.h"
#include "executable.hpp"
#include "prefs.hpp"
#include "log.hpp"

int main(int argc, char *argv[])
{
  const flags::args args(argc, argv);
  std::filesystem::path binary_dir = std::filesystem::absolute(argv[0]).parent_path();

  std::filesystem::path dll_path = args.positional().empty() ? "" : args.positional().at(0);
  if (dll_path.empty() || !std::filesystem::exists(dll_path))
  {
    for (const auto &file: std::filesystem::directory_iterator(binary_dir))
    {
      if (!file.is_regular_file() || file.path().filename() != "needle.dll")
      {
        continue;
      }
      dll_path = file.path();
      break;
    }
  }
  if (dll_path.empty() || !std::filesystem::exists(dll_path))
  {
    logg::error("No DLL specified/found. Specify manually as first positional argument\n");
    return 1;
  }
  dll_path = std::filesystem::absolute(dll_path);
  logg::log("Found DLL at %s\n", LOGG_PATH(dll_path));

  if (!executable::find(args))
  {
    logg::error("Failed to find Spotify executable. Specify manually using --exec <path/to/spotify>\n");
    return 1;
  }
  logg::log("Found spotify executable at %s\n", LOGG_PATH(executable::path));

  if (!prefs::find_file(args))
  {
    logg::error("Failed to find prefs file. Specify manually using --prefs <path/to/prefs>\n");
    return 1;
  }
  logg::log("Found spotify prefs file at %s\n", LOGG_PATH(prefs::file_path));
  prefs::read();
  prefs::original_prefs = prefs::prefs;

//  std::wstring args = L"";
////  args += L" --show-console";
//  STARTUPINFOW info = {};
//  ZeroMemory(&info, sizeof(info));
//  info.cb = sizeof(info);
//  PROCESS_INFORMATION pi = {};
//  CreateProcessW(spotify_executable.generic_wstring().c_str(), const_cast<wchar_t *>(args.c_str()), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &info, &pi);
//  printf("Created process\n");
//  std::this_thread::sleep_for(100ms);
//
//  LPTHREAD_START_ROUTINE lla_addr = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));
//  LPVOID filename_ptr = VirtualAllocEx(pi.hProcess, nullptr, dll_path.generic_string().size(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//  WriteProcessMemory(pi.hProcess, filename_ptr, dll_path.generic_string().c_str(), dll_path.generic_string().size(), 0);
//  HANDLE dll_thread = CreateRemoteThread(pi.hProcess, nullptr, 0, lla_addr, filename_ptr, 0, nullptr);
//  WaitForSingleObject(dll_thread, INFINITE);
//  CloseHandle(dll_thread);
//  VirtualFreeEx(pi.hProcess, filename_ptr, 0, MEM_RELEASE);
//  printf("Injected DLL into process %lu\n", pi.dwProcessId);
//  fflush(stdout);
//
//  WaitForSingleObject(pi.hProcess, INFINITE);
//
//  std::this_thread::sleep_for(1s);
//
//  prefs_file.open(prefs_file_path, std::ios::out | std::ios::trunc);
//  if (!prefs_file.is_open())
//  {
//    fprintf(stderr, "Failed to write original prefs file, dumping...\n\n%s\n", prev_prefs.str().c_str());
//    return 1;
//  }
//  prefs_file << prev_prefs.str();
//  prefs_file.close();
//
//  return 0;
}