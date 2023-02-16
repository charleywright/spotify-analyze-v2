#ifdef _WIN32

#include "executable.hpp"
#include "log.hpp"
#include <windows.h>
#include <shobjidl.h>
#include <objbase.h>
#include <objidl.h>
#include <shlguid.h>
#include <processthreadsapi.h>

std::filesystem::path find_spotify_lnk()
{
  logg::string appdata = std::getenv("APPDATA");
  if (appdata.empty())
  {
    return "";
  }
  std::filesystem::path path = appdata;
  path /= R"(Microsoft\Windows\Start Menu\Programs\Spotify.lnk)";
  if (!std::filesystem::exists(path))
  {
    return "";
  }
  return path;
}

std::filesystem::path resolve_lnk(const std::filesystem::path &lnk_path)
{
  std::filesystem::path link_path;
  CoInitialize(nullptr);
  IShellLink *psl = nullptr;
  HRESULT res;
  if (res = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLink, reinterpret_cast<LPVOID *>(&psl)), res != S_OK)
  {
    logg::error("Failed to create IShellLink. Got code %ld\n", res);
    CoUninitialize();
    return link_path;
  }

  IPersistFile *pf = nullptr;
  if (res = psl->QueryInterface(IID_PPV_ARGS(&pf)), res != S_OK)
  {
    logg::error("Failed to get file for shortcut. Got code %ld\n", res);
    psl->Release();
    CoUninitialize();
    return link_path;
  }

  if (res = pf->Load(lnk_path.generic_wstring().c_str(), 0), res != S_OK)
  {
    logg::error("Failed to load LNK file. Got code %lu\n", res);
    pf->Release();
    psl->Release();
    CoUninitialize();
    return link_path;
  }
  if (res = psl->Resolve(nullptr, 0), res != S_OK)
  {
    logg::error("Failed to resolve LNK file. Got Code %ld\n", res);
    pf->Release();
    psl->Release();
    CoUninitialize();
    return link_path;
  }

  TCHAR executable_path[MAX_PATH] = {0};
  if (res = psl->GetPath(executable_path, MAX_PATH, nullptr, SLGP_SHORTPATH), res != S_OK)
  {
    logg::error("Failed to get path for LNK file. Got code %ld\n", res);
    pf->Release();
    psl->Release();
    CoUninitialize();
    return link_path;
  }

  pf->Release();
  psl->Release();
  CoUninitialize();
  link_path = executable_path;
  return link_path;
}

bool executable::find(const flags::args &args)
{
  const std::optional<logg::string> path_from_args = args.get<logg::string>("exec");
  if (path_from_args.has_value())
  {
    std::filesystem::path p = path_from_args.value();
    if (std::filesystem::exists(p))
    {
      executable::path = p;
      return true;
    }
  }

  std::filesystem::path lnk_file = find_spotify_lnk();
  if (lnk_file.empty())
  {
    logg::error("Failed to find Spotify.lnk\n");
    return false;
  }

  std::filesystem::path exec_path = resolve_lnk(lnk_file);
  if (exec_path.empty())
  {
    logg::error("Failed to resolve LNK file at %s\n", LOGG_PATH(lnk_file));
    return false;
  }

  executable::path = exec_path;
  return true;
}

#endif