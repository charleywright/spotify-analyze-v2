#include "prefs.hpp"
#include "executable.hpp"
#include "log.hpp"
#include <fstream>
#include <sstream>

#if defined(__linux__)

bool prefs::platform_find_file()
{
  char* env_var = std::getenv("XDG_CONFIG_HOME");
  std::filesystem::path xdg_home;
  if (env_var == nullptr)
  {
    env_var = std::getenv("HOME");
    if(env_var == nullptr)
    {
      logg::error("HOME environment variable not set\n");
      return false;
    }
    xdg_home = env_var;
    xdg_home /= ".config";
  } else
  {
    xdg_home = env_var;
  }

  if (!std::filesystem::exists(xdg_home))
  {
    return false;
  }

  std::filesystem::path spotify_path = xdg_home / "spotify";

  if (!std::filesystem::exists(spotify_path))
  {
    logg::error("%s doesn't exist\n", LOGG_PATH(spotify_path));
    return false;
  }

  spotify_path /= "prefs";

  if (!std::filesystem::exists(spotify_path))
  {
    logg::error("Prefs file not found in %s\n", LOGG_PATH(spotify_path));
    return false;
  }

  prefs::file_path = spotify_path;
  return true;
}

#else

bool prefs::platform_find_file()
{
  std::filesystem::path spotify_dir = executable::path.parent_path();
  std::filesystem::path p = spotify_dir / "prefs";
  if (!std::filesystem::exists(p))
  {
    logg::error("Prefs file not in same directory as spotify executable\n");
    return false;
  }

  prefs::file_path = p;
  return true;
}

#endif

bool prefs::find_file(const flags::args &args)
{
  const std::optional<logg::string> prefs_path_from_args = args.get<logg::string>("prefs");
  if (prefs_path_from_args.has_value())
  {
    std::filesystem::path p = prefs_path_from_args.value();
    if (std::filesystem::exists(p))
    {
      prefs::file_path = p;
      return true;
    }
  }

  return prefs::platform_find_file();
}

void prefs::read()
{
  std::ifstream file(prefs::file_path, std::ios::in);
  if (!file.is_open())
  {
    return;
  }
  prefs::prefs.clear();
  logg::string line;
  while (std::getline(file, line))
  {
    logg::string::size_type key_end = line.find('=');
    if (key_end == logg::string::npos)
    {
      continue;
    }
    const logg::string key = line.substr(0, key_end);
    logg::string value = line.substr(key_end + 1);
    {
      logg::string::iterator i = value.begin();
      bool escaped = false;
      while (i != value.end())
      {
        if (!escaped && *i == '"')
        {
          value.erase(i);
          escaped = false;
          continue;
        }
        if (escaped)
        {
          escaped = false;
        }
        if (*i == '\\')
        {
          escaped = true;
        }
        i++;
      }
    }
    prefs::prefs.emplace(key, value);
  }
}

void prefs::write()
{
  logg::ofstream file(prefs::file_path, std::ios::out | std::ios::trunc);
  if (!file.is_open())
  {
    return;
  }

  logg::string str;
  for (const auto &[key, value]: prefs::prefs)
  {
    str += key;
    str += '=';
    if (prefs::get<std::int64_t>(key) || value == "true" ||
        value == "false") // This will fail for numbers above 0x7FFFFFFFFFFFFFFF, but something else is probably wrong at that point
    {
      str += value;
    } else
    {
      str += '"';
      str += value;
      str += '"';
    }
    str += '\n';
  }
  file << str;
  file.close();
}

void prefs::set_str(const logg::string &key, const logg::string &value)
{
  if (prefs::prefs.count(key) > 0)
  {
    prefs::prefs.at(key) = value;
  } else
  {
    prefs::prefs.emplace(key, value);
  }
}

void prefs::set_int(const logg::string &key, std::int64_t value)
{
  return prefs::set_str(key, std::to_string(value));
}

void prefs::set_bool(const logg::string &key, bool value)
{
  return prefs::set_str(key, value ? "true" : "false");
}

void prefs::process_args(const flags::args &args)
{
  std::optional<logg::string> proxy_type = args.get<logg::string>("proxy-type");
  if (proxy_type.has_value())
  {
    if (proxy_type.value() == "none")
    {
      prefs::set_int("network.proxy.mode", 0);
    } else if (proxy_type.value() == "detect")
    {
      prefs::set_int("network.proxy.mode", 1);
    } else if (proxy_type.value() == "http")
    {
      prefs::set_int("network.proxy.mode", 2);
    } else if (proxy_type.value() == "socks4")
    {
      prefs::set_int("network.proxy.mode", 3);
    } else if (proxy_type.value() == "socks5")
    {
      prefs::set_int("network.proxy.mode", 4);
    } else
    {
      logg::error("Invalid proxy-type %s, use none/detect/http/socks4/socks5\n", proxy_type.value().c_str());
    }
  }

  std::optional<logg::string> proxy_host = args.get<logg::string>("proxy");
  if (proxy_host.has_value())
  {
    prefs::set_str("network.proxy.addr", proxy_host.value());
  }

  std::optional<logg::string> proxy_auth = args.get<logg::string>("proxy-auth");
  if (proxy_auth.has_value())
  {
    logg::string::size_type colon_idx = proxy_auth.value().find(':');
    if (colon_idx == logg::string::npos)
    {
      prefs::set_str("network.proxy.user", proxy_auth.value());
    } else
    {
      prefs::set_str("network.proxy.user", proxy_auth.value().substr(0, colon_idx));
      prefs::set_str("network.proxy.pass",
                     proxy_auth.value().substr(colon_idx + 1)); // Encrypted on launch. Looks like AES 128, maybe hook calls and look for a key?
    }
  }

  std::optional<bool> preserve_prefs = args.get<bool>("preserve-prefs");
  if (preserve_prefs.has_value() && preserve_prefs.value())
  {
    prefs::preserve_new_prefs = false;
  }
}

template<typename T>
std::optional<T> prefs::get(const logg::string &key)
{
  if (prefs::prefs.count(key) == 0)
  {
    return std::nullopt;
  }

  const std::string &v = prefs::prefs.at(key);
  T value;
  std::istringstream ss(v);
  ss >> value;
  char c;
  if (ss.fail() || ss.get(c))
  {
    return std::nullopt;
  }
  return value;
}

std::optional<logg::string> prefs::get(const logg::string &key)
{
  return prefs::get<std::string>(key);
}
