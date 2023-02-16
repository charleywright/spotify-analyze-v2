#include "prefs.hpp"
#include "executable.hpp"
#include "log.hpp"
#include <fstream>
#include <sstream>

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

  std::filesystem::path spotify_dir = executable::path.parent_path();
  std::filesystem::path p = spotify_dir / "prefs"; // TODO: Can a unicode filesystem::path have a u8 literal appended?
  if (!std::filesystem::exists(p))
  {
    logg::error("Prefs file not in same directory as spotify executable\n");
    return false;
  }

  prefs::file_path = p;
  return true;
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

  logg::stringstream ss;
  for (const auto &[key, value]: prefs::prefs)
  {
    ss << key << '=';
    if (prefs::get<std::int64_t>(key) || value == "true" ||
        value == "false") // This will fail for numbers above 0x7FFFFFFFFFFFFFFF, but something else is probably wrong
    {
      ss << value << '\n';
    } else
    {
      ss << '"' << value << '"' << '\n';
    }
  }
  file << ss.str();
  file.close();
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
