#include "flags.h"
#include "executable.hpp"
#include "prefs.hpp"
#include "log.hpp"
#include "process.hpp"

void print_help(const char *argv0)
{
  std::filesystem::path executable(argv0);
  logg::log("Usage: %s [Path to .dll/.so/.dylib]\n\n"
            ""
            "Config arguments:\n"
            "  --username <username/email>                       - Specify a username/email for autologin\n"
            "  --password <password>                             - Specify a password for autologin\n"
            "  --spotify-console                                 - Enable Spotify's debug console\n"
            "  --preserve-prefs                                  - Don't reset prefs. Useful to stay logged in\n"
            "  --proxy-type none/detect/http/socks4/socks5       - Type of proxy\n"
            "  --proxy-host <host>:<ip>                          - Proxy host and IP\n"
            "  --proxy-auth <username>[:<password>]              - Auth for proxy. Empty passwords can be omitted\n\n"
            "Program arguments:\n"
            "  --exec                                            - Manually specify location of Spotify executable\n"
            "  [Path to .dll/.so/.dylib]                         - The path to the library to inject. Can be omitted to search the current directory\n",
            LOGG_PATH(executable.filename()));
}

int main(int argc, char *argv[])
{
  const flags::args args(argc, argv);
  std::filesystem::path binary_dir = std::filesystem::absolute(argv[0]).parent_path();

  if (args.get<bool>("h") || args.get<bool>("help"))
  {
    print_help(argv[0]);
    return 0;
  }

  std::filesystem::path lib_path = args.positional().empty() ? "" : args.positional().at(0);
  if (lib_path.empty() || !std::filesystem::exists(lib_path))
  {
    for (const auto &file: std::filesystem::directory_iterator(binary_dir))
    {
      if (!file.is_regular_file() || file.path().stem() != "needle")
      {
        continue;
      }
      if (file.path().extension() != ".dll" && file.path().extension() != ".so" && file.path().extension() != ".dylib")
      {
        continue;
      }
      lib_path = file.path();
      break;
    }
  }
  if (lib_path.empty() || !std::filesystem::exists(lib_path))
  {
    logg::error("No library specified/found. Specify manually as first positional argument\n");
    return 1;
  }
  process::lib_to_inject = std::filesystem::absolute(lib_path);
  logg::log("Found lib at %s\n", LOGG_PATH(process::lib_to_inject));

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
  prefs::process_args(args);
  prefs::write();

  process::generate_args(args);
  process::spawn_and_wait();

  if (!prefs::preserve_new_prefs)
  {
    prefs::prefs = prefs::original_prefs;
    prefs::write();
  }

  return 0;
}
