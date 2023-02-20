#include "process.hpp"
#include <vector>
#include <random>

void process::generate_args(const flags::args &args)
{
  process::process_args.clear();

  std::optional<logg::string> username = args.get<logg::string>("username");
  if (username.has_value())
  {
    logg::string u = "--username=";
    u += username.value();
    process::process_args.emplace_back(u);
  }

  std::optional<logg::string> password = args.get<logg::string>("password");
  if (password.has_value())
  {
    logg::string p = "--password=";
    p += password.value();
    process::process_args.emplace_back(p);
  }

  std::optional<bool> show_console = args.get<bool>("spotify-console");
  if (show_console.has_value() && show_console.value())
  {
    process::process_args.emplace_back("--show-console");
  }

  std::optional<logg::string> profile = args.get<logg::string>("profile");
  if (profile.has_value())
  {
    logg::string mu = "--mu=";
    mu += profile.value();
    process::process_args.emplace_back(mu);
  }
}
