#include "process.hpp"

void process::generate_args(const flags::args &args)
{
  process::process_args.clear();

  std::optional<logg::string> username = args.get<logg::string>("username");
  if (username.has_value())
  {
    process::process_args += " --username ";
    process::process_args += username.value();
  }

  std::optional<logg::string> password = args.get<logg::string>("password");
  if (password.has_value())
  {
    process::process_args += " --password ";
    process::process_args += password.value();
  }

  std::optional<bool> show_console = args.get<bool>("spotify-console");
  if (show_console.has_value() && show_console.value())
  {
    process::process_args += " --show-console";
  }
}
