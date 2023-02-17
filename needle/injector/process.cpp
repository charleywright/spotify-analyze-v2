#include "process.hpp"
#include <vector>
#include <random>

logg::string random_segment()
{
  const static std::vector<logg::string::value_type> chars = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
                                                              'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
                                                              's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
  std::random_device rd;
  std::mt19937 engine(rd());
  std::uniform_int_distribution dist(static_cast<decltype(chars.size())>(0), chars.size() - 1);

  logg::string str = "needle-";
  for (std::uint8_t i = 0; i < 16; i++)
  {
    str += chars[dist(engine)];
  }

  return str;
}

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

  std::optional<bool> enable_multiple = args.get<bool>("multiple");
  if (enable_multiple.has_value() && enable_multiple.value())
  {
    process::process_args += " --mu=";
    process::process_args += random_segment();
  }
}
