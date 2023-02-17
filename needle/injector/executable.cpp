#include "executable.hpp"
#include "log.hpp"

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

  return executable::platform_find();
}
