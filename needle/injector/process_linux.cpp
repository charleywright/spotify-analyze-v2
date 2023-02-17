#ifdef __linux__

#include "process.hpp"
#include "log.hpp"
#include "executable.hpp"
#include <cstdlib>

void process::spawn_and_wait()
{
  logg::string cmd = "LD_RELOAD=";
  cmd += LOGG_PATH(process::lib_to_inject);
  cmd += ' ';
  cmd += LOGG_PATH(executable::path);
  cmd += process::process_args;

  logg::log("Executing %s\n", cmd.c_str());
  std::system(cmd.c_str());
}

#endif
