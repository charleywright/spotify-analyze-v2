#ifdef __linux__

#include "process.hpp"
#include "executable.hpp"

// TODO: This should be doable using execve, however given multiple hours of research and attempts I couldn't get Spotify to not segfault
void process::spawn_and_wait()
{
  logg::string exec_command;
  exec_command += "DYLD_INSERT_LIBRARIES=";
  exec_command += LOGG_PATH(process::lib_to_inject);
  exec_command += " LD_PRELOAD=";
  exec_command += LOGG_PATH(process::lib_to_inject);
  exec_command += ' ';
  exec_command += LOGG_PATH(executable::path);
  for (const auto &arg: process::process_args)
  {
    exec_command += ' ';
    exec_command += arg;
  }

  logg::log("Invoking %s\n", exec_command.c_str());

  std::system(exec_command.c_str());
}

#endif
