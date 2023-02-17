#ifdef __linux__

#include "executable.hpp"
#include "log.hpp"

bool executable::platform_find()
{
  std::filesystem::path spotify_link = "/bin/spotify";
  if(!std::filesystem::exists(spotify_link))
  {
    logg::error("/bin/spotify not found\n");
    return false;
  }

  if(!std::filesystem::is_symlink(spotify_link))
  {
    logg::error("/bin/spotify is not a symlink\n");
    return false;
  }

  std::filesystem::path spotify_bin = std::filesystem::read_symlink(spotify_link);

  if(!std::filesystem::exists(spotify_bin))
  {
    logg::error("/bin/spotify points to a file that doesn't exist\n");
    return false;
  }

  executable::path = spotify_bin;

  return true;
}

#endif
