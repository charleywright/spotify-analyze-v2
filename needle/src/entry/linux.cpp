#ifdef __linux__
#include "entry.hpp"
#include <sys/socket.h>
#include <dlfcn.h>
#include <pthread.h>

// Provide our own connect() that will be called from Spotify's code. Upon first run it will trigger our entrypoint
int __attribute__((used)) connect(int sock_fd, const struct sockaddr *addr, socklen_t addrlen)
{
  static int (*real_connect)(int, const struct sockaddr *, socklen_t) = nullptr;
  static pthread_once_t patch_once = PTHREAD_ONCE_INIT;
  if (real_connect == nullptr)
  {
    real_connect = reinterpret_cast<decltype(real_connect)>(dlsym(RTLD_NEXT, "connect"));
  }
  pthread_once(&patch_once, &entry::entrypoint);
  return real_connect(sock_fd, addr, addrlen);
}
#endif