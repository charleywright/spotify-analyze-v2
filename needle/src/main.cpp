// The patching code is heavily based upon https://github.com/librespot-org/spotify-analyze/blob/master/dump/dump.c with some changes

#include <sys/socket.h>
#include <dlfcn.h>
#include <pthread.h>
#include <cstdio>
#include <cstring>
#include <inttypes.h>

pthread_once_t patch_once = PTHREAD_ONCE_INIT;

void entrypoint();

// [LINUX] Trigger an entrypoint by providing a new connect() function that calls our entry once
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  static int (*real_connect)(int, const struct sockaddr *, socklen_t) = nullptr;
  if (real_connect == nullptr)
  {
    real_connect = reinterpret_cast<decltype(real_connect)>(dlsym(RTLD_NEXT, "connect"));
  }
  pthread_once(&patch_once, entrypoint);
  return real_connect(sockfd, addr, addrlen);
}

void *get_executable_memory(uint64_t *len)
{
  *len = 0;
  FILE *mapfile = fopen("/proc/self/maps", "r");
  if (mapfile == nullptr)
  {
    return nullptr;
  }
  char line[256], flags[4];
  uint64_t start = 0, end = 0;
  unsigned found = 0;
  while (fgets(line, sizeof(line), mapfile))
  {
    sscanf(line, "%llx-%llx %4s", &start, &end, flags);
    if (strcmp(flags, "r-xp") == 0)
    {
      found = 1;
      break;
    }
  }
  fclose(mapfile);
  *len = end - start;
  return (void *)(uintptr_t)start;
}

// Avoid GNU Source
void *memrmem(const void *haystack, size_t haystack_size,
              const void *needle, size_t needle_size)
{
  if (haystack_size < needle_size)
    return nullptr;
  if (needle_size == 0)
    return (void *)haystack + haystack_size;

  const void *p;
  for (p = haystack + haystack_size - needle_size; haystack_size >= needle_size; --p, --haystack_size)
  {
    if (memcmp(p, needle, needle_size) == 0)
    {
      return (void *)p;
    }
  }
  return nullptr;
}

void find_shn(void **shn_encrypt_addr, void **shn_decrypt_addr)
{
  *shn_encrypt_addr = nullptr;
  *shn_decrypt_addr = nullptr;

  uint64_t exec_mem_len = 0;
  void *exec_mem = get_executable_memory(&exec_mem_len);
  if (exec_mem == nullptr || exec_mem_len == 0)
  {
    fprintf(stderr, "[ERROR] Failed get_executable_memory, exec_mem=%p exec_mem_len=%llu\n", exec_mem, exec_mem_len);
    return;
  }
  printf("[FOUND] text=%p size=%zx\n", exec_mem, exec_mem_len);

  const static unsigned char SHN_CONSTANT[] = {0x3a, 0xc5, 0x96, 0x69};
  void *constant_location = memrmem(exec_mem, exec_mem_len, SHN_CONSTANT, sizeof(SHN_CONSTANT));
  if (constant_location == nullptr)
  {
    fprintf(stderr, "[ERROR] Failed to find shannon constant 0x6996c53a\n");
    return;
  }
  printf("[FOUND] shn_const=%p\n", constant_location);
  exec_mem_len = reinterpret_cast<unsigned char *>(constant_location) - reinterpret_cast<unsigned char *>(exec_mem);

  const static unsigned char SHN_FUNCTION_PATTERN[] = {0x55, 0x48, 0x89, 0xe5}; // PUSH RBP; MOV RBP,RSP

  void *shn_finish_addr = memrmem(exec_mem, exec_mem_len, SHN_FUNCTION_PATTERN, sizeof(SHN_FUNCTION_PATTERN));
  if (shn_finish_addr == nullptr)
  {
    fprintf(stderr, "[ERROR] Failed to find shn_finish\n");
    return;
  }
  printf("[FOUND] shn_finish=%p\n", shn_finish_addr);
  exec_mem_len = reinterpret_cast<unsigned char *>(shn_finish_addr) - reinterpret_cast<unsigned char *>(exec_mem);

  *shn_decrypt_addr = memrmem(exec_mem, exec_mem_len, SHN_FUNCTION_PATTERN, sizeof(SHN_FUNCTION_PATTERN));
  if (*shn_decrypt_addr == nullptr)
  {
    fprintf(stderr, "[ERROR] Failed to find shn_decrypt\n");
    return;
  }
  printf("[FOUND] shn_decrypt=%p\n", *shn_decrypt_addr);
  exec_mem_len = reinterpret_cast<unsigned char *>(*shn_decrypt_addr) - reinterpret_cast<unsigned char *>(exec_mem);

  *shn_encrypt_addr = memrmem(exec_mem, exec_mem_len, SHN_FUNCTION_PATTERN, sizeof(SHN_FUNCTION_PATTERN));
  if (*shn_encrypt_addr == nullptr)
  {
    fprintf(stderr, "[ERROR] Failed to find shn_decrypt\n");
    *shn_decrypt_addr = nullptr;
    return;
  }
  printf("[FOUND] shn_encrypt=%p\n", *shn_encrypt_addr);

  return;
}

// TODO: Could we start our own thread, then use a hook to signal when to shutdown (Maybe when a specific file is written as the app shuts down?)
void entrypoint()
{
  void *shn_encrypt_addr = nullptr, *shn_decrypt_addr = nullptr;
  find_shn(&shn_encrypt_addr, &shn_decrypt_addr);
  if (shn_encrypt_addr == nullptr || shn_decrypt_addr == nullptr)
  {
    return;
  }

  printf("Found shn_encrypt=%p shn_decrypt=%p\n", shn_encrypt_addr, shn_decrypt_addr);
}