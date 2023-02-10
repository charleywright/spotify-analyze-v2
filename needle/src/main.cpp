// The patching code is heavily based upon https://github.com/librespot-org/spotify-analyze/blob/master/dump/dump.c with some changes

#include <sys/socket.h>
#include <dlfcn.h>
#include <pthread.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include "subhook.h"

pthread_once_t patch_once = PTHREAD_ONCE_INIT;

void entrypoint();

// [LINUX] Trigger an entrypoint by providing a new connect() function that calls our entry once
int connect(int sock_fd, const struct sockaddr *addr, socklen_t addrlen)
{
  static int (*real_connect)(int, const struct sockaddr *, socklen_t) = nullptr;
  if (real_connect == nullptr)
  {
    real_connect = reinterpret_cast<decltype(real_connect)>(dlsym(RTLD_NEXT, "connect"));
  }
  pthread_once(&patch_once, entrypoint);
  return real_connect(sock_fd, addr, addrlen);
}

std::uint8_t *get_executable_memory(std::uint64_t *len)
{
  *len = 0;

  std::fstream mapfile("/proc/self/maps", std::ios::in);
  if (!mapfile.good())
  {
    return nullptr;
  }

  while (!mapfile.eof())
  {
    std::string line;
    std::getline(mapfile, line);
    std::uint64_t start = 0, end = 0;
    char permissions[5] = {0};
    std::sscanf(line.data(), "%lx-%lx %4s", &start, &end, permissions);
    if (std::strncmp(permissions, "r-xp", 4) == 0)
    {
      *len = end - start;
      return reinterpret_cast<std::uint8_t *>(static_cast<std::uintptr_t>(start));
    }
  }

  std::cout << "End of file" << std::endl;
  return nullptr;
}

// Find block of memory inside a larger block, starting from the end working backwards. Taken from GNU Source and rewritten
template<typename ptr>
ptr memrmem(ptr const haystack, std::size_t haystack_len, ptr const needle, const std::size_t needle_len)
{
  if (haystack_len < needle_len)
  {
    return nullptr;
  }
  if (needle_len == 0)
  {
    return haystack + haystack_len;
  }

  auto p = reinterpret_cast<std::uint8_t const *>(haystack) + haystack_len - needle_len;
  for (; haystack_len >= needle_len; --p, --haystack_len)
  {
    if (std::memcmp(p, needle, needle_len) == 0)
    {
      return reinterpret_cast<ptr>(p);
    }
  }

  return nullptr;
}

void find_shn(void **shn_encrypt_addr, void **shn_decrypt_addr)
{
  *shn_encrypt_addr = nullptr;
  *shn_decrypt_addr = nullptr;

  std::uint64_t exec_mem_len = 0;
  const std::uint8_t *exec_mem = get_executable_memory(&exec_mem_len);
  if (exec_mem == nullptr || exec_mem_len == 0)
  {
    fprintf(stderr, "[ERROR] Failed get_executable_memory, exec_mem=%p exec_mem_len=%lu\n", exec_mem, exec_mem_len);
    return;
  }
  printf("[FOUND] text=%p size=%zx\n", exec_mem, exec_mem_len);

  const static std::uint8_t SHN_CONSTANT[] = {0x3a, 0xc5, 0x96, 0x69};
  const std::uint8_t *constant_location = memrmem(exec_mem, exec_mem_len, SHN_CONSTANT, sizeof(SHN_CONSTANT));
  if (constant_location == nullptr)
  {
    fprintf(stderr, "[ERROR] Failed to find shannon constant 0x6996c53a\n");
    return;
  }
  printf("[FOUND] shn_const=%p\n", constant_location);
  exec_mem_len = constant_location - exec_mem;

  const static std::uint8_t SHN_FUNCTION_PATTERN[] = {0x55, 0x48, 0x89, 0xe5}; // PUSH RBP; MOV RBP,RSP

  const void *shn_finish_addr = memrmem(exec_mem, exec_mem_len, SHN_FUNCTION_PATTERN, sizeof(SHN_FUNCTION_PATTERN));
  if (shn_finish_addr == nullptr)
  {
    fprintf(stderr, "[ERROR] Failed to find shn_finish\n");
    return;
  }
  printf("[FOUND] shn_finish=%p\n", shn_finish_addr);
  exec_mem_len = reinterpret_cast<const std::uint8_t *>(shn_finish_addr) - exec_mem;

  *shn_decrypt_addr = const_cast<void *>(reinterpret_cast<const void *>(memrmem(exec_mem, exec_mem_len, SHN_FUNCTION_PATTERN, sizeof(SHN_FUNCTION_PATTERN))));
  if (*shn_decrypt_addr == nullptr)
  {
    fprintf(stderr, "[ERROR] Failed to find shn_decrypt\n");
    return;
  }
  printf("[FOUND] shn_decrypt=%p\n", *shn_decrypt_addr);
  exec_mem_len = reinterpret_cast<std::uint8_t *>(*shn_decrypt_addr) - exec_mem;

  *shn_encrypt_addr = const_cast<void *>(reinterpret_cast<const void *>(memrmem(exec_mem, exec_mem_len, SHN_FUNCTION_PATTERN, sizeof(SHN_FUNCTION_PATTERN))));
  if (*shn_encrypt_addr == nullptr)
  {
    fprintf(stderr, "[ERROR] Failed to find shn_decrypt\n");
    *shn_decrypt_addr = nullptr;
    return;
  }
  printf("[FOUND] shn_encrypt=%p\n", *shn_encrypt_addr);
}

void log_hex(std::uint8_t *buf, int num_bytes)
{
  for (int i = 0; i < num_bytes; i++)
  {
    printf("%02x", buf[i]);
  }
  printf("\n");
}

subhook_t shn_encrypt_hook;

void shn_encrypt(struct shn_ctx *c, uint8_t *buf, int num_bytes)
{
  printf("shn_encrypt ");
  log_hex(buf, num_bytes);
  reinterpret_cast<std::add_pointer_t<decltype(shn_encrypt)>>(subhook_get_trampoline(shn_encrypt_hook))(c, buf, num_bytes);
}

subhook_t shn_decrypt_hook;

void shn_decrypt(struct shn_ctx *c, uint8_t *buf, int num_bytes)
{
  reinterpret_cast<std::add_pointer_t<decltype(shn_decrypt)>>(subhook_get_trampoline(shn_decrypt_hook))(c, buf, num_bytes);
  printf("shn_decrypt ");
  log_hex(buf, num_bytes);
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

  const auto hook_flags = static_cast<subhook_flags_t>(SUBHOOK_TRAMPOLINE | SUBHOOK_64BIT_OFFSET);

  shn_encrypt_hook = subhook_new(shn_encrypt_addr, reinterpret_cast<void *>(&shn_encrypt), hook_flags);
  if (subhook_install(shn_encrypt_hook) != 0)
  {
    fprintf(stderr, "[ERROR] Failed to hook shn_encrypt\n");
    subhook_free(shn_encrypt_hook);
    return;
  }

  shn_decrypt_hook = subhook_new(shn_decrypt_addr, reinterpret_cast<void *>(&shn_decrypt), hook_flags);
  if (subhook_install(shn_decrypt_hook) != 0)
  {
    fprintf(stderr, "[ERROR] Failed to hook shn_decrypt\n");
    subhook_remove(shn_encrypt_hook);
    subhook_free(shn_encrypt_hook);
    subhook_free(shn_decrypt_hook);
    return;
  }

  printf("Installed hooks\n");

  // TODO: If a persistent thread is added, add a socket to allow communication (add/remove hooks, look at memory, breakpoints etc)
}