#include "hooking.hpp"
#include <cstring>
#include <fstream>

// Significantly based upon https://github.com/librespot-org/spotify-analyze/blob/master/dump/dump.c

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

  printf("End of /proc/self/maps\n");
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

bool hooking::hook()
{
  void *shn_encrypt_addr = nullptr, *shn_decrypt_addr = nullptr;
  find_shn(&shn_encrypt_addr, &shn_decrypt_addr);

  if (shn_encrypt_addr == nullptr || shn_decrypt_addr == nullptr)
  {
    fprintf(stderr, "[ERROR] shn_encrypt_addr=%p shn_decrypt_addr=%p\n", shn_encrypt_addr, shn_decrypt_addr);
    return false;
  }

  const auto hook_flags = static_cast<subhook_flags_t>(SUBHOOK_TRAMPOLINE | SUBHOOK_64BIT_OFFSET);
  detail::shn_encrypt_hook = subhook_new(shn_encrypt_addr, reinterpret_cast<void *>(&detail::shn_encrypt), hook_flags);
  if (subhook_install(detail::shn_encrypt_hook) != 0)
  {
    fprintf(stderr, "[ERROR] Failed to hook shn_encrypt\n");
    subhook_free(detail::shn_encrypt_hook);
    return false;
  }
  detail::shn_decrypt_hook = subhook_new(shn_decrypt_addr, reinterpret_cast<void *>(&detail::shn_decrypt), hook_flags);
  if (subhook_install(detail::shn_decrypt_hook) != 0)
  {
    fprintf(stderr, "[ERROR] Failed to hook shn_decrypt\n");
    subhook_remove(detail::shn_encrypt_hook);
    subhook_free(detail::shn_encrypt_hook);
    subhook_free(detail::shn_decrypt_hook);
    return false;
  }

  return true;
}

void hooking::unhook()
{
  subhook_remove(detail::shn_encrypt_hook);
  subhook_free(detail::shn_encrypt_hook);
  subhook_remove(detail::shn_decrypt_hook);
  subhook_free(detail::shn_decrypt_hook);
}
