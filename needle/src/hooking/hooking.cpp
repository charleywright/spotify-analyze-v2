#include "hooking.hpp"
#include "logger.hpp"
#include <cstring>
#include <string>
#include <fstream>

// Significantly based upon https://github.com/librespot-org/spotify-analyze/blob/master/dump/dump.c

#ifdef _WIN32

#include <windows.h>
#include <psapi.h>

void log_sig_scan(const BYTE *signature, const char *mask, std::size_t len)
{
  logger::info("[SIGSCAN] Scanning for ");
  for (std::size_t i = 0; i < len; i++)
  {
    logger::info("%02X ", signature[i]);
  }
  logger::info("using mask %s...\n", mask);
}

LPVOID find_sig(LPCVOID ptr, DWORD len, const BYTE *signature, const char *mask)
{
  const std::size_t SIG_LEN = std::strlen(mask);
  log_sig_scan(signature, mask, SIG_LEN);
  if (len < SIG_LEN)
  {
    logger::error("Block to small to scan for signature: ptr=%p, len=%d\n", ptr, len);
    return nullptr;
  }
  for (DWORD i = 0; i < len - SIG_LEN; i++)
  {
    bool match = true;
    for (std::size_t j = 0; j < SIG_LEN; j++)
    {
      if (mask[j] == '?')
      {
        continue;
      }
      if (*(reinterpret_cast<const BYTE *>(ptr) + i + j) != signature[j])
      {
        match = false;
        break;
      }
    }
    if (match)
    {
      return const_cast<BYTE *>(reinterpret_cast<const BYTE *>(ptr) + i);
    }
  }
  return nullptr;
}

LPVOID rfind_sig(LPCVOID ptr, DWORD len, const BYTE *signature, const char *mask)
{
  const std::size_t SIG_LEN = std::strlen(mask);
  log_sig_scan(signature, mask, SIG_LEN);
  if (len < SIG_LEN)
  {
    logger::error("Block to small to scan for signature: ptr=%p, len=%d\n", ptr, len);
    return nullptr;
  }
  for (DWORD i = len - SIG_LEN; i > 0; i--)
  {
    DWORD real_i = i - 1; // If we used i >= 0 it would wrap and be infinite
    bool match = true;
    for (std::size_t j = 0; j < SIG_LEN; j++)
    {
      if (mask[j] == '?')
      {
        continue;
      }
      if (*(reinterpret_cast<const BYTE *>(ptr) + real_i + j) != signature[j])
      {
        match = false;
        break;
      }
    }
    if (match)
    {
      return const_cast<BYTE *>(reinterpret_cast<const BYTE *>(ptr) + real_i);
    }
  }
  return nullptr;
}

void find_shn(void **shn_encrypt_addr, void **shn_decrypt_addr)
{
  *shn_encrypt_addr = nullptr;
  *shn_decrypt_addr = nullptr;

  MODULEINFO mod_info;
  ZeroMemory(&mod_info, sizeof(mod_info));
  GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(nullptr), &mod_info, sizeof(mod_info));
  LPVOID exe_base = mod_info.lpBaseOfDll;
  DWORD exe_len = mod_info.SizeOfImage;
  logger::info("[FOUND] image_base=%p, image_len=%d\n", exe_base, exe_len);

  static const BYTE SHANNON_CONSTANT[] = {0x3a, 0xc5, 0x96, 0x69};
  static const char *SHANNON_CONSTANT_MASK = "xxxx";
  LPVOID shannon_constant_addr = find_sig(exe_base, exe_len, SHANNON_CONSTANT, SHANNON_CONSTANT_MASK);
  if (shannon_constant_addr == nullptr)
  {
    logger::error("[ERROR] Failed to find shannon constant 0x6996c53a\n");
    return;
  }
  logger::info("[FOUND] shn_constant=%p\n", shannon_constant_addr);

  static const BYTE ENCRYPTION_PROLOGUE[] = {0x55, 0x8b, 0xec, 0x51, 0x51};
  static const char *ENCRYPTION_PROLOGUE_MASK = "xxxxx";
  DWORD scan_len = reinterpret_cast<BYTE *>(shannon_constant_addr) - reinterpret_cast<BYTE *>(exe_base);
  *shn_encrypt_addr = rfind_sig(exe_base, scan_len, ENCRYPTION_PROLOGUE, ENCRYPTION_PROLOGUE_MASK);
  if (*shn_encrypt_addr == nullptr)
  {
    logger::error("[ERROR] Failed to find encryption constant above shannon constant\n");
    return;
  }
  logger::info("[FOUND] shn_encrypt=%p\n", *shn_encrypt_addr);
  scan_len = reinterpret_cast<BYTE *>(*shn_encrypt_addr) - reinterpret_cast<BYTE *>(exe_base);
  *shn_decrypt_addr = rfind_sig(exe_base, scan_len, ENCRYPTION_PROLOGUE, ENCRYPTION_PROLOGUE_MASK);
  if (*shn_decrypt_addr == nullptr)
  {
    logger::error("[ERROR] Failed to find encryption constant above shn_encrypt\n");
    return;
  }
  logger::info("[FOUND] shn_decrypt=%p\n", *shn_decrypt_addr);
}

#else
#include <unistd.h>

std::uint8_t *get_executable_memory(std::uint64_t *len)
{
  *len = 0;

  char our_executable[256] = {0};
  bool have_our_executable = readlink("/proc/self/exe", our_executable, sizeof(our_executable) - 1) != -1;
  if (!have_our_executable)
  {
    logger::error("[ERROR] Failed to find our executable using /proc/self/maps");
    return nullptr;
  }
  if (std::strstr(our_executable, "spotify") == nullptr)
  {
    logger::error("[ERROR] This is probably not a spotify executable. If so create a symlink with \"spotify\" (lowercase) in the name. Got %s\n", our_executable);
    return nullptr;
  }

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
    if (have_our_executable && line.find(our_executable) == std::string::npos)
    {
      continue;
    }
    if (std::strncmp(permissions, "r-xp", 4) == 0)
    {
      logger::info("Found {%s} using exec name {%s}\n", line.c_str(), our_executable);
      *len = end - start;
      return reinterpret_cast<std::uint8_t *>(static_cast<std::uintptr_t>(start));
    }
  }

  logger::info("End of /proc/self/maps. Our executable = %s\n", have_our_executable ? our_executable : "<NOT FOUND>");

  return nullptr;
}

template <typename ptr>
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
    logger::error("[ERROR] Failed get_executable_memory, exec_mem=%p exec_mem_len=%lu\n", exec_mem, exec_mem_len);
    return;
  }
  logger::info("[FOUND] text=%p size=%zx\n", exec_mem, exec_mem_len);

  const static std::uint8_t SHN_CONSTANT[] = {0x3a, 0xc5, 0x96, 0x69};
  const std::uint8_t *constant_location = memrmem(exec_mem, exec_mem_len, SHN_CONSTANT, sizeof(SHN_CONSTANT));
  if (constant_location == nullptr)
  {
    logger::error("[ERROR] Failed to find shannon constant 0x6996c53a\n");
    return;
  }
  logger::info("[FOUND] shn_const=%p\n", constant_location);
  exec_mem_len = constant_location - exec_mem;

  const static std::uint8_t SHN_FUNCTION_PATTERN[] = {0x55, 0x48, 0x89, 0xe5}; // PUSH RBP; MOV RBP,RSP

  const void *shn_finish_addr = memrmem(exec_mem, exec_mem_len, SHN_FUNCTION_PATTERN, sizeof(SHN_FUNCTION_PATTERN));
  if (shn_finish_addr == nullptr)
  {
    logger::error("[ERROR] Failed to find shn_finish\n");
    return;
  }
  logger::info("[FOUND] shn_finish=%p\n", shn_finish_addr);
  exec_mem_len = reinterpret_cast<const std::uint8_t *>(shn_finish_addr) - exec_mem;

  *shn_decrypt_addr = const_cast<void *>(reinterpret_cast<const void *>(memrmem(exec_mem, exec_mem_len, SHN_FUNCTION_PATTERN, sizeof(SHN_FUNCTION_PATTERN))));
  if (*shn_decrypt_addr == nullptr)
  {
    logger::error("[ERROR] Failed to find shn_decrypt\n");
    return;
  }
  logger::info("[FOUND] shn_decrypt=%p\n", *shn_decrypt_addr);
  exec_mem_len = reinterpret_cast<std::uint8_t *>(*shn_decrypt_addr) - exec_mem;

  *shn_encrypt_addr = const_cast<void *>(reinterpret_cast<const void *>(memrmem(exec_mem, exec_mem_len, SHN_FUNCTION_PATTERN, sizeof(SHN_FUNCTION_PATTERN))));
  if (*shn_encrypt_addr == nullptr)
  {
    logger::error("[ERROR] Failed to find shn_decrypt\n");
    *shn_decrypt_addr = nullptr;
    return;
  }
  logger::info("[FOUND] shn_encrypt=%p\n", *shn_encrypt_addr);
}
#endif

bool hooking::hook()
{
  void *shn_encrypt_addr = nullptr, *shn_decrypt_addr = nullptr;
  find_shn(&shn_encrypt_addr, &shn_decrypt_addr);

  if (shn_encrypt_addr == nullptr || shn_decrypt_addr == nullptr)
  {
    logger::error("[ERROR] shn_encrypt_addr=%p shn_decrypt_addr=%p\n", shn_encrypt_addr, shn_decrypt_addr);
    return false;
  }

  const auto hook_flags = static_cast<subhook_flags_t>(SUBHOOK_TRAMPOLINE | SUBHOOK_64BIT_OFFSET);
  logger::info("Hooking %p, redirecting to %p\n", shn_encrypt_addr, &detail::hooks::shn_encrypt);
  detail::shn_encrypt_hook = subhook_new(shn_encrypt_addr, reinterpret_cast<void *>(&detail::hooks::shn_encrypt), hook_flags);
  if (subhook_install(detail::shn_encrypt_hook) != 0)
  {
    logger::error("[ERROR] Failed to hook shn_encrypt\n");
    subhook_free(detail::shn_encrypt_hook);
    return false;
  }
  logger::info("Hooking %p, redirecting to %p\n", shn_decrypt_addr, &detail::hooks::shn_decrypt);
  detail::shn_decrypt_hook = subhook_new(shn_decrypt_addr, reinterpret_cast<void *>(&detail::hooks::shn_decrypt), hook_flags);
  if (subhook_install(detail::shn_decrypt_hook) != 0)
  {
    logger::error("[ERROR] Failed to hook shn_decrypt\n");
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
