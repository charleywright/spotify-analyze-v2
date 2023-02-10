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
#include "bigendian.hpp"
#include "pugixml.hpp"
#include "json.hpp"

#include "authentication/authentication.old.pb.h"

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

enum class PacketType : std::uint8_t
{
    SecretBlock = 0x02,
    Ping = 0x04,
    StreamChunk = 0x08,
    StreamChunkRes = 0x09,
    ChannelError = 0x0a,
    ChannelAbort = 0x0b,
    RequestKey = 0x0c,
    AesKey = 0x0d,
    AesKeyError = 0x0e,
    Image = 0x19,
    CountryCode = 0x1b,
    Pong = 0x49,
    PongAck = 0x4a,
    Pause = 0x4b,
    ProductInfo = 0x50,
    LegacyWelcome = 0x69,
    LicenseVersion = 0x76,
    Login = 0xab,
    APWelcome = 0xac,
    AuthFailure = 0xad,
    MercuryReq = 0xb2,
    MercurySub = 0xb3,
    MercuryUnsub = 0xb4,
    MercuryEvent = 0xb5,
    TrackEndedTime = 0x82,
    UnknownDataAllZeros = 0x1f,
    PreferredLocale = 0x74,
    Unknown0x0f = 0x0f,
    Unknown0x10 = 0x10,
    Unknown0x4f = 0x4f,
    Unknown0xb6 = 0xb6,

    Error = 0xff
};

const char *packet_type_str(PacketType type)
{
  switch (type)
  {
    case PacketType::SecretBlock:
      return "SecretBlock";
    case PacketType::Ping:
      return "Ping";
    case PacketType::StreamChunk:
      return "StreamChunk";
    case PacketType::StreamChunkRes:
      return "StreamChunkRes";
    case PacketType::ChannelError:
      return "ChannelError";
    case PacketType::ChannelAbort:
      return "ChannelAbort";
    case PacketType::RequestKey:
      return "RequestKey";
    case PacketType::AesKey:
      return "AesKey";
    case PacketType::AesKeyError:
      return "AesKeyError";
    case PacketType::Image:
      return "Image";
    case PacketType::CountryCode:
      return "CountryCode";
    case PacketType::Pong:
      return "Pong";
    case PacketType::PongAck:
      return "PongAck";
    case PacketType::Pause:
      return "Pause";
    case PacketType::ProductInfo:
      return "ProductInfo";
    case PacketType::LegacyWelcome:
      return "LegacyWelcome";
    case PacketType::LicenseVersion:
      return "LicenseVersion";
    case PacketType::Login:
      return "Login";
    case PacketType::APWelcome:
      return "APWelcome";
    case PacketType::AuthFailure:
      return "AuthFailure";
    case PacketType::MercuryReq:
      return "MercuryReq";
    case PacketType::MercurySub:
      return "MercurySub";
    case PacketType::MercuryUnsub:
      return "MercuryUnsub";
    case PacketType::MercuryEvent:
      return "MercuryEvent";
    case PacketType::TrackEndedTime:
      return "TrackEndedTime";
    case PacketType::UnknownDataAllZeros:
      return "UnknownDataAllZeros";
    case PacketType::PreferredLocale:
      return "PreferredLocale";
    case PacketType::Unknown0x0f:
      return "Unknown0x0f";
    case PacketType::Unknown0x10:
      return "Unknown0x10";
    case PacketType::Unknown0x4f:
      return "Unknown0x4f";
    case PacketType::Unknown0xb6:
      return "Unknown0xb6";
    case PacketType::Error:
      return "Error";
    default:
      return "Default";
  }
};

// https://man7.org/linux/man-pages/man5/terminal-colors.d.5.html
void text_red()
{
  printf("\033[31m");
}

void text_green()
{
  printf("\033[32m");
}

void text_reset()
{
  printf("\033[0m");
}

std::string time_str()
{
  std::string str;
  str.resize(11);
  time_t time = std::time(nullptr);
  tm *tm = std::localtime(&time);
  std::snprintf(str.data(), str.size(), "[%02d:%02d:%02d]", tm->tm_hour, tm->tm_min, tm->tm_sec);
  return str;
}

#ifndef NEEDLE_COMPACT_PROTO
#define PRINT_PROTO_MESSAGE(message) (printf("%s\n", message.DebugString().c_str()))
#else
#define PRINT_PROTO_MESSAGE(message) (printf("%s\n", message.ShortDebugString().c_str()))
#endif

subhook_t shn_encrypt_hook;

void shn_encrypt(struct shn_ctx *c, std::uint8_t *buf, int num_bytes)
{
  if (num_bytes < 2)
  {
    text_green();
    printf("[SEND] FAILED TO PARSE:\n");
    log_hex(buf, num_bytes);
    printf("\n");
    text_reset();
    return;
  }

  auto type = static_cast<PacketType>(buf[0]);
  std::uint16_t length = bigendian::read_u16(&buf[1]);
  text_green();
  printf("%s [SEND] type=%s len=%u\n", time_str().c_str(), packet_type_str(type), (std::uint32_t) length);
  switch (type)
  {
    case PacketType::Login:
    {
      spotify::authentication::ClientResponseEncrypted client_response;
      client_response.ParseFromArray(&buf[3], num_bytes);
      PRINT_PROTO_MESSAGE(client_response);
      break;
    }
    default:
    {
      log_hex(buf, num_bytes);
      break;
    }
  }
  printf("\n");
  text_reset();

  reinterpret_cast<std::add_pointer_t<decltype(shn_encrypt)>>(subhook_get_trampoline(shn_encrypt_hook))(c, buf, num_bytes);
}

subhook_t shn_decrypt_hook;

struct recv_header
{
    PacketType type = PacketType::Error;
    std::uint16_t length = 0;
};

void shn_decrypt(struct shn_ctx *c, uint8_t *buf, int num_bytes)
{
  static recv_header header;
  reinterpret_cast<std::add_pointer_t<decltype(shn_decrypt)>>(subhook_get_trampoline(shn_decrypt_hook))(c, buf, num_bytes);

  if (num_bytes == 3)
  {
    header.type = static_cast<PacketType>(static_cast<std::uint8_t>(buf[0]));
    header.length = bigendian::read_u16(&buf[1]);
  } else
  {
    text_red();
    printf("%s [RECV] type=%s len=%u\n", time_str().c_str(), packet_type_str(header.type), (std::uint32_t) header.length);
    switch (header.type)
    {
      case PacketType::APWelcome:
      {
        spotify::authentication::APWelcome welcome;
        welcome.ParseFromArray(buf, num_bytes);
        PRINT_PROTO_MESSAGE(welcome);
        break;
      }
      case PacketType::Ping:
      {
        std::int64_t server_ts = (std::int64_t) bigendian::read_u32(buf) * 1000;
        printf("Server TS: %ld\n", server_ts);
        break;
      }
      case PacketType::PongAck:
      {
        printf("Pong Ack\n");
        break;
      }
      case PacketType::CountryCode:
      {
        printf("Country Code: ");
        for (int i = 0; i < num_bytes; i++)
        {
          printf("%c", buf[i]);
        }
        printf("\n");
        break;
      }
      case PacketType::ProductInfo:
      {
        pugi::xml_document document;
        document.load_string((char *) buf);
        if (!document.child("products").child("product"))
        {
          printf("Failed to parse ProductInfo: ");
          log_hex(buf, num_bytes);
        }

#ifdef NEEDLE_JSON_PI
        nlohmann::json product_info;
        for (pugi::xml_node node: document.child("products").child("product").children())
        {
          product_info.emplace(node.name(), node.child_value());
        }
#ifdef NEEDLE_COMPACT_PI
        printf("%s\n", product_info.dump().c_str());
#else
        printf("%s\n", product_info.dump(4).c_str());
#endif
#else
#ifdef NEEDLE_COMPACT_PI
        printf("%.*s\n", num_bytes, reinterpret_cast<char*>(buf));
#else
        for (pugi::xml_node node: document.child("products").child("product").children())
        {
          printf("%s = %s\n", node.name(), node.child_value());
        }
#endif
#endif
        break;
      }
      default:
      {
        log_hex(buf, num_bytes);
        break;
      }
    }
    printf("\n");
    text_reset();
    header.type = PacketType::Error;
    header.length = 0;
  }
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