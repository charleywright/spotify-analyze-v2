#include "hooking.hpp"
#include "util.hpp"
#include "bigendian.hpp"
#include "authentication/authentication.old.pb.h"
#include "pugixml.hpp"
#include "json.hpp"
#include "mercury/mercury.hpp"

void hooking::detail::shn_encrypt(struct shn_ctx *c, std::uint8_t *buf, int num_bytes)
{
  if (num_bytes < 2)
  {
    util::text_green();
    printf("%s [SEND] FAILED TO PARSE:\n", util::time_str().c_str());
    util::log_hex(buf, num_bytes);
    printf("\n");
    util::text_reset();
    return;
  }

  auto type = static_cast<util::PacketType>(buf[0]);
  std::uint16_t length = bigendian::read_u16(&buf[1]);

  if (type == util::PacketType::MercuryReq || type == util::PacketType::MercuryEvent || type == util::PacketType::MercurySub ||
      type == util::PacketType::MercuryUnsub)
  {
    mercury::send(type, buf + 3, length);
    reinterpret_cast<std::add_pointer_t<decltype(shn_encrypt)>>(subhook_get_trampoline(shn_encrypt_hook))(c, buf, num_bytes);
    return;
  }

  util::text_green();
  printf("%s [SEND] type=%s len=%u\n", util::time_str().c_str(), packet_type_str(type), (std::uint32_t) length);
  switch (type)
  {
    case util::PacketType::Login:
    {
      spotify::authentication::ClientResponseEncrypted client_response;
      client_response.ParseFromArray(&buf[3], num_bytes - 3);
      PRINT_PROTO_MESSAGE(client_response);
      break;
    }
    case util::PacketType::MercuryEvent:
    case util::PacketType::MercuryReq:
    case util::PacketType::MercurySub:
    case util::PacketType::MercuryUnsub:
    {
      mercury::send(type, &buf[3], length);
      break;
    }
    default:
    {
      util::log_hex(&buf[3], num_bytes - 3);
      break;
    }
  }
  printf("\n");
  util::text_reset();

  reinterpret_cast<std::add_pointer_t<decltype(shn_encrypt)>>(subhook_get_trampoline(shn_encrypt_hook))(c, buf, num_bytes);
}

struct recv_header
{
    util::PacketType type = util::PacketType::Error;
    std::uint16_t length = 0;
};

void hooking::detail::shn_decrypt(struct shn_ctx *c, std::uint8_t *buf, int num_bytes)
{
  static recv_header header;
  reinterpret_cast<std::add_pointer_t<decltype(shn_decrypt)>>(subhook_get_trampoline(shn_decrypt_hook))(c, buf, num_bytes);

  if (num_bytes == 3)
  {
    header.type = static_cast<util::PacketType>(static_cast<std::uint8_t>(buf[0]));
    header.length = bigendian::read_u16(&buf[1]);
  } else
  {
    if (header.type == util::PacketType::MercuryReq || header.type == util::PacketType::MercuryEvent || header.type == util::PacketType::MercurySub ||
        header.type == util::PacketType::MercuryUnsub)
    {
      mercury::recv(header.type, buf, num_bytes);
      header.type = util::PacketType::Error;
      header.length = 0;
      return;
    }

    util::text_red();
    printf("%s [RECV] type=%s len=%u\n", util::time_str().c_str(), packet_type_str(header.type), (std::uint32_t) header.length);
    switch (header.type)
    {
      case util::PacketType::APWelcome:
      {
        spotify::authentication::APWelcome welcome;
        welcome.ParseFromArray(buf, num_bytes);
        PRINT_PROTO_MESSAGE(welcome);
        break;
      }
      case util::PacketType::Ping:
      {
        std::int64_t server_ts = static_cast<std::int64_t>(bigendian::read_u32(buf)) * 1000;
        std::int64_t our_ts = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        printf("Server TS: %ld\n", server_ts);
        printf("Our TS: %ld\n", our_ts);
        break;
      }
      case util::PacketType::PongAck:
      {
        printf("Pong Ack\n");
        break;
      }
      case util::PacketType::CountryCode:
      {
        printf("Country Code: ");
        for (int i = 0; i < num_bytes; i++)
        {
          printf("%c", buf[i]);
        }
        printf("\n");
        break;
      }
      case util::PacketType::ProductInfo:
      {
        pugi::xml_document document;
        document.load_buffer(buf, num_bytes);
        if (!document.child("products").child("product"))
        {
          printf("Failed to parse ProductInfo: ");
          util::log_hex(buf, num_bytes);
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
        if (num_bytes == 0)
        {
          printf("<EMPTY>\n");
        } else
        {
          util::log_hex(buf, num_bytes);
        }
        break;
      }
    }
    printf("\n");
    util::text_reset();
    header.type = util::PacketType::Error;
    header.length = 0;
  }
}
