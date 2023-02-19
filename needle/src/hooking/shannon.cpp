#include "hooking.hpp"
#include "util.hpp"
#include <type_traits>
#include "bigendian.hpp"

#include "authentication/authentication.old.pb.h"
#include "pugixml.hpp"
#include "json.hpp"
#include "mercury/mercury.hpp"

void hooking::detail::hooks::shn_encrypt(struct shn_ctx *c, std::uint8_t *buf, int num_bytes)
{
  if (num_bytes < 2)
  {
    logger::set_option(logger::option::FG_DARK_GREEN);
    logger::info("\n%s [SEND] FAILED TO PARSE:\n", util::time_str().c_str());
    util::log_hex(buf, num_bytes);
    logger::set_option(logger::option::DEFAULT);
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

#ifdef NEEDLE_HIDE_PINGS
  if (type == util::PacketType::Pong)
  {
    reinterpret_cast<std::add_pointer_t<decltype(shn_encrypt)>>(subhook_get_trampoline(shn_encrypt_hook))(c, buf, num_bytes);
    return;
  }
#endif

  logger::set_option(logger::option::FG_DARK_GREEN);
  logger::info("\n%s [SEND] type=%s len=%u\n", util::time_str().c_str(), packet_type_str(type), (std::uint32_t) length);
  switch (type)
  {
    case util::PacketType::Login:
    {
      spotify::authentication::ClientResponseEncrypted client_response;
      client_response.ParseFromArray(&buf[3], num_bytes - 3);
      PRINT_PROTO_MESSAGE(client_response);
      break;
    }
    default:
    {
      util::log_hex(&buf[3], num_bytes - 3);
      break;
    }
  }
  logger::set_option(logger::option::DEFAULT);

  reinterpret_cast<std::add_pointer_t<decltype(shn_encrypt)>>(subhook_get_trampoline(shn_encrypt_hook))(c, buf, num_bytes);
}


struct recv_header
{
    util::PacketType type = util::PacketType::Error;
    std::uint16_t length = 0;
};

void hooking::detail::hooks::shn_decrypt(struct shn_ctx *c, std::uint8_t *buf, int num_bytes)
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

#ifdef NEEDLE_HIDE_PINGS
    if (header.type == util::PacketType::Ping || header.type == util::PacketType::PongAck)
    {
      header.type = util::PacketType::Error;
      header.length = 0;
      return;
    }
#endif

    logger::set_option(logger::option::FG_LIGHT_RED);
    logger::info("\n%s [RECV] type=%s len=%u\n", util::time_str().c_str(), packet_type_str(header.type), (std::uint32_t) header.length);
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
        logger::info("Server TS: %ld\n", server_ts);
        logger::info("Our TS: %ld\n", our_ts);
        break;
      }
      case util::PacketType::PongAck:
      {
        logger::info("Pong Ack\n");
        break;
      }
      case util::PacketType::CountryCode:
      {
        logger::info("Country Code: ");
        for (int i = 0; i < num_bytes; i++)
        {
          logger::info("%c", buf[i]);
        }
        logger::info("\n");
        break;
      }
      case util::PacketType::ProductInfo:
      {
        pugi::xml_document document;
        document.load_buffer(buf, num_bytes);
        if (!document.child("products").child("product"))
        {
          logger::info("Failed to parse ProductInfo: ");
          util::log_hex(buf, num_bytes);
        }

#ifdef NEEDLE_JSON_PI
        nlohmann::json product_info;
        for (pugi::xml_node node: document.child("products").child("product").children())
        {
          product_info.emplace(node.name(), node.child_value());
        }
#ifdef NEEDLE_COMPACT_PI
        logger::info("%s\n", product_info.dump().c_str());
#else
        logger::info("%s\n", product_info.dump(4).c_str());
#endif
#else
#ifdef NEEDLE_COMPACT_PI
        logger::info("%.*s\n", num_bytes, reinterpret_cast<char*>(buf));
#else
        for (pugi::xml_node node: document.child("products").child("product").children())
        {
          logger::info("%s = %s\n", node.name(), node.child_value());
        }
#endif
#endif
        break;
      }
      default:
      {
        if (num_bytes == 0)
        {
          logger::info("<EMPTY>\n");
        } else
        {
          util::log_hex(buf, num_bytes);
        }
        break;
      }
    }
    logger::set_option(logger::option::DEFAULT);
    header.type = util::PacketType::Error;
    header.length = 0;
  }
}
