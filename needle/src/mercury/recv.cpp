#include "mercury.hpp"
#include "bigendian.hpp"
#include "hermes_mercury/mercury.old.pb.h"
#include "url.hpp"
#include "logger.hpp"

void mercury::recv(util::PacketType type, std::uint8_t *data, int buff_len)
{
  std::unique_lock recv_lock(mercury::detail::pending_recv_mutex);
  int offset = 0;
  std::uint16_t seq_len = bigendian::read_u16(&data[offset]);
  offset += 2;
  std::uint64_t seq = 0;
  switch (seq_len)
  {
    case 2:
    {
      seq = bigendian::read_u16(&data[offset]);
      break;
    }
    case 4:
    {
      seq = bigendian::read_u32(&data[offset]);
      break;
    }
    case 8:
    {
      seq = bigendian::read_u64(&data[offset]);
      break;
    }
    default:
    {
      logger::error("\n[ERROR] Invalid mercury sequence size %u\n", (std::uint32_t) seq_len);
      break;
    }
  }
  offset += seq_len;
  if (mercury::detail::pending_recv_messages.count(seq) == 0)
  {
    mercury::detail::pending_recv_messages.emplace(seq, std::vector<std::string>());
  }
  std::uint8_t flags = data[offset];
  offset += 1;
  std::uint16_t num_parts = bigendian::read_u16(&data[offset]);
  offset += 2;
  auto message_it = mercury::detail::pending_recv_messages.find(seq);
  for (std::uint16_t i = 0; i < num_parts; i++)
  {
    std::uint16_t part_size = bigendian::read_u16((std::uint8_t *) &data[offset]);
    offset += 2;
    std::string part_buffer;
    part_buffer.assign(reinterpret_cast<char *>(data + offset), part_size);
    message_it->second.push_back(std::move(part_buffer));
    offset += part_size;
  }
  if ((flags & 1) != 1)
  {
    return;
  }
  std::vector<std::string> parts(std::move(message_it->second));
  mercury::detail::pending_recv_messages.erase(message_it);
  recv_lock.unlock();
  spotify::mercury::Header header;
  header.ParseFromString(parts[0]);
  parts.erase(parts.begin());

  const std::string &url = header.uri();
  std::unordered_map<std::string, std::string> params;
  auto handler_it = url::find_match(url, mercury::detail::recv_handlers, params);
  logger::set_option(logger::option::FG_LIGHT_RED);
  logger::info("\n%s [RECV] MERCURY - %s\n", util::time_str().c_str(), url.c_str());
  PRINT_PROTO_MESSAGE(header);
  if (handler_it == mercury::detail::recv_handlers.end())
  {
    for (const auto &part: parts)
    {
      util::log_hex(reinterpret_cast<const std::uint8_t *>(part.data()), (int) part.size());
    }
  } else
  {
    handler_it->second(params, std::move(header), std::move(parts));
  }
  logger::set_option(logger::option::DEFAULT);
}
