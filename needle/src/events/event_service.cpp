#include "events.hpp"
#include "util.hpp"

void events::send_event_service_event(std::unordered_map<std::string, std::string> params, spotify::mercury::Header header, std::vector<std::string> parts)
{
  for (const auto &part: parts)
  {
    std::vector<std::string> event_parts = util::split_str(part, 0x09);
    for (const auto &event_part: event_parts)
    {
      logger::info("%.*s\n", (int) event_part.size(), event_part.data());
    }
  }
}

void events::recv_event_service_event(std::unordered_map<std::string, std::string> params, spotify::mercury::Header header, std::vector<std::string> parts)
{
  for (const auto &part: parts)
  {
    util::log_hex(reinterpret_cast<const std::uint8_t *>(part.data()), (int) part.size());

    std::vector<std::string> event_parts = util::split_str(part, 0x09);
    for (const auto &event_part: event_parts)
    {
      logger::info("%.*s\n", (int) event_part.size(), event_part.data());
    }
  }
}
