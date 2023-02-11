#pragma once
#include <string>
#include <unordered_map>
#include <vector>
#include "hermes_mercury/mercury.old.pb.h"

namespace events
{
    void recv_event_service_event(std::unordered_map<std::string, std::string> params, spotify::mercury::Header header, std::vector<std::string> parts);
    void send_event_service_event(std::unordered_map<std::string, std::string> params, spotify::mercury::Header header, std::vector<std::string> parts);

    namespace detail
    {
      void parse_event_service_event(std::vector<std::string> parts);
    }
}