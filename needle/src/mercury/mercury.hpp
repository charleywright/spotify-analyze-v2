#pragma once

#include "util.hpp"
#include <cinttypes>
#include <unordered_map>
#include <vector>
#include <string>
#include <functional>
#include <mutex>
#include "hermes_mercury/mercury.old.pb.h"

namespace mercury
{
    void send(util::PacketType type, std::uint8_t *data, int buff_len);
    void recv(util::PacketType type, std::uint8_t *data, int buff_len);

    namespace detail
    {
        typedef std::function<void(std::unordered_map<std::string, std::string> params, spotify::mercury::Header header,
                                   std::vector<std::string> parts)> handler_t;

        inline std::unordered_map<std::uint64_t, std::vector<std::string>> pending_send_messages;
        inline std::mutex pending_send_mutex;
        inline std::unordered_map<std::string, handler_t> send_handlers = {};

        inline std::unordered_map<std::uint64_t, std::vector<std::string>> pending_recv_messages;
        inline std::mutex pending_recv_mutex;
        inline std::unordered_map<std::string, handler_t> recv_handlers = {};
    }
}
