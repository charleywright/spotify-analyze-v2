#pragma once
#include <cstdint>
#include <ctime>
#include <string>

#ifndef NEEDLE_COMPACT_PROTO
#define PRINT_PROTO_MESSAGE(message) (printf("%s\n", message.DebugString().c_str()))
#else
#define PRINT_PROTO_MESSAGE(message) (printf("%s\n", message.ShortDebugString().c_str()))
#endif

namespace util
{
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

    inline const char *packet_type_str(PacketType type)
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
    inline void text_red()
    {
      printf("\033[31m");
    }

    inline void text_green()
    {
      printf("\033[32m");
    }

    inline void text_reset()
    {
      printf("\033[0m");
    }

    inline std::string time_str()
    {
      std::string str;
      str.resize(11);
      time_t time = std::time(nullptr);
      tm *tm = std::localtime(&time);
      std::snprintf(str.data(), str.size(), "[%02d:%02d:%02d]", tm->tm_hour, tm->tm_min, tm->tm_sec);
      return str;
    }

    inline void log_hex(std::uint8_t *buf, int num_bytes)
    {
      for (int i = 0; i < num_bytes; i++)
      {
        printf("%02x", buf[i]);
      }
      printf("\n");
    }
}
