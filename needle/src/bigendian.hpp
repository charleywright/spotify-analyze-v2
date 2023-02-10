#pragma once

#include <cstdint>

namespace bigendian
{
    inline std::uint64_t read_u64(const std::uint8_t *buffer)
    {
      return (
              ((unsigned long long) buffer[0] << 56) |
              ((unsigned long long) buffer[1] << 48) |
              ((unsigned long long) buffer[2] << 40) |
              ((unsigned long long) buffer[3] << 32) |
              ((unsigned long long) buffer[4] << 24) |
              ((unsigned long long) buffer[5] << 16) |
              ((unsigned long long) buffer[6] << 8) |
              ((unsigned long long) buffer[7] << 0));
    }

    inline void write_u64(std::uint64_t num, std::uint8_t *buffer)
    {
      buffer[0] = (unsigned char) ((num & 0xFF00000000000000) >> 56);
      buffer[1] = (unsigned char) ((num & 0x00FF000000000000) >> 48);
      buffer[2] = (unsigned char) ((num & 0x0000FF0000000000) >> 40);
      buffer[3] = (unsigned char) ((num & 0x000000FF00000000) >> 32);
      buffer[4] = (unsigned char) ((num & 0x00000000FF000000) >> 24);
      buffer[5] = (unsigned char) ((num & 0x0000000000FF0000) >> 16);
      buffer[6] = (unsigned char) ((num & 0x000000000000FF00) >> 8);
      buffer[7] = (unsigned char) ((num & 0x00000000000000FF) >> 0);
    }

    inline std::uint32_t read_u32(const std::uint8_t *buffer)
    {
      return (
              ((unsigned int) buffer[0] << 24) |
              ((unsigned int) buffer[1] << 16) |
              ((unsigned int) buffer[2] << 8) |
              ((unsigned int) buffer[3] << 0));
    }

    inline void write_u32(std::uint32_t num, std::uint8_t *buffer)
    {
      buffer[0] = (unsigned char) ((num & 0xFF000000) >> 24);
      buffer[1] = (unsigned char) ((num & 0x00FF0000) >> 16);
      buffer[2] = (unsigned char) ((num & 0x0000FF00) >> 8);
      buffer[3] = (unsigned char) ((num & 0x000000FF) >> 0);
    }

    inline std::uint16_t read_u16(const std::uint8_t *buffer)
    {
      return (((unsigned short) buffer[0] << 8) |
              ((unsigned short) buffer[1] << 0));
    }

    inline void write_u16(std::uint16_t num, std::uint8_t *buffer)
    {
      buffer[0] = (unsigned char) ((num & 0xFF00) >> 8);
      buffer[1] = (unsigned char) ((num & 0x00FF) >> 0);
    }
}