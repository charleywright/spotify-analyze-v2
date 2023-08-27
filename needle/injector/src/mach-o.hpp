#pragma once

#include <cstdint>
#include <string_view>
#include <unordered_map>
#include <string>
#include <fmt/format.h>

/*
 * References:
 * https://en.wikipedia.org/wiki/Mach-O
 * https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o
 * https://web.archive.org/web/20140904004108mp_/https://developer.apple.com/library/mac/documentation/developertools/conceptual/MachORuntime/Reference/reference.html#//apple_ref/doc/uid/20001298-BAJFFCGF
 */

/*
 * std::hash doesn't support std::pair<std::uint32_t, std::uint32_t> by default
 * so we must add our own. Source: https://stackoverflow.com/a/55083395/12282075
 */
struct hash_pair final
{
    template<class TFirst, class TSecond>
    size_t operator()(const std::pair<TFirst, TSecond> &p) const noexcept
    {
      uintmax_t hash = std::hash<TFirst>{}(p.first);
      hash <<= sizeof(uintmax_t) * 4;
      hash ^= std::hash<TSecond>{}(p.second);
      return std::hash<uintmax_t>{}(hash);
    }
};

namespace mach_o
{
    typedef std::uint8_t header_magic[4];

    typedef struct file_header32
    {
        header_magic magic;
        std::uint32_t cpu;
        std::uint32_t cpu_subtype;
        std::uint32_t file_type;
        std::uint32_t load_commands_count;
        std::uint32_t load_commands_size;
        std::uint32_t flags;
    } file_header32;

    typedef struct file_header64
    {
        header_magic magic;
        std::uint32_t cpu;
        std::uint32_t cpu_subtype;
        std::uint32_t file_type;
        std::uint32_t load_commands_count;
        std::uint32_t load_commands_size;
        std::uint32_t flags;
        std::uint32_t reserved; // Reserved anyway, so no point reading it
    } file_header64;

    // We could use integers instead but this is more readable and performance isn't an issue
    constexpr std::uint8_t HEADER_MAGIC_32_LE[4] = {0xFE, 0xED, 0xFA, 0xCE};
    constexpr std::uint8_t HEADER_MAGIC_32_BE[4] = {0xCE, 0xFA, 0xED, 0xFE};
    constexpr std::uint8_t HEADER_MAGIC_64_LE[4] = {0xFE, 0xED, 0xFA, 0xCF};
    constexpr std::uint8_t HEADER_MAGIC_64_BE[4] = {0xCF, 0xFA, 0xED, 0xFE};

    // No need for full enums, iOS only uses ARM
    constexpr std::uint32_t CPU_CAPABILITY_ABI64 = 0x01000000;
    constexpr std::uint32_t CPU_TYPE_ARM = 12;
    constexpr std::uint32_t CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_CAPABILITY_ABI64;
    constexpr std::uint32_t CPU_SUBTYPE_ARM_V6 = 6;
    constexpr std::uint32_t CPU_SUBTYPE_ARM_V7 = 9;
    constexpr std::uint32_t CPU_SUBTYPE_ARM64_ALL = 0;

    // Supported architectures. We use the same strings as Lipo
    // https://github.com/tpoechtrager/cctools-port/blob/f28fb5e9c31efd3d0552afcce2d2c03cae25c1ca/cctools/libstuff/arch.c#L33-L110
    constexpr std::string_view CPU_ARMV6 = "armv6";
    constexpr std::string_view CPU_ARMV7 = "armv7";
    constexpr std::string_view CPU_ARM64 = "arm64";

    const inline std::unordered_map<std::pair<std::uint32_t, std::uint32_t>, std::string_view, hash_pair> CPU_NAMES = {
            {{CPU_TYPE_ARM,   CPU_SUBTYPE_ARM_V6},    CPU_ARMV6},
            {{CPU_TYPE_ARM,   CPU_SUBTYPE_ARM_V7},    CPU_ARMV7},
            {{CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL}, CPU_ARM64}
    };

    std::string get_cpu_string(std::uint32_t cpu, std::uint32_t cpu_subtype)
    {
      std::pair<std::uint32_t, std::uint32_t> cpu_pair = {cpu, cpu_subtype};
      const auto cpu_str = CPU_NAMES.find(cpu_pair);
      if(cpu_str != CPU_NAMES.end())
      {
        return std::string(cpu_str->second);
      }
      return fmt::format("Unknown CPU (type: {}, subtype: {})", cpu, cpu_subtype);
    }

    typedef struct universal_header
    {
        std::uint8_t magic[4];
        std::uint32_t binaries_count;
    } universal_header;

    constexpr std::uint8_t HEADER_MAGIC_UNIVERSAL[4] = {0xCA, 0xFE, 0xBA, 0xBE};

    typedef struct universal_file_entry
    {
        std::uint32_t cpu;
        std::uint32_t cpu_subtype;
        std::uint32_t offset;
        std::uint32_t size;
        std::uint32_t align_pow;
    } universal_file_entry;

    typedef struct load_command
    {
        std::uint32_t type;
        std::uint32_t size;
    } load_command;

    constexpr std::uint32_t LC_SEGMENT = 0x00000001;
    constexpr std::uint32_t LC_SEGMENT_64 = 0x00000019;

    typedef struct segment_command32
    {
        char name[16];
        std::uint32_t v_addr;
        std::uint32_t v_size;
        std::uint32_t offset;
        std::uint32_t size;
        std::uint32_t max_protection;
        std::uint32_t init_protection;
        std::uint32_t sections_count;
        std::uint32_t flags;
    } segment_command32;

    typedef struct segment_command64
    {
        char name[16];
        std::uint64_t v_addr;
        std::uint64_t v_size;
        std::uint64_t offset;
        std::uint64_t size;
        std::uint32_t max_protection;
        std::uint32_t init_protection;
        std::uint32_t sections_count;
        std::uint32_t flags;
    } segment_command64;
}
