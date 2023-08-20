#pragma once

#include <cstdint>

/*
 * References:
 * https://en.wikipedia.org/wiki/Mach-O
 * https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o
 * https://web.archive.org/web/20140904004108mp_/https://developer.apple.com/library/mac/documentation/developertools/conceptual/MachORuntime/Reference/reference.html#//apple_ref/doc/uid/20001298-BAJFFCGF
 */

namespace mach_o
{
    typedef std::uint8_t header_magic[4];

    enum class cpu_type : std::uint32_t
    {
        VAX = 0x00000001,
        ROMP = 0x00000002,
        NS32032 = 0x00000004,
        NS32332 = 0x00000005,
        MC680x0 = 0x00000006,
        x86 = 0x00000007,
        MIPS = 0x00000008,
        NS32532 = 0x00000009,
        MC98000 = 0x0000000A,
        HP_PA = 0x0000000B,
        ARM = 0x0000000C,
        MC88000 = 0x0000000D,
        SPARC = 0x0000000E,
        i860_BE = 0x0000000F,
        i860_LE = 0x00000010,
        RS6000 = 0x00000011,
        PowerPC = 0x00000012,
    };

    const char *cpu_type_str(cpu_type type)
    {
      bool is_64_bit = static_cast<std::uint32_t>(type) & 0x01000000;
      type = static_cast<cpu_type>(static_cast<std::uint32_t>(type) & 0xFEFFFFFF);
      switch (type)
      {
        case cpu_type::VAX:
          return is_64_bit ? "VAX 64-bit" : "VAX";
        case cpu_type::ROMP:
          return is_64_bit ? "ROMP 64-bit" : "ROMP";
        case cpu_type::NS32032:
          return is_64_bit ? "NS32032 64-bit" : "NS32032";
        case cpu_type::NS32332:
          return is_64_bit ? "NS32332 64-bit" : "NS32332";
        case cpu_type::MC680x0:
          return is_64_bit ? "MC680x0 64-bit" : "MC680x0";
        case cpu_type::x86:
          return is_64_bit ? "x86 64-bit" : "x86";
        case cpu_type::MIPS:
          return is_64_bit ? "MIPS 64-bit" : "MIPS";
        case cpu_type::NS32532:
          return is_64_bit ? "NS32532 64-bit" : "NS32532";
        case cpu_type::MC98000:
          return is_64_bit ? "MC98000 64-bit" : "MC98000";
        case cpu_type::HP_PA:
          return is_64_bit ? "HP_PA 64-bit" : "HP_PA";
        case cpu_type::ARM:
          return is_64_bit ? "ARM 64-bit" : "ARM";
        case cpu_type::MC88000:
          return is_64_bit ? "MC88000 64-bit" : "MC88000";
        case cpu_type::SPARC:
          return is_64_bit ? "SPARC 64-bit" : "SPARC";
        case cpu_type::i860_BE:
          return is_64_bit ? "i860_BE 64-bit" : "i860_BE";
        case cpu_type::i860_LE:
          return is_64_bit ? "i860_LE 64-bit" : "i860_LE";
        case cpu_type::RS6000:
          return is_64_bit ? "RS6000 64-bit" : "RS6000";
        case cpu_type::PowerPC:
          return is_64_bit ? "PowerPC 64-bit" : "PowerPC";
        default:
          return is_64_bit ? "Unknown 64-bit" : "Unknown";
      }
    }

    typedef struct file_header32
    {
        header_magic magic;
        cpu_type cpu;
        std::uint32_t cpu_subtype;
        std::uint32_t file_type;
        std::uint32_t load_commands_count;
        std::uint32_t load_commands_size;
        std::uint32_t flags;
    } file_header32;

    typedef struct file_header64
    {
        header_magic magic;
        cpu_type cpu;
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

    typedef struct universal_header
    {
        std::uint8_t magic[4];
        std::uint32_t binaries_count;
    } universal_header;

    constexpr std::uint8_t HEADER_MAGIC_UNIVERSAL[4] = {0xCA, 0xFE, 0xBA, 0xBE};

    typedef struct universal_file_entry
    {
        cpu_type cpu;
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

    enum class cpu_subtype_arm : std::uint32_t
    {
        ALL = 0x00000000,
        A500_ARCH = 0x00000001,
        A500 = 0x00000002,
        A440 = 0x00000003,
        M4 = 0x00000004,
        V4T = 0x00000005,
        V6 = 0x00000006,
        V5TEJ = 0x00000007,
        XSCALE = 0x00000008,
        V7 = 0x00000009,
        V7F = 0x0000000A,
        V7S = 0x0000000B,
        V7K = 0x0000000C,
        V8 = 0x0000000D,
        V6M = 0x0000000E,
        V7M = 0x0000000F,
        V7EM = 0x00000010,
    };

    const char *cpu_subtype_arm_str(cpu_subtype_arm subtype)
    {
      switch (subtype)
      {
        case cpu_subtype_arm::ALL:
          return "ALL";
        case cpu_subtype_arm::A500_ARCH:
          return "A500_ARCH";
        case cpu_subtype_arm::A500:
          return "A500";
        case cpu_subtype_arm::A440:
          return "A440";
        case cpu_subtype_arm::M4:
          return "M4";
        case cpu_subtype_arm::V4T:
          return "V4T";
        case cpu_subtype_arm::V6:
          return "V6";
        case cpu_subtype_arm::V5TEJ:
          return "V5TEJ";
        case cpu_subtype_arm::XSCALE:
          return "XSCALE";
        case cpu_subtype_arm::V7:
          return "V7";
        case cpu_subtype_arm::V7F:
          return "V7F";
        case cpu_subtype_arm::V7S:
          return "V7S";
        case cpu_subtype_arm::V7K:
          return "V7K";
        case cpu_subtype_arm::V8:
          return "V8";
        case cpu_subtype_arm::V6M:
          return "V6M";
        case cpu_subtype_arm::V7M:
          return "V7M";
        case cpu_subtype_arm::V7EM:
          return "V7EM";
        default:
          return "Unknown";
      }
    }

    const char *cpu_subtype_str(cpu_type cpu, std::uint32_t subtype)
    {
      cpu = static_cast<cpu_type>(static_cast<std::uint32_t>(cpu) & 0xFEFFFFFF);
      switch (cpu)
      {
        case cpu_type::ARM:
          return cpu_subtype_arm_str(static_cast<cpu_subtype_arm>(subtype));
        default:
          return "Unknown";
      }
    }
}
