#pragma once

#include <cstdint>
#include <variant>
#include "platform.hpp"

/*
 * References:
 * https://man7.org/linux/man-pages/man5/elf.5.html
 * https://refspecs.linuxbase.org/elf/gabi4+/ch4.intro.html
 * https://refspecs.linuxbase.org/elf/gabi4+/ch4.eheader.html
 * https://refspecs.linuxbase.org/elf/gabi4+/ch4.sheader.html
 */

namespace elf
{
    typedef std::uint8_t byte;

    typedef std::uint32_t Elf32_Addr;
    typedef std::uint32_t Elf32_Off;
    typedef std::uint16_t Elf32_Half;
    typedef std::uint32_t Elf32_Word;
    typedef std::int32_t Elf32_Sword;

    typedef std::uint64_t Elf64_Addr;
    typedef std::uint64_t Elf64_Off;
    typedef std::uint16_t Elf64_Half;
    typedef std::uint32_t Elf64_Word;
    typedef std::int32_t Elf64_Sword;
    typedef std::uint64_t Elf64_Xword;
    typedef std::int64_t Elf64_Sxword;

    typedef struct Elf_Ident
    {
        byte ei_mag[4];     /* 7F 45 4C 46 */
        byte ei_class;      /* 1 = 32-bit, 2 = 64-bit */
        byte ei_data;       /* 1 = little endian, 2 = big endian */
        byte ei_version;    /* 1 = original ELF */
        byte ei_osabi;      /* Quite a few. Normally 0 (System V) */
        byte ei_abiversion; /* Depends on OSABI */
        byte ei_pad[7];     /* Reserved */

        static constexpr byte ELFCLASS32 = 1;
        static constexpr byte ELFCLASS64 = 2;

        static constexpr byte ELFDATA2LSB = 1;
        static constexpr byte ELFDATA2MSB = 2;
    } Elf_Ident;

    typedef struct Elf32_Ehdr
    {
        Elf_Ident e_ident;
        Elf32_Half e_type;
        Elf32_Half e_machine;
        Elf32_Word e_version;
        Elf32_Addr e_entry;
        Elf32_Off e_phoff;
        Elf32_Off e_shoff;
        Elf32_Word e_flags;
        Elf32_Half e_ehsize;
        Elf32_Half e_phentsize;
        Elf32_Half e_phnum;
        Elf32_Half e_shentsize;
        Elf32_Half e_shnum;
        Elf32_Half e_shstrndx;

        static constexpr Elf32_Half SHN_UNDEF = 0;
        static constexpr Elf32_Half SHN_XINDEX = 0xFFFF;
    } Elf32_Ehdr;

    typedef struct Elf64_Ehdr
    {
        Elf_Ident e_ident;
        Elf64_Half e_type;
        Elf64_Half e_machine;
        Elf64_Word e_version;
        Elf64_Addr e_entry;
        Elf64_Off e_phoff;
        Elf64_Off e_shoff;
        Elf64_Word e_flags;
        Elf64_Half e_ehsize;
        Elf64_Half e_phentsize;
        Elf64_Half e_phnum;
        Elf64_Half e_shentsize;
        Elf64_Half e_shnum;
        Elf64_Half e_shstrndx;

        static constexpr Elf64_Half SHN_UNDEF = 0;
        static constexpr Elf64_Half SHN_XINDEX = 0xFFFF;
    } Elf64_Ehdr;

    typedef std::variant<Elf32_Ehdr, Elf64_Ehdr> Elf_Ehdr;

    typedef struct Elf32_Shdr
    {
        Elf32_Word sh_name;
        Elf32_Word sh_type;
        Elf32_Word sh_flags;
        Elf32_Addr sh_addr;
        Elf32_Off sh_offset;
        Elf32_Word sh_size;
        Elf32_Word sh_link;
        Elf32_Word sh_info;
        Elf32_Word sh_addralign;
        Elf32_Word sh_entsize;

        static constexpr Elf32_Word SHT_PROGBITS = 1;
    } Elf32_Shdr;

    typedef struct Elf64_Shdr
    {
        Elf64_Word sh_name;
        Elf64_Word sh_type;
        Elf64_Xword sh_flags;
        Elf64_Addr sh_addr;
        Elf64_Off sh_offset;
        Elf64_Xword sh_size;
        Elf64_Word sh_link;
        Elf64_Word sh_info;
        Elf64_Xword sh_addralign;
        Elf64_Xword sh_entsize;

        static constexpr Elf64_Word SHT_PROGBITS = 1;
    } Elf64_Shdr;

    typedef struct elf_file_details
    {
        bool is_64_bit = false;
        bool is_little_endian = false;
        std::uint16_t machine = 0;
        Elf_Ehdr header;
    } elf_file_details;
}
