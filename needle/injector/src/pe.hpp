#pragma once

#include <cstdint>

/*
 * References:
 * https://github.com/hasherezade/bearparser/blob/65d6417b1283eb64237141ee0c865bdf0f13ac73/parser/pe/PECore.cpp
 * C:\Program Files (x86)\Windows Kits\10\Include\10.0.22000.0\um\winnt.h
 * C:\Program Files (x86)\Windows Kits\10\Include\10.0.22000.0\shared\minwindef.h
 * https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
 * https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64
 * https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header
 * https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers64
 * https://0xrick.github.io/win-internals/pe1/
 * https://0xrick.github.io/win-internals/pe2/
 * https://0xrick.github.io/win-internals/pe3/
 * https://0xrick.github.io/win-internals/pe4/
 * https://0xrick.github.io/win-internals/pe5/
 */

namespace pe
{
    typedef struct IMAGE_DOS_HEADER
    {
        std::uint16_t e_magic;                     // Magic number
        std::uint16_t e_cblp;                      // Bytes on last page of file
        std::uint16_t e_cp;                        // Pages in file
        std::uint16_t e_crlc;                      // Relocations
        std::uint16_t e_cparhdr;                   // Size of header in paragraphs
        std::uint16_t e_minalloc;                  // Minimum extra paragraphs needed
        std::uint16_t e_maxalloc;                  // Maximum extra paragraphs needed
        std::uint16_t e_ss;                        // Initial (relative) SS value
        std::uint16_t e_sp;                        // Initial SP value
        std::uint16_t e_csum;                      // Checksum
        std::uint16_t e_ip;                        // Initial IP value
        std::uint16_t e_cs;                        // Initial (relative) CS value
        std::uint16_t e_lfarlc;                    // File address of relocation table
        std::uint16_t e_ovno;                      // Overlay number
        std::uint16_t e_res[4];                    // Reserved words
        std::uint16_t e_oemid;                     // OEM identifier (for e_oeminfo)
        std::uint16_t e_oeminfo;                   // OEM information; e_oemid specific
        std::uint16_t e_res2[10];                  // Reserved words
        std::int32_t e_lfanew;                     // File address of new exe header
    } IMAGE_DOS_HEADER;

    typedef struct IMAGE_FILE_HEADER
    {
        std::uint16_t Machine;
        std::uint16_t NumberOfSections;
        std::uint32_t TimeDateStamp;
        std::uint32_t PointerToSymbolTable;
        std::uint32_t NumberOfSymbols;
        std::uint16_t SizeOfOptionalHeader;
        std::uint16_t Characteristics;

        static constexpr std::uint16_t IMAGE_FILE_MACHINE_I386 = 0x014c;
        static constexpr std::uint16_t IMAGE_FILE_MACHINE_IA64 = 0x0200;
        static constexpr std::uint16_t IMAGE_FILE_MACHINE_AMD64 = 0x8664;
    } IMAGE_FILE_HEADER;

    typedef struct IMAGE_DATA_DIRECTORY
    {
        std::uint32_t VirtualAddress;
        std::uint32_t Size;
    } IMAGE_DATA_DIRECTORY;
    static constexpr int IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

    typedef struct IMAGE_OPTIONAL_HEADER32
    {
        //
        // Standard fields.
        //
        std::uint16_t Magic;
        std::uint8_t MajorLinkerVersion;
        std::uint8_t MinorLinkerVersion;
        std::uint32_t SizeOfCode;
        std::uint32_t SizeOfInitializedData;
        std::uint32_t SizeOfUninitializedData;
        std::uint32_t AddressOfEntryPoint;
        std::uint32_t BaseOfCode;
        std::uint32_t BaseOfData;

        //
        // NT additional fields.
        //
        std::uint32_t ImageBase;
        std::uint32_t SectionAlignment;
        std::uint32_t FileAlignment;
        std::uint16_t MajorOperatingSystemVersion;
        std::uint16_t MinorOperatingSystemVersion;
        std::uint16_t MajorImageVersion;
        std::uint16_t MinorImageVersion;
        std::uint16_t MajorSubsystemVersion;
        std::uint16_t MinorSubsystemVersion;
        std::uint32_t Win32VersionValue;
        std::uint32_t SizeOfImage;
        std::uint32_t SizeOfHeaders;
        std::uint32_t CheckSum;
        std::uint16_t Subsystem;
        std::uint16_t DllCharacteristics;
        std::uint32_t SizeOfStackReserve;
        std::uint32_t SizeOfStackCommit;
        std::uint32_t SizeOfHeapReserve;
        std::uint32_t SizeOfHeapCommit;
        std::uint32_t LoaderFlags;
        std::uint32_t NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER32;

    typedef struct IMAGE_OPTIONAL_HEADER64
    {
        std::uint16_t Magic;
        std::uint8_t MajorLinkerVersion;
        std::uint8_t MinorLinkerVersion;
        std::uint32_t SizeOfCode;
        std::uint32_t SizeOfInitializedData;
        std::uint32_t SizeOfUninitializedData;
        std::uint32_t AddressOfEntryPoint;
        std::uint32_t BaseOfCode;
        std::uint64_t ImageBase;
        std::uint32_t SectionAlignment;
        std::uint32_t FileAlignment;
        std::uint16_t MajorOperatingSystemVersion;
        std::uint16_t MinorOperatingSystemVersion;
        std::uint16_t MajorImageVersion;
        std::uint16_t MinorImageVersion;
        std::uint16_t MajorSubsystemVersion;
        std::uint16_t MinorSubsystemVersion;
        std::uint32_t Win32VersionValue;
        std::uint32_t SizeOfImage;
        std::uint32_t SizeOfHeaders;
        std::uint32_t CheckSum;
        std::uint16_t Subsystem;
        std::uint16_t DllCharacteristics;
        std::uint64_t SizeOfStackReserve;
        std::uint64_t SizeOfStackCommit;
        std::uint64_t SizeOfHeapReserve;
        std::uint64_t SizeOfHeapCommit;
        std::uint32_t LoaderFlags;
        std::uint32_t NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER64;

    static constexpr std::uint16_t IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
    static constexpr std::uint16_t IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

    typedef struct IMAGE_NT_HEADERS32
    {
        std::uint32_t Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    } IMAGE_NT_HEADERS32;

    typedef struct IMAGE_NT_HEADERS64
    {
        std::uint32_t Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    } IMAGE_NT_HEADERS64;

    typedef struct IMAGE_SECTION_HEADER
    {
        char Name[8];
        union
        {
            std::uint32_t PhysicalAddress;
            std::uint32_t VirtualSize;
        } Misc;
        std::uint32_t VirtualAddress;
        std::uint32_t SizeOfRawData;
        std::uint32_t PointerToRawData;
        std::uint32_t PointerToRelocations;
        std::uint32_t PointerToLinenumbers;
        std::uint16_t NumberOfRelocations;
        std::uint16_t NumberOfLinenumbers;
        std::uint32_t Characteristics;
    } IMAGE_SECTION_HEADER;
}
