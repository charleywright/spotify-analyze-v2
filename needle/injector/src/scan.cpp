#include "scan.hpp"
#include <fstream>
#include "sigscanner/sigscanner.hpp"
#include "elf.hpp"
#include "pe.hpp"
#include "mach-o.hpp"
#include <memory>
#include <array>
#include "fmt/core.h"
#include <variant>
#include "byteswap.hpp"
#include "file_backed_block.hpp"

const char *SERVER_PUBLIC_KEY_SIG = "ac e0 46 0b ff c2 30 af f4 6b fe c3 bf bf 86 3d a1 91 c6 cc 33 6c 93 a1 4f b3 b0 16 12 ac ac 6a f1 80 e7 f6 14 d9 42 9d be 2e 34 66 43 e3 62 d2 32 7a 1a 0d 92 3b ae dd 14 02 b1 81 55 05 61 04 d5 2c 96 a4 4c 1e cc 02 4a d4 b2 0c 00 1f 17 ed c2 2f c4 35 21 c8 f0 cb ae d2 ad d7 2b 0f 9d b3 c5 32 1a 2a fe 59 f3 5a 0d ac 68 f1 fa 62 1e fb 2c 8d 0c b7 39 2d 92 47 e3 d7 35 1a 6d bd 24 c2 ae 25 5b 88 ff ab 73 29 8a 0b cc cd 0c 58 67 31 89 e8 bd 34 80 78 4a 5f c9 6b 89 9d 95 6b fc 86 d7 4f 33 a6 78 17 96 c9 c3 2d 0d 32 a5 ab cd 05 27 e2 f7 10 a3 96 13 c4 2f 99 c0 27 bf ed 04 9c 3c 27 58 04 b6 b2 19 f9 c1 2f 02 e9 48 63 ec a1 b6 42 a0 9d 48 25 f8 b3 9d d0 e8 6a f9 48 4d a1 c2 ba 86 30 42 ea 9d b3 08 6c 19 0e 48 b3 9d 66 eb 00 06 a2 5a ee a1 1b 13 87 3c d7 19 e6 55 bd";

struct relocation_entry
{
    std::uint64_t offset_in_file = 0;
    std::uint64_t size_in_file = 0;
    std::uint64_t offset_in_memory = 0;
    std::uint64_t size_in_memory = 0;
};

/*
 * Take a position in a file and calculate the offset from the module base address to that data.
 * Frida's modules (Process.getModuleByName etc.) do not have a concept of segments so the offset
 * must be calculated relative to the first segment in the file that is loaded. For example if the
 * position is in the third loadable segment, the offset will be s1.len + s2.len + s3_offset. It
 * would be nice if it was that simple however some sections such as .bss will not occupy space in
 * the file but will occupy space in memory. We need to take all of this into account when calculating
 * the relocated offset.
 */
std::uint64_t calculate_relocated_offset(std::uint64_t position, const std::vector<relocation_entry> &relocations)
{
  for (const auto &entry: relocations)
  {
    if (position >= entry.offset_in_file && position < entry.offset_in_file + entry.size_in_file)
    {
      const std::uint64_t offset_from_segment = position - entry.offset_in_file;
      const std::uint64_t offset_from_base = entry.offset_in_memory - relocations[0].offset_in_memory;
      return offset_from_base + offset_from_segment;
    }
  }
  return position;
}

/*
 * Take a position in a file and calculate the offset in virtual memory where the data at that
 * position will be placed. This is only reliable for executables as position independent dynamic
 * libraries can be loaded at any base address.
 */
std::uint64_t calculate_relocated_address(std::uint64_t position, const std::vector<relocation_entry> &relocations)
{
  for (const auto &entry: relocations)
  {
    if (position >= entry.offset_in_file && position < entry.offset_in_file + entry.size_in_file)
    {
      const std::uint64_t offset = position - entry.offset_in_file;
      return entry.offset_in_memory + offset;
    }
  }
  return position;
}

elf::elf_file_details parse_elf(std::ifstream &binary_file)
{
  elf::elf_file_details binary_details;

  elf::Elf_Ident e_ident;
  binary_file.read(reinterpret_cast<char *>(&e_ident), sizeof(e_ident));
  if (binary_file.gcount() != sizeof(e_ident))
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to read ELF identifier\n");
    return binary_details;
  }

  const sigscanner::signature elf_header_magic = "7F 45 4C 46";
  if (!elf_header_magic.check(e_ident.ei_mag, sizeof(e_ident.ei_mag)))
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Binary is not an ELF file\n");
    return binary_details;
  }

  binary_details.is_64_bit = e_ident.ei_class == elf::Elf_Ident::ELFCLASS64;
  binary_details.is_little_endian = e_ident.ei_data == elf::Elf_Ident::ELFDATA2LSB;

  fmt::print("Detected binary as {} {}\n", binary_details.is_64_bit ? "64-bit" : "32-bit", binary_details.is_little_endian ? "little endian" : "big endian");

  if (binary_details.is_64_bit)
  {
    binary_details.header = elf::Elf64_Ehdr{0};
    auto &elf_header = std::get<elf::Elf64_Ehdr>(binary_details.header);
    elf_header.e_ident = e_ident;
    binary_file.read(reinterpret_cast<char *>(&elf_header) + sizeof(e_ident), sizeof(elf_header) - sizeof(e_ident));
    if (binary_file.gcount() != sizeof(elf_header) - sizeof(e_ident))
    {
      fflush(stdout);
      fmt::print(stderr, "Error: Failed to read ELF header\n");
      return binary_details;
    }
    binary_details.machine = elf_header.e_machine;
  } else
  {
    binary_details.header = elf::Elf32_Ehdr{0};
    auto &elf_header = std::get<elf::Elf32_Ehdr>(binary_details.header);
    elf_header.e_ident = e_ident;
    binary_file.read(reinterpret_cast<char *>(&elf_header) + sizeof(e_ident), sizeof(elf_header) - sizeof(e_ident));
    if (binary_file.gcount() != sizeof(elf_header) - sizeof(e_ident))
    {
      fflush(stdout);
      fmt::print(stderr, "Error: Failed to read ELF header\n");
      return binary_details;
    }
    binary_details.machine = elf_header.e_machine;
  }

  return binary_details;
}

std::vector<relocation_entry> parse_elf_relocations(std::ifstream &binary_file, const elf::elf_file_details &binary_details)
{
  /*
   * These are offsets of the shannon constant using a binary file scan:
   *   0x0001a6ed47
   *   0x0001a6f0aa
   *   0x0001a70887
   * These are the offsets when the binary is loaded into memory:
   *   0x0001c6fd47
   *   0x0001c700aa
   *   0x0001c71887
   * The difference is 0x201000, this is due to relocations. When an executable is loaded from disk it is memory-mapped
   * into virtual memory according to the segments defined in the file. In an ELF file the segments to be loaded are
   * defined in the program header table with p_type being PT_LOAD. We can look at these headers using readelf:
   *
   *   readelf --segments /opt/spotify/spotify
   *     Type           Offset             VirtAddr           PhysAddr
   *                    FileSiz            MemSiz              Flags  Align
   *     PHDR           0x0000000000000040 0x0000000000200040 0x0000000000200040
   *                    0x00000000000002a0 0x00000000000002a0  R      0x8
   *     INTERP         0x00000000000002e0 0x00000000002002e0 0x00000000002002e0
   *                    0x000000000000001c 0x000000000000001c  R      0x1
   *         [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
   *     LOAD           0x0000000000000000 0x0000000000200000 0x0000000000200000
   *                    0x00000000008dab74 0x00000000008dab74  R      0x1000
   *     LOAD           0x00000000008dab80 0x0000000000adbb80 0x0000000000adbb80
   *                    0x0000000001336070 0x0000000001336070  R E    0x1000
   *     LOAD           0x0000000001c10c00 0x0000000001e12c00 0x0000000001e12c00
   *                    0x000000000000a8e8 0x000000000000a8e8  RW     0x1000
   *     LOAD           0x0000000001c1b4f0 0x0000000001e1e4f0 0x0000000001e1e4f0
   *                    0x000000000052bfb0 0x000000000055a468  RWE    0x1000
   *     TLS            0x0000000001c10c00 0x0000000001e12c00 0x0000000001e12c00
   *                    0x0000000000000040 0x0000000000001431  R      0x40
   *     DYNAMIC        0x0000000001c1b198 0x0000000001e1d198 0x0000000001e1d198
   *                    0x0000000000000330 0x0000000000000330  RW     0x8
   *     GNU_RELRO      0x0000000001c10c00 0x0000000001e12c00 0x0000000001e12c00
   *                    0x000000000000a8e8 0x000000000000b400  R      0x1
   *     GNU_EH_FRAME   0x000000000041b2b0 0x000000000061b2b0 0x000000000061b2b0
   *                    0x00000000000c895c 0x00000000000c895c  R      0x4
   *     GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
   *                    0x0000000000000000 0x0000000000000000  RW     0x0
   *     NOTE           0x00000000000002fc 0x00000000002002fc 0x00000000002002fc
   *                    0x0000000000000020 0x0000000000000020  R      0x4
   *
   * There are 4 LOAD segments and use an alignment of 0x1000 bytes. Looking at /proc/<pid>/maps it appears to match:
   *
   *   address           perms offset  dev    inode       pathname
   *   00200000-00adb000 r--p 00000000 103:07 933388      /opt/spotify/spotify
   *   00adb000-01e12000 r-xp 008da000 103:07 933388      /opt/spotify/spotify
   *   01e12000-01e1e000 r--p 01c10000 103:07 933388      /opt/spotify/spotify
   *   01e1e000-0234b000 rwxp 01c1b000 103:07 933388      /opt/spotify/spotify
   *
   * The addresses used for loading don't exactly match the program headers, but after taking alignment into consideration
   * they match. If the segment start and/or end don't lie on page boundaries the linker looks backwards in the file and
   * reads the bytes behind the current position to pad the segment. The same occurs after the segment, and if no data is
   * available (EOF) the segment is padded with zeroes. This allows the segment to be mapped with only a single continuous
   * read from the file and the segment's data is mapped to the correct location. This causes the segments in
   * /proc/pid/maps to not be the same size nor have the same base address as the program headers but the data is in the
   * expected location. There are some resources about the ELF format linked at the top of elf.hpp and for learning about
   * linkers there are a few very good videos in a playlist called "CS 361 Systems Programming" on YouTube.
  */

  std::vector<relocation_entry> relocations;

  /*
   * TODO: Migrate to an elf_file class. This will allow us to use the same code for both 32-bit
   * and 64-bit binaries and abstract away the implementation.
   */
  if (binary_details.is_64_bit)
  {
    const auto &header = std::get<elf::Elf64_Ehdr>(binary_details.header);
    elf::Elf64_Half program_header_table_entry_size = header.e_phentsize;
    if (program_header_table_entry_size != sizeof(elf::Elf64_Phdr))
    {
      fflush(stdout);
      fmt::print(stderr, "Error: Invalid program header table entry size\n");
      return relocations;
    }

    std::vector<elf::Elf64_Phdr> program_headers(header.e_phnum);
    elf::Elf64_Half program_header_table_size = header.e_phnum * program_header_table_entry_size;
    binary_file.seekg(static_cast<std::streamoff>(header.e_phoff));
    binary_file.read(reinterpret_cast<char *>(program_headers.data()), static_cast<std::streamsize>(program_header_table_size));
    if (binary_file.gcount() != program_header_table_size)
    {
      fflush(stdout);
      fmt::print(stderr, "Error: Failed to read program headers\n");
      return relocations;
    }

    for (const auto &program_header: program_headers)
    {
      if (program_header.p_type == elf::Elf64_Phdr::PT_LOAD)
      {
        relocation_entry entry;
        entry.offset_in_file = program_header.p_offset;
        entry.size_in_file = program_header.p_filesz;
        elf::Elf64_Addr aligned_vaddr_start = program_header.p_vaddr / program_header.p_align * program_header.p_align;
        elf::Elf64_Addr aligned_vaddr_end =
                (program_header.p_vaddr + program_header.p_memsz + program_header.p_align - 1) / program_header.p_align * program_header.p_align;
        entry.size_in_memory = program_header.p_memsz;
        entry.offset_in_memory = program_header.p_vaddr;
        entry.size_in_memory = program_header.p_memsz;
        fmt::print("Found ELF relocation {:#012x}-{:#012x} -> {:#012x}-{:#012x} ({:#012x} - {:#012x})\n",
                   program_header.p_offset,
                   program_header.p_filesz,
                   program_header.p_vaddr,
                   program_header.p_vaddr + program_header.p_memsz,
                   aligned_vaddr_start,
                   aligned_vaddr_end
        );
        relocations.emplace_back(entry);
      }
    }
  } else
  {
    const auto &header = std::get<elf::Elf32_Ehdr>(binary_details.header);
    elf::Elf32_Half program_header_table_entry_size = header.e_phentsize;
    if (program_header_table_entry_size != sizeof(elf::Elf32_Shdr))
    {
      fflush(stdout);
      fmt::print(stderr, "Error: Invalid section header table entry size\n");
      return relocations;
    }

    std::vector<elf::Elf32_Phdr> program_headers(header.e_phnum);
    elf::Elf32_Half program_header_table_size = header.e_phnum * program_header_table_entry_size;
    binary_file.seekg(static_cast<std::streamoff>(header.e_phoff));
    binary_file.read(reinterpret_cast<char *>(program_headers.data()), static_cast<std::streamsize>(program_header_table_size));
    if (binary_file.gcount() != program_header_table_size)
    {
      fflush(stdout);
      fmt::print(stderr, "Error: Failed to read program headers\n");
      return relocations;
    }

    for (const auto &program_header: program_headers)
    {
      if (program_header.p_type == elf::Elf32_Phdr::PT_LOAD)
      {
        relocation_entry entry;
        entry.offset_in_file = program_header.p_offset;
        entry.size_in_file = program_header.p_filesz;
        elf::Elf32_Addr aligned_vaddr_start = program_header.p_vaddr / program_header.p_align * program_header.p_align;
        elf::Elf32_Addr aligned_vaddr_end =
                (program_header.p_vaddr + program_header.p_memsz + program_header.p_align - 1) / program_header.p_align * program_header.p_align;
        entry.size_in_memory = program_header.p_memsz;
        entry.offset_in_memory = program_header.p_vaddr;
        entry.size_in_memory = program_header.p_memsz;
        fmt::print("Found ELF relocation {:#012x}-{:#012x} -> {:#012x}-{:#012x} ({:#012x} - {:#012x})\n",
                   program_header.p_offset,
                   program_header.p_filesz,
                   program_header.p_vaddr,
                   program_header.p_vaddr + program_header.p_memsz,
                   aligned_vaddr_start,
                   aligned_vaddr_end
        );
        relocations.emplace_back(entry);
      }
    }
  }

  return relocations;
}

void scan_linux(scan_result &offsets, const std::filesystem::path &binary_path)
{
  /*
   * On Linux the spotify binary is an ELF file. We can use this to determine the architecture of the binary and then
   * use the correct signatures. We also need to parse the ELF file to find relocations.
   */
  const std::string binary_filename = binary_path.filename().string();
  std::ifstream binary_file(binary_path, std::ios::binary);
  if (!binary_file)
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to open {}\n", binary_path.string());
    return;
  }

  elf::elf_file_details binary_details = parse_elf(binary_file);
  if (binary_details.machine == 0)
  {
    return;
  }

  // Symbols move around when loaded into memory. See the comment at the top of the implementation
  std::vector<relocation_entry> relocations = parse_elf_relocations(binary_file, binary_details);

  const sigscanner::signature SHANNON_CONSTANT = "3A C5 96 69";
  const sigscanner::signature SERVER_PUBLIC_KEY = SERVER_PUBLIC_KEY_SIG;
  sigscanner::multi_scanner scanner;
  scanner.add_signature(SHANNON_CONSTANT);
  scanner.add_signature(SERVER_PUBLIC_KEY);
  std::unordered_map<sigscanner::signature, std::vector<sigscanner::offset>> results = scanner.scan_file(binary_path);
  std::vector<sigscanner::offset> &shannon_constant_offsets = results[SHANNON_CONSTANT];
  std::vector<sigscanner::offset> &server_public_key_offsets = results[SERVER_PUBLIC_KEY];
  if (server_public_key_offsets.empty())
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to find server public key\n");
    return;
  }
  if (server_public_key_offsets.size() != 1)
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Expected only one server public key, found {}\n", server_public_key_offsets.size());
    return;
  }
  std::uint64_t server_key_offset = calculate_relocated_offset(server_public_key_offsets[0], relocations);
  std::uint64_t server_key_addr = calculate_relocated_address(server_public_key_offsets[0], relocations);
  fmt::print("Found server public key at {}:{:#012x} Offset: {:#012x} Address: {:#012x}\n",
             binary_filename,
             server_public_key_offsets[0],
             server_key_offset,
             server_key_addr
  );
  offsets.server_public_key = server_key_offset;
  if (shannon_constant_offsets.empty())
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to find shannon constant\n");
    return;
  }
  for (const auto &offset: shannon_constant_offsets)
  {
    std::uint64_t relocated_offset = calculate_relocated_offset(offset, relocations);
    std::uint64_t relocated_addr = calculate_relocated_address(offset, relocations);
    fmt::print("Found shannon constant at {}:{:#012x} Offset: {:#012x} Address: {:#012x}\n",
               binary_filename,
               offset,
               relocated_offset,
               relocated_addr
    );
  }

  /*
   * shn_encrypt, shn_decrypt and shn_finish all have the same prologue:
   * shn_encrypt 55 48 89 E5 41 56 53 83 BF CC 00 00 00 00 74 64                  start=0x0000000001C700D0 end=0x0000000001C70C07 size=0xB37
   * shn_decrypt 55 48 89 E5 41 56 53 83 BF CC 00 00 00 00 74 73                  start=0x0000000001C70C10 end=0x0000000001C7177F size=0xB6F
   * shn_finish  55 48 89 E5 41 57 41 56 41 54 53 41 89 D7 49 89 F6 48 89 FB 44   start=0x0000000001C71790 end=0x0000000001C719B0 size=0x220
   *
   * 55         push    rbp
   * 48 89 E5   mov     rbp, rsp
   *
   * Since this is a very common prologue it should be very reliable. We can discount shn_finish by
   * checking the distance between the address we hit and the constant due to the encryption/decryption
   * functions being quite long.
   */

  sigscanner::offset last_shannon_constant = shannon_constant_offsets[shannon_constant_offsets.size() - 1];
  std::array<std::uint8_t, 0x2000> shn_bytes{0};
  std::int64_t shn_prologue_scan_base = static_cast<std::int64_t>(last_shannon_constant - shn_bytes.size());
  binary_file.seekg(std::max(std::int64_t{0}, shn_prologue_scan_base));
  binary_file.read(reinterpret_cast<char *>(shn_bytes.data()), shn_bytes.size());
  sigscanner::signature function_prologue = "55 48 89 E5";
  std::vector<sigscanner::offset> function_prologues = function_prologue.reverse_scan(shn_bytes.data(), shn_bytes.size(), shn_prologue_scan_base);
  if (function_prologues.empty())
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to find shn_encrypt/shn_decrypt prologue\n");
    return;
  }
  // We hit shn_finish
  if (last_shannon_constant - function_prologues[0] < 0x200)
  {
    std::uint64_t relocated_shn_finish_offset = calculate_relocated_offset(function_prologues[0], relocations);
    std::uint64_t relocated_shn_finish_addr = calculate_relocated_address(function_prologues[0], relocations);
    fmt::print("Found shn_finish at {}:{:#012x} Offset: {:#012x} Address: {:#012x}\n",
               binary_filename,
               function_prologues[0],
               relocated_shn_finish_offset,
               relocated_shn_finish_addr
    );
    function_prologues.erase(function_prologues.begin());
  }
  for (auto &prologue: function_prologues)
  {
    std::uint64_t relocated_prologue_offset = calculate_relocated_offset(prologue, relocations);
    std::uint64_t relocated_prologue_addr = calculate_relocated_address(prologue, relocations);
    fmt::print("Found function prologue at {}:{:#012x} Offset: {:#012x} Address: {:#012x}\n",
               binary_filename,
               prologue,
               relocated_prologue_offset,
               relocated_prologue_addr
    );
    prologue = relocated_prologue_offset;
  }
  if (function_prologues.size() < 2)
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Found too few prologues\n");
    return;
  }

  offsets.shn_addr1 = function_prologues[0];
  offsets.shn_addr2 = function_prologues[1];
  offsets.success = true;
}

void scan_windows(scan_result &offsets, const std::filesystem::path &binary_path)
{
  /*
   * Executables on Windows use the PE format. There is an amazing tool we can use
   * to look at PE files called PE-Bear (https://github.com/hasherezade/pe-bear).
   * We are interested in the image base which is in the optional header and the
   * section headers so we can compute the correct relocations for the addresses
   * we find. We could use Win32 APIs for this however
   *   A) They are a pain to use
   *   B) We want to keep platform-dependent code to a minimum
   *   C) We are only interested in a very small amount of data and don't need to
   *      parse the entire PE file.
   * For these reasons we will define some structs and if something breaks we'll
   * print an error and quit.
   *
   * A PE file looks like this:
   *   IMAGE_DOS_HEADER{}
   *   DOS_STUB
   *   RICH_HEADER
   *   IMAGE_NT_HEADERS {
   *     Magic
   *     IMAGE_FILE_HEADER
   *     IMAGE_OPTIONAL_HEADER[32/64]
   *   }
   *   IMAGE_SECTION_HEADER[] (contains relocation info)
   *   <sections>
   */

  const std::string binary_filename = binary_path.filename().string();
  std::ifstream binary_file(binary_path, std::ios::binary);
  if (!binary_file)
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to open {}\n", binary_path.string());
    return;
  }
  pe::IMAGE_DOS_HEADER dos_header;
  binary_file.read(reinterpret_cast<char *>(&dos_header), sizeof(dos_header));
  if (binary_file.gcount() != sizeof(dos_header))
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to read DOS header\n");
    return;
  }

  const sigscanner::signature dos_header_magic = "4D 5A";
  if (!dos_header_magic.check(reinterpret_cast<sigscanner::byte *>(&dos_header.e_magic), sizeof(dos_header.e_magic)))
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Invalid DOS header magic\n");
    return;
  }

  std::uint32_t new_header_offset = dos_header.e_lfanew;
  binary_file.seekg(new_header_offset);
  // Read the magic separately because we don't know the size of the NT header yet
  char nt_header_magic[4];
  binary_file.read(nt_header_magic, sizeof(nt_header_magic));
  if (binary_file.gcount() != sizeof(nt_header_magic))
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to read NT header magic\n");
    return;
  }
  if (
          nt_header_magic[0] != 'P' ||
          nt_header_magic[1] != 'E' ||
          nt_header_magic[2] != '\0' ||
          nt_header_magic[3] != '\0'
          )
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Invalid NT header magic\n");
    return;
  }

  pe::IMAGE_FILE_HEADER file_header;
  binary_file.read(reinterpret_cast<char *>(&file_header), sizeof(file_header));
  if (binary_file.gcount() != sizeof(file_header))
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to read file header\n");
    return;
  }

  std::uint64_t image_base, section_alignment;
  if (file_header.SizeOfOptionalHeader == sizeof(pe::IMAGE_OPTIONAL_HEADER64))
  {
    pe::IMAGE_OPTIONAL_HEADER64 optional_header;
    binary_file.read(reinterpret_cast<char *>(&optional_header), sizeof(optional_header));
    if (binary_file.gcount() != sizeof(optional_header))
    {
      fflush(stdout);
      fmt::print(stderr, "Error: Failed to read optional header\n");
      return;
    }
    if (
            optional_header.Magic != pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
            optional_header.Magic != pe::IMAGE_NT_OPTIONAL_HDR32_MAGIC
            )
    {
      fflush(stdout);
      fmt::print(stderr, "Error: Invalid optional header magic\n");
      return;
    }
    image_base = optional_header.ImageBase;
    section_alignment = optional_header.SectionAlignment;
  } else if (file_header.SizeOfOptionalHeader == sizeof(pe::IMAGE_OPTIONAL_HEADER32))
  {
    pe::IMAGE_OPTIONAL_HEADER32 optional_header;
    binary_file.read(reinterpret_cast<char *>(&optional_header), sizeof(optional_header));
    if (binary_file.gcount() != sizeof(optional_header))
    {
      fflush(stdout);
      fmt::print(stderr, "Error: Failed to read optional header\n");
      return;
    }
    if (
            optional_header.Magic != pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
            optional_header.Magic != pe::IMAGE_NT_OPTIONAL_HDR32_MAGIC
            )
    {
      fflush(stdout);
      fmt::print(stderr, "Error: Invalid optional header magic\n");
      return;
    }
    image_base = optional_header.ImageBase;
    section_alignment = optional_header.SectionAlignment;
  } else
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Invalid optional header size\n");
    return;
  }

  std::vector<pe::IMAGE_SECTION_HEADER> section_headers(file_header.NumberOfSections);
  const auto section_headers_size = static_cast<std::streamsize>(file_header.NumberOfSections * sizeof(pe::IMAGE_SECTION_HEADER));
  binary_file.read(reinterpret_cast<char *>(section_headers.data()), section_headers_size);
  if (binary_file.gcount() != section_headers_size)
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to read section headers\n");
    return;
  }

  std::vector<relocation_entry> relocations;
  /*
   * calculate_relocated_offset uses the first relocation entry to determine the base address that will be used. Since
   * this is subtracted the actual value doesn't matter as long as it is the correct offset from the other relocation
   * entries' addresses. Using VMMap from SysInternals we can see that the first part of memory-mapped data is the DOS
   * header with a size of 0x1000 bytes due to padding. When we get the address of the Spotify.exe module in Frida we
   * get the address of the header, so our offsets need to be relative to the header, not the first relocation entry.
   * This means we need to add the header to the start of the relocation entries even though it isn't one. Alternatively
   * we could subtract the padded size of the header but this is a cleaner solution.
   */
  {
    relocation_entry entry;
    entry.offset_in_file = 0;
    entry.size_in_file = sizeof(pe::IMAGE_DOS_HEADER);
    entry.offset_in_memory = image_base;
    entry.size_in_memory = sizeof(pe::IMAGE_DOS_HEADER);
    relocations.emplace_back(entry);
    std::uint64_t aligned_vaddr_start = entry.offset_in_memory / section_alignment * section_alignment;
    std::uint64_t aligned_vaddr_end = (entry.offset_in_memory + entry.size_in_memory + section_alignment - 1) / section_alignment * section_alignment;
    fmt::print("Found PE relocation {:#012x}-{:#012x} -> {:#012x}-{:#012x} ({:#012x} - {:#012x})\n",
               entry.offset_in_file,
               entry.offset_in_file + entry.size_in_file,
               entry.offset_in_memory,
               entry.offset_in_memory + entry.size_in_memory,
               aligned_vaddr_start,
               aligned_vaddr_end
    );
  }
  for (const auto &section_header: section_headers)
  {
    relocation_entry entry;
    entry.offset_in_file = section_header.PointerToRawData;
    entry.size_in_file = section_header.SizeOfRawData;
    entry.offset_in_memory = image_base + section_header.VirtualAddress;
    entry.size_in_memory = section_header.Misc.VirtualSize;
    std::uint64_t aligned_vaddr_start = entry.offset_in_memory / section_alignment * section_alignment;
    std::uint64_t aligned_vaddr_end = (entry.offset_in_memory + entry.size_in_memory + section_alignment - 1) / section_alignment * section_alignment;
    fmt::print("Found PE relocation {:#012x}-{:#012x} -> {:#012x}-{:#012x} ({:#012x} - {:#012x})\n",
               section_header.PointerToRawData,
               section_header.PointerToRawData + section_header.SizeOfRawData,
               entry.offset_in_memory,
               entry.offset_in_memory + entry.size_in_memory,
               aligned_vaddr_start,
               aligned_vaddr_end
    );
    relocations.emplace_back(entry);
  }

  const sigscanner::signature SHANNON_CONSTANT = "3A C5 96 69";
  const sigscanner::signature SERVER_PUBLIC_KEY = SERVER_PUBLIC_KEY_SIG;
  sigscanner::multi_scanner scanner;
  scanner.add_signature(SHANNON_CONSTANT);
  scanner.add_signature(SERVER_PUBLIC_KEY);
  std::unordered_map<sigscanner::signature, std::vector<sigscanner::offset>> results = scanner.scan_file(binary_path);
  std::vector<sigscanner::offset> &shannon_constant_offsets = results[SHANNON_CONSTANT];
  std::vector<sigscanner::offset> &server_public_key_offsets = results[SERVER_PUBLIC_KEY];
  if (server_public_key_offsets.empty())
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to find server public key\n");
    return;
  }
  if (server_public_key_offsets.size() != 1)
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Expected only one server public key, found {}\n", server_public_key_offsets.size());
    return;
  }
  std::uint64_t server_key_offset = calculate_relocated_offset(server_public_key_offsets[0], relocations);
  std::uint64_t server_key_addr = calculate_relocated_address(server_public_key_offsets[0], relocations);
  fmt::print("Found server public key at {}:{:#012x} Offset: {:#012x} Address: {:#012x}\n",
             binary_filename,
             server_public_key_offsets[0],
             server_key_offset,
             server_key_addr
  );
  offsets.server_public_key = server_key_offset;
  if (shannon_constant_offsets.empty())
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to find shannon constant\n");
    return;
  }
  for (const auto &offset: shannon_constant_offsets)
  {
    std::uint64_t relocated_offset = calculate_relocated_offset(offset, relocations);
    std::uint64_t relocated_addr = calculate_relocated_address(offset, relocations);
    fmt::print("Found shannon constant at {}:{:#012x} Offset: {:#012x} Address: {:#012x}\n",
               binary_filename,
               offset,
               relocated_offset,
               relocated_addr
    );
  }

  /*
   * On Windows I noticed that sometimes shn_diffuse would be found in-between
   * the encryption/decryption functions. This doesn't appear to cause issues
   * though as the function prologue is quite different:
   *
   * shn_encrypt:
   *   48 89 5C 24 08      mov     [rsp+arg_0], rbx
   *   48 89 6C 24 10      mov     [rsp+arg_8], rbp
   *   48 89 74 24 18      mov     [rsp+arg_10], rsi
   *
   * shn_decrypt:
   *   48 89 5C 24 08      mov     [rsp+arg_0], rbx
   *   48 89 6C 24 10      mov     [rsp+arg_8], rbp
   *   48 89 74 24 18      mov     [rsp+arg_10], rsi
   *
   * shn_diffuse:
   *   48 89 4C 24 08      mov     [rsp+arg_0], rcx
   *   53                  push    rbx
   *
   *  The other difference on Windows is shn_finish contains the first instance
   *  of the constant instead of the last. If this changes in the future, we can
   *  always try scanning backwards from each occurrence of the constant however
   *  that is not ideal. shn_finish also has a different prologue to the other
   *  functions so no need to deal with hitting that.
   */

  std::uint64_t first_shannon_constant = shannon_constant_offsets[0];
  std::array<std::uint8_t, 0x4000> shn_bytes{0};
  std::int64_t shn_prologue_scan_base = static_cast<std::int64_t>(first_shannon_constant - shn_bytes.size());
  binary_file.seekg(shn_prologue_scan_base);
  binary_file.read(reinterpret_cast<char *>(shn_bytes.data()), shn_bytes.size());
  if (binary_file.gcount() != shn_bytes.size())
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to read bytes to scan for shannon prologue\n");
    return;
  }
  sigscanner::signature function_prologue = "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18";
  std::vector<sigscanner::offset> function_prologues = function_prologue.reverse_scan(shn_bytes.data(), shn_bytes.size(), shn_prologue_scan_base);
  if (function_prologues.empty())
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to find shn_encrypt/shn_decrypt prologue\n");
    return;
  }
  for (auto &prologue: function_prologues)
  {
    std::uint64_t relocated_prologue_offset = calculate_relocated_offset(prologue, relocations);
    std::uint64_t relocated_prologue_addr = calculate_relocated_address(prologue, relocations);
    fmt::print("Found function prologue at {}:{:#012x} Offset: {:#012x} Address: {:#012x}\n",
               binary_filename,
               prologue,
               relocated_prologue_offset,
               relocated_prologue_addr
    );
    prologue = relocated_prologue_offset;
  }
  if (function_prologues.size() < 2)
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Found too few prologues\n");
    return;
  }

  offsets.shn_addr1 = function_prologues[0];
  offsets.shn_addr2 = function_prologues[1];
  offsets.success = true;
}

void scan_android(scan_result &offsets, const std::filesystem::path &binary_path)
{
  /*
   * Android apps are packaged as APKs. APKs are just zip files with a different
   * extension. When the APK is extracted there is a libs folder which contains
   * JNI libraries (Java Native Interface). These are libraries written in a
   * compiled language such as C, C++ or Rust that can be called from Java. Since
   * phones can have different architectures, Spotify ships multiple builds of the
   * library: x86, x86_64, armeabi-v7a, arm64-v8a. These are different binaries
   * with different instruction sets therefore have different signatures and
   * offsets. We could ask the user to specify however since they are all shared
   * libraries (.so files) we can read the ELF header to find the architecture.
   */

  // These are the values I found on my phone. They should be constant
  static constexpr std::uint16_t JNI_X86 = 3;
  static constexpr std::uint16_t JNI_X86_64 = 62;
  static constexpr std::uint16_t JNI_ARMEABI_V7A = 40;
  static constexpr std::uint16_t JNI_ARM64_V8A = 183;
  static const std::unordered_map<std::uint16_t, std::string_view> JNI_ARCHITECTURES =
          {
                  {JNI_X86,         "x86"},
                  {JNI_X86_64,      "x86_64"},
                  {JNI_ARMEABI_V7A, "armeabi-v7a"},
                  {JNI_ARM64_V8A,   "arm64-v8a"}
          };
  /*
   * Tested all signatures on 8.8.12.545 on all architectures
   */
  static const std::unordered_map<std::uint16_t, sigscanner::signature> JNI_SHANNON_CONSTANTS =
          {
                  /*
                   *
                   */
                  {JNI_X86,         "3A C5 96 69"},
                  {JNI_X86_64,      "3A C5 96 69"},
                  /*
                   * Constant is embedded after function, and is loaded using offset from PC
                   * .text:00C7B410                 LDR             R2, [PC, #0xAC]
                   * ...
                   * .text:00C7B4C4 dword_C7B4C4    DCD 0x6996C53A
                   */
                  {JNI_ARMEABI_V7A, "3A C5 96 69"},
                  /*
                   * Registers can change, so 4B and CB are wildcards
                   * 4B A7 98 52    movz w11, #0xc53a
                   * CB 32 AD 72    movk w11, #0x6996, lsl #16
                   */
                  {JNI_ARM64_V8A,   "?? A7 98 52 ?? 32 AD 72"}
          };
  static const std::unordered_map<std::uint16_t, sigscanner::signature> JNI_SHANNON_PROLOGUES =
          {
                  /*
                   * 55                push ebp
                   * 89 E5             mov  ebp, esp
                   * 53                push ebx
                   * 57                push edi
                   * 56                push esi
                   * 83 E4 F0          and  esp, 0xfffffff0
                   * 83 EC ??          sub  esp, ??
                   * E8 00 00 00 00    call 0x5
                   */
                  {JNI_X86,         "55 89 E5 53 57 56 83 E4 ?? 83 EC ?? E8 00 00 00 00"},
                  /*
                   * 55                push rbp
                   * 48 89 E5          mov  rbp, rsp
                   */
                  {JNI_X86_64,      "55 48 89 E5"},
                  /*
                   * F0 4D 2D E9       push {r4, r5, r6, r7, r8, sl, fp, lr}
                   * 18 B0 8D E2       add  fp, sp, #0x18
                   */
                  {JNI_ARMEABI_V7A, "F0 4D 2D E9 18 B0 8D E2"},
                  /*
                   * F7 0F 1C F8    str x23, [sp, #-0x40]!
                   * F6 57 01 A9    stp x22, x21, [sp, #0x10]
                   * F4 4F 02 A9    stp x20, x19, [sp, #0x20]
                   * FD 7B 03 A9    stp x29, x30, [sp, #0x30]
                   */
                  {JNI_ARM64_V8A,   "F7 0F 1C F8 F6 57 01 A9 F4 4F 02 A9 FD 7B 03 A9"}
          };

  const std::string binary_filename = binary_path.filename().string();
  std::ifstream binary_file(binary_path, std::ios::binary);
  if (!binary_file)
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to open {}\n", binary_path.string());
    return;
  }

  elf::elf_file_details binary_details = parse_elf(binary_file);
  if (binary_details.machine == 0)
  {
    return;
  }

  // Same as Linux. See the comment at the top of the implementation
  std::vector<relocation_entry> relocations = parse_elf_relocations(binary_file, binary_details);

  switch (binary_details.machine)
  {
    case JNI_X86:
    {
      if (binary_details.is_64_bit || !binary_details.is_little_endian)
      {
        fflush(stdout);
        fmt::print(stderr, "Error: Expected x86 to be 32-bit and little endian\n");
        return;
      }
      fmt::print("Detected JNI for x86\n");
      break;
    }
    case JNI_X86_64:
    {
      if (!binary_details.is_64_bit || !binary_details.is_little_endian)
      {
        fflush(stdout);
        fmt::print(stderr, "Error: Expected x86_64 to be 64-bit and little endian\n");
        return;
      }
      fmt::print("Detected JNI for x86_64\n");
      break;
    }
    case JNI_ARMEABI_V7A:
    {
      if (binary_details.is_64_bit || !binary_details.is_little_endian)
      {
        fflush(stdout);
        fmt::print(stderr, "Error: Expected armeabi-v7a to be 32-bit and little endian\n");
        return;
      }
      fmt::print("Detected JNI for armeabi-v7a\n");
      break;
    }
    case JNI_ARM64_V8A:
    {
      if (!binary_details.is_64_bit || !binary_details.is_little_endian)
      {
        fflush(stdout);
        fmt::print(stderr, "Error: Expected arm64-v8a to be 64-bit and little endian\n");
        return;
      }
      fmt::print("Detected JNI for arm64-v8a\n");
      break;
    }
    default:
    {
      fflush(stdout);
      fmt::print(stderr, "Error: Unknown JNI target %u. See 'scan_android' implementation\n", binary_details.machine);
      return;
    }
  }

  const auto &SHANNON_CONSTANT = JNI_SHANNON_CONSTANTS.at(binary_details.machine);
  const sigscanner::signature SERVER_PUBLIC_KEY = SERVER_PUBLIC_KEY_SIG;
  sigscanner::multi_scanner scanner;
  scanner.add_signature(SHANNON_CONSTANT);
  scanner.add_signature(SERVER_PUBLIC_KEY);
  std::unordered_map<sigscanner::signature, std::vector<sigscanner::offset>> results = scanner.scan_file(binary_path);
  std::vector<sigscanner::offset> &shannon_constant_offsets = results[SHANNON_CONSTANT];
  std::vector<sigscanner::offset> &server_public_key_offsets = results[SERVER_PUBLIC_KEY];
  if (server_public_key_offsets.empty())
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to find server public key\n");
    return;
  }
  if (server_public_key_offsets.size() != 1)
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Expected only one server public key, found {}\n", server_public_key_offsets.size());
    return;
  }
  offsets.server_public_key = calculate_relocated_offset(server_public_key_offsets[0], relocations);
  fmt::print("Found server public key at {}:{:#012x} Offset: {:#012x}\n", binary_filename, server_public_key_offsets[0], offsets.server_public_key);
  if (shannon_constant_offsets.empty())
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to find shannon constant\n");
    return;
  }
  for (const auto &offset: shannon_constant_offsets)
  {
    std::uint64_t relocated_offset = calculate_relocated_offset(offset, relocations);
    fmt::print("Found shannon constant at {}:{:#012x} Offset: {:#012x}\n", binary_filename, offset, relocated_offset);
  }

  /*
   * On all architectures, shn_finish contains the last instance of the constant.
   * The encryption/decryption functions are then directly above, so we can have
   * shorter function prologues.
   */

  std::uint64_t last_shannon_constant = shannon_constant_offsets[shannon_constant_offsets.size() - 1];
  std::array<std::uint8_t, 0x2000> shn_bytes{0};
  std::int64_t shn_prologue_scan_base = static_cast<std::int64_t>(last_shannon_constant - shn_bytes.size());
  binary_file.seekg(std::max(std::int64_t{0}, shn_prologue_scan_base));
  binary_file.read(reinterpret_cast<char *>(shn_bytes.data()), shn_bytes.size());
  const sigscanner::signature &function_prologue = JNI_SHANNON_PROLOGUES.at(binary_details.machine);
  std::vector<sigscanner::offset> function_prologues = function_prologue.reverse_scan(shn_bytes.data(), shn_bytes.size(), shn_prologue_scan_base);
  if (function_prologues.empty())
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to find shn_encrypt/shn_decrypt prologue\n");
    return;
  }
  // We hit shn_finish
  if (last_shannon_constant - function_prologues[0] < 0x200)
  {
    std::uint64_t relocated_shn_finish = calculate_relocated_offset(function_prologues[0], relocations);
    fmt::print("Found shn_finish at {}:{:#012x} Offset: {:#012x}\n", binary_filename, function_prologues[0], relocated_shn_finish);
    function_prologues.erase(function_prologues.begin());
  }
  for (auto &prologue: function_prologues)
  {
    std::uint64_t relocated_prologue = calculate_relocated_offset(prologue, relocations);
    fmt::print("Found function prologue at {}:{:#012x} Offset: {:#012x}\n", binary_filename, prologue, relocated_prologue);
    prologue = relocated_prologue;
  }
  if (function_prologues.size() < 2)
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Found too few prologues\n");
    return;
  }

  offsets.shn_addr1 = function_prologues[0];
  offsets.shn_addr2 = function_prologues[1];
  offsets.success = true;
}

std::vector<mach_o::universal_file_entry>::const_iterator
determine_mach_o_universal_file_entry(const std::vector<mach_o::universal_file_entry> &file_entries, const flags::args &args)
{
  if (file_entries.size() == 1)
  {
    return file_entries.begin();
  }

  const std::string_view &architecture = args.get<std::string_view>("arch", "");
  if (architecture.empty())
  {
    return file_entries.end();
  }

  for (const auto &[cpu, cpu_str]: mach_o::CPU_NAMES)
  {
    if (architecture == cpu_str)
    {
      for (auto it = file_entries.begin(); it != file_entries.end(); it++)
      {
        if (it->cpu == cpu.first && it->cpu_subtype == cpu.second)
        {
          return it;
        }
      }
    }
  }

  return file_entries.end();
}

// TODO: Support big endian hosts
void scan_ios(scan_result &offsets, const std::filesystem::path &binary_path, const flags::args &args)
{
  /*
   * Apps on iOS are distributed using .ipa files which are zip archives. When
   * downloaded from the App Store APIs directly they are encrypted and must be
   * decrypted by a device running iOS or macOS. There are various tools that
   * allow this, mostly using mremap_encrypted. Alternatively the decrypted file
   * can be copied from an iOS device using frida-ios-dump or similar. an encrypted
   * IPA will decrypt properly but the Spotify binary will be encrypted and useless
   * to us.
   *
   * After unzipping the .ipa file there will be a "Payload" folder which contains
   * a "Spotify.app" folder which itself contains the "Spotify" binary. This is a
   * Mach-O executable which contains all the stuff we're interested in. Mach-O
   * files are a container for executables and other compiled code and have the
   * same purpose as Unix's ELF files. They support multiple architectures, which
   * means one file may contain code for armv7 and armv8, each with different
   * offsets. To account for this we require an extra command line flag to specify
   * which architecture should be used.
   *
   * Once we have the image to parse, we read the header magic to determine the
   * bitness and endianness. We then read the rest of the file header to get the
   * CPU type and the number of load commands. Load commands are used to describe
   * segments in the file which we need because some of the segments will be loaded
   * into virtual memory. We do not need to parse the segments themselves as the
   * load commands contain the virtual memory map of the file from which we can
   * determine the relocations.
   */

  const std::string binary_filename = binary_path.filename().string();
  std::unique_ptr<file_backed_block> binary_file = std::make_unique<file_backed_block>(binary_path);
  if (binary_file->error())
  {
    fflush(stdout);
    fmt::print(stderr, "Error: {}\n", binary_file->error_str());
    return;
  }

  std::string_view architecture;
  mach_o::header_magic header_magic;
  binary_file->read(reinterpret_cast<char *>(&header_magic), sizeof(header_magic));
  binary_file->seek(0);

  /*
   * Take care of multi-architecture files by putting the read cursor at the
   * start of the image for the architecture we want to scan.
   */
  if (std::memcmp(header_magic, mach_o::HEADER_MAGIC_UNIVERSAL, sizeof(header_magic)) == 0)
  {
    fmt::print("Detected Mach-O file as multi-architecture\n");
    mach_o::universal_header file_header;
    binary_file->read(reinterpret_cast<char *>(&file_header), sizeof(file_header));
    file_header.binaries_count = bswap_32(file_header.binaries_count);
    if (file_header.binaries_count == 0)
    {
      fflush(stdout);
      fmt::print(stderr, "Error: Mach-O file has no architectures\n");
      return;
    }
    std::vector<mach_o::universal_file_entry> file_entries(file_header.binaries_count);
    std::streamsize file_entries_size = (long) sizeof(mach_o::universal_file_entry) * file_header.binaries_count;
    binary_file->read(reinterpret_cast<char *>(file_entries.data()), file_entries_size);

    for (auto &file_entry: file_entries)
    {
      file_entry.cpu = bswap_32(file_entry.cpu);
      file_entry.cpu_subtype = bswap_32(file_entry.cpu_subtype);
      file_entry.offset = bswap_32(file_entry.offset);
      file_entry.size = bswap_32(file_entry.size);
      file_entry.align_pow = bswap_32(file_entry.align_pow);
      fmt::print("Found Mach-O file entry for {} at {:#012x} with length {}\n",
                 mach_o::get_cpu_string(file_entry.cpu, file_entry.cpu_subtype),
                 file_entry.offset, file_entry.size
      );
    }

    const auto &file_entry_it = determine_mach_o_universal_file_entry(file_entries, args);
    if (file_entry_it == file_entries.end())
    {
      fflush(stdout);
      fmt::print(stderr, "Error: Couldn't determine which Mach-O entry to use. "
                         "See entries above for valid --arch values\n");
      std::exit(1);
    }
    binary_file = std::make_unique<file_backed_block>(binary_path, file_entry_it->offset, file_entry_it->size);
    if (binary_file->error())
    {
      fflush(stdout);
      fmt::print(stderr, "Error: {}", binary_file->error_str());
      return;
    }
    binary_file->read(reinterpret_cast<char *>(&header_magic), sizeof(header_magic));
    binary_file->seek(0);
    // Fall through into the standard parsing code
  }

  std::vector<relocation_entry> relocations;
  if (std::memcmp(header_magic, mach_o::HEADER_MAGIC_32_LE, sizeof(header_magic)) == 0)
  {
    fmt::print("Detected Mach-O image as 32-bit Little Endian\n");
    fflush(stdout);
    fmt::print(stderr, "Error: No implementation for 32-bit Little Endian Mach-O\n"
                       "Feel free to open an issue or pull request on GitHub\n");
    return;
  } else if (std::memcmp(header_magic, mach_o::HEADER_MAGIC_32_BE, sizeof(header_magic)) == 0)
  {
    fmt::print("Detected Mach-O image as 32-bit Big Endian\n");
    mach_o::file_header32 file_header;
    binary_file->read(reinterpret_cast<char *>(&file_header), sizeof(file_header));
    fmt::print("Found Mach-O file header for {} with {} load commands\n",
               mach_o::get_cpu_string(file_header.cpu, file_header.cpu_subtype),
               file_header.load_commands_count
    );
    const auto cpu_name = mach_o::CPU_NAMES.find({file_header.cpu, file_header.cpu_subtype});
    if (cpu_name == mach_o::CPU_NAMES.end())
    {
      fflush(stdout);
      fmt::print(stderr, "Error: Unsupported CPU\n");
      return;
    }
    architecture = cpu_name->second;
    for (std::size_t i = 0; i < file_header.load_commands_count; i++)
    {
      mach_o::load_command load_command;
      binary_file->read(reinterpret_cast<char *>(&load_command), sizeof(load_command));
      std::uint64_t next_load_command_offset = binary_file->pos() + load_command.size - sizeof(load_command);
      if (load_command.type == mach_o::LC_SEGMENT)
      {
        mach_o::segment_command32 segment_command;
        binary_file->read(reinterpret_cast<char *>(&segment_command), sizeof(segment_command));
        if (segment_command.size == 0)
        {
          continue;
        }
        relocation_entry entry;
        entry.offset_in_file = segment_command.offset;
        entry.size_in_file = segment_command.size;
        entry.offset_in_memory = segment_command.v_addr;
        entry.size_in_memory = segment_command.v_size;
        fmt::print("Found Mach-O relocation {:#012x}-{:#012x} -> {:#012x}-{:#012x} [{:^16}] with {} sections\n",
                   entry.offset_in_file,
                   entry.offset_in_file + entry.size_in_file,
                   entry.offset_in_memory,
                   entry.offset_in_memory + entry.size_in_memory,
                   segment_command.name,
                   segment_command.sections_count
        );
        relocations.emplace_back(entry);
      }
      // Skip remaining bytes of this load command structure
      binary_file->seek(next_load_command_offset);
    }
  } else if (std::memcmp(header_magic, mach_o::HEADER_MAGIC_64_LE, sizeof(header_magic)) == 0)
  {
    fmt::print("Detected Mach-O image as 64-bit Little Endian\n");
    fflush(stdout);
    fmt::print(stderr, "Error: No implementation for 64-bit Little Endian Mach-O\n"
                       "Feel free to open an issue or pull request on GitHub\n");
    return;
  } else if (std::memcmp(header_magic, mach_o::HEADER_MAGIC_64_BE, sizeof(header_magic)) == 0)
  {
    fmt::print("Detected Mach-O image as 64-bit Big Endian\n");
    mach_o::file_header64 file_header;
    binary_file->read(reinterpret_cast<char *>(&file_header), sizeof(file_header));
    fmt::print("Found Mach-O file header for {} with {} load commands\n",
               mach_o::get_cpu_string(file_header.cpu, file_header.cpu_subtype),
               file_header.load_commands_count
    );
    const auto cpu_name = mach_o::CPU_NAMES.find({file_header.cpu, file_header.cpu_subtype});
    if (cpu_name == mach_o::CPU_NAMES.end())
    {
      fflush(stdout);
      fmt::print(stderr, "Error: Unsupported CPU\n");
      return;
    }
    architecture = cpu_name->second;
    for (std::size_t i = 0; i < file_header.load_commands_count; i++)
    {
      mach_o::load_command load_command;
      binary_file->read(reinterpret_cast<char *>(&load_command), sizeof(load_command));
      std::uint64_t next_load_command_offset = binary_file->pos() + load_command.size - sizeof(load_command);
      if (load_command.type == mach_o::LC_SEGMENT_64)
      {
        mach_o::segment_command64 segment_command;
        binary_file->read(reinterpret_cast<char *>(&segment_command), sizeof(segment_command));
        if (segment_command.size == 0)
        {
          continue;
        }
        relocation_entry entry;
        entry.offset_in_file = segment_command.offset;
        entry.size_in_file = segment_command.size;
        entry.offset_in_memory = segment_command.v_addr;
        entry.size_in_memory = segment_command.v_size;
        fmt::print("Found Mach-O relocation {:#012x}-{:#012x} -> {:#012x}-{:#012x} [{:^16}] with {} sections\n",
                   entry.offset_in_file,
                   entry.offset_in_file + entry.size_in_file,
                   entry.offset_in_memory,
                   entry.offset_in_memory + entry.size_in_memory,
                   segment_command.name,
                   segment_command.sections_count
        );
        relocations.emplace_back(entry);
      }
      // Skip remaining bytes of this load command structure
      binary_file->seek(next_load_command_offset);
    }
  } else
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Invalid Mach-O header magic\n");
    return;
  }

  static const std::unordered_map<std::string_view, sigscanner::signature> SHANNON_CONSTANTS =
          {
                  /*
                   * Constant is embedded after function, and is loaded using offset from PC
                   * 000FE750 C4 10 9F E5    ldr r1, [pc, #0xc4]
                   * 000FE754 82 01 20 E0    eor r0, r0, r2, lsl #3
                   * ...
                   * 000FE81C 3A C5 96 69    0x6996C53A
                   */
                  {mach_o::CPU_ARMV6, "3A C5 96 69"},
                  /*
                   * 4C F2 3A 52    movw r2, #0xc53a
                   * 68 6B          ldr  r0, [r5, #0x34]
                   * C6 F6 96 12    movt r2, #0x6996
                   *
                   * The second instruction appears to stay constant across versions
                   */
                  {mach_o::CPU_ARMV7, "4C F2 3A 51 C6 F6 96 11"},
                  /*
                   * Registers can change, so 4B and CB are wildcards
                   * 4A A7 98 52    movz w10, #0xc53a
                   * CA 32 AD 72    movk w10, #0x6996, lsl #16
                   */
                  {mach_o::CPU_ARM64, "?? A7 98 52 ?? 32 AD 72"},
          };
  static const std::unordered_map<std::string_view, sigscanner::signature> SHANNON_PROLOGUES =
          {
                  /*
                   * F0 40 2D E9    push {r4, r5, r6, r7, lr}
                   * 0C 70 8D E2    add  r7, sp, #0xc
                   * 00 0D 2D E9    push {r8, sl, fp}
                   * 08 D0 4D E2    sub  sp, sp, #8
                   * 00 40 A0 E1    mov  r4, r0
                   */
                  {mach_o::CPU_ARMV6, "F0 40 2D E9 0C 70 8D E2 00 0D 2D E9 08 D0 4D E2 00 40 A0 E1"},
                  /*
                   * F0 B5    push {r4, r5, r6, r7, lr}
                   * 03 AF    add  r7, sp, #0xc
                   */
                  {mach_o::CPU_ARMV7, "F0 B5 03 AF 2D E9 00 0D 82 B0"},
                  /*
                   * FA 67 BB A9    stp x26, x25, [sp, #-0x50]!
                   * F8 5F 01 A9    stp x24, x23, [sp, #0x10]
                   * F6 57 02 A9    stp x22, x21, [sp, #0x20]
                   * F4 4F 03 A9    stp x20, x19, [sp, #0x30]
                   */
                  {mach_o::CPU_ARM64, "FA 67 BB A9 F8 5F 01 A9 F6 57 02 A9 F4 4F 03 A9"},
          };

  const auto &SHANNON_CONSTANT = SHANNON_CONSTANTS.at(architecture);
  const sigscanner::signature SERVER_PUBLIC_KEY = SERVER_PUBLIC_KEY_SIG;
  sigscanner::multi_scanner scanner;
  scanner.add_signature(SHANNON_CONSTANT);
  scanner.add_signature(SERVER_PUBLIC_KEY);
  sigscanner::scan_options scan_options;
  scan_options.set_thread_count(2);
  std::unordered_map<sigscanner::signature, std::vector<sigscanner::offset>> results = scanner.scan(
          reinterpret_cast<const sigscanner::byte *>(binary_file->base_ptr()),
          binary_file->size(),
          scan_options
  );
  std::vector<sigscanner::offset> &shannon_constant_offsets = results[SHANNON_CONSTANT];
  std::vector<sigscanner::offset> &server_public_key_offsets = results[SERVER_PUBLIC_KEY];
  if (server_public_key_offsets.empty())
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to find server public key\n");
    return;
  }
  if (server_public_key_offsets.size() != 1)
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Expected only one server public key, found {}\n", server_public_key_offsets.size());
    return;
  }
  offsets.server_public_key = calculate_relocated_offset(server_public_key_offsets[0], relocations);
  fmt::print("Found server public key at {}:{:#012x} Offset: {:#012x}\n", binary_filename, server_public_key_offsets[0], offsets.server_public_key);
  if (shannon_constant_offsets.empty())
  {
    fflush(stdout);
    fmt::print(stderr, "Error: Failed to find shannon constant\n");
    return;
  }
  for (const auto &offset: shannon_constant_offsets)
  {
    std::uint64_t relocated_offset = calculate_relocated_offset(offset, relocations);
    fmt::print("Found shannon constant at {}:{:#012x} Offset: {:#012x}\n", binary_filename, offset, relocated_offset);
  }

  /*
   * shn_finish seems to contain the last instance of the constant however on
   * arm64 it is the second instance of six. The encryption/decryption functions
   * are normally above shn_finish however on arm64 one was above and one was
   * below with a few smaller functions in-between. The only reliable way to
   * always find the functions is to check before and after all occurrences of
   * the constant which could be up to 12 scans, so instead of reading the file
   * up to 12 times, we will load the whole thing into memory and scan it there.
   * Memory mapping the file saves us potentially 100MB.
   *
   * This would work well however on multi-architecture files we could find
   * signature matches in the wrong architecture. To combat this we will only
   * read the data for the architecture we are interested in by changing the
   * binary chunk to only be that image. The offsets used for segments in an
   * image from a multi-architecture binary are relative to that image, for
   * example if the first image is at 0x1000, the first segment may have a
   * load_command with file offset 0 which is actually 0x1000 + 0. This means
   * we can safely adjust our binary chunk to only contain the image we want to
   * scan without having to deal with adding a delta to every offset.
   */

  const auto push_offset = [&offsets](sigscanner::offset
                                      offset) -> bool {
      if (offsets.shn_addr1 > 0)
      {
        offsets.shn_addr2 = offset;
        offsets.success = true;
        return true;
      } else
      {
        offsets.shn_addr1 = offset;
        return false;
      }
  };

  const auto &SHANNON_PROLOGUE = SHANNON_PROLOGUES.at(architecture);
  const std::size_t SCAN_SIZE = 0x2000; // Functions themselves can be 0x1100 (4KB+)
  /*
   * Scan backwards, on average the functions are closer to the last instances of the constant
   */
  for (auto shannon_constant_it = shannon_constant_offsets.rbegin(); shannon_constant_it != shannon_constant_offsets.rend(); shannon_constant_it++)
  {
    sigscanner::scanner prologue_scanner(SHANNON_PROLOGUE);
    std::uint64_t scan_start = std::max(std::int64_t{0}, static_cast<std::int64_t>(*shannon_constant_it - SCAN_SIZE));
    std::size_t scan_size = std::min(static_cast<std::size_t>(binary_file->size() - scan_start), SCAN_SIZE);
    binary_file->seek(scan_start);
    std::vector<sigscanner::offset> prologue_offsets = prologue_scanner.reverse_scan(reinterpret_cast<sigscanner::byte *>(binary_file->pos_ptr()), scan_size);
    if (!prologue_offsets.empty())
    {
      std::uint64_t first_offset = prologue_offsets[0] + binary_file->pos();
      std::uint64_t first_relocated = calculate_relocated_offset(first_offset, relocations);
      fmt::print("Found function prologue at {}:{:#012x} Offset: {:#012x}\n", binary_filename, first_offset, first_relocated);
      if (push_offset(first_relocated))
      {
        return;
      }
      scan_start = std::max(std::int64_t{0}, static_cast<std::int64_t>(first_offset - SCAN_SIZE));
      scan_size = std::min(static_cast<std::size_t>(binary_file->size() - scan_start), SCAN_SIZE);
      binary_file->seek(scan_start);
      prologue_offsets = prologue_scanner.reverse_scan(reinterpret_cast<sigscanner::byte *>(binary_file->pos_ptr()), scan_size);
      if (!prologue_offsets.empty())
      {
        std::uint64_t second_offset = prologue_offsets[0] + binary_file->pos();
        std::uint64_t second_relocated = calculate_relocated_offset(second_offset, relocations);
        fmt::print("Found function prologue at {}:{:#012x} Offset: {:#012x}\n", binary_filename, second_offset, second_relocated);
        push_offset(second_relocated);
        return;
      }
    }

    scan_start = *shannon_constant_it;
    scan_size = std::min(static_cast<std::size_t>(binary_file->size() - scan_start), SCAN_SIZE);
    binary_file->seek(scan_start);
    prologue_offsets = prologue_scanner.scan(reinterpret_cast<sigscanner::byte *>(binary_file->pos_ptr()), scan_size);
    if (!prologue_offsets.empty())
    {
      std::uint64_t file_offset = prologue_offsets[0] + binary_file->pos();
      std::uint64_t relocated_offset = calculate_relocated_offset(file_offset, relocations);
      fmt::print("Found function prologue at {}:{:#012x} Offset: {:#012x}\n", binary_filename, file_offset, relocated_offset);
      if (push_offset(relocated_offset))
      {
        return;
      }
      scan_start = std::max(std::int64_t{0}, static_cast<std::int64_t>(file_offset - SCAN_SIZE));
      scan_size = std::min(static_cast<std::size_t>(binary_file->size() - scan_start), SCAN_SIZE);
      binary_file->seek(scan_start);
      prologue_offsets = prologue_scanner.scan(reinterpret_cast<sigscanner::byte *>(binary_file->pos_ptr()), scan_size);
      if (!prologue_offsets.empty())
      {
        std::uint64_t second_offset = prologue_offsets[0] + binary_file->pos();
        std::uint64_t second_relocated = calculate_relocated_offset(second_offset, relocations);
        fmt::print("Found function prologue at {}:{:#012x} Offset: {:#012x}\n", binary_filename, second_offset, second_relocated);
        push_offset(second_relocated);
        return;
      }
    }
  }
}

scan_result scan_binary(platform target, const std::filesystem::path &binary_path, const flags::args &args)
{
  scan_result offsets;

  /*
   * The server public key is the same for all platforms so we can just hardcode it.
   * We can also directly scan for it because it should only occur once.
   *
   * Finding shn_encrypt and shn_decrypt is a little more difficult. Since we are
   * looking for functions, we can't just scan for a constant value as when a new
   * version is released, the registers used and order of instructions may change,
   * breaking our scanning. We could use wildcards to combat this, but then we
   * would end up with very long signatures that would likely break due to being
   * too long. Instead, we can scan for a constant that is used in a few of the
   * shn_ functions (shn_initstate, shn_nonce and shn_finish). We can then use
   * function prologues to find the start of nearby functions and since the order
   * of the functions in memory is unlikely to change, this should give us a
   * reliable way of finding them. This idea was originally created by plietar in
   * the origin spotify-analyze and since it works really well I'm going to use it
   * here.
   *
   * For the most part, the functions will look like this in memory:
   *   shn_encrypt
   *   shn_decrypt
   *   shn_finish
   *  "For the most part" because on older versions of the Android app, shn_encrypt
   *  came after shn_decrypt. To combat this we can allocate a shn_ctx then call
   *  each of the functions and check what happened to the shn_ctx. Since we know
   *  what each function does to the shn_ctx, we can determine which function is
   *  which.
   *
   *  This gives birth to the following method:
   *  1. Scan for shannon constant (0x6996c53a)
   *  2. Take the last occurrence which should be in shn_finish. Scan backwards
   *     for function prologues.
   *  3. Check if the first prologue we find is shn_finish itself. If so, skip it
   *  4. Take the next two addresses. These should be shn_encrypt and shn_decrypt.
   *  5. Allocate a shn_ctx then call addr1. Check what happened to the shn_ctx.
   *  6. Allocate a shn_ctx then call addr2. Check what happened to the shn_ctx.
   *  7. Now we have done one of 3 things. We have either found shn_encrypt and
   *     shn_decrypt, crashed the app, or we got lucky with the assembly. In either
   *     of the negative cases, we can open our disassembler of choice and start
   *     looking for the functions manually using the addresses we found in step 1.
   *     Then we can update our signatures or add additional logic.
   *
   *  This works perfectly to find the functions, however after hooking them we may
   *  sometimes run into another problem. These functions are called from more than
   *  one place, and we are only interested in SPIRC data. To combat this we can
   *  find the places we expect them to be called from and check if the return address
   *  is one of them. To find the places they can be called from, we need to find
   *  cross-references (commonly called XREFS) then analyze the calling function.
   *  The calling function for shn_encrypt should create the header then copy the
   *  data then call shn_encrypt with the whole buffer:
   *   *(_BYTE *)v11[0] = packetType;
   *   *((_BYTE *)v11[0] + 1) = BYTE1(packetLength);
   *   *((_BYTE *)v11[0] + 2) = packetLength;
   *   memcpy((char *)v11[0] + 3, packet, packetLength);
   *   shn_encrypt((void *)(a1 + 952), v11[0], packetLength + 3);
   *  The calling function for shn_decrypt should first call it with nbytes=3 to
   *  decrypt the header then again to decrypt the body:
   *    shn_decrypt(a1 + 744, v47, 3LL);
   *    *(_BYTE *)(a1 + 56) = v47[0];
   *    v10 = v47[1];
   *    v11 = v47[2];
   *    *(_QWORD *)(a1 + 64) = v11 & 0xFFFFFFFFFFFF00FFLL | ((unsigned __int64)v10 << 8);
   *    shn_decrypt(a1 + 744, v15, *(unsigned int *)(a1 + 64));
   *
   *  Notes:
   *  The offset into the binary file may not be the same as the offset once that file
   *  is mapped into memory. This is because due to dynamic linking, different parts
   *  (sections) of the binary file can be loaded at different offsets. To combat
   *  this we can read the binary file and apply the relocations ourselves.
   */

  switch (target)
  {
    case platform::LINUX:
    {
      scan_linux(offsets, binary_path);
      return offsets;
    }
    case platform::WINDOWS:
    {
      scan_windows(offsets, binary_path);
      return offsets;
    }
    case platform::ANDROID:
    {
      scan_android(offsets, binary_path);
      return offsets;
    }
    case platform::IOS:
    {
      scan_ios(offsets, binary_path, args);
      return offsets;
    }
    default:
    {
      fflush(stdout);
      fmt::print(stderr, "Error: Scanning not implemented for this target\n");
      return offsets;
    }
  }
}
