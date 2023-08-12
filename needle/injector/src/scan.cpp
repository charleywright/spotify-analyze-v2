#include "scan.hpp"
#include <fstream>
#include "sigscanner/sigscanner.hpp"
#include "elf.hpp"
#include "pe.hpp"
#include <memory>
#include <array>
#include "fmt/core.h"
#include <cstring>
#include <variant>

const char *SERVER_PUBLIC_KEY_SIG = "ac e0 46 0b ff c2 30 af f4 6b fe c3 bf bf 86 3d a1 91 c6 cc 33 6c 93 a1 4f b3 b0 16 12 ac ac 6a f1 80 e7 f6 14 d9 42 9d be 2e 34 66 43 e3 62 d2 32 7a 1a 0d 92 3b ae dd 14 02 b1 81 55 05 61 04 d5 2c 96 a4 4c 1e cc 02 4a d4 b2 0c 00 1f 17 ed c2 2f c4 35 21 c8 f0 cb ae d2 ad d7 2b 0f 9d b3 c5 32 1a 2a fe 59 f3 5a 0d ac 68 f1 fa 62 1e fb 2c 8d 0c b7 39 2d 92 47 e3 d7 35 1a 6d bd 24 c2 ae 25 5b 88 ff ab 73 29 8a 0b cc cd 0c 58 67 31 89 e8 bd 34 80 78 4a 5f c9 6b 89 9d 95 6b fc 86 d7 4f 33 a6 78 17 96 c9 c3 2d 0d 32 a5 ab cd 05 27 e2 f7 10 a3 96 13 c4 2f 99 c0 27 bf ed 04 9c 3c 27 58 04 b6 b2 19 f9 c1 2f 02 e9 48 63 ec a1 b6 42 a0 9d 48 25 f8 b3 9d d0 e8 6a f9 48 4d a1 c2 ba 86 30 42 ea 9d b3 08 6c 19 0e 48 b3 9d 66 eb 00 06 a2 5a ee a1 1b 13 87 3c d7 19 e6 55 bd";

struct relocation_entry
{
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    std::int64_t offset = 0;
    std::string name;
};

std::uint64_t apply_relocations(std::uint64_t address, const std::vector<relocation_entry> &relocations)
{
  for (const relocation_entry &entry: relocations)
  {
    if (address >= entry.start && address < entry.end)
    {
      return address + entry.offset;
    }
  }
  return address;
}

elf::elf_file_details parse_elf(std::ifstream &binary_file)
{
  elf::elf_file_details binary_details;

  elf::Elf_Ident e_ident{0};
  binary_file.read(reinterpret_cast<char *>(&e_ident), sizeof(e_ident));
  if (binary_file.gcount() != sizeof(e_ident))
  {
    fmt::print(stderr, "Error: Failed to read ELF identifier\n");
    return binary_details;
  }

  const sigscanner::signature elf_header_magic = "7F 45 4C 46";
  if (!elf_header_magic.check(e_ident.ei_mag, sizeof(e_ident.ei_mag)))
  {
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
   * The difference is 0x201000, this is due to relocations. Since the constant is used in assembly it will be in the .text
   * section. To find the offset this section is loaded at we need to parse the Elf header and section table.
   *
   * If we run 'readelf --sections --wide /opt/spotify/spotify' we find the following entry:
   *   [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
   *   [15] .text             PROGBITS        0000000000adbb80 8dab80 13339e5 00  AX  0   0 32
   *
   * If we take the address of the .text section and subtract the offset in the file we get 0x201000.
   *
   * To find and apply these offsets ourselves we need to parse the section header table. To do that we need to parse the
   * ELF header to find the offset of the section header table however we are already doing so to find the machine type.
   * The ELF format is very well documented and there are some resources linked at the top of elf.hpp
  */

  std::vector<relocation_entry> relocations;

  if (binary_details.is_64_bit)
  {
    const auto &header = std::get<elf::Elf64_Ehdr>(binary_details.header);
    elf::Elf64_Half section_header_table_entry_size = header.e_shentsize;
    if (section_header_table_entry_size != sizeof(elf::Elf64_Shdr))
    {
      fmt::print(stderr, "Error: Invalid section header table entry size\n");
      return relocations;
    }

    std::vector<elf::Elf64_Shdr> section_headers(header.e_shnum);
    elf::Elf64_Half section_header_table_size = header.e_shnum * section_header_table_entry_size;
    binary_file.seekg(static_cast<std::streamoff>(header.e_shoff));
    binary_file.read(reinterpret_cast<char *>(section_headers.data()), static_cast<std::streamsize>(section_header_table_size));
    if (binary_file.gcount() != section_header_table_size)
    {
      fmt::print(stderr, "Error: Failed to read section headers\n");
      return relocations;
    }

    elf::Elf64_Half section_header_string_table_index = header.e_shstrndx;
    if (section_header_string_table_index == elf::Elf64_Ehdr::SHN_UNDEF)
    {
      fmt::print(stderr, "Error: Section header string table index is undefined\n");
      return relocations;
    }
    if (section_header_string_table_index == elf::Elf64_Ehdr::SHN_XINDEX)
    {
      section_header_string_table_index = section_headers[0].sh_link;
    }

    const elf::Elf64_Shdr &section_header_string_table_entry = section_headers[section_header_string_table_index];
    std::unique_ptr<void, void (*)(void *)> section_header_string_table(std::malloc(section_header_string_table_entry.sh_size), std::free);
    if (!section_header_string_table)
    {
      fmt::print(stderr, "Error: Failed to allocate memory for section header string table\n");
      return relocations;
    }
    binary_file.seekg(static_cast<std::streamoff>(section_header_string_table_entry.sh_offset));
    binary_file.read(reinterpret_cast<char *>(section_header_string_table.get()), static_cast<std::streamsize>(section_header_string_table_entry.sh_size));
    if (binary_file.gcount() != section_header_string_table_entry.sh_size)
    {
      fmt::print(stderr, "Error: Failed to read section header string table\n");
      return relocations;
    }
    const auto resolve_str = [&section_header_string_table](elf::Elf64_Word offset) {
        return reinterpret_cast<const char *>(section_header_string_table.get()) + offset;
    };

    for (const auto &section_header: section_headers)
    {
      if (section_header.sh_type == elf::Elf64_Shdr::SHT_PROGBITS)
      {
        relocation_entry entry;
        entry.start = section_header.sh_offset;
        entry.end = section_header.sh_offset + section_header.sh_size;
        entry.offset = static_cast<std::int64_t>(section_header.sh_addr) - static_cast<std::int64_t>(section_header.sh_offset);
        entry.name = resolve_str(section_header.sh_name);
        relocations.emplace_back(std::move(entry));
      }
    }
  } else
  {
    const auto &header = std::get<elf::Elf32_Ehdr>(binary_details.header);
    elf::Elf32_Half section_header_table_entry_size = header.e_shentsize;
    if (section_header_table_entry_size != sizeof(elf::Elf32_Shdr))
    {
      fmt::print(stderr, "Error: Invalid section header table entry size\n");
      return relocations;
    }

    std::vector<elf::Elf32_Shdr> section_headers(header.e_shnum);
    elf::Elf32_Half section_header_table_size = header.e_shnum * section_header_table_entry_size;
    binary_file.seekg(static_cast<std::streamoff>(header.e_shoff));
    binary_file.read(reinterpret_cast<char *>(section_headers.data()), static_cast<std::streamsize>(section_header_table_size));
    if (binary_file.gcount() != section_header_table_size)
    {
      fmt::print(stderr, "Error: Failed to read section headers\n");
      return relocations;
    }

    elf::Elf32_Half section_header_string_table_index = header.e_shstrndx;
    if (section_header_string_table_index == elf::Elf32_Ehdr::SHN_UNDEF)
    {
      fmt::print(stderr, "Error: Section header string table index is undefined\n");
      return relocations;
    }
    if (section_header_string_table_index == elf::Elf32_Ehdr::SHN_XINDEX)
    {
      section_header_string_table_index = section_headers[0].sh_link;
    }

    const elf::Elf32_Shdr &section_header_string_table_entry = section_headers[section_header_string_table_index];
    std::unique_ptr<void, void (*)(void *)> section_header_string_table(std::malloc(section_header_string_table_entry.sh_size), std::free);
    if (!section_header_string_table)
    {
      fmt::print(stderr, "Error: Failed to allocate memory for section header string table\n");
      return relocations;
    }
    binary_file.seekg(static_cast<std::streamoff>(section_header_string_table_entry.sh_offset));
    binary_file.read(reinterpret_cast<char *>(section_header_string_table.get()), static_cast<std::streamsize>(section_header_string_table_entry.sh_size));
    if (binary_file.gcount() != section_header_string_table_entry.sh_size)
    {
      fmt::print(stderr, "Error: Failed to read section header string table\n");
      return relocations;
    }
    const auto resolve_str = [&section_header_string_table](elf::Elf32_Word offset) {
        return reinterpret_cast<const char *>(section_header_string_table.get()) + offset;
    };

    for (const auto &section_header: section_headers)
    {
      if (section_header.sh_type == elf::Elf32_Shdr::SHT_PROGBITS)
      {
        relocation_entry entry;
        entry.start = section_header.sh_offset;
        entry.end = section_header.sh_offset + section_header.sh_size;
        entry.offset = section_header.sh_addr - section_header.sh_offset;
        entry.name = resolve_str(section_header.sh_name);
        relocations.emplace_back(std::move(entry));
      }
    }
  }
  return relocations;
}

void scan_linux(scan_result &offsets, const std::filesystem::path &binary_path)
{
  /*
   * On Linux the spotify binary is of course an ELF file. We can use this to determine
   * the architecture of the binary and then use the correct signatures. We could read
   * the whole ELF header however we only need the e_ident array which is the first 16
   * bytes.
   */
  const std::string binary_filename = binary_path.filename().string();
  std::ifstream binary_file(binary_path, std::ios::binary);
  if (!binary_file)
  {
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
    fmt::print(stderr, "Error: Failed to find server public key\n");
    return;
  }
  if (server_public_key_offsets.size() != 1)
  {
    fmt::print(stderr, "Error: Expected only one server public key, found {}\n", server_public_key_offsets.size());
    return;
  }
  offsets.server_public_key = apply_relocations(server_public_key_offsets[0], relocations);
  fmt::print("Found server public key at {}:{:#012x} ({:#012x})\n", binary_filename, server_public_key_offsets[0], offsets.server_public_key);
  if (shannon_constant_offsets.empty())
  {
    fmt::print(stderr, "Error: Failed to find shannon constant\n");
    return;
  }
  for (const auto &offset: shannon_constant_offsets)
  {
    sigscanner::offset relocated_offset = apply_relocations(offset, relocations);
    fmt::print("Found shannon constant at {}:{:#012x} ({:#012x})\n", binary_filename, offset, relocated_offset);
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
    fmt::print(stderr, "Error: Failed to find shn_encrypt/shn_decrypt prologue\n");
    return;
  }
  // We hit shn_finish
  if (last_shannon_constant - function_prologues[0] < 0x200)
  {
    sigscanner::offset relocated_shn_finish = apply_relocations(function_prologues[0], relocations);
    fmt::print("Found shn_finish at {}:{:#012x} ({:#012x})\n", binary_filename, function_prologues[0], relocated_shn_finish);
    function_prologues.erase(function_prologues.begin());
  }
  for (auto &prologue: function_prologues)
  {
    sigscanner::offset relocated_prologue = apply_relocations(prologue, relocations);
    fmt::print("Found function prologue at {}:{:#012x} ({:#012x})\n", binary_filename, prologue, relocated_prologue);
    prologue = relocated_prologue;
  }
  if (function_prologues.size() < 2)
  {
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
    fmt::print(stderr, "Error: Failed to open {}\n", binary_path.string());
    return;
  }
  pe::IMAGE_DOS_HEADER dos_header{0};
  binary_file.read(reinterpret_cast<char *>(&dos_header), sizeof(dos_header));
  if (binary_file.gcount() != sizeof(dos_header))
  {
    fmt::print(stderr, "Error: Failed to read DOS header\n");
    return;
  }

  const sigscanner::signature dos_header_magic = "4D 5A";
  if (!dos_header_magic.check(reinterpret_cast<sigscanner::byte *>(&dos_header.e_magic), sizeof(dos_header.e_magic)))
  {
    fmt::print(stderr, "Error: Invalid DOS header magic\n");
    return;
  }

  std::uint32_t new_header_offset = dos_header.e_lfanew;
  binary_file.seekg(new_header_offset);
  // Read the magic separately because we don't know the size of the NT header yet
  sigscanner::byte nt_header_magic[4];
  binary_file.read(reinterpret_cast<char *>(nt_header_magic), sizeof(nt_header_magic));
  if (binary_file.gcount() != sizeof(nt_header_magic))
  {
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
    fmt::print(stderr, "Error: Invalid NT header magic\n");
    return;
  }

  pe::IMAGE_FILE_HEADER file_header{0};
  binary_file.read(reinterpret_cast<char *>(&file_header), sizeof(file_header));
  if (binary_file.gcount() != sizeof(file_header))
  {
    fmt::print(stderr, "Error: Failed to read file header\n");
    return;
  }

  std::uint64_t image_base;
  if (file_header.SizeOfOptionalHeader == sizeof(pe::IMAGE_OPTIONAL_HEADER64))
  {
    pe::IMAGE_OPTIONAL_HEADER64 optional_header{0};
    binary_file.read(reinterpret_cast<char *>(&optional_header), sizeof(optional_header));
    if (binary_file.gcount() != sizeof(optional_header))
    {
      fmt::print(stderr, "Error: Failed to read optional header\n");
      return;
    }
    if (
            optional_header.Magic != pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
            optional_header.Magic != pe::IMAGE_NT_OPTIONAL_HDR32_MAGIC
            )
    {
      fmt::print(stderr, "Error: Invalid optional header magic\n");
      return;
    }
    image_base = optional_header.ImageBase;
  } else if (file_header.SizeOfOptionalHeader == sizeof(pe::IMAGE_OPTIONAL_HEADER32))
  {
    pe::IMAGE_OPTIONAL_HEADER32 optional_header{0};
    binary_file.read(reinterpret_cast<char *>(&optional_header), sizeof(optional_header));
    if (binary_file.gcount() != sizeof(optional_header))
    {
      fmt::print(stderr, "Error: Failed to read optional header\n");
      return;
    }
    if (
            optional_header.Magic != pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
            optional_header.Magic != pe::IMAGE_NT_OPTIONAL_HDR32_MAGIC
            )
    {
      fmt::print(stderr, "Error: Invalid optional header magic\n");
      return;
    }
    image_base = optional_header.ImageBase;
  } else
  {
    fmt::print(stderr, "Error: Invalid optional header size\n");
    return;
  }

  std::vector<pe::IMAGE_SECTION_HEADER> section_headers(file_header.NumberOfSections);
  const auto section_headers_size = static_cast<std::streamsize>(file_header.NumberOfSections * sizeof(pe::IMAGE_SECTION_HEADER));
  binary_file.read(reinterpret_cast<char *>(section_headers.data()), section_headers_size);
  if (binary_file.gcount() != section_headers_size)
  {
    fmt::print(stderr, "Error: Failed to read section headers\n");
    return;
  }

  std::vector<relocation_entry> relocations;
  for (const auto &section_header: section_headers)
  {
    relocation_entry relocation;
    relocation.start = section_header.PointerToRawData;
    relocation.end = section_header.PointerToRawData + section_header.SizeOfRawData;
    relocation.offset = static_cast<std::int64_t>(image_base) + section_header.VirtualAddress - section_header.PointerToRawData;
    relocation.name = std::string(section_header.Name, strnlen(section_header.Name, sizeof(section_header.Name)));
    relocations.emplace_back(std::move(relocation));
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
    fmt::print(stderr, "Error: Failed to find server public key\n");
    return;
  }
  if (server_public_key_offsets.size() != 1)
  {
    fmt::print(stderr, "Error: Expected only one server public key, found {}\n", server_public_key_offsets.size());
    return;
  }
  offsets.server_public_key = apply_relocations(server_public_key_offsets[0], relocations);
  fmt::print("Found server public key at {}:{:#012x} ({:#012x})\n", binary_filename, server_public_key_offsets[0], offsets.server_public_key);
  if (shannon_constant_offsets.empty())
  {
    fmt::print(stderr, "Error: Failed to find shannon constant\n");
    return;
  }
  for (const auto &offset: shannon_constant_offsets)
  {
    sigscanner::offset relocated_offset = apply_relocations(offset, relocations);
    fmt::print("Found shannon constant at {}:{:#012x} ({:#012x})\n", binary_filename, offset, relocated_offset);
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

  sigscanner::offset first_shannon_constant = shannon_constant_offsets[0];
  std::array<std::uint8_t, 0x4000> shn_bytes{0};
  std::int64_t shn_prologue_scan_base = static_cast<std::int64_t>(first_shannon_constant - shn_bytes.size());
  binary_file.seekg(shn_prologue_scan_base);
  binary_file.read(reinterpret_cast<char *>(shn_bytes.data()), shn_bytes.size());
  if (binary_file.gcount() != shn_bytes.size())
  {
    fmt::print(stderr, "Error: Failed to read bytes to scan for shannon prologue\n");
    return;
  }
  sigscanner::signature function_prologue = "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18";
  std::vector<sigscanner::offset> function_prologues = function_prologue.reverse_scan(shn_bytes.data(), shn_bytes.size(), shn_prologue_scan_base);
  if (function_prologues.empty())
  {
    fmt::print(stderr, "Error: Failed to find shn_encrypt/shn_decrypt prologue\n");
    return;
  }
  for (auto &prologue: function_prologues)
  {
    sigscanner::offset relocated_prologue = apply_relocations(prologue, relocations);
    fmt::print("Found function prologue at {}:{:#012x} ({:#012x})\n", binary_filename, prologue, relocated_prologue);
    prologue = relocated_prologue;
  }
  if (function_prologues.size() < 2)
  {
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
        fmt::print(stderr, "Error: Expected arm64-v8a to be 64-bit and little endian\n");
        return;
      }
      fmt::print("Detected JNI for arm64-v8a\n");
      break;
    }
    default:
    {
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
    fmt::print(stderr, "Error: Failed to find server public key\n");
    return;
  }
  if (server_public_key_offsets.size() != 1)
  {
    fmt::print(stderr, "Error: Expected only one server public key, found {}\n", server_public_key_offsets.size());
    return;
  }
  offsets.server_public_key = apply_relocations(server_public_key_offsets[0], relocations);
  fmt::print("Found server public key at {}:{:#012x} ({:#012x})\n", binary_filename, server_public_key_offsets[0], offsets.server_public_key);
  if (shannon_constant_offsets.empty())
  {
    fmt::print(stderr, "Error: Failed to find shannon constant\n");
    return;
  }
  for (const auto &offset: shannon_constant_offsets)
  {
    sigscanner::offset relocated_offset = apply_relocations(offset, relocations);
    fmt::print("Found shannon constant at {}:{:#012x} ({:#012x})\n", binary_filename, offset, relocated_offset);
  }

  /*
   * On all architectures, shn_finish contains the last instance of the constant.
   * The encryption/decryption functions are then directly above, so we can have
   * shorter function prologues.
   */

  sigscanner::offset last_shannon_constant = shannon_constant_offsets[shannon_constant_offsets.size() - 1];
  std::array<std::uint8_t, 0x2000> shn_bytes{0};
  std::int64_t shn_prologue_scan_base = static_cast<std::int64_t>(last_shannon_constant - shn_bytes.size());
  binary_file.seekg(std::max(std::int64_t{0}, shn_prologue_scan_base));
  binary_file.read(reinterpret_cast<char *>(shn_bytes.data()), shn_bytes.size());
  const sigscanner::signature &function_prologue = JNI_SHANNON_PROLOGUES.at(binary_details.machine);
  std::vector<sigscanner::offset> function_prologues = function_prologue.reverse_scan(shn_bytes.data(), shn_bytes.size(), shn_prologue_scan_base);
  if (function_prologues.empty())
  {
    fmt::print(stderr, "Error: Failed to find shn_encrypt/shn_decrypt prologue\n");
    return;
  }
  // We hit shn_finish
  if (last_shannon_constant - function_prologues[0] < 0x200)
  {
    sigscanner::offset relocated_shn_finish = apply_relocations(function_prologues[0], relocations);
    fmt::print("Found shn_finish at {}:{:#012x} ({:#012x})\n", binary_filename, function_prologues[0], relocated_shn_finish);
    function_prologues.erase(function_prologues.begin());
  }
  for (auto &prologue: function_prologues)
  {
    sigscanner::offset relocated_prologue = apply_relocations(prologue, relocations);
    fmt::print("Found function prologue at {}:{:#012x} ({:#012x})\n", binary_filename, prologue, relocated_prologue);
    prologue = relocated_prologue;
  }
  if(function_prologues.size() < 2)
  {
    fmt::print(stderr, "Error: Found too few prologues\n");
    return;
  }

  offsets.shn_addr1 = function_prologues[0];
  offsets.shn_addr2 = function_prologues[1];
  offsets.success = true;
}

scan_result scan_binary(platform target, const std::filesystem::path &binary_path)
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
    default:
    {
      fmt::print(stderr, "Error: Scanning not implemented for this target\n");
      return offsets;
    }
  }
}
