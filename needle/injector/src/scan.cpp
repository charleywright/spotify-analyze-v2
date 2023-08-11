#include "scan.hpp"
#include <fstream>
#include "sigscanner/sigscanner.hpp"
#include "elf.hpp"
#include <memory>
#include <cstring>

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

void scan_linux(scan_result &offsets, const std::filesystem::path &executable_path)
{
  /*
   * On Linux the spotify binary is of course an ELF file. We can use this to determine
   * the architecture of the binary and then use the correct signatures. We could read
   * the whole ELF header however we only need the e_ident array which is the first 16
   * bytes.
   */
  std::ifstream executable(executable_path, std::ios::binary);
  if (!executable)
  {
    std::fprintf(stderr, "Error: Failed to open %s\n", executable_path.c_str());
    return;
  }
  elf::Elf_Ident e_ident{0};
  executable.read(reinterpret_cast<char *>(&e_ident), sizeof(e_ident));
  if (executable.gcount() != sizeof(e_ident))
  {
    std::fprintf(stderr, "Error: Failed to read ELF identifier\n");
    return;
  }
  executable.close();

  const sigscanner::signature elf_header_magic("7F 45 4C 46");
  if (!elf_header_magic.check(e_ident.ei_mag, sizeof(e_ident.ei_mag)))
  {
    std::fprintf(stderr, "Error: %s is not an ELF file\n", executable_path.c_str());
    return;
  }

  bool is_64_bit = e_ident.ei_class == elf::Elf_Ident::ELFCLASS64;
  bool is_little_endian = e_ident.ei_data == elf::Elf_Ident::ELFDATA2LSB;

  std::printf("Detected binary as %s %s\n", is_64_bit ? "64-bit" : "32-bit", is_little_endian ? "little endian" : "big endian");

  const sigscanner::signature SHANNON_CONSTANT = "3a c5 96 69";
  const sigscanner::signature SERVER_PUBLIC_KEY = SERVER_PUBLIC_KEY_SIG;
  sigscanner::multi_scanner scanner;
  scanner.add_signature(SHANNON_CONSTANT);
  scanner.add_signature(SERVER_PUBLIC_KEY);
  std::unordered_map<sigscanner::signature, std::vector<sigscanner::offset>> results = scanner.scan_file(executable_path);
  std::vector<sigscanner::offset> &shannon_constant_offsets = results[SHANNON_CONSTANT];
  std::vector<sigscanner::offset> &server_public_key_offsets = results[SERVER_PUBLIC_KEY];
  if (server_public_key_offsets.empty())
  {
    std::fprintf(stderr, "Error: Failed to find server public key\n");
    return;
  }
  if (server_public_key_offsets.size() != 1)
  {
    std::fprintf(stderr, "Error: Expected only one server public key, found %lu\n", server_public_key_offsets.size());
    return;
  }
  std::printf("Found server public key at 0x%010lx\n", server_public_key_offsets[0]);
  if (shannon_constant_offsets.empty())
  {
    std::fprintf(stderr, "Error: Failed to find shannon constant\n");
    return;
  }
  for (const auto &offset: shannon_constant_offsets)
  {
    std::printf("Found shannon constant at 0x%010lx\n", offset);
  }

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
  */

  std::vector<relocation_entry> relocations;
  // TODO: Refactor so we don't need to duplicate this code
  if (is_64_bit)
  {
    elf::Elf64_Ehdr header{0};
    executable.open(executable_path, std::ios::binary);
    executable.read(reinterpret_cast<char *>(&header), sizeof(header));
    if (executable.gcount() != sizeof(header))
    {
      std::fprintf(stderr, "Error: Failed to read ELF header\n");
      return;
    }

    elf::Elf64_Half section_header_table_entry_size = header.e_shentsize;
    if (section_header_table_entry_size != sizeof(elf::Elf64_Shdr))
    {
      std::fprintf(stderr, "Error: Invalid section header table entry size\n");
      return;
    }

    std::vector<elf::Elf64_Shdr> section_headers(header.e_shnum);
    elf::Elf64_Half section_header_table_size = header.e_shnum * section_header_table_entry_size;
    executable.seekg(static_cast<std::ifstream::off_type>(header.e_shoff), std::ios::beg);
    executable.read(reinterpret_cast<char *>(section_headers.data()), static_cast<std::streamsize>(section_header_table_size));
    if (executable.gcount() != section_header_table_size)
    {
      std::fprintf(stderr, "Error: Failed to read section headers\n");
      return;
    }

    elf::Elf64_Half section_header_string_table_index = header.e_shstrndx;
    if (section_header_string_table_index == elf::Elf64_Ehdr::SHN_UNDEF)
    {
      std::fprintf(stderr, "Error: Section header string table index is undefined\n");
      return;
    }
    if (section_header_string_table_index == elf::Elf64_Ehdr::SHN_XINDEX)
    {
      section_header_string_table_index = section_headers[0].sh_link;
    }

    const elf::Elf64_Shdr &section_header_string_table_entry = section_headers[section_header_string_table_index];
    std::unique_ptr<void, void (*)(void *)> section_header_string_table(std::malloc(section_header_string_table_entry.sh_size), std::free);
    if (!section_header_string_table)
    {
      std::fprintf(stderr, "Error: Failed to allocate memory for section header string table\n");
      return;
    }
    executable.seekg(static_cast<std::ifstream::off_type>(section_header_string_table_entry.sh_offset), std::ios::beg);
    executable.read(reinterpret_cast<char *>(section_header_string_table.get()), static_cast<std::streamsize>(section_header_string_table_entry.sh_size));
    if (executable.gcount() != section_header_string_table_entry.sh_size)
    {
      std::fprintf(stderr, "Error: Failed to read section header string table\n");
      return;
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
    elf::Elf32_Ehdr header{0};
    executable.open(executable_path, std::ios::binary);
    executable.read(reinterpret_cast<char *>(&header), sizeof(header));
    if (executable.gcount() != sizeof(header))
    {
      std::fprintf(stderr, "Error: Failed to read ELF header\n");
      return;
    }

    elf::Elf32_Half section_header_table_entry_size = header.e_shentsize;
    if (section_header_table_entry_size != sizeof(elf::Elf32_Shdr))
    {
      std::fprintf(stderr, "Error: Invalid section header table entry size\n");
      return;
    }

    std::vector<elf::Elf32_Shdr> section_headers(header.e_shnum);
    elf::Elf32_Half section_header_table_size = header.e_shnum * section_header_table_entry_size;
    executable.seekg(static_cast<std::ifstream::off_type>(header.e_shoff), std::ios::beg);
    executable.read(reinterpret_cast<char *>(section_headers.data()), static_cast<std::streamsize>(section_header_table_size));
    if (executable.gcount() != section_header_table_size)
    {
      std::fprintf(stderr, "Error: Failed to read section headers\n");
      return;
    }

    elf::Elf32_Half section_header_string_table_index = header.e_shstrndx;
    if (section_header_string_table_index == elf::Elf32_Ehdr::SHN_UNDEF)
    {
      std::fprintf(stderr, "Error: Section header string table index is undefined\n");
      return;
    }
    if (section_header_string_table_index == elf::Elf32_Ehdr::SHN_XINDEX)
    {
      section_header_string_table_index = section_headers[0].sh_link;
    }

    const elf::Elf32_Shdr &section_header_string_table_entry = section_headers[section_header_string_table_index];
    std::unique_ptr<void, void (*)(void *)> section_header_string_table(std::malloc(section_header_string_table_entry.sh_size), std::free);
    if (!section_header_string_table)
    {
      std::fprintf(stderr, "Error: Failed to allocate memory for section header string table\n");
      return;
    }
    executable.seekg(static_cast<std::ifstream::off_type>(section_header_string_table_entry.sh_offset), std::ios::beg);
    executable.read(reinterpret_cast<char *>(section_header_string_table.get()), static_cast<std::streamsize>(section_header_string_table_entry.sh_size));
    if (executable.gcount() != section_header_string_table_entry.sh_size)
    {
      std::fprintf(stderr, "Error: Failed to read section header string table\n");
      return;
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

  server_public_key_offsets[0] = apply_relocations(server_public_key_offsets[0], relocations);
  std::printf("Adjusted server public key, offset = 0x%010lx\n", server_public_key_offsets[0]);
  for (auto &offset: shannon_constant_offsets)
  {
    offset = apply_relocations(offset, relocations);
    std::printf("Adjusted shannon constant, offset = 0x%010lx\n", offset);
  }
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
    default:
    {
      std::fprintf(stderr, "Error: Scanning not implemented for this target\n");
      return offsets;
    }
  }
}
