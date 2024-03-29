use std::collections::{HashMap, VecDeque};
use std::io::Cursor;
use std::path::PathBuf;

use lazy_static::lazy_static;

use super::scanner;
use super::Target;

lazy_static! {
    static ref SERVER_PUBLIC_KEY_SIGNATURE: scanner::Signature = scanner::Signature::from_ida_style("ac e0 46 0b ff c2 30 af f4 6b fe c3 bf bf 86 3d a1 91 c6 cc 33 6c 93 a1 4f b3 b0 16 12 ac ac 6a f1 80 e7 f6 14 d9 42 9d be 2e 34 66 43 e3 62 d2 32 7a 1a 0d 92 3b ae dd 14 02 b1 81 55 05 61 04 d5 2c 96 a4 4c 1e cc 02 4a d4 b2 0c 00 1f 17 ed c2 2f c4 35 21 c8 f0 cb ae d2 ad d7 2b 0f 9d b3 c5 32 1a 2a fe 59 f3 5a 0d ac 68 f1 fa 62 1e fb 2c 8d 0c b7 39 2d 92 47 e3 d7 35 1a 6d bd 24 c2 ae 25 5b 88 ff ab 73 29 8a 0b cc cd 0c 58 67 31 89 e8 bd 34 80 78 4a 5f c9 6b 89 9d 95 6b fc 86 d7 4f 33 a6 78 17 96 c9 c3 2d 0d 32 a5 ab cd 05 27 e2 f7 10 a3 96 13 c4 2f 99 c0 27 bf ed 04 9c 3c 27 58 04 b6 b2 19 f9 c1 2f 02 e9 48 63 ec a1 b6 42 a0 9d 48 25 f8 b3 9d d0 e8 6a f9 48 4d a1 c2 ba 86 30 42 ea 9d b3 08 6c 19 0e 48 b3 9d 66 eb 00 06 a2 5a ee a1 1b 13 87 3c d7 19 e6 55 bd").unwrap();
}

fn scan_multiple(signatures: &[scanner::Signature], data: &[u8], offset: usize) -> Vec<usize> {
    signatures.iter().flat_map(|sig| sig.scan_with_offset(data, offset)).collect()
}

fn multiple_sig_prologue_scan(signatures: &[scanner::Signature], data: &[u8], offset: usize) -> Vec<usize> {
        for signature in signatures {
           let offsets = signature.scan_with_offset(data, offset);
            if offsets.len() >= 2 {
                return offsets;
            }
        }
        Vec::new()
}

struct RelocationEntry {
    offset_in_file: usize,
    size_in_file: usize,
    offset_in_memory: usize,
    size_in_memory: usize,
}

/// Take a position in a file and calculate the offset from the module base address to that data. Frida's modules
/// (Process.getModuleByName etc.) do not have a concept of segments so the offset must be calculated relative to the
/// first segment in the file that is loaded. For example if the position is in the third loadable segment, the offset
/// will be s1.len + s2.len + s3_offset. It would be nice if it was that simple however some sections such as .bss will
/// not occupy space in the file but will occupy space in memory. We need to take all of this into account when
/// calculating the relocated offset. This function assumes the relocations are sorted by their virtual address.
fn calculate_relocated_offset(relocations: &Vec<RelocationEntry>, position: usize) -> usize {
    for relocation in relocations {
        if position >= relocation.offset_in_file && position < relocation.offset_in_file + relocation.size_in_file {
            let offset_from_segment = position - relocation.offset_in_file;
            let offset_from_base = relocation.offset_in_memory - relocations[0].offset_in_memory;
            return offset_from_base + offset_from_segment;
        }
    }
    position
}

/// Take a position in a file and calculate the offset in virtual memory where the data at that
/// position will be placed. This is only reliable for executables as position independent dynamic
/// libraries can be loaded at any base address.
fn calculate_relocated_address(relocations: &Vec<RelocationEntry>, position: usize) -> usize {
    for relocation in relocations {
        if position >= relocation.offset_in_file && position < relocation.offset_in_file + relocation.size_in_file {
            let offset_from_segment = position - relocation.offset_in_file;
            return relocation.offset_in_memory + offset_from_segment;
        }
    }
    position
}

/// Parse the ELF segment headers to find the segments that will be loaded into memory. Use these to build a vector of
/// relocation rules for varying offsets in the file to the offsets in memory.
fn parse_elf_relocations(elf_file: &mut elf::ElfBytes<elf::endian::NativeEndian>) -> Vec<RelocationEntry> {
    // These are offsets of the shannon constant using a binary file scan:
    //   0x0001a6ed47
    //   0x0001a6f0aa
    //   0x0001a70887
    // These are the offsets when the binary is loaded into memory:
    //   0x0001c6fd47
    //   0x0001c700aa
    //   0x0001c71887
    // The difference is 0x201000, this is due to relocations. When an executable is loaded from disk it is memory-mapped
    // into virtual memory according to the segments defined in the file. In an ELF file the segments to be loaded are
    // defined in the program header table with p_type being PT_LOAD. We can look at these headers using readelf:
    //
    //   readelf --wide --segments /opt/spotify/spotify
    //   Type           Offset    VirtAddr           PhysAddr           FileSiz   MemSiz    Flg Align
    //   PHDR           0x000040  0x0000000000200040 0x0000000000200040 0x0002a0  0x0002a0  R   0x8
    //   INTERP         0x0002e0  0x00000000002002e0 0x00000000002002e0 0x00001c  0x00001c  R   0x1
    //   LOAD           0x000000  0x0000000000200000 0x0000000000200000 0x930b54  0x930b54  R   0x1000
    //   LOAD           0x930b60  0x0000000000b31b60 0x0000000000b31b60 0x13fab50 0x13fab50 R E 0x1000
    //   LOAD           0x1d2b6c0 0x0000000001f2d6c0 0x0000000001f2d6c0 0x00aaa8  0x00aaa8  RW  0x1000
    //   LOAD           0x1d36170 0x0000000001f39170 0x0000000001f39170 0x52dd48  0x55c2a8  RWE 0x1000
    //   TLS            0x1d2b6c0 0x0000000001f2d6c0 0x0000000001f2d6c0 0x000040  0x001439  R   0x40
    //   DYNAMIC        0x1d35df8 0x0000000001f37df8 0x0000000001f37df8 0x000350  0x000350  RW  0x8
    //   GNU_RELRO      0x1d2b6c0 0x0000000001f2d6c0 0x0000000001f2d6c0 0x00aaa8  0x00b940  R   0x1
    //   GNU_EH_FRAME   0x4424d0  0x00000000006424d0 0x00000000006424d0 0x0cf804  0x0cf804  R   0x4
    //   GNU_STACK      0x000000  0x0000000000000000 0x0000000000000000 0x000000  0x000000  RW  0
    //   NOTE           0x0002fc  0x00000000002002fc 0x00000000002002fc 0x000020  0x000020  R   0x4
    //
    // There are 4 LOAD segments and use an alignment of 0x1000 bytes. Looking at /proc/<pid>/maps it appears to match:
    //
    //   address           perms offset   dev    inode  pathname
    //   00200000-00b31000 r--p  00000000 103:07 933385 /opt/spotify/spotify
    //   00b31000-01f2d000 r-xp  00930000 103:07 933385 /opt/spotify/spotify
    //   01f2d000-01f39000 r--p  01d2b000 103:07 933385 /opt/spotify/spotify
    //   01f39000-02467000 rwxp  01d36000 103:07 933385 /opt/spotify/spotify
    //
    // The addresses used for loading don't exactly match the program headers, but after taking alignment into consideration
    // they match. If the segment start and/or end don't lie on page boundaries the linker looks backwards in the file and
    // reads the bytes behind the current position to pad the segment. The same occurs after the segment, and if no data is
    // available (EOF) the segment is padded with zeroes. This allows the segment to be mapped with only a single continuous
    // read from the file and the segment's data is mapped to the correct location. This causes the segments in
    // /proc/pid/maps to not be the same size nor have the same base address as the program headers but the data is in the
    // expected location. There are some resources about the ELF format linked at the top of elf.hpp and for learning about
    // linkers there are a few very good videos in a playlist called "CS 361 Systems Programming" on YouTube.
    let mut relocations: Vec<RelocationEntry> = Vec::new();

    let segments = elf_file.segments().expect("Failed to parse ELF segments");
    for segment in segments {
        if segment.p_type == elf::abi::PT_LOAD {
            let entry = RelocationEntry {
                offset_in_file: segment.p_offset as usize,
                size_in_file: segment.p_filesz as usize,
                offset_in_memory: segment.p_vaddr as usize,
                size_in_memory: segment.p_memsz as usize,
            };
            let aligned_vaddr_start = segment.p_vaddr & !(segment.p_align - 1);
            let aligned_vaddr_end = (segment.p_vaddr + segment.p_memsz + segment.p_align - 1) & !(segment.p_align - 1);
            println!(
                "Found ELF relocation {:#012x}-{:#012x} -> {:#012x}-{:#012x} ({:#012x} - {:#012x})",
                entry.offset_in_file,
                entry.offset_in_file + entry.size_in_file,
                entry.offset_in_memory,
                entry.offset_in_memory + entry.size_in_memory,
                aligned_vaddr_start,
                aligned_vaddr_end
            );
            relocations.push(entry);
        }
    }

    relocations.sort_by_key(|entry| entry.offset_in_memory);

    relocations
}

fn parse_mach_o_relocations(commands: &Vec<mach_object::MachCommand>) -> Vec<RelocationEntry> {
    let mut relocations = vec![];

    for command in commands {
        match &command.0 {
            mach_object::LoadCommand::Segment {
                segname,
                fileoff,
                filesize,
                vmaddr,
                vmsize,
                sections,
                ..
            } => {
                if segname == "__PAGEZERO" {
                    println!("Skipping __PAGEZERO segment");
                    continue;
                }
                println!(
                    "Found Mach-O relocation {:#012x}-{:#012x} -> {:#012x}-{:#012x} [{:^16}] with {} sections",
                    fileoff,
                    fileoff + filesize,
                    vmaddr,
                    vmaddr + vmsize,
                    segname,
                    sections.len()
                );
                relocations.push(RelocationEntry {
                    offset_in_file: *fileoff,
                    size_in_file: *filesize,
                    offset_in_memory: *vmaddr,
                    size_in_memory: *vmsize,
                });
            },
            mach_object::LoadCommand::Segment64 {
                segname,
                fileoff,
                filesize,
                vmaddr,
                vmsize,
                sections,
                ..
            } => {
                if segname == "__PAGEZERO" {
                    println!("Skipping __PAGEZERO segment");
                    continue;
                }
                println!(
                    "Found Mach-O relocation {:#012x}-{:#012x} -> {:#012x}-{:#012x} [{:^16}] with {} sections",
                    fileoff,
                    fileoff + filesize,
                    vmaddr,
                    vmaddr + vmsize,
                    segname,
                    sections.len()
                );
                relocations.push(RelocationEntry {
                    offset_in_file: *fileoff,
                    size_in_file: *filesize,
                    offset_in_memory: *vmaddr,
                    size_in_memory: *vmsize,
                });
            },
            _ => {},
        }
    }

    relocations.sort_by_key(|entry| entry.offset_in_memory);

    relocations
}

struct ScannableMachOFile<'a> {
    file: &'a mach_object::OFile,
    offset: u64,
    #[allow(unused)]
    size: u64,
    arch: &'static str,
}

impl<'a> ScannableMachOFile<'a> {
    fn from_ofile(ofile: &'a mach_object::OFile, header: &mach_object::MachHeader) -> Self {
        ScannableMachOFile {
            file: ofile,
            offset: 0,
            size: 0,
            arch: mach_object::get_arch_name_from_types(header.cputype, header.cpusubtype).unwrap(),
        }
    }

    fn from_fat(file: &'a (mach_object::FatArch, mach_object::OFile)) -> Self {
        ScannableMachOFile {
            file: &file.1,
            offset: file.0.offset,
            size: file.0.size,
            arch: mach_object::get_arch_name_from_types(file.0.cputype, file.0.cpusubtype).unwrap(),
        }
    }
}

fn find_macho_file<'a>(target_arch: Option<&String>, ofile: &'a mach_object::OFile) -> Option<ScannableMachOFile<'a>> {
    match ofile {
        mach_object::OFile::MachFile {
            commands: _commands,
            header,
        } => Some(ScannableMachOFile::from_ofile(ofile, header)),
        mach_object::OFile::FatFile {
            magic: _magic,
            files,
        } => {
            println!("Detected Mach-O file as multi-architecture");

            if files.len() == 1 {
                return Some(ScannableMachOFile::from_fat(&files[0]));
            }

            for (arch, _file) in files.iter() {
                println!("Found Mach-O file entry for {}", arch.name().unwrap());
            }

            if target_arch.is_none() {
                eprintln!("Mach-O architecture is ambiguous, please specify --arch");
                return None;
            }

            let target_file = files.iter().find(|x| x.0.name().unwrap() == target_arch.unwrap().as_str());

            target_file.map(ScannableMachOFile::from_fat)
        },
        _ => {
            eprintln!("Unsupported Mach-O format");
            None
        },
    }
}

pub struct Offsets {
    pub shannon_offset1: usize,
    pub shannon_offset2: usize,
    pub server_public_key_offset: usize,
}

pub fn scan_binary(target: &Target, args: &clap::ArgMatches) -> Option<Offsets> {
    let executable = args.get_one::<String>("executable").unwrap();
    let mut offsets = Offsets {
        shannon_offset1: 0,
        shannon_offset2: 0,
        server_public_key_offset: 0,
    };

    match target {
        Target::Linux => {
            // On Linux the spotify binary is an ELF file. We can parse this file to significantly reduce the scanning
            // area and find the relocation entries for the binary

            lazy_static! {
                static ref SHANNON_CONSTANT: scanner::Signature =
                    scanner::Signature::from_ida_style("3A C5 96 69").unwrap();
                static ref SHANNON_PROLOGUE: scanner::Signature =
                    scanner::Signature::from_ida_style("55 48 89 E5").unwrap();
            }

            let binary = args.get_one::<String>("binary").unwrap_or(executable);
            let binary_path = PathBuf::from(binary).canonicalize().unwrap();
            let binary_filename = binary_path.file_name().unwrap().to_str().unwrap();

            println!("Target: linux");
            println!("Executable: {}", executable);
            println!("Binary: {}", binary_path.display());

            let binary_data = std::fs::read(&binary_path).unwrap();
            let mut elf_file = elf::ElfBytes::<elf::endian::NativeEndian>::minimal_parse(&binary_data).unwrap();
            let relocations = parse_elf_relocations(&mut elf_file);

            // The server key is easy to find, it's stored in the .rodata section and is always the same across all
            // versions of the app and contains no wildcards
            let rodata_header =
                elf_file.section_header_by_name(".rodata").unwrap().expect("Failed to find .rodata section");
            let rodata_start = rodata_header.sh_offset as usize;
            let rodata_end = rodata_start + rodata_header.sh_size as usize;
            let rodata_section = &binary_data[rodata_start..rodata_end];
            let server_key_offsets =
                SERVER_PUBLIC_KEY_SIGNATURE.scan_with_offset(rodata_section, rodata_header.sh_offset as usize);
            if server_key_offsets.is_empty() {
                eprintln!("Failed to find server public key");
                return None;
            }
            for server_key_offset in server_key_offsets {
                let relocated_offset = calculate_relocated_offset(&relocations, server_key_offset);
                let relocated_address = calculate_relocated_address(&relocations, server_key_offset);
                println!(
                    "Found server public key at {}:{:#012x} Offset: {:#012x} Address: {:#012x}",
                    binary_filename, server_key_offset, relocated_offset, relocated_address
                );
                offsets.server_public_key_offset = relocated_offset;
            }

            let text_header = elf_file.section_header_by_name(".text").unwrap().expect("Failed to find .text section");
            let text_start = text_header.sh_offset as usize;
            let text_end = text_start + text_header.sh_size as usize;
            let text_section = &binary_data[text_start..text_end];
            let shannon_constant_offsets =
                SHANNON_CONSTANT.scan_with_offset(text_section, text_header.sh_offset as usize);
            if shannon_constant_offsets.is_empty() {
                eprintln!("Failed to find shannon constant");
                return None;
            }
            for shannon_constant_offset in &shannon_constant_offsets {
                let relocated_offset = calculate_relocated_offset(&relocations, *shannon_constant_offset);
                let relocated_address = calculate_relocated_address(&relocations, *shannon_constant_offset);
                println!(
                    "Found shannon constant at {}:{:#012x} Offset: {:#012x} Address: {:#012x}",
                    binary_filename, shannon_constant_offset, relocated_offset, relocated_address
                );
            }

            // shn_encrypt, shn_decrypt and shn_finish all have the same prologue:
            // shn_encrypt 55 48 89 E5 41 56 53 83 BF CC 00 00 00 00 74 64                  start=0x0000000001C700D0 end=0x0000000001C70C07 size=0xB37
            // shn_decrypt 55 48 89 E5 41 56 53 83 BF CC 00 00 00 00 74 73                  start=0x0000000001C70C10 end=0x0000000001C7177F size=0xB6F
            // shn_finish  55 48 89 E5 41 57 41 56 41 54 53 41 89 D7 49 89 F6 48 89 FB 44   start=0x0000000001C71790 end=0x0000000001C719B0 size=0x220
            //
            // 55         push    rbp
            // 48 89 E5   mov     rbp, rsp
            //
            // Since this is a very common prologue it should be very reliable. We can discount shn_finish by
            // checking the distance between the address we hit and the constant due to the encryption/decryption
            // functions being quite long.

            const SHANNON_PROLOGUE_SCAN_SIZE: usize = 0x2000;
            let last_shannon_constant = shannon_constant_offsets.last().unwrap();
            let shannon_prologue_scan_base = last_shannon_constant.saturating_sub(SHANNON_PROLOGUE_SCAN_SIZE);
            let shannon_prologue_scan_end = *last_shannon_constant;
            let shannon_prologue_scan_section = &binary_data[shannon_prologue_scan_base..shannon_prologue_scan_end];
            let mut shannon_prologue_offsets = VecDeque::from(
                SHANNON_PROLOGUE.reverse_scan_with_offset(shannon_prologue_scan_section, shannon_prologue_scan_base),
            );
            if shannon_prologue_offsets.is_empty() {
                eprintln!("Failed to find shn_encrypt/shn_decrypt prologue");
                return None;
            }

            // We hit shn_finish
            if last_shannon_constant - shannon_prologue_offsets[0] < 0x200 {
                let relocated_shn_finish_offset = calculate_relocated_offset(&relocations, shannon_prologue_offsets[0]);
                let relocated_shn_finish_address =
                    calculate_relocated_address(&relocations, shannon_prologue_offsets[0]);
                println!(
                    "Found shn_finish at {}:{:#012x} Offset: {:#012x} Address: {:#012x}",
                    binary_filename,
                    shannon_prologue_offsets[0],
                    relocated_shn_finish_offset,
                    relocated_shn_finish_address
                );
                shannon_prologue_offsets.pop_front();
            }

            for shannon_prologue in &shannon_prologue_offsets {
                let relocated_prologue_offset = calculate_relocated_offset(&relocations, *shannon_prologue);
                let relocated_prologue_address = calculate_relocated_address(&relocations, *shannon_prologue);
                println!(
                    "Found function prologue at {}:{:#012x} Offset: {:#012x} Address: {:#012x}",
                    binary_filename, shannon_prologue, relocated_prologue_offset, relocated_prologue_address
                );
            }
            if shannon_prologue_offsets.len() < 2 {
                eprintln!("Found too few prologues");
                return None;
            }

            offsets.shannon_offset1 = calculate_relocated_offset(&relocations, shannon_prologue_offsets[0]);
            offsets.shannon_offset2 = calculate_relocated_offset(&relocations, shannon_prologue_offsets[1]);

            Some(offsets)
        },
        Target::Windows => {
            // Executables on Windows use the PE format. There is an amazing tool we can use to look at PE files called
            // PE-Bear (https://github.com/hasherezade/pe-bear). We are interested in the image base which is in the
            // optional header and the section headers so we can compute the correct relocations for the offsets we
            // find

            lazy_static! {
                static ref SHANNON_CONSTANT: scanner::Signature =
                    scanner::Signature::from_ida_style("3A C5 96 69").unwrap();
                static ref SHANNON_PROLOGUE: scanner::Signature =
                    scanner::Signature::from_ida_style("48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18").unwrap();
            }

            let binary = args.get_one::<String>("binary").unwrap_or(executable);
            let binary_path = PathBuf::from(binary).canonicalize().unwrap();
            let binary_filename = binary_path.file_name().unwrap().to_str().unwrap();

            println!("Target: windows");
            println!("Executable: {}", executable);
            println!("Binary: {}", binary_path.display());

            let binary_data = std::fs::read(&binary_path).unwrap();
            let pe_file = pe_parser::pe::parse_portable_executable(&binary_data);
            if pe_file.is_err() {
                eprintln!("Failed to parse executable file");
                return None;
            }
            let pe_file = pe_file.ok().unwrap();

            // calculate_relocated_offset uses the first relocation entry to determine the base address to be used.
            // Since this is subtracted from any virtual address the number itself doesn't matter so long as it is
            // correct relative to the virtual addresses specified in the section headers. On Linux we simply read the
            // PT_LOAD segment headers and build a vector of file to virtual memory mappings, using the first one as
            // the base. Doing the same on Windows using the section headers (as segments don't exist in PE files) does
            // not work however as all offsets are off by 0x1000. Using VMMap from SysInternals it becomes apparent
            // that the first bit of memory-mapped data is the IMAGE_DOS_HEADER itself, NOT the first section. The
            // header is only 64 bytes long, but since a section alignment of 0x1000 is specified, the header is padded
            // to that length. This means the first section is loaded at 0x1000 which is indeed the value of it's
            // virtual address, however that is not what our calculation code uses as the module base. To fix this we
            // could either calculate the size of the padded DOS header then subtract that from every section's virtual
            // address or add a dummy section with a virtual address of 0 to represent the DOS header. The dummy
            // section seems like a cleaner solution, so that is what we are using

            // To find all our relocations we need the image base & section alignment from the optional header as well
            // as the section headers

            let mut relocations = vec![];
            let image_base;
            let section_alignment;
            if let Some(optional_header) = pe_file.optional_header_32 {
                image_base = optional_header.image_base as usize;
                section_alignment = optional_header.section_alignment as usize;
            } else if let Some(optional_header) = pe_file.optional_header_64 {
                image_base = optional_header.image_base as usize;
                section_alignment = optional_header.section_alignment as usize;
            } else {
                eprintln!("No optional header in executable");
                return None;
            }
            {
                let dummy_section = RelocationEntry {
                    offset_in_file: 0,
                    size_in_file: 64,
                    offset_in_memory: image_base,
                    size_in_memory: 64,
                };
                let aligned_vaddr_start = dummy_section.offset_in_memory & !(section_alignment - 1);
                let aligned_vaddr_end =
                    (dummy_section.offset_in_memory + dummy_section.size_in_memory + section_alignment - 1)
                        & !(section_alignment - 1);
                println!(
                    "Found PE relocation {:#012x}-{:#012x} -> {:#012x}-{:#012x} ({:#012x} - {:#012x}) [{:^10}]",
                    dummy_section.offset_in_file,
                    dummy_section.offset_in_file + dummy_section.size_in_file,
                    dummy_section.offset_in_memory,
                    dummy_section.offset_in_memory + dummy_section.size_in_memory,
                    aligned_vaddr_start,
                    aligned_vaddr_end,
                    ".dummy"
                );
                relocations.push(dummy_section);
            }
            for section_header in &pe_file.section_table {
                let entry = RelocationEntry {
                    offset_in_file: section_header.pointer_to_raw_data as usize,
                    size_in_file: section_header.size_of_raw_data as usize,
                    offset_in_memory: image_base + section_header.virtual_address as usize,
                    size_in_memory: section_header.virtual_size as usize,
                };
                let aligned_vaddr_start = entry.offset_in_memory & !(section_alignment - 1);
                let aligned_vaddr_end =
                    (entry.offset_in_memory + entry.size_in_memory + section_alignment - 1) & !(section_alignment - 1);
                println!(
                    "Found PE relocation {:#012x}-{:#012x} -> {:#012x}-{:#012x} ({:#012x} - {:#012x}) [{:^10}]",
                    entry.offset_in_file,
                    entry.offset_in_file + entry.size_in_file,
                    entry.offset_in_memory,
                    entry.offset_in_memory + entry.size_in_memory,
                    aligned_vaddr_start,
                    aligned_vaddr_end,
                    section_header.get_name().unwrap_or("<none>".to_string()).trim_matches(char::from(0))
                );
                relocations.push(entry);
            }

            // Server key is read only data thus is in .rdata
            let rdata_header = pe_file
                .section_table
                .iter()
                .find(|header| {
                    if let Some(name) = header.get_name() {
                        name.trim_matches(char::from(0)) == ".rdata"
                    } else {
                        false
                    }
                })
                .expect("Failed to find .rdata section");
            let rdata_start = rdata_header.pointer_to_raw_data as usize;
            let rdata_end = rdata_start + rdata_header.size_of_raw_data as usize;
            let rdata_section = &binary_data[rdata_start..rdata_end];
            let server_key_offsets = SERVER_PUBLIC_KEY_SIGNATURE.scan_with_offset(rdata_section, rdata_start);
            if server_key_offsets.is_empty() {
                eprintln!("Failed to find server public key");
                return None;
            }
            for server_key_offset in server_key_offsets {
                let relocated_offset = calculate_relocated_offset(&relocations, server_key_offset);
                let relocated_address = calculate_relocated_address(&relocations, server_key_offset);
                println!(
                    "Found server public key at {}:{:#012x} Offset: {:#012x} Address: {:#012x}",
                    binary_filename, server_key_offset, relocated_offset, relocated_address
                );
                offsets.server_public_key_offset = relocated_offset;
            }

            // Constants and functions are in .text as they are code
            let text_header = pe_file
                .section_table
                .iter()
                .find(|header| {
                    if let Some(name) = header.get_name() {
                        name.trim_matches(char::from(0)) == ".text"
                    } else {
                        false
                    }
                })
                .expect("Failed to find .text section");
            let text_start = text_header.pointer_to_raw_data as usize;
            let text_end = text_start + text_header.size_of_raw_data as usize;
            let text_section = &binary_data[text_start..text_end];
            let shannon_constant_offsets = SHANNON_CONSTANT.scan_with_offset(text_section, text_start);
            if shannon_constant_offsets.is_empty() {
                eprintln!("Failed to find shannon constant");
                return None;
            }
            for shannon_constant_offset in &shannon_constant_offsets {
                let relocated_offset = calculate_relocated_offset(&relocations, *shannon_constant_offset);
                let relocated_address = calculate_relocated_address(&relocations, *shannon_constant_offset);
                println!(
                    "Found shannon constant at {}:{:#012x} Offset: {:#012x} Address: {:#012x}",
                    binary_filename, shannon_constant_offset, relocated_offset, relocated_address
                );
            }

            // On Windows sometimes shn_diffuse can be found between the encryption/decryption functions. This doesn't
            // appear to cause issues though as the function prologue is quite different:
            //
            //   shn_encrypt:
            //     48 89 5C 24 08      mov     [rsp+arg_0], rbx
            //     48 89 6C 24 10      mov     [rsp+arg_8], rbp
            //     48 89 74 24 18      mov     [rsp+arg_10], rsi
            //
            //   shn_decrypt:
            //     48 89 5C 24 08      mov     [rsp+arg_0], rbx
            //     48 89 6C 24 10      mov     [rsp+arg_8], rbp
            //     48 89 74 24 18      mov     [rsp+arg_10], rsi
            //
            //   shn_diffuse:
            //     48 89 4C 24 08      mov     [rsp+arg_0], rcx
            //     53                  push    rbx
            //
            // The other difference on Windows is shn_finish contains the first instance of the constant instead of the
            // last. If this changes in the future, we can always try scanning backwards from each occurrence of the
            // constant however that is not ideal. shn_finish also has a different prologue to the other functions so
            // no need to deal with hitting that.

            const SHANNON_PROLOGUE_SCAN_SIZE: usize = 0x4000;
            let first_shannon_constant = shannon_constant_offsets[0];
            let shannon_prologue_scan_base = first_shannon_constant.saturating_sub(SHANNON_PROLOGUE_SCAN_SIZE);
            let shannon_prologue_scan_end = first_shannon_constant;
            let shannon_prologue_scan_data = &binary_data[shannon_prologue_scan_base..shannon_prologue_scan_end];
            let shannon_prologue_offsets =
                SHANNON_PROLOGUE.reverse_scan_with_offset(shannon_prologue_scan_data, shannon_prologue_scan_base);
            for shannon_prologue_offset in &shannon_prologue_offsets {
                let relocated_prologue_offset = calculate_relocated_offset(&relocations, *shannon_prologue_offset);
                let relocated_prologue_address = calculate_relocated_address(&relocations, *shannon_prologue_offset);
                println!(
                    "Found function prologue at {}:{:#012x} Offset: {:#012x} Address: {:#012x}",
                    binary_filename, shannon_prologue_offset, relocated_prologue_offset, relocated_prologue_address
                );
            }

            if shannon_prologue_offsets.len() < 2 {
                eprintln!("Found too few prologues");
                return None;
            }

            offsets.shannon_offset1 = calculate_relocated_offset(&relocations, shannon_prologue_offsets[0]);
            offsets.shannon_offset2 = calculate_relocated_offset(&relocations, shannon_prologue_offsets[1]);
            Some(offsets)
        },
        Target::Android => {
            // Android apps are packaged as APKs. APKs are just zip files with a different extension. When the APK is
            // extracted there is a libs folder which contains JNI libraries (Java Native Interface). These are
            // libraries written in a compiled language such as C, C++ or Rust that can be called from Java. Since
            // phones can have different architectures, Spotify ships multiple builds of the library: x86, x86_64,
            // armeabi-v7a, arm64-v8a. These are different binaries with different instruction sets therefore have
            // different signatures and offsets. We could ask the user to specify however since they are all shared
            // libraries (.so files) we can read the ELF header to find the architecture.

            // These seem to be the JNI library machine types for android
            const JNI_X86: u16 = elf::abi::EM_386;
            const JNI_X86_64: u16 = elf::abi::EM_X86_64;
            const JNI_ARMEABI_V7A: u16 = elf::abi::EM_ARM;
            const JNI_ARM64_V8A: u16 = elf::abi::EM_AARCH64;

            // Tested all signatures on 8.8.12.545 on all architectures
            lazy_static! {
                static ref JNI_SHANNON_CONSTANTS: HashMap<u16, Vec<scanner::Signature>> = HashMap::from([
                    (JNI_X86, vec![scanner::Signature::from_ida_style("3A C5 96 69").unwrap()]),
                    (JNI_X86_64, vec![scanner::Signature::from_ida_style("3A C5 96 69").unwrap()]),
                    /*
                      Constant is embedded after function, and is loaded using offset from PC
                      .text:00C7B410                 LDR             R2, [PC, #0xAC]
                      ...
                      .text:00C7B4C4 dword_C7B4C4    DCD 0x6996C53A
                    */
                    (JNI_ARMEABI_V7A, vec![scanner::Signature::from_ida_style("3A C5 96 69").unwrap()]),
                    (
                        JNI_ARM64_V8A,
                        vec![
                            /*
                              Registers can change, so use wildcards
                              movz w11, #0xc53a
                              movk w11, #0x6996, lsl #16
                            */
                            scanner::Signature::from_ida_style("?? A7 98 52 ?? 32 AD 72").unwrap(),
                            /*
                              Added for 8.9.6.458
                              movz w11, #0xc53a
                              ldr  w10, [x19, #0x34] (Not relevant, use wildcards)
                              movk w11, #0x6996, lsl #16
                            */
                            scanner::Signature::from_ida_style("?? A7 98 52 ?? ?? ?? ?? ?? 32 AD 72").unwrap(),
                        ],
                    ),
                ]);
                static ref JNI_SHANNON_PROLOGUES: HashMap<u16, Vec<scanner::Signature>> = HashMap::from([
                    (
                        JNI_X86,
                        vec![
                            /*
                              push ebp
                              mov  ebp, esp
                              push ebx
                              push edi
                              push esi
                              and  esp, 0xfffffff0
                              sub  esp, ??
                            */
                            scanner::Signature::from_ida_style("55 89 E5 53 57 56 83 E4 ?? 83 EC ??").unwrap()
                        ],
                    ),
                    (
                        JNI_X86_64,
                        vec![
                            /*
                              push rbp
                              mov  rbp, rsp
                            */
                            scanner::Signature::from_ida_style("55 48 89 E5").unwrap(),
                            /*
                              Added for 8.9.6.458
                              push rbp
                              push r15
                              push r14
                              push r12
                              push rbx
                            */
                            scanner::Signature::from_ida_style("55 41 57 41 56 41 54 53").unwrap(),
                        ],
                    ),
                    (
                        JNI_ARMEABI_V7A,
                        vec![
                            /*
                              push {r4, r5, r6, r7, r8, sl, fp, lr}
                              add  fp, sp, #0x18
                            */
                            scanner::Signature::from_ida_style("F0 4D 2D E9 18 B0 8D E2").unwrap(),
                            /*
                              Added for 8.8.90.893
                              push.w {r4, r5, r6, r7, r8, lr}
                              mov    r5, r0
                            */
                            scanner::Signature::from_ida_style("2D E9 F0 41 05 46").unwrap(),
                            /*
                              Added for 8.9.6.458
                              push.w {r4, r5, r6, r7, r8, sb, sl, lr}
                              mov    r5, r0
                            */
                            scanner::Signature::from_ida_style("2D E9 F0 47 05 46").unwrap(),
                        ],
                    ),
                    (
                        JNI_ARM64_V8A,
                        vec![
                            /*
                              str x23, [sp, #-0x40]!
                              stp x22, x21, [sp, #0x10]
                              stp x20, x19, [sp, #0x20]
                              stp x29, x30, [sp, #0x30]
                            */
                            scanner::Signature::from_ida_style("F7 0F 1C F8 F6 57 01 A9 F4 4F 02 A9 FD 7B 03 A9").unwrap(),
                            /*
                              Added for 8.8.90.893
                              stp x23, x22, [sp, #-0x30]!
                              stp x21, x20, [sp, #0x10]
                              stp x19, x30, [sp, #0x20]
                            */
                            scanner::Signature::from_ida_style("F7 5B BD A9 F5 53 01 A9 F3 7B 02 A9").unwrap(),
                            /*
                              Added for 8.9.6.458
                              stp x30, x23, [sp, #-0x30]!
                              stp x22, x21, [sp, #0x10]
                              stp x20, x19, [sp, #0x20]
                            */
                            scanner::Signature::from_ida_style("FE 5F BD A9 F6 57 01 A9 F4 4F 02 A9").unwrap(),
                        ],
                    ),
                ]);
            }

            let binary = args.get_one::<String>("binary").unwrap();
            let binary_path = PathBuf::from(binary).canonicalize().unwrap();
            let binary_filename = binary_path.file_name().unwrap().to_str().unwrap();

            println!("Target: android");
            println!("Executable: {}", executable);
            println!("Binary: {}", binary_path.display());

            let binary_data = std::fs::read(&binary_path).unwrap();
            let mut elf_file = elf::ElfBytes::<elf::endian::NativeEndian>::minimal_parse(&binary_data).unwrap();
            let relocations = parse_elf_relocations(&mut elf_file);

            match elf_file.ehdr.e_machine {
                JNI_X86 => {
                    if elf_file.ehdr.class != elf::file::Class::ELF32 {
                        eprintln!("Expected x86 to be 32 bit");
                        return None;
                    }
                    if elf_file.ehdr.endianness != elf::endian::LittleEndian {
                        eprintln!("Expected x86 to be little endian");
                        return None;
                    }
                    println!("Detected JNI for x86");
                },
                JNI_X86_64 => {
                    if elf_file.ehdr.class != elf::file::Class::ELF64 {
                        eprintln!("Expected x86_64 to be 64 bit");
                        return None;
                    }
                    if elf_file.ehdr.endianness != elf::endian::LittleEndian {
                        eprintln!("Expected x86_64 to be little endian");
                        return None;
                    }
                    println!("Detected JNI for x86_64");
                },
                JNI_ARMEABI_V7A => {
                    if elf_file.ehdr.class != elf::file::Class::ELF32 {
                        eprintln!("Expected armeabi-v7a to be 32 bit");
                        return None;
                    }
                    if elf_file.ehdr.endianness != elf::endian::LittleEndian {
                        eprintln!("Expected armeabi-v7a to be little endian");
                        return None;
                    }
                    println!("Detected JNI for armeabi-v7a");
                },
                JNI_ARM64_V8A => {
                    if elf_file.ehdr.class != elf::file::Class::ELF64 {
                        eprintln!("Expected arm64-v8a to be 64 bit");
                        return None;
                    }
                    if elf_file.ehdr.endianness != elf::endian::LittleEndian {
                        eprintln!("Expected arm64-v8a to be little endian");
                        return None;
                    }
                    println!("Detected JNI for arm64-v8a");
                },
                _ => {
                    eprintln!("Unknown JNI target {}", elf_file.ehdr.e_machine);
                    return None;
                },
            }

            // Same as on Linux, the server key is in .rodata and there is only one instance with no wildcards
            let rodata_header =
                elf_file.section_header_by_name(".rodata").unwrap().expect("Failed to find .rodata section");
            let rodata_start = rodata_header.sh_offset as usize;
            let rodata_end = rodata_start + rodata_header.sh_size as usize;
            let rodata_section = &binary_data[rodata_start..rodata_end];
            let server_key_offsets =
                SERVER_PUBLIC_KEY_SIGNATURE.scan_with_offset(rodata_section, rodata_header.sh_offset as usize);
            if server_key_offsets.is_empty() {
                eprintln!("Failed to find server public key");
                return None;
            }
            for server_key_offset in server_key_offsets {
                let relocated_offset = calculate_relocated_offset(&relocations, server_key_offset);
                let relocated_address = calculate_relocated_address(&relocations, server_key_offset);
                println!(
                    "Found server public key at {}:{:#012x} Offset: {:#012x} Address: {:#012x}",
                    binary_filename, server_key_offset, relocated_offset, relocated_address
                );
                offsets.server_public_key_offset = relocated_offset;
            }

            let text_header = elf_file.section_header_by_name(".text").unwrap().expect("Failed to find .text section");
            let text_start = text_header.sh_offset as usize;
            let text_end = text_start + text_header.sh_size as usize;
            let text_section = &binary_data[text_start..text_end];
            let shannon_constant_signatures = JNI_SHANNON_CONSTANTS.get(&elf_file.ehdr.e_machine).unwrap();
            let shannon_constant_offsets = scan_multiple(shannon_constant_signatures, text_section, text_header.sh_offset as usize);
            if shannon_constant_offsets.is_empty() {
                eprintln!("Failed to find shannon constant");
                return None;
            }
            for shannon_constant_offset in &shannon_constant_offsets {
                let relocated_offset = calculate_relocated_offset(&relocations, *shannon_constant_offset);
                let relocated_address = calculate_relocated_address(&relocations, *shannon_constant_offset);
                println!(
                    "Found shannon constant at {}:{:#012x} Offset: {:#012x} Address: {:#012x}",
                    binary_filename, shannon_constant_offset, relocated_offset, relocated_address
                );
            }

            // Same as for Linux, shn_encrypt, shn_decrypt and sometimes shn_finish all have the same prologue. We could
            // probably get away with shorter signatures but these work for now

            const SHANNON_PROLOGUE_SCAN_SIZE: usize = 0x2000;
            let last_shannon_constant = shannon_constant_offsets.last().unwrap();
            let shannon_prologue_scan_base = last_shannon_constant.saturating_sub(SHANNON_PROLOGUE_SCAN_SIZE);
            let shannon_prologue_scan_end = *last_shannon_constant;
            let shannon_prologue_scan_section = &binary_data[shannon_prologue_scan_base..shannon_prologue_scan_end];
            let shannon_prologue_signatures = JNI_SHANNON_PROLOGUES.get(&elf_file.ehdr.e_machine).unwrap();
            let mut shannon_prologue_offsets = VecDeque::from(multiple_sig_prologue_scan(
                shannon_prologue_signatures,
                shannon_prologue_scan_section,
                shannon_prologue_scan_base,
            ));
            if shannon_prologue_offsets.is_empty() {
                eprintln!("Failed to find shn_encrypt/shn_decrypt prologue");
                return None;
            }

            // We hit shn_finish
            if last_shannon_constant - shannon_prologue_offsets[0] < 0x200 {
                let relocated_shn_finish_offset = calculate_relocated_offset(&relocations, shannon_prologue_offsets[0]);
                let relocated_shn_finish_address =
                    calculate_relocated_address(&relocations, shannon_prologue_offsets[0]);
                println!(
                    "Found shn_finish at {}:{:#012x} Offset: {:#012x} Address: {:#012x}",
                    binary_filename,
                    shannon_prologue_offsets[0],
                    relocated_shn_finish_offset,
                    relocated_shn_finish_address
                );
                shannon_prologue_offsets.pop_front();
            }

            for shannon_prologue in &shannon_prologue_offsets {
                let relocated_prologue_offset = calculate_relocated_offset(&relocations, *shannon_prologue);
                let relocated_prologue_address = calculate_relocated_address(&relocations, *shannon_prologue);
                println!(
                    "Found function prologue at {}:{:#012x} Offset: {:#012x} Address: {:#012x}",
                    binary_filename, shannon_prologue, relocated_prologue_offset, relocated_prologue_address
                );
            }
            if shannon_prologue_offsets.len() < 2 {
                eprintln!("Found too few prologues");
                return None;
            }

            offsets.shannon_offset1 = calculate_relocated_offset(&relocations, shannon_prologue_offsets[0]);
            offsets.shannon_offset2 = calculate_relocated_offset(&relocations, shannon_prologue_offsets[1]);

            Some(offsets)
        },
        Target::IOS => {
            // Apps on iOS are distributed using .ipa files which are zip archives. When downloaded from the App Store
            // APIs directly they are encrypted and must be decrypted by a device running iOS or macOS. There are
            // various tools that allow this, mostly using mremap_encrypted. Alternatively the decrypted file can be
            // copied from an iOS device using frida-ios-dump or similar. an encrypted IPA will decrypt properly but the
            // Spotify binary will be encrypted and useless to us.
            //
            // After unzipping the .ipa file there will be a "Payload" folder which contains a "Spotify.app" folder
            // which itself contains the "Spotify" binary. This is a Mach-O executable which contains all the stuff
            // we're interested in. Mach-O files are a container for executables and other compiled code and have the
            // same purpose as Unix's ELF files. They support multiple architectures, which means one file may contain
            // code for armv7 and armv8, each with different offsets. To account for this we require an extra command
            // line flag to specify which architecture should be used.
            //
            // Once we have the image to parse, we read the header magic to determine the bitness and endianness. We
            // then read the rest of the file header to get the CPU type and the number of load commands. Load commands
            // are used to describe segments in the file which we need because some of the segments will be loaded into
            // virtual memory. Using the load commands we can compute our relocation entries and if we parse LC_SEGMENT/
            // LC_SEGMENT64 we can find the sections of the file which can be used to optimise signature scanning

            lazy_static! {
                static ref SHANNON_CONSTANTS: HashMap<&'static str, scanner::Signature> = HashMap::from([
                    /*
                      Constant is embedded after function, and is loaded using offset from PC
                      000FE750 C4 10 9F E5    ldr r1, [pc, #0xc4]
                      000FE754 82 01 20 E0    eor r0, r0, r2, lsl #3
                      ...
                      000FE81C 3A C5 96 69    0x6996C53A
                    */
                    ("armv6", scanner::Signature::from_ida_style("3A C5 96 69").unwrap()),
                    /*
                      Registers don't seem to change, might need updating
                      movw r1, #0xc53a
                      movt r1, #0x6996
                    */
                    ("armv7", scanner::Signature::from_ida_style("4C F2 3A 51 C6 F6 96 11").unwrap()),
                    /*
                      Registers can change, so use wildcards
                      movz w10, #0xc53a
                      movk w10, #0x6996, lsl #16
                    */
                    ("arm64", scanner::Signature::from_ida_style("?? A7 98 52 ?? 32 AD 72").unwrap()),
                ]);
                static ref SHANNON_PROLOGUES: HashMap<&'static str, scanner::Signature> = HashMap::from([
                    /*
                      push {r4, r5, r6, r7, lr}
                      add  r7, sp, #0xc
                      push {r8, sl, fp}
                      sub  sp, sp, #8
                      mov  r4, r0
                    */
                    (
                        "armv6",
                        scanner::Signature::from_ida_style("F0 40 2D E9 0C 70 8D E2 00 0D 2D E9 08 D0 4D E2 00 40 A0 E1")
                            .unwrap(),
                    ),
                    /*
                      push   {r4, r5, r6, r7, lr}
                      add    r7, sp, #0xc
                      push.w {r8, sl, fp}
                      sub    sp, #8
                    */
                    ("armv7", scanner::Signature::from_ida_style("F0 B5 03 AF 2D E9 00 0D 82 B0").unwrap()),
                    /*
                      stp x26, x25, [sp, #-0x50]!
                      stp x24, x23, [sp, #0x10]
                      stp x22, x21, [sp, #0x20]
                      stp x20, x19, [sp, #0x30]
                      stp x29, x30, [sp, #0x40]
                      add x29, sp, #0x40
                    */
                    (
                        "arm64",
                        scanner::Signature::from_ida_style(
                            "FA 67 BB A9 F8 5F 01 A9 F6 57 02 A9 F4 4F 03 A9 FD 7B 04 A9 FD 03 01 91",
                        )
                        .unwrap(),
                    ),
                ]);
            }

            let binary = args.get_one::<String>("binary").unwrap();
            let binary_path = PathBuf::from(binary).canonicalize().unwrap();
            let binary_filename = binary_path.file_name().unwrap().to_str().unwrap();
            let target_arch = args.get_one::<String>("macho-architecture");

            println!("Target: ios");
            println!("Executable: {}", executable);
            println!("Binary: {}", binary_path.display());

            let mut binary_data = std::fs::read(binary_path.clone()).unwrap();
            let mut binary_data_cursor = Cursor::new(&mut binary_data);
            let binary_file = mach_object::OFile::parse(&mut binary_data_cursor).expect("Failed to parse Mach-O file");
            if let Some(scannable_file) = find_macho_file(target_arch, &binary_file) {
                if SHANNON_CONSTANTS.get(scannable_file.arch).is_none()
                    || SHANNON_PROLOGUES.get(scannable_file.arch).is_none()
                {
                    eprintln!("Architecture {} is not supported", scannable_file.arch);
                    return None;
                }

                match scannable_file.file {
                    mach_object::OFile::MachFile { commands, header } => {
                        match header.magic {
                            mach_object::MH_MAGIC => {
                                println!("Detected Mach-O image as 32-bit Little Endian");
                                println!(
                                    "Found Mach-O file header for {} with {} load commands",
                                    scannable_file.arch, header.ncmds
                                );
                            },
                            mach_object::MH_CIGAM => {
                                println!("Detected Mach-O image as 32-bit Big Endian");
                                eprintln!("No implementation for 32-bit Big Endian Mach-O");
                                return None;
                            },
                            mach_object::MH_MAGIC_64 => {
                                println!("Detected Mach-O image as 64-bit Little Endian");
                                println!(
                                    "Found Mach-O file header for {} with {} load commands",
                                    scannable_file.arch, header.ncmds
                                );
                            },
                            mach_object::MH_CIGAM_64 => {
                                println!("Detected Mach-O image as 64-bit Big Endian");
                                eprintln!("No implementation for 64-bit Big Endian Mach-O");
                                return None;
                            },
                            _ => {
                                eprintln!("Unsupported Mach-O magic {:0x}", header.magic);
                                return None;
                            },
                        }

                        let relocations = parse_mach_o_relocations(commands);
                        let sections = {
                            let mut sections = vec![];
                            for command in commands {
                                match &command.0 {
                                    mach_object::LoadCommand::Segment {
                                        sections: segment_sections,
                                        ..
                                    } => {
                                        sections.extend(segment_sections.to_vec());
                                    },
                                    mach_object::LoadCommand::Segment64 {
                                        sections: segment_sections,
                                        ..
                                    } => {
                                        sections.extend(segment_sections.to_vec());
                                    },
                                    _ => {},
                                }
                            }
                            sections
                        };

                        let const_header = sections.iter().find(|&x| x.sectname == "__const");
                        if const_header.is_none() {
                            eprintln!("Failed to find __const section");
                            return None;
                        }
                        let const_header = const_header.unwrap();
                        let const_start = scannable_file.offset as usize + const_header.offset as usize;
                        let const_end = const_start + const_header.size;
                        let const_section = &binary_data[const_start..const_end];
                        let server_key_offsets =
                            SERVER_PUBLIC_KEY_SIGNATURE.scan_with_offset(const_section, const_header.offset as usize);
                        if server_key_offsets.is_empty() {
                            eprintln!("Failed to find server public key");
                            return None;
                        }
                        for server_key_offset in server_key_offsets {
                            let relocated_offset = calculate_relocated_offset(&relocations, server_key_offset);
                            let relocated_address = calculate_relocated_address(&relocations, server_key_offset);
                            println!(
                                "Found server public key at {}:{:#012x} Offset: {:#012x} Address: {:#012x}",
                                binary_filename,
                                server_key_offset + scannable_file.offset as usize,
                                relocated_offset,
                                relocated_address
                            );
                            offsets.server_public_key_offset = relocated_offset;
                        }

                        let text_header = sections.iter().find(|&x| x.sectname == "__text");
                        if text_header.is_none() {
                            eprintln!("Failed to find __text section");
                            return None;
                        }
                        let text_header = text_header.unwrap();
                        let text_start = scannable_file.offset as usize + text_header.offset as usize;
                        let text_end = text_start + text_header.size;
                        let text_section = &binary_data[text_start..text_end];
                        let shannon_constant_signature = SHANNON_CONSTANTS.get(scannable_file.arch).unwrap();
                        let shannon_constant_offsets =
                            shannon_constant_signature.scan_with_offset(text_section, text_header.offset as usize);
                        if shannon_constant_offsets.is_empty() {
                            eprintln!("Failed to find shannon constant");
                            return None;
                        }
                        for shannon_constant_offset in &shannon_constant_offsets {
                            let relocated_offset = calculate_relocated_offset(&relocations, *shannon_constant_offset);
                            let relocated_address = calculate_relocated_address(&relocations, *shannon_constant_offset);
                            println!(
                                "Found shannon constant at {}:{:#012x} Offset: {:#012x} Address: {:#012x}",
                                binary_filename,
                                shannon_constant_offset + scannable_file.offset as usize,
                                relocated_offset,
                                relocated_address
                            );
                        }

                        // shn_finish seems to contain the last instance of the constant however on arm64 it contains
                        // the second instance of six. The encryption/decryption functions are normally above shn_finish
                        // however on arm64 one was above and one was below with some small functions separating them.
                        // The only reliable way to always find the functions is to check before and after all
                        // occurrences of the constant

                        let mut push_offset = |offset: usize| -> bool {
                            if offsets.shannon_offset1 > 0 {
                                if offsets.shannon_offset1 == offset {
                                    false
                                } else {
                                    offsets.shannon_offset2 = offset;
                                    true
                                }
                            } else {
                                offsets.shannon_offset1 = offset;
                                false
                            }
                        };
                        let shannon_prologue_signature = SHANNON_PROLOGUES.get(scannable_file.arch).unwrap();
                        const SHANNON_PROLOGUE_SCAN_SIZE: usize = 0x2000;
                        for shannon_constant_offset in shannon_constant_offsets.iter().rev() {
                            // Scan above
                            let shannon_prologue_scan_offset =
                                shannon_constant_offset.saturating_sub(SHANNON_PROLOGUE_SCAN_SIZE);
                            let shannon_prologue_scan_base =
                                shannon_prologue_scan_offset + scannable_file.offset as usize;
                            let shannon_prologue_scan_end = *shannon_constant_offset;
                            let shannon_prologue_scan_section =
                                &binary_data[shannon_prologue_scan_base..shannon_prologue_scan_end];
                            let shannon_prologue_offsets = shannon_prologue_signature
                                .reverse_scan_with_offset(shannon_prologue_scan_section, shannon_prologue_scan_offset);
                            if !shannon_prologue_offsets.is_empty() {
                                let first_prologue_offset = shannon_prologue_offsets[0];
                                let first_prologue_relocated_offset =
                                    calculate_relocated_offset(&relocations, first_prologue_offset);
                                let first_prologue_relocated_address =
                                    calculate_relocated_address(&relocations, first_prologue_offset);
                                println!(
                                    "Found function prologue at {}:{:#012x} Offset: {:#012x} Address: {:#012x}",
                                    binary_filename,
                                    first_prologue_offset + scannable_file.offset as usize,
                                    first_prologue_relocated_offset,
                                    first_prologue_relocated_address
                                );
                                if push_offset(first_prologue_relocated_offset) {
                                    return Some(offsets);
                                }
                                let shannon_prologue_scan_offset =
                                    first_prologue_offset.saturating_sub(SHANNON_PROLOGUE_SCAN_SIZE);
                                let shannon_prologue_scan_base =
                                    shannon_prologue_scan_offset + scannable_file.offset as usize;
                                let shannon_prologue_scan_end = first_prologue_offset + scannable_file.offset as usize;
                                let shannon_prologue_scan_section =
                                    &binary_data[shannon_prologue_scan_base..shannon_prologue_scan_end];
                                let shannon_prologue_offsets = shannon_prologue_signature.reverse_scan_with_offset(
                                    shannon_prologue_scan_section,
                                    shannon_prologue_scan_offset,
                                );
                                if !shannon_prologue_offsets.is_empty() {
                                    let first_prologue_offset = shannon_prologue_offsets[0];
                                    let first_prologue_relocated_offset =
                                        calculate_relocated_offset(&relocations, first_prologue_offset);
                                    let first_prologue_relocated_address =
                                        calculate_relocated_address(&relocations, first_prologue_offset);
                                    println!(
                                        "Found function prologue at {}:{:#012x} Offset: {:#012x} Address: {:#012x}",
                                        binary_filename,
                                        first_prologue_offset + scannable_file.offset as usize,
                                        first_prologue_relocated_offset,
                                        first_prologue_relocated_address
                                    );
                                    if push_offset(first_prologue_relocated_offset) {
                                        return Some(offsets);
                                    }
                                }
                            }

                            // Scan below
                            let shannon_prologue_scan_offset = *shannon_constant_offset;
                            let shannon_prologue_scan_base =
                                shannon_prologue_scan_offset + scannable_file.offset as usize;
                            let shannon_prologue_scan_end = std::cmp::min(
                                shannon_prologue_scan_base + SHANNON_PROLOGUE_SCAN_SIZE,
                                binary_data.len(),
                            );
                            let shannon_prologue_scan_section =
                                &binary_data[shannon_prologue_scan_base..shannon_prologue_scan_end];
                            let shannon_prologue_offsets = shannon_prologue_signature
                                .scan_with_offset(shannon_prologue_scan_section, shannon_prologue_scan_offset);
                            if !shannon_prologue_offsets.is_empty() {
                                let first_prologue_offset = shannon_prologue_offsets[0];
                                let first_prologue_relocated_offset =
                                    calculate_relocated_offset(&relocations, first_prologue_offset);
                                let first_prologue_relocated_address =
                                    calculate_relocated_address(&relocations, first_prologue_offset);
                                println!(
                                    "Found function prologue at {}:{:#012x} Offset: {:#012x} Address: {:#012x}",
                                    binary_filename,
                                    first_prologue_offset + scannable_file.offset as usize,
                                    first_prologue_relocated_offset,
                                    first_prologue_relocated_address
                                );
                                if push_offset(first_prologue_relocated_offset) {
                                    return Some(offsets);
                                }
                                let shannon_prologue_scan_offset = first_prologue_offset;
                                let shannon_prologue_scan_base =
                                    shannon_prologue_scan_offset + scannable_file.offset as usize;
                                let shannon_prologue_scan_end = std::cmp::min(
                                    shannon_prologue_scan_base + SHANNON_PROLOGUE_SCAN_SIZE,
                                    binary_data.len(),
                                );
                                let shannon_prologue_scan_section =
                                    &binary_data[shannon_prologue_scan_base..shannon_prologue_scan_end];
                                let shannon_prologue_offsets = shannon_prologue_signature
                                    .scan_with_offset(shannon_prologue_scan_section, shannon_prologue_scan_offset);
                                if !shannon_prologue_offsets.is_empty() {
                                    let first_prologue_offset = shannon_prologue_offsets[0];
                                    let first_prologue_relocated_offset =
                                        calculate_relocated_offset(&relocations, first_prologue_offset);
                                    let first_prologue_relocated_address =
                                        calculate_relocated_address(&relocations, first_prologue_offset);
                                    println!(
                                        "Found function prologue at {}:{:#012x} Offset: {:#012x} Address: {:#012x}",
                                        binary_filename,
                                        first_prologue_offset + scannable_file.offset as usize,
                                        first_prologue_relocated_offset,
                                        first_prologue_relocated_address
                                    );
                                    if push_offset(first_prologue_relocated_offset) {
                                        return Some(offsets);
                                    }
                                }
                            }
                        }

                        None
                    },
                    _ => None,
                }
            } else {
                None
            }
        },
    }
}
