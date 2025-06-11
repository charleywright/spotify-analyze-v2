// The CLI injects a script before this which sets the configuration
const TARGET_IP = (globalThis as any).TARGET_IP || "127.0.0.1";
const TARGET_PORT = (globalThis as any).TARGET_PORT || 4070;
const OUR_SERVER_KEY = (globalThis as any).OUR_SERVER_KEY || [
  0x94, 0x8f, 0x67, 0xa9, 0x51, 0xd7, 0x5f, 0x38, 0xa4, 0x36, 0x19, 0x11, 0x28,
  0x32, 0xad, 0x49, 0x33, 0xdd, 0x00, 0xf5, 0xdd, 0x24, 0xe6, 0xb9, 0x10, 0xed,
  0xd3, 0x8c, 0xcd, 0xd0, 0x0a, 0x3d, 0x77, 0x30, 0x8f, 0x91, 0x7c, 0x96, 0x43,
  0xbe, 0x2b, 0x17, 0x7d, 0x2a, 0x4f, 0xaf, 0x7d, 0xdb, 0x35, 0xd4, 0xe5, 0x41,
  0x8a, 0x33, 0x18, 0xd1, 0x2c, 0x00, 0xe6, 0x07, 0xf4, 0xd3, 0xc6, 0xd4, 0x1f,
  0xc8, 0xd6, 0xf5, 0x26, 0x16, 0x59, 0xea, 0x71, 0x32, 0xec, 0xda, 0xeb, 0x0f,
  0x55, 0x70, 0xd0, 0x98, 0x21, 0x57, 0x6b, 0x87, 0x1a, 0x03, 0x64, 0x2c, 0x8c,
  0xe1, 0x3c, 0x8e, 0xa8, 0x02, 0x7c, 0x8a, 0x1b, 0x9a, 0xe9, 0xcc, 0x36, 0x7d,
  0x9c, 0x3f, 0xbf, 0x02, 0xc6, 0x7f, 0xc1, 0x6f, 0x46, 0x54, 0x5b, 0xe6, 0x95,
  0x05, 0x6e, 0x6b, 0x2b, 0x66, 0x0e, 0x4f, 0xae, 0xc2, 0xe7, 0x4a, 0xc1, 0x43,
  0x87, 0xa4, 0xf9, 0x56, 0x24, 0xda, 0x87, 0x3f, 0x78, 0x9a, 0x13, 0x55, 0x1f,
  0x32, 0x51, 0x93, 0x36, 0x1e, 0xa9, 0xf2, 0xee, 0x3a, 0xc8, 0xd2, 0x73, 0xd2,
  0x81, 0xa7, 0x6f, 0xfb, 0xe9, 0xbc, 0x87, 0xd7, 0x7d, 0xbd, 0xfb, 0xdf, 0x91,
  0xd5, 0x83, 0x76, 0xd3, 0x7c, 0x46, 0x8a, 0xd1, 0xc2, 0x73, 0x1c, 0x5e, 0xa1,
  0xa0, 0x9f, 0xf8, 0xc4, 0xaf, 0xcb, 0x8c, 0x7c, 0x86, 0x09, 0x8e, 0xd7, 0xc8,
  0x51, 0xc7, 0x2d, 0xac, 0x61, 0x37, 0x3b, 0x84, 0xa8, 0x4f, 0x7a, 0x76, 0x17,
  0x2d, 0x88, 0xf3, 0x16, 0x7f, 0x73, 0x83, 0x38, 0x86, 0x09, 0xe1, 0xcd, 0xe1,
  0x89, 0x3d, 0x9d, 0x91, 0x61, 0x6c, 0xb4, 0x5f, 0x4c, 0xf4, 0x93, 0x6d, 0xa8,
  0x42, 0xa2, 0x4b, 0xf6, 0xf1, 0x82, 0x1e, 0xcc, 0x05, 0xd2, 0x10, 0xff, 0xd3,
  0x9f, 0xe9, 0x12, 0x05, 0x3a, 0x0c, 0x0c, 0xa6, 0x93,
];

// Actual logic begins here. The basic idea of this script is as follows:
// 1. Trigger a platform-specific entrypoint
// 2. Locate and parse the correct binary for that platform
// 3. Extract the file-to-memory mapping for that binary
// 4. Find the section that contains the server key then use the file-to-memory mapping to find it in memory
// 5. Scan that section for the server key, if not found fall back to scanning the whole binary
// This gives us a potential speedup of 100x over scanning the whole binary
import { DosHeader, PEHeader, OptionalHeader, SectionHeader } from "./pe.js";
import { ElfEndianReader, ElfHeader, ElfSegment, ElfSection } from "./elf.js";
import {
  MachOHeader,
  MachOLoadCommand,
  MachOSegmentLoadCommand,
} from "./macho.js";

const SCRIPT_START = Date.now();
const AP_PORTS = [80, 443, 4070]; // The app will try these without modification
const AP_SERVER_KEY =
  "ac e0 46 0b ff c2 30 af f4 6b fe c3 bf bf 86 3d a1 91 c6 cc 33 6c 93 a1 4f b3 b0 16 12 ac ac 6a f1 80 e7 f6 14 d9 42 9d be 2e 34 66 43 e3 62 d2 32 7a 1a 0d 92 3b ae dd 14 02 b1 81 55 05 61 04 d5 2c 96 a4 4c 1e cc 02 4a d4 b2 0c 00 1f 17 ed c2 2f c4 35 21 c8 f0 cb ae d2 ad d7 2b 0f 9d b3 c5 32 1a 2a fe 59 f3 5a 0d ac 68 f1 fa 62 1e fb 2c 8d 0c b7 39 2d 92 47 e3 d7 35 1a 6d bd 24 c2 ae 25 5b 88 ff ab 73 29 8a 0b cc cd 0c 58 67 31 89 e8 bd 34 80 78 4a 5f c9 6b 89 9d 95 6b fc 86 d7 4f 33 a6 78 17 96 c9 c3 2d 0d 32 a5 ab cd 05 27 e2 f7 10 a3 96 13 c4 2f 99 c0 27 bf ed 04 9c 3c 27 58 04 b6 b2 19 f9 c1 2f 02 e9 48 63 ec a1 b6 42 a0 9d 48 25 f8 b3 9d d0 e8 6a f9 48 4d a1 c2 ba 86 30 42 ea 9d b3 08 6c 19 0e 48 b3 9d 66 eb 00 06 a2 5a ee a1 1b 13 87 3c d7 19 e6 55 bd";
const AP_SERVER_KEY_LEN = 256;
const APRESOLVE_OVERRIDE = "dont.resolve.scdn.co"; // Spotify don't own scdn.com
const PLATFORM_CHECK_INTERVAL = 10; // ms

type RelocationEntry = {
  offset_in_file: UInt64;
  size_in_file: UInt64;
  offset_in_memory: UInt64;
  size_in_memory: UInt64;
};
function calculateRelocatedOffset(
  relocations: Array<RelocationEntry>,
  position: UInt64
): UInt64 {
  for (const relocation of relocations) {
    if (
      position >= relocation.offset_in_file &&
      position < relocation.offset_in_file.add(relocation.size_in_file)
    ) {
      const offset_from_segment = position.sub(relocation.offset_in_file);
      const offset_from_base = relocation.offset_in_memory.sub(
        relocations[0].offset_in_memory
      );
      return offset_from_base.add(offset_from_segment);
    }
  }
  return position;
}

function replaceServerKey(locations: MemoryScanMatch[]) {
  for (const location of locations) {
    console.log(
      `Found server key at ${DebugSymbol.fromAddress(
        location.address
      )}\n${hexdump(location.address, { length: AP_SERVER_KEY_LEN })}`
    );
    Memory.patchCode(location.address, AP_SERVER_KEY_LEN, (location) =>
      location.writeByteArray(OUR_SERVER_KEY)
    );
    console.log(
      `Replaced server key\n${hexdump(location.address, {
        length: AP_SERVER_KEY_LEN,
      })}`
    );
  }
}

function replaceServerKeyWin32(module: Module) {
  const file = new File(module.path, "rb");

  const header_buffer = file.readBytes(DosHeader.SIZE);
  const header = new DosHeader(header_buffer.unwrap());
  console.log(header);
  if (!header.isValid()) {
    console.error(
      `Read invalid DOS header from ${module.path}:\n${hexdump(header_buffer)}`
    );
    return;
  }

  file.seek(header.pe_header_offset);
  const pe_header_buffer = file.readBytes(PEHeader.SIZE);
  const pe_header = new PEHeader(pe_header_buffer.unwrap());
  console.log(pe_header);
  if (!pe_header.isValid()) {
    console.error(
      `Read invalid PE header from ${module.path}:\n${hexdump(
        pe_header_buffer
      )}`
    );
    return;
  }

  const optional_header_buffer = file.readBytes(pe_header.optional_header_size);
  const optional_header = new OptionalHeader(optional_header_buffer.unwrap());
  console.log(optional_header);
  if (!optional_header.isValid()) {
    console.error(
      `Read invalid optional header from ${module.path}:\n${hexdump(
        optional_header_buffer
      )}`
    );
    return;
  }

  let key_locations: MemoryScanMatch[] = [];
  for (let i = 0; i < pe_header.section_count; i++) {
    const section_header_buffer = file.readBytes(SectionHeader.SIZE);
    const section_header = new SectionHeader(section_header_buffer.unwrap());
    console.log(section_header);

    if (section_header.name === ".rdata") {
      // PE uses "RVA" values which don't include the image base, no need to calculate relocations
      const section_address = module.base.add(section_header.virtual_addr);
      console.log(
        `Found .rdata at {${section_address} ${
          module.name
        }+0x${section_header.virtual_addr.toString(16)}}`
      );
      key_locations = Memory.scanSync(
        section_address,
        section_header.virtual_size,
        AP_SERVER_KEY
      );
    }
  }

  if (key_locations.length === 0) {
    console.warn(
      "Failed to find server key in .rdata section, falling back to slower module scan"
    );
    key_locations = Memory.scanSync(module.base, module.size, AP_SERVER_KEY);
  }
  replaceServerKey(key_locations);
}

function replaceServerKeyLinux(module: Module) {
  const file = new File(module.path, "rb");

  // Actual header is 52 bytes (32-bit) or 64 bytes (64-bit)
  const header_buffer = file.readBytes(64);
  const header = new ElfHeader(header_buffer.unwrap());
  if (!header.isValid()) {
    console.error(
      `Read invalid ELF header from ${module.path}:\n${hexdump(header_buffer)}`
    );
    return;
  }

  const PH_SIZE_64 = 56;
  const PH_SIZE_32 = 32;
  if (Process.pointerSize === 64 && header.e_phentsize != PH_SIZE_64) {
    console.error(
      `Failed to replace server key, expected program header size ${PH_SIZE_64} got ${header.e_phentsize}`
    );
    return;
  } else if (Process.pointerSize === 32 && header.e_phentsize != PH_SIZE_32) {
    console.error(
      `Failed to replace server key, expected program header size ${PH_SIZE_32} got ${header.e_phentsize}`
    );
    return;
  }
  const ph_start = header.e_phoff;
  const ph_len = header.e_phnum * header.e_phentsize;
  file.seek(ph_start.toNumber());
  const ph_buffer = file.readBytes(ph_len);

  let program_headers = [];
  for (let i = 0; i < header.e_phnum; i++) {
    let header_addr = ph_buffer.unwrap().add(i * header.e_phentsize);
    const phdr = new ElfSegment(
      new ElfEndianReader(header.e_ident, header_addr)
    );
    program_headers.push(phdr);
  }
  program_headers.forEach((phdr) => console.log(phdr));

  const SH_SIZE_64 = 64;
  const SH_SIZE_32 = 40;
  if (Process.pointerSize === 64 && header.e_shentsize != SH_SIZE_64) {
    console.error(
      `Failed to replace server key, expected section header size ${SH_SIZE_64} got ${header.e_shentsize}`
    );
    return;
  } else if (Process.pointerSize === 32 && header.e_shentsize != SH_SIZE_32) {
    console.error(
      `Failed to replace server key, expected section header size ${SH_SIZE_32} got ${header.e_shentsize}`
    );
    return;
  }
  const sh_start = header.e_shoff;
  const sh_len = header.e_shnum * header.e_shentsize;
  file.seek(sh_start.toNumber());
  const sh_buffer = file.readBytes(sh_len);
  let section_headers = [];
  for (let i = 0; i < header.e_shnum; i++) {
    let header_addr = sh_buffer.unwrap().add(i * header.e_shentsize);
    const shdr = new ElfSection(
      new ElfEndianReader(header.e_ident, header_addr)
    );
    section_headers.push(shdr);
  }

  let string_table_idx = header.e_shstrndx;
  if (string_table_idx === 0xffff) {
    string_table_idx = section_headers[0].sh_link;
  }
  if (string_table_idx >= section_headers.length) {
    console.error(
      `String table index ${string_table_idx} is out of bounds of section headers (${section_headers.length})`
    );
    return;
  }
  const string_table_header = section_headers[string_table_idx];
  file.seek(string_table_header.sh_offset.toNumber());
  const string_table_buffer = file.readBytes(
    string_table_header.sh_size.toNumber()
  );
  section_headers.forEach((shdr) =>
    shdr.setStringTableAddr(string_table_buffer.unwrap())
  );
  section_headers.forEach((shdr) => console.log(shdr));

  const relocations: RelocationEntry[] = program_headers
    .filter((phdr) => phdr.p_type === ElfSegment.PT_LOAD)
    .map((phdr) => ({
      offset_in_file: phdr.p_offset,
      size_in_file: phdr.p_filesz,
      offset_in_memory: phdr.p_vaddr,
      size_in_memory: phdr.p_memsz,
    }));

  let key_locations: MemoryScanMatch[] = [];
  for (const shdr of section_headers) {
    if (shdr.getName() === ".rodata") {
      const section_offset = calculateRelocatedOffset(
        relocations,
        shdr.sh_offset
      );
      const section_address = module.base.add(section_offset);
      console.log(
        `Found .rodata at ${DebugSymbol.fromAddress(section_address)}`
      );
      key_locations = key_locations.concat(
        Memory.scanSync(section_address, shdr.sh_size, AP_SERVER_KEY)
      );
    }
  }
  if (key_locations.length === 0) {
    console.warn(
      "Failed to find server key in .rodata section, falling back to slower module scan"
    );
    key_locations = Memory.scanSync(module.base, module.size, AP_SERVER_KEY);
  }
  replaceServerKey(key_locations);
}

function replaceDarwinServerKey(module: Module) {
  const file = new File(module.path, "rb");

  const header_buffer = file.readBytes(32);
  const header = new MachOHeader(header_buffer.unwrap());
  console.log(header);

  let key_locations: MemoryScanMatch[] = [];
  if (header.isValid()) {
    file.seek(header.size());
    const load_commands_buffer = file.readBytes(header.load_commands_size);
    let relocations: RelocationEntry[] = [];
    let const_section = null;
    for (let offset = 0; offset < load_commands_buffer.byteLength; ) {
      const cmd = new MachOLoadCommand(
        load_commands_buffer.unwrap().add(offset)
      );
      if (
        cmd.type === MachOLoadCommand.LC_SEGMENT32 ||
        cmd.type === MachOLoadCommand.LC_SEGMENT64
      ) {
        const segment_header = new MachOSegmentLoadCommand(
          load_commands_buffer.unwrap().add(offset)
        );
        console.log(segment_header);

        if (segment_header.name !== "__PAGEZERO") {
          relocations.push({
            offset_in_file: segment_header.file_offset,
            size_in_file: segment_header.file_size,
            offset_in_memory: segment_header.memory_offset,
            size_in_memory: segment_header.memory_size,
          });
        }

        for (const section of segment_header.sections) {
          console.log(` -> ${section}`);
          if (section.name === "__const" && section.segment === "__TEXT") {
            const_section = section;
          }
        }
      }
      offset += cmd.size;
    }

    if (const_section !== null) {
      const const_offset = calculateRelocatedOffset(
        relocations,
        uint64(const_section.offset)
      );
      const const_address = module.base.add(const_offset);
      console.log(`Found __const at ${DebugSymbol.fromAddress(const_address)}`);
      key_locations = key_locations.concat(
        Memory.scanSync(const_address, const_section.size, AP_SERVER_KEY)
      );
    }
  }

  if (key_locations.length === 0) {
    console.warn(
      "Failed to find server key in __const section, falling back to slower module scan"
    );
    key_locations = Memory.scanSync(module.base, module.size, AP_SERVER_KEY);
  }

  replaceServerKey(key_locations);
}

function stopAllPlatformChecks() {
  clearInterval(windows_check);
  clearInterval(linux_check);
  clearInterval(darwin_check);
  clearInterval(android_check);
}

const windows_check = setInterval(() => {
  const mod = Process.findModuleByName("Spotify.exe");
  if (mod !== null && Process.platform === "windows") {
    stopAllPlatformChecks();
    console.log(
      `\rFound windows desktop binary loaded at ${mod.base} from ${mod.path}`
    );
    replaceServerKeyWin32(mod);
    console.log(`[WINDOWS] Startup took ${Date.now() - SCRIPT_START}ms`);
  }
}, PLATFORM_CHECK_INTERVAL);

const linux_check = setInterval(() => {
  const mod = Process.findModuleByName("spotify");
  if (
    mod !== null &&
    Process.platform === "linux" &&
    mod.base.equals(0x200000)
  ) {
    stopAllPlatformChecks();
    console.log(`\rFound linux desktop binary loaded at ${mod.base}`);
    replaceServerKeyLinux(mod);
    console.log(`[LINUX] Startup took ${Date.now() - SCRIPT_START}ms`);
  }
}, PLATFORM_CHECK_INTERVAL);

const android_check = setInterval(() => {
  const mod = Process.findModuleByName("liborbit-jni-spotify.so");
  if (mod !== null && Process.platform === "linux") {
    stopAllPlatformChecks();
    console.log(`\rFound Android binary loaded at ${mod.base}`);
    replaceServerKeyLinux(mod);
    console.log(`[ANDROID] Startup took ${Date.now() - SCRIPT_START}ms`);
  }
}, PLATFORM_CHECK_INTERVAL);

const darwin_check = setInterval(() => {
  const mod = Process.findModuleByName("Spotify");
  if (mod !== null && Process.platform === "darwin") {
    stopAllPlatformChecks();
    console.log(`\rFound Darwin binary loaded at ${mod.base}`);
    replaceDarwinServerKey(mod);
    console.log(`[Darwin] Startup took ${Date.now() - SCRIPT_START}ms`);
  }
}, PLATFORM_CHECK_INTERVAL);

const getaddrinfoCheck = setInterval(() => {
  const libc = Process.findModuleByName("libc.so");
  if (libc === null) return;
  console.log(
    `[GETADDRINFO] Found libc at ${libc.base} loaded from ${libc.path}`
  );
  const getaddrinfo = libc.findExportByName("getaddrinfo");
  if (getaddrinfo === null) {
    console.error("[GETADDRINFO] Found libc but failed to find getaddrinfo");
    return;
  }
  console.log(
    `[GETADDRINFO] Found getaddrinfo at ${DebugSymbol.fromAddress(getaddrinfo)}`
  );
  clearInterval(getaddrinfoCheck);
  Interceptor.attach(getaddrinfo, {
    onEnter: function (args) {
      const node = args[0].readCString() || "";
      if (node.startsWith("apresolve")) {
        args[0].writeUtf8String(APRESOLVE_OVERRIDE);
        console.log(
          `getaddrinfo(${node}) -> getaddrinfo(${APRESOLVE_OVERRIDE})`
        );
      } else if (
        node.startsWith("ap.spotify.com") ||
        node.startsWith("mobile-ap.spotify.com") ||
        /ap-[a-z0-9]+\.spotify\.com/.test(node)
      ) {
        args[0].writeUtf8String(TARGET_IP);
        console.log(`getaddrinfo(${node}) -> getaddrinfo(${TARGET_IP})`);
      } else {
        // console.log(`getaddrinfo(node=${node})`);
      }
    },
  });
  if (!AP_PORTS.includes(TARGET_PORT)) {
    Interceptor.attach(Module.getExportByName(null, "connect"), {
      onEnter: function (args) {
        const addr = args[1];
        const sa_family = addr.add(0).readU16();
        switch (sa_family) {
          /* AF_INET */
          case 0x02: {
            const sin_port = (addr.add(2).readU8() << 8) | addr.add(3).readU8();
            const ip = [
              addr.add(4 + 0).readU8(),
              addr.add(4 + 1).readU8(),
              addr.add(4 + 2).readU8(),
              addr.add(4 + 3).readU8(),
            ].join(".");
            if (ip === TARGET_IP) {
              if (sin_port != TARGET_PORT) {
                addr.add(2).writeU8((TARGET_PORT >> 8) & 0xff);
                addr.add(3).writeU8((TARGET_PORT >> 0) & 0xff);
                console.log(
                  `connect(${ip}:${sin_port}) -> connect(${ip}:${TARGET_PORT})`
                );
              } else {
                console.log(`connect(${ip}:${sin_port})`);
              }
            }
          }
        }
      },
    });
  }
}, PLATFORM_CHECK_INTERVAL);
