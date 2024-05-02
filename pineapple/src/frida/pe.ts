export class DosHeader {
  public static SIZE: number = 64;

  public signature: number;
  public last_page_bytes_count: number;
  public pages_in_file: number;
  public relocation_count: number;
  public header_size_in_paragraphs: number;
  public min_extra_paragraphs: number;
  public max_extra_paragraphs: number;
  public initial_ss: number;
  public initial_sp: number;
  public checksum: number;
  public initial_ip: number;
  public initial_cs: number;
  public relocs_offset: number;
  public overlay_num: number;
  // 8 reserved bytes
  public oem_id: number;
  public oem_info: number;
  // 20 reserved bytes
  public pe_header_offset: number;

  constructor(ptr: NativePointer) {
    this.signature = ptr.add(0).readU16();
    this.last_page_bytes_count = ptr.add(2).readU16();
    this.pages_in_file = ptr.add(4).readU16();
    this.relocation_count = ptr.add(6).readU16();
    this.header_size_in_paragraphs = ptr.add(8).readU16();
    this.min_extra_paragraphs = ptr.add(10).readU16();
    this.max_extra_paragraphs = ptr.add(12).readU16();
    this.initial_ss = ptr.add(14).readU16();
    this.initial_sp = ptr.add(16).readU16();
    this.checksum = ptr.add(18).readU16();
    this.initial_ip = ptr.add(20).readU16();
    this.initial_cs = ptr.add(22).readU16();
    this.relocs_offset = ptr.add(24).readU16();
    this.overlay_num = ptr.add(26).readU16();

    this.oem_id = ptr.add(34).readU16();
    this.oem_info = ptr.add(36).readU16();

    this.pe_header_offset = ptr.add(60).readU32();
  }

  isValid(): boolean {
    return this.signature === 0x5a_4d;
  }

  toString(): string {
    return `DosHeader{signature=0x${this.signature.toString(
      16
    )} last_page_bytes_count=${this.last_page_bytes_count} pages_in_file=${
      this.pages_in_file
    } relocation_count=${
      this.relocation_count
    } header_size_in_paragraphs=0x${this.header_size_in_paragraphs.toString(
      16
    )} min_extra_paragraphs=${this.min_extra_paragraphs} max_extra_paragraphs=${
      this.max_extra_paragraphs
    } initial_ss=${this.initial_ss} initial_sp=${this.initial_sp} checksum=${
      this.checksum
    } initial_ip=${this.initial_ip} initial_cs=${
      this.initial_cs
    } relocs_offset=0x${this.relocs_offset.toString(16)} overlay_num=${
      this.overlay_num
    } oem_id=${this.oem_id} oem_info=${
      this.oem_info
    } pe_header=0x${this.pe_header_offset.toString(16)}}`;
  }
}

export class PEHeader {
  public static SIZE: number = 24;

  public magic: number;
  public machine: number;
  public section_count: number;
  public timestamp: number;
  public sym_table_addr: number;
  public sym_table_count: number;
  public optional_header_size: number;
  public characteristics: number;

  constructor(ptr: NativePointer) {
    this.magic = ptr.add(0).readU32();
    this.machine = ptr.add(4).readU16();
    this.section_count = ptr.add(6).readU16();
    this.timestamp = ptr.add(8).readU32();
    this.sym_table_addr = ptr.add(12).readU32();
    this.sym_table_count = ptr.add(16).readU32();
    this.optional_header_size = ptr.add(20).readU16();
    this.characteristics = ptr.add(22).readU16();
  }

  isValid(): boolean {
    return (
      this.magic === 0x45_50 &&
      this.optional_header_size === OptionalHeader.SIZE
    );
  }

  toString(): string {
    return `PeHeader{magic=0x${this.magic.toString(
      16
    )} machine=0x${this.machine.toString(16)} section_count=${
      this.section_count
    } timestamp=0x${this.timestamp.toString(
      16
    )} sym_table_addr=0x${this.sym_table_addr.toString(16)} sym_table_count=${
      this.sym_table_count
    } optional_header_size=${
      this.optional_header_size
    } characteristics=0x${this.characteristics.toString(16)}}`;
  }
}

export class OptionalHeader {
  public static SIZE: number = 240;

  public magic: number;
  public major_linker_version: number;
  public minor_linker_version: number;
  public size_of_code: number;
  public size_of_init_data: number;
  public size_of_uninit_data: number;
  public entry_point_addr: number;
  public base_of_code: number;
  public base_of_data: number | null;
  public image_base: UInt64;
  public section_alignment: number;
  public file_alignment: number;
  public major_os_version: number;
  public minor_os_version: number;
  public major_image_version: number;
  public minor_image_version: number;
  public major_subsystem_version: number;
  public minor_subsystem_version: number;
  public win32_version_value: number;
  public size_of_image: number;
  public size_of_headers: number;
  public checksum: number;
  public subsystem: number;
  public dll_characteristics: number;
  public size_of_stack_reserve: number;
  public size_of_stack_commit: number;
  public size_of_heap_reserve: number;
  public size_of_heap_commit: number;
  public loader_flags: number;
  public rva_and_sizes_count: number;

  constructor(ptr: NativePointer) {
    this.magic = ptr.add(0).readU16();
    this.major_linker_version = ptr.add(2).readU8();
    this.minor_linker_version = ptr.add(3).readU8();
    this.size_of_code = ptr.add(4).readU32();
    this.size_of_init_data = ptr.add(8).readU32();
    this.size_of_uninit_data = ptr.add(12).readU32();
    this.entry_point_addr = ptr.add(16).readU32();
    this.base_of_code = ptr.add(20).readU32();
    if (this.magic === 0x10b /* PE32 */) {
      this.base_of_data = ptr.add(24).readU32();
      this.image_base = uint64(ptr.add(28).readU32());
    } else {
      this.base_of_data = null;
      this.image_base = ptr.add(24).readU64();
    }
    this.section_alignment = ptr.add(32).readU32();
    this.file_alignment = ptr.add(36).readU32();
    this.major_os_version = ptr.add(40).readU16();
    this.minor_os_version = ptr.add(42).readU16();
    this.major_image_version = ptr.add(44).readU16();
    this.minor_image_version = ptr.add(46).readU16();
    this.major_subsystem_version = ptr.add(48).readU16();
    this.minor_subsystem_version = ptr.add(50).readU16();
    this.win32_version_value = ptr.add(52).readU32();
    this.size_of_image = ptr.add(56).readU32();
    this.size_of_headers = ptr.add(60).readU32();
    this.checksum = ptr.add(64).readU32();
    this.subsystem = ptr.add(68).readU16();
    this.dll_characteristics = ptr.add(70).readU16();
    this.size_of_stack_reserve = ptr.add(72).readU32();
    this.size_of_stack_commit = ptr.add(76).readU32();
    this.size_of_heap_reserve = ptr.add(80).readU32();
    this.size_of_heap_commit = ptr.add(84).readU32();
    this.loader_flags = ptr.add(88).readU32();
    this.rva_and_sizes_count = ptr.add(92).readU32();
  }

  isValid(): boolean {
    return this.magic === 0x10b || this.magic === 0x20b;
  }

  toString(): string {
    return `OptionalHeader{magic=0x${this.magic.toString(
      16
    )} major_linker_version=${this.major_linker_version} minor_linker_version=${
      this.minor_linker_version
    } size_of_code=${this.size_of_code} size_of_init_data=${
      this.size_of_init_data
    } size_of_uninit_data=${
      this.size_of_uninit_data
    } entry_point_addr=0x${this.entry_point_addr.toString(
      16
    )} base_of_code=0x${this.base_of_code.toString(16)} base_of_data=${
      this.base_of_data ? "0x" + this.base_of_data.toString(16) : "<null>"
    } image_base=0x${this.image_base.toString(
      16
    )} section_alignment=0x${this.section_alignment.toString(
      16
    )} file_alignment=0x${this.file_alignment.toString(16)} major_os_version=${
      this.major_os_version
    } minor_os_version=${this.minor_os_version} major_image_version=${
      this.major_image_version
    } minor_image_version=${this.minor_image_version} major_subsystem_version=${
      this.major_subsystem_version
    } minor_subsystem_version=${
      this.minor_subsystem_version
    } win32_version_value=${this.win32_version_value} size_of_image=${
      this.size_of_image
    } size_of_headers=${
      this.size_of_headers
    } checksum=0x${this.checksum.toString(16)} subsystem=${
      this.subsystem
    } dll_characteristics=${this.dll_characteristics} size_of_stack_reserve=${
      this.size_of_stack_reserve
    } size_of_stack_commit=${this.size_of_stack_commit} size_of_heap_reserve=${
      this.size_of_heap_reserve
    } size_of_heap_commit=${
      this.size_of_heap_commit
    } loader_flags=0x${this.loader_flags.toString(16)} rva_and_sizes_count=${
      this.rva_and_sizes_count
    }}`;
  }
}

export class SectionHeader {
  public static SIZE: number = 40;

  public name: string;
  public virtual_size: number;
  public virtual_addr: number;
  public raw_data_size: number;
  public raw_data_offset: number;
  public relocs_offset: number;
  public line_nums_offset: number;
  public reloc_count: number;
  public line_nums_count: number;
  public characteristics: number;

  constructor(ptr: NativePointer) {
    this.name = ptr.add(0).readAnsiString(8) || "";
    this.virtual_size = ptr.add(8).readU32();
    this.virtual_addr = ptr.add(12).readU32();
    this.raw_data_size = ptr.add(16).readU32();
    this.raw_data_offset = ptr.add(20).readU32();
    this.relocs_offset = ptr.add(24).readU32();
    this.line_nums_offset = ptr.add(28).readU32();
    this.reloc_count = ptr.add(32).readU16();
    this.line_nums_count = ptr.add(34).readU16();
    this.characteristics = ptr.add(36).readU32();
  }

  toString(): string {
    return `SectionHeader{name=${this.name} virtual_size=${
      this.virtual_size
    } virtual_addr=0x${this.virtual_addr.toString(16)} raw_data_size=${
      this.raw_data_size
    } raw_data_offset=0x${this.raw_data_offset.toString(
      16
    )} relocs_offset=0x${this.relocs_offset.toString(
      16
    )} line_nums_offset=0x${this.line_nums_offset.toString(16)} reloc_count=${
      this.reloc_count
    } line_nums_count=${this.line_nums_count} characteristics=${
      this.characteristics
    }}`;
  }
}
