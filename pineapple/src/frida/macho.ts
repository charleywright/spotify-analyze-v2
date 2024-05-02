export class MachOHeader {
  public static MAGIC_32: number = 0xfeedface;
  public static MAGIC_64: number = 0xfeedfacf;

  public magic: number;
  public cpu_type: number;
  public cpu_subtype: number;
  public file_type: number;
  public load_commands_count: number;
  public load_commands_size: number;
  public flags: number;

  constructor(ptr: NativePointer) {
    this.magic = ptr.add(0).readU32();
    this.cpu_type = ptr.add(4).readU32();
    this.cpu_subtype = ptr.add(8).readU32();
    this.file_type = ptr.add(12).readU32();
    this.load_commands_count = ptr.add(16).readU32();
    this.load_commands_size = ptr.add(20).readU32();
    this.flags = ptr.add(24).readU32();
  }

  isValid(): boolean {
    return (
      this.magic === MachOHeader.MAGIC_32 || this.magic === MachOHeader.MAGIC_64
    );
  }

  size(): number {
    switch (this.magic) {
      case MachOHeader.MAGIC_32:
        return 28;
      case MachOHeader.MAGIC_64:
        return 32;
      default:
        return 0;
    }
  }

  isMulti(): boolean {
    return this.magic === 0xcafebabe;
  }

  toString(): string {
    return `MachOHeader{valid=${this.isValid()} magic=0x${this.magic.toString(
      16
    )} cpu_type=0x${this.cpu_type.toString(
      16
    )} cpu_subtype=0x${this.cpu_subtype.toString(
      16
    )} file_type=0x${this.file_type.toString(16)} load_commands_count=${
      this.load_commands_count
    } load_commands_size=${this.load_commands_size} flags=${this.flags}}`;
  }
}

export class MachOLoadCommand {
  static LC_SEGMENT32: number = 0x00000001;
  static LC_SEGMENT64: number = 0x00000019;

  public type: number;
  public neededForLoading: boolean;
  public size: number;

  constructor(ptr: NativePointer) {
    this.type = ptr.add(0).readU32();
    this.neededForLoading = (this.type & 0x80000000) !== 0;
    this.type = this.type & ~0x80000000;
    this.size = ptr.add(4).readU32();
  }

  toString(): string {
    return `MachOLoadCommand{type=0x${this.type.toString(
      16
    )} neededForLoading=${this.neededForLoading} size=${this.size}}`;
  }
}

export class MachOSegmentLoadCommand {
  public command: MachOLoadCommand;
  public name: string;
  public memory_offset: UInt64;
  public memory_size: UInt64;
  public file_offset: UInt64;
  public file_size: UInt64;
  public max_prot: number;
  public init_prot: number;
  public section_count: number;
  public flags: number;
  public sections: MachOSection[] = [];

  constructor(ptr: NativePointer) {
    this.command = new MachOLoadCommand(ptr);
    const is_32_bit = this.command.type === MachOLoadCommand.LC_SEGMENT32;
    if (is_32_bit) {
      this.name = (ptr.add(8).readCString() || "").substring(0, 16);
      this.memory_offset = uint64(ptr.add(24).readU32());
      this.memory_size = uint64(ptr.add(28).readU32());
      this.file_offset = uint64(ptr.add(32).readU32());
      this.file_size = uint64(ptr.add(36).readU32());
      this.max_prot = ptr.add(40).readU32();
      this.init_prot = ptr.add(44).readU32();
      this.section_count = ptr.add(48).readU32();
      this.flags = ptr.add(52).readU32();
    } else {
      this.name = (ptr.add(8).readCString() || "").substring(0, 16);
      this.memory_offset = ptr.add(24).readU64();
      this.memory_size = ptr.add(32).readU64();
      this.file_offset = ptr.add(40).readU64();
      this.file_size = ptr.add(48).readU64();
      this.max_prot = ptr.add(56).readU32();
      this.init_prot = ptr.add(60).readU32();
      this.section_count = ptr.add(64).readU32();
      this.flags = ptr.add(68).readU32();
    }
    const section_base = ptr.add(this.size());
    for (let section_idx = 0; section_idx < this.section_count; section_idx++) {
      const section_addr = section_base.add(section_idx * this.sectionSize());
      const section = new MachOSection(section_addr, is_32_bit);
      this.sections.push(section);
    }
  }

  public size(): number {
    if (this.command.type === MachOLoadCommand.LC_SEGMENT32) {
      return 56;
    } else {
      return 72;
    }
  }

  private sectionSize(): number {
    if (this.command.type === MachOLoadCommand.LC_SEGMENT32) {
      return 68;
    } else {
      return 80;
    }
  }

  public toString(): string {
    return `Segment{command=${this.command} name=${
      this.name
    } memory_offset=0x${this.memory_offset.toString(
      16
    )} memory_size=0x${this.memory_size.toString(
      16
    )} file_offset=0x${this.file_offset.toString(
      16
    )} file_size=0x${this.file_size.toString(16)} max_prot=${
      this.max_prot
    } target_prot=${this.init_prot} section_count=${
      this.section_count
    } flags=0x${this.flags.toString(16)}}`;
  }
}

export class MachOSection {
  public name: string;
  public segment: string;
  public address: UInt64;
  public size: UInt64;
  public offset: number;
  public alignment: number;
  public reloc_offset: number;
  public reloc_count: number;
  public type: number;

  constructor(ptr: NativePointer, is_32_bit: boolean) {
    if (is_32_bit) {
      this.name = ptr.add(0).readCString()?.substring(0, 16) || "";
      this.segment = ptr.add(16).readCString()?.substring(0, 16) || "";
      this.address = uint64(ptr.add(32).readU32());
      this.size = uint64(ptr.add(36).readU32());
      this.offset = ptr.add(40).readU32();
      this.alignment = ptr.add(44).readU32();
      this.reloc_offset = ptr.add(48).readU32();
      this.reloc_count = ptr.add(52).readU32();
      this.type = ptr.add(56).readU32();
    } else {
      this.name = ptr.add(0).readCString()?.substring(0, 16) || "";
      this.segment = ptr.add(16).readCString()?.substring(0, 16) || "";
      this.address = ptr.add(32).readU64();
      this.size = ptr.add(40).readU64();
      this.offset = ptr.add(48).readU32();
      this.alignment = ptr.add(52).readU32();
      this.reloc_offset = ptr.add(56).readU32();
      this.reloc_count = ptr.add(60).readU32();
      this.type = ptr.add(64).readU32();
    }
  }

  toString(): string {
    return `MachOSection{name=${this.name} segment=${
      this.segment
    } address=0x${this.address.toString(16)} size=0x${this.size.toString(
      16
    )} offset=0x${this.offset.toString(
      16
    )} alignment=0x${this.alignment.toString(16)} reloc_offset=${
      this.reloc_offset
    } reloc_count=${this.reloc_count} type=0x${this.type.toString(16)}}`;
  }
}
