export class ElfEndianReader {
  private ident: ElfIdent;
  private ptr: NativePointer;

  static ELFCLASSNONE = 0; /* Invalid class */
  static ELFCLASS32 = 1; /* 32-bit objects */
  static ELFCLASS64 = 2; /* 64-bit objects */
  static ELFDATANONE = 0; /* Invalid data encoding */
  static ELFDATA2LSB = 1; /* 2's complement, little endian */
  static ELFDATA2MSB = 2; /* 2's complement, big endian */

  constructor(ident: ElfIdent, ptr: NativePointer) {
    this.ident = ident;
    this.ptr = ptr;
  }

  private readU16(): number {
    const old_ptr = this.ptr;
    this.ptr = this.ptr.add(2);
    if (this.ident.ei_data === ElfEndianReader.ELFDATA2LSB) {
      return (old_ptr.add(0).readU8() << 0) | (old_ptr.add(1).readU8() << 8);
    } else if (this.ident.ei_data === ElfEndianReader.ELFDATA2MSB) {
      return (old_ptr.add(0).readU8() << 8) | (old_ptr.add(1).readU8() << 0);
    } else {
      return 0;
    }
  }

  private readU32(): number {
    const old_ptr = this.ptr;
    this.ptr = this.ptr.add(4);
    if (this.ident.ei_data === ElfEndianReader.ELFDATA2LSB) {
      return (
        (old_ptr.add(0).readU8() << 0) |
        (old_ptr.add(1).readU8() << 8) |
        (old_ptr.add(2).readU8() << 16) |
        (old_ptr.add(3).readU8() << 24)
      );
    } else if (this.ident.ei_data === ElfEndianReader.ELFDATA2MSB) {
      return (
        (old_ptr.add(0).readU8() << 24) |
        (old_ptr.add(1).readU8() << 16) |
        (old_ptr.add(2).readU8() << 8) |
        (old_ptr.add(3).readU8() << 0)
      );
    } else {
      return 0;
    }
  }

  private readU64(): UInt64 {
    const old_ptr = this.ptr;
    this.ptr = this.ptr.add(8);
    if (this.ident.ei_data === ElfEndianReader.ELFDATA2LSB) {
      return uint64(0)
        .or(uint64(old_ptr.add(0).readU8()).shl(0))
        .or(uint64(old_ptr.add(1).readU8()).shl(8))
        .or(uint64(old_ptr.add(2).readU8()).shl(16))
        .or(uint64(old_ptr.add(3).readU8()).shl(24))
        .or(uint64(old_ptr.add(4).readU8()).shl(32))
        .or(uint64(old_ptr.add(5).readU8()).shl(40))
        .or(uint64(old_ptr.add(6).readU8()).shl(48))
        .or(uint64(old_ptr.add(7).readU8()).shl(56));
    } else if (this.ident.ei_data === ElfEndianReader.ELFDATA2MSB) {
      return uint64(0)
        .or(uint64(old_ptr.add(0).readU8()).shl(56))
        .or(uint64(old_ptr.add(1).readU8()).shl(48))
        .or(uint64(old_ptr.add(2).readU8()).shl(40))
        .or(uint64(old_ptr.add(3).readU8()).shl(32))
        .or(uint64(old_ptr.add(4).readU8()).shl(24))
        .or(uint64(old_ptr.add(5).readU8()).shl(16))
        .or(uint64(old_ptr.add(6).readU8()).shl(8))
        .or(uint64(old_ptr.add(7).readU8()).shl(0));
    } else {
      return uint64(0);
    }
  }

  public readAddr(): UInt64 {
    return this.readSize();
  }

  public readOff(): UInt64 {
    return this.readSize();
  }

  public readHalf(): number {
    return this.readU16();
  }

  public readWord(): number {
    return this.readU32();
  }

  public readSize(): UInt64 {
    if (this.ident.ei_class === ElfEndianReader.ELFCLASS32) {
      return uint64(this.readU32());
    } else if (this.ident.ei_class === ElfEndianReader.ELFCLASS64) {
      return this.readU64();
    } else {
      return uint64(0);
    }
  }

  public advance32(amount: number) {
    if (this.ident.ei_class === ElfEndianReader.ELFCLASS32) {
      this.ptr = this.ptr.add(amount);
    }
  }

  public advance64(amount: number) {
    if (this.ident.ei_class === ElfEndianReader.ELFCLASS64) {
      this.ptr = this.ptr.add(amount);
    }
  }
}

export class ElfIdent {
  public ei_magic: number[];
  public ei_class: number;
  public ei_data: number;
  public ei_version: number;
  public ei_osabi: number;
  public ei_abiversion: number;

  constructor(ptr: NativePointer) {
    this.ei_magic = [
      ptr.add(0).readU8(),
      ptr.add(1).readU8(),
      ptr.add(2).readU8(),
      ptr.add(3).readU8(),
    ];
    this.ei_class = ptr.add(4).readU8();
    this.ei_data = ptr.add(5).readU8();
    this.ei_version = ptr.add(6).readU8();
    this.ei_osabi = ptr.add(7).readU8();
    this.ei_abiversion = ptr.add(8).readU8();
  }

  public isValid() {
    return (
      this.ei_magic[0] == 127 &&
      this.ei_magic[1] == "E".charCodeAt(0) &&
      this.ei_magic[2] == "L".charCodeAt(0) &&
      this.ei_magic[3] == "F".charCodeAt(0)
    );
  }

  toString(): string {
    return `ElfIdent{ei_magic=${this.ei_magic} ei_class=${this.ei_class} ei_data=${this.ei_data} ei_version=${this.ei_version} ei_osabi=${this.ei_osabi} ei_abiversion=${this.ei_abiversion}}`;
  }
}

export class ElfHeader {
  public e_ident: ElfIdent;
  public e_type: number;
  public e_machine: number;
  public e_version: number;
  public e_entry: UInt64;
  public e_phoff: UInt64;
  public e_shoff: UInt64;
  public e_flags: number;
  public e_ehsize: number;
  public e_phentsize: number;
  public e_phnum: number;
  public e_shentsize: number;
  public e_shnum: number;
  public e_shstrndx: number;

  public constructor(ptr: NativePointer) {
    this.e_ident = new ElfIdent(ptr);
    const reader = new ElfEndianReader(this.e_ident, ptr.add(16));
    this.e_type = reader.readHalf();
    this.e_machine = reader.readHalf();
    this.e_version = reader.readWord();
    this.e_entry = reader.readAddr();
    this.e_phoff = reader.readOff();
    this.e_shoff = reader.readOff();
    this.e_flags = reader.readWord();
    this.e_ehsize = reader.readHalf();
    this.e_phentsize = reader.readHalf();
    this.e_phnum = reader.readHalf();
    this.e_shentsize = reader.readHalf();
    this.e_shnum = reader.readHalf();
    this.e_shstrndx = reader.readHalf();
  }

  public isValid() {
    return this.e_ident.isValid();
  }

  public toString() {
    return `ElfHeader{e_ident=${this.e_ident} e_type=${this.e_type} e_machine=${this.e_machine} e_version=${this.e_version} e_entry=${this.e_entry} e_phoff=${this.e_phoff} e_shoff=${this.e_shoff} e_flags=${this.e_flags} e_ehsize=${this.e_ehsize} e_phentsize=${this.e_phentsize} e_phnum=${this.e_phnum} e_shentsize=${this.e_shentsize} e_shnum=${this.e_shnum} e_shstrndx=${this.e_shstrndx}}`;
  }
}

export class ElfSegment {
  public p_type: number;
  public p_offset: UInt64;
  public p_vaddr: UInt64;
  public p_paddr: UInt64;
  public p_filesz: UInt64;
  public p_memsz: UInt64;
  public p_flags: number;
  public p_align: number;

  public static PT_LOAD: number = 1;

  public constructor(reader: ElfEndianReader) {
    this.p_type = reader.readWord();
    reader.advance64(4); // Skip p_flags, read later
    this.p_offset = reader.readOff();
    this.p_vaddr = reader.readAddr();
    this.p_paddr = reader.readAddr();
    this.p_filesz = reader.readSize();
    this.p_memsz = reader.readSize();
    reader.advance64(-44); // Back to p_flags
    this.p_flags = reader.readWord();
    reader.advance64(40); // Forward to p_align
    this.p_align = reader.readWord();
  }

  public toString() {
    return `ElfSegment{p_type=${this.p_type} p_flags=${
      this.p_flags
    } p_offset=0x${this.p_offset.toString(
      16
    )} p_vaddr=0x${this.p_vaddr.toString(16)} p_paddr=0x${this.p_paddr.toString(
      16
    )} p_filesz=0x${this.p_filesz.toString(
      16
    )} p_memsz=0x${this.p_memsz.toString(16)} p_align=0x${this.p_align.toString(
      16
    )}}`;
  }
}

export class ElfSection {
  public sh_name: number;
  public sh_type: number;
  public sh_flags: UInt64;
  public sh_addr: UInt64;
  public sh_offset: UInt64;
  public sh_size: UInt64;
  public sh_link: number;
  public sh_info: number;
  public sh_addralign: UInt64;
  public sh_entsize: UInt64;
  private string_table_addr: NativePointer = NULL;

  public constructor(reader: ElfEndianReader) {
    this.sh_name = reader.readWord();
    this.sh_type = reader.readWord();
    this.sh_flags = reader.readSize();
    this.sh_addr = reader.readAddr();
    this.sh_offset = reader.readOff();
    this.sh_size = reader.readSize();
    this.sh_link = reader.readWord();
    this.sh_info = reader.readWord();
    this.sh_addralign = reader.readSize();
    this.sh_entsize = reader.readSize();
  }

  public setStringTableAddr(addr: NativePointer) {
    this.string_table_addr = addr;
  }

  public getName() {
    if (this.string_table_addr.isNull()) {
      return "";
    } else {
      return this.string_table_addr.add(this.sh_name).readCString() || "";
    }
  }

  public toString() {
    const name = this.string_table_addr.isNull()
      ? this.sh_name
      : `${this.sh_name} (${this.string_table_addr
          .add(this.sh_name)
          .readCString()})`;
    return `ElfSection{sh_name=${name} sh_type=${this.sh_type} sh_flags=${this.sh_flags} sh_addr=${this.sh_addr} sh_offset=${this.sh_offset} sh_size=${this.sh_size} sh_link=${this.sh_link} sh_info=${this.sh_info} sh_addralign=${this.sh_addralign} sh_entsize=${this.sh_entsize}}`;
  }
}
