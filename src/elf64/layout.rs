//! Binary layout definitions for the ELF64 format structures
#![allow(non_camel_case_types)]

use binary_layout::prelude::*;

// Type definitions
type Elf64_Addr = u64;
type Elf64_Off = u64;
type Elf64_Half = u16;
type Elf64_Word = u32;
type Elf64_Xword = u64;

// Constants
pub(crate) const PROGRAM_OFFSET: u64 = {
    let sz1 = match elf64_hdr::SIZE {
        Some(s) => s,
        None => panic!("unsized"),
    };
    let sz2 = match elf64_phdr::SIZE {
        Some(s) => s,
        None => panic!("unsized"),
    };
    (sz1 + sz2) as u64
};

pub(crate) const VADDR: u64 = 0x400000;

// Structure definitions
binary_layout!(elf64_ident, LittleEndian, {
    mag: [u8; 4],
    class: u8,
    data: u8,
    version: u8,
    os_abi: u8,
    abi_version: u8,
    pad: [u8; 7],
});

binary_layout!(elf64_hdr, LittleEndian, {
    ident: elf64_ident::NestedView, // ELF identification
    _type: Elf64_Half,             // Object file type
    machine: Elf64_Half,           // Machine type
    version: Elf64_Word,           // Object file version
    entry: Elf64_Addr,             // Entry point address
    phoff: Elf64_Off,              // Program header offset
    shoff: Elf64_Off,              // Section header offse
    flags: Elf64_Word,             // Processor-specific flags
    ehsize: Elf64_Half,            // ELF header size
    phentsize: Elf64_Half,         // Size of program header entry
    phnum: Elf64_Half,             // Number of program header entries
    shentsize: Elf64_Half,         // Size of section header entry
    shnum: Elf64_Half,             // Number of section header entries
    shstrndx: Elf64_Half,          // Section name string table index
});

binary_layout!(elf64_phdr, LittleEndian, {
    _type: Elf64_Word,
    flags: Elf64_Word,
    offset: Elf64_Off,
    vaddr: Elf64_Addr,
    paddr: Elf64_Addr,
    filesz: Elf64_Xword,
    memsz: Elf64_Xword,
    align: Elf64_Xword,
});

binary_layout!(elf64_file, LittleEndian, {
    hdr: elf64_hdr::NestedView,
    phdr: elf64_phdr::NestedView,
    program: [u8],
});
