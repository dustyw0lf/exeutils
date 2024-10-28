//! Binary layout definitions for the ELF64 format structures.
//!
//! Based on the [ELF-64 standard](https://uclibc.org/docs/elf-64-gen.pdf)
//! and the [x86-64 architecture supplement](https://uclibc.org/docs/psABI-x86_64.pdf)
//! for the value `EM_X86_64`, specific to x86-64.
#![allow(non_camel_case_types)]

use binary_layout::prelude::*;

// Type definitions
type Elf64_Addr = u64;
type Elf64_Off = u64;
type Elf64_Half = u16;
type Elf64_Word = u32;
// type Elf64_Sword = u32;
type Elf64_Xword = u64;
// type Elf64_Sxword = u64;

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
// ELF identification header
binary_layout!(elf64_ident, LittleEndian, {
    mag: [u8; 4],     // File identification
    class: u8,        // File class
    data: u8,         // Data encoding
    version: u8,      // File version
    os_abi: u8,       // OS/ABI identification
    abi_version: u8,  // ABI version
    pad: [u8; 7],     // Start of padding bytes
});

// ELF file header
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

// ELF program header
binary_layout!(elf64_phdr, LittleEndian, {
    _type: Elf64_Word,   // Type of segment
    flags: Elf64_Word,   // Segment attributes
    offset: Elf64_Off,   // Offset in file
    vaddr: Elf64_Addr,   // Virtual address in memory
    paddr: Elf64_Addr,   // Reserved
    filesz: Elf64_Xword, // Size of segment in file
    memsz: Elf64_Xword,  // Size of segment in memory
    align: Elf64_Xword,  // Alignment of segment
});

// ELF executable
binary_layout!(elf64_file, LittleEndian, {
    hdr: elf64_hdr::NestedView,
    phdr: elf64_phdr::NestedView,
    program: [u8],
});
