//! Binary layout definitions for the PE64 format structures.

#![allow(non_camel_case_types)]

use binary_layout::prelude::*;

// Type definitions
type BYTE = u8;
type WORD = u16;
type DWORD = u32;
type LONG = u32;
type ULONGLONG = u64;

// Constants
pub(crate) const E_MAGIC: WORD = 0x5A4D; // DOS signature - "MZ"
pub(crate) const IMAGE_NT_OPTIONAL_HDR64_MAGIC: WORD = 0x20B; // PE32+ magic (64-bit)
pub(crate) const NT_SIGNATURE: DWORD = 0x50450000; // PE signature - "PE\0\0"
pub(crate) const IMAGE_NUMBER_OF_DIRECTORY_ENTRIES: usize = 16;

// region:    --- DOS Header structures

// IMAGE_DOS_HEADER
binary_layout!(image_dos_header, LittleEndian, {
    e_magic: WORD,    // Magic number
    e_cblp: WORD,     // Bytes on last page of file
    e_cp: WORD,       // Pages in file
    e_crlc: WORD,     // Relocations
    e_cparhdr: WORD,  // Size of header in paragraphs
    e_minalloc: WORD, // Minimum extra paragraphs needed
    e_maxalloc: WORD, // Maximum extra paragraphs needed
    e_ss: WORD,       // Initial (relative) SS value
    e_sp: WORD,       // Initial SP value
    e_csum: WORD,     // Checksum
    e_ip: WORD,       // Initial IP value
    e_cs: WORD,       // Initial (relative) CS value
    e_lfarlc: WORD,   // File address of relocation table
    e_ovno: WORD,     // Overlay number
    e_res1_1: WORD,   // Reserved word
    e_res1_2: WORD,   // Reserved word
    e_res1_3: WORD,   // Reserved word
    e_res1_4: WORD,   // Reserved word
    e_oemid: WORD,    // OEM identifier (for e_oeminfo)
    e_oeminfo: WORD,  // OEM information; e_oemid specific
    e_res2_1: WORD,   // Reserved word
    e_res2_2: WORD,   // Reserved word
    e_res2_3: WORD,   // Reserved word
    e_res2_4: WORD,   // Reserved word
    e_res2_5: WORD,   // Reserved word
    e_res2_6: WORD,   // Reserved word
    e_res2_7: WORD,   // Reserved word
    e_res2_8: WORD,   // Reserved word
    e_res2_9: WORD,   // Reserved word
    e_res2_10: WORD,  // Reserved word
    e_lfanew: LONG,   // File address of new exe header
});
