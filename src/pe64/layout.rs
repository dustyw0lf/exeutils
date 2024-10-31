//! Binary layout definitions for the PE64 format structures.

#![allow(non_camel_case_types)]

use binary_layout::prelude::*;

// Type definitions
type BYTE = u8;
type WORD = u16;
type DWORD = u32;
type LONG = u32;
type ULONGLONG = u64;

// region:    --- constants

// IMAGE_DOS_HEADER constants
pub(crate) const E_MAGIC: WORD = 0x5A4D; // DOS signature: "MZ"

// IMAGE_OPTIONAL_HEADER32 constants
pub(crate) const IMAGE_NT_OPTIONAL_HDR64_MAGIC: WORD = 0x20B; // PE32+ magic (64-bit)

// IMAGE_NT_HEADERS64 constans
pub(crate) const SIGNATURE: DWORD = 0x50450000; // PE signature: "PE\0\0"

// IMAGE_FILE_HEADER constants
pub(crate) const IMAGE_FILE_MACHINE_AMD64: WORD = 0x8664; // Arch: x64
pub(crate) const IMAGE_FILE_EXECUTABLE_IMAGE: WORD = 0x0002; // Executable

// IMAGE_OPTIONAL_HEADER64 constants
// pub(crate) const IMAGE_NUMBER_OF_DIRECTORY_ENTRIES: usize = 16;

// endregion: --- constants

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

// endregion: --- DOS Header structures

// region:    --- PE Header structures

// IMAGE_NT_HEADERS64
binary_layout!(image_nt_headers64, LittleEndian, {
    signature: DWORD,
    file_header: image_file_header::NestedView,
    optional_header: image_optional_header64::NestedView,
});

// IMAGE_FILE_HEADER
binary_layout!(image_file_header, LittleEndian, {
    machine: WORD,
    number_of_sections: WORD,
    time_date_stamp: DWORD,
    pointer_to_symbol_table: DWORD,
    number_of_symbols: DWORD,
    size_of_optional_header: WORD,
    characteristics: WORD,
});

// endregion: --- PE Header structures

// region:    --- Optional Header structures

// IMAGE_DATA_DIRECTORY
binary_layout!(image_data_directory, LittleEndian, {
    virtual_address: DWORD,
    size: DWORD,
});

// IMAGE_OPTIONAL_HEADER64
binary_layout!(image_optional_header64, LittleEndian, {
    magic: WORD,
    major_linker_version: BYTE,
    minor_linker_version: BYTE,
    size_of_code: DWORD,
    size_of_initialized_data: DWORD,
    size_of_uninitialized_data: DWORD,
    address_of_entry_point: DWORD,
    base_of_code: DWORD,
    image_base: ULONGLONG,              // 64-bit value
    section_alignment: DWORD,
    file_alignment: DWORD,
    major_operating_system_version: WORD,
    minor_operating_system_version: WORD,
    major_image_version: WORD,
    minor_image_version: WORD,
    major_subsystem_version: WORD,
    minor_subsystem_version: WORD,
    win32_version_value: DWORD,
    size_of_image: DWORD,
    size_of_headers: DWORD,
    check_sum: DWORD,
    subsystem: WORD,
    dll_characteristics: WORD,
    size_of_stack_reserve: ULONGLONG,   // 64-bit value
    size_of_stack_commit: ULONGLONG,    // 64-bit value
    size_of_heap_reserve: ULONGLONG,    // 64-bit value
    size_of_heap_commit: ULONGLONG,     // 64-bit value
    loader_flags: DWORD,
    number_of_rva_and_sizes: DWORD,
    data_directory_1: image_data_directory::NestedView,
    data_directory_2: image_data_directory::NestedView,
    data_directory_3: image_data_directory::NestedView,
    data_directory_4: image_data_directory::NestedView,
    data_directory_5: image_data_directory::NestedView,
    data_directory_6: image_data_directory::NestedView,
    data_directory_7: image_data_directory::NestedView,
    data_directory_8: image_data_directory::NestedView,
    data_directory_9: image_data_directory::NestedView,
    data_directory_10: image_data_directory::NestedView,
    data_directory_11: image_data_directory::NestedView,
    data_directory_12: image_data_directory::NestedView,
    data_directory_13: image_data_directory::NestedView,
    data_directory_14: image_data_directory::NestedView,
    data_directory_15: image_data_directory::NestedView,
    data_directory_16: image_data_directory::NestedView,
});

// endregion: --- Optional Header structures

// PE 64 executable
binary_layout!(pe64_file, LittleEndian, {
    dos_header: image_dos_header::NestedView,
    nt_headers64: image_nt_headers64::NestedView,
    shellcode: [u8],
});
