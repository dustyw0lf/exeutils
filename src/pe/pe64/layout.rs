//! Binary layout definitions for the PE64 format structures.

#![allow(non_camel_case_types)]

use binary_layout::prelude::*;

// Type definitions
pub(crate) type BYTE = u8;
pub(crate) type WORD = u16;
pub(crate) type DWORD = u32;
pub(crate) type LONG = u32;
pub(crate) type ULONGLONG = u64;

// region:    --- constants

// IMAGE_DOS_HEADER constants
pub(crate) const E_MAGIC: WORD = 0x5A4D; // DOS signature: "MZ"

// IMAGE_OPTIONAL_HEADER32 constants
pub(crate) const IMAGE_NT_OPTIONAL_HDR64_MAGIC: WORD = 0x20B; // PE32+ magic (64-bit)

// IMAGE_NT_HEADERS64 constans
pub(crate) const SIGNATURE: DWORD = 0x00004550; // PE signature: "PE\0\0"

// IMAGE_FILE_HEADER constants
pub(crate) const IMAGE_FILE_MACHINE_AMD64: WORD = 0x8664; // Arch: x64
pub(crate) const IMAGE_FILE_EXECUTABLE_IMAGE: WORD = 0x0002; // Executable

// IMAGE_OPTIONAL_HEADER64 constants
pub(crate) const IMAGE_BASE: ULONGLONG = 0x400000; // Default value for applications
pub(crate) const MAJOR_SUBSYSTEM_VERSION: WORD = 6;
pub(crate) const IMAGE_SUBSYSTEM_WINDOWS_CUI: WORD = 3; // Default value for applications

pub(crate) const IMAGE_NUMBER_OF_DIRECTORY_ENTRIES: usize = 16;
pub(crate) const SECTION_ALIGNMENT: DWORD = 0x1000; // Default section alignment
pub(crate) const FILE_ALIGNMENT: DWORD = 0x200; // Default file alignment

pub(crate) const IMAGE_SCN_MEM_EXECUTE: DWORD = 0x20000000;
pub(crate) const IMAGE_SCN_MEM_READ: DWORD = 0x40000000;
pub(crate) const IMAGE_SCN_MEM_WRITE: DWORD = 0x80000000;
pub(crate) const IMAGE_SCN_CNT_CODE: DWORD = 0x00000020;

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
    // Reserved words
    e_res2_1: WORD,
    e_res2_2: WORD,
    e_res2_3: WORD,
    e_res2_4: WORD,
    e_res2_5: WORD,
    e_res2_6: WORD,
    e_res2_7: WORD,
    e_res2_8: WORD,
    e_res2_9: WORD,
    e_res2_10: WORD,
    e_lfanew: LONG,   // File address of new exe header
});

// endregion: --- DOS Header structures

// IMAGE_DOS_STUB
binary_layout!(image_dos_stub, LittleEndian, {
    data: [BYTE; 64],
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

// IMAGE_DATA_DIRECTORY
binary_layout!(image_data_directory, LittleEndian, {
    virtual_address: DWORD,          // RVA of the table
    size: DWORD,                     // Size of the table
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
    image_base: ULONGLONG,
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
    checksum: DWORD,
    subsystem: WORD,
    dll_characteristics: WORD,
    size_of_stack_reserve: ULONGLONG,
    size_of_stack_commit: ULONGLONG,
    size_of_heap_reserve: ULONGLONG,
    size_of_heap_commit: ULONGLONG,
    loader_flags: DWORD,
    number_of_rva_and_sizes: DWORD,
    export_table: image_data_directory::NestedView,
    import_table: image_data_directory::NestedView,
    resource_table: image_data_directory::NestedView,
    exception_table: image_data_directory::NestedView,
    certificate_table: image_data_directory::NestedView,
    base_relocation_table: image_data_directory::NestedView,
    debug: image_data_directory::NestedView,
    architecture: image_data_directory::NestedView,
    global_ptr: image_data_directory::NestedView,
    tls_table: image_data_directory::NestedView,
    load_config_table: image_data_directory::NestedView,
    bound_import: image_data_directory::NestedView,
    iat: image_data_directory::NestedView,
    delay_import_descriptor: image_data_directory::NestedView,
    clr_runtime_header: image_data_directory::NestedView,
    reserved: image_data_directory::NestedView,
});

// IMAGE_NT_HEADERS64
binary_layout!(image_nt_headers64, LittleEndian, {
    signature: DWORD,                               // PE signature "PE\0\0"
    file_header: image_file_header::NestedView,     // File header
    optional_header: image_optional_header64::NestedView, // Optional header (PE32+)
});

// IMAGE_SECTION_HEADER
binary_layout!(image_section_header, LittleEndian, {
    name: [BYTE; 8],
    virtual_size: DWORD,             // Size of section in memory
    virtual_address: DWORD,          // RVA of section in memory
    size_of_raw_data: DWORD,         // Size of initialized data
    pointer_to_raw_data: DWORD,
    pointer_to_relocations: DWORD,
    pointer_to_linenumbers: DWORD,
    number_of_relocations: WORD,
    number_of_linenumbers: WORD,
    characteristics: DWORD,          // Flags describing section
});

// PE64 headers
binary_layout!(pe64_headers, LittleEndian, {
    dos_header: image_dos_header::NestedView,
    dos_stub: image_dos_stub::NestedView,
    nt_headers: image_nt_headers64::NestedView,
    text_section: image_section_header::NestedView,
});
