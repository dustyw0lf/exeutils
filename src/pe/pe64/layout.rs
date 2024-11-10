//! Binary layout definitions for the PE64 format structures.

#![allow(non_camel_case_types)]

use binary_layout::prelude::*;

// Constants
pub(crate) type ULONGLONG = u64;

// region:    --- constants

// IMAGE_OPTIONAL_HEADER64 magic number
pub(crate) const IMAGE_NT_OPTIONAL_HDR64_MAGIC: WORD = 0x20B; // PE32+ magic (64-bit)

pub(crate) const IMAGE_BASE: ULONGLONG = 0x400000; // Default value for applications

// Version requirements for 64-bit executables
pub(crate) const MAJOR_SUBSYSTEM_VERSION: WORD = 6; // Windows Vista or later required for 64-bit

// endregion: --- constants

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

// PE64 headers
binary_layout!(pe64_headers, LittleEndian, {
    dos_header: image_dos_header::NestedView,
    dos_stub: image_dos_stub::NestedView,
    nt_headers: image_nt_headers64::NestedView,
    text_section: image_section_header::NestedView,
});
