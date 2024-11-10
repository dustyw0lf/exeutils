//! Binary layout definitions for the PE32 format structures.

// IMAGE_FILE_HEADER constant
pub(crate) const IMAGE_FILE_MACHINE_I386: WORD = 0x014c; // Arch: x86

// IMAGE_OPTIONAL_HEADER32 constants
pub(crate) const IMAGE_NT_OPTIONAL_HDR32_MAGIC: WORD = 0x10b;

pub(crate) const IMAGE_BASE: DWORD = 0x400000; // Default value for applications

// IMAGE_OPTIONAL_HEADER32
binary_layout!(image_optional_header32, LittleEndian, {
    magic: WORD,
    major_linker_version: BYTE,
    minor_linker_version: BYTE,
    size_of_code: DWORD,
    size_of_initialized_data: DWORD,
    size_of_uninitialized_data: DWORD,
    address_of_entry_point: DWORD,
    base_of_code: DWORD,
    image_base: DWORD,
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
    size_of_stack_reserve: DWORD,
    size_of_stack_commit: DWORD,
    size_of_heap_reserve: DWORD,
    size_of_heap_commit: DWORD,
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
