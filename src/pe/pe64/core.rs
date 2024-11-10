//! Core functionality for working with PE64 files
use super::layout::*;

use crate::pe64::common_core::*;
use crate::pe64::common_layout::*;

/// Sets up the IMAGE_OPTIONAL_HEADER64
fn set_image_optional_header64<S: AsRef<[u8]> + AsMut<[u8]>>(
    mut view: image_optional_header64::View<S>,
    code_size: DWORD,
    address_of_entry_point: DWORD,
    size_of_image: DWORD,
) {
    view.magic_mut().write(IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    view.major_linker_version_mut().write(14);
    view.minor_linker_version_mut().write(16);
    view.size_of_code_mut().write(code_size);
    view.size_of_initialized_data_mut().write(0);
    view.size_of_uninitialized_data_mut().write(0);
    view.address_of_entry_point_mut()
        .write(address_of_entry_point); // Entry point after headers
    view.base_of_code_mut().write(0x1000);
    view.image_base_mut().write(IMAGE_BASE);
    view.section_alignment_mut().write(SECTION_ALIGNMENT);
    view.file_alignment_mut().write(FILE_ALIGNMENT);
    view.major_operating_system_version_mut().write(6); // Windows Vista or later
    view.minor_operating_system_version_mut().write(0);
    view.major_image_version_mut().write(0);
    view.minor_image_version_mut().write(0);
    view.major_subsystem_version_mut()
        .write(MAJOR_SUBSYSTEM_VERSION);
    view.minor_subsystem_version_mut().write(0);
    view.win32_version_value_mut().write(0);
    view.size_of_image_mut().write(size_of_image);
    view.size_of_headers_mut().write(0x400);
    view.checksum_mut().write(0);
    view.subsystem_mut().write(IMAGE_SUBSYSTEM_WINDOWS_CUI);
    view.dll_characteristics_mut().write(0x8100);
    view.size_of_stack_reserve_mut().write(0x100000);
    view.size_of_stack_commit_mut().write(0x1000);
    view.size_of_heap_reserve_mut().write(0x100000);
    view.size_of_heap_commit_mut().write(0x1000);
    view.loader_flags_mut().write(0);
    view.number_of_rva_and_sizes_mut()
        .write(IMAGE_NUMBER_OF_DIRECTORY_ENTRIES as DWORD);

    // Initialize all data directories to empty
    set_image_data_directory(view.export_table_mut());
    set_image_data_directory(view.import_table_mut());
    set_image_data_directory(view.resource_table_mut());
    set_image_data_directory(view.exception_table_mut());
    set_image_data_directory(view.certificate_table_mut());
    set_image_data_directory(view.base_relocation_table_mut());
    set_image_data_directory(view.debug_mut());
    set_image_data_directory(view.architecture_mut());
    set_image_data_directory(view.global_ptr_mut());
    set_image_data_directory(view.tls_table_mut());
    set_image_data_directory(view.load_config_table_mut());
    set_image_data_directory(view.bound_import_mut());
    set_image_data_directory(view.iat_mut());
    set_image_data_directory(view.delay_import_descriptor_mut());
    set_image_data_directory(view.clr_runtime_header_mut());
    set_image_data_directory(view.reserved_mut());
}

/// Sets up the IMAGE_NT_HEADERS64
fn set_image_nt_headers64<S: AsRef<[u8]> + AsMut<[u8]>>(
    mut view: image_nt_headers64::View<S>,
    num_of_sections: WORD,
    code_size: DWORD,
    address_of_entry_point: DWORD,
    size_of_image: DWORD,
) {
    view.signature_mut().write(SIGNATURE);
    set_image_file_header(
        view.file_header_mut(),
        IMAGE_FILE_MACHINE_AMD64,
        num_of_sections,
        image_optional_header64::SIZE.unwrap() as WORD,
    );
    set_image_optional_header64(
        view.optional_header_mut(),
        code_size,
        address_of_entry_point,
        size_of_image,
    );
}

/// Converts shellcode into a PE64 executable
pub fn shellcode_to_exe(shellcode: &[u8]) -> Vec<u8> {
    // Calculate PE header sizes
    let dos_hdr_size = image_dos_header::SIZE.unwrap() as DWORD;
    let dos_stub_size = image_dos_stub::SIZE.unwrap() as DWORD;
    let nt_hdrs_size = image_nt_headers64::SIZE.unwrap() as DWORD;
    let shellcode_size = shellcode.len() as DWORD;
    let total_size = dos_hdr_size + dos_stub_size + nt_hdrs_size + shellcode_size;

    let section_hdr_size = image_section_header::SIZE.unwrap() as DWORD;
    let headers_size = dos_hdr_size + dos_stub_size + nt_hdrs_size + section_hdr_size;

    // Calculate offsets
    let lfanew_offset = (dos_hdr_size + dos_stub_size) as LONG;

    let section_alignment = 0x1000;
    let size_of_image: DWORD = if shellcode_size % section_alignment == 0 {
        0x1000 + shellcode_size
    } else {
        0x1000 + ((shellcode_size / section_alignment + 1) * section_alignment)
    };

    // Create padding buffer
    let section_padding = 0x400 - headers_size;

    // Create a buffer to hold the PE content
    let mut buf = vec![0u8; total_size as usize];

    // Create the PE headers structures
    let mut pe_headers = pe64_headers::View::new(&mut buf);
    set_image_dos_header(pe_headers.dos_header_mut(), lfanew_offset);
    set_image_dos_stub(pe_headers.dos_stub_mut());
    set_image_nt_headers64(
        pe_headers.nt_headers_mut(),
        1,
        shellcode_size,
        0x1000,
        size_of_image,
    );
    set_image_section_header(
        pe_headers.text_section_mut(),
        ".text",
        shellcode_size,
        0x1000,
        shellcode_size,
    );

    // Extend the buffer with padding to align to the next section
    buf.resize((headers_size + section_padding) as usize, 0);

    // Append the shellcode at the end of the buffer
    buf.extend(shellcode);

    buf
}
