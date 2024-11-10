//! Core functionality for working with PE32 files
use super::layout::*;

use crate::pe32::common_core::*;
use crate::pe32::common_layout::*;

/// Sets up the IMAGE_OPTIONAL_HEADER32
fn set_image_optional_header32<S: AsRef<[u8]> + AsMut<[u8]>>(
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

pub fn shellcode_to_exe(shellcode: &[u8]) -> Vec<u8> {
    todo!();
}
