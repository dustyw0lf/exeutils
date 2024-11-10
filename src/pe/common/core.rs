//! Core functionality for working with PE32 and PE64 files

use super::layout::*;

/// Sets up the IMAGE_DOS_HEADER header
pub(crate) fn set_image_dos_header<S: AsRef<[u8]> + AsMut<[u8]>>(
    mut view: image_dos_header::View<S>,
    offset: LONG,
) {
    view.e_magic_mut().write(E_MAGIC); // Magic number "MZ"
    view.e_cblp_mut().write(0x0090); // Bytes on last page of file
    view.e_cp_mut().write(0x0003); // Pages in file
    view.e_crlc_mut().write(0x0000); // Relocations
    view.e_cparhdr_mut().write(0x0004); // Size of header in paragraphs
    view.e_minalloc_mut().write(0x0000); // Minimum extra paragraphs needed
    view.e_maxalloc_mut().write(0xFFFF); // Maximum extra paragraphs needed
    view.e_ss_mut().write(0x0000); // Initial (relative) SS value
    view.e_sp_mut().write(0x00B8); // Initial SP value
    view.e_csum_mut().write(0x0000); // Checksum
    view.e_ip_mut().write(0x0000); // Initial IP value
    view.e_cs_mut().write(0x0000); // Initial (relative) CS value
    view.e_lfarlc_mut().write(0x0040); // File address of relocation table
    view.e_ovno_mut().write(0x0000); // Overlay number

    // Reserved words
    view.e_res1_1_mut().write(0x0000);
    view.e_res1_2_mut().write(0x0000);
    view.e_res1_3_mut().write(0x0000);
    view.e_res1_4_mut().write(0x0000);

    view.e_oemid_mut().write(0x0000); // OEM identifier (for e_oeminfo)
    view.e_oeminfo_mut().write(0x0000); // OEM information; e_oemid specific

    // Reserved words
    view.e_res2_1_mut().write(0x0000);
    view.e_res2_2_mut().write(0x0000);
    view.e_res2_3_mut().write(0x0000);
    view.e_res2_4_mut().write(0x0000);
    view.e_res2_5_mut().write(0x0000);
    view.e_res2_6_mut().write(0x0000);
    view.e_res2_7_mut().write(0x0000);
    view.e_res2_8_mut().write(0x0000);
    view.e_res2_9_mut().write(0x0000);
    view.e_res2_10_mut().write(0x0000);

    view.e_lfanew_mut().write(offset); // File address of new exe header
}

/// Sets up the IMAGE_DOS_STUB
pub(crate) fn set_image_dos_stub<S: AsRef<[u8]> + AsMut<[u8]>>(mut view: image_dos_stub::View<S>) {
    let dos_msg = b"This program cannot be run in DOS mode.";
    let len = dos_msg.len().min(64);

    view.data_mut()[..len].copy_from_slice(&dos_msg[..len]);
}

/// Sets up an IMAGE_DATA_DIRECTORY entry
pub(crate) fn set_image_data_directory<S: AsRef<[u8]> + AsMut<[u8]>>(
    mut view: image_data_directory::View<S>,
) {
    view.virtual_address_mut().write(0); // No special tables
    view.size_mut().write(0);
}

/// Sets up the IMAGE_SECTION_HEADER
pub(crate) fn set_image_section_header<S: AsRef<[u8]> + AsMut<[u8]>>(
    mut view: image_section_header::View<S>,
    section: &str,
    virtual_size: DWORD,
    virtual_address: DWORD,
    size_of_raw_data: DWORD,
) {
    let len = section.len().min(8);
    let section = section.as_bytes();

    view.name_mut()[..len].copy_from_slice(&section[..len]);
    view.virtual_size_mut().write(virtual_size);
    view.virtual_address_mut().write(virtual_address);
    view.size_of_raw_data_mut().write(size_of_raw_data);
    view.pointer_to_raw_data_mut().write(0x400); //
    view.pointer_to_relocations_mut().write(0);
    view.pointer_to_linenumbers_mut().write(0);
    view.number_of_relocations_mut().write(0);
    view.number_of_linenumbers_mut().write(0);
    view.characteristics_mut().write(
        IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE,
    );
}

/// Sets up the IMAGE_FILE_HEADER
pub(crate) fn set_image_file_header<S: AsRef<[u8]> + AsMut<[u8]>>(
    mut view: image_file_header::View<S>,
    machine: WORD,
    num_of_sections: WORD,
    size_of_optional_header: WORD,
) {
    view.machine_mut().write(machine);
    view.number_of_sections_mut().write(num_of_sections);
    view.time_date_stamp_mut().write(0);
    view.pointer_to_symbol_table_mut().write(0);
    view.number_of_symbols_mut().write(0);
    view.size_of_optional_header_mut()
        .write(size_of_optional_header);
    view.characteristics_mut()
        .write(IMAGE_FILE_EXECUTABLE_IMAGE);
}
