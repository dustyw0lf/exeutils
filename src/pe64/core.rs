//! Core functionality for working with PE64 files
use binary_layout::Field;

use super::layout::*;

/// Sets up the PE64 IMAGE_DOS_HEADER header
fn set_image_dos_header<S: AsRef<[u8]> + AsMut<[u8]>>(
    mut view: image_dos_header::View<S>,
    offset: LONG,
) {
    view.e_magic_mut().write(E_MAGIC);
    view.e_lfanew_mut().write(offset);
}

/// Sets up the IMAGE_NT_HEADERS64 header
fn set_image_nt_headers64<S: AsRef<[u8]> + AsMut<[u8]>>(
    mut view: image_nt_headers64::View<S>,
    image_size: DWORD,
    headers_size: DWORD,
) {
    view.signature_mut().write(SIGNATURE);
    set_image_file_header(view.file_header_mut());
    set_image_optional_header64(view.optional_header_mut(), image_size, headers_size);
}

/// Sets up the IMAGE_FILE_HEADER haeder
fn set_image_file_header<S: AsRef<[u8]> + AsMut<[u8]>>(mut view: image_file_header::View<S>) {
    view.machine_mut().write(IMAGE_FILE_MACHINE_AMD64);
    view.characteristics_mut()
        .write(IMAGE_FILE_EXECUTABLE_IMAGE);
}

/// Sets up the IMAGE_OPTIONAL_HEADER64 header
fn set_image_optional_header64<S: AsRef<[u8]> + AsMut<[u8]>>(
    mut view: image_optional_header64::View<S>,
    image_size: DWORD,
    headers_size: DWORD,
) {
    view.magic_mut().write(IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    view.address_of_entry_point_mut().write(headers_size); // RVA
    view.image_base_mut().write(IMAGE_BASE);
    view.section_alignment_mut().write(1);
    view.file_alignment_mut().write(1);
    view.major_subsystem_version_mut()
        .write(MAJOR_SUBSYSTEM_VERSION);
    view.size_of_image_mut().write(image_size);
    view.size_of_headers_mut().write(headers_size);
    view.subsystem_mut().write(IMAGE_SUBSYSTEM_WINDOWS_CUI);
}

pub fn shellcode_to_exe(shellcode: &[u8]) -> Vec<u8> {
    let dos_header_size = image_dos_header::SIZE.unwrap();
    let nt_headers64_size = image_nt_headers64::SIZE.unwrap();
    let headers_size = (image_dos_header::e_lfanew::SIZE.unwrap()
        + 4
        + image_file_header::SIZE.unwrap()
        + image_optional_header64::SIZE.unwrap()) as DWORD;

    let mut buf = vec![0u8; dos_header_size + nt_headers64_size + shellcode.len()];
    let image_size = buf.len() as DWORD;

    let mut file = pe64_file::View::new(&mut buf);
    set_image_dos_header(file.dos_header_mut(), dos_header_size as DWORD);
    set_image_nt_headers64(file.nt_headers64_mut(), image_size, headers_size);
    file.shellcode_mut().copy_from_slice(shellcode);

    buf
}
