//! Core functionality for working with PE64 files
use super::layout::*;

/// Sets up the PE64 IMAGE_DOS_HEADER header
fn set_image_dos_header<S: AsRef<[u8]> + AsMut<[u8]>>(mut view: image_dos_header::View<S>) {
    view.e_magic_mut().write(E_MAGIC);
    view.e_lfanew_mut().write(0x40);
}

/// Sets up the IMAGE_NT_HEADERS64 header
fn set_image_nt_headers64<S: AsRef<[u8]> + AsMut<[u8]>>(mut view: image_nt_headers64::View<S>) {
    view.signature_mut().write(SIGNATURE);
    set_image_file_header(view.file_header_mut());
    set_image_optional_header64(view.optional_header_mut());
}

/// Sets up the IMAGE_FILE_HEADER haeder
fn set_image_file_header<S: AsRef<[u8]> + AsMut<[u8]>>(mut view: image_file_header::View<S>) {
    view.machine_mut().write(IMAGE_FILE_MACHINE_AMD64);
}

/// Sets up the IMAGE_OPTIONAL_HEADER64 haeder
fn set_image_optional_header64<S: AsRef<[u8]> + AsMut<[u8]>>(
    mut view: image_optional_header64::View<S>,
) {
    todo!()
}

#[allow(unused_variables)]
pub fn shellcode_to_exe(shellcode: &[u8]) -> Vec<u8> {
    todo!();
}
