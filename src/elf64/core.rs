//! Core functionality for working with ELF64 files
use super::layout::*;

/// Sets up the ELF64 file identification header
fn set_ident<S: AsRef<[u8]> + AsMut<[u8]>>(mut view: elf64_ident::View<S>) {
    view.mag_mut().copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    view.class_mut().write(2); // class: ELFCLASS64
    view.data_mut().write(1); // data encoding: ELFDATA2LSB
    view.version_mut().write(1); // file version: EV_CURRENT
    view.os_abi_mut().write(0); // OS/ABI identification: System V
    view.abi_version_mut().write(0); // ABI version: System V third edition
    view.pad_mut().copy_from_slice(&[0u8; 7]);
}

/// Sets up the ELF64 main header
fn set_elf64_hdr<S: AsRef<[u8]> + AsMut<[u8]>>(mut view: elf64_hdr::View<S>) {
    set_ident(view.ident_mut());
    view._type_mut().write(2); // ET_EXEC
    view.machine_mut().write(62); // EM_X86_64
    view.version_mut().write(1); // EV_CURRENT
    view.entry_mut().write(VADDR + PROGRAM_OFFSET);
    view.phoff_mut().write(elf64_hdr::SIZE.unwrap() as u64);
    view.flags_mut().write(0); // no processor-specific flags
    view.ehsize_mut().write(elf64_hdr::SIZE.unwrap() as u16);
    view.phentsize_mut().write(elf64_phdr::SIZE.unwrap() as u16);
    view.phnum_mut().write(1);
}

/// Sets up the ELF64 program header
fn set_elf64_phdr<S>(mut view: elf64_phdr::View<S>, program_size: u64)
where
    S: AsRef<[u8]> + AsMut<[u8]>,
{
    view._type_mut().write(1); // PT_LOAD
    view.flags_mut().write(0x1 | 0x2 | 0x4); // PF_X | PF_W | PF_R

    // location of segment in file
    let offset = (elf64_hdr::SIZE.unwrap() + elf64_phdr::SIZE.unwrap()) as u64;
    view.offset_mut().write(offset);
    // virtual address of segment
    view.vaddr_mut().write(VADDR + PROGRAM_OFFSET);

    view.filesz_mut().write(program_size);
    view.memsz_mut().write(program_size);
    view.align_mut().write(4096);
}

/// Converts shellcode into an ELF64 executable
pub fn shellcode_to_exe(shellcode: &[u8]) -> Vec<u8> {
    let hdr_sz = elf64_hdr::SIZE.unwrap();
    let phdr_sz = elf64_phdr::SIZE.unwrap();
    let mut buf = vec![0u8; hdr_sz + phdr_sz + shellcode.len()];
    let mut file = elf64_file::View::new(&mut buf);
    set_elf64_hdr(file.hdr_mut());
    set_elf64_phdr(file.phdr_mut(), shellcode.len() as u64);
    file.program_mut().copy_from_slice(shellcode);
    buf
}
