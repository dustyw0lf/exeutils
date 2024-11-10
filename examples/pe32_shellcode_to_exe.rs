use std::env::current_dir;
use std::fs::{self, File};
use std::io::Write;

use exeutils::pe32;

fn main() {
    let path = current_dir().unwrap();
    let cwd = path.display();

    // Shellcode:
    let shellcode_path = format!("{}/assets/windows-x86.bin", cwd);

    let shellcode_bytes = fs::read(shellcode_path).expect("Failed to open file");

    let pe_bytes = pe32::shellcode_to_exe(&shellcode_bytes);

    let pe_path = format!("{}/assets/converted_x86.exe", cwd);

    let mut file = File::create(&pe_path).unwrap();
    file.write_all(&pe_bytes).unwrap();
}
