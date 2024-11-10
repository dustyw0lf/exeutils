# Exeutils
`exeutils` is a Rust crate for working with executable formats and shellcode.

## Functionality
| Format | Source | Destination | Implemented |
|--------|--------|-------------|-------------|
| ELF64  | Shellcode | Executable | ✔️ |
| ELF32  | Shellcode | Executable | ❌ |
| PE64   | Shellcode | Executable | ✔️ |
| PE32   | Shellcode | Executable | ❌ |

## Usage
Add `exeutils` as a dependency to your Rust project with the required features, e.g., `elf64`
```bash
cargo add --git https://github.com/dustyw0lf/exeutils.git --features elf64
```

## Features


## Examples
Convert ELF shellcode to an executable
```bash
cargo run --example elf_shellcode_to_exe
```

## Testing
Run tests
```bash
cargo test
```

## Documentation
Build the documentation
```bash
cargo doc --no-deps
```

The documentation will be in `target/doc/linc/index.html`.

## Acknowledgments
The code that turns shellcode into an ELF64 file is based on the [minimal-elf](https://github.com/tchajed/minimal-elf) repository by [Tej Chajed](https://www.chajed.io).