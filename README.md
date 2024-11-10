# Exeutils
`exeutils` is a Rust crate for working with executable formats and shellcode.

## Functionality
`exeutils` supports the following conversion operations:

ELF64:
- From shellcode to executable.

PE64:
- From shellcode to executable.

## Usage
Add `exeutils` as a dependency to your Rust project with the required features, e.g., `elf64`
```bash
cargo add --git https://github.com/dustyw0lf/exeutils.git --features elf64
```

## Features
`exeutils` has no features enabled by default. The user should enable one or more of the follwoing:
- `elf64`: Adds functionality to work with the ELF64 format.
- `pe64`: Adds functionality to work with the PE64 format.

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