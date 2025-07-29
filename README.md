# Exeutils
`exeutils` is a Rust crate for working with executable formats and shellcode.

## Functionality
`exeutils` currently supports converting 64-bit ELF, as well as 32-bit and 64-bit PE shellcode to an executable.

## Usage
Add `exeutils` as a dependency to your Rust project with the required features, e.g., `elf64`
```bash
cargo add --git https://github.com/dustyw0lf/exeutils.git --features elf64
```

## Features
`exeutils` has no features enabled by default. The user should enable one or more of the following
features to enable converting shellcode:
- `elf64`
- `pe32`
- `pe64`

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

The documentation will be in `target/doc/exeutils/index.html`.

## Acknowledgments
The code that turns shellcode into an ELF64 executable is based on the [minimal-elf](https://github.com/tchajed/minimal-elf) repository by [Tej Chajed](https://www.chajed.io).