# Exeutils
`exeutils` is a Rust crate for working with executable formats and shellcode.

## Functionality


## Usage


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
The code that turns shellcode into an ELF file was taken from the [minimal-elf](https://github.com/tchajed/minimal-elf) repository by [Tej Chajed](https://www.chajed.io).