//! Rust crate for working with executable
//! formats and shellcode
//! # Features
//!
//! - `elf64`: Functions for 64-bit ELF executables and shellcode.
//! - `pef64`: Functions for 64-bit PE executables and shellcode.

// region:    --- Modules

#[cfg(feature = "elf64")]
pub mod elf64;
#[cfg(feature = "pe64")]
pub mod pe64;

// endregion: --- Modules
