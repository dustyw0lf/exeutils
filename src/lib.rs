//! Rust crate for working with executable
//! formats and shellcode
//! # Features
//!
//! - `elf64`: Functions for 64-bit ELF executables and shellcode.
//! - `pef32`: Functions for 32-bit PE executables and shellcode.
//! - `pef64`: Functions for 64-bit PE executables and shellcode.

#[cfg(feature = "elf64")]
pub mod elf64;

#[cfg(any(feature = "pe32", feature = "pe64"))]
mod pe;

// Re-export pe64 at the top level
#[cfg(feature = "pe32")]
pub use pe::pe32;

#[cfg(feature = "pe64")]
pub use pe::pe64;
