//! Rust crate for working with executable
//! formats and shellcode
//! # Features
//!
//! - `[feature]`: [description].

// region:    --- Modules

#[cfg(feature = "elf64")]
pub mod elf64;
#[cfg(feature = "pe64")]
pub mod pe64;

// endregion: --- Modules
