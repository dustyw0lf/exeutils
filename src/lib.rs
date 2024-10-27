//! Rust crate for working with executable
//! formats and shellcode
//! # Features
//!
//! - `[feature]`: [description].

// region:    --- Modules

#[cfg(feature = "elf64")]
pub mod elf;
#[cfg(feature = "pe64")]
pub mod pe;

// endregion: --- Modules
