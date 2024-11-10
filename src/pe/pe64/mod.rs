//! Tools and definitions for working with the PE64 format
use super::common::layout as common_layout;

mod core;
mod layout;

pub use core::shellcode_to_exe;
