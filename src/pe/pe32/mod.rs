//! Tools and definitions for working with the PE32 format
use super::common::core as common_core;
use super::common::layout as common_layout;

mod core;
mod layout;

pub use core::shellcode_to_exe;
