#[cfg(any(feature = "pe32", feature = "pe64"))]
mod common;

#[cfg(feature = "pe32")]
mod pe32;
#[cfg(feature = "pe64")]
mod pe64;

#[cfg(feature = "pe32")]
pub use pe32::shellcode_to_exe;
#[cfg(feature = "pe64")]
pub use pe64::shellcode_to_exe;
