#[cfg(any(feature = "pe32", feature = "pe64"))]
pub(crate) mod common;

#[cfg(feature = "pe32")]
pub mod pe32;
#[cfg(feature = "pe64")]
pub mod pe64;
