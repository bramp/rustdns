//! Classic DNS ("Do53") client combining UDP with TCP retry on truncation.

pub const GOOGLE_IPV4_PRIMARY: &str = "8.8.8.8:53";
pub const GOOGLE_IPV4_SECONDARY: &str = "8.8.4.4:53";
pub const GOOGLE_IPV6_PRIMARY: &str = "[2001:4860:4860::8888]:53";
pub const GOOGLE_IPV6_SECONDARY: &str = "[2001:4860:4860::8844]:53";

pub const GOOGLE: [&str; 4] = [
    GOOGLE_IPV4_PRIMARY,
    GOOGLE_IPV4_SECONDARY,
    GOOGLE_IPV6_PRIMARY,
    GOOGLE_IPV6_SECONDARY,
];

mod r#async;
pub use r#async::*;

#[cfg(feature = "sync")]
pub mod sync;
