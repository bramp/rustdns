//! Classic DNS ("Do53") client combining UDP with TCP retry on truncation.

/// Google Public DNS primary IPv4 address and port.
pub const GOOGLE_IPV4_PRIMARY: &str = "8.8.8.8:53";
/// Google Public DNS secondary IPv4 address and port.
pub const GOOGLE_IPV4_SECONDARY: &str = "8.8.4.4:53";
/// Google Public DNS primary IPv6 address and port.
pub const GOOGLE_IPV6_PRIMARY: &str = "[2001:4860:4860::8888]:53";
/// Google Public DNS secondary IPv6 address and port.
pub const GOOGLE_IPV6_SECONDARY: &str = "[2001:4860:4860::8844]:53";

/// Google Public DNS upstream endpoints covering IPv4 and IPv6 primary and secondary addresses.
pub const GOOGLE: [&str; 4] = [
    GOOGLE_IPV4_PRIMARY,
    GOOGLE_IPV4_SECONDARY,
    GOOGLE_IPV6_PRIMARY,
    GOOGLE_IPV6_SECONDARY,
];

// TODO Add CloudFlare, Quad9, and other popular DNS providers.

mod r#async;
pub use r#async::*;

#[cfg(feature = "sync")]
pub mod sync;
