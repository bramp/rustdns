//! DNS-over-HTTPS JSON client (Google / Cloudflare format).

// For use in Content-type and Accept headers
// Google actually uses "application/json", but Cloud Flare requires "application/dns-json".
// Since Google's API seems to accept either, we default to dns-json.
pub use crate::json::{CONTENT_TYPE_APPLICATION_DNS_JSON, CONTENT_TYPE_APPLICATION_JSON};

/// Google Public DNS JSON endpoint URL.
pub const GOOGLE: &str = "https://dns.google/resolve";

/// Cloudflare DNS over HTTPS JSON endpoint URL.
pub const CLOUDFLARE: &str = "https://cloudflare-dns.com/dns-query";

#[cfg(feature = "doh-json")]
mod r#async;
#[cfg(feature = "doh-json")]
pub use r#async::*;
