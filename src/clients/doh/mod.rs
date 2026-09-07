//! DNS-over-HTTPS (DoH) client (RFC 8484).

/// Media type for DNS-over-HTTPS binary wire messages per [RFC 8484 §6].
///
/// [RFC 8484 §6]: https://datatracker.ietf.org/doc/html/rfc8484#section-6
pub const CONTENT_TYPE_APPLICATION_DNS_MESSAGE: &str = "application/dns-message";

/// The URI parameter name containing the base64url-encoded DNS query in DoH GET requests per [RFC 8484 §4.1].
///
/// [RFC 8484 §4.1]: https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
pub const DNS_QUERY_PARAM: &str = "dns";

/// Google Public DNS DoH endpoint URL.
pub const GOOGLE: &str = "https://dns.google/dns-query";

/// Cloudflare DNS over HTTPS DoH endpoint URL.
pub const CLOUDFLARE: &str = "https://cloudflare-dns.com/dns-query";

#[cfg(feature = "doh")]
mod r#async;
#[cfg(feature = "doh")]
pub use r#async::*;
