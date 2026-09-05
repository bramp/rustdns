//! DNS clients (transports).
//!
//! `udp`, `tcp`, `do53`, `dot`, `doh`, and `json` follow one constructor convention:
//!
//! - `new(server, ..)` — `server` is already resolved / typed (e.g. `SocketAddr` or `Url`).
//!   Infallible, unless argument validation is needed (see `try_new`). Never performs
//!   a DNS lookup.
//! - `try_new(server, ..)` — same as `new`, but returns `Result` because validation
//!   is required (for example, HTTPS scheme for DoH/JSON, or TLS server name for DoT).
//! - `try_from_host_port(server: &str)` / `try_from_url(server: &str, ..)` — resolves or
//!   parses a string representation before constructing the client.
//!
//! Prefer `new`/`try_new` whenever the address/URL is already known, such as
//! inside a `Resolver` upstream. Reach for `try_from_host_port` / `try_from_url`
//! for human-entered strings, such as CLI arguments.

use crate::Message;
use std::sync::Arc;

#[cfg(feature = "doh")]
pub mod doh;

#[cfg(feature = "dot")]
pub mod dot;

#[cfg(feature = "json")]
pub mod json;

#[cfg(feature = "do53")]
pub mod do53;

#[cfg(feature = "do53")]
pub mod tcp;

#[cfg(feature = "do53")]
pub mod udp;

#[cfg(feature = "sync")]
pub mod sync;

#[cfg(any(feature = "do53", feature = "dot"))]
mod framing;

#[cfg(any(feature = "doh", feature = "json"))]
pub(crate) mod http;

#[cfg(any(feature = "do53", feature = "dot", feature = "doh", feature = "json"))]
pub(crate) mod timeouts;

#[cfg(any(feature = "doh", feature = "json"))]
mod mime;

#[cfg(any(
    feature = "doh",
    feature = "json",
    all(feature = "sync", any(feature = "do53", feature = "dot"))
))]
mod stats;

/// Exchanger takes a query and returns a response.
pub trait Exchanger {
    fn exchange(&self, query: &Message) -> Result<Message, crate::Error>;

    /// Returns a string describing the endpoint of this exchanger (e.g. server address or URL).
    fn endpoint(&self) -> Arc<str>;
}

use async_trait::async_trait;

#[async_trait]
pub trait AsyncExchanger {
    async fn exchange(&self, query: &Message) -> Result<Message, crate::Error>;

    /// Returns a string describing the endpoint of this exchanger (e.g. server address or URL).
    fn endpoint(&self) -> Arc<str>;
}

#[cfg(test)]
mod tests {
    #[test]
    fn clients_reject_plaintext_urls() {
        let plaintext: url::Url = "http://dns.example/dns-query".parse\(\).unwrap\(\)\;

        #[cfg(feature = "doh")]
        assert!(super::doh::Client::try_new(plaintext.clone(), http::Method::GET\).is_err\(\)\)\;

        #[cfg(feature = "json")]
        assert!(super::json::Client::try_new(plaintext).is_err());
    }
}
