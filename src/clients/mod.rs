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

#[cfg(any(feature = "doh", feature = "exchanger"))]
pub mod doh;

#[cfg(feature = "dot")]
pub mod dot;

#[cfg(any(feature = "doh-json", feature = "exchanger"))]
pub mod json;

#[cfg(feature = "do53")]
pub mod do53;

#[cfg(feature = "do53")]
pub mod tcp;

#[cfg(feature = "do53")]
pub mod udp;

#[cfg(feature = "sync")]
pub mod sync;

pub(crate) mod common;

cfg_feature! {
    #![any(feature = "clients", feature = "resolver")]

    mod into_exchanger;
    pub use self::into_exchanger::IntoAsyncExchanger;
}

cfg_feature! {
    #![feature = "resolver"]

    mod resolver;
    pub use self::resolver::{
        AsyncResolver, Backoff, Resolver, ResolverBuilder, Response, ResponseMeta, Strategy,
    };
}

mod wire_response;
pub use wire_response::{WireResponse, WireResponseMeta};

use crate::types::ChannelSecurity;

/// Exchanger takes a query and returns a low-level [`WireResponse`].
pub trait Exchanger {
    fn exchange(&self, query: &Message) -> Result<WireResponse, crate::Error>;

    /// Returns a string describing the endpoint of this exchanger (e.g. server address or URL).
    fn endpoint(&self) -> Arc<str>;

    /// Returns the transport security classification of this exchanger.
    ///
    /// Defaults to [`ChannelSecurity::Insecure`].
    ///
    /// # Security & Cryptographic Policies
    ///
    /// Callers that require minimum TLS protocol versions (such as TLS 1.3), specific
    /// cipher suites, certificate revocation checks, or custom trust roots should
    /// configure those settings directly on the underlying client or connector
    /// (e.g., via [`rustls::ClientConfig`]) when instantiating the exchanger.
    fn channel_security(&self) -> ChannelSecurity {
        ChannelSecurity::Insecure
    }

    /// Returns whether this exchanger communicates over a secure channel
    /// (either [`ChannelSecurity::Loopback`] or [`ChannelSecurity::Encrypted`]).
    fn is_secure_channel(&self) -> bool {
        self.channel_security().is_secure()
    }
}

use async_trait::async_trait;

#[async_trait]
pub trait AsyncExchanger {
    async fn exchange(&self, query: &Message) -> Result<WireResponse, crate::Error>;

    /// Returns a string describing the endpoint of this exchanger (e.g. server address or URL).
    fn endpoint(&self) -> Arc<str>;

    /// Returns the transport security classification of this exchanger.
    ///
    /// Defaults to [`ChannelSecurity::Insecure`].
    ///
    /// # Security & Cryptographic Policies
    ///
    /// Callers that require minimum TLS protocol versions (such as TLS 1.3), specific
    /// cipher suites, certificate revocation checks, or custom trust roots should
    /// configure those settings directly on the underlying client or connector
    /// (e.g., via [`rustls::ClientConfig`]) when instantiating the exchanger.
    fn channel_security(&self) -> ChannelSecurity {
        ChannelSecurity::Insecure
    }

    /// Returns whether this exchanger communicates over a secure channel
    /// (either [`ChannelSecurity::Loopback`] or [`ChannelSecurity::Encrypted`]).
    fn is_secure_channel(&self) -> bool {
        self.channel_security().is_secure()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn clients_reject_plaintext_urls() {
        let plaintext: url::Url = "http://dns.example/dns-query".parse().unwrap();

        #[cfg(feature = "doh")]
        assert!(super::doh::Client::try_new(plaintext.clone(), http::Method::GET).is_err());

        #[cfg(feature = "doh-json")]
        assert!(super::json::Client::try_new(plaintext).is_err());
    }
}
