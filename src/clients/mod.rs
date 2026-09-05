//! DNS clients (transports).
//!
//! `udp`, `tcp`, `do53`, and `dot` (async and their `sync` equivalents) follow
//! one constructor convention:
//!
//! - `new(server: SocketAddr, ..)` — `server` is already resolved. Infallible,
//!   unless another argument needs validation (see `try_new`). Never performs
//!   a DNS lookup.
//! - `try_new(.., server: SocketAddr, ..)` — same as `new`, but returns
//!   `Result` because some other argument needs validation, for example DoT's
//!   TLS server name. Still never performs a DNS lookup.
//! - `try_from_host_port(server: &str)` — resolves a `host:port` string before
//!   constructing the client. This is a bootstrap DNS dependency: it must not
//!   be served by the resolver being built. The sync clients block the
//!   calling thread to resolve; the async DoT client awaits
//!   `tokio::net::lookup_host` instead. Always fallible.
//!
//! Prefer `new`/`try_new` whenever the address is already known, such as
//! inside a `Resolver` upstream. Reach for `try_from_host_port` only for
//! one-off, human-entered addresses, such as CLI arguments.

use crate::Message;

#[cfg(any(feature = "doh", feature = "json"))]
use http_body_util::combinators::BoxBody;
#[cfg(any(feature = "doh", feature = "json"))]
use hyper::body::Bytes;
#[cfg(any(feature = "doh", feature = "json"))]
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
#[cfg(any(feature = "doh", feature = "json"))]
use hyper_util::client::legacy::Client as HyperClient;
#[cfg(any(feature = "doh", feature = "json"))]
use hyper_util::client::legacy::connect::HttpConnector;
#[cfg(any(feature = "doh", feature = "json"))]
use hyper_util::rt::TokioExecutor;

#[cfg(any(feature = "doh", feature = "json"))]
use std::io;

#[cfg(any(feature = "doh", feature = "json"))]
use http::StatusCode;

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

#[cfg(any(feature = "do53", feature = "dot"))]
mod timeouts;

cfg_feature! {
    #![feature = "http_deps"]

    mod to_urls;

    pub use self::to_urls::ToUrls;
}

#[cfg(any(feature = "doh", feature = "json"))]
mod mime;

#[cfg(any(
    feature = "doh",
    feature = "json",
    all(feature = "sync", any(feature = "do53", feature = "dot"))
))]
mod stats;

#[cfg(any(feature = "doh", feature = "json"))]
pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[cfg(any(feature = "doh", feature = "json"))]
pub(crate) type HttpClient = HyperClient<HttpsConnector<HttpConnector>, BoxBody<Bytes, BoxError>>;

#[cfg(any(feature = "doh", feature = "json"))]
pub(crate) fn new_http_client() -> HttpClient {
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();

    HyperClient::builder(TokioExecutor::new())
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .http2_only(true)
        .build(https)
}

#[cfg(any(feature = "doh", feature = "json"))]
pub(crate) fn validate_http_status(status: StatusCode) -> io::Result<()> {
    if status.is_success() {
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("recevied unexpected HTTP status code: {status}"),
    ))
}

/// Exchanger takes a query and returns a response.
pub trait Exchanger {
    fn exchange(&self, query: &Message) -> Result<Message, crate::Error>;
}

use async_trait::async_trait;

#[async_trait]
pub trait AsyncExchanger {
    async fn exchange(&self, query: &Message) -> Result<Message, crate::Error>;
}

#[cfg(feature = "do53")]
mod pooled {
    use super::{AsyncExchanger, Message, async_trait};

    /// Like [`AsyncExchanger`], but requires exclusive access, for transports
    /// (such as the async UDP/TCP clients) that reuse a socket or connection
    /// across exchanges.
    pub trait AsyncExchangerMut {
        fn exchange(
            &mut self,
            query: &Message,
        ) -> impl std::future::Future<Output = Result<Message, crate::Error>> + Send;
    }

    #[cfg(feature = "do53")]
    impl AsyncExchangerMut for super::udp::Client {
        async fn exchange(&mut self, query: &Message) -> Result<Message, crate::Error> {
            self.exchange(query).await
        }
    }

    #[cfg(feature = "do53")]
    impl AsyncExchangerMut for super::tcp::Client {
        async fn exchange(&mut self, query: &Message) -> Result<Message, crate::Error> {
            self.exchange(query).await
        }
    }

    #[cfg(feature = "do53")]
    impl AsyncExchangerMut for super::do53::Client {
        async fn exchange(&mut self, query: &Message) -> Result<Message, crate::Error> {
            self.exchange(query).await
        }
    }

    #[cfg(feature = "dot")]
    impl AsyncExchangerMut for super::dot::Client {
        async fn exchange(&mut self, query: &Message) -> Result<Message, crate::Error> {
            self.exchange(query).await
        }
    }

    /// Adapts an [`AsyncExchangerMut`] transport into the object-safe
    /// [`AsyncExchanger`] by serializing exchanges through an internal async mutex.
    pub struct Pooled<T>(tokio::sync::Mutex<T>);

    impl<T> Pooled<T> {
        pub fn new(transport: T) -> Self {
            Self(tokio::sync::Mutex::new(transport))
        }
    }

    #[async_trait]
    impl<T> AsyncExchanger for Pooled<T>
    where
        T: AsyncExchangerMut + Send,
    {
        async fn exchange(&self, query: &Message) -> Result<Message, crate::Error> {
            self.0.lock().await.exchange(query).await
        }
    }
}

#[cfg(feature = "do53")]
pub use self::pooled::{AsyncExchangerMut, Pooled};

#[cfg(test)]
mod tests {
    #[test]
    fn clients_reject_empty_server_lists() {
        #[cfg(feature = "doh")]
        assert!(super::doh::Client::new(&[] as &[url::Url], http::Method::GET).is_err());

        #[cfg(feature = "json")]
        assert!(super::json::Client::new(&[] as &[url::Url]).is_err());
    }
}
