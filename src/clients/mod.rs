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

    /// Returns a string describing the endpoint of this exchanger (e.g. server address or URL).
    fn endpoint(&self) -> Arc<str>;
}

use async_trait::async_trait;

#[async_trait]
pub trait AsyncExchanger {
    async fn exchange(&self, query: &Message) -> Result<Message, crate::Error>;

    /// Returns a string describing the endpoint of this exchanger (e.g. server address or URL),
    /// if available.
    fn endpoint(&self) -> Option<Arc<str>> {
        None
    }
}

#[cfg(feature = "do53")]
mod pooled {
    use super::{AsyncExchanger, Message, async_trait};
    use std::sync::Arc;

    /// Like [`AsyncExchanger`], but requires exclusive access, for transports
    /// (such as the async UDP/TCP clients) that reuse a socket or connection
    /// across exchanges.
    pub trait AsyncExchangerMut {
        fn exchange(
            &mut self,
            query: &Message,
        ) -> impl std::future::Future<Output = Result<Message, crate::Error>> + Send;

        /// Returns a string describing the endpoint of this exchanger, if available.
        fn endpoint(&self) -> Option<Arc<str>> {
            None
        }
    }

    #[cfg(feature = "do53")]
    impl AsyncExchangerMut for super::udp::Client {
        async fn exchange(&mut self, query: &Message) -> Result<Message, crate::Error> {
            self.exchange(query).await
        }

        fn endpoint(&self) -> Option<Arc<str>> {
            Some(self.server().to_string().into())
        }
    }

    #[cfg(feature = "do53")]
    impl AsyncExchangerMut for super::tcp::Client {
        async fn exchange(&mut self, query: &Message) -> Result<Message, crate::Error> {
            self.exchange(query).await
        }

        fn endpoint(&self) -> Option<Arc<str>> {
            Some(self.server().to_string().into())
        }
    }

    #[cfg(feature = "do53")]
    impl AsyncExchangerMut for super::do53::Client {
        async fn exchange(&mut self, query: &Message) -> Result<Message, crate::Error> {
            self.exchange(query).await
        }

        fn endpoint(&self) -> Option<Arc<str>> {
            Some(self.server().to_string().into())
        }
    }

    #[cfg(feature = "dot")]
    impl AsyncExchangerMut for super::dot::Client {
        async fn exchange(&mut self, query: &Message) -> Result<Message, crate::Error> {
            self.exchange(query).await
        }

        fn endpoint(&self) -> Option<Arc<str>> {
            Some(format!("{}:{}", self.server_name(), self.server().port()).into())
        }
    }

    /// Adapts an [`AsyncExchangerMut`] transport into the object-safe
    /// [`AsyncExchanger`] by serializing exchanges through an internal async mutex.
    pub struct Pooled<T> {
        endpoint: Option<Arc<str>>,
        transport: tokio::sync::Mutex<T>,
    }

    impl<T: AsyncExchangerMut> Pooled<T> {
        pub fn new(transport: T) -> Self {
            let endpoint = transport.endpoint();
            Self {
                endpoint,
                transport: tokio::sync::Mutex::new(transport),
            }
        }
    }

    #[async_trait]
    impl<T> AsyncExchanger for Pooled<T>
    where
        T: AsyncExchangerMut + Send,
    {
        async fn exchange(&self, query: &Message) -> Result<Message, crate::Error> {
            self.transport.lock().await.exchange(query).await
        }

        fn endpoint(&self) -> Option<Arc<str>> {
            self.endpoint.clone()
        }
    }
}

#[cfg(feature = "do53")]
pub use self::pooled::{AsyncExchangerMut, Pooled};

#[cfg(test)]
mod tests {
    #[test]
    fn clients_reject_plaintext_urls() {
        let plaintext: url::Url = "http://dns.example/dns-query".parse().unwrap();

        #[cfg(feature = "doh")]
        assert!(super::doh::Client::try_new(plaintext.clone(), http::Method::GET).is_err());

        #[cfg(feature = "json")]
        assert!(super::json::Client::try_new(plaintext).is_err());
    }
}
