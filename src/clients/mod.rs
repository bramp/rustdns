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

#[cfg(any(feature = "tcp", feature = "async-tcp"))]
pub mod tcp;

#[cfg(feature = "async-tcp")]
mod tcp_async;

#[cfg(feature = "async-udp")]
mod udp_async;

cfg_feature! {
    #![feature = "udp"]

    #[cfg(any(feature = "udp", feature = "async-udp"))]
    pub mod udp;
    mod resolver;
    pub use self::resolver::Resolver;
}

cfg_feature! {
    #![feature = "http_deps"]

    mod to_urls;

    pub use self::to_urls::ToUrls;
}

#[cfg(any(feature = "doh", feature = "json"))]
mod mime;

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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    #[test]
    fn clients_reject_empty_server_lists() {
        #[cfg(feature = "tcp")]
        assert!(super::tcp::Client::new(&[] as &[SocketAddr]).is_err());

        #[cfg(feature = "udp")]
        assert!(super::udp::Client::new(&[] as &[SocketAddr]).is_err());

        #[cfg(feature = "doh")]
        assert!(super::doh::Client::new(&[] as &[url::Url], http::Method::GET).is_err());

        #[cfg(feature = "dot")]
        assert!(
            super::dot::Client::new_with_server_name("dns.google", &[] as &[SocketAddr]).is_err()
        );

        #[cfg(feature = "json")]
        assert!(super::json::Client::new(&[] as &[url::Url]).is_err());
    }
}
