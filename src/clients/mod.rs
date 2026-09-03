use crate::Message;

#[cfg(any(feature = "doh", feature = "json"))]
use std::io;

#[cfg(any(feature = "doh", feature = "json"))]
use http::StatusCode;

#[cfg(feature = "doh")]
pub mod doh;

#[cfg(feature = "json")]
pub mod json;

#[cfg(feature = "tcp")]
pub mod tcp;

cfg_feature! {
    #![feature = "udp"]

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

        #[cfg(feature = "json")]
        assert!(super::json::Client::new(&[] as &[url::Url]).is_err());
    }
}
