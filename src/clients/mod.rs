use crate::Message;

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

/// Exchanger takes a query and returns a response.
pub trait Exchanger {
    fn exchange(&self, query: &Message) -> Result<Message, crate::Error>;
}

use async_trait::async_trait;

#[async_trait]
pub trait AsyncExchanger {
    async fn exchange(&self, query: &Message) -> Result<Message, crate::Error>;
}
