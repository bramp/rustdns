use crate::Message;

pub use self::resolver::Resolver;
pub use self::to_urls::ToUrls;

pub mod doh;
pub mod json;
pub mod tcp;
pub mod udp;

mod resolver;
mod to_urls;
mod utils;

/// Exchanger takes a query and returns a response.
pub trait Exchanger {
    fn exchange(&self, query: &Message) -> Result<Message, crate::Error>;
}

use async_trait::async_trait;

#[async_trait]
pub trait AsyncExchanger {
    async fn exchange(&self, query: &Message) -> Result<Message, crate::Error>;
}
