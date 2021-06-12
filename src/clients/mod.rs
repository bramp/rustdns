use crate::Message;
use std::io;

pub use self::doh::DoHClient;
pub use self::tcp::TcpClient;
pub use self::udp::UdpClient;

mod doh;
mod tcp;
mod udp;

/// Exchanger takes a query and returns a response.
pub trait Exchanger {
    fn exchange(&self, query: &Message) -> io::Result<Message>;
}

use async_trait::async_trait;

#[async_trait]
pub trait AsyncExchanger {
    // TODO Standardise on our Result type.
    async fn exchange(
        &self,
        query: &Message,
    ) -> std::result::Result<Message, Box<dyn std::error::Error + Send + Sync>>;
}
