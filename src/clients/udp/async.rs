use crate::Message;
use crate::clients::AsyncExchanger;
use crate::clients::common::timeouts::with_timeout;
use crate::limits::MAX_DNS_MESSAGE_LEN;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// An asynchronous DNS-over-UDP client.
///
/// This is a low-level client: it sends one query to one server and returns the
/// response. It does not retry, does not fail over between servers, and does
/// not follow a truncated (`TC=1`) response over TCP.
///
/// Prefer [`do53::Client`](crate::clients::do53::Client), which pairs UDP with
/// TCP and performs the truncation retry required by [rfc2181] and [rfc7766].
///
/// Exchanges are serialized across tasks. The socket is reused across exchanges,
/// and discarded on failure.
///
/// # Example
///
/// ```rust,no_run
/// use rustdns::clients::AsyncExchanger;
/// use rustdns::clients::udp::Client;
/// use rustdns::types::*;
///
/// #[tokio::main]
/// async fn main() -> Result<(), rustdns::Error> {
///     let mut query = Message::default();
///     query.try_add_question("bramp.net", Type::A, Class::Internet)?;
///
///     let client = Client::new("8.8.8.8:53".parse().unwrap());
///     let response = client.exchange(&query).await?;
///
///     println!("{}", response);
///     Ok(())
/// }
/// ```
///
/// See [rfc1035].
///
/// See the `clients` module docs for the `new`/`try_from_host_port` convention.
///
/// [rfc1035]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.1
/// [rfc2181]: https://datatracker.ietf.org/doc/html/rfc2181#section-9
/// [rfc7766]: https://datatracker.ietf.org/doc/html/rfc7766#section-5
pub struct Client {
    /// The DNS server this client queries.
    server: SocketAddr,

    /// Maximum time allowed to receive a response. Defaults to five seconds.
    read_timeout: Duration,

    /// Lazily created socket, connected to `server` and reused across exchanges.
    socket: tokio::sync::Mutex<Option<tokio::net::UdpSocket>>,
}

impl Client {
    /// Creates an asynchronous client for one DNS server.
    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
            read_timeout: Duration::from_secs(5),
            socket: tokio::sync::Mutex::new(None),
        }
    }

    /// Returns the server this client queries.
    pub fn server(&self) -> SocketAddr {
        self.server
    }

    /// Sets the timeout for receiving a response.
    ///
    /// UDP has no delivery guarantee, so without a timeout a dropped response
    /// leaves the exchange waiting indefinitely.
    pub fn set_read_timeout(&mut self, timeout: Duration) {
        self.read_timeout = timeout;
    }
}

#[async_trait]
impl AsyncExchanger for Client {
    /// Sends one DNS query and returns its response.
    async fn exchange(&self, query: &Message) -> Result<Message, crate::Error> {
        let mut guard = self.socket.lock().await;
        if guard.is_none() {
            log::trace!("async UDP target={}", self.server);
            let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
            socket.connect(self.server).await?;
            log::trace!(
                "async UDP connected local={} peer={}",
                socket.local_addr()?,
                socket.peer_addr()?
            );
            *guard = Some(socket);
        } else {
            log::trace!("async UDP reusing connected socket peer={}", self.server);
        }

        let read_timeout = self.read_timeout;
        let result: std::io::Result<Message> = async {
            let socket = guard.as_mut().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotConnected, "UDP socket unavailable")
            })?;
            let request = query.to_vec()?;
            log::trace!(
                "async UDP sending {} bytes to {}",
                request.len(),
                self.server
            );
            socket.send(&request).await?;
            let mut response = [0; MAX_DNS_MESSAGE_LEN];
            let length = with_timeout(
                read_timeout,
                "UDP read timed out",
                socket.recv(&mut response),
            )
            .await?;
            log::trace!("async UDP received {length} bytes from {}", self.server);
            Ok(Message::from_slice(&response[..length])?)
        }
        .await;

        match result {
            Ok(response) => Ok(response),
            Err(error) => {
                log::trace!("async UDP discarding socket after error: {error}");
                *guard = None;
                Err(error.into())
            }
        }
    }

    fn endpoint(&self) -> Arc<str> {
        format!("udp://{}", self.server).into()
    }

    fn channel_security(&self) -> crate::types::ChannelSecurity {
        if self.server.ip().is_loopback() {
            crate::types::ChannelSecurity::Loopback
        } else {
            crate::types::ChannelSecurity::Insecure
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Client;
    use crate::Message;
    use crate::clients::AsyncExchanger;
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn exchanges_with_local_server() {
        let server_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind test socket");
        let address: SocketAddr = server_socket
            .local_addr()
            .expect("read test socket address");
        let server = tokio::spawn(async move {
            let mut request = [0; 512];
            let (_, peer) = server_socket
                .recv_from(&mut request)
                .await
                .expect("read request");
            server_socket
                .send_to(&[0; 12], peer)
                .await
                .expect("write response");
        });

        let client = Client::new(address);
        assert!(client.exchange(&Message::default()).await.is_ok());
        server.await.expect("join test server");
    }

    #[tokio::test]
    async fn read_timeout_ends_an_unanswered_exchange() {
        // Bound to nothing that replies, so only the read timeout ends the wait.
        let server_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind test socket");
        let address: SocketAddr = server_socket
            .local_addr()
            .expect("read test socket address");

        let mut client = Client::new(address);
        client.set_read_timeout(std::time::Duration::from_millis(10));

        let error = client
            .exchange(&Message::default())
            .await
            .expect_err("unanswered query should time out");
        assert!(error.to_string().contains("timed out"), "{error}");
    }
}
