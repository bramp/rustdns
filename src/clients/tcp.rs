use crate::Message;
use crate::clients::framing::encode_tcp_frame;
use crate::clients::timeouts::with_timeout;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// An asynchronous DNS-over-TCP client.
///
/// This is a low-level client: it sends one query to one server and returns the
/// response. It does not retry or fail over between servers. DNS messages are
/// framed with a two-byte big-endian length prefix, and the connection is
/// reused across exchanges.
///
/// TCP carries responses that would be truncated over UDP, so this client is
/// the target of a `TC=1` retry rather than a source of one. Prefer
/// [`do53::Client`](crate::clients::do53::Client) to query over UDP first and
/// upgrade to TCP only when the server truncates.
///
/// Exchanges are sequential and require mutable access. The connection is
/// discarded on failure.
///
/// # Example
///
/// ```rust,no_run
/// use rustdns::clients::tcp::Client;
/// use rustdns::types::*;
///
/// #[tokio::main]
/// async fn main() -> Result<(), rustdns::Error> {
///     let mut query = Message::default();
///     query.try_add_question("bramp.net", Type::A, Class::Internet)?;
///
///     let mut client = Client::new("8.8.8.8:53".parse().unwrap());
///     let response = client.exchange(&query).await?;
///
///     println!("{}", response);
///     Ok(())
/// }
/// ```
///
/// See [rfc1035] and [rfc7766].
///
/// See the `clients` module docs for the `new`/`try_from_host_port` convention.
///
/// [rfc1035]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2
/// [rfc7766]: https://datatracker.ietf.org/doc/html/rfc7766
pub struct Client {
    /// The DNS server this client queries.
    server: SocketAddr,

    /// Maximum time allowed to establish a connection. Defaults to five seconds.
    connect_timeout: Duration,

    /// Maximum time allowed to read a framed response. Defaults to five
    /// seconds; `None` disables it.
    read_timeout: Option<Duration>,

    /// Maximum time allowed to write a framed query. Defaults to five seconds;
    /// `None` disables it.
    write_timeout: Option<Duration>,

    /// Lazily created connection, reused across exchanges.
    connection: Option<tokio::net::TcpStream>,
}

impl Client {
    /// Creates an asynchronous client for one DNS server.
    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Some(Duration::from_secs(5)),
            write_timeout: Some(Duration::from_secs(5)),
            connection: None,
        }
    }

    /// Sets the maximum time allowed to establish a connection.
    pub fn set_connect_timeout(&mut self, timeout: Duration) {
        self.connect_timeout = timeout;
    }

    /// Sets the timeout for reading a response. Pass `None` to disable it.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    /// Sets the timeout for writing a query. Pass `None` to disable it.
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) {
        self.write_timeout = timeout;
    }

    /// Sends one DNS query and returns its response.
    ///
    /// The connection is discarded after any I/O, framing, or parsing error;
    /// the failed query is not retried.
    pub async fn exchange(&mut self, query: &Message) -> Result<Message, crate::Error> {
        if self.connection.is_none() {
            log::trace!("async TCP target={}", self.server);
            let stream = tokio::time::timeout(
                self.connect_timeout,
                tokio::net::TcpStream::connect(self.server),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP connect timed out")
            })??;
            log::trace!(
                "async TCP connected local={} peer={}",
                stream.local_addr()?,
                stream.peer_addr()?
            );
            self.connection = Some(stream);
        } else {
            log::trace!("async TCP reusing connection peer={}", self.server);
        }

        let read_timeout = self.read_timeout;
        let write_timeout = self.write_timeout;
        let result: std::io::Result<Message> = async {
            let stream = self.connection.as_mut().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "TCP connection unavailable",
                )
            })?;
            let message = query.to_vec()?;
            let frame = encode_tcp_frame(&message)?;
            log::trace!("async TCP sending {} bytes to {}", frame.len(), self.server);
            with_timeout(
                write_timeout,
                "TCP write timed out",
                stream.write_all(&frame),
            )
            .await?;

            let response = with_timeout(read_timeout, "TCP read timed out", async {
                let response_length = stream.read_u16().await?;
                log::trace!("async TCP response length prefix={response_length}");
                let mut response = vec![0; response_length as usize];
                stream.read_exact(&mut response).await?;
                Ok(response)
            })
            .await?;
            log::trace!(
                "async TCP received {} bytes from {}",
                response.len() + 2,
                self.server
            );
            Ok(Message::from_slice(&response)?)
        }
        .await;

        match result {
            Ok(response) => Ok(response),
            Err(error) => {
                log::trace!("async TCP discarding connection after error: {error}");
                self.connection = None;
                Err(error.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Client;
    use crate::Message;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn reuses_connection_for_sequential_exchanges() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let address: SocketAddr = listener.local_addr().expect("read test listener address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept test connection");
            for _ in 0..2 {
                let request_length = stream.read_u16().await.expect("read request length");
                let mut request = vec![0; request_length as usize];
                stream.read_exact(&mut request).await.expect("read request");
                stream.write_u16(12).await.expect("write response length");
                stream.write_all(&[0; 12]).await.expect("write response");
            }
        });

        let mut client = Client::new(address);
        assert!(client.exchange(&Message::default()).await.is_ok());
        assert!(client.exchange(&Message::default()).await.is_ok());
        server.await.expect("join test server");
    }
}
