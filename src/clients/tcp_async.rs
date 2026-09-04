use crate::Message;
use crate::clients::tcp::encode_tcp_frame;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// An asynchronous DNS-over-TCP client with a reusable connection.
///
/// Exchanges are sequential and require mutable access. A failed exchange
/// discards the connection; the failed query is not retried.
pub struct AsyncClient {
    server: SocketAddr,
    connect_timeout: Duration,
    connection: Option<tokio::net::TcpStream>,
}

impl AsyncClient {
    /// Creates an asynchronous client for one DNS server.
    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
            connect_timeout: Duration::from_secs(5),
            connection: None,
        }
    }

    /// Sets the maximum time allowed to establish a connection.
    pub fn set_connect_timeout(&mut self, timeout: Duration) {
        self.connect_timeout = timeout;
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
            stream.write_all(&frame).await?;
            let response_length = stream.read_u16().await?;
            log::trace!("async TCP response length prefix={response_length}");
            let mut response = vec![0; response_length as usize];
            stream.read_exact(&mut response).await?;
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
    use super::AsyncClient;
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

        let mut client = AsyncClient::new(address);
        assert!(client.exchange(&Message::default()).await.is_ok());
        assert!(client.exchange(&Message::default()).await.is_ok());
        server.await.expect("join test server");
    }
}
