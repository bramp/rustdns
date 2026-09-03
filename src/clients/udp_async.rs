use crate::Message;
use std::net::SocketAddr;

/// An asynchronous DNS-over-UDP client for one DNS server.
///
/// Exchanges are sequential and require mutable access. A failed exchange
/// discards the socket; the failed query is not retried.
pub struct AsyncClient {
    server: SocketAddr,
    socket: Option<tokio::net::UdpSocket>,
}

impl AsyncClient {
    /// Creates an asynchronous client for one DNS server.
    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
            socket: None,
        }
    }

    /// Sends one DNS query and returns its response.
    pub async fn exchange(&mut self, query: &Message) -> Result<Message, crate::Error> {
        if self.socket.is_none() {
            let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
            socket.connect(self.server).await?;
            self.socket = Some(socket);
        }

        let result: std::io::Result<Message> = async {
            let socket = self.socket.as_mut().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotConnected, "UDP socket unavailable")
            })?;
            let request = query.to_vec()?;
            socket.send(&request).await?;
            let mut response = [0; 65535];
            let length = socket.recv(&mut response).await?;
            Message::from_slice(&response[..length])
        }
        .await;

        match result {
            Ok(response) => Ok(response),
            Err(error) => {
                self.socket = None;
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

        let mut client = AsyncClient::new(address);
        assert!(client.exchange(&Message::default()).await.is_ok());
        server.await.expect("join test server");
    }
}
