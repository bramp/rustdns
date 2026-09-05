use crate::Message;
use crate::clients::tcp::Client as TcpClient;
use crate::clients::udp::Client as UdpClient;
use std::net::SocketAddr;
use std::time::Duration;

/// A classic DNS ("Do53") client for one server, speaking UDP and TCP.
///
/// Queries are sent over UDP. When the server sets the truncation bit (`TC=1`),
/// the query is re-sent over TCP to the *same* server, as required by
/// [rfc2181] and [rfc7766]. Because both transports are built from a single
/// [`SocketAddr`], the "same server" requirement holds by construction.
///
/// The truncated UDP response is never returned to the caller: per
/// [rfc7766#section-5] a client must not rely on anything in a truncated
/// response except the fact that it was truncated. If the TCP retry fails, that
/// failure is returned rather than the truncated response.
///
/// Exchanges are sequential and require mutable access. The UDP socket and TCP
/// connection are reused across exchanges, and discarded on failure.
///
/// See the `clients` module docs for the `new`/`try_from_host_port` convention.
///
/// [rfc2181]: https://datatracker.ietf.org/doc/html/rfc2181#section-9
/// [rfc7766]: https://datatracker.ietf.org/doc/html/rfc7766#section-5
/// [rfc7766#section-5]: https://datatracker.ietf.org/doc/html/rfc7766#section-5
pub struct Client {
    /// The DNS server this client queries over both transports.
    server: SocketAddr,

    /// Sends every query; used first for each exchange.
    udp: UdpClient,

    /// Re-sends a query whose UDP response was truncated.
    tcp: TcpClient,
}

impl Client {
    /// Creates a client for one DNS server, using UDP with TCP retry on truncation.
    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
            udp: UdpClient::new(server),
            tcp: TcpClient::new(server),
        }
    }

    /// Returns the server this client queries.
    pub fn server(&self) -> SocketAddr {
        self.server
    }

    /// Sets the timeout for receiving the UDP response. Pass `None` to disable it.
    pub fn set_udp_read_timeout(&mut self, timeout: Option<Duration>) {
        self.udp.set_read_timeout(timeout);
    }

    /// Sets the maximum time allowed to establish the TCP connection used for
    /// truncated responses.
    pub fn set_tcp_connect_timeout(&mut self, timeout: Duration) {
        self.tcp.set_connect_timeout(timeout);
    }

    /// Sends one DNS query and returns its response, retrying over TCP when the
    /// UDP response is truncated.
    ///
    /// # Errors
    ///
    /// Returns an error if the UDP exchange fails, or if a truncated response
    /// could not be re-fetched over TCP.
    pub async fn exchange(&mut self, query: &Message) -> Result<Message, crate::Error> {
        let response = self.udp.exchange(query).await?;
        if !response.tc {
            return Ok(response);
        }

        log::debug!(
            "Do53 {} returned a truncated response, retrying over TCP",
            self.server
        );
        self.tcp.exchange(query).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clients::framing::encode_tcp_frame;
    use crate::types::{Class, QR, Rcode, Record, Resource, Type};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Builds a response echoing `request`'s question.
    fn respond(request: &[u8], truncated: bool, answer: Option<Resource>) -> Vec<u8> {
        let request = Message::from_slice(request).expect("valid request");
        let mut response = Message {
            id: request.id,
            qr: QR::Response,
            rcode: Rcode::NoError,
            tc: truncated,
            questions: request.questions.clone(),
            ..Default::default()
        };
        if let Some(resource) = answer {
            response.answers.push(Record {
                name: request.questions[0].name.clone(),
                class: Class::Internet,
                ttl: Duration::from_secs(10),
                resource,
            });
        }
        response.to_vec().expect("response encodes")
    }

    fn query() -> Message {
        let mut query = Message::default();
        query
            .try_add_question("bramp.net", Type::A, Class::Internet)
            .expect("valid question");
        query
    }

    /// Binds a UDP socket on an ephemeral port, then a TCP listener on that same
    /// port, so one `SocketAddr` serves both transports.
    async fn bind_pair() -> (tokio::net::UdpSocket, tokio::net::TcpListener, SocketAddr) {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind UDP");
        let addr = udp.local_addr().expect("UDP address");
        let tcp = tokio::net::TcpListener::bind(addr).await.expect("bind TCP");
        (udp, tcp, addr)
    }

    #[tokio::test]
    async fn truncated_udp_response_is_retried_over_tcp() {
        let (udp, tcp, addr) = bind_pair().await;

        let udp_server = tokio::spawn(async move {
            let mut buf = [0; 512];
            let (len, peer) = udp.recv_from(&mut buf).await.expect("read UDP request");
            let response = respond(&buf[..len], true, None);
            udp.send_to(&response, peer).await.expect("write UDP");
        });

        let tcp_server = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.expect("accept TCP");
            let len = stream.read_u16().await.expect("read length prefix");
            let mut buf = vec![0; len as usize];
            stream.read_exact(&mut buf).await.expect("read TCP request");
            let response = respond(&buf, false, Some(Resource::A("127.0.0.1".parse().unwrap())));
            let frame = encode_tcp_frame(&response).expect("frame encodes");
            stream.write_all(&frame).await.expect("write TCP");
        });

        let mut client = Client::new(addr);
        let response = client.exchange(&query()).await.expect("exchange succeeds");

        assert!(!response.tc, "truncated response leaked to the caller");
        assert_eq!(response.answers.len(), 1);

        udp_server.await.expect("join UDP server");
        tcp_server.await.expect("join TCP server");
    }

    #[tokio::test]
    async fn a_failed_tcp_retry_does_not_return_the_truncated_response() {
        let (udp, tcp, addr) = bind_pair().await;
        drop(tcp); // Refuse the TCP retry.

        let udp_server = tokio::spawn(async move {
            let mut buf = [0; 512];
            let (len, peer) = udp.recv_from(&mut buf).await.expect("read UDP request");
            let response = respond(&buf[..len], true, None);
            udp.send_to(&response, peer).await.expect("write UDP");
        });

        let mut client = Client::new(addr);
        assert!(client.exchange(&query()).await.is_err());

        udp_server.await.expect("join UDP server");
    }

    #[tokio::test]
    async fn an_untruncated_udp_response_is_returned_directly() {
        let (udp, _tcp, addr) = bind_pair().await;

        let udp_server = tokio::spawn(async move {
            let mut buf = [0; 512];
            let (len, peer) = udp.recv_from(&mut buf).await.expect("read UDP request");
            let response = respond(
                &buf[..len],
                false,
                Some(Resource::A("127.0.0.1".parse().unwrap())),
            );
            udp.send_to(&response, peer).await.expect("write UDP");
        });

        let mut client = Client::new(addr);
        let response = client.exchange(&query()).await.expect("exchange succeeds");
        assert_eq!(response.answers.len(), 1);

        udp_server.await.expect("join UDP server");
    }
}
