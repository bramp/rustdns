use crate::Message;
use crate::clients::Exchanger;
use crate::clients::stats::StatsBuilder;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::net::UdpSocket;
use std::time::Duration;

pub const GOOGLE_IPV4_PRIMARY: &str = "8.8.8.8:53";
pub const GOOGLE_IPV4_SECONDARY: &str = "8.8.4.4:53";
pub const GOOGLE_IPV6_PRIMARY: &str = "2001:4860:4860::8888:53";
pub const GOOGLE_IPV6_SECONDARY: &str = "2001:4860:4860::8844:53";

pub const GOOGLE: [&str; 4] = [
    GOOGLE_IPV4_PRIMARY,
    GOOGLE_IPV4_SECONDARY,
    GOOGLE_IPV6_PRIMARY,
    GOOGLE_IPV6_SECONDARY,
];

/// A DNS-over-UDP client.
///
/// This is a low-level, synchronous client: it sends one query to one server
/// and returns the response. It does not retry, does not fail over between
/// servers, and does not follow a truncated (`TC=1`) response over TCP.
///
/// Prefer [`sync::do53::Client`](crate::clients::sync::do53::Client), which
/// pairs UDP with TCP and performs the truncation retry required by [rfc2181]
/// and [rfc7766].
///
/// # Example
///
/// ```rust,no_run
/// use rustdns::clients::Exchanger;
/// use rustdns::clients::sync::udp::Client;
/// use rustdns::types::*;
///
/// fn main() -> Result<(), rustdns::Error> {
///     let mut query = Message::default();
///     query.try_add_question("bramp.net", Type::A, Class::Internet)?;
///
///     let response = Client::new("8.8.8.8:53".parse().unwrap())
///        .exchange(&query)
///        .expect("could not exchange message");
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

    /// Maximum time allowed to receive a UDP response. Defaults to five seconds; `None` disables it.
    read_timeout: Option<Duration>,
}

impl Client {
    /// Creates a client for one DNS server.
    ///
    /// Because `server` is a [`SocketAddr`] rather than a generic
    /// [`ToSocketAddrs`], no name resolution can happen here.
    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
            read_timeout: Some(Duration::new(5, 0)),
        }
    }

    /// Creates a client from a `host:port` string.
    ///
    /// This resolves `server` with the system resolver, which is a bootstrap
    /// dependency: it must not be served by the resolver this client is being
    /// built for. Prefer [`Client::new`] when the address is already known.
    ///
    /// # Errors
    ///
    /// Returns an error if address resolution fails or produces no addresses.
    pub fn try_from_host_port(server: &str) -> Result<Self, crate::Error> {
        let address = server.to_socket_addrs()?.next().ok_or_else(|| {
            crate::Error::InvalidArgument(format!("no addresses found for '{server}'"))
        })?;
        Ok(Self::new(address))
    }

    /// Sets the timeout for UDP reads. Pass `None` to disable the timeout.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }
}

impl Exchanger for Client {
    /// Sends the query [`Message`] to the `server` via UDP and returns the result.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket, network exchange, or response parsing fails.
    fn exchange(&self, query: &Message) -> Result<Message, crate::Error> {
        // TODO Implement retries, backoffs, and cycling of servers.
        // per https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.1

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(self.read_timeout)?;

        // Connect us to the server, meaning recv will only receive directly
        // from the server.
        let server = self.server;
        log::trace!("UDP target={server}");
        socket.connect(server)?;
        log::trace!(
            "UDP connected local={} peer={}",
            socket.local_addr()?,
            socket.peer_addr()?
        );

        let req = query.to_vec()?;

        let stats = StatsBuilder::start(req.len());
        log::trace!("UDP sending {} bytes to {}", req.len(), socket.peer_addr()?);
        socket.send(&req)?;

        // TODO Set this to the size in req.
        let mut buf = [0; 4096];
        let len = socket.recv(&mut buf)?;
        log::trace!("UDP received {len} bytes from {}", socket.peer_addr()?);
        let mut resp = Message::from_slice(&buf[0..len])?;

        resp.stats = Some(stats.end(socket.peer_addr()?, len));

        Ok(resp)
    }
}
