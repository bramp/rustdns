use crate::clients::Exchanger;
use crate::Message;
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

/// A UDP DNS Client.
///
/// # Example
///
/// ```rust
/// use rustdns::clients::Exchanger;
/// use rustdns::clients::udp::Client;
/// use rustdns::types::*;
///
/// fn main() -> Result<(), rustdns::Error> {
///     let mut query = Message::default();
///     query.try_add_question("bramp.net", Type::A, Class::Internet)?;
///
///     let response = Client::new("8.8.8.8:53")?
///        .exchange(&query)
///        .expect("could not exchange message");
///
///     println!("{}", response);
///     Ok(())
/// }
/// ```
///
/// See <https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.1>
pub struct Client {
    /// Resolved DNS server addresses. The first address is used for each exchange.
    ///
    /// The input to [`Client::new`] may be a socket address, a `host:port` string,
    /// or another [`ToSocketAddrs`] implementation. Hostnames are resolved when
    /// the client is constructed, not for each exchange.
    servers: Vec<SocketAddr>,

    /// Maximum time allowed to receive a UDP response. Defaults to five seconds; `None` disables it.
    read_timeout: Option<Duration>,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            servers: Vec::default(),
            read_timeout: Some(Duration::new(5, 0)),
        }
    }
}

impl Client {
    /// Creates a new Client bound to the specific servers.
    ///
    /// `servers` can be a `SocketAddr`, a `host:port` string, or any other value
    /// implementing [`ToSocketAddrs`]. A port must be supplied because DNS uses
    /// the server's socket address directly.
    ///
    /// Multiple addresses are accepted for compatibility, but this low-level
    /// client uses only the first resolved address. It does not perform
    /// application-level retries or failover.
    ///
    /// # Errors
    ///
    /// Returns an error if address resolution fails or produces no addresses.
    pub fn new<A: ToSocketAddrs>(servers: A) -> Result<Self, crate::Error> {
        let servers: Vec<_> = servers.to_socket_addrs()?.collect();
        if servers.is_empty() {
            return Err(crate::Error::InvalidArgument(
                "at least one DNS server is required".to_string(),
            ));
        }
        Ok(Self {
            servers,

            ..Default::default()
        })
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
        let server = self.servers.first().ok_or_else(|| {
            crate::Error::InvalidArgument("at least one DNS server is required".to_string())
        })?;
        socket.connect(server)?;

        let req = query.to_vec()?;

        let stats = StatsBuilder::start(req.len());
        socket.send(&req)?;

        // TODO Set this to the size in req.
        let mut buf = [0; 4096];
        let len = socket.recv(&mut buf)?;
        let mut resp = Message::from_slice(&buf[0..len])?;

        resp.stats = Some(stats.end(socket.peer_addr()?, len));

        Ok(resp)
    }
}

#[cfg(feature = "async-udp")]
pub use crate::clients::udp_async::AsyncClient;
