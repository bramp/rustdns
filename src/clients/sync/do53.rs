use crate::Message;
use crate::clients::Exchanger;
use crate::clients::sync::tcp::Client as TcpClient;
use crate::clients::sync::udp::Client as UdpClient;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::time::Duration;

/// A synchronous classic DNS ("Do53") client, speaking UDP and TCP.
///
/// This is the blocking counterpart of [`crate::clients::do53::Client`].
/// Queries are sent over UDP; a truncated (`TC=1`) response is re-sent over TCP
/// to the *same* server, as required by [rfc2181] and [rfc7766]. Because both
/// transports are built from a single [`SocketAddr`], that requirement holds by
/// construction.
///
/// The truncated response is never returned to the caller: per [rfc7766] a
/// client must not rely on anything in a truncated response except the fact
/// that it was truncated. If the TCP retry fails, that failure is returned.
///
/// # Example
///
/// ```rust,no_run
/// use rustdns::clients::Exchanger;
/// use rustdns::clients::sync::do53::Client;
/// use rustdns::types::*;
///
/// fn main() -> Result<(), rustdns::Error> {
///     let mut query = Message::default();
///     query.try_add_question("bramp.net", Type::A, Class::Internet)?;
///
///     let response = Client::new("8.8.8.8:53".parse().unwrap())
///         .exchange(&query)
///         .expect("could not exchange message");
///
///     println!("{}", response);
///     Ok(())
/// }
/// ```
///
/// See [rfc2181] and [rfc7766].
///
/// See the `clients` module docs for the `new`/`try_from_host_port` convention.
///
/// [rfc2181]: https://datatracker.ietf.org/doc/html/rfc2181#section-9
/// [rfc7766]: https://datatracker.ietf.org/doc/html/rfc7766#section-5
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
    ///
    /// Because `server` is a [`SocketAddr`] rather than a generic
    /// [`ToSocketAddrs`], no name resolution can happen here.
    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
            udp: UdpClient::new(server),
            tcp: TcpClient::new(server),
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

    /// Returns the server this client queries.
    pub fn server(&self) -> SocketAddr {
        self.server
    }

    /// Sets the timeout for UDP reads. Pass `None` to disable the timeout.
    pub fn set_udp_read_timeout(&mut self, timeout: Option<Duration>) {
        self.udp.set_read_timeout(timeout);
    }

    /// Sets the maximum time allowed to establish the TCP connection used for
    /// truncated responses.
    pub fn set_tcp_connect_timeout(&mut self, timeout: Duration) {
        self.tcp.set_connect_timeout(timeout);
    }
}

impl Exchanger for Client {
    /// Sends the query [`Message`] over UDP, retrying over TCP when truncated.
    ///
    /// # Errors
    ///
    /// Returns an error if the UDP exchange fails, or if a truncated response
    /// could not be re-fetched over TCP.
    fn exchange(&self, query: &Message) -> Result<Message, crate::Error> {
        let response = self.udp.exchange(query)?;
        if !response.tc {
            return Ok(response);
        }

        log::debug!(
            "Do53 {} returned a truncated response, retrying over TCP",
            self.server
        );
        self.tcp.exchange(query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_its_server() {
        let client = Client::new("127.0.0.1:53".parse().unwrap());
        assert_eq!(client.server(), "127.0.0.1:53".parse().unwrap());
    }

    #[test]
    fn try_from_host_port_resolves_the_address() {
        let client = Client::try_from_host_port("127.0.0.1:53").expect("create client");
        assert_eq!(client.server(), "127.0.0.1:53".parse().unwrap());
    }
}
