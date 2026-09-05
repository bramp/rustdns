use crate::Message;
use crate::clients::Exchanger;
use crate::clients::dot::{new_tls_config, server_name_from_addr, validate_server_name};
use crate::clients::framing::encode_tcp_frame;
use crate::clients::stats::StatsBuilder;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use socket2::{Socket, TcpKeepalive};
use std::cell::Cell;
use std::convert::TryFrom;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

const TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(30);
const DOT_CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

type TlsStream = StreamOwned<ClientConnection, TcpStream>;

/// A DNS-over-TLS (DoT) client.
///
/// This is a low-level, synchronous client: it sends one query to one server
/// and returns the response. It does not retry or fail over between servers.
/// DoT uses the same two-byte length-prefixed framing as DNS over TCP, carried
/// inside a TLS connection, so responses are not truncated. The connection is
/// reused across exchanges until it goes idle or fails.
///
/// # Example
///
/// ```rust,no_run
/// use rustdns::clients::Exchanger;
/// use rustdns::clients::sync::dot::Client;
/// use rustdns::types::*;
///
/// fn main() -> Result<(), rustdns::Error> {
///     let mut query = Message::default();
///     query.try_add_question("bramp.net", Type::A, Class::Internet)?;
///
///     // No bootstrap lookup: the address is given, the name only validates TLS.
///     let response = Client::try_new("dns.google", "8.8.8.8:853".parse().unwrap())?
///         .exchange(&query)
///         .expect("could not exchange message");
///
///     println!("{}", response);
///     Ok(())
/// }
/// ```
///
/// See [rfc7858].
///
/// See the `clients` module docs for the `try_new`/`try_from_host_port` convention.
///
/// [rfc7858]: https://datatracker.ietf.org/doc/html/rfc7858
pub struct Client {
    /// TLS server name used for SNI and certificate validation.
    server_name: String,

    /// The DNS server this client queries.
    server: SocketAddr,

    /// Maximum time allowed to establish a TCP connection. Defaults to five seconds.
    connect_timeout: Duration,
    /// Maximum time allowed for TLS-over-TCP reads. Defaults to five seconds; `None` disables it.
    read_timeout: Option<Duration>,
    /// Maximum time allowed for TLS-over-TCP writes. Defaults to five seconds; `None` disables it.
    write_timeout: Option<Duration>,

    /// TLS configuration using WebPKI root certificates.
    tls_config: Arc<ClientConfig>,

    /// Lazily created TLS connection and its last successful-use time.
    connection: Cell<Option<(TlsStream, Instant)>>,
}

impl Client {
    /// Creates a DoT client from a `host:port` string, using the host for both
    /// the address lookup and TLS validation.
    ///
    /// This resolves `server` with the system resolver, which is a bootstrap
    /// dependency: it must not be served by the resolver this client is being
    /// built for. Prefer [`Client::try_new`] when the address is already known.
    ///
    /// # Errors
    ///
    /// Returns an error if `server` is not a `host:port` string with a valid
    /// TLS server name, resolution fails, or produces no addresses.
    pub fn try_from_host_port(server: &str) -> Result<Self, crate::Error> {
        let server_name = server_name_from_addr(server)?;
        let address = server.to_socket_addrs()?.next().ok_or_else(|| {
            crate::Error::InvalidArgument(format!("no addresses found for '{server}'"))
        })?;

        Self::try_new(&server_name, address)
    }

    /// Creates a DoT client for `server`, validating its certificate against
    /// `server_name`.
    ///
    /// The two are independent: `server` is where to connect, and
    /// `server_name` is the name the certificate must be valid for. Because
    /// `server` is a [`SocketAddr`] rather than a generic
    /// [`ToSocketAddrs`], no name resolution can happen here.
    ///
    /// # Errors
    ///
    /// Returns an error if `server_name` is not valid for TLS validation.
    pub fn try_new(server_name: &str, server: SocketAddr) -> Result<Self, crate::Error> {
        validate_server_name(server_name)?;

        Ok(Self {
            server_name: server_name.to_string(),
            server,
            connect_timeout: Duration::new(5, 0),
            read_timeout: Some(Duration::new(5, 0)),
            write_timeout: Some(Duration::new(5, 0)),
            tls_config: new_tls_config(),
            connection: Cell::new(None),
        })
    }

    /// Sets the timeout for establishing the TCP connection before TLS starts.
    pub fn set_connect_timeout(&mut self, timeout: Duration) {
        self.connect_timeout = timeout;
    }

    /// Sets the timeout for TLS-over-TCP reads. Pass `None` to disable the timeout.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    /// Sets the timeout for TLS-over-TCP writes. Pass `None` to disable the timeout.
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) {
        self.write_timeout = timeout;
    }

    fn get_stream(&self, server: &SocketAddr) -> Result<TlsStream, crate::Error> {
        if let Some((stream, last_used)) = self.connection.take() {
            if last_used.elapsed() <= DOT_CONNECTION_IDLE_TIMEOUT {
                log::trace!(
                    "DoT reusing TLS connection peer={}",
                    stream.sock.peer_addr()?
                );
                return Ok(stream);
            }
            log::trace!(
                "DoT discarding idle TLS connection peer={}",
                stream.sock.peer_addr()?
            );
        }

        log::trace!("DoT target={server} sni={}", self.server_name);
        let stream = TcpStream::connect_timeout(server, self.connect_timeout)?;
        let socket = Socket::from(stream);
        let keepalive = TcpKeepalive::new().with_time(TCP_KEEPALIVE_TIME);
        socket.set_tcp_keepalive(&keepalive)?;

        let stream: TcpStream = socket.into();
        stream.set_nodelay(true)?;
        stream.set_read_timeout(self.read_timeout)?;
        stream.set_write_timeout(self.write_timeout)?;
        log::trace!(
            "DoT TCP connected local={} peer={}",
            stream.local_addr()?,
            stream.peer_addr()?
        );

        let server_name = ServerName::try_from(self.server_name.clone()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid DoT server name: {error}"),
            )
        })?;
        let connection = ClientConnection::new(Arc::clone(&self.tls_config), server_name)
            .map_err(io::Error::other)?;
        log::trace!("DoT TLS connection created sni={}", self.server_name);

        Ok(StreamOwned::new(connection, stream))
    }
}

impl Exchanger for Client {
    /// Sends the query [`Message`] to the server via DNS-over-TLS and returns the result.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP connection, TLS handshake, DNS framing, or
    /// response parsing fails.
    fn exchange(&self, query: &Message) -> Result<Message, crate::Error> {
        let mut stream = self.get_stream(&self.server)?;

        let result: io::Result<Message> = (|| {
            let message = query.to_vec()?;
            let frame = encode_tcp_frame(&message)?;
            let stats = StatsBuilder::start(frame.len());

            log::trace!(
                "DoT sending {} bytes to {} inside TLS",
                frame.len(),
                stream.sock.peer_addr()?
            );
            stream.write_all(&frame)?;
            stream.flush()?;

            let mut length = [0; 2];
            stream.read_exact(&mut length)?;
            let length = u16::from_be_bytes(length);
            log::trace!("DoT response length prefix={length}");
            let mut response = vec![0; length.into()];
            stream.read_exact(&mut response)?;
            log::trace!(
                "DoT received {} bytes from {} inside TLS",
                response.len() + 2,
                stream.sock.peer_addr()?
            );

            let mut response = Message::from_slice(&response)?;
            response.stats = Some(stats.end(stream.sock.peer_addr()?, usize::from(length) + 2));
            Ok(response)
        })();

        match result {
            Ok(response) => {
                self.connection.set(Some((stream, Instant::now())));
                Ok(response)
            }
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Client;
    use std::net::SocketAddr;
    use std::time::Duration;

    #[test]
    fn rejects_invalid_server_name() {
        let address: SocketAddr = "8.8.8.8:853".parse().expect("valid address");
        assert!(Client::try_new("not a valid server name", address).is_err());
    }

    #[test]
    fn configures_timeouts() {
        let address: SocketAddr = "127.0.0.1:853".parse().expect("valid address");
        let mut client = Client::try_new("dns.google", address).expect("create DoT client");

        client.set_connect_timeout(Duration::from_secs(1));
        client.set_read_timeout(None);
        client.set_write_timeout(Some(Duration::from_secs(2)));
    }

    #[test]
    fn try_from_host_port_rejects_ip_addresses() {
        assert!(Client::try_from_host_port("127.0.0.1:853").is_err());
    }
}
