use crate::clients::stats::StatsBuilder;
use crate::clients::tcp::encode_tcp_frame;
use crate::clients::Exchanger;
use crate::Message;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use socket2::{Socket, TcpKeepalive};
use std::cell::Cell;
use std::convert::TryFrom;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

const TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(30);
const DOT_CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

pub const GOOGLE: &str = "dns.google:853";
pub const CLOUDFLARE: &str = "cloudflare-dns.com:853";

type TlsStream = StreamOwned<ClientConnection, TcpStream>;

/// A DNS-over-TLS (DoT) client.
///
/// DoT uses the same two-byte length-prefixed DNS message framing as DNS over
/// TCP, but carries the framed messages inside a TLS connection. The
/// host passed to [`Client::new`] is used for TLS SNI and certificate validation.
///
/// # Example
///
/// ```rust,no_run
/// use rustdns::clients::dot::Client;
/// use rustdns::clients::Exchanger;
/// use rustdns::types::*;
///
/// fn main() -> Result<(), rustdns::Error> {
///     let mut query = Message::default();
///     query.try_add_question("bramp.net", Type::A, Class::Internet)?;
///
///     let response = Client::new("dns.google:853")?
///         .exchange(&query)
///         .expect("could not exchange message");
///
///     println!("{}", response);
///     Ok(())
/// }
/// ```
///
/// See <https://datatracker.ietf.org/doc/html/rfc7858>.
pub struct Client {
    /// TLS server name used for SNI and certificate validation.
    server_name: String,

    /// Resolved DNS server addresses. The first address is used for each exchange.
    servers: Vec<SocketAddr>,

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
    /// Creates a new DoT client.
    ///
    /// `server` should be a `host:port` string. The host is used as the TLS
    /// server name for SNI and certificate validation. DoT conventionally uses
    /// port 853.
    ///
    /// # Errors
    ///
    /// Returns an error if `server` does not include a valid TLS server name,
    /// address resolution fails, or no server address is supplied.
    pub fn new(server: &str) -> Result<Self, crate::Error> {
        let server_name = server_name_from_addr(server)?;
        Self::new_with_server_name(&server_name, server)
    }

    /// Creates a new DoT client with an explicit TLS server name.
    ///
    /// Use this when connecting to an IP address or alternate socket address
    /// while validating the TLS certificate against a DNS name.
    ///
    /// # Errors
    ///
    /// Returns an error if `server_name` is not valid for TLS validation, server
    /// address resolution fails, or no server address is supplied.
    pub fn new_with_server_name<A: ToSocketAddrs>(
        server_name: &str,
        servers: A,
    ) -> Result<Self, crate::Error> {
        Self::validate_server_name(server_name)?;
        let servers: Vec<_> = servers.to_socket_addrs()?.collect();
        if servers.is_empty() {
            return Err(crate::Error::InvalidArgument(
                "at least one DoT server is required".to_string(),
            ));
        }

        Ok(Self {
            server_name: server_name.to_string(),
            servers,
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

    fn validate_server_name(server_name: &str) -> Result<(), crate::Error> {
        ServerName::try_from(server_name.to_string())
            .map(|_| ())
            .map_err(|error| {
                crate::Error::InvalidArgument(format!("invalid DoT server name: {error}"))
            })
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

fn server_name_from_addr(server: &str) -> Result<String, crate::Error> {
    let server = server.trim();
    let host = server
        .rsplit_once(':')
        .map(|(host, _)| host)
        .ok_or_else(|| {
            crate::Error::InvalidArgument("DoT server must include a port".to_string())
        })?;
    let host = host.trim_start_matches('[').trim_end_matches(']');

    if host.is_empty() {
        return Err(crate::Error::InvalidArgument(
            "DoT server must include a host".to_string(),
        ));
    }

    if host.parse::<IpAddr>().is_ok() {
        return Err(crate::Error::InvalidArgument(
            "DoT server host must be a DNS name; use new_with_server_name for IP addresses"
                .to_string(),
        ));
    }

    Client::validate_server_name(host)?;
    Ok(host.to_string())
}

impl Exchanger for Client {
    /// Sends the query [`Message`] to the server via DNS-over-TLS and returns the result.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP connection, TLS handshake, DNS framing, or
    /// response parsing fails.
    fn exchange(&self, query: &Message) -> Result<Message, crate::Error> {
        let server = self.servers.first().ok_or_else(|| {
            crate::Error::InvalidArgument("at least one DoT server is required".to_string())
        })?;
        let mut stream = self.get_stream(server)?;

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

fn new_tls_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

#[cfg(test)]
mod tests {
    use super::server_name_from_addr;
    use super::Client;
    use std::net::SocketAddr;
    use std::time::Duration;

    #[test]
    fn rejects_invalid_server_name() {
        assert!(Client::new("not a valid server name:853").is_err());
    }

    #[test]
    fn rejects_empty_server_lists() {
        assert!(Client::new_with_server_name("dns.google", &[] as &[SocketAddr]).is_err());
    }

    #[test]
    fn configures_timeouts() {
        let mut client =
            Client::new_with_server_name("dns.google", "127.0.0.1:853").expect("create DoT client");

        client.set_connect_timeout(Duration::from_secs(1));
        client.set_read_timeout(None);
        client.set_write_timeout(Some(Duration::from_secs(2)));
    }

    #[test]
    fn new_extracts_server_name_from_host_port() {
        let client = Client::new("dns.google:853").expect("create DoT client");

        assert_eq!(client.server_name, "dns.google");
    }

    #[test]
    fn server_name_extraction_rejects_missing_port_and_ip_addresses() {
        assert!(server_name_from_addr("dns.google").is_err());
        assert!(server_name_from_addr("8.8.8.8:853").is_err());
        assert!(server_name_from_addr("[2001:4860:4860::8888]:853").is_err());
    }
}
