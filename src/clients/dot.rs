use crate::Message;
use crate::clients::framing::encode_tcp_frame;
use crate::clients::timeouts::with_timeout;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

pub const GOOGLE: &str = "dns.google:853";
pub const CLOUDFLARE: &str = "cloudflare-dns.com:853";

/// An asynchronous DNS-over-TLS (DoT) client.
///
/// This is a low-level client: it sends one query to one server and returns the
/// response. It does not retry or fail over between servers. DoT uses the same
/// two-byte length-prefixed framing as DNS over TCP, carried inside a TLS
/// connection, so responses are not truncated.
///
/// The connection target and the TLS server name are independent, so a client
/// can connect straight to an address without a bootstrap DNS lookup. See
/// [`Client::try_new`] and [`Client::try_from_host_port`].
///
/// Exchanges are sequential and require mutable access. The TLS connection is
/// reused across exchanges, and discarded on failure.
///
/// # Example
///
/// ```rust,no_run
/// use rustdns::clients::dot::Client;
/// use rustdns::types::*;
///
/// #[tokio::main]
/// async fn main() -> Result<(), rustdns::Error> {
///     let mut query = Message::default();
///     query.try_add_question("bramp.net", Type::A, Class::Internet)?;
///
///     // No bootstrap lookup: the address is given, the name only validates TLS.
///     let mut client = Client::try_new("dns.google", "8.8.8.8:853".parse().unwrap())?;
///     let response = client.exchange(&query).await?;
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

    /// Maximum time allowed to establish the TCP connection before TLS starts.
    /// Defaults to five seconds.
    connect_timeout: Duration,

    /// Maximum time allowed to read a framed response. Defaults to five
    /// seconds; `None` disables it.
    read_timeout: Option<Duration>,

    /// Maximum time allowed to write a framed query. Defaults to five seconds;
    /// `None` disables it.
    write_timeout: Option<Duration>,

    /// TLS configuration using WebPKI root certificates.
    connector: TlsConnector,

    /// Lazily created TLS connection, reused across exchanges.
    connection: Option<TlsStream<tokio::net::TcpStream>>,
}

impl Client {
    /// Creates a DoT client for `server`, validating its certificate against
    /// `server_name`.
    ///
    /// The two are independent: `server` is where to connect, and
    /// `server_name` is the name the certificate must be valid for. Passing an
    /// address directly avoids the bootstrap DNS lookup that resolving a
    /// hostname would require.
    ///
    /// # Errors
    ///
    /// Returns an error if `server_name` is not valid for TLS validation.
    pub fn try_new(server_name: &str, server: SocketAddr) -> Result<Self, crate::Error> {
        validate_server_name(server_name)?;

        Ok(Self {
            server_name: server_name.to_string(),
            server,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Some(Duration::from_secs(5)),
            write_timeout: Some(Duration::from_secs(5)),
            connector: TlsConnector::from(new_tls_config()),
            connection: None,
        })
    }

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
    /// TLS server name, or resolution fails or produces no addresses.
    pub async fn try_from_host_port(server: &str) -> Result<Self, crate::Error> {
        let server_name = server_name_from_addr(server)?;
        let address = tokio::net::lookup_host(server)
            .await?
            .next()
            .ok_or_else(|| {
                crate::Error::InvalidArgument(format!("no addresses found for '{server}'"))
            })?;

        Self::try_new(&server_name, address)
    }

    /// Sets the maximum time allowed to establish the TCP connection before TLS starts.
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
    /// The connection is discarded after any I/O, TLS, framing, or parsing
    /// error; the failed query is not retried.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection, TLS handshake, exchange, or response
    /// parsing fails.
    pub async fn exchange(&mut self, query: &Message) -> Result<Message, crate::Error> {
        if self.connection.is_none() {
            self.connection = Some(self.connect().await?);
        }

        let read_timeout = self.read_timeout;
        let write_timeout = self.write_timeout;
        let result: io::Result<Message> = async {
            let stream = self.connection.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "DoT connection unavailable")
            })?;

            let message = query.to_vec()?;
            let frame = encode_tcp_frame(&message)?;
            log::trace!("DoT sending {} bytes to {}", frame.len(), self.server);
            with_timeout(write_timeout, "DoT write timed out", async {
                stream.write_all(&frame).await?;
                stream.flush().await
            })
            .await?;

            let response = with_timeout(read_timeout, "DoT read timed out", async {
                let length = stream.read_u16().await?;
                log::trace!("DoT response length prefix={length}");
                let mut response = vec![0; length.into()];
                stream.read_exact(&mut response).await?;
                Ok(response)
            })
            .await?;
            log::trace!(
                "DoT received {} bytes from {}",
                response.len() + 2,
                self.server
            );

            Ok(Message::from_slice(&response)?)
        }
        .await;

        match result {
            Ok(response) => Ok(response),
            Err(error) => {
                log::trace!("DoT discarding connection after error: {error}");
                self.connection = None;
                Err(error.into())
            }
        }
    }

    async fn connect(&self) -> Result<TlsStream<tokio::net::TcpStream>, crate::Error> {
        log::trace!("DoT target={} sni={}", self.server, self.server_name);
        let stream = tokio::time::timeout(
            self.connect_timeout,
            tokio::net::TcpStream::connect(self.server),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DoT connect timed out"))??;
        stream.set_nodelay(true)?;

        let server_name = ServerName::try_from(self.server_name.clone()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid DoT server name: {error}"),
            )
        })?;

        let stream = self.connector.connect(server_name, stream).await?;
        log::trace!("DoT TLS connected peer={}", self.server);
        Ok(stream)
    }
}

/// Checks that `server_name` can be used for TLS SNI and certificate validation.
pub(crate) fn validate_server_name(server_name: &str) -> Result<(), crate::Error> {
    ServerName::try_from(server_name.to_string())
        .map(|_| ())
        .map_err(|error| crate::Error::InvalidArgument(format!("invalid DoT server name: {error}")))
}

/// Extracts the TLS server name from a `host:port` string.
pub(crate) fn server_name_from_addr(server: &str) -> Result<String, crate::Error> {
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

    validate_server_name(host)?;
    Ok(host.to_string())
}

/// Builds a TLS client configuration using the WebPKI root certificates.
pub(crate) fn new_tls_config() -> Arc<ClientConfig> {
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
    use super::*;

    fn address() -> SocketAddr {
        "8.8.8.8:853".parse().expect("valid address")
    }

    #[test]
    fn rejects_invalid_server_name() {
        assert!(Client::try_new("not a valid server name", address()).is_err());
    }

    #[test]
    fn accepts_an_address_with_an_explicit_server_name() {
        let client = Client::try_new("dns.google", address()).expect("create DoT client");
        assert_eq!(client.server_name, "dns.google");
        assert_eq!(client.server, address());
    }

    #[test]
    fn server_name_extraction_rejects_missing_port_and_ip_addresses() {
        assert!(server_name_from_addr("dns.google").is_err());
        assert!(server_name_from_addr("8.8.8.8:853").is_err());
        assert!(server_name_from_addr("[2001:4860:4860::8888]:853").is_err());
    }
}
