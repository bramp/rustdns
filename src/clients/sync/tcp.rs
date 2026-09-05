use crate::Message;
use crate::clients::Exchanger;
use crate::clients::stats::StatsBuilder;
use socket2::{Socket, TcpKeepalive};
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

const TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(30);
const TCP_CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

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

/// A DNS-over-TCP client.
///
/// This is a low-level, synchronous client: it sends one query to one server
/// and returns the response. It does not retry or fail over between servers.
/// DNS messages are framed with a two-byte big-endian length prefix, and the
/// connection is reused across exchanges until it goes idle or fails.
///
/// TCP carries responses that would be truncated over UDP, so this client is
/// the target of a `TC=1` retry rather than a source of one. Prefer
/// [`sync::do53::Client`](crate::clients::sync::do53::Client) to query over UDP
/// first and upgrade to TCP only when the server truncates.
///
/// # Example
///
/// ```rust,no_run
/// use rustdns::clients::Exchanger;
/// use rustdns::clients::sync::tcp::Client;
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
/// See [rfc1035] and [rfc7766].
///
/// See the `clients` module docs for the `new`/`try_from_host_port` convention.
///
/// [rfc1035]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2
/// [rfc7766]: https://datatracker.ietf.org/doc/html/rfc7766
pub struct Client {
    /// The DNS server this client queries.
    server: SocketAddr,

    /// Maximum time allowed to establish a TCP connection. Defaults to five seconds.
    connect_timeout: Duration,
    /// Maximum time allowed for TCP reads. Defaults to five seconds; `None` disables it.
    read_timeout: Option<Duration>,
    /// Maximum time allowed for TCP writes. Defaults to five seconds; `None` disables it.
    write_timeout: Option<Duration>,

    /// Lazily created TCP connection and its last successful-use time.
    connection: Mutex<Option<(TcpStream, Instant)>>,
}

impl Client {
    /// Creates a client for one DNS server.
    ///
    /// Because `server` is a [`SocketAddr`] rather than a generic
    /// [`ToSocketAddrs`], no name resolution can happen here.
    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
            connect_timeout: Duration::new(5, 0),
            read_timeout: Some(Duration::new(5, 0)),
            write_timeout: Some(Duration::new(5, 0)),
            connection: Mutex::new(None),
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

    /// Sets the timeout for establishing a TCP connection.
    pub fn set_connect_timeout(&mut self, timeout: Duration) {
        self.connect_timeout = timeout;
    }

    /// Sets the timeout for TCP reads. Pass `None` to disable the timeout.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    /// Sets the timeout for TCP writes. Pass `None` to disable the timeout.
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) {
        self.write_timeout = timeout;
    }

    fn get_stream(&self, server: &SocketAddr) -> Result<TcpStream, crate::Error> {
        let cached = self
            .connection
            .lock()
            .map_err(|_| io::Error::other("TCP connection lock poisoned"))?
            .take();

        if let Some((stream, last_used)) = cached {
            if last_used.elapsed() <= TCP_CONNECTION_IDLE_TIMEOUT {
                log::trace!("TCP reusing connection peer={}", stream.peer_addr()?);
                return Ok(stream);
            }
            log::trace!(
                "TCP discarding idle connection peer={}",
                stream.peer_addr()?
            );
        }

        log::trace!("TCP target={server}");
        let stream = TcpStream::connect_timeout(server, self.connect_timeout)?;
        let socket = Socket::from(stream);
        let keepalive = TcpKeepalive::new().with_time(TCP_KEEPALIVE_TIME);
        socket.set_tcp_keepalive(&keepalive)?;

        let stream: TcpStream = socket.into();
        stream.set_nodelay(true)?;
        stream.set_read_timeout(self.read_timeout)?;
        stream.set_write_timeout(self.write_timeout)?;
        log::trace!(
            "TCP connected local={} peer={}",
            stream.local_addr()?,
            stream.peer_addr()?
        );

        Ok(stream)
    }
}

impl Exchanger for Client {
    /// Sends the [`Message`] to the `server` via TCP and returns the result.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection, DNS framing, or response parsing fails.
    fn exchange(&self, query: &Message) -> Result<Message, crate::Error> {
        let mut stream = self.get_stream(&self.server)?;

        let message = query.to_vec()?;

        let stats = StatsBuilder::start(message.len() + 2);

        // Two byte length prefix followed by the message.
        // TODO Move this into a single message!
        log::trace!(
            "TCP sending {} bytes to {}",
            message.len() + 2,
            stream.peer_addr()?
        );
        stream.write_all(&(message.len() as u16).to_be_bytes())?;
        stream.write_all(&message)?;

        // Now receive a two byte length
        let buf = &mut [0; 2];
        stream.read_exact(buf)?;
        let len = u16::from_be_bytes(*buf);
        log::trace!("TCP response length prefix={len}");

        // and finally the message
        let mut buf = vec![0; len.into()];

        stream.read_exact(&mut buf)?;
        log::trace!(
            "TCP received {} bytes from {}",
            buf.len() + 2,
            stream.peer_addr()?
        );

        let mut resp = Message::from_slice(&buf)?;
        resp.stats = Some(stats.end(stream.peer_addr()?, (len + 2).into()));

        *self
            .connection
            .lock()
            .map_err(|_| io::Error::other("TCP connection lock poisoned"))? =
            Some((stream, Instant::now()));

        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::Client;
    use crate::Message;
    use crate::clients::Exchanger;
    use std::io::Read;
    use std::io::Write;
    use std::net::SocketAddr;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn rejects_truncated_and_oversized_frames() {
        for declared_length in [11_u16, u16::MAX] {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
            let address = listener.local_addr().expect("read test listener address");
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept test connection");
                let mut request_length = [0; 2];
                stream
                    .read_exact(&mut request_length)
                    .expect("read request length");
                let request_length = u16::from_be_bytes(request_length) as usize;
                let mut request = vec![0; request_length];
                stream.read_exact(&mut request).expect("read request");
                stream
                    .write_all(&declared_length.to_be_bytes())
                    .expect("write response length");
                stream.flush().expect("flush response");
            });

            let client = Client::new(address);
            assert!(client.exchange(&Message::default()).is_err());
            server.join().expect("join test server");
        }
    }

    #[test]
    fn configures_timeouts() {
        let address: SocketAddr = "127.0.0.1:53".parse().expect("valid address");
        let mut client = Client::new(address);

        client.set_connect_timeout(Duration::from_secs(1));
        client.set_read_timeout(None);
        client.set_write_timeout(Some(Duration::from_secs(2)));
    }

    #[test]
    fn reuses_connection_for_sequential_exchanges() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("read test listener address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept test connection");
            for _ in 0..2 {
                let mut request_length = [0; 2];
                stream
                    .read_exact(&mut request_length)
                    .expect("read request length");
                let request_length = u16::from_be_bytes(request_length) as usize;
                let mut request = vec![0; request_length];
                stream.read_exact(&mut request).expect("read request");
                stream
                    .write_all(&12_u16.to_be_bytes())
                    .expect("write response length");
                stream.write_all(&[0; 12]).expect("write response");
            }
        });

        let client = Client::new(address);
        assert!(client.exchange(&Message::default()).is_ok());
        assert!(client.exchange(&Message::default()).is_ok());
        server.join().expect("join test server");
    }

    #[test]
    fn reconnects_after_failed_exchange() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("read test listener address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept first connection");
            let mut request_length = [0; 2];
            stream
                .read_exact(&mut request_length)
                .expect("read first request length");
            let request_length = u16::from_be_bytes(request_length) as usize;
            let mut request = vec![0; request_length];
            stream.read_exact(&mut request).expect("read first request");
            stream
                .write_all(&11_u16.to_be_bytes())
                .expect("write bad response");
            drop(stream);

            let (mut stream, _) = listener.accept().expect("accept replacement connection");
            let mut request_length = [0; 2];
            stream
                .read_exact(&mut request_length)
                .expect("read second request length");
            let request_length = u16::from_be_bytes(request_length) as usize;
            let mut request = vec![0; request_length];
            stream
                .read_exact(&mut request)
                .expect("read second request");
            stream
                .write_all(&12_u16.to_be_bytes())
                .expect("write response length");
            stream.write_all(&[0; 12]).expect("write response");
        });

        let client = Client::new(address);
        assert!(client.exchange(&Message::default()).is_err());
        assert!(client.exchange(&Message::default()).is_ok());
        server.join().expect("join test server");
    }
}
