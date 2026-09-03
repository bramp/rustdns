use crate::clients::stats::StatsBuilder;
use crate::clients::Exchanger;
use crate::Message;
use socket2::{Socket, TcpKeepalive};
use std::cell::Cell;
use std::convert::TryFrom;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
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

pub(crate) fn encode_tcp_frame(message: &[u8]) -> std::io::Result<Vec<u8>> {
    let length = u16::try_from(message.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "DNS message is too large")
    })?;
    let mut frame = Vec::with_capacity(message.len() + 2);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(message);
    Ok(frame)
}

/// A TCP DNS Client.
///
/// # Example
///
/// ```rust
/// use rustdns::clients::Exchanger;
/// use rustdns::clients::tcp::Client;
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
/// See <https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2>
pub struct Client {
    /// Resolved DNS server addresses. The first address is used for each exchange.
    servers: Vec<SocketAddr>,

    /// Maximum time allowed to establish a TCP connection. Defaults to five seconds.
    connect_timeout: Duration,
    /// Maximum time allowed for TCP reads. Defaults to five seconds; `None` disables it.
    read_timeout: Option<Duration>,
    /// Maximum time allowed for TCP writes. Defaults to five seconds; `None` disables it.
    write_timeout: Option<Duration>,

    /// Lazily created TCP connection and its last successful-use time.
    connection: Cell<Option<(TcpStream, Instant)>>,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            servers: Vec::default(),
            connect_timeout: Duration::new(5, 0),
            read_timeout: Some(Duration::new(5, 0)),
            write_timeout: Some(Duration::new(5, 0)),
            connection: Cell::new(None),
        }
    }
}

impl Client {
    /// Creates a new Client bound to the specific servers.
    ///
    /// The first resolved server is used for each exchange.
    ///
    /// # Errors
    ///
    /// Returns an error if server address resolution fails or produces no addresses.
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
        if let Some((stream, last_used)) = self.connection.take() {
            if last_used.elapsed() <= TCP_CONNECTION_IDLE_TIMEOUT {
                return Ok(stream);
            }
        }

        let stream = TcpStream::connect_timeout(server, self.connect_timeout)?;
        let socket = Socket::from(stream);
        let keepalive = TcpKeepalive::new().with_time(TCP_KEEPALIVE_TIME);
        socket.set_tcp_keepalive(&keepalive)?;

        let stream: TcpStream = socket.into();
        stream.set_nodelay(true)?;
        stream.set_read_timeout(self.read_timeout)?;
        stream.set_write_timeout(self.write_timeout)?;

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
        let server = self.servers.first().ok_or_else(|| {
            crate::Error::InvalidArgument("at least one DNS server is required".to_string())
        })?;
        let mut stream = self.get_stream(server)?;

        let message = query.to_vec()?;

        let stats = StatsBuilder::start(message.len() + 2);

        // Two byte length prefix followed by the message.
        // TODO Move this into a single message!
        stream.write_all(&(message.len() as u16).to_be_bytes())?;
        stream.write_all(&message)?;

        // Now receive a two byte length
        let buf = &mut [0; 2];
        stream.read_exact(buf)?;
        let len = u16::from_be_bytes(*buf);

        // and finally the message
        let mut buf = vec![0; len.into()];

        stream.read_exact(&mut buf)?;

        let mut resp = Message::from_slice(&buf)?;
        resp.stats = Some(stats.end(stream.peer_addr()?, (len + 2).into()));

        self.connection.set(Some((stream, Instant::now())));

        Ok(resp)
    }
}

#[cfg(feature = "async-tcp")]
pub use crate::clients::tcp_async::AsyncClient;

#[cfg(test)]
mod tests {
    use super::Client;
    use crate::clients::Exchanger;
    use crate::Message;
    use std::io::Read;
    use std::io::Write;
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

            let client = Client::new(address).expect("create test client");
            assert!(client.exchange(&Message::default()).is_err());
            server.join().expect("join test server");
        }
    }

    #[test]
    fn configures_timeouts() {
        let mut client = Client::new("127.0.0.1:53").expect("create test client");

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

        let client = Client::new(address).expect("create test client");
        assert!(client.exchange(&Message::default()).is_ok());
        assert!(client.exchange(&Message::default()).is_ok());
        server.join().expect("join test server");
    }
}
