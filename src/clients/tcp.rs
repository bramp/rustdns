use crate::clients::Exchanger;
use crate::Message;
use crate::clients::stats::StatsBuilder;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
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
///     query.add_question("bramp.net", Type::A, Class::Internet);
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
// TODO Document all the options.
pub struct Client {
    servers: Vec<SocketAddr>,

    connect_timeout: Duration,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            servers: Vec::default(),
            connect_timeout: Duration::new(5, 0),
            read_timeout: Some(Duration::new(5, 0)),
            write_timeout: Some(Duration::new(5, 0)),
        }
    }
}

impl Client {
    /// Creates a new Client bound to the specific servers.
    // TODO Document how it fails.
    pub fn new<A: ToSocketAddrs>(servers: A) -> Result<Self, crate::Error> {
        let servers = servers.to_socket_addrs()?.collect();
        // TODO Check for zero servers.
        Ok(Self {
            servers,

            ..Default::default()
        })
    }
}

impl Exchanger for Client {
    /// Sends the [`Message`] to the `server` via TCP and returns the result.
    fn exchange(&self, query: &Message) -> Result<Message, crate::Error> {
        let mut stream = TcpStream::connect_timeout(&self.servers[0], self.connect_timeout)?;
        stream.set_nodelay(true)?; // We send discrete packets, so we can send as soon as possible.
        stream.set_read_timeout(self.read_timeout)?;
        stream.set_write_timeout(self.write_timeout)?;

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

        Ok(resp)
    }
}
