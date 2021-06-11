use crate::Message;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::time::Duration;

/// A TCP DNS Client.
///
/// # Example
///
/// ```rust
/// use rustdns::types::*;
/// use rustdns::clients::TcpClient;
/// use std::io::Result;
///
/// fn main() -> Result<()> {
///     let mut query = Message::default();
///     query.add_question("bramp.net", Type::A, Class::Internet);
///
///     let response = TcpClient::new("8.8.8.8:53")?
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
pub struct TcpClient {
    servers: Vec<SocketAddr>,

    connect_timeout: Duration,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl Default for TcpClient {
    fn default() -> Self {
        TcpClient {
            servers: Vec::default(),
            connect_timeout: Duration::new(5, 0),
            read_timeout: Some(Duration::new(5, 0)),
            write_timeout: Some(Duration::new(5, 0)),
        }
    }
}

impl TcpClient {
    /// Creates a new TcpClient bound to the specific servers.
    // TODO Document how it fails.
    pub fn new<A: ToSocketAddrs>(servers: A) -> io::Result<Self> {
        let servers = servers.to_socket_addrs()?.collect();
        // TODO Check for zero servers.
        Ok(Self {
            servers,

            ..Default::default()
        })
    }

    /// Sends the [`Message`] to the `server` via TCP and returns the result.
    pub fn exchange(&self, query: &Message) -> io::Result<Message> {
        let mut stream = TcpStream::connect_timeout(&self.servers[0], self.connect_timeout)?;
        stream.set_nodelay(true)?; // We send discrete packets, so we can send as soon as possible.
        stream.set_read_timeout(self.read_timeout)?;
        stream.set_write_timeout(self.write_timeout)?;

        let message = query.to_vec()?;

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

        let resp = Message::from_slice(&buf)?;

        Ok(resp)
    }
}
