use crate::Message;
use crate::StatsBuilder;

use std::io;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::net::UdpSocket;
use std::time::Duration;

/// A UDP DNS Client.
///
/// # Example
///
/// ```rust
/// use rustdns::types::*;
/// use rustdns::clients::UdpClient;
/// use std::io::Result;
///
/// fn main() -> Result<()> {
///     let mut query = Message::default();
///     query.add_question("bramp.net", Type::A, Class::Internet);
///
///     let response = UdpClient::new("8.8.8.8:53")?
///        .exchange(&query)
///        .expect("could not exchange message");
///
///     println!("{}", response);
///     Ok(())
/// }
/// ```
///
/// See <https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.1>
// TODO Document all the options.
pub struct UdpClient {
    servers: Vec<SocketAddr>,

    read_timeout: Option<Duration>,
}

impl Default for UdpClient {
    fn default() -> Self {
        UdpClient {
            servers: Vec::default(),
            read_timeout: Some(Duration::new(5, 0)),
        }
    }
}

impl UdpClient {
    /// Creates a new UdpClient bound to the specific servers.
    // TODO Document how it fails.
    // TODO Document how you can give it a set of addresses.
    // TODO Document how they should be IP addresses, not hostnames.
    pub fn new<A: ToSocketAddrs>(servers: A) -> io::Result<Self> {
        let servers = servers.to_socket_addrs()?.collect();
        // TODO Check for zero servers.
        Ok(Self {
            servers,

            ..Default::default()
        })
    }

    /// Sends the [`Message`] to the `server` via UDP and returns the result.
    pub fn exchange(&self, query: &Message) -> io::Result<Message> {
        // TODO Implement retries, backoffs, and cycling of servers.
        // per https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.1

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(self.read_timeout)?;

        // Connect us to the server, meaning recv will only receive directly
        // from the server.
        socket.connect(self.servers.as_slice())?;

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
