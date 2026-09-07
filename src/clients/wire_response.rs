use crate::Message;
use crate::types::{ChannelSecurity, TlsInfo};
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::time::Duration;

/// Metadata and statistics from one transport exchange over the wire.
#[derive(Clone, Debug, PartialEq)]
pub struct WireResponseMeta {
    /// Target server socket address (IP and port), if known from the transport.
    pub server: Option<SocketAddr>,

    /// Duration of this single attempt across the wire.
    pub elapsed: Duration,

    /// Number of bytes sent over the wire for this query.
    pub bytes_sent: usize,

    /// Number of bytes received from the wire for this response.
    pub bytes_received: usize,

    /// Transport security classification of this exchange.
    pub channel_security: ChannelSecurity,

    /// Optional TLS connection details if this exchange was over an encrypted transport.
    pub tls_info: Option<TlsInfo>,
}

impl std::fmt::Display for WireResponseMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, ";; Query time: {} msec", self.elapsed.as_millis())?;
        if let Some(server) = self.server {
            writeln!(f, ";; SERVER: {server}")?;
        }
        writeln!(
            f,
            ";; MSG SIZE sent: {} rcvd: {}",
            self.bytes_sent, self.bytes_received
        )?;
        writeln!(f, ";; CHANNEL: {}", self.channel_security)?;
        if let Some(tls) = &self.tls_info {
            write!(f, ";; TLS: {}", tls.version)?;
            if let Some(cs) = &tls.cipher_suite {
                write!(f, ", {cs}")?;
            }
            if let Some(alpn) = &tls.alpn {
                write!(f, ", alpn: {alpn}")?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

/// The result of one low-level transport exchange, pairing the decoded DNS
/// [`Message`] with transport-level execution metadata ([`WireResponseMeta`]).
///
/// Implements [`Deref<Target = Message>`] and [`DerefMut`] for convenient
/// direct access to DNS message fields without unwrapping.
#[derive(Clone, Debug, PartialEq)]
pub struct WireResponse {
    /// The decoded DNS message.
    pub message: Message,

    /// Transport-level metadata and statistics from this exchange.
    pub meta: WireResponseMeta,
}

impl WireResponse {
    /// Creates a new [`WireResponse`] wrapping `message` and `meta`.
    pub fn new(message: Message, meta: WireResponseMeta) -> Self {
        Self { message, meta }
    }

    /// Creates a synthetic [`WireResponse`] for testing.
    #[doc(hidden)]
    pub fn test(message: Message, channel_security: ChannelSecurity) -> Self {
        Self {
            message,
            meta: WireResponseMeta {
                server: Some("127.0.0.1:53".parse().unwrap()),
                elapsed: Duration::from_millis(1),
                bytes_sent: 0,
                bytes_received: 0,
                channel_security,
                tls_info: None,
            },
        }
    }
}

impl Deref for WireResponse {
    type Target = Message;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl DerefMut for WireResponse {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.message
    }
}

impl std::fmt::Display for WireResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)?;
        write!(f, "{}", self.meta)
    }
}
