use crate::Message;
use crate::clients::wire_response::{WireResponse, WireResponseMeta};
use crate::types::{ChannelSecurity, TlsInfo};
use std::net::SocketAddr;
use std::time::Instant;

/// Builder class to aid in the construction of [`WireResponse`] objects.
pub(crate) struct WireResponseBuilder {
    timer: Instant,
    bytes_sent: usize,
}

impl WireResponseBuilder {
    /// Call just before the request is sent, with the payload size.
    pub fn start(bytes_sent: usize) -> WireResponseBuilder {
        WireResponseBuilder {
            timer: Instant::now(),
            bytes_sent,
        }
    }

    /// Call just after the response is received. Consumes the builder and returns a [`WireResponse`].
    pub fn finish(
        self,
        message: Message,
        server: Option<SocketAddr>,
        bytes_received: usize,
        channel_security: ChannelSecurity,
        tls_info: Option<TlsInfo>,
    ) -> WireResponse {
        WireResponse {
            message,
            meta: WireResponseMeta {
                server,
                elapsed: self.timer.elapsed(),
                bytes_sent: self.bytes_sent,
                bytes_received,
                channel_security,
                tls_info,
            },
        }
    }
}
