use std::time::SystemTime;
use crate::Stats;
use std::net::SocketAddr;
use std::time::Instant;

/// Builder class to aid in the construction of Stats objects.
pub(crate) struct StatsBuilder {
    start: SystemTime,
    timer: Instant,
    request_size: usize,
}

impl StatsBuilder {
    /// Call just before the request is sent, with the payload size.
    pub fn start(request_size: usize) -> StatsBuilder {
        StatsBuilder {
            start: SystemTime::now(),
            timer: Instant::now(),

            request_size,
        }
    }

    /// Call just after the response is receivesd. Consumes the MetadataBuilder and returns a Metadata.
    pub fn end(self, server: SocketAddr, response_size: usize) -> Stats {
        Stats {
            start: self.start,
            duration: self.timer.elapsed(),

            request_size: self.request_size,

            server,
            response_size,
        }
    }
}