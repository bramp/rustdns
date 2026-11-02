//! Browser clock and resolver adapter for web-based DNS-over-HTTPS.

use crate::exchangers::BrowserClient;
use crate::trace::{QueryTrace, TraceEntry};
use rustdns::Message;
use rustdns::clients::{AsyncResolver, Response, ResponseMeta};
use rustdns::dnssec::Clock;
use rustdns::types::{QR, UpstreamTrustPolicy};
use std::time::{Duration, SystemTime};

/// Opaque monotonic browser instant used by the shared resolver interface.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BrowserInstant(Duration);

/// Monotonic browser clock backed by `performance.now()`.
#[derive(Clone, Copy, Debug, Default)]
pub struct BrowserClock;

impl Clock for BrowserClock {
    type Instant = BrowserInstant;

    fn now(&self) -> Option<Self::Instant> {
        let milliseconds = web_sys::window()?.performance()?.now();
        if !milliseconds.is_finite() || milliseconds < 0.0 {
            return None;
        }
        let micros = milliseconds * 1_000.0;
        if micros >= u64::MAX as f64 {
            return None;
        }
        Some(BrowserInstant(Duration::from_micros(micros as u64)))
    }

    fn checked_add(&self, instant: Self::Instant, duration: Duration) -> Option<Self::Instant> {
        instant.0.checked_add(duration).map(BrowserInstant)
    }

    fn checked_duration_since(
        &self,
        later: Self::Instant,
        earlier: Self::Instant,
    ) -> Option<Duration> {
        later.0.checked_sub(earlier.0)
    }
}

/// Browser-backed implementation of rustdns's standard [`AsyncResolver`] interface.
///
/// It performs one DoH exchange. DNSSEC dependency queries made by
/// [`rustdns::dnssec::ChainValidator`] use the same endpoint and deadline.
/// Every exchange is recorded; see [`BrowserResolver::take_trace`].
pub struct BrowserResolver {
    client: BrowserClient,
    clock: BrowserClock,
    trace: QueryTrace,
}

impl BrowserResolver {
    /// Creates a browser resolver using one DoH client.
    pub fn new(client: BrowserClient) -> Self {
        Self {
            client,
            clock: BrowserClock,
            trace: QueryTrace::default(),
        }
    }

    /// Removes and returns the exchanges made so far, in start order.
    pub fn take_trace(&self) -> Vec<TraceEntry> {
        self.trace.take()
    }

    async fn exchange_once(
        &self,
        query: &Message,
        start: BrowserInstant,
        deadline: BrowserInstant,
    ) -> Result<Response, rustdns::Error> {
        let timeout = self
            .clock
            .checked_duration_since(deadline, start)
            .filter(|timeout| !timeout.is_zero())
            .ok_or_else(timeout_error)?;
        let when = browser_system_time().ok_or_else(clock_error)?;

        let mut wire = self.client.exchange_with_timeout(query, timeout).await?;
        let completed = self.clock.now().ok_or_else(clock_error)?;
        if self
            .clock
            .checked_duration_since(completed, deadline)
            .is_some()
        {
            return Err(timeout_error());
        }
        correlate_doh_response(query, &mut wire.message)?;

        let elapsed = self
            .clock
            .checked_duration_since(completed, start)
            .ok_or_else(clock_error)?;
        let channel_security = wire.meta.channel_security;
        let security_status = rustdns::clients::upstream_security_status(
            &wire.message,
            channel_security,
            UpstreamTrustPolicy::SecureTransportOnly,
        );
        let upstream = self.client.endpoint();

        Ok(Response {
            message: wire.message,
            meta: ResponseMeta {
                upstream,
                attempts: 1,
                elapsed,
                when,
                security_status,
                security_source: rustdns::types::SecuritySource::AdFlag,
                dnssec_error: None,
                channel_security,
                wire: vec![wire.meta],
            },
        })
    }
}

#[async_trait::async_trait]
impl AsyncResolver<BrowserInstant> for BrowserResolver {
    async fn exchange_with_deadline(
        &self,
        query: &Message,
        deadline: BrowserInstant,
    ) -> Result<Response, rustdns::Error> {
        if query.questions.is_empty() {
            return Err(rustdns::Error::MissingQuestion);
        }
        let start = self.clock.now().ok_or_else(clock_error)?;
        let result = self.exchange_once(query, start, deadline).await;
        let elapsed = self
            .clock
            .now()
            .and_then(|end| self.clock.checked_duration_since(end, start))
            .unwrap_or_default();
        self.trace.record(query, start.0, elapsed, result.as_ref());
        result
    }
}

/// Checks that a DoH `response` answers `query`, then restores the query ID.
///
/// HTTP correlates DoH exchanges, and [RFC 8484 §4.1] requires clients to
/// accept a response ID that differs from the (zeroed) query ID, so the ID is
/// not compared.
///
/// [RFC 8484 §4.1]: https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
fn correlate_doh_response(query: &Message, response: &mut Message) -> Result<(), rustdns::Error> {
    if response.qr != QR::Response || response.questions != query.questions {
        return Err(rustdns::Error::ResponseMismatch);
    }
    response.id = query.id;
    Ok(())
}

pub(crate) fn browser_system_time() -> Option<SystemTime> {
    let milliseconds = js_sys::Date::now();
    if !milliseconds.is_finite() || milliseconds < 0.0 {
        return None;
    }
    let milliseconds = milliseconds as u64;
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_millis(milliseconds))
}

fn clock_error() -> rustdns::Error {
    rustdns::Error::ClockUnavailable
}

fn timeout_error() -> rustdns::Error {
    rustdns::Error::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "DNS resolution exceeded the deadline",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn browser_instant_ordering_tracks_elapsed_duration() {
        let clock = BrowserClock;
        let start = BrowserInstant(Duration::from_millis(10));
        let end = clock.checked_add(start, Duration::from_millis(20)).unwrap();

        assert_eq!(
            clock.checked_duration_since(end, start),
            Some(Duration::from_millis(20))
        );
        assert_eq!(clock.checked_duration_since(start, end), None);
        assert!(end > start);
    }

    fn query_and_response() -> (Message, Message) {
        let mut query = Message {
            id: 0x1234,
            ..Default::default()
        };
        query
            .try_add_question("example.com", rustdns::Type::A, rustdns::Class::Internet)
            .unwrap();
        let mut response = query.clone();
        response.qr = QR::Response;
        (query, response)
    }

    #[wasm_bindgen_test]
    fn doh_response_with_any_id_is_accepted_and_restored() {
        for id in [0, 0x1234, 0xBEEF] {
            let (query, mut response) = query_and_response();
            response.id = id;
            correlate_doh_response(&query, &mut response).unwrap();
            assert_eq!(response.id, query.id);
        }
    }

    #[wasm_bindgen_test]
    fn doh_response_must_be_a_response_to_the_same_question() {
        let (query, mut response) = query_and_response();
        response.qr = QR::Query;
        assert!(correlate_doh_response(&query, &mut response).is_err());

        let (query, mut response) = query_and_response();
        response.questions.clear();
        assert!(correlate_doh_response(&query, &mut response).is_err());
    }
}
