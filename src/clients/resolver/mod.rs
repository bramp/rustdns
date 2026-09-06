use crate::Extension;
use crate::Message;
use crate::clients::{AsyncExchanger, IntoAsyncExchanger};
use crate::types::*;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

mod backoff;
pub use backoff::Backoff;

/// Upstream selection strategy used by a [`Resolver`].
///
/// Only [`Strategy::Failover`] is implemented today. Racing, fastest-upstream,
/// and staggered strategies are planned; see the "Resolution Strategies"
/// section of PLAN.md.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Strategy {
    /// Try upstreams in configured order, moving on for retryable failures.
    #[default]
    Failover,
}

/// Resolver execution metadata attached to a [`Response`].
#[derive(Clone, Debug)]
pub struct ResponseMeta {
    /// The endpoint or identifier of the upstream that produced this response.
    pub upstream: Arc<str>,

    /// Number of attempts made against that upstream before this response was returned.
    pub attempts: u32,

    /// Total time spent resolving, including any retries against earlier upstreams.
    pub elapsed: Duration,
}

/// A decoded DNS [`Message`] together with resolver execution metadata.
#[derive(Clone, Debug)]
pub struct Response {
    /// The decoded DNS message. Remains the source of truth for protocol contents.
    pub message: Message,

    /// Metadata describing how this response was obtained.
    pub meta: ResponseMeta,
}

/// Builder for [`Resolver`].
pub struct ResolverBuilder {
    upstreams: Vec<Box<dyn AsyncExchanger + Send + Sync>>,
    error: Option<crate::Error>,
    strategy: Strategy,
    timeout: Duration,
    retries: u32,
    backoff: Backoff,
}

impl Default for ResolverBuilder {
    fn default() -> Self {
        Self {
            upstreams: Vec::new(),
            error: None,
            strategy: Strategy::default(),
            timeout: Duration::from_secs(5),
            retries: 2,
            backoff: Backoff::default(),
        }
    }
}

impl ResolverBuilder {
    /// Adds an upstream. Accepts any target implementing [`IntoAsyncExchanger`]:
    /// a transport, an address ([`SocketAddr`](std::net::SocketAddr) or [`IpAddr`]), or a URL or address string (`"8.8.8.8"`, `"https://..."`).
    pub fn upstream(mut self, upstream: impl IntoAsyncExchanger) -> Self {
        if self.error.is_none() {
            match upstream.into_async_exchanger() {
                Ok(transport) => self.upstreams.push(transport),
                Err(err) => self.error = Some(err),
            }
        }
        self
    }

    /// Sets the upstream selection strategy. Defaults to [`Strategy::Failover`].
    pub fn strategy(mut self, strategy: Strategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Sets the default resolution budget used by [`Resolver::exchange`] and
    /// [`Resolver::lookup`]. Defaults to 5 seconds.
    ///
    /// This is only a default: it is not a property of any one exchange.
    /// When DNS resolution is one step inside a larger, already deadline-bound
    /// operation (for example an incoming request with its own SLA), use
    /// [`Resolver::exchange_with_deadline`] or [`Resolver::lookup_with_deadline`]
    /// to pass the caller's actual remaining budget instead.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the number of retries per upstream, in addition to the first attempt. Defaults to 2.
    pub fn retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    /// Sets the delay strategy applied between retries against the same
    /// upstream. Defaults to exponential backoff with full jitter (200ms
    /// base, factor 2, capped at 2 seconds).
    pub fn backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// Builds the [`Resolver`].
    ///
    /// # Errors
    ///
    /// Returns an error if an upstream target failed to parse, or if no upstream was added.
    pub fn build(self) -> Result<Resolver, crate::Error> {
        if let Some(err) = self.error {
            return Err(err);
        }

        if self.upstreams.is_empty() {
            return Err(crate::Error::InvalidArgument(
                "at least one upstream is required".to_string(),
            ));
        }

        Ok(Resolver {
            upstreams: self.upstreams,
            strategy: self.strategy,
            timeout: self.timeout,
            retries: self.retries,
            backoff: self.backoff,
        })
    }
}

/// Classification of a correlated response, used to decide whether to retry or fail over.
enum Outcome {
    /// A final answer for the caller: `NoError`, `NXDomain`, `Refused`, etc.
    Definitive,

    /// Worth retrying against another attempt or upstream (e.g. `ServFail`).
    Retryable,
}

/// Classifies a correlated response's rcode.
///
/// `ServFail` is retryable in the absence of a stronger signal (for example an
/// Extended DNS Error code); other rcodes are treated as definitive.
/// See the "Retry And Failure Semantics" section of PLAN.md.
fn classify(response: &Message) -> Outcome {
    match response.rcode {
        Rcode::ServFail => Outcome::Retryable,
        _ => Outcome::Definitive,
    }
}

/// Checks that `response` is a plausible answer to `query`: it must be a
/// response (not a query), match the transaction id, and echo the question
/// section.
///
/// Under [RFC 5452 §4.3] (Measures for Making DNS More Resilient against
/// Forged Answers), resolvers must match the query ID, question name, type,
/// and class to defend against spoofing and cache poisoning. We also verify
/// that the question counts match exactly (`response.questions.len() == query.questions.len()`)
/// to prevent injection of extraneous questions.
///
/// As permitted by [RFC 1035 §4.1.1], servers responding with an error status
/// (such as `FORMERR`, `SERVFAIL`, or `NOTIMP`) may omit the Question section
/// entirely (e.g. if the query packet could not be parsed). If the response
/// reports an error rcode (`rcode != NoError`), an empty Question section is
/// accepted as correlated so the resolver can classify and act on the error.
///
/// The transaction id is compared loosely: DoH clients may rewrite it to `0`
/// for HTTP cache-friendliness ([RFC 8484 §4.1]), so a response id of `0` is
/// always accepted.
///
/// [RFC 1035 §4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
/// [RFC 5452 §4.3]: https://datatracker.ietf.org/doc/html/rfc5452#section-4.3
/// [RFC 8484 §4.1]: https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
fn correlates(query: &Message, response: &Message) -> bool {
    if response.qr != QR::Response {
        return false;
    }

    if response.id != query.id && response.id != 0 {
        return false;
    }

    // RFC 1035 §4.1.1: servers returning an error (e.g. FORMERR) may omit the
    // question section when unable to echo it.
    if response.questions.is_empty() && response.rcode != Rcode::NoError {
        return true;
    }

    // RFC 5452 §4.3: ensure exact 1:1 match of the Question section.
    if response.questions.len() != query.questions.len() {
        return false;
    }

    query.questions.iter().all(|question| {
        response.questions.iter().any(|candidate| {
            candidate.name.eq_ignore_ascii_case(&question.name)
                && candidate.r#type == question.r#type
                && candidate.class == question.class
        })
    })
}

/// The orchestration layer above single-target transports.
///
/// A [`Resolver`] owns upstream selection, retries, and failover; transports
/// (see [`AsyncExchanger`]) own the protocol mechanics of talking to one
/// endpoint. See the "Resolver Architecture And Policy" section of PLAN.md.
///
/// Construct one with [`Resolver::builder`].
pub struct Resolver {
    upstreams: Vec<Box<dyn AsyncExchanger + Send + Sync>>,
    strategy: Strategy,
    timeout: Duration,
    retries: u32,
    backoff: Backoff,
}

impl Resolver {
    /// Returns a new [`ResolverBuilder`].
    pub fn builder() -> ResolverBuilder {
        ResolverBuilder::default()
    }

    /// Like [`Resolver::exchange_with_deadline`], using a deadline `self.timeout` from now.
    ///
    /// # Errors
    ///
    /// See [`Resolver::exchange_with_deadline`].
    pub async fn exchange(&self, query: &Message) -> Result<Response, crate::Error> {
        self.exchange_with_deadline(query, Instant::now() + self.timeout)
            .await
    }

    /// Sends `query` to the configured upstreams, following the resolver's
    /// strategy, retry, and failover policy, and returns the response plus
    /// resolver execution metadata.
    ///
    /// `deadline` bounds the entire resolution, including every attempt and
    /// retry. Pass the caller's own remaining budget when DNS resolution is
    /// one step inside a larger, already deadline-bound operation.
    ///
    /// # Errors
    ///
    /// Returns an error if `query` has no question, if `deadline` elapses, or
    /// if every eligible upstream is exhausted without a usable response.
    pub async fn exchange_with_deadline(
        &self,
        query: &Message,
        deadline: Instant,
    ) -> Result<Response, crate::Error> {
        if query.questions.is_empty() {
            return Err(crate::Error::InvalidArgument(
                "query must have at least one question".to_string(),
            ));
        }

        let start = Instant::now();
        tokio::time::timeout_at(deadline.into(), async {
            let mut tried = Vec::new();
            let mut last_err = None;

            match self.strategy {
                Strategy::Failover => {
                    for upstream in &self.upstreams {
                        if !self.is_eligible(upstream.as_ref()) {
                            continue;
                        }

                        let id = upstream.endpoint();
                        tried.push(id.clone());
                        match self.attempt_upstream(upstream.as_ref(), query, deadline).await {
                            Ok((message, attempts)) => {
                                return Ok(Response {
                                    message,
                                    meta: ResponseMeta {
                                        upstream: id,
                                        attempts,
                                        elapsed: start.elapsed(),
                                    },
                                });
                            }
                            Err(error) => last_err = Some(error),
                        }
                    }
                }
            }

            Err(last_err.unwrap_or_else(|| {
                crate::Error::InvalidArgument(format!(
                    "no upstream returned a usable response (tried: {})",
                    tried.join(", ")
                ))
            }))
        })
        .await
        .map_err(|_| {
            crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "resolution exceeded the deadline",
            ))
        })?
    }

    /// Like [`Resolver::lookup_with_deadline`], using a deadline `self.timeout` from now.
    ///
    /// # Errors
    ///
    /// See [`Resolver::lookup_with_deadline`].
    pub async fn lookup(&self, name: &str) -> Result<Vec<IpAddr>, crate::Error> {
        self.lookup_with_deadline(name, Instant::now() + self.timeout)
            .await
    }

    /// Resolves `name`'s `A` and `AAAA` records, both bounded by `deadline`.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` cannot be encoded, `deadline` elapses, an
    /// exchange fails, or a response reports a failure status.
    // https://datatracker.ietf.org/doc/html/rfc1035#section-7
    pub async fn lookup_with_deadline(
        &self,
        name: &str,
        deadline: Instant,
    ) -> Result<Vec<IpAddr>, crate::Error> {
        let mut results = std::collections::HashSet::new();

        // TODO Send the A and AAAA queries concurrently.
        for r#type in [Type::A, Type::AAAA] {
            let mut query = Message::default();
            // TODO Should I explictly set query values - incase the defaults are not suitable.
            query.try_add_question(name, r#type, Class::Internet)?;
            query.set_extension(Extension {
                // TODO Is this the correct value to set for payload size?
                payload_size: 4096, // Allow for bigger responses.
                ..Default::default()
            });

            let response = self.exchange_with_deadline(&query, deadline).await?;
            log::debug!(
                "{name}: {type} query via upstream '{:?}' returned {} answer(s)",
                response.meta.upstream,
                response.message.answers.len()
            );

            if response.message.rcode != Rcode::NoError {
                return Err(crate::Error::InvalidArgument(format!(
                    "query failed with rcode: {}",
                    response.message.rcode
                )));
            }

            for answer in response.message.answers {
                match answer.resource {
                    Resource::A(ip4) => results.insert(IpAddr::V4(ip4)),
                    Resource::AAAA(ip6) => results.insert(IpAddr::V6(ip6)),
                    _ => false, // Ignore other types.
                };
            }
        }

        Ok(results.into_iter().collect())
    }

    // TODO(resolver-health): plug in SRTT/circuit-breaker eligibility here.
    // See PLAN.md "Upstreams And Resolver Configuration".
    fn is_eligible(&self, _upstream: &(dyn AsyncExchanger + Send + Sync)) -> bool {
        true
    }

    /// Runs up to `self.retries + 1` attempts against one upstream.
    ///
    /// Each attempt is bounded only by `deadline` and by the transport's own
    /// timeout behavior; the resolver does not impose a separate per-attempt
    /// timeout.
    async fn attempt_upstream(
        &self,
        upstream: &(dyn AsyncExchanger + Send + Sync),
        query: &Message,
        deadline: Instant,
    ) -> Result<(Message, u32), crate::Error> {
        let mut last_err = None;
        let mut previous_delay = Duration::ZERO;
        let id = upstream.endpoint();

        for attempt in 0..=self.retries {
            if attempt > 0 {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let delay = self.backoff.next_delay(attempt, previous_delay);
                previous_delay = delay;
                tokio::time::sleep(delay.min(remaining)).await;
            }

            if deadline.saturating_duration_since(Instant::now()).is_zero() {
                break;
            }

            match upstream.exchange(query).await {
                Ok(response) if correlates(query, &response) => match classify(&response) {
                    Outcome::Definitive => return Ok((response, attempt + 1)),
                    Outcome::Retryable => {
                        last_err = Some(crate::Error::InvalidArgument(format!(
                            "upstream '{id}' returned rcode {}",
                            response.rcode
                        )));
                    }
                },
                Ok(_uncorrelated) => {
                    last_err = Some(crate::Error::InvalidArgument(format!(
                        "upstream '{id}' returned a response that did not match the query"
                    )));
                }
                Err(error) => last_err = Some(error),
            }
        }

        Err(last_err.unwrap_or_else(|| {
            crate::Error::InvalidArgument(format!("upstream '{id}' exhausted all attempts"))
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_with_id(id: u16) -> Message {
        let mut query = Message {
            id,
            ..Default::default()
        };
        query
            .try_add_question("bramp.net", Type::A, Class::Internet)
            .expect("valid question");
        query
    }

    fn response_to(query: &Message) -> Message {
        let mut response = query.clone();
        response.qr = QR::Response;
        response
    }

    #[test]
    fn correlates_matching_response() {
        let query = query_with_id(0x1234);
        let response = response_to(&query);
        assert!(correlates(&query, &response));
    }

    #[test]
    fn correlates_rejects_non_response() {
        let query = query_with_id(0x1234);
        let response = query.clone(); // qr is still QR::Query
        assert!(!correlates(&query, &response));
    }

    #[test]
    fn correlates_rejects_mismatched_id() {
        let query = query_with_id(0x1234);
        let mut response = response_to(&query);
        response.id = 0x4321;
        assert!(!correlates(&query, &response));
    }

    #[test]
    fn correlates_accepts_doh_style_zero_id() {
        let query = query_with_id(0x1234);
        let mut response = response_to(&query);
        response.id = 0;
        assert!(correlates(&query, &response));
    }

    #[test]
    fn correlates_rejects_missing_question() {
        let query = query_with_id(0x1234);
        let mut response = response_to(&query);
        response.questions.clear();
        assert!(!correlates(&query, &response));
    }

    #[test]
    fn correlates_rejects_extraneous_question() {
        let query = query_with_id(0x1234);
        let mut response = response_to(&query);
        response
            .try_add_question("injected.attacker.com", Type::A, Class::Internet)
            .unwrap();
        assert!(!correlates(&query, &response));
    }

    #[test]
    fn correlates_accepts_error_with_omitted_questions() {
        let query = query_with_id(0x1234);
        let mut response = response_to(&query);
        response.questions.clear();
        response.rcode = Rcode::FormErr;
        assert!(correlates(&query, &response));
    }

    #[test]
    fn builder_rejects_empty_upstreams() {
        assert!(ResolverBuilder::default().build().is_err());
    }

    struct Noop;

    #[async_trait::async_trait]
    impl AsyncExchanger for Noop {
        async fn exchange(&self, _query: &Message) -> Result<Message, crate::Error> {
            unreachable!("not called by this test")
        }

        fn endpoint(&self) -> Arc<str> {
            "noop".into()
        }
    }

    #[test]
    fn builder_accepts_various_upstream_types() {
        let resolver = Resolver::builder()
            .upstream(Noop)
            .upstream("8.8.8.8:53")
            .upstream("dns://8.8.8.8:53")
            .upstream("udp://8.8.8.8:53")
            .upstream("tcp://8.8.8.8:53")
            .build();

        assert!(resolver.is_ok());
    }

    #[test]
    fn builder_rejects_invalid_upstream_string() {
        let result = Resolver::builder().upstream("invalid://foo").build();

        assert!(result.is_err());
    }

    #[test]
    fn upstream_endpoints_are_roundtrippable() {
        let inputs = [
            "dns://8.8.8.8:53",
            "udp://8.8.8.8:53",
            "tcp://8.8.8.8:53",
            #[cfg(feature = "dot")]
            "tls://dns.google:853",
            #[cfg(feature = "doh")]
            "https://dns.google/dns-query",
        ];

        for &input in &inputs {
            let upstream = input
                .into_async_exchanger()
                .unwrap_or_else(|e| panic!("failed into_async_exchanger for '{input}': {e}"));
            let endpoint = upstream.endpoint();
            assert_eq!(
                &*endpoint, input,
                "endpoint for '{input}' did not match input"
            );

            // Round trip: feeding the endpoint back into into_async_exchanger must succeed
            // and produce an identical endpoint.
            let roundtripped = (&*endpoint).into_async_exchanger().unwrap_or_else(|e| {
                panic!("failed roundtrip into_async_exchanger for '{endpoint}': {e}")
            });
            assert_eq!(
                roundtripped.endpoint(),
                endpoint,
                "roundtripped endpoint did not match original"
            );
        }
    }

    #[test]
    fn bare_ip_assumes_do53_scheme() {
        let upstream = "8.8.8.8:53".into_async_exchanger().expect("valid address");
        assert_eq!(&*upstream.endpoint(), "dns://8.8.8.8:53");

        let upstream_default_port = "8.8.8.8".into_async_exchanger().expect("valid IP");
        assert_eq!(&*upstream_default_port.endpoint(), "dns://8.8.8.8:53");
    }
}

