use crate::Extension;
use crate::Message;
use crate::clients::resolver::ResolverBuilder;
use crate::clients::{AsyncExchanger, WireResponse, WireResponseMeta};
use crate::types::*;
use std::net::IpAddr;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use super::Backoff;

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

    /// Number of attempts made across upstreams before this response was returned.
    pub attempts: u32,

    /// Total time spent resolving, including any retries against earlier upstreams.
    pub elapsed: Duration,

    /// Timestamp when resolution started.
    pub when: SystemTime,

    /// DNSSEC security status evaluated for this response.
    pub security_status: SecurityStatus,

    /// Transport security classification of the channel that serviced this response.
    pub channel_security: ChannelSecurity,

    /// Low-level transport metadata and metrics from each attempt that produced a wire response,
    /// in chronological order. The last entry corresponds to the winning response.
    pub wire: Vec<WireResponseMeta>,
}

impl ResponseMeta {
    /// Returns the transport metadata of the winning attempt, if any wire response was received.
    pub fn winning_wire(&self) -> Option<&WireResponseMeta> {
        self.wire.last()
    }
}

impl std::fmt::Display for ResponseMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, ";; Query time: {} msec", self.elapsed.as_millis())?;
        writeln!(f, ";; UPSTREAM: {}", self.upstream)?;
        if let Some(winning) = self.wire.last() {
            if let Some(server) = winning.server {
                writeln!(f, ";; SERVER: {server}")?;
            }
        }
        let when: chrono::DateTime<chrono::Local> = self.when.into();
        writeln!(f, ";; WHEN: {}", when.format("%a %b %d %H:%M:%S %Z %Y"))?;

        if self.attempts > 1 {
            writeln!(f, ";; ATTEMPTS: {}", self.attempts)?;
        }
        if let Some(winning) = self.wire.last() {
            writeln!(
                f,
                ";; MSG SIZE sent: {} rcvd: {}",
                winning.bytes_sent, winning.bytes_received
            )?;
        }
        writeln!(f, ";; SECURITY: {}", self.security_status)?;
        writeln!(f, ";; CHANNEL: {}", self.channel_security)?;
        if let Some(winning) = self.wire.last() {
            if let Some(tls) = &winning.tls_info {
                write!(f, ";; TLS: {}", tls.version)?;
                if let Some(cs) = &tls.cipher_suite {
                    write!(f, ", {cs}")?;
                }
                if let Some(alpn) = &tls.alpn {
                    write!(f, ", alpn: {alpn}")?;
                }
                writeln!(f)?;
            }
        }
        Ok(())
    }
}

/// A decoded DNS [`Message`] together with resolver execution metadata.
#[derive(Clone, Debug)]
pub struct Response {
    /// The decoded DNS message. Remains the source of truth for protocol contents.
    pub message: Message,

    /// Metadata describing how this response was obtained.
    pub meta: ResponseMeta,
}

impl Deref for Response {
    type Target = Message;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl DerefMut for Response {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.message
    }
}

impl std::fmt::Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)?;
        write!(f, "{}", self.meta)
    }
}

/// The orchestration layer above single-target transports.
///
/// A [`Resolver`] owns upstream selection, retries, and failover; transports
/// (see [`AsyncExchanger`]) own the protocol mechanics of talking to one
/// endpoint. See the "Resolver Architecture And Policy" section of PLAN.md.
///
/// Construct one with [`Resolver::builder`].
pub struct Resolver {
    pub(crate) upstreams: Vec<Box<dyn AsyncExchanger + Send + Sync>>,
    pub(crate) strategy: Strategy,
    pub(crate) timeout: Duration,
    pub(crate) retries: u32,
    pub(crate) backoff: Backoff,
    pub(crate) dnssec_mode: DnssecMode,
    pub(crate) upstream_trust_policy: UpstreamTrustPolicy,
    pub(crate) payload_size: u16,
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

/// Evaluates the DNSSEC security status of a response.
fn evaluate_security_status(
    response: &Message,
    channel_security: ChannelSecurity,
    trust_policy: UpstreamTrustPolicy,
) -> SecurityStatus {
    if response.rcode == Rcode::ServFail {
        return SecurityStatus::Bogus;
    }

    if response.ad {
        if channel_security.is_secure() || trust_policy == UpstreamTrustPolicy::AlwaysTrust {
            SecurityStatus::Secure
        } else {
            SecurityStatus::Indeterminate
        }
    } else {
        SecurityStatus::Insecure
    }
}

impl Resolver {
    /// Returns a new [`ResolverBuilder`].
    pub fn builder() -> ResolverBuilder {
        ResolverBuilder::default()
    }

    /// Returns the configured DNSSEC validation mode.
    pub fn dnssec_mode(&self) -> DnssecMode {
        self.dnssec_mode
    }

    /// Returns the configured upstream trust policy.
    pub fn upstream_trust_policy(&self) -> UpstreamTrustPolicy {
        self.upstream_trust_policy
    }

    /// Returns the configured EDNS(0) UDP payload size in bytes.
    pub fn payload_size(&self) -> u16 {
        self.payload_size
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
    /// # Direct Exchange Contract
    ///
    /// This is a low-level protocol exchange operation. The provided [`Message`] is
    /// sent **verbatim** to upstreams without mutation:
    /// - It is **not** modified to set EDNS(0) or the `DO` (DNSSEC OK) bit.
    /// - Responses are **not** validated against [`DnssecMode`] policy; the response
    ///   is returned as received, with `meta.security_status` computed for caller inspection.
    ///
    /// For standard resolution where the resolver manages query construction, EDNS,
    /// DNSSEC flags, and enforces fail-closed validation policies, prefer the higher-level
    /// [`Resolver::query`] or [`Resolver::lookup`] methods.
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
        let when = SystemTime::now();
        tokio::time::timeout_at(deadline.into(), async {
            let mut tried = Vec::new();
            let mut last_err = None;
            let mut total_attempts = 0;
            let mut all_wire = Vec::new();

            match self.strategy {
                Strategy::Failover => {
                    for upstream in &self.upstreams {
                        if !self.is_eligible(upstream.as_ref()) {
                            continue;
                        }

                        let id = upstream.endpoint();
                        let channel_security = upstream.channel_security();
                        tried.push(id.clone());
                        match self.attempt_upstream(upstream.as_ref(), query, deadline).await {
                            Ok((wire_response, attempts, mut wires)) => {
                                total_attempts += attempts;
                                all_wire.append(&mut wires);
                                let security_status = evaluate_security_status(
                                    &wire_response.message,
                                    channel_security,
                                    self.upstream_trust_policy,
                                );
                                return Ok(Response {
                                    message: wire_response.message,
                                    meta: ResponseMeta {
                                        upstream: id,
                                        attempts: total_attempts,
                                        elapsed: start.elapsed(),
                                        when,
                                        security_status,
                                        channel_security,
                                        wire: all_wire,
                                    },
                                });
                            }
                            Err((error, attempts, mut wires)) => {
                                total_attempts += attempts;
                                all_wire.append(&mut wires);
                                last_err = Some(error);
                            }
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

    /// Helper to enforce DNSSEC validation policy on a response.
    fn validate_dnssec(&self, response: &Response) -> Result<(), crate::Error> {
        match self.dnssec_mode {
            DnssecMode::Off => Ok(()),
            DnssecMode::TrustUpstream { require_secure } => match response.meta.security_status {
                SecurityStatus::Secure => Ok(()),
                SecurityStatus::Insecure => {
                    if require_secure {
                        Err(crate::Error::Dnssec(
                            crate::errors::DnssecError::InsecureResponse,
                        ))
                    } else {
                        Ok(())
                    }
                }
                SecurityStatus::Bogus => {
                    Err(crate::Error::Dnssec(crate::errors::DnssecError::BogusResponse))
                }
                SecurityStatus::Indeterminate => {
                    Err(crate::Error::Dnssec(crate::errors::DnssecError::UntrustedChannel))
                }
            },
            DnssecMode::StrictLocal => Err(crate::Error::Dnssec(
                crate::errors::DnssecError::ValidationFailed(
                    "strict local validation is not yet implemented".to_string(),
                ),
            )),
        }
    }

    /// Like [`Resolver::query_with_deadline`], using a deadline `self.timeout` from now.
    ///
    /// # Errors
    ///
    /// See [`Resolver::query_with_deadline`].
    pub async fn query(&self, name: &str, rtype: Type) -> Result<Response, crate::Error> {
        self.query_with_deadline(name, rtype, Instant::now() + self.timeout)
            .await
    }

    /// Queries `name` for records of type `rtype`, bounded by `deadline`.
    ///
    /// Constructs a query [`Message`] with appropriate EDNS extension settings using
    /// [`Resolver::payload_size`] (defaulting to [`crate::limits::EDNS_SAFE_UDP_PAYLOAD_SIZE`],
    /// 1232 bytes) and, when [`DnssecMode`] is not [`DnssecMode::Off`], sets the `DO`
    /// (DNSSEC OK) bit.
    ///
    /// Enforces fail-closed DNSSEC validation on the received response according to
    /// the configured [`DnssecMode`].
    ///
    /// Returns the complete validated [`Response`] object containing the decoded DNS message
    /// and resolver metadata (including `security_status`).
    ///
    /// # Errors
    ///
    /// Returns an error if `name` cannot be encoded, `deadline` elapses, all upstreams
    /// fail without returning a usable response, or DNSSEC validation fails.
    pub async fn query_with_deadline(
        &self,
        name: &str,
        rtype: Type,
        deadline: Instant,
    ) -> Result<Response, crate::Error> {
        let mut query = Message::default();
        query.try_add_question(name, rtype, Class::Internet)?;

        let ext = Extension {
            payload_size: self.payload_size,
            dnssec_ok: self.dnssec_mode != DnssecMode::Off,
            ..Default::default()
        };
        query.set_extension(ext);

        let response = self.exchange_with_deadline(&query, deadline).await?;
        self.validate_dnssec(&response)?;
        Ok(response)
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
    /// Uses [`Resolver::query_with_deadline`] to dispatch queries (which automatically
    /// handles EDNS configuration and DNSSEC policy enforcement).
    ///
    /// # Errors
    ///
    /// Returns an error if `name` cannot be encoded, `deadline` elapses, an
    /// exchange fails, a response reports a failure status, or DNSSEC validation fails.
    // https://datatracker.ietf.org/doc/html/rfc1035#section-7
    pub async fn lookup_with_deadline(
        &self,
        name: &str,
        deadline: Instant,
    ) -> Result<Vec<IpAddr>, crate::Error> {
        let (a_response, aaaa_response) = tokio::try_join!(
            self.query_with_deadline(name, Type::A, deadline),
            self.query_with_deadline(name, Type::AAAA, deadline),
        )?;

        let mut results = std::collections::HashSet::new();

        for (r#type, response) in [(Type::A, a_response), (Type::AAAA, aaaa_response)] {
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
    ) -> Result<
        (WireResponse, u32, Vec<WireResponseMeta>),
        (crate::Error, u32, Vec<WireResponseMeta>),
    > {
        let mut last_err = None;
        let mut previous_delay = Duration::ZERO;
        let mut attempts = 0;
        let mut wires = Vec::new();
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

            attempts += 1;
            match upstream.exchange(query).await {
                Ok(response) if correlates(query, &response.message) => {
                    match classify(&response.message) {
                        Outcome::Definitive => {
                            wires.push(response.meta.clone());
                            return Ok((response, attempts, wires));
                        }
                        Outcome::Retryable => {
                            wires.push(response.meta.clone());
                            last_err = Some(crate::Error::InvalidArgument(format!(
                                "upstream '{id}' returned rcode {}",
                                response.rcode
                            )));
                        }
                    }
                }
                Ok(uncorrelated) => {
                    wires.push(uncorrelated.meta);
                    last_err = Some(crate::Error::InvalidArgument(format!(
                        "upstream '{id}' returned a response that did not match the query"
                    )));
                }
                Err(error) => last_err = Some(error),
            }
        }

        let err = last_err.unwrap_or_else(|| {
            crate::Error::InvalidArgument(format!("upstream '{id}' exhausted all attempts"))
        });
        Err((err, attempts, wires))
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

    struct DnssecMockExchanger {
        secure: bool,
        ad: bool,
        rcode: Rcode,
        answers: Vec<Record>,
        received_do: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl AsyncExchanger for DnssecMockExchanger {
        async fn exchange(&self, query: &Message) -> Result<WireResponse, crate::Error> {
            let has_do = query.extension.as_ref().is_some_and(|e| e.dnssec_ok);
            self.received_do
                .store(has_do, std::sync::atomic::Ordering::SeqCst);

            let mut response = response_to(query);
            response.ad = self.ad;
            response.rcode = self.rcode;
            response.answers = self.answers.clone();
            Ok(WireResponse::test(response, self.channel_security()))
        }

        fn endpoint(&self) -> Arc<str> {
            "dnssec-mock".into()
        }

        fn channel_security(&self) -> ChannelSecurity {
            if self.secure {
                ChannelSecurity::Encrypted
            } else {
                ChannelSecurity::Insecure
            }
        }
    }

    #[tokio::test]
    async fn dnssec_mode_controls_do_bit() {
        let do_tracker = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mock = DnssecMockExchanger {
            secure: true,
            ad: true,
            rcode: Rcode::NoError,
            answers: vec![Record::new(
                "bramp.net",
                Class::Internet,
                Duration::from_secs(60),
                Resource::A("127.0.0.1".parse().unwrap()),
            )],
            received_do: do_tracker.clone(),
        };

        // When DNSSEC mode is Off, DO bit is not set on query().
        let resolver_off = Resolver::builder()
            .dnssec_mode(DnssecMode::Off)
            .upstream(mock)
            .build()
            .expect("build resolver");
        let resp = resolver_off.query("bramp.net", Type::A).await.expect("query");
        assert!(!do_tracker.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(resp.meta.security_status, SecurityStatus::Secure);

        // When DNSSEC mode is TrustUpstream, DO bit is set on query().
        let do_tracker2 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mock2 = DnssecMockExchanger {
            secure: true,
            ad: true,
            rcode: Rcode::NoError,
            answers: vec![Record::new(
                "bramp.net",
                Class::Internet,
                Duration::from_secs(60),
                Resource::A("127.0.0.1".parse().unwrap()),
            )],
            received_do: do_tracker2.clone(),
        };
        let resolver_dnssec = Resolver::builder()
            .dnssec_mode(DnssecMode::TrustUpstream {
                require_secure: false,
            })
            .upstream(mock2)
            .build()
            .expect("build resolver");
        let resp2 = resolver_dnssec.query("bramp.net", Type::A).await.expect("query");
        assert!(do_tracker2.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(resp2.meta.security_status, SecurityStatus::Secure);

        // Direct exchange sends query verbatim without modifying DO bit
        let q_without_do = query_with_id(1);
        let resp3 = resolver_dnssec.exchange(&q_without_do).await.expect("exchange");
        assert!(!do_tracker2.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(resp3.meta.security_status, SecurityStatus::Secure);
    }

    #[tokio::test]
    async fn security_status_and_upstream_trust_policy() {
        let tracker = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let a_record = Record::new(
            "bramp.net",
            Class::Internet,
            Duration::from_secs(60),
            Resource::A("127.0.0.1".parse().unwrap()),
        );

        // AD=1 over insecure channel with SecureTransportOnly policy -> Indeterminate
        let mock_insecure = DnssecMockExchanger {
            secure: false,
            ad: true,
            rcode: Rcode::NoError,
            answers: vec![a_record.clone()],
            received_do: tracker.clone(),
        };
        let resolver = Resolver::builder()
            .dnssec_mode(DnssecMode::TrustUpstream {
                require_secure: false,
            })
            .upstream_trust_policy(UpstreamTrustPolicy::SecureTransportOnly)
            .upstream(mock_insecure)
            .build()
            .unwrap();
        // Direct exchange observes the evaluated status without fail-closed error
        let q = query_with_id(1);
        let resp = resolver.exchange(&q).await.unwrap();
        assert_eq!(resp.meta.security_status, SecurityStatus::Indeterminate);
        // Both query() and lookup() must fail closed on Indeterminate
        assert!(matches!(
            resolver.query("bramp.net", Type::A).await,
            Err(crate::Error::Dnssec(crate::errors::DnssecError::UntrustedChannel))
        ));
        assert!(matches!(
            resolver.lookup("bramp.net").await,
            Err(crate::Error::Dnssec(crate::errors::DnssecError::UntrustedChannel))
        ));

        // AD=1 over insecure channel with AlwaysTrust policy -> Secure
        let mock_always_trust = DnssecMockExchanger {
            secure: false,
            ad: true,
            rcode: Rcode::NoError,
            answers: vec![a_record.clone()],
            received_do: tracker.clone(),
        };
        let resolver_always = Resolver::builder()
            .dnssec_mode(DnssecMode::TrustUpstream {
                require_secure: true,
            })
            .upstream_trust_policy(UpstreamTrustPolicy::AlwaysTrust)
            .upstream(mock_always_trust)
            .build()
            .unwrap();
        let resp_always = resolver_always.query("bramp.net", Type::A).await.unwrap();
        assert_eq!(resp_always.meta.security_status, SecurityStatus::Secure);
        assert!(resolver_always.lookup("bramp.net").await.is_ok());

        // AD=0 (unsigned domain):
        // If require_secure=false -> Insecure, lookup succeeds
        let mock_unsigned = DnssecMockExchanger {
            secure: true,
            ad: false,
            rcode: Rcode::NoError,
            answers: vec![a_record.clone()],
            received_do: tracker.clone(),
        };
        let resolver_insecure_ok = Resolver::builder()
            .dnssec_mode(DnssecMode::TrustUpstream {
                require_secure: false,
            })
            .upstream(mock_unsigned)
            .build()
            .unwrap();
        let resp_unsigned = resolver_insecure_ok
            .query("bramp.net", Type::A)
            .await
            .unwrap();
        assert_eq!(resp_unsigned.meta.security_status, SecurityStatus::Insecure);
        assert!(resolver_insecure_ok.lookup("bramp.net").await.is_ok());

        // If require_secure=true -> query() and lookup() fail with InsecureResponse
        let mock_unsigned2 = DnssecMockExchanger {
            secure: true,
            ad: false,
            rcode: Rcode::NoError,
            answers: vec![a_record],
            received_do: tracker.clone(),
        };
        let resolver_strict = Resolver::builder()
            .dnssec_mode(DnssecMode::TrustUpstream {
                require_secure: true,
            })
            .upstream(mock_unsigned2)
            .build()
            .unwrap();
        assert!(matches!(
            resolver_strict.query("bramp.net", Type::A).await,
            Err(crate::Error::Dnssec(crate::errors::DnssecError::InsecureResponse))
        ));
        assert!(matches!(
            resolver_strict.lookup("bramp.net").await,
            Err(crate::Error::Dnssec(crate::errors::DnssecError::InsecureResponse))
        ));

        // ServFail -> evaluate_security_status classifies as Bogus
        let servfail_msg = Message {
            rcode: Rcode::ServFail,
            ..Default::default()
        };
        assert_eq!(
            evaluate_security_status(
                &servfail_msg,
                ChannelSecurity::Encrypted,
                UpstreamTrustPolicy::SecureTransportOnly
            ),
            SecurityStatus::Bogus
        );
        assert_eq!(
            evaluate_security_status(
                &servfail_msg,
                ChannelSecurity::Insecure,
                UpstreamTrustPolicy::AlwaysTrust
            ),
            SecurityStatus::Bogus
        );

        // When upstream returns ServFail, Resolver treats it as retryable and fails if exhausted
        let mock_bogus = DnssecMockExchanger {
            secure: true,
            ad: false,
            rcode: Rcode::ServFail,
            answers: vec![],
            received_do: tracker,
        };
        let resolver_bogus = Resolver::builder()
            .dnssec_mode(DnssecMode::TrustUpstream {
                require_secure: false,
            })
            .retries(0)
            .upstream(mock_bogus)
            .build()
            .unwrap();
        let query = query_with_id(1);
        assert!(resolver_bogus.exchange(&query).await.is_err());
    }

    #[tokio::test]
    async fn response_display_includes_message_and_metadata() {
        let tracker = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mock = DnssecMockExchanger {
            secure: true,
            ad: true,
            rcode: Rcode::NoError,
            answers: vec![Record::new(
                "bramp.net",
                Class::Internet,
                Duration::from_secs(60),
                Resource::A("127.0.0.1".parse().unwrap()),
            )],
            received_do: tracker,
        };

        let resolver = Resolver::builder()
            .dnssec_mode(DnssecMode::TrustUpstream {
                require_secure: false,
            })
            .upstream(mock)
            .build()
            .unwrap();

        let resp = resolver.query("bramp.net", Type::A).await.unwrap();
        let formatted = format!("{resp}");
        assert!(formatted.contains(";; ->>HEADER<<-"));
        assert!(formatted.contains("bramp.net."));
        assert!(formatted.contains(";; Query time:"));
        assert!(formatted.contains(";; UPSTREAM: dnssec-mock"));
        assert!(formatted.contains(";; WHEN:"));
        assert!(formatted.contains(";; SECURITY: Secure"));
        assert!(formatted.contains(";; CHANNEL: Encrypted"));
    }

    struct FlakyMockExchanger {
        call_count: Arc<std::sync::atomic::AtomicU32>,
    }

    #[async_trait::async_trait]
    impl AsyncExchanger for FlakyMockExchanger {
        async fn exchange(&self, query: &Message) -> Result<WireResponse, crate::Error> {
            let attempt = self
                .call_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut response = response_to(query);
            if attempt == 0 {
                response.rcode = Rcode::ServFail;
            } else {
                response.rcode = Rcode::NoError;
                response.answers.push(Record::new(
                    "bramp.net",
                    Class::Internet,
                    Duration::from_secs(60),
                    Resource::A("127.0.0.1".parse().unwrap()),
                ));
            }
            Ok(WireResponse::test(response, ChannelSecurity::Loopback))
        }

        fn endpoint(&self) -> Arc<str> {
            "flaky-mock".into()
        }

        fn channel_security(&self) -> ChannelSecurity {
            ChannelSecurity::Loopback
        }
    }

    #[tokio::test]
    async fn multiple_attempts_collect_wire_responses_in_meta() {
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let mock = FlakyMockExchanger {
            call_count: calls.clone(),
        };

        let resolver = Resolver::builder()
            .dnssec_mode(DnssecMode::Off)
            .retries(1)
            .upstream(mock)
            .build()
            .unwrap();

        let resp = resolver.query("bramp.net", Type::A).await.unwrap();
        assert_eq!(resp.meta.attempts, 2);
        assert_eq!(resp.meta.wire.len(), 2);
        assert_eq!(resp.meta.winning_wire().unwrap().channel_security, ChannelSecurity::Loopback);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);

        let formatted = format!("{resp}");
        assert!(formatted.contains(";; ATTEMPTS: 2"));
    }

    #[tokio::test]
    async fn failover_collects_wire_responses_across_upstreams() {
        let mock1 = DnssecMockExchanger {
            secure: true,
            ad: false,
            rcode: Rcode::ServFail,
            answers: vec![],
            received_do: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let mock2 = DnssecMockExchanger {
            secure: true,
            ad: true,
            rcode: Rcode::NoError,
            answers: vec![Record::new(
                "bramp.net",
                Class::Internet,
                Duration::from_secs(60),
                Resource::A("127.0.0.1".parse().unwrap()),
            )],
            received_do: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        let resolver = Resolver::builder()
            .dnssec_mode(DnssecMode::TrustUpstream {
                require_secure: false,
            })
            .retries(0)
            .upstream(mock1)
            .upstream(mock2)
            .build()
            .unwrap();

        let resp = resolver.query("bramp.net", Type::A).await.unwrap();
        assert_eq!(resp.meta.attempts, 2);
        assert_eq!(resp.meta.wire.len(), 2);
        assert_eq!(resp.meta.upstream.as_ref(), "dnssec-mock");
    }
}
