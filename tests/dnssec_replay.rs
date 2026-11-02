//! Replays captured upstream responses through [`ChainValidator`] offline.
//!
//! Fixtures in `tests/fixtures/dnssec` hold real DoH responses, so these
//! tests exercise deployed zone configurations (such as 1024-bit RSA keys)
//! with a fixed validation time and no network access.
#![cfg(feature = "dnssec")]

use rustdns::clients::{AsyncResolver, Response, ResponseMeta};
use rustdns::dnssec::{ChainValidator, Clock, DnssecCache, RsaKeySizePolicy, TrustStore};
use rustdns::types::{ChannelSecurity, SecuritySource, SecurityStatus, Type};
use rustdns::{DnssecError, Message, Name};
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, UNIX_EPOCH};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

/// A time inside the validity period of every captured RRSIG.
const PIZZA_WS_NOW: Duration = Duration::from_secs(1_793_570_000);

/// Answers queries from captured responses with a matching question.
struct Replay(Vec<Message>);

impl Replay {
    fn load(fixture: &str) -> Self {
        let messages = fixture
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                let hex = line.rsplit(' ').next().expect("hex column");
                Message::from_slice(&hex::decode(hex).expect("valid hex")).expect("valid DNS")
            })
            .collect();
        Self(messages)
    }

    fn response(&self, name: &str, rtype: Type) -> Message {
        let name: Name = name.parse().expect("valid name");
        self.0
            .iter()
            .find(|m| m.questions[0].name == name && m.questions[0].r#type == rtype)
            .cloned()
            .expect("captured response")
    }
}

#[async_trait::async_trait]
impl AsyncResolver<u64> for Replay {
    async fn exchange_with_deadline(
        &self,
        query: &Message,
        _deadline: u64,
    ) -> Result<Response, rustdns::Error> {
        let message = self
            .0
            .iter()
            .find(|m| m.questions == query.questions)
            .cloned()
            .ok_or(rustdns::Error::ResponseMismatch)?;
        Ok(Response {
            message,
            meta: ResponseMeta {
                upstream: "replay".into(),
                attempts: 1,
                elapsed: Duration::ZERO,
                when: UNIX_EPOCH,
                security_status: SecurityStatus::Indeterminate,
                security_source: rustdns::types::SecuritySource::AdFlag,
                dnssec_error: None,
                channel_security: ChannelSecurity::Encrypted,
                wire: Vec::new(),
            },
        })
    }
}

/// A clock whose instants are whole seconds, so deadlines never expire.
#[derive(Clone, Copy, Debug, Default)]
struct FixedClock;

impl Clock for FixedClock {
    type Instant = u64;

    fn now(&self) -> Option<u64> {
        Some(0)
    }

    fn checked_add(&self, instant: u64, duration: Duration) -> Option<u64> {
        instant.checked_add(duration.as_secs())
    }

    fn checked_duration_since(&self, later: u64, earlier: u64) -> Option<Duration> {
        later.checked_sub(earlier).map(Duration::from_secs)
    }
}

/// Polls a future that never waits, since [`Replay`] answers immediately.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
}

/// Validates the captured `xn--vi8h.ws. A` response, returning it with the
/// outcome recorded in its metadata.
fn validate_pizza_ws(policy: RsaKeySizePolicy) -> (Response, Result<(), rustdns::Error>) {
    let resolver = Replay::load(include_str!("replays/pizza-ws.txt"));
    let query = resolver.response("xn--vi8h.ws.", Type::A);
    let mut response = block_on(resolver.exchange_with_deadline(&query, 0)).expect("captured");
    let store = TrustStore::default();
    let cache = DnssecCache::with_clock(FixedClock);
    let mut validator =
        ChainValidator::new(&resolver, &store, &cache, 1_000).with_rsa_key_sizes(policy);
    let result =
        block_on(validator.validate_response_mut(&mut response, UNIX_EPOCH + PIZZA_WS_NOW));
    (response, result)
}

#[test]
fn unsigned_delegation_from_1024_bit_rsa_zone_is_insecure() {
    let (response, result) = validate_pizza_ws(RsaKeySizePolicy::default());
    assert_eq!(result.map_err(|e| e.to_string()), Ok(()));
    assert_eq!(response.meta.security_status, SecurityStatus::Insecure);
    assert_eq!(
        response.meta.security_source,
        SecuritySource::LocalValidation
    );
    assert_eq!(response.meta.dnssec_error, None);
}

#[test]
fn rsa_key_size_policy_rejects_1024_bit_zone_signing_key() {
    let policy = RsaKeySizePolicy::new(2048, 4096).expect("valid policy");
    let (response, result) = validate_pizza_ws(policy);
    let error = result.expect_err("1024-bit key rejected");
    assert_eq!(response.meta.security_status, SecurityStatus::Bogus);
    assert_eq!(
        response.meta.dnssec_error.as_ref().map(ToString::to_string),
        Some(error.to_string())
    );
    let rustdns::Error::Dnssec(DnssecError::MissingInsecureProof {
        name,
        signed_zone,
        rejected_proof: Some(reason),
    }) = &error
    else {
        panic!("expected MissingInsecureProof with a rejected proof, got {error:?}");
    };
    let ws: Name = "ws.".parse().unwrap();
    assert_eq!(*name, "xn--vi8h.ws.".parse::<Name>().unwrap());
    assert_eq!(signed_zone.as_ref(), Some(&ws));
    assert!(
        matches!(
            reason.as_ref(),
            DnssecError::RsaKeySize { signer, rtype: Type::NSEC3, bits: 1024, allowed, .. }
                if *signer == ws && *allowed == policy
        ),
        "{reason}"
    );
}
