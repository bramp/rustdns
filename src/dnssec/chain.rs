//! Iterative chain-of-trust validation and DNSKEY/DS resolution.
//!
//! Conforms to [RFC 4035 §5]:
//! - For a target RRset and its covering RRSIG from zone `Z`:
//!   1. Verify target RRset RRSIG using the matching ZSK in zone `Z`'s DNSKEY RRset.
//!   2. Verify zone `Z`'s DNSKEY RRset RRSIG using the matching KSK in zone `Z`'s DNSKEY RRset.
//!   3. If `Z` is a trust anchor (e.g. root `.`), verify the KSK matches an anchor in [`TrustStore`].
//!   4. Otherwise, query the parent zone for `Z`'s DS record.
//!   5. Verify that `Z`'s KSK matches the parent's DS record (key tag, algorithm, digest).
//!   6. Recurse upward until a trust anchor is reached.
//!
//! [RFC 4035 §5]: https://datatracker.ietf.org/doc/html/rfc4035#section-5

use crate::clients::AsyncResolver;
use crate::dnssec::anchor::TrustStore;
use crate::dnssec::rrset_validator::{ValidationReport, validate_rrset};
use crate::errors::DnssecError;
use crate::names::Name;
use crate::resource::{DNSKEY, DS, RRSIG};
use crate::types::{Class, Message, Record, Resource, SecurityStatus, Type};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

const MAX_CACHE_ENTRIES: usize = 1024;
const MAX_VALIDATION_WORK: usize = 1024;

#[derive(Clone, Debug)]
struct CachedRecords {
    records: Vec<Record>,
    inserted: Instant,
    lifetime: Duration,
}

type RecordCache = Arc<Mutex<HashMap<Name, CachedRecords>>>;

/// Bounded, TTL-aware cache of DNSKEY and DS query results.
///
/// Cached records are not inherently trusted. [`ChainValidator`] revalidates
/// signatures, validity periods, and delegation links on every use.
#[derive(Clone, Debug, Default)]
pub struct DnssecCache {
    dnskeys: RecordCache,
    ds_records: RecordCache,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnssec::TrustAnchor;
    use crate::types::{Algorithm, DigestType};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::time::{Duration, UNIX_EPOCH};

    struct NoNetwork;

    struct DependencyResponse(Message);

    struct LocalZoneExchanger {
        responses: HashMap<(Name, Type), Message>,
    }

    #[async_trait::async_trait]
    impl crate::clients::AsyncExchanger for LocalZoneExchanger {
        async fn exchange(
            &self,
            query: &Message,
        ) -> Result<crate::clients::WireResponse, crate::Error> {
            assert!(query.cd);
            assert!(query.extension.as_ref().unwrap().dnssec_ok);
            let question = &query.questions[0];
            let mut response = self
                .responses
                .get(&(question.name.clone(), question.r#type))
                .cloned()
                .unwrap_or_default();
            response.qr = crate::QR::Response;
            response.id = query.id;
            response.questions = query.questions.clone();
            response.ad = true; // Forged AD must not affect local validation.
            Ok(crate::clients::WireResponse::test(
                response,
                crate::ChannelSecurity::Insecure,
            ))
        }

        fn endpoint(&self) -> Arc<str> {
            Arc::from("local-signed-zone")
        }
    }

    #[async_trait::async_trait]
    impl AsyncResolver for DependencyResponse {
        async fn exchange_with_deadline(
            &self,
            query: &Message,
            _deadline: Instant,
        ) -> Result<crate::clients::Response, crate::Error> {
            assert!(
                query.cd,
                "local validators must request unchecked dependency data"
            );
            assert!(query.extension.as_ref().unwrap().dnssec_ok);
            let mut message = self.0.clone();
            message.questions = query.questions.clone();
            Ok(crate::clients::Response {
                message,
                meta: crate::clients::ResponseMeta {
                    upstream: Arc::from("signed-chain-fixture"),
                    attempts: 1,
                    elapsed: Duration::ZERO,
                    when: UNIX_EPOCH,
                    security_status: SecurityStatus::Indeterminate,
                    channel_security: crate::ChannelSecurity::Insecure,
                    wire: Vec::new(),
                },
            })
        }
    }

    #[async_trait::async_trait]
    impl AsyncResolver for NoNetwork {
        async fn exchange_with_deadline(
            &self,
            _query: &Message,
            _deadline: Instant,
        ) -> Result<crate::clients::Response, crate::Error> {
            Err(crate::Error::InvalidArgument(
                "unexpected network query in signed-chain fixture".into(),
            ))
        }
    }

    struct SignedChain {
        cache: DnssecCache,
        store: TrustStore,
        child: Name,
        parent: Name,
        key: DNSKEY,
        pair: Ed25519KeyPair,
        answer: Vec<Record>,
        signature: RRSIG,
        now: SystemTime,
    }

    fn record(owner: &Name, resource: Resource) -> Record {
        Record::new(
            owner.clone(),
            Class::Internet,
            Duration::from_secs(3600),
            resource,
        )
    }

    fn key(seed: u8) -> (Ed25519KeyPair, DNSKEY) {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        let key = DNSKEY {
            flags: 257,
            protocol: 3,
            algorithm: Algorithm::ED25519,
            public_key: pair.public_key().as_ref().to_vec(),
        };
        (pair, key)
    }

    fn sign(
        owner: &Name,
        signer: &Name,
        records: &[Record],
        key: &DNSKEY,
        pair: &Ed25519KeyPair,
    ) -> RRSIG {
        let mut signature = RRSIG {
            type_covered: records[0].r#type(),
            algorithm: key.algorithm,
            labels: owner.count_labels(),
            original_ttl: Duration::from_secs(3600),
            inception: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            expiration: UNIX_EPOCH + Duration::from_secs(1_700_086_400),
            key_tag: key.key_tag(),
            signer_name: signer.clone(),
            signature: Vec::new(),
        };
        let signed =
            crate::dnssec::canonical::signed_data_to_vec(owner, &signature, records).unwrap();
        signature.signature = pair.sign(&signed).as_ref().to_vec();
        signature
    }

    impl SignedChain {
        fn new() -> Self {
            // The parent signer is deliberately not the child's immediate DNS parent.
            let parent = Name::new("example.").unwrap();
            let child = Name::new("child.branch.example.").unwrap();
            let (parent_pair, parent_key) = key(1);
            let (pair, key) = key(2);
            let cache = DnssecCache::default();
            for (zone, key, pair) in [(&parent, &parent_key, &parent_pair), (&child, &key, &pair)] {
                let mut records = vec![record(zone, Resource::DNSKEY(key.clone()))];
                let signature = sign(zone, zone, &records, key, pair);
                records.push(record(zone, Resource::RRSIG(signature)));
                cache.insert_dnskeys(zone, records);
            }
            let ds = DS::from_dnskey(&child, &key, DigestType::Sha256).unwrap();
            let mut records = vec![record(&child, Resource::DS(ds))];
            let signature = sign(&child, &parent, &records, &parent_key, &parent_pair);
            records.push(record(&child, Resource::RRSIG(signature)));
            cache.insert_ds(&child, records);
            let anchor = DS::from_dnskey(&parent, &parent_key, DigestType::Sha256).unwrap();
            let mut store = TrustStore::empty();
            store.add_anchor(TrustAnchor {
                zone: parent.clone(),
                key_tag: anchor.key_tag,
                algorithm: anchor.algorithm,
                digest_type: anchor.digest_type,
                digest: anchor.digest,
            });
            let owner = Name::new("www.child.branch.example.").unwrap();
            let answer = vec![record(&owner, Resource::A("192.0.2.1".parse().unwrap()))];
            let signature = sign(&owner, &child, &answer, &key, &pair);
            Self {
                cache,
                store,
                child,
                parent,
                key,
                pair,
                answer,
                signature,
                now: UNIX_EPOCH + Duration::from_secs(1_700_043_200),
            }
        }

        async fn validate(&self) -> Result<ValidationReport, crate::Error> {
            let validator = ChainValidator::new(
                &NoNetwork,
                &self.store,
                &self.cache,
                Instant::now() + Duration::from_secs(10),
            );
            validator
                .validate_rrset_chain(
                    &self.answer[0].name,
                    &self.answer,
                    &self.signature,
                    self.now,
                )
                .await
        }

        fn unsigned_delegation(&self) -> Message {
            let (pair, key) = key(1);
            let mut records = vec![record(
                &self.child,
                Resource::NSEC(crate::NSEC {
                    next_domain: Name::new("z.example.").unwrap(),
                    types: vec![Type::NS, Type::NSEC, Type::RRSIG],
                }),
            )];
            let signature = sign(&self.child, &self.parent, &records, &key, &pair);
            records.push(record(&self.child, Resource::RRSIG(signature)));
            Message {
                qr: crate::QR::Response,
                authoritys: records,
                ..Message::default()
            }
        }

        fn unsigned_answer(&self) -> Message {
            let mut message = Message {
                qr: crate::QR::Response,
                answers: self.answer.clone(),
                ..Message::default()
            };
            message
                .try_add_question(&self.answer[0].name, Type::A, Class::Internet)
                .unwrap();
            message
        }

        fn negative_answer(&self, name: &str, rtype: Type, nxdomain: bool) -> Message {
            let mut message = Message {
                qr: crate::QR::Response,
                rcode: if nxdomain {
                    crate::Rcode::NXDomain
                } else {
                    crate::Rcode::NoError
                },
                ..Message::default()
            };
            message
                .try_add_question(name, rtype, Class::Internet)
                .unwrap();
            message
        }

        fn add_nsec(&self, message: &mut Message, owner: &str, next: &str, types: Vec<Type>) {
            let owner = Name::new(owner).unwrap();
            let records = vec![record(
                &owner,
                Resource::NSEC(crate::NSEC {
                    next_domain: Name::new(next).unwrap(),
                    types,
                }),
            )];
            let (pair, key) = key(1);
            let signature = sign(&owner, &self.parent, &records, &key, &pair);
            message.authoritys.extend(records);
            message
                .authoritys
                .push(record(&owner, Resource::RRSIG(signature)));
        }

        fn add_nsec3(&self, message: &mut Message, name: &Name, types: Vec<Type>, flags: u8) {
            let hash = super::super::denial::nsec3_hash(name, &[], 0);
            let owner = Name::new(&format!(
                "{}.{}",
                crate::util::base32hex_encode(&hash),
                self.parent
            ))
            .unwrap();
            let records = vec![record(
                &owner,
                Resource::NSEC3(crate::NSEC3 {
                    hash_algorithm: crate::Nsec3HashAlgorithm::Sha1,
                    flags,
                    iterations: 0,
                    salt: Vec::new(),
                    next_hashed_owner_name: hash,
                    types,
                }),
            )];
            self.sign_parent_proof(message, records);
        }

        fn sign_parent_proof(&self, message: &mut Message, records: Vec<Record>) {
            let (pair, key) = key(1);
            let signature = sign(&records[0].name, &self.parent, &records, &key, &pair);
            let owner = records[0].name.clone();
            message.authoritys.extend(records);
            message
                .authoritys
                .push(record(&owner, Resource::RRSIG(signature)));
        }

        fn refresh_signatures(&self, message: &mut Message) {
            for section in [&mut message.answers, &mut message.authoritys] {
                let originals = section.clone();
                for record in section {
                    let Resource::RRSIG(signature) = &mut record.resource else {
                        continue;
                    };
                    let records: Vec<_> = originals
                        .iter()
                        .filter(|candidate| {
                            candidate.name == record.name
                                && candidate.r#type() == signature.type_covered
                        })
                        .cloned()
                        .collect();
                    signature.inception = SystemTime::now() - Duration::from_secs(60);
                    signature.expiration = SystemTime::now() + Duration::from_secs(3600);
                    let data = crate::dnssec::canonical::signed_data_to_vec(
                        &record.name,
                        signature,
                        &records,
                    )
                    .unwrap();
                    let (parent_pair, _) = key(1);
                    let pair = if signature.signer_name == self.parent {
                        &parent_pair
                    } else {
                        &self.pair
                    };
                    signature.signature = pair.sign(&data).as_ref().to_vec();
                }
            }
        }
    }

    #[tokio::test]
    async fn unsigned_answers_require_authenticated_delegation() {
        let chain = SignedChain::new();
        for mutation in [
            "valid",
            "missing",
            "tampered",
            "has-ds",
            "not-delegation",
            "child-signed",
            "unrelated",
            "outside-zone",
        ] {
            let mut proof = chain.unsigned_delegation();
            match mutation {
                "missing" => proof.authoritys.clear(),
                "tampered" => {
                    if let Resource::RRSIG(sig) = &mut proof.authoritys[1].resource {
                        sig.signature[0] ^= 1;
                    }
                }
                "has-ds" | "not-delegation" | "unrelated" | "outside-zone" => {
                    if let Resource::NSEC(nsec) = &mut proof.authoritys[0].resource {
                        if mutation == "has-ds" {
                            nsec.types.push(Type::DS);
                        }
                        if mutation == "not-delegation" {
                            nsec.types.retain(|rtype| *rtype != Type::NS);
                        }
                        if mutation == "outside-zone" {
                            nsec.next_domain = Name::new("elsewhere.").unwrap();
                        }
                    }
                    if mutation == "unrelated" {
                        proof.authoritys[0].name = Name::new("other.example.").unwrap();
                    }
                    let (pair, key) = key(1);
                    let owner = proof.authoritys[0].name.clone();
                    let signature =
                        sign(&owner, &chain.parent, &proof.authoritys[..1], &key, &pair);
                    proof.authoritys[1] = record(&owner, Resource::RRSIG(signature));
                }
                "child-signed" => {
                    let signature = sign(
                        &chain.child,
                        &chain.child,
                        &proof.authoritys[..1],
                        &chain.key,
                        &chain.pair,
                    );
                    proof.authoritys[1] = record(&chain.child, Resource::RRSIG(signature));
                }
                _ => {}
            }
            let response = DependencyResponse(proof);
            let cache = chain.cache.clone();
            cache.ds_records.lock().unwrap().remove(&chain.child);
            let validator = ChainValidator::new(
                &response,
                &chain.store,
                &cache,
                Instant::now() + Duration::from_secs(10),
            );
            let result = validator
                .validate_message_answers(&chain.unsigned_answer(), chain.now)
                .await;
            if mutation == "valid" {
                assert_eq!(result.unwrap(), SecurityStatus::Insecure);
            } else {
                assert!(
                    result.is_err(),
                    "{mutation}: unproven insecurity must be rejected"
                );
            }
        }
    }

    #[tokio::test]
    async fn unsigned_answer_cannot_hide_bogus_signed_rrset() {
        let chain = SignedChain::new();
        let mut message = chain.unsigned_answer();
        let mut signature = chain.signature.clone();
        signature.signature[0] ^= 1;
        message
            .answers
            .push(record(&message.answers[0].name, Resource::RRSIG(signature)));
        message.answers.push(record(
            &chain.child,
            Resource::AAAA("2001:db8::1".parse().unwrap()),
        ));
        let response = DependencyResponse(chain.unsigned_delegation());
        let validator = ChainValidator::new(
            &response,
            &chain.store,
            &chain.cache,
            Instant::now() + Duration::from_secs(10),
        );
        assert!(
            validator
                .validate_message_answers(&message, chain.now)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn nsec_negative_answers_require_signed_complete_proofs() {
        let chain = SignedChain::new();
        for nxdomain in [false, true] {
            for mutation in [
                "valid",
                "missing",
                "tampered",
                "wrong-zone",
                "cname",
                "qtype",
            ] {
                let mut message = chain.negative_answer("missing.example.", Type::AAAA, nxdomain);
                if nxdomain {
                    chain.add_nsec(
                        &mut message,
                        "example.",
                        "a.example.",
                        vec![Type::SOA, Type::NS],
                    );
                    chain.add_nsec(&mut message, "a.example.", "z.example.", vec![Type::A]);
                } else {
                    let types = match mutation {
                        "cname" => vec![Type::CNAME],
                        "qtype" => vec![Type::AAAA],
                        _ => vec![Type::A],
                    };
                    chain.add_nsec(&mut message, "missing.example.", "z.example.", types);
                }
                if mutation == "missing" {
                    message.authoritys.clear();
                }
                if mutation == "tampered" {
                    for record in &mut message.authoritys {
                        if let Resource::RRSIG(sig) = &mut record.resource {
                            sig.signature[0] ^= 1;
                        }
                    }
                }
                if mutation == "wrong-zone" {
                    message.questions[0].name = Name::new("missing.other.").unwrap();
                }
                let validator = ChainValidator::new(
                    &NoNetwork,
                    &chain.store,
                    &chain.cache,
                    Instant::now() + Duration::from_secs(10),
                );
                let result = validator
                    .validate_message_answers(&message, chain.now)
                    .await;
                if mutation == "valid" || (nxdomain && matches!(mutation, "cname" | "qtype")) {
                    assert_eq!(result.unwrap(), SecurityStatus::Secure);
                } else {
                    assert!(result.is_err(), "nxdomain={nxdomain}, {mutation}");
                }
            }
        }
    }

    #[tokio::test]
    async fn nsec_nxdomain_requires_wildcard_denial_at_actual_closest_encloser() {
        let chain = SignedChain::new();
        let mut message = chain.negative_answer("missing.branch.example.", Type::A, true);
        chain.add_nsec(
            &mut message,
            "example.",
            "a.example.",
            vec![Type::SOA, Type::NS],
        );
        chain.add_nsec(
            &mut message,
            "a.branch.example.",
            "z.branch.example.",
            vec![Type::A],
        );
        let validator = ChainValidator::new(
            &NoNetwork,
            &chain.store,
            &chain.cache,
            Instant::now() + Duration::from_secs(10),
        );
        assert!(
            validator
                .validate_message_answers(&message, chain.now)
                .await
                .is_err()
        );
        chain.add_nsec(
            &mut message,
            "branch.example.",
            "a.branch.example.",
            vec![Type::TXT],
        );
        let validator = ChainValidator::new(
            &NoNetwork,
            &chain.store,
            &chain.cache,
            Instant::now() + Duration::from_secs(10),
        );
        assert_eq!(
            validator
                .validate_message_answers(&message, chain.now)
                .await
                .unwrap(),
            SecurityStatus::Secure
        );
    }

    #[tokio::test]
    async fn nsec_nodata_supports_empty_nonterminals_and_wildcards() {
        let chain = SignedChain::new();
        for wildcard in [false, true] {
            let mut message = chain.negative_answer(
                if wildcard {
                    "missing.example."
                } else {
                    "branch.example."
                },
                Type::AAAA,
                false,
            );
            if wildcard {
                chain.add_nsec(&mut message, "*.example.", "a.example.", vec![Type::A]);
                chain.add_nsec(&mut message, "a.example.", "z.example.", vec![Type::A]);
            } else {
                chain.add_nsec(
                    &mut message,
                    "a.example.",
                    "x.branch.example.",
                    vec![Type::A],
                );
            }
            let validator = ChainValidator::new(
                &NoNetwork,
                &chain.store,
                &chain.cache,
                Instant::now() + Duration::from_secs(10),
            );
            assert_eq!(
                validator
                    .validate_message_answers(&message, chain.now)
                    .await
                    .unwrap(),
                SecurityStatus::Secure
            );
        }
    }

    #[tokio::test]
    async fn nsec3_negative_answers_validate_hashes_flags_parameters_and_signatures() {
        let chain = SignedChain::new();
        for nxdomain in [false, true] {
            for mutation in [
                "valid",
                "tampered",
                "long-hash",
                "algorithm",
                "flags",
                "iterations",
                "optout",
            ] {
                let mut message = chain.negative_answer("missing.example.", Type::AAAA, nxdomain);
                let name = if nxdomain {
                    &chain.parent
                } else {
                    &message.questions[0].name.clone()
                };
                chain.add_nsec3(
                    &mut message,
                    name,
                    if nxdomain {
                        vec![Type::SOA, Type::NS]
                    } else {
                        vec![Type::A]
                    },
                    0,
                );
                let mut proof = message.authoritys.remove(0);
                message.authoritys.clear();
                if let Resource::NSEC3(nsec3) = &mut proof.resource {
                    match mutation {
                        "long-hash" => nsec3.next_hashed_owner_name.push(0),
                        "algorithm" => nsec3.hash_algorithm = crate::Nsec3HashAlgorithm::Unknown(2),
                        "flags" => nsec3.flags = 2,
                        "iterations" => nsec3.iterations = u16::MAX,
                        "optout" => nsec3.flags = 1,
                        _ => {}
                    }
                }
                chain.sign_parent_proof(&mut message, vec![proof]);
                if mutation == "tampered" {
                    if let Resource::RRSIG(sig) = &mut message.authoritys[1].resource {
                        sig.signature[0] ^= 1;
                    }
                }
                let validator = ChainValidator::new(
                    &NoNetwork,
                    &chain.store,
                    &chain.cache,
                    Instant::now() + Duration::from_secs(10),
                );
                let result = validator
                    .validate_message_answers(&message, chain.now)
                    .await;
                if mutation == "valid" || (!nxdomain && mutation == "optout") {
                    assert_eq!(result.unwrap(), SecurityStatus::Secure);
                } else {
                    assert!(result.is_err(), "nxdomain={nxdomain}, {mutation}");
                }
            }
        }
    }

    #[tokio::test]
    async fn nsec3_unsigned_delegation_supports_exact_match_and_optout() {
        let chain = SignedChain::new();
        for optout in [false, true] {
            let mut proof = Message {
                qr: crate::QR::Response,
                ..Message::default()
            };
            chain.add_nsec3(
                &mut proof,
                if optout { &chain.parent } else { &chain.child },
                if optout {
                    vec![Type::SOA, Type::NS]
                } else {
                    vec![Type::NS]
                },
                u8::from(optout),
            );
            let response = DependencyResponse(proof);
            let validator = ChainValidator::new(
                &response,
                &chain.store,
                &chain.cache,
                Instant::now() + Duration::from_secs(10),
            );
            assert_eq!(
                validator
                    .validate_message_answers(&chain.unsigned_answer(), chain.now)
                    .await
                    .unwrap(),
                SecurityStatus::Insecure
            );
        }
    }

    #[tokio::test]
    async fn nsec3_proofs_reject_mixed_parameters_and_missing_closest_encloser() {
        let chain = SignedChain::new();
        for mode in [
            "salt",
            "iterations",
            "missing-closest",
            "bad-owner",
            "qtype",
            "cname",
            "wildcard-exists",
        ] {
            let mut message = chain.negative_answer("missing.example.", Type::AAAA, true);
            chain.add_nsec3(&mut message, &chain.parent, vec![Type::SOA, Type::NS], 0);
            if mode == "wildcard-exists" {
                chain.add_nsec3(
                    &mut message,
                    &Name::new("*.example.").unwrap(),
                    vec![Type::A],
                    0,
                );
            } else if matches!(mode, "salt" | "iterations") {
                let name = Name::new("other.example.").unwrap();
                chain.add_nsec3(&mut message, &name, vec![Type::A], 0);
                let mut record = message.authoritys.remove(2);
                message.authoritys.pop();
                if let Resource::NSEC3(nsec3) = &mut record.resource {
                    if mode == "salt" {
                        nsec3.salt.push(1);
                    } else {
                        nsec3.iterations = 1;
                    }
                }
                chain.sign_parent_proof(&mut message, vec![record]);
            } else if mode == "qtype" || mode == "cname" {
                message = chain.negative_answer("missing.example.", Type::AAAA, false);
                chain.add_nsec3(
                    &mut message,
                    &Name::new("missing.example.").unwrap(),
                    vec![if mode == "qtype" {
                        Type::AAAA
                    } else {
                        Type::CNAME
                    }],
                    0,
                );
            } else {
                let mut record = message.authoritys.remove(0);
                message.authoritys.clear();
                record.name = Name::new(if mode == "bad-owner" {
                    "bad.example."
                } else {
                    "00000000000000000000000000000000.example."
                })
                .unwrap();
                chain.sign_parent_proof(&mut message, vec![record]);
            }
            let validator = ChainValidator::new(
                &NoNetwork,
                &chain.store,
                &chain.cache,
                Instant::now() + Duration::from_secs(10),
            );
            assert!(
                validator
                    .validate_message_answers(&message, chain.now)
                    .await
                    .is_err(),
                "{mode}"
            );
        }
    }

    #[tokio::test]
    async fn denial_validation_enforces_work_limits() {
        let chain = SignedChain::new();
        let validator = ChainValidator::new(
            &NoNetwork,
            &chain.store,
            &chain.cache,
            Instant::now() + Duration::from_secs(10),
        );
        validator.work.store(1024, Ordering::Relaxed);
        let error = validator
            .validate_message_answers(&chain.unsigned_answer(), chain.now)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("work limit"));
    }

    #[tokio::test]
    async fn signed_answers_must_match_question_or_authenticated_alias_target() {
        let chain = SignedChain::new();
        for mode in [
            "valid",
            "unrelated",
            "alias-valid",
            "alias-missing",
            "alias-negative",
        ] {
            let mut message = chain.unsigned_answer();
            message.answers.push(record(
                &chain.answer[0].name,
                Resource::RRSIG(chain.signature.clone()),
            ));
            if mode == "unrelated" {
                message.questions[0].name = Name::new("other.example.").unwrap();
            }
            if mode.starts_with("alias") {
                let alias = Name::new("alias.child.branch.example.").unwrap();
                let records = vec![record(
                    &alias,
                    Resource::CNAME(chain.answer[0].name.clone()),
                )];
                let signature = sign(&alias, &chain.child, &records, &chain.key, &chain.pair);
                if mode != "alias-valid" {
                    message.answers.clear();
                }
                message.answers.extend(records);
                message
                    .answers
                    .push(record(&alias, Resource::RRSIG(signature)));
                message.questions[0].name = alias;
                if mode == "alias-negative" {
                    chain.add_nsec(
                        &mut message,
                        "www.child.branch.example.",
                        "z.example.",
                        vec![Type::AAAA],
                    );
                }
            }
            let validator = ChainValidator::new(
                &NoNetwork,
                &chain.store,
                &chain.cache,
                Instant::now() + Duration::from_secs(10),
            );
            let result = validator
                .validate_message_answers(&message, chain.now)
                .await;
            if matches!(mode, "valid" | "alias-valid" | "alias-negative") {
                assert_eq!(result.unwrap(), SecurityStatus::Secure);
            } else {
                assert!(result.is_err(), "{mode}");
            }
        }
    }

    #[tokio::test]
    async fn wildcard_answers_require_signed_next_closer_denial() {
        let chain = SignedChain::new();
        for nsec3 in [false, true] {
            for include_proof in [false, true] {
                let owner = Name::new("missing.example.").unwrap();
                let mut records = vec![record(&owner, Resource::A("192.0.2.3".parse().unwrap()))];
                let (pair, key) = key(1);
                let mut signature = sign(&owner, &chain.parent, &records, &key, &pair);
                signature.labels = 1;
                let signed =
                    crate::dnssec::canonical::signed_data_to_vec(&owner, &signature, &records)
                        .unwrap();
                signature.signature = pair.sign(&signed).as_ref().to_vec();
                records.push(record(&owner, Resource::RRSIG(signature)));
                let mut message = chain.negative_answer("missing.example.", Type::A, false);
                message.answers = records;
                if include_proof {
                    if nsec3 {
                        chain.add_nsec3(&mut message, &chain.parent, vec![Type::SOA, Type::NS], 0);
                    } else {
                        chain.add_nsec(&mut message, "a.example.", "z.example.", vec![Type::A]);
                    }
                }

                let validator = ChainValidator::new(
                    &NoNetwork,
                    &chain.store,
                    &chain.cache,
                    Instant::now() + Duration::from_secs(10),
                );
                let result = validator
                    .validate_message_answers(&message, chain.now)
                    .await;
                if include_proof {
                    assert_eq!(result.unwrap(), SecurityStatus::Secure);
                } else {
                    assert!(result.is_err(), "wildcard without proof, nsec3={nsec3}");
                }
            }
        }
    }

    #[tokio::test]
    async fn resolver_query_validates_local_denial_without_trusting_forged_ad() {
        let chain = SignedChain::new();
        for mode in [
            "positive",
            "nsec",
            "nsec3",
            "nsec-nx",
            "nsec3-nx",
            "unsigned",
            "unsigned-negative",
            "alias",
            "wildcard",
            "tampered",
            "stripped",
        ] {
            let name = Name::new("missing.example.").unwrap();
            let mut response = chain.negative_answer(name.as_ascii(), Type::AAAA, false);
            match mode {
                "positive" => {
                    response = chain.unsigned_answer();
                    response.answers.push(record(
                        &chain.answer[0].name,
                        Resource::RRSIG(chain.signature.clone()),
                    ));
                }
                "unsigned" => response = chain.unsigned_answer(),
                "unsigned-negative" => {
                    response = chain.negative_answer(chain.child.as_ascii(), Type::AAAA, false)
                }
                "nsec-nx" => {
                    response.rcode = crate::Rcode::NXDomain;
                    chain.add_nsec(
                        &mut response,
                        "example.",
                        "a.example.",
                        vec![Type::SOA, Type::NS],
                    );
                    chain.add_nsec(&mut response, "a.example.", "z.example.", vec![Type::A]);
                }
                "nsec3-nx" => {
                    response.rcode = crate::Rcode::NXDomain;
                    chain.add_nsec3(&mut response, &chain.parent, vec![Type::SOA, Type::NS], 0);
                }
                "alias" => {
                    response = chain.unsigned_answer();
                    response.answers.push(record(
                        &chain.answer[0].name,
                        Resource::RRSIG(chain.signature.clone()),
                    ));
                    let owner = Name::new("alias.child.branch.example.").unwrap();
                    let records = vec![record(
                        &owner,
                        Resource::CNAME(chain.answer[0].name.clone()),
                    )];
                    let sig = sign(&owner, &chain.child, &records, &chain.key, &chain.pair);
                    response.answers.extend(records);
                    response.answers.push(record(&owner, Resource::RRSIG(sig)));
                    response.questions[0].name = owner;
                }
                "wildcard" => {
                    response.questions[0].r#type = Type::A;
                    let records = vec![record(&name, Resource::A("192.0.2.3".parse().unwrap()))];
                    let (pair, key) = key(1);
                    let mut sig = sign(&name, &chain.parent, &records, &key, &pair);
                    sig.labels = 1;
                    response.answers.extend(records);
                    response.answers.push(record(&name, Resource::RRSIG(sig)));
                    chain.add_nsec(&mut response, "a.example.", "z.example.", vec![Type::A]);
                }
                "nsec3" => chain.add_nsec3(&mut response, &name, vec![Type::A], 0),
                "nsec" | "tampered" => {
                    chain.add_nsec(&mut response, name.as_ascii(), "z.example.", vec![Type::A])
                }
                _ => {}
            }
            chain.refresh_signatures(&mut response);
            if mode == "tampered" {
                if let Resource::RRSIG(sig) = &mut response.authoritys[1].resource {
                    sig.signature[0] ^= 1;
                }
            }
            let question = response.questions[0].clone();
            let mut responses = HashMap::new();
            responses.insert((question.name.clone(), question.r#type), response);
            for zone in [&chain.parent, &chain.child] {
                let mut response = Message {
                    answers: chain.cache.get_dnskeys(zone).unwrap(),
                    ..Message::default()
                };
                chain.refresh_signatures(&mut response);
                responses.insert((zone.clone(), Type::DNSKEY), response);
            }
            if mode.starts_with("unsigned") {
                let mut proof = chain.unsigned_delegation();
                chain.refresh_signatures(&mut proof);
                responses.insert((chain.child.clone(), Type::DS), proof);
            } else {
                let mut ds = Message {
                    answers: chain.cache.get_ds(&chain.child).unwrap(),
                    ..Message::default()
                };
                chain.refresh_signatures(&mut ds);
                responses.insert((chain.child.clone(), Type::DS), ds);
            }
            let resolver = crate::clients::Resolver::builder()
                .dnssec_mode(crate::DnssecMode::ValidateLocal)
                .trust_store(chain.store.clone())
                .retries(0)
                .upstream(LocalZoneExchanger { responses })
                .build()
                .unwrap();
            let result = resolver.query(&question.name, question.r#type).await;
            if matches!(mode, "tampered" | "stripped") {
                assert!(result.is_err(), "{mode}");
            } else {
                assert_eq!(
                    result.unwrap().meta.security_status,
                    if mode.starts_with("unsigned") {
                        SecurityStatus::Insecure
                    } else {
                        SecurityStatus::Secure
                    },
                    "{mode}"
                );
            }
        }
    }

    #[tokio::test]
    async fn unsigned_proofs_cannot_override_a_more_specific_local_anchor() {
        let mut chain = SignedChain::new();
        let ds = DS::from_dnskey(&chain.child, &chain.key, DigestType::Sha256).unwrap();
        chain.store.add_anchor(TrustAnchor {
            zone: chain.child.clone(),
            key_tag: ds.key_tag,
            algorithm: ds.algorithm,
            digest_type: ds.digest_type,
            digest: ds.digest,
        });
        let mut proof = Message {
            qr: crate::QR::Response,
            ..Message::default()
        };
        chain.add_nsec3(&mut proof, &chain.parent, vec![Type::NS, Type::SOA], 1);
        let response = DependencyResponse(proof);
        let validator = ChainValidator::new(
            &response,
            &chain.store,
            &chain.cache,
            Instant::now() + Duration::from_secs(10),
        );
        assert!(
            validator
                .validate_message_answers(&chain.unsigned_answer(), chain.now)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn nsec3_iteration_work_limit_has_an_explicit_boundary() {
        let chain = SignedChain::new();
        let name = Name::new("missing.example.").unwrap();
        for iterations in [150, 151] {
            let mut message = chain.negative_answer(name.as_ascii(), Type::AAAA, false);
            let hash = super::super::denial::nsec3_hash(&name, &[], iterations);
            let owner = Name::new(&format!(
                "{}.example.",
                crate::util::base32hex_encode(&hash)
            ))
            .unwrap();
            chain.sign_parent_proof(
                &mut message,
                vec![record(
                    &owner,
                    Resource::NSEC3(crate::NSEC3 {
                        hash_algorithm: crate::Nsec3HashAlgorithm::Sha1,
                        flags: 0,
                        iterations,
                        salt: Vec::new(),
                        next_hashed_owner_name: hash,
                        types: vec![Type::A],
                    }),
                )],
            );
            let validator = ChainValidator::new(
                &NoNetwork,
                &chain.store,
                &chain.cache,
                Instant::now() + Duration::from_secs(10),
            );
            let result = validator
                .validate_message_answers(&message, chain.now)
                .await;
            if iterations == 150 {
                assert_eq!(result.unwrap(), SecurityStatus::Secure);
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[tokio::test]
    async fn nsec3_wildcard_nodata_requires_usable_closest_encloser_proof() {
        let chain = SignedChain::new();
        for mode in ["valid", "missing-closest", "qtype", "cname", "delegation"] {
            let mut message = chain.negative_answer("missing.example.", Type::AAAA, false);
            if mode != "missing-closest" {
                chain.add_nsec3(&mut message, &chain.parent, vec![Type::NS, Type::SOA], 0);
            }
            let types = vec![match mode {
                "qtype" => Type::AAAA,
                "cname" => Type::CNAME,
                "delegation" => Type::NS,
                _ => Type::A,
            }];
            chain.add_nsec3(&mut message, &Name::new("*.example.").unwrap(), types, 0);
            let validator = ChainValidator::new(
                &NoNetwork,
                &chain.store,
                &chain.cache,
                Instant::now() + Duration::from_secs(10),
            );
            let result = validator
                .validate_message_answers(&message, chain.now)
                .await;
            if mode == "valid" {
                assert_eq!(result.unwrap(), SecurityStatus::Secure);
            } else {
                assert!(result.is_err(), "{mode}");
            }
        }
    }

    #[tokio::test]
    async fn nsec3_proof_count_limit_has_an_explicit_boundary() {
        let chain = SignedChain::new();
        for count in [128, 129] {
            let mut message = chain.negative_answer("missing.example.", Type::AAAA, false);
            chain.add_nsec3(
                &mut message,
                &Name::new("missing.example.").unwrap(),
                vec![Type::A],
                0,
            );
            let proof = message.authoritys[0].clone();
            message.authoritys.clear();
            chain.sign_parent_proof(&mut message, vec![proof; count]);
            let validator = ChainValidator::new(
                &NoNetwork,
                &chain.store,
                &chain.cache,
                Instant::now() + Duration::from_secs(10),
            );
            let result = validator
                .validate_message_answers(&message, chain.now)
                .await;
            if count == 128 {
                assert_eq!(result.unwrap(), SecurityStatus::Secure);
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[tokio::test]
    async fn signed_answers_reject_cname_loops_and_conflicting_targets() {
        let chain = SignedChain::new();
        for conflict in [false, true] {
            let owner = chain.answer[0].name.clone();
            let other = Name::new("other.child.branch.example.").unwrap();
            let mut message = chain.unsigned_answer();
            message.answers.clear();
            let mut records = vec![record(&owner, Resource::CNAME(other.clone()))];
            if conflict {
                records.push(record(&owner, Resource::CNAME(chain.parent.clone())));
            }
            let signature = sign(&owner, &chain.child, &records, &chain.key, &chain.pair);
            message.answers.extend(records);
            message
                .answers
                .push(record(&owner, Resource::RRSIG(signature)));
            if !conflict {
                let records = vec![record(&other, Resource::CNAME(owner))];
                let signature = sign(&other, &chain.child, &records, &chain.key, &chain.pair);
                message.answers.extend(records);
                message
                    .answers
                    .push(record(&other, Resource::RRSIG(signature)));
            }
            let validator = ChainValidator::new(
                &NoNetwork,
                &chain.store,
                &chain.cache,
                Instant::now() + Duration::from_secs(10),
            );
            let error = validator
                .validate_message_answers(&message, chain.now)
                .await
                .unwrap_err();
            assert!(error.to_string().contains(if conflict {
                "conflicting CNAME"
            } else {
                "CNAME loop"
            }));
        }
    }

    #[tokio::test]
    async fn signed_answers_must_use_the_question_class() {
        let chain = SignedChain::new();
        let mut message = chain.unsigned_answer();
        message.answers[0].class = Class::Chaos;
        let signature = sign(
            &message.answers[0].name,
            &chain.child,
            &message.answers,
            &chain.key,
            &chain.pair,
        );
        let mut signature_record = record(&message.answers[0].name, Resource::RRSIG(signature));
        signature_record.class = Class::Chaos;
        message.answers.push(signature_record);
        let validator = ChainValidator::new(
            &NoNetwork,
            &chain.store,
            &chain.cache,
            Instant::now() + Duration::from_secs(10),
        );
        let error = validator
            .validate_message_answers(&message, chain.now)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("class does not match query"));
    }

    #[tokio::test]
    async fn signed_chain_accepts_authenticated_parent_delegation() {
        let chain = SignedChain::new();
        assert!(chain.validate().await.is_ok());
    }

    #[cfg(feature = "zones")]
    #[tokio::test]
    async fn published_root_dnskey_signature_validates_against_iana_anchor() {
        let records = include_str!("fixtures/root-dnskey.zone")
            .parse::<crate::zones::File>()
            .unwrap()
            .try_into_records()
            .unwrap();
        let keys: Vec<_> = records
            .iter()
            .filter(|record| record.r#type() == Type::DNSKEY)
            .cloned()
            .collect();
        assert_eq!(keys.len(), 3);
        let signature = records
            .iter()
            .find_map(|record| match &record.resource {
                Resource::RRSIG(signature) => Some(signature.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(signature.key_tag, 20326);
        let now = signature.inception + Duration::from_secs(3600);
        let cache = DnssecCache::default();
        cache.insert_dnskeys(".", records);
        let store = TrustStore::default();
        let validator = ChainValidator::new(
            &NoNetwork,
            &store,
            &cache,
            Instant::now() + Duration::from_secs(10),
        );
        assert!(
            validator
                .validate_rrset_chain(".", &keys, &signature, now)
                .await
                .is_ok()
        );
        let mut tampered = signature;
        tampered.signature[0] ^= 1;
        assert!(
            validator
                .validate_rrset_chain(".", &keys, &tampered, now)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn signed_chain_rejects_unsigned_ds() {
        let chain = SignedChain::new();
        let mut records = chain.cache.get_ds(&chain.child).unwrap();
        records.retain(|record| !matches!(record.resource, Resource::RRSIG(_)));
        chain.cache.insert_ds(&chain.child, records);
        assert!(
            chain.validate().await.is_err(),
            "a matching DS without an authenticated parent signature must not establish trust"
        );
    }

    #[tokio::test]
    async fn signed_chain_rejects_tampered_ds_signature() {
        let chain = SignedChain::new();
        let mut records = chain.cache.get_ds(&chain.child).unwrap();
        if let Resource::RRSIG(sig) = &mut records[1].resource {
            sig.signature[0] ^= 1;
        }
        chain.cache.insert_ds(&chain.child, records);
        assert!(chain.validate().await.is_err());
    }

    #[tokio::test]
    async fn signed_chain_tries_all_dnskey_signatures() {
        let chain = SignedChain::new();
        let mut records = chain.cache.get_dnskeys(&chain.child).unwrap();
        let mut invalid = records[1].clone();
        if let Resource::RRSIG(sig) = &mut invalid.resource {
            sig.signature[0] ^= 1;
        }
        records.insert(1, invalid);
        chain.cache.insert_dnskeys(&chain.child, records);
        assert!(
            chain.validate().await.is_ok(),
            "a bad first DNSKEY signature must not hide a valid rollover signature"
        );
    }

    #[tokio::test]
    async fn signed_chain_tries_all_ds_signatures() {
        let chain = SignedChain::new();
        let mut records = chain.cache.get_ds(&chain.child).unwrap();
        let mut invalid = records[1].clone();
        if let Resource::RRSIG(sig) = &mut invalid.resource {
            sig.signature[0] ^= 1;
        }
        records.insert(1, invalid);
        chain.cache.insert_ds(&chain.child, records);
        assert!(chain.validate().await.is_ok());
    }

    #[tokio::test]
    async fn signed_chain_rejects_expired_signature() {
        let mut chain = SignedChain::new();
        chain.now += Duration::from_secs(86_400);
        assert!(chain.validate().await.is_err());
    }

    #[tokio::test]
    async fn signed_chain_rejects_answer_tampering() {
        let mut chain = SignedChain::new();
        chain.answer[0].resource = Resource::A("192.0.2.2".parse().unwrap());
        assert!(chain.validate().await.is_err());
    }

    #[tokio::test]
    async fn signed_chain_rejects_expired_deadline() {
        let chain = SignedChain::new();
        let validator = ChainValidator::new(&NoNetwork, &chain.store, &chain.cache, Instant::now());
        assert!(
            validator
                .validate_rrset_chain(
                    &chain.answer[0].name,
                    &chain.answer,
                    &chain.signature,
                    chain.now,
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn signed_chain_rejects_child_self_signed_delegation() {
        let chain = SignedChain::new();
        let mut records = chain.cache.get_ds(&chain.child).unwrap();
        records.truncate(1);
        let signature = sign(
            &chain.child,
            &chain.child,
            &records,
            &chain.key,
            &chain.pair,
        );
        records.push(record(&chain.child, Resource::RRSIG(signature)));
        chain.cache.insert_ds(&chain.child, records);
        assert!(chain.validate().await.is_err());
    }

    #[tokio::test]
    async fn signed_chain_rejects_wrong_trust_anchor() {
        let mut chain = SignedChain::new();
        chain.store = TrustStore::empty();
        let (_, wrong_key) = key(3);
        let ds = DS::from_dnskey(&chain.parent, &wrong_key, DigestType::Sha256).unwrap();
        chain.store.add_anchor(TrustAnchor {
            zone: chain.parent.clone(),
            key_tag: ds.key_tag,
            algorithm: ds.algorithm,
            digest_type: ds.digest_type,
            digest: ds.digest,
        });
        assert!(chain.validate().await.is_err());
    }

    #[tokio::test]
    async fn signed_chain_rejects_relabelled_answer() {
        let mut chain = SignedChain::new();
        chain.answer[0].name = Name::new("other.child.branch.example.").unwrap();
        // Reusing the original owner argument must not hide the record's actual owner.
        let validator = ChainValidator::new(
            &NoNetwork,
            &chain.store,
            &chain.cache,
            Instant::now() + Duration::from_secs(10),
        );
        let result = validator
            .validate_rrset_chain(
                "www.child.branch.example.",
                &chain.answer,
                &chain.signature,
                chain.now,
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn signed_chain_rejects_mismatched_covered_type() {
        let mut chain = SignedChain::new();
        chain.signature.type_covered = Type::AAAA;
        let data = crate::dnssec::canonical::signed_data_to_vec(
            &chain.answer[0].name,
            &chain.signature,
            &chain.answer,
        )
        .unwrap();
        chain.signature.signature = chain.pair.sign(&data).as_ref().to_vec();
        assert!(chain.validate().await.is_err());
    }

    #[tokio::test]
    async fn signed_chain_rejects_impossible_label_count() {
        let mut chain = SignedChain::new();
        chain.signature.labels = chain.answer[0].name.count_labels() + 1;
        let data = crate::dnssec::canonical::signed_data_to_vec(
            &chain.answer[0].name,
            &chain.signature,
            &chain.answer,
        )
        .unwrap();
        chain.signature.signature = chain.pair.sign(&data).as_ref().to_vec();
        assert!(chain.validate().await.is_err());
    }

    #[tokio::test]
    async fn signed_chain_rejects_mixed_rrset_classes() {
        let mut chain = SignedChain::new();
        let mut other = chain.answer[0].clone();
        other.class = Class::Chaos;
        chain.answer.push(other);
        chain.signature = sign(
            &chain.answer[0].name,
            &chain.child,
            &chain.answer,
            &chain.key,
            &chain.pair,
        );
        assert!(chain.validate().await.is_err());
    }

    #[tokio::test]
    async fn signed_chain_rejects_invalid_dnskey_protocol_and_flags() {
        for (flags, protocol) in [(257, 2), (1, 3), (385, 3)] {
            let mut chain = SignedChain::new();
            chain.key.flags = flags;
            chain.key.protocol = protocol;
            let mut records = vec![record(&chain.child, Resource::DNSKEY(chain.key.clone()))];
            let signature = sign(
                &chain.child,
                &chain.child,
                &records,
                &chain.key,
                &chain.pair,
            );
            records.push(record(&chain.child, Resource::RRSIG(signature)));
            chain.cache.insert_dnskeys(&chain.child, records);
            let ds = DS::from_dnskey(&chain.child, &chain.key, DigestType::Sha256).unwrap();
            chain.store.add_anchor(TrustAnchor {
                zone: chain.child.clone(),
                key_tag: ds.key_tag,
                algorithm: ds.algorithm,
                digest_type: ds.digest_type,
                digest: ds.digest,
            });
            chain.signature = sign(
                &chain.answer[0].name,
                &chain.child,
                &chain.answer,
                &chain.key,
                &chain.pair,
            );
            assert!(
                chain.validate().await.is_err(),
                "flags={flags}, protocol={protocol}"
            );
        }
    }

    #[test]
    fn dnssec_cache_does_not_reuse_zero_ttl_records() {
        let cache = DnssecCache::default();
        let zone = Name::new("example.").unwrap();
        let (_, key) = key(1);
        let mut records = vec![record(&zone, Resource::DNSKEY(key))];
        cache.insert_dnskeys(&zone, records.clone());
        assert!(cache.get_dnskeys(&zone).is_some());
        records[0].ttl = Duration::ZERO;
        cache.insert_dnskeys(&zone, records.clone());
        assert!(cache.get_dnskeys(&zone).is_none());
        cache.insert_ds(&zone, records);
        assert!(cache.get_ds(&zone).is_none());
    }

    #[test]
    fn dnssec_cache_expires_and_ages_records() {
        let cache = DnssecCache::default();
        let zone = Name::new("example.").unwrap();
        let (_, key) = key(1);
        let records = vec![record(&zone, Resource::DNSKEY(key))];
        for entries in [&cache.dnskeys, &cache.ds_records] {
            DnssecCache::insert(entries, &zone, records.clone());
            entries.lock().unwrap().get_mut(&zone).unwrap().inserted =
                Instant::now() - Duration::from_secs(10);
            let cached = DnssecCache::get(entries, &zone).unwrap();
            assert_eq!(cached[0].ttl, Duration::from_secs(3590));
            entries.lock().unwrap().get_mut(&zone).unwrap().inserted =
                Instant::now() - Duration::from_secs(3601);
            assert!(DnssecCache::get(entries, &zone).is_none());
        }
    }

    #[test]
    fn dnssec_cache_evicts_oldest_entry_at_capacity() {
        let cache = DnssecCache::default();
        let (_, key) = key(1);
        for index in 0..=MAX_CACHE_ENTRIES {
            let zone = Name::new(&format!("zone{index}.example.")).unwrap();
            cache.insert_dnskeys(&zone, vec![record(&zone, Resource::DNSKEY(key.clone()))]);
        }
        assert_eq!(cache.dnskeys.lock().unwrap().len(), MAX_CACHE_ENTRIES);
        assert!(cache.get_dnskeys("zone0.example.").is_none());
        assert!(
            cache
                .get_dnskeys(format!("zone{MAX_CACHE_ENTRIES}.example."))
                .is_some()
        );
    }

    #[tokio::test]
    async fn dependency_queries_preserve_ttls_and_scope() {
        let chain = SignedChain::new();
        for rtype in [Type::DNSKEY, Type::DS] {
            let mut records = if rtype == Type::DNSKEY {
                chain.cache.get_dnskeys(&chain.child).unwrap()
            } else {
                chain.cache.get_ds(&chain.child).unwrap()
            };
            records[1].ttl = Duration::from_secs(1);
            let mut unrelated = records[0].clone();
            unrelated.name = Name::new("unrelated.example.").unwrap();
            records.push(unrelated);
            let mut wrong_class = records[0].clone();
            wrong_class.class = Class::Chaos;
            records.push(wrong_class);
            let response = DependencyResponse(Message {
                qr: crate::QR::Response,
                answers: records,
                ..Message::default()
            });
            let cache = DnssecCache::default();
            let validator = ChainValidator::new(
                &response,
                &chain.store,
                &cache,
                Instant::now() + Duration::from_secs(10),
            );
            let (records, signatures) = if rtype == Type::DNSKEY {
                validator.get_zone_dnskeys(&chain.child).await.unwrap()
            } else {
                validator.get_zone_ds(&chain.child).await.unwrap()
            };
            assert_eq!(records.len(), 1);
            assert_eq!(signatures.len(), 1);
            let cached = if rtype == Type::DNSKEY {
                cache.get_dnskeys(&chain.child).unwrap()
            } else {
                cache.get_ds(&chain.child).unwrap()
            };
            assert_eq!(cached.len(), 2);
            assert_eq!(cached[1].ttl, Duration::from_secs(1));
        }
    }

    #[tokio::test]
    async fn signed_chain_tries_keys_with_colliding_tags() {
        let chain = SignedChain::new();
        let mut collision = chain.key.clone();
        collision.public_key[0] ^= 1;
        let tag = chain.key.key_tag();
        let mut found = false;
        for tail in 0..=u16::MAX {
            collision.public_key[30..].copy_from_slice(&tail.to_be_bytes());
            if collision.key_tag() == tag {
                found = true;
                break;
            }
        }
        assert!(found);
        assert_ne!(collision.public_key, chain.key.public_key);
        let mut keys = vec![
            record(&chain.child, Resource::DNSKEY(collision)),
            record(&chain.child, Resource::DNSKEY(chain.key.clone())),
        ];
        let signature = sign(&chain.child, &chain.child, &keys, &chain.key, &chain.pair);
        keys.push(record(&chain.child, Resource::RRSIG(signature)));
        chain.cache.insert_dnskeys(&chain.child, keys);
        assert!(chain.validate().await.is_ok());
    }
}

impl DnssecCache {
    /// Caches DNSKEY records until the smallest record TTL expires.
    ///
    /// Invalid names and poisoned cache locks are logged and not cached.
    pub fn insert_dnskeys(&self, zone: impl crate::names::IntoName, records: Vec<Record>) {
        Self::insert(&self.dnskeys, zone, records);
    }

    /// Gets unexpired DNSKEY query records with their remaining TTLs.
    ///
    /// Invalid names and poisoned cache locks are logged and treated as misses.
    #[must_use]
    pub fn get_dnskeys(&self, zone: impl crate::names::IntoName) -> Option<Vec<Record>> {
        Self::get(&self.dnskeys, zone)
    }

    /// Caches DS records until the smallest record TTL expires.
    ///
    /// Invalid names and poisoned cache locks are logged and not cached.
    pub fn insert_ds(&self, zone: impl crate::names::IntoName, records: Vec<Record>) {
        Self::insert(&self.ds_records, zone, records);
    }

    /// Gets unexpired DS query records with their remaining TTLs.
    ///
    /// Invalid names and poisoned cache locks are logged and treated as misses.
    #[must_use]
    pub fn get_ds(&self, zone: impl crate::names::IntoName) -> Option<Vec<Record>> {
        Self::get(&self.ds_records, zone)
    }

    fn insert(cache: &RecordCache, zone: impl crate::names::IntoName, records: Vec<Record>) {
        let name = match zone.into_name() {
            Ok(name) => name,
            Err(error) => {
                log::warn!("cannot insert DNSSEC cache entry: {error}");
                return;
            }
        };
        let mut map = match cache.lock() {
            Ok(map) => map,
            Err(error) => {
                log::warn!("cannot insert DNSSEC cache entry: {error}");
                return;
            }
        };
        let lifetime = records
            .iter()
            .map(|record| record.ttl)
            .min()
            .unwrap_or_default();
        map.retain(|_, entry| entry.inserted.elapsed() < entry.lifetime);
        if lifetime.is_zero() {
            map.remove(&name);
            return;
        }
        if map.len() >= MAX_CACHE_ENTRIES && !map.contains_key(&name) {
            let oldest = map
                .iter()
                .min_by_key(|(_, entry)| entry.inserted)
                .map(|(name, _)| name.clone());
            if let Some(oldest) = oldest {
                map.remove(&oldest);
            }
        }
        map.insert(
            name,
            CachedRecords {
                records,
                inserted: Instant::now(),
                lifetime,
            },
        );
    }

    fn get(cache: &RecordCache, zone: impl crate::names::IntoName) -> Option<Vec<Record>> {
        let name = match zone.into_name() {
            Ok(name) => name,
            Err(error) => {
                log::warn!("cannot read DNSSEC cache entry: {error}");
                return None;
            }
        };
        let mut map = match cache.lock() {
            Ok(map) => map,
            Err(error) => {
                log::warn!("cannot read DNSSEC cache entry: {error}");
                return None;
            }
        };
        let entry = map.get(&name)?;
        let elapsed = entry.inserted.elapsed();
        if elapsed >= entry.lifetime {
            map.remove(&name);
            return None;
        }
        let mut records = entry.records.clone();
        for record in &mut records {
            record.ttl = record
                .ttl
                .saturating_sub(Duration::from_secs(elapsed.as_secs()));
        }
        Some(records)
    }
}

/// An iterative DNSSEC chain-of-trust validator.
#[derive(Debug)]
pub struct ChainValidator<'a, R: AsyncResolver + ?Sized> {
    resolver: &'a R,
    trust_store: &'a TrustStore,
    cache: &'a DnssecCache,
    deadline: Instant,
    work: AtomicUsize,
}

impl<'a, R: AsyncResolver + ?Sized> ChainValidator<'a, R> {
    /// Creates a chain validator with a shared deadline and 1,024-unit work budget.
    pub fn new(
        resolver: &'a R,
        trust_store: &'a TrustStore,
        cache: &'a DnssecCache,
        deadline: Instant,
    ) -> Self {
        Self {
            resolver,
            trust_store,
            cache,
            deadline,
            work: AtomicUsize::new(0),
        }
    }

    /// Validates answers and authenticated denial against the trust store.
    ///
    /// Accepts one IN question in a complete NoError or NXDOMAIN response.
    /// Follows CNAMEs and validates wildcard expansion proofs. Unsigned data is
    /// insecure only after an authenticated unsigned-delegation proof.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported response shapes, missing or invalid
    /// signatures/proofs, malformed aliases, unavailable trust paths, dependency
    /// exchange failures, or exhausted deadlines/work limits. NSEC3 validation
    /// accepts at most 128 proof records and 150 iterations.
    pub async fn validate_message_answers(
        &self,
        message: &Message,
        now: SystemTime,
    ) -> Result<SecurityStatus, crate::Error> {
        self.spend_work()?;
        if message.tc
            || message.qr != crate::QR::Response
            || message.questions.len() != 1
            || !matches!(
                message.rcode,
                crate::Rcode::NoError | crate::Rcode::NXDomain
            )
            || message.questions[0].class != Class::Internet
        {
            return Err(DnssecError::ValidationFailed(
                "invalid response for local DNSSEC validation".into(),
            )
            .into());
        }

        // Partition answer records into RRsets and their covering RRSIGs keyed by (owner, type).
        // Using Entry API allows a single pass partition without redundant lookups.
        let mut rrsets: HashMap<(Name, Type), Vec<Record>> = HashMap::new();
        let mut rrsigs: HashMap<(Name, Type), Vec<RRSIG>> = HashMap::new();

        for record in &message.answers {
            self.spend_work()?;
            if record.class != message.questions[0].class {
                return Err(DnssecError::ValidationFailed(
                    "answer class does not match query".into(),
                )
                .into());
            }
            let canonical_name = record.name.clone(); // TODO Change to a canonical key
            match &record.resource {
                Resource::RRSIG(rrsig) => {
                    rrsigs
                        .entry((canonical_name, rrsig.type_covered))
                        .or_default()
                        .push(rrsig.clone());
                }
                _ => {
                    rrsets
                        .entry((canonical_name, record.r#type()))
                        .or_default()
                        .push(record.clone());
                }
            }
        }

        if rrsets.is_empty() {
            let question = &message.questions[0];
            return self
                .validate_negative_or_insecure(message, &question.name, question.r#type, now)
                .await;
        }

        let mut insecure = false;
        for ((name, rtype), set) in &rrsets {
            let Some(candidate_sigs) = rrsigs.get(&(name.clone(), *rtype)) else {
                self.prove_insecure(name, now).await?;
                insecure = true;
                continue;
            };

            // Multi-Signature Support (RFC 4035 §5.3.1):
            // An RRset may be signed by multiple keys (e.g. during an algorithm
            // rollover, key rollover, or multi-signer setups). RFC 4035 §5.3.1
            // specifies: "A validator MUST try each signature until it finds one
            // that validates or exhausts all of them."
            let mut last_err = None;
            let mut verified = false;

            for rrsig in candidate_sigs {
                // Validate the RRset and recursively verify its chain of trust up to an anchor.
                // This may trigger additional queries to fetch DNSKEY and DS records for the zone and its parent.
                match self.validate_rrset_chain(name, set, rrsig, now).await {
                    Ok(_) => {
                        if rrsig.labels < name.count_labels() {
                            let proofs = self
                                .authenticated_proofs(&message.authoritys, &rrsig.signer_name, now)
                                .await?;
                            if !super::denial::verify_wildcard_expansion(
                                &proofs,
                                name,
                                rrsig.labels,
                                &rrsig.signer_name,
                            ) {
                                last_err = Some(
                                    DnssecError::ValidationFailed(
                                        "missing authenticated wildcard expansion proof".into(),
                                    )
                                    .into(),
                                );
                                continue;
                            }
                        }
                        verified = true;
                        break;
                    }
                    Err(err) => {
                        last_err = Some(err);
                    }
                }
            }

            if !verified {
                if let Some(err) = last_err {
                    if let crate::Error::Dnssec(ref dnssec_err) = err {
                        if matches!(dnssec_err, DnssecError::InsecureResponse) {
                            insecure = true;
                            continue;
                        }
                    }
                    return Err(err);
                }
            }
        }

        let question = &message.questions[0];
        let mut target = question.name.clone();
        let mut seen = Vec::new();
        loop {
            self.spend_work()?;
            if seen.contains(&target) {
                return Err(
                    DnssecError::ValidationFailed("CNAME loop in DNSSEC answer".into()).into(),
                );
            }
            seen.push(target.clone());
            if rrsets.contains_key(&(target.clone(), question.r#type))
                || question.r#type == Type::ANY && rrsets.keys().any(|(owner, _)| *owner == target)
            {
                if message.rcode != crate::Rcode::NoError {
                    return Err(DnssecError::ValidationFailed(
                        "NXDOMAIN contains queried answer".into(),
                    )
                    .into());
                }
                break;
            }
            let aliases: Vec<_> = message
                .answers
                .iter()
                .filter_map(|record| match &record.resource {
                    Resource::CNAME(name) if record.name == target => Some(name),
                    _ => None,
                })
                .collect();
            if let Some(alias) = aliases.first() {
                if aliases.iter().any(|candidate| *candidate != *alias) {
                    return Err(
                        DnssecError::ValidationFailed("conflicting CNAME targets".into()).into(),
                    );
                }
                target = (*alias).clone();
                continue;
            }
            let status = self
                .validate_negative_or_insecure(message, &target, question.r#type, now)
                .await?;
            insecure |= status == SecurityStatus::Insecure;
            break;
        }
        self.spend_work()?;
        Ok(if insecure {
            SecurityStatus::Insecure
        } else {
            SecurityStatus::Secure
        })
    }

    /// Validates an RRset and recursively verifies its chain of trust up to an anchor.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid owner names, an exhausted deadline, missing or
    /// invalid signatures, mismatched delegation digests, or unavailable trust anchors.
    pub async fn validate_rrset_chain(
        &self,
        owner_name: impl crate::names::IntoName,
        rrset: &[Record],
        rrsig: &RRSIG,
        now: SystemTime,
    ) -> Result<ValidationReport, crate::Error> {
        let owner = owner_name.into_name()?;
        let zone = &rrsig.signer_name;
        self.spend_work()?;
        if !owner.is_subdomain_of(zone)
            || !self.signer_is_eligible(&owner, zone, rrsig.type_covered)
        {
            return Err(DnssecError::ValidationFailed(
                "RRSIG signer is not an ancestor of the RRset owner".into(),
            )
            .into());
        }

        // Fetch or get zone DNSKEYs
        let (dnskeys, dnskey_rrsigs) = self.get_zone_dnskeys(zone).await?;

        let mut last_error = crate::Error::Dnssec(DnssecError::MissingSignature);
        let mut authenticated = false;
        for signature in &dnskey_rrsigs {
            if signature.type_covered != Type::DNSKEY
                || signature.signer_name != *zone
                || signature.labels != zone.count_labels()
            {
                continue;
            }
            for record in &dnskeys {
                self.spend_work()?;
                let Resource::DNSKEY(key) = &record.resource else {
                    continue;
                };
                if key.algorithm != signature.algorithm || key.key_tag() != signature.key_tag {
                    continue;
                }
                if let Err(error) = validate_rrset(zone, &dnskeys, signature, key, now) {
                    last_error = error.into();
                    continue;
                }
                match self
                    .verify_key_against_parent_or_anchor(zone, key, now)
                    .await
                {
                    Ok(()) => {
                        authenticated = true;
                        break;
                    }
                    Err(error) => last_error = error,
                }
            }
            if authenticated {
                break;
            }
        }
        if !authenticated {
            return Err(last_error);
        }
        for record in &dnskeys {
            self.spend_work()?;
            let Resource::DNSKEY(key) = &record.resource else {
                continue;
            };
            if key.algorithm != rrsig.algorithm || key.key_tag() != rrsig.key_tag {
                continue;
            }
            match validate_rrset(&owner, rrset, rrsig, key, now) {
                Ok(report) => {
                    self.spend_work()?;
                    return Ok(report);
                }
                Err(error) => last_error = error.into(),
            }
        }
        Err(last_error)
    }

    /// Verifies that a zone's KSK matches a trust anchor or the parent zone's DS record.
    fn verify_key_against_parent_or_anchor<'b>(
        &'b self,
        zone: &'b Name,
        ksk: &'b DNSKEY,
        now: SystemTime,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), crate::Error>> + Send + 'b>> {
        Box::pin(async move {
            let anchors = self.trust_store.find_anchors(zone);
            if !anchors.is_empty() {
                // Check if KSK matches any trust anchor
                for anchor in anchors {
                    self.spend_work()?;
                    let calculated = DS::from_dnskey(zone, ksk, anchor.digest_type)?;
                    if anchor.matches_ds(&calculated) {
                        return Ok(());
                    }
                }
                return Err(crate::Error::Dnssec(DnssecError::ValidationFailed(
                    format!(
                        "KSK with key tag {} does not match any trust anchor for zone '{zone}'",
                        ksk.key_tag()
                    ),
                )));
            }

            // Zone is not an anchor; walk to parent zone
            if zone.is_root() {
                return Err(crate::Error::Dnssec(DnssecError::NoTrustAnchor(
                    zone.to_string(),
                )));
            }

            let (ds_records, ds_rrsigs) = self.get_zone_ds(zone).await?;
            if ds_records.is_empty() {
                self.prove_insecure(zone, now).await?;
                return Err(DnssecError::InsecureResponse.into());
            }
            let matching_ds = ds_records.iter().find(|r| {
                if let Resource::DS(ds) = &r.resource {
                    if ds.key_tag == ksk.key_tag() && ds.algorithm == ksk.algorithm {
                        if let Ok(calc) = DS::from_dnskey(zone, ksk, ds.digest_type) {
                            return calc.digest == ds.digest;
                        }
                    }
                }
                false
            });

            let Some(_) = matching_ds else {
                return Err(crate::Error::Dnssec(DnssecError::ValidationFailed(
                    format!(
                        "no parent DS record matches KSK with key tag {} for zone '{zone}'",
                        ksk.key_tag()
                    ),
                )));
            };

            // Validate DS RRset using parent zone
            let mut last_error = crate::Error::Dnssec(DnssecError::MissingSignature);
            for signature in &ds_rrsigs {
                if signature.type_covered != Type::DS
                    || signature.signer_name == *zone
                    || !zone.is_subdomain_of(&signature.signer_name)
                {
                    continue;
                }
                match self
                    .validate_rrset_chain(zone, &ds_records, signature, now)
                    .await
                {
                    Ok(_) => return Ok(()),
                    Err(error) => last_error = error,
                }
            }
            Err(last_error)
        })
    }

    /// Queries or fetches cached DNSKEY records for `zone`.
    async fn get_zone_dnskeys(
        &self,
        zone: &Name,
    ) -> Result<(Vec<Record>, Vec<RRSIG>), crate::Error> {
        self.get_zone_records(zone, Type::DNSKEY).await
    }

    /// Queries or fetches cached DS records for `zone`.
    async fn get_zone_ds(&self, zone: &Name) -> Result<(Vec<Record>, Vec<RRSIG>), crate::Error> {
        self.get_zone_records(zone, Type::DS).await
    }

    async fn get_zone_records(
        &self,
        zone: &Name,
        rtype: Type,
    ) -> Result<(Vec<Record>, Vec<RRSIG>), crate::Error> {
        self.spend_work()?;
        let cached = if rtype == Type::DNSKEY {
            self.cache.get_dnskeys(zone)
        } else {
            self.cache.get_ds(zone)
        };
        let records = if let Some(records) = cached {
            records
        } else {
            let mut query = Message {
                cd: true,
                ..Message::default()
            };
            query.try_add_question(zone, rtype, Class::Internet)?;
            query.extension = Some(crate::Extension {
                dnssec_ok: true,
                ..Default::default()
            });
            let response = self
                .resolver
                .exchange_with_deadline(&query, self.deadline)
                .await?;
            if response.tc
                || response.qr != crate::QR::Response
                || response.questions != query.questions
                || !matches!(
                    response.rcode,
                    crate::Rcode::NoError | crate::Rcode::NXDomain
                )
            {
                return Err(DnssecError::ValidationFailed(format!(
                    "invalid {rtype} dependency response for '{zone}'"
                ))
                .into());
            }
            let mut records = Vec::new();
            for record in &response.answers {
                self.spend_work()?;
                if record.name == *zone
                    && record.class == Class::Internet
                    && (record.r#type() == rtype
                        || matches!(&record.resource, Resource::RRSIG(sig) if sig.type_covered == rtype))
                {
                    records.push(record.clone());
                }
            }
            if rtype == Type::DNSKEY {
                self.cache.insert_dnskeys(zone, records.clone());
            } else {
                self.cache.insert_ds(zone, records.clone());
            }
            records
        };
        let mut rrset = Vec::new();
        let mut signatures = Vec::new();
        for record in records {
            self.spend_work()?;
            if record.name != *zone || record.class != Class::Internet {
                continue;
            }
            match &record.resource {
                Resource::RRSIG(sig) if sig.type_covered == rtype => signatures.push(sig.clone()),
                _ if record.r#type() == rtype => rrset.push(record),
                _ => {}
            }
        }
        Ok((rrset, signatures))
    }

    fn spend_work(&self) -> Result<(), crate::Error> {
        if Instant::now() >= self.deadline
            || self.work.fetch_add(1, Ordering::Relaxed) >= MAX_VALIDATION_WORK
        {
            return Err(DnssecError::ValidationFailed(
                "DNSSEC validation deadline or work limit exceeded".into(),
            )
            .into());
        }
        Ok(())
    }

    fn closest_anchor(&self, name: &Name) -> Option<Name> {
        let mut candidate = Some(name.clone());
        while let Some(zone) = candidate {
            if !self.trust_store.find_anchors(&zone).is_empty() {
                return Some(zone);
            }
            candidate = zone.parent();
        }
        None
    }

    fn signer_is_eligible(&self, owner: &Name, signer: &Name, rtype: Type) -> bool {
        let scope = if rtype == Type::DS {
            owner.parent().unwrap_or_else(Name::root)
        } else {
            owner.clone()
        };
        self.closest_anchor(&scope)
            .is_none_or(|anchor| signer.is_subdomain_of(&anchor))
    }

    async fn prove_insecure(&self, name: &Name, now: SystemTime) -> Result<(), crate::Error> {
        let anchor = self.closest_anchor(name);
        let mut candidate = Some(name.clone());
        while let Some(zone) = candidate {
            self.spend_work()?;
            if !self.trust_store.find_anchors(&zone).is_empty() || zone.is_root() {
                break;
            }
            let mut query = Message {
                cd: true,
                ..Message::default()
            };
            query.try_add_question(&zone, Type::DS, Class::Internet)?;
            query.extension = Some(crate::Extension {
                dnssec_ok: true,
                ..Default::default()
            });
            let response = self
                .resolver
                .exchange_with_deadline(&query, self.deadline)
                .await?;
            if response.qr != crate::QR::Response
                || response.tc
                || response.questions != query.questions
                || !matches!(
                    response.rcode,
                    crate::Rcode::NoError | crate::Rcode::NXDomain
                )
            {
                return Err(DnssecError::ValidationFailed(
                    "invalid unsigned-delegation response".into(),
                )
                .into());
            }
            if response
                .answers
                .iter()
                .any(|record| record.name == zone && record.r#type() == Type::DS)
            {
                return Err(DnssecError::MissingSignature.into());
            }
            let mut signers = Vec::new();
            for record in &response.authoritys {
                self.spend_work()?;
                if let Resource::RRSIG(signature) = &record.resource {
                    if signature.signer_name != zone
                        && zone.is_subdomain_of(&signature.signer_name)
                        && anchor
                            .as_ref()
                            .is_none_or(|anchor| signature.signer_name.is_subdomain_of(anchor))
                        && !signers.contains(&signature.signer_name)
                    {
                        signers.push(signature.signer_name.clone());
                    }
                }
            }
            for signer in signers {
                let proofs = self
                    .authenticated_proofs(&response.authoritys, &signer, now)
                    .await?;
                if super::denial::verify_unsigned_delegation(&proofs, &zone, &signer) {
                    self.spend_work()?;
                    return Ok(());
                }
            }
            candidate = zone.parent();
        }
        Err(DnssecError::ValidationFailed(format!(
            "no authenticated unsigned delegation for '{name}'"
        ))
        .into())
    }

    async fn validate_negative(
        &self,
        message: &Message,
        name: &Name,
        rtype: Type,
        now: SystemTime,
    ) -> Result<(), crate::Error> {
        let mut zones = Vec::new();
        for record in &message.authoritys {
            self.spend_work()?;
            if let Resource::RRSIG(signature) = &record.resource {
                if matches!(signature.type_covered, Type::NSEC | Type::NSEC3)
                    && name.is_subdomain_of(&signature.signer_name)
                    && self.signer_is_eligible(name, &signature.signer_name, rtype)
                    && !zones.contains(&signature.signer_name)
                {
                    zones.push(signature.signer_name.clone());
                }
            }
        }
        for zone in zones {
            let proofs = self
                .authenticated_proofs(&message.authoritys, &zone, now)
                .await?;
            if super::denial::verify_nsec_response(
                &proofs,
                name,
                rtype,
                &zone,
                message.rcode == crate::Rcode::NXDomain,
            ) || super::denial::verify_nsec3_response(
                &proofs,
                name,
                rtype,
                &zone,
                message.rcode == crate::Rcode::NXDomain,
                false,
            ) {
                self.spend_work()?;
                return Ok(());
            }
        }
        Err(DnssecError::MissingSignature.into())
    }

    async fn validate_negative_or_insecure(
        &self,
        message: &Message,
        name: &Name,
        rtype: Type,
        now: SystemTime,
    ) -> Result<SecurityStatus, crate::Error> {
        match self.validate_negative(message, name, rtype, now).await {
            Ok(()) => Ok(SecurityStatus::Secure),
            Err(crate::Error::Dnssec(DnssecError::MissingSignature)) => {
                self.prove_insecure(name, now).await?;
                Ok(SecurityStatus::Insecure)
            }
            Err(error) => Err(error),
        }
    }

    async fn authenticated_proofs(
        &self,
        records: &[Record],
        zone: &Name,
        now: SystemTime,
    ) -> Result<Vec<Record>, crate::Error> {
        let mut sets: HashMap<(Name, Type), Vec<Record>> = HashMap::new();
        for record in records {
            self.spend_work()?;
            if record.class == Class::Internet
                && record.name.is_subdomain_of(zone)
                && matches!(record.r#type(), Type::NSEC | Type::NSEC3)
            {
                sets.entry((record.name.clone(), record.r#type()))
                    .or_default()
                    .push(record.clone());
            }
        }
        let mut proofs = Vec::new();
        for ((owner, rtype), set) in sets {
            for record in records {
                self.spend_work()?;
                let Resource::RRSIG(signature) = &record.resource else {
                    continue;
                };
                if record.name != owner
                    || record.class != Class::Internet
                    || signature.type_covered != rtype
                    || signature.signer_name != *zone
                    || signature.labels != owner.count_labels()
                {
                    continue;
                }
                if self
                    .validate_rrset_chain(&owner, &set, signature, now)
                    .await
                    .is_ok()
                {
                    proofs.extend(set);
                    break;
                }
            }
        }
        self.spend_work()?;
        Ok(proofs)
    }
}
