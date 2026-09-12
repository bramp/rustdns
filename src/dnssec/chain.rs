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
use crate::resource::{DNSKEY, DS, RRSIG};
use crate::types::{Class, Message, Record, Resource, SecurityStatus, Type};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

/// In-memory cache for validated DNSSEC keys and delegation signers.
// TODO Consider merging this with a more general cache.
#[derive(Clone, Debug, Default)]
pub struct DnssecCache {
    dnskeys: Arc<Mutex<HashMap<String, Vec<Record>>>>,
    ds_records: Arc<Mutex<HashMap<String, Vec<Record>>>>,
}

impl DnssecCache {
    /// Inserts validated DNSKEY records for a zone.
    pub fn insert_dnskeys(&self, zone: &str, records: Vec<Record>) {
        let mut map = self.dnskeys.lock().unwrap();
        map.insert(crate::names::canonical_key(zone), records);
    }

    /// Gets cached DNSKEY records for a zone.
    #[must_use]
    pub fn get_dnskeys(&self, zone: &str) -> Option<Vec<Record>> {
        let map = self.dnskeys.lock().unwrap();
        map.get(&crate::names::canonical_key(zone)).cloned()
    }

    /// Inserts validated DS records for a zone.
    pub fn insert_ds(&self, zone: &str, records: Vec<Record>) {
        let mut map = self.ds_records.lock().unwrap();
        map.insert(crate::names::canonical_key(zone), records);
    }

    /// Gets cached DS records for a zone.
    #[must_use]
    pub fn get_ds(&self, zone: &str) -> Option<Vec<Record>> {
        let map = self.ds_records.lock().unwrap();
        map.get(&crate::names::canonical_key(zone)).cloned()
    }
}

/// An iterative DNSSEC chain-of-trust validator.
#[derive(Debug)]
pub struct ChainValidator<'a, R: AsyncResolver + ?Sized> {
    resolver: &'a R,
    trust_store: &'a TrustStore,
    cache: &'a DnssecCache,
    deadline: Instant,
}

impl<'a, R: AsyncResolver + ?Sized> ChainValidator<'a, R> {
    /// Creates a new chain validator.
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
        }
    }

    /// Validates a target RRset in a response message against the trust store.
    pub async fn validate_message_answers(
        &self,
        message: &Message,
        now: SystemTime,
    ) -> Result<SecurityStatus, crate::Error> {
        if message.answers.is_empty() {
            return Ok(SecurityStatus::Insecure);
        }

        // Partition answer records into RRsets and their covering RRSIGs keyed by (owner, type).
        // Using Entry API allows a single pass partition without redundant lookups.
        let mut rrsets: HashMap<(String, Type), Vec<Record>> = HashMap::new();
        let mut rrsigs: HashMap<(String, Type), Vec<RRSIG>> = HashMap::new();

        for record in &message.answers {
            let canonical_name = crate::names::canonical_key(&record.name);
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
            return Ok(SecurityStatus::Insecure);
        }

        for ((name, rtype), set) in &rrsets {
            let Some(candidate_sigs) = rrsigs.get(&(name.clone(), *rtype)) else {
                // If there are no signatures for an RRset, determine if the zone is signed
                return Ok(SecurityStatus::Insecure);
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
                        if dnssec_err.is_insecure() {
                            return Ok(SecurityStatus::Insecure);
                        }
                    }
                    return Err(err);
                }
            }
        }

        Ok(SecurityStatus::Secure)
    }

    /// Validates an RRset and recursively verifies its chain of trust up to an anchor.
    pub async fn validate_rrset_chain(
        &self,
        owner_name: &str,
        rrset: &[Record],
        rrsig: &RRSIG,
        now: SystemTime,
    ) -> Result<ValidationReport, crate::Error> {
        let zone = &rrsig.signer_name;

        // Fetch or get zone DNSKEYs
        let (dnskeys, dnskey_rrsigs) = self.get_zone_dnskeys(zone).await?;

        // 1. Find matching DNSKEY (ZSK) for this RRSIG
        let zsk_record = dnskeys.iter().find(|r| {
            if let Resource::DNSKEY(k) = &r.resource {
                k.algorithm == rrsig.algorithm && k.key_tag() == rrsig.key_tag
            } else {
                false
            }
        });

        let Some(zsk_record) = zsk_record else {
            return Err(crate::Error::Dnssec(DnssecError::ValidationFailed(format!(
                "no matching DNSKEY with key tag {} in zone '{zone}'",
                rrsig.key_tag
            ))));
        };

        let Resource::DNSKEY(zsk) = &zsk_record.resource else {
            unreachable!();
        };

        // 2. Validate RRset against ZSK
        let report = validate_rrset(owner_name, rrset, rrsig, zsk, now)?;

        // 3. Validate DNSKEY RRset against KSK
        let ksk_rrsig = dnskey_rrsigs.iter().find(|s| s.type_covered == Type::DNSKEY);
        let Some(ksk_rrsig) = ksk_rrsig else {
            return Err(crate::Error::Dnssec(DnssecError::MissingSignature));
        };

        let ksk_record = dnskeys.iter().find(|r| {
            if let Resource::DNSKEY(k) = &r.resource {
                k.algorithm == ksk_rrsig.algorithm && k.key_tag() == ksk_rrsig.key_tag
            } else {
                false
            }
        });

        let Some(ksk_record) = ksk_record else {
            return Err(crate::Error::Dnssec(DnssecError::ValidationFailed(format!(
                "no matching KSK with key tag {} in zone '{zone}'",
                ksk_rrsig.key_tag
            ))));
        };

        let Resource::DNSKEY(ksk) = &ksk_record.resource else {
            unreachable!();
        };

        validate_rrset(zone, &dnskeys, ksk_rrsig, ksk, now)?;

        // 4. Verify KSK against trust anchor or parent DS
        self.verify_key_against_parent_or_anchor(zone, ksk, now).await?;

        Ok(report)
    }

    /// Verifies that a zone's KSK matches a trust anchor or the parent zone's DS record.
    fn verify_key_against_parent_or_anchor<'b>(
        &'b self,
        zone: &'b str,
        ksk: &'b DNSKEY,
        now: SystemTime,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), crate::Error>> + Send + 'b>> {
        Box::pin(async move {
            let anchors = self.trust_store.find_anchors(zone);
            if !anchors.is_empty() {
                // Check if KSK matches any trust anchor
                for anchor in anchors {
                    let calculated = DS::from_dnskey(zone, ksk, anchor.digest_type)?;
                    if anchor.matches_ds(&calculated) {
                        return Ok(());
                    }
                }
                return Err(crate::Error::Dnssec(DnssecError::ValidationFailed(format!(
                    "KSK with key tag {} does not match any trust anchor for zone '{zone}'",
                    ksk.key_tag()
                ))));
            }

            // Zone is not an anchor; walk to parent zone
            let parent = crate::names::parent_zone(zone);
            if parent.is_empty() && zone == "." {
                return Err(crate::Error::Dnssec(DnssecError::NoTrustAnchor(zone.to_string())));
            }

            let (ds_records, ds_rrsigs) = self.get_zone_ds(zone).await?;
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
                return Err(crate::Error::Dnssec(DnssecError::ValidationFailed(format!(
                    "no parent DS record matches KSK with key tag {} for zone '{zone}'",
                    ksk.key_tag()
                ))));
            };

            // Validate DS RRset using parent zone
            let covering_rrsig = ds_rrsigs.iter().find(|s| s.type_covered == Type::DS);
            if let Some(rrsig) = covering_rrsig {
                self.validate_rrset_chain(zone, &ds_records, rrsig, now).await?;
            }

            Ok(())
        })
    }

    /// Queries or fetches cached DNSKEY records for `zone`.
    async fn get_zone_dnskeys(&self, zone: &str) -> Result<(Vec<Record>, Vec<RRSIG>), crate::Error> {
        if let Some(cached) = self.cache.get_dnskeys(zone) {
            let mut keys = Vec::new();
            let mut sigs = Vec::new();
            for r in cached {
                if let Resource::RRSIG(s) = &r.resource {
                    sigs.push(s.clone());
                } else {
                    keys.push(r);
                }
            }
            return Ok((keys, sigs));
        }

        let mut query = Message::default();
        query.try_add_question(zone, Type::DNSKEY, Class::Internet)?;
        query.extension = Some(crate::Extension {
            dnssec_ok: true,
            ..Default::default()
        });

        let resp = self.resolver.exchange_with_deadline(&query, self.deadline).await?;
        let mut keys = Vec::new();
        let mut sigs = Vec::new();

        for r in &resp.answers {
            match &r.resource {
                Resource::DNSKEY(_) => keys.push(r.clone()),
                Resource::RRSIG(s) => sigs.push(s.clone()),
                _ => {}
            }
        }

        let mut all = keys.clone();
        for s in &sigs {
            all.push(Record::new(
                zone, 
                Class::Internet, 
                std::time::Duration::from_secs(300), 
                Resource::RRSIG(s.clone())
            ));
        }
        self.cache.insert_dnskeys(zone, all);

        Ok((keys, sigs))
    }

    /// Queries or fetches cached DS records for `zone`.
    async fn get_zone_ds(&self, zone: &str) -> Result<(Vec<Record>, Vec<RRSIG>), crate::Error> {
        if let Some(cached) = self.cache.get_ds(zone) {
            let mut ds = Vec::new();
            let mut sigs = Vec::new();
            for r in cached {
                if let Resource::RRSIG(s) = &r.resource {
                    sigs.push(s.clone());
                } else {
                    ds.push(r);
                }
            }
            return Ok((ds, sigs));
        }

        // TODO Should we use self.resolver.query instead of creating the message ourselves?
        let mut query = Message::default();
        query.try_add_question(zone, Type::DS, Class::Internet)?;
        query.extension = Some(crate::Extension {
            dnssec_ok: true,
            ..Default::default()
        });

        let resp = self.resolver.exchange_with_deadline(&query, self.deadline).await?;
        let mut ds = Vec::new();
        let mut sigs = Vec::new();

        for r in &resp.answers {
            match &r.resource {
                Resource::DS(_) => ds.push(r.clone()),
                Resource::RRSIG(s) => sigs.push(s.clone()),
                _ => {}
            }
        }

        let mut all = ds.clone();
        for s in &sigs {
            all.push(Record::new(zone, Class::Internet, std::time::Duration::from_secs(300), Resource::RRSIG(s.clone())));
        }
        self.cache.insert_ds(zone, all);

        Ok((ds, sigs))
    }
}
