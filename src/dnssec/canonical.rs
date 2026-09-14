//! DNSSEC canonical name and RRset wire serialization.
//!
//! Conforms to [RFC 4034 §3.1.8 & §6] and [RFC 6840].
//!
//! [RFC 4034 §3.1.8 & §6]: https://datatracker.ietf.org/doc/html/rfc4034#section-6
//! [RFC 6840]: https://datatracker.ietf.org/doc/html/rfc6840

use crate::names::Name;
use crate::resource::RRSIG;
use crate::types::{Record, Resource};
use crate::EncodeError;
use std::time::Duration;

/// Adjusts an owner name for wildcard expansion if necessary ([RFC 4035 §5.3.2]).
///
/// If `rrsig.labels < record_name.count_labels()`, the signature was generated via
/// wildcard expansion (e.g. from a `*.example.com.` RRset). The reconstructed owner
/// name replaces the leftmost excess labels with `*`.
///
/// [RFC 4035 §5.3.2]: https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.2
///
/// # Examples
///
/// Direct match (no wildcard expansion):
/// ```text
/// canonical_owner_for_rrsig(&Name::new("sub.example.com.").unwrap(), 3) == Name::new("sub.example.com.").unwrap()
/// ```
///
/// Wildcard expansion:
/// ```text
/// canonical_owner_for_rrsig(&Name::new("a.b.example.com.").unwrap(), 2) == Name::new("*.example.com.").unwrap()
/// ```
#[must_use]
pub(crate) fn canonical_owner_for_rrsig(record_name: &Name, rrsig_labels: u8) -> Name {
    let current_count = record_name.count_labels();
    if current_count == 0 {
        return Name::root();
    }

    if rrsig_labels < current_count {
        // Wildcard substitution: keep the rightmost `rrsig_labels` and prepend "*."
        let excess = (current_count - rrsig_labels) as usize;
        let trimmed = record_name.as_ascii().trim_end_matches('.');
        let labels: Vec<&str> = trimmed.split('.').collect();
        let suffix = labels[excess..].join(".");
        Name::new(&format!("*.{suffix}.")).expect("valid wildcard domain name").to_canonical()
    } else {
        record_name.to_canonical()
    }
}

/// Appends RDATA in canonical DNSSEC wire format per [RFC 4034 §6.2].
///
/// Any domain names embedded inside RDATA (such as in CNAME, NS, PTR, MX, SOA, SRV,
/// and NSEC records) are converted to lowercase canonical form without compression.
fn append_canonical_rdata_to_vec(
    resource: &Resource,
    buf: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    match resource {
        Resource::CNAME(name) | Resource::NS(name) | Resource::PTR(name) => {
            name.to_canonical().append_to_vec(buf);
        }
        Resource::MX(mx) => {
            buf.extend_from_slice(&mx.preference.to_be_bytes());
            mx.exchange.to_canonical().append_to_vec(buf);
        }
        Resource::SOA(soa) => {
            soa.mname.to_canonical().append_to_vec(buf);
            Name::new(&soa.rname)?.to_canonical().append_to_vec(buf);
            let duration_to_u32 = |duration: Duration| {
                u32::try_from(duration.as_secs()).map_err(|_| EncodeError::DurationTooLong {
                    max: u64::from(u32::MAX),
                })
            };
            for value in [
                soa.serial,
                duration_to_u32(soa.refresh)?,
                duration_to_u32(soa.retry)?,
                duration_to_u32(soa.expire)?,
                duration_to_u32(soa.minimum)?,
            ] {
                buf.extend_from_slice(&value.to_be_bytes());
            }
        }
        Resource::SRV(srv) => {
            buf.extend_from_slice(&srv.priority.to_be_bytes());
            buf.extend_from_slice(&srv.weight.to_be_bytes());
            buf.extend_from_slice(&srv.port.to_be_bytes());
            srv.name.to_canonical().append_to_vec(buf);
        }
        Resource::NSEC(nsec) => {
            nsec.next_domain.to_canonical().append_to_vec(buf);
            crate::resource::NSEC::encode_type_bit_maps(&nsec.types, buf);
        }
        other => {
            other.append_rdata_to_vec(buf)?;
        }
    }
    Ok(())
}

/// Appends an individual RR in canonical DNSSEC wire format to `buf`:
/// `owner_name | type | class | original_ttl | rdata_len | rdata`
///
/// Name and RDATA domain names (if any) are canonicalized (lowercased) without compression.
pub(crate) fn append_canonical_record_to_vec(
    buf: &mut Vec<u8>,
    owner_name: &Name,
    record: &Record,
    original_ttl: Duration,
) -> Result<(), EncodeError> {
    owner_name.to_canonical().append_to_vec(buf);
    buf.extend_from_slice(&record.r#type().code().to_be_bytes());
    buf.extend_from_slice(&(record.class as u16).to_be_bytes());
    let ttl = u32::try_from(original_ttl.as_secs()).map_err(|_| EncodeError::TtlTooLong {
        max: u64::from(u32::MAX),
    })?;
    buf.extend_from_slice(&ttl.to_be_bytes());

    // Serialize RDATA into temporary buffer with canonical domain names
    let mut rdata = Vec::new();
    append_canonical_rdata_to_vec(&record.resource, &mut rdata)?;

    let rdata_len = u16::try_from(rdata.len()).map_err(|_| EncodeError::RdataTooLong {
        max: crate::limits::MAX_RDATA_LEN,
    })?;
    buf.extend_from_slice(&rdata_len.to_be_bytes());
    buf.extend_from_slice(&rdata);

    Ok(())
}

/// Appends the canonical signed data octets for an RRset covered by `rrsig` to `buf` ([RFC 4034 §3.1.8]).
///
/// The signed data consists of:
/// 1. The RRSIG RDATA fields up to the signature field (excluding the signature itself).
/// 2. Canonical wire format representations of each record in the RRset, sorted in canonical RDATA order.
///
/// [RFC 4034 §3.1.8]: https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.8
pub(crate) fn append_signed_data_to_vec(
    buf: &mut Vec<u8>,
    owner_name: &Name,
    rrsig: &RRSIG,
    rrset: &[Record],
) -> Result<(), EncodeError> {
    let orig_ttl = u32::try_from(rrsig.original_ttl.as_secs()).map_err(|_| EncodeError::TtlTooLong {
        max: u64::from(u32::MAX),
    })?;
    let expiration = rrsig.expiration_seconds()?;
    let inception = rrsig.inception_seconds()?;

    // 1. RRSIG RDATA without signature
    buf.extend_from_slice(&rrsig.type_covered.code().to_be_bytes());
    buf.push(rrsig.algorithm.code());
    buf.push(rrsig.labels);
    buf.extend_from_slice(&orig_ttl.to_be_bytes());
    buf.extend_from_slice(&expiration.to_be_bytes());
    buf.extend_from_slice(&inception.to_be_bytes());
    buf.extend_from_slice(&rrsig.key_tag.to_be_bytes());

    // Signer name in canonical wire format (RFC 4034 §3.1.8.1)
    rrsig.signer_name.to_canonical().append_to_vec(buf);

    // 2. Canonical owner name (adjusted for wildcard expansion)
    let canonical_owner = canonical_owner_for_rrsig(owner_name, rrsig.labels);

    // 3. Serialize each record and sort by canonical RDATA (RFC 4034 §6.3)
    let mut encoded_records = Vec::with_capacity(rrset.len());
    for rr in rrset {
        let mut wire = Vec::new();
        append_canonical_record_to_vec(&mut wire, &canonical_owner, rr, rrsig.original_ttl)?;
        encoded_records.push(wire);
    }

    // Sort canonical records (canonical wire ordering compares octets left-to-right as unsigned bytes)
    encoded_records.sort();

    for wire in encoded_records {
        buf.extend_from_slice(&wire);
    }

    Ok(())
}

/// Constructs the canonical signed data octets for an RRset covered by `rrsig` ([RFC 4034 §3.1.8]).
///
/// Convenience wrapper allocating a new `Vec<u8>` via [`append_signed_data_to_vec`].
///
/// [RFC 4034 §3.1.8]: https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.8
#[cfg(test)]
pub(crate) fn signed_data_to_vec(
    owner_name: &Name,
    rrsig: &RRSIG,
    rrset: &[Record],
) -> Result<Vec<u8>, EncodeError> {
    let mut data = Vec::new();
    append_signed_data_to_vec(&mut data, owner_name, rrsig, rrset)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Class, Resource, Type};
    use std::time::Duration;

    #[test]
    fn test_count_labels() {
        assert_eq!(Name::root().count_labels(), 0);
        assert_eq!(Name::new("com.").unwrap().count_labels(), 1);
        assert_eq!(Name::new("example.com.").unwrap().count_labels(), 2);
        assert_eq!(Name::new("a.b.c.example.com").unwrap().count_labels(), 5);
    }

    #[test]
    fn test_canonical_owner_wildcard() {
        let sub = Name::new("sub.example.com.").unwrap();
        // No wildcard expansion
        assert_eq!(
            canonical_owner_for_rrsig(&sub, 3),
            sub
        );
        // Wildcard expansion: labels = 2, owner has 3 labels -> "*.example.com."
        assert_eq!(
            canonical_owner_for_rrsig(&sub, 2),
            Name::new("*.example.com.").unwrap()
        );
    }

    #[test]
    fn test_canonical_record_sorting() {
        let owner = Name::new("example.com.").unwrap();
        let r1 = Record::new(
            owner.clone(),
            Class::Internet,
            Duration::from_secs(300),
            Resource::A("192.0.2.2".parse().unwrap()),
        );
        let r2 = Record::new(
            owner.clone(),
            Class::Internet,
            Duration::from_secs(300),
            Resource::A("192.0.2.1".parse().unwrap()),
        );

        let rrsig = RRSIG {
            type_covered: Type::A,
            algorithm: crate::types::Algorithm::ECDSAP256SHA256,
            labels: 2,
            original_ttl: Duration::from_secs(300),
            expiration: std::time::UNIX_EPOCH + Duration::from_secs(1000),
            inception: std::time::UNIX_EPOCH + Duration::from_secs(500),
            key_tag: 1234,
            signer_name: Name::new("example.com.").unwrap(),
            signature: vec![1, 2, 3],
        };

        let signed = signed_data_to_vec(&owner, &rrsig, &[r1, r2]).unwrap();
        assert!(!signed.is_empty());
    }

    #[test]
    fn test_canonical_owner_casing() {
        let mixed = Name::new("SuB.ExAmPlE.cOm.").unwrap();
        assert_eq!(mixed.as_ascii(), "SuB.ExAmPlE.cOm.");

        // Direct match produces lowercase canonical name
        let owner_direct = canonical_owner_for_rrsig(&mixed, 3);
        assert_eq!(owner_direct.as_ascii(), "sub.example.com.");
        assert!(owner_direct.is_canonical());

        // Wildcard match produces lowercase canonical wildcard
        let owner_wild = canonical_owner_for_rrsig(&mixed, 2);
        assert_eq!(owner_wild.as_ascii(), "*.example.com.");
        assert!(owner_wild.is_canonical());
    }

    #[test]
    fn test_canonical_signed_data_case_invariance() {
        // Lowercase signed data
        let lower_owner = Name::new("www.example.com.").unwrap();
        let lower_signer = Name::new("example.com.").unwrap();
        let lower_cname = Record::new(
            lower_owner.clone(),
            Class::Internet,
            Duration::from_secs(300),
            Resource::CNAME(Name::new("target.example.com.").unwrap()),
        );
        let lower_rrsig = RRSIG {
            type_covered: Type::CNAME,
            algorithm: crate::types::Algorithm::ECDSAP256SHA256,
            labels: 3,
            original_ttl: Duration::from_secs(300),
            expiration: std::time::UNIX_EPOCH + Duration::from_secs(1000),
            inception: std::time::UNIX_EPOCH + Duration::from_secs(500),
            key_tag: 1234,
            signer_name: lower_signer,
            signature: vec![1, 2, 3],
        };
        let lower_wire = signed_data_to_vec(&lower_owner, &lower_rrsig, &[lower_cname]).unwrap();

        // Mixed-case (0x20) signed data
        let mixed_owner = Name::new("wWw.ExAmPlE.cOm.").unwrap();
        let mixed_signer = Name::new("ExAmPlE.cOm.").unwrap();
        let mixed_cname = Record::new(
            mixed_owner.clone(),
            Class::Internet,
            Duration::from_secs(300),
            Resource::CNAME(Name::new("TaRgEt.ExAmPlE.cOm.").unwrap()),
        );
        let mixed_rrsig = RRSIG {
            type_covered: Type::CNAME,
            algorithm: crate::types::Algorithm::ECDSAP256SHA256,
            labels: 3,
            original_ttl: Duration::from_secs(300),
            expiration: std::time::UNIX_EPOCH + Duration::from_secs(1000),
            inception: std::time::UNIX_EPOCH + Duration::from_secs(500),
            key_tag: 1234,
            signer_name: mixed_signer,
            signature: vec![1, 2, 3],
        };
        let mixed_wire = signed_data_to_vec(&mixed_owner, &mixed_rrsig, &[mixed_cname]).unwrap();

        // RFC 4034 §6.2: canonical signed data MUST be identical regardless of input casing
        assert_eq!(lower_wire, mixed_wire);
    }
}
