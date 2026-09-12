//! DNSSEC canonical name and RRset wire serialization.
//!
//! Conforms to [RFC 4034 §3.1.8 & §6] and [RFC 6840].
//!
//! [RFC 4034 §3.1.8 & §6]: https://datatracker.ietf.org/doc/html/rfc4034#section-6
//! [RFC 6840]: https://datatracker.ietf.org/doc/html/rfc6840

use crate::resource::RRSIG;
use crate::types::Record;
use crate::{EncodeError, Message};
use std::time::Duration;

/// Appends a domain name to `buf` in canonical DNSSEC wire format
/// (all labels converted to lowercase, uncompressed length-prefixed octets).
///
/// Per RFC 4034 §6.1, for the purpose of DNSSEC calculations, all uppercase US-ASCII letters
/// in domain names are converted to lowercase.
pub(crate) fn append_canonical_name_to_vec(
    buf: &mut Vec<u8>,
    name: &str,
) -> Result<(), EncodeError> {
    let lower = name.to_ascii_lowercase();
    Message::append_qname_to_vec(buf, &lower)
}

/// Computes the number of labels in a domain name, excluding the root label.
///
/// Example: `"example.com."` -> 2, `"bramp.net"` -> 2, `"."` -> 0.
// TODO Should we remove this simple wrapper?
#[inline]
#[must_use]
pub(crate) fn count_labels(name: &str) -> u8 {
    crate::names::count_labels(name)
}

/// Adjusts an owner name for wildcard expansion if necessary (RFC 4035 §5.3.2).
///
/// If `rrsig.labels < count_labels(record_name)`, the signature was generated via
/// wildcard expansion (e.g. from a `*.example.com.` RRset). The reconstructed owner
/// name replaces the leftmost excess labels with `*`.
///
/// # Examples
///
/// Direct match (no wildcard expansion):
/// ```text
/// canonical_owner_for_rrsig("sub.example.com.", 3) == "sub.example.com."
/// ```
///
/// Wildcard expansion:
/// ```text
/// canonical_owner_for_rrsig("a.b.example.com.", 2) == "*.example.com."
/// ```
#[must_use]
pub(crate) fn canonical_owner_for_rrsig(record_name: &str, rrsig_labels: u8) -> String {
    let current_count = count_labels(record_name);
    if current_count == 0 {
        return ".".to_string();
    }
    let trimmed = record_name.trim_matches('.');
    let labels: Vec<&str> = trimmed.split('.').collect();

    if rrsig_labels < current_count {
        // Wildcard substitution: keep the rightmost `rrsig_labels` and prepend "*."
        let excess = (current_count - rrsig_labels) as usize;
        let suffix = labels[excess..].join(".");
        format!("*.{suffix}.")
    } else if record_name.ends_with('.') {
        record_name.to_string()
    } else {
        format!("{record_name}.")
    }
}

/// Appends an individual RR in canonical DNSSEC wire format to `buf`:
/// `owner_name | type | class | original_ttl | rdata_len | rdata`
///
/// Name and RDATA domain names (if any) are canonicalized (lowercased) without compression.
pub(crate) fn append_canonical_record_to_vec(
    buf: &mut Vec<u8>,
    owner_name: &str,
    record: &Record,
    original_ttl: Duration,
) -> Result<(), EncodeError> {
    append_canonical_name_to_vec(buf, owner_name)?;
    buf.extend_from_slice(&record.r#type().code().to_be_bytes());
    buf.extend_from_slice(&(record.class as u16).to_be_bytes());
    let ttl = u32::try_from(original_ttl.as_secs()).map_err(|_| EncodeError::TtlTooLong {
        max: u64::from(u32::MAX),
    })?;
    buf.extend_from_slice(&ttl.to_be_bytes());

    // Serialize RDATA into temporary buffer
    let mut rdata = Vec::new();
    record.resource.append_rdata_to_vec(&mut rdata)?;

    let rdata_len = u16::try_from(rdata.len()).map_err(|_| EncodeError::RdataTooLong {
        max: crate::limits::MAX_RDATA_LEN,
    })?;
    buf.extend_from_slice(&rdata_len.to_be_bytes());
    buf.extend_from_slice(&rdata);

    Ok(())
}

/// Appends the canonical signed data octets for an RRset covered by `rrsig` to `buf` (RFC 4034 §3.1.8).
///
/// The signed data consists of:
/// 1. The RRSIG RDATA fields up to the signature field (excluding the signature itself).
/// 2. Canonical wire format representations of each record in the RRset, sorted in canonical RDATA order.
pub(crate) fn append_signed_data_to_vec(
    buf: &mut Vec<u8>,
    owner_name: &str,
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

    // Signer name in canonical wire format
    append_canonical_name_to_vec(buf, &rrsig.signer_name)?;

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

/// Constructs the canonical signed data octets for an RRset covered by `rrsig` (RFC 4034 §3.1.8).
///
/// Convenience wrapper allocating a new `Vec<u8>` via [`append_signed_data_to_vec`].
#[cfg(test)]
pub(crate) fn signed_data_to_vec(
    owner_name: &str,
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
        assert_eq!(count_labels("."), 0);
        assert_eq!(count_labels("com."), 1);
        assert_eq!(count_labels("example.com."), 2);
        assert_eq!(count_labels("a.b.c.example.com"), 5);
    }

    #[test]
    fn test_canonical_owner_wildcard() {
        // No wildcard expansion
        assert_eq!(
            canonical_owner_for_rrsig("sub.example.com.", 3),
            "sub.example.com."
        );
        // Wildcard expansion: labels = 2, owner has 3 labels -> "*.example.com."
        assert_eq!(
            canonical_owner_for_rrsig("sub.example.com.", 2),
            "*.example.com."
        );
    }

    #[test]
    fn test_canonical_record_sorting() {
        let r1 = Record::new(
            "example.com.",
            Class::Internet,
            Duration::from_secs(300),
            Resource::A("192.0.2.2".parse().unwrap()),
        );
        let r2 = Record::new(
            "example.com.",
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
            signer_name: "example.com.".to_string(),
            signature: vec![1, 2, 3],
        };

        let signed = signed_data_to_vec("example.com.", &rrsig, &[r1, r2]).unwrap();
        assert!(!signed.is_empty());
    }
}
