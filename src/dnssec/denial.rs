//! Authenticated Denial of Existence proofs for DNSSEC.
//!
//! Conforms to [RFC 4034 §4 & §6], [RFC 4035 §5.4] (NSEC), and [RFC 5155 §5 & §8] (NSEC3).
//!
//! [RFC 4034 §4 & §6]: https://datatracker.ietf.org/doc/html/rfc4034#section-6
//! [RFC 4035 §5.4]: https://datatracker.ietf.org/doc/html/rfc4035#section-5.4
//! [RFC 5155 §5 & §8]: https://datatracker.ietf.org/doc/html/rfc5155#section-8

use crate::EncodeError;
use crate::dnssec::canonical::append_canonical_name_to_vec;
pub use crate::names::{canonical_cmp, canonical_name_cmp};
use crate::resource::{NSEC, NSEC3};
use crate::types::Type;
use std::cmp::Ordering;

/// Checks whether an NSEC record's interval covers `name` in canonical DNS name order ([RFC 4035 §5.4]).
///
/// An NSEC record with owner $O$ and next domain $N$ covers target $T$ if:
/// - In the standard non-wrapping case ($O < N$): $O < T < N$.
/// - In the circular zone wrap-around case ($O \ge N$): $T > O$ or $T < N$.
#[must_use]
pub fn nsec_covers(owner: &str, next_domain: &str, name: &str) -> bool {
    let cmp_on = canonical_name_cmp(owner, next_domain);
    let cmp_ot = canonical_name_cmp(owner, name);
    let cmp_tn = canonical_name_cmp(name, next_domain);

    match cmp_on {
        Ordering::Less => cmp_ot == Ordering::Less && cmp_tn == Ordering::Less,
        Ordering::Greater | Ordering::Equal => {
            cmp_ot == Ordering::Less || cmp_tn == Ordering::Less
        }
    }
}

/// Verifies an NSEC No Data (NODATA) proof per [RFC 4035 §5.4].
///
/// Proves that the queried `qname` exists but has no records of type `qtype`.
/// Requires that:
/// - The NSEC owner name matches `qname` exactly.
/// - `qtype` is NOT present in the NSEC types bitmap.
/// - `CNAME` is NOT present in the NSEC types bitmap (otherwise the query would follow CNAME).
#[must_use]
pub fn verify_nsec_nodata(nsec: &NSEC, nsec_owner: &str, qname: &str, qtype: Type) -> bool {
    if canonical_name_cmp(nsec_owner, qname) != Ordering::Equal {
        return false;
    }
    !nsec.types.contains(&qtype) && !nsec.types.contains(&Type::CNAME)
}

/// Verifies an NSEC Name Error (NXDOMAIN) proof per [RFC 4035 §5.4].
///
/// Proves that `qname` does not exist and could not have been synthesized by a wildcard.
/// Requires:
/// 1. An NSEC record covering `qname`.
/// 2. An NSEC record covering the wildcard under the closest enclosing ancestor (or zone apex).
#[must_use]
pub fn verify_nsec_nxdomain(nsecs: &[(&str, &NSEC)], qname: &str, zone: &str) -> bool {
    let qname_covered = nsecs
        .iter()
        .any(|(owner, nsec)| nsec_covers(owner, &nsec.next_domain, qname));

    if !qname_covered {
        return false;
    }

    // Check wildcard non-existence (*.<closest_enclosing_ancestor>)
    let wildcard = format!("*.{zone}");
    nsecs
        .iter()
        .any(|(owner, nsec)| nsec_covers(owner, &nsec.next_domain, &wildcard))
}

/// Computes the NSEC3 hashed owner name for a domain name per [RFC 5155 §5].
///
/// Implements $IH(\text{salt}, x, \text{iterations})$ where $x$ is the uncompressed canonical
/// wire-format encoding of `name` (lowercased) and hash algorithm is SHA-1.
///
/// # Errors
///
/// Returns [`EncodeError`] if canonical name serialization fails.
pub fn nsec3_hash(name: &str, salt: &[u8], iterations: u16) -> Result<Vec<u8>, EncodeError> {
    let mut wire = Vec::new();
    append_canonical_name_to_vec(&mut wire, name)?;

    // Initial hash: SHA-1(wire || salt)
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(&wire);
    ctx.update(salt);
    let mut digest = ctx.finish();

    // Iterations: SHA-1(digest || salt)
    for _ in 0..iterations {
        let mut next_ctx = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
        next_ctx.update(digest.as_ref());
        next_ctx.update(salt);
        digest = next_ctx.finish();
    }

    Ok(digest.as_ref().to_vec())
}

/// Checks whether an NSEC3 record covers a target hash in the circular NSEC3 hash ring ([RFC 5155 §8.4]).
///
/// - If `owner_hash < next_hash`: covers $T$ where $\text{owner\_hash} < T < \text{next\_hash}$.
/// - If `owner_hash \ge next_hash` (wrap-around): covers $T$ where $T > \text{owner\_hash}$ or $T < \text{next\_hash}$.
///
/// [RFC 5155 §8.4]: https://datatracker.ietf.org/doc/html/rfc5155#section-8.4
#[must_use]
pub fn nsec3_covers(owner_hash: &[u8], next_hash: &[u8], target_hash: &[u8]) -> bool {
    let cmp_on = owner_hash.cmp(next_hash);
    let cmp_ot = owner_hash.cmp(target_hash);
    let cmp_tn = target_hash.cmp(next_hash);

    match cmp_on {
        Ordering::Less => cmp_ot == Ordering::Less && cmp_tn == Ordering::Less,
        Ordering::Greater | Ordering::Equal => {
            cmp_ot == Ordering::Less || cmp_tn == Ordering::Less
        }
    }
}

/// Verifies an NSEC3 No Data (NODATA) proof per [RFC 5155 §8.5].
///
/// Proves that `qname_hash` exists, but has no records of type `qtype`.
///
/// [RFC 5155 §8.5]: https://datatracker.ietf.org/doc/html/rfc5155#section-8.5
#[must_use]
pub fn verify_nsec3_nodata(
    nsec3: &NSEC3,
    nsec3_owner_hash: &[u8],
    qname_hash: &[u8],
    qtype: Type,
) -> bool {
    if nsec3_owner_hash != qname_hash {
        return false;
    }
    !nsec3.types.contains(&qtype) && !nsec3.types.contains(&Type::CNAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_name_order_rfc4034_example() {
        // RFC 4034 §6.1 sorting example
        let sorted = [
            "example",
            "a.example",
            "yljkjljk.a.example",
            "Z.a.example",
            "zABC.a.EXAMPLE",
            "z.example",
            "\x01.z.example",
            "*.z.example",
            "\u{0080}.z.example",
        ];

        for i in 0..sorted.len() {
            for j in 0..sorted.len() {
                let expected = i.cmp(&j);
                let actual = canonical_name_cmp(sorted[i], sorted[j]);
                assert_eq!(
                    actual, expected,
                    "comparison failed between '{}' and '{}'",
                    sorted[i], sorted[j]
                );
            }
        }
    }

    #[test]
    fn test_nsec_covers_standard_and_wraparound() {
        // Standard range: a.example.com -> c.example.com
        assert!(nsec_covers(
            "a.example.com",
            "c.example.com",
            "b.example.com"
        ));
        assert!(!nsec_covers(
            "a.example.com",
            "c.example.com",
            "a.example.com"
        ));
        assert!(!nsec_covers(
            "a.example.com",
            "c.example.com",
            "c.example.com"
        ));
        assert!(!nsec_covers(
            "a.example.com",
            "c.example.com",
            "d.example.com"
        ));

        // Circular wrap-around: z.example.com -> a.example.com
        assert!(nsec_covers(
            "z.example.com",
            "a.example.com",
            "zz.example.com"
        ));
        assert!(nsec_covers(
            "z.example.com",
            "a.example.com",
            "0.example.com"
        ));
        assert!(!nsec_covers(
            "z.example.com",
            "a.example.com",
            "m.example.com"
        ));
    }

    #[test]
    fn test_verify_nsec_nodata() {
        let nsec = NSEC {
            next_domain: "host.example.com.".to_string(),
            types: vec![Type::A, Type::MX, Type::RRSIG, Type::NSEC],
        };

        // Querying for AAAA on alfa.example.com should succeed (NODATA proof)
        assert!(verify_nsec_nodata(
            &nsec,
            "alfa.example.com.",
            "alfa.example.com.",
            Type::AAAA
        ));

        // Querying for A should fail (A exists)
        assert!(!verify_nsec_nodata(
            &nsec,
            "alfa.example.com.",
            "alfa.example.com.",
            Type::A
        ));

        // Mismatched name should fail
        assert!(!verify_nsec_nodata(
            &nsec,
            "alfa.example.com.",
            "beta.example.com.",
            Type::AAAA
        ));
    }

    #[test]
    fn test_verify_nsec_nxdomain() {
        let nsec_name = NSEC {
            next_domain: "d.example.com.".to_string(),
            types: vec![Type::A, Type::RRSIG, Type::NSEC],
        };
        // In canonical order, example.com. < *.example.com. < a.example.com.
        let nsec_wildcard = NSEC {
            next_domain: "a.example.com.".to_string(),
            types: vec![Type::SOA, Type::NS, Type::RRSIG, Type::NSEC],
        };

        let nsecs = [
            ("b.example.com.", &nsec_name),         // covers c.example.com
            ("example.com.", &nsec_wildcard),       // covers *.example.com
        ];

        assert!(verify_nsec_nxdomain(&nsecs, "c.example.com.", "example.com."));
        assert!(!verify_nsec_nxdomain(&nsecs, "e.example.com.", "example.com."));
    }

    #[cfg(feature = "dnssec")]
    #[test]
    fn test_rfc5155_nsec3_hash_vector() {
        // RFC 5155 Appendix A test vector:
        // Zone: example.
        // NSEC3PARAM: 1 0 12 aabbccdd
        // H(example.) = 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom
        let salt = crate::util::hex_decode("aabbccdd").unwrap();
        let hash = nsec3_hash("example.", &salt, 12).expect("nsec3_hash should succeed");
        let b32_hash = crate::util::base32hex_encode(&hash).to_ascii_lowercase();
        assert_eq!(b32_hash, "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom");
    }

    #[test]
    fn test_nsec3_covers() {
        let h1 = [0x10];
        let h2 = [0x30];
        let target_in = [0x20];
        let target_out = [0x40];

        // Standard range [0x10, 0x30)
        assert!(nsec3_covers(&h1, &h2, &target_in));
        assert!(!nsec3_covers(&h1, &h2, &target_out));

        // Wrap around [0x30, 0x10)
        assert!(nsec3_covers(&h2, &h1, &[0x40]));
        assert!(nsec3_covers(&h2, &h1, &[0x05]));
        assert!(!nsec3_covers(&h2, &h1, &[0x20]));
    }
}
