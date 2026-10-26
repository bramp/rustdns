//! Authenticated Denial of Existence proofs for DNSSEC.
//!
//! Conforms to [RFC 4034 §4 & §6], [RFC 4035 §5.4] (NSEC), and [RFC 5155 §5 & §8] (NSEC3).
//!
//! [RFC 4034 §4 & §6]: https://datatracker.ietf.org/doc/html/rfc4034#section-6
//! [RFC 4035 §5.4]: https://datatracker.ietf.org/doc/html/rfc4035#section-5.4
//! [RFC 5155 §5 & §8]: https://datatracker.ietf.org/doc/html/rfc5155#section-8

use crate::names::Name;
use crate::resource::{NSEC, NSEC3};
use crate::types::Type;
use std::cmp::Ordering;

#[cfg(feature = "resolver")]
const MAX_NSEC3_PROOFS: usize = 128;
#[cfg(feature = "resolver")]
const MAX_NSEC3_ITERATIONS: u16 = 150;

/// Checks whether an NSEC record's interval covers `name` in canonical DNS name order ([RFC 4035 §5.4]).
///
/// An NSEC record with owner $O$ and next domain $N$ covers target $T$ if:
/// - In the standard non-wrapping case ($O < N$): $O < T < N$.
/// - In the circular zone wrap-around case ($O \ge N$): $T > O$ or $T < N$.
#[must_use]
pub fn nsec_covers(owner: &Name, next_domain: &Name, name: &Name) -> bool {
    match owner.cmp(next_domain) {
        Ordering::Less => owner < name && name < next_domain,
        Ordering::Greater | Ordering::Equal => name > owner || name < next_domain,
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
pub fn verify_nsec_nodata(nsec: &NSEC, nsec_owner: &Name, qname: &Name, qtype: Type) -> bool {
    if nsec_owner != qname {
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
pub fn verify_nsec_nxdomain(nsecs: &[(&Name, &NSEC)], qname: &Name, zone: &Name) -> bool {
    if !qname.is_subdomain_of(zone)
        || qname == zone
        || nsecs.iter().any(|(owner, nsec)| {
            !owner.is_subdomain_of(zone)
                || !nsec.next_domain.is_subdomain_of(zone)
                || **owner == *qname
                || nsec.next_domain == *qname
                || owner.is_subdomain_of(qname)
                || nsec.next_domain.is_subdomain_of(qname)
        })
    {
        return false;
    }
    let qname_covered = nsecs
        .iter()
        .any(|(owner, nsec)| nsec_covers(owner, &nsec.next_domain, qname));

    if !qname_covered {
        return false;
    }

    let Some(closest) = closest_nsec_encloser(nsecs, qname, zone) else {
        return false;
    };
    let Some(next) = next_closer(qname, &closest) else {
        return false;
    };
    if !nsecs
        .iter()
        .any(|(owner, nsec)| nsec_covers(owner, &nsec.next_domain, &next))
    {
        return false;
    }
    let Some(wildcard) = wildcard_name(&closest) else {
        return false;
    };
    if nsecs
        .iter()
        .any(|(owner, nsec)| **owner == wildcard || nsec.next_domain == wildcard)
    {
        return false;
    }
    nsecs
        .iter()
        .any(|(owner, nsec)| nsec_covers(owner, &nsec.next_domain, &wildcard))
}

fn wildcard_name(closest: &Name) -> Option<Name> {
    let text = if closest.is_root() {
        "*.".into()
    } else {
        format!("*.{}", closest.as_ascii())
    };
    Name::from_presentation(&text).ok()
}

fn closest_nsec_encloser(nsecs: &[(&Name, &NSEC)], qname: &Name, zone: &Name) -> Option<Name> {
    let mut candidate = qname.parent();
    while let Some(name) = candidate {
        if !name.is_subdomain_of(zone) {
            break;
        }
        if name == *zone
            || nsecs.iter().any(|(owner, nsec)| {
                owner.is_subdomain_of(&name) || nsec.next_domain.is_subdomain_of(&name)
            })
        {
            return Some(name);
        }
        candidate = name.parent();
    }
    None
}

#[cfg(feature = "resolver")]
pub(crate) fn verify_nsec_response(
    records: &[crate::Record],
    qname: &Name,
    qtype: Type,
    zone: &Name,
    nxdomain: bool,
) -> bool {
    let nsecs: Vec<_> = records
        .iter()
        .filter_map(|record| match &record.resource {
            crate::Resource::NSEC(nsec) => Some((&record.name, nsec)),
            _ => None,
        })
        .collect();
    if nsecs.is_empty()
        || qtype == Type::ANY
        || !qname.is_subdomain_of(zone)
        || nsecs.iter().any(|(owner, nsec)| {
            !owner.is_subdomain_of(zone)
                || !nsec.next_domain.is_subdomain_of(zone)
                || (nsec.types.contains(&Type::NS)
                    && !nsec.types.contains(&Type::SOA)
                    && qname.is_subdomain_of(owner)
                    && **owner != *qname)
                || nsec.types.contains(&Type::DNAME)
                    && qname.is_subdomain_of(owner)
                    && **owner != *qname
        })
    {
        return false;
    }
    if nxdomain {
        return verify_nsec_nxdomain(&nsecs, qname, zone);
    }
    if nsecs.iter().any(|(owner, _)| **owner == *qname) {
        return nsecs.iter().any(|(owner, nsec)| {
            verify_nsec_nodata(nsec, owner, qname, qtype)
                && (qtype == Type::DS
                    || !nsec.types.contains(&Type::NS)
                    || nsec.types.contains(&Type::SOA))
        });
    }
    // An interval ending below qname proves that qname is an empty nonterminal.
    if nsecs.iter().any(|(owner, nsec)| {
        nsec_covers(owner, &nsec.next_domain, qname)
            && nsec.next_domain != *qname
            && nsec.next_domain.is_subdomain_of(qname)
    }) {
        return true;
    }
    let Some(closest) = closest_nsec_encloser(&nsecs, qname, zone) else {
        return false;
    };
    let Some(wildcard) = wildcard_name(&closest) else {
        return false;
    };
    let Some(next) = next_closer(qname, &closest) else {
        return false;
    };
    nsecs
        .iter()
        .any(|(owner, nsec)| nsec_covers(owner, &nsec.next_domain, &next))
        && nsecs.iter().any(|(owner, nsec)| {
            verify_nsec_nodata(nsec, owner, &wildcard, qtype)
                && (!nsec.types.contains(&Type::NS) || nsec.types.contains(&Type::SOA))
        })
}

#[cfg(feature = "resolver")]
pub(crate) fn verify_unsigned_delegation(
    records: &[crate::Record],
    child: &Name,
    zone: &Name,
) -> bool {
    if child == zone || !child.is_subdomain_of(zone) {
        return false;
    }
    records.iter().any(|record| match &record.resource {
        crate::Resource::NSEC(nsec) => {
            record.name == *child
                && nsec.next_domain.is_subdomain_of(zone)
                && nsec.types.contains(&Type::NS)
                && !nsec
                    .types
                    .iter()
                    .any(|rtype| matches!(rtype, Type::DS | Type::SOA | Type::CNAME))
        }
        _ => false,
    }) || verify_nsec3_response(records, child, Type::DS, zone, false, true)
}

#[cfg(feature = "resolver")]
pub(crate) fn verify_nsec3_response(
    records: &[crate::Record],
    qname: &Name,
    qtype: Type,
    zone: &Name,
    nxdomain: bool,
    delegation_only: bool,
) -> bool {
    // Bounds apply before hashing. At most 128 ancestors and two additional
    // names are hashed, each with at most 151 SHA-1 operations.
    let Some(entries) = nsec3_entries(records, zone) else {
        return false;
    };
    let Some((_, parameters)) = entries.first() else {
        return false;
    };
    if qtype == Type::ANY
        || !qname.is_subdomain_of(zone)
        || entries.iter().any(|(_, entry)| {
            entry.salt != parameters.salt || entry.iterations != parameters.iterations
        })
    {
        return false;
    }
    let hash = |name: &Name| nsec3_hash(name, &parameters.salt, parameters.iterations);
    let qhash = hash(qname);
    if let Some((_, exact)) = entries.iter().find(|(owner, _)| *owner == qhash) {
        return !nxdomain
            && !exact.types.contains(&qtype)
            && !exact.types.contains(&Type::CNAME)
            && if delegation_only {
                qtype == Type::DS
                    && exact.types.contains(&Type::NS)
                    && !exact.types.contains(&Type::SOA)
            } else {
                qtype == Type::DS
                    || !exact.types.contains(&Type::NS)
                    || exact.types.contains(&Type::SOA)
            };
    }

    let mut candidate = qname.parent();
    let mut closest = None;
    while let Some(name) = candidate {
        if !name.is_subdomain_of(zone) {
            break;
        }
        let hashed = hash(&name);
        if let Some((_, entry)) = entries.iter().find(|(owner, _)| *owner == hashed) {
            if entry.types.contains(&Type::DNAME)
                || entry.types.contains(&Type::NS) && !entry.types.contains(&Type::SOA)
            {
                return false;
            }
            closest = Some(name);
            break;
        }
        candidate = name.parent();
    }
    let Some(closest) = closest else { return false };
    let Some(next) = next_closer(qname, &closest) else {
        return false;
    };
    let next_hash = hash(&next);
    let Some((_, cover)) = entries
        .iter()
        .find(|(owner, entry)| nsec3_covers(owner, &entry.next_hashed_owner_name, &next_hash))
    else {
        return false;
    };
    if delegation_only {
        // RFC 5155 §8.9: closest-encloser proof plus an Opt-Out next-closer span.
        return qtype == Type::DS && cover.flags & 1 != 0;
    }
    if cover.flags & 1 != 0 {
        return false;
    }
    let Some(wildcard) = wildcard_name(&closest) else {
        return false;
    };
    let wildcard_hash = hash(&wildcard);
    if nxdomain {
        if entries.iter().any(|(owner, _)| *owner == wildcard_hash) {
            return false;
        }
        entries.iter().any(|(owner, entry)| {
            entry.flags & 1 == 0
                && nsec3_covers(owner, &entry.next_hashed_owner_name, &wildcard_hash)
        })
    } else {
        entries.iter().any(|(owner, entry)| {
            *owner == wildcard_hash
                && !entry.types.contains(&qtype)
                && !entry.types.contains(&Type::CNAME)
                && (!entry.types.contains(&Type::NS) || entry.types.contains(&Type::SOA))
        })
    }
}

#[cfg(feature = "resolver")]
fn nsec3_entries<'a>(
    records: &'a [crate::Record],
    zone: &Name,
) -> Option<Vec<(Vec<u8>, &'a NSEC3)>> {
    let mut entries = Vec::new();
    for record in records {
        let crate::Resource::NSEC3(entry) = &record.resource else {
            continue;
        };
        if entries.len() >= MAX_NSEC3_PROOFS
            || entry.hash_algorithm != crate::Nsec3HashAlgorithm::Sha1
            || entry.flags & !1 != 0
            || entry.iterations > MAX_NSEC3_ITERATIONS
            || entry.salt.len() > 255
            || entry.next_hashed_owner_name.len() != 20
            || record.name.parent().as_ref() != Some(zone)
        {
            return None;
        }
        let label = std::str::from_utf8(record.name.labels().next()?).ok()?;
        let owner = crate::util::base32hex_decode(label).ok()?;
        if owner.len() != 20 || !crate::util::base32hex_encode(&owner).eq_ignore_ascii_case(label) {
            return None;
        }
        if entries.iter().any(|(_, prior): &(Vec<u8>, &NSEC3)| {
            prior.salt != entry.salt || prior.iterations != entry.iterations
        }) {
            return None;
        }
        entries.push((owner, entry));
    }
    Some(entries)
}

#[cfg(feature = "resolver")]
pub(crate) fn verify_wildcard_expansion(
    records: &[crate::Record],
    name: &Name,
    labels: u8,
    zone: &Name,
) -> bool {
    if labels >= name.count_labels() {
        return false;
    }
    let mut closest = name.clone();
    while closest.count_labels() > labels {
        let Some(parent) = closest.parent() else {
            return false;
        };
        closest = parent;
    }
    if !closest.is_subdomain_of(zone) {
        return false;
    }
    let Some(next) = next_closer(name, &closest) else {
        return false;
    };
    let nsecs: Vec<_> = records
        .iter()
        .filter_map(|record| match &record.resource {
            crate::Resource::NSEC(nsec) => Some((&record.name, nsec)),
            _ => None,
        })
        .collect();
    if nsecs
        .iter()
        .all(|(owner, nsec)| owner.is_subdomain_of(zone) && nsec.next_domain.is_subdomain_of(zone))
        && !nsecs.iter().any(|(owner, nsec)| {
            name.is_subdomain_of(owner)
                && (nsec.types.contains(&Type::DNAME)
                    || nsec.types.contains(&Type::NS) && !nsec.types.contains(&Type::SOA))
        })
        && !nsecs.iter().any(|(owner, nsec)| {
            owner.is_subdomain_of(&next) || nsec.next_domain.is_subdomain_of(&next)
        })
        && nsecs
            .iter()
            .any(|(owner, nsec)| nsec_covers(owner, &nsec.next_domain, &next))
    {
        return true;
    }
    let Some(entries) = nsec3_entries(records, zone) else {
        return false;
    };
    let Some((_, parameters)) = entries.first() else {
        return false;
    };
    let closest_hash = nsec3_hash(&closest, &parameters.salt, parameters.iterations);
    let next_hash = nsec3_hash(&next, &parameters.salt, parameters.iterations);
    entries.iter().any(|(owner, entry)| {
        *owner == closest_hash
            && !entry.types.contains(&Type::DNAME)
            && (!entry.types.contains(&Type::NS) || entry.types.contains(&Type::SOA))
    }) && !entries.iter().any(|(owner, _)| *owner == next_hash)
        && entries.iter().any(|(owner, entry)| {
            entry.flags & 1 == 0 && nsec3_covers(owner, &entry.next_hashed_owner_name, &next_hash)
        })
}

fn next_closer(name: &Name, closest: &Name) -> Option<Name> {
    let mut candidate = name.clone();
    while let Some(parent) = candidate.parent() {
        if parent == *closest {
            return Some(candidate);
        }
        candidate = parent;
    }
    None
}

/// Computes the NSEC3 hashed owner name for a domain name per [RFC 5155 §5].
///
/// Implements $IH(\text{salt}, x, \text{iterations})$ where $x$ is the uncompressed canonical
/// wire-format encoding of `name` (lowercased) and hash algorithm is SHA-1.
///
/// This primitive performs the caller-specified iteration count. Local response
/// validation separately limits untrusted NSEC3 records to 150 iterations.
#[must_use]
pub fn nsec3_hash(name: &Name, salt: &[u8], iterations: u16) -> Vec<u8> {
    let mut wire = Vec::new();
    name.to_canonical().append_to_vec(&mut wire);

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

    digest.as_ref().to_vec()
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
        Ordering::Greater | Ordering::Equal => cmp_ot == Ordering::Less || cmp_tn == Ordering::Less,
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
        // TODO We seem to ave this list in multiple places in the code base. Are we testing the same thing twice? should we dedup?
        // RFC 4034 §6.1 sorting example (valid IDNA domain subset)
        let sorted = [
            Name::new("example").unwrap(),
            Name::new("a.example").unwrap(),
            Name::new("yljkjljk.a.example").unwrap(),
            Name::new("Z.a.example").unwrap(),
            Name::new("zABC.a.EXAMPLE").unwrap(),
            Name::new("z.example").unwrap(),
            Name::new("\x01.z.example").unwrap(),
            Name::new("*.z.example").unwrap(),
        ];

        for i in 0..sorted.len() {
            for j in 0..sorted.len() {
                let expected = i.cmp(&j);
                let actual = sorted[i].cmp(&sorted[j]);
                assert_eq!(
                    actual, expected,
                    "comparison failed between '{:?}' and '{:?}'",
                    sorted[i], sorted[j]
                );
            }
        }
    }

    #[test]
    fn test_nsec_covers_standard_and_wraparound() {
        let a = Name::new("a.example.com").unwrap();
        let b = Name::new("b.example.com").unwrap();
        let c = Name::new("c.example.com").unwrap();
        let d = Name::new("d.example.com").unwrap();
        let z = Name::new("z.example.com").unwrap();
        let zz = Name::new("zz.example.com").unwrap();
        let zero = Name::new("0.example.com").unwrap();
        let m = Name::new("m.example.com").unwrap();

        // Standard range: a.example.com -> c.example.com
        assert!(nsec_covers(&a, &c, &b));
        assert!(!nsec_covers(&a, &c, &a));
        assert!(!nsec_covers(&a, &c, &c));
        assert!(!nsec_covers(&a, &c, &d));

        // Circular wrap-around: z.example.com -> a.example.com
        assert!(nsec_covers(&z, &a, &zz));
        assert!(nsec_covers(&z, &a, &zero));
        assert!(!nsec_covers(&z, &a, &m));
    }

    #[test]
    fn test_verify_nsec_nodata() {
        let nsec = NSEC {
            next_domain: Name::new("host.example.com.").unwrap(),
            types: vec![Type::A, Type::MX, Type::RRSIG, Type::NSEC],
        };
        let alfa = Name::new("alfa.example.com.").unwrap();
        let beta = Name::new("beta.example.com.").unwrap();

        // Querying for AAAA on alfa.example.com should succeed (NODATA proof)
        assert!(verify_nsec_nodata(&nsec, &alfa, &alfa, Type::AAAA));

        // Querying for A should fail (A exists)
        assert!(!verify_nsec_nodata(&nsec, &alfa, &alfa, Type::A));

        // Mismatched name should fail
        assert!(!verify_nsec_nodata(&nsec, &alfa, &beta, Type::AAAA));
    }

    #[test]
    fn test_verify_nsec_nxdomain() {
        let nsec_name = NSEC {
            next_domain: Name::new("d.example.com.").unwrap(),
            types: vec![Type::A, Type::RRSIG, Type::NSEC],
        };
        // In canonical order, example.com. < *.example.com. < a.example.com.
        let nsec_wildcard = NSEC {
            next_domain: Name::new("a.example.com.").unwrap(),
            types: vec![Type::SOA, Type::NS, Type::RRSIG, Type::NSEC],
        };

        let b = Name::new("b.example.com.").unwrap();
        let example = Name::new("example.com.").unwrap();
        let c = Name::new("c.example.com.").unwrap();
        let e = Name::new("e.example.com.").unwrap();

        let nsecs = [
            (&b, &nsec_name),           // covers c.example.com
            (&example, &nsec_wildcard), // covers *.example.com
        ];

        assert!(verify_nsec_nxdomain(&nsecs, &c, &example));
        assert!(!verify_nsec_nxdomain(&nsecs, &e, &example));
    }

    #[cfg(feature = "dnssec")]
    #[test]
    fn test_rfc5155_nsec3_hash_vector() {
        // RFC 5155 Appendix A test vector:
        // Zone: example.
        // NSEC3PARAM: 1 0 12 aabbccdd
        // H(example.) = 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom
        let salt = crate::util::hex_decode("aabbccdd").unwrap();
        let name = Name::new("example.").unwrap();
        let hash = nsec3_hash(&name, &salt, 12);
        let b32_hash = crate::util::base32hex_encode(&hash).to_ascii_lowercase();
        assert_eq!(b32_hash, "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom");

        // RFC 5155 §5: Hashing mixed-case name MUST produce identical digest
        let mixed = Name::new("ExAmPlE.").unwrap();
        let mixed_hash = nsec3_hash(&mixed, &salt, 12);
        assert_eq!(hash, mixed_hash);
    }

    #[test]
    fn test_verify_nsec_nodata_case_insensitive() {
        let nsec = NSEC {
            next_domain: Name::new("b.example.com.").unwrap(),
            types: vec![Type::A, Type::RRSIG, Type::NSEC],
        };
        let owner = Name::new("a.example.com.").unwrap();
        let mixed_query = Name::new("A.ExAmPlE.cOm.").unwrap();

        // Nodota matches case-insensitively
        assert!(verify_nsec_nodata(&nsec, &owner, &mixed_query, Type::AAAA));
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
