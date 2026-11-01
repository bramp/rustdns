//! Cryptographic signature verification and digests for DNSSEC.
//!
//! Supported DNSSEC algorithms ([RFC 4034], [RFC 5702], [RFC 6605], [RFC 8080]):
//! - Algorithm 8: RSA/SHA-256
//! - Algorithm 10: RSA/SHA-512
//! - Algorithm 13: ECDSA Curve P-256 with SHA-256
//! - Algorithm 14: ECDSA Curve P-384 with SHA-384
//! - Algorithm 15: Ed25519
//!
//! This module parses DNSKEY wire formats and dispatches to a [`Backend`]
//! selected at compile time: `dnssec-ring` uses `ring`, and
//! `dnssec-rustcrypto` uses pure-Rust RustCrypto crates. When both features
//! are enabled, `ring` is used.
//!
//! [RFC 4034]: https://datatracker.ietf.org/doc/html/rfc4034
//! [RFC 5702]: https://datatracker.ietf.org/doc/html/rfc5702
//! [RFC 6605]: https://datatracker.ietf.org/doc/html/rfc6605
//! [RFC 8080]: https://datatracker.ietf.org/doc/html/rfc8080

#[cfg(feature = "dnssec-ring")]
mod ring;
// With both backends enabled, `ring` is active and RustCrypto is only used by tests.
#[cfg(feature = "dnssec-rustcrypto")]
#[cfg_attr(feature = "dnssec-ring", allow(dead_code))]
mod rustcrypto;

#[cfg(not(any(feature = "dnssec-ring", feature = "dnssec-rustcrypto")))]
compile_error!(
    "the `dnssec` feature requires a cryptographic backend: enable `dnssec-ring` or `dnssec-rustcrypto`"
);

use crate::DnssecError;
use crate::resource::DNSKEY;
use crate::types::Algorithm;

#[cfg(feature = "dnssec-ring")]
type Active = ring::Ring;
#[cfg(all(feature = "dnssec-rustcrypto", not(feature = "dnssec-ring")))]
type Active = rustcrypto::RustCrypto;

/// Hash functions used by DNSSEC digests and signature algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HashAlgorithm {
    /// SHA-1, which is not collision resistant. Only for protocol-mandated uses:
    /// NSEC3 hashing (RFC 5155) and SHA-1 DS digests (RFC 4034).
    Sha1ForLegacyUseOnly,
    Sha256,
    Sha384,
    Sha512,
}

/// Elliptic curves used by DNSSEC ECDSA algorithms ([RFC 6605]).
///
/// [RFC 6605]: https://datatracker.ietf.org/doc/html/rfc6605
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EcdsaCurve {
    /// P-256 with SHA-256; 64-octet keys and signatures.
    P256Sha256,
    /// P-384 with SHA-384; 96-octet keys and signatures.
    P384Sha384,
}

impl EcdsaCurve {
    const fn key_len(self) -> usize {
        match self {
            EcdsaCurve::P256Sha256 => 64,
            EcdsaCurve::P384Sha384 => 96,
        }
    }
}

/// RSA public key components borrowed from DNSKEY public key octets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RsaPublicKey<'a> {
    /// Big-endian modulus.
    pub n: &'a [u8],
    /// Big-endian public exponent.
    pub e: &'a [u8],
}

/// Cryptographic primitives required by DNSSEC validation.
///
/// Implementations only verify; key parsing and algorithm dispatch are shared
/// so every backend accepts the same DNSKEY encodings. Errors are short
/// descriptions that callers wrap in [`DnssecError::ValidationFailed`].
pub(crate) trait Backend {
    /// Hashes the concatenation of `parts`.
    fn digest(algorithm: HashAlgorithm, parts: &[&[u8]]) -> Vec<u8>;

    /// Verifies an RSASSA-PKCS1-v1_5 signature with a 2048 to 8192-bit modulus.
    ///
    /// `hash` is [`HashAlgorithm::Sha256`] or [`HashAlgorithm::Sha512`].
    fn verify_rsa_pkcs1(
        hash: HashAlgorithm,
        key: RsaPublicKey<'_>,
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<(), String>;

    /// Verifies a fixed-width `r || s` ECDSA signature against a raw `X || Y` public key.
    fn verify_ecdsa(
        curve: EcdsaCurve,
        public_key: &[u8],
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<(), String>;

    /// Verifies an Ed25519 signature against a raw 32-octet public key.
    fn verify_ed25519(
        public_key: &[u8; 32],
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<(), String>;
}

/// Hashes the concatenation of `parts` with the active backend.
pub(crate) fn digest(algorithm: HashAlgorithm, parts: &[&[u8]]) -> Vec<u8> {
    Active::digest(algorithm, parts)
}

/// Verifies a cryptographic signature over `signed_data` using the provided DNSKEY.
///
/// # Errors
///
/// Returns [`DnssecError::UnsupportedAlgorithm`] for algorithms without a
/// verifier, or [`DnssecError::ValidationFailed`] if the key is malformed or
/// signature verification fails.
pub(crate) fn verify_signature(
    algorithm: Algorithm,
    dnskey: &DNSKEY,
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), DnssecError> {
    verify_signature_with::<Active>(algorithm, dnskey, signed_data, signature)
}

fn verify_signature_with<B: Backend>(
    algorithm: Algorithm,
    dnskey: &DNSKEY,
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), DnssecError> {
    let key = dnskey.public_key.as_slice();
    match algorithm {
        Algorithm::RSASHA256 => B::verify_rsa_pkcs1(
            HashAlgorithm::Sha256,
            check_rsa_key_bounds(parse_rsa_public_key(key)?)?,
            signed_data,
            signature,
        )
        .map_err(|e| failed("RSA signature verification failed", &e)),
        Algorithm::RSASHA512 => B::verify_rsa_pkcs1(
            HashAlgorithm::Sha512,
            check_rsa_key_bounds(parse_rsa_public_key(key)?)?,
            signed_data,
            signature,
        )
        .map_err(|e| failed("RSA signature verification failed", &e)),
        Algorithm::ECDSAP256SHA256 => {
            let curve = EcdsaCurve::P256Sha256;
            B::verify_ecdsa(curve, check_ecdsa_key(curve, key)?, signed_data, signature)
                .map_err(|e| failed("ECDSA P-256 verification failed", &e))
        }
        Algorithm::ECDSAP384SHA384 => {
            let curve = EcdsaCurve::P384Sha384;
            B::verify_ecdsa(curve, check_ecdsa_key(curve, key)?, signed_data, signature)
                .map_err(|e| failed("ECDSA P-384 verification failed", &e))
        }
        Algorithm::ED25519 => {
            B::verify_ed25519(parse_ed25519_public_key(key)?, signed_data, signature)
                .map_err(|e| failed("Ed25519 verification failed", &e))
        }
        other => Err(DnssecError::UnsupportedAlgorithm(other)),
    }
}

fn failed(context: &str, detail: &str) -> DnssecError {
    DnssecError::ValidationFailed(format!("{context}: {detail}"))
}

/// Parses RFC 3110 §2 RSA DNSKEY public key octets into modulus and exponent.
///
/// The exponent length is one octet, or a zero octet followed by a two-octet
/// length, followed by the exponent and then the modulus.
fn parse_rsa_public_key(public_key: &[u8]) -> Result<RsaPublicKey<'_>, DnssecError> {
    let malformed =
        |reason: &str| DnssecError::ValidationFailed(format!("{reason} RSA public key"));
    let (&first, rest) = public_key.split_first().ok_or_else(|| malformed("empty"))?;
    let (exp_len, rest) = if first == 0 {
        let (len, rest) = rest
            .split_first_chunk::<2>()
            .ok_or_else(|| malformed("truncated"))?;
        (usize::from(u16::from_be_bytes(*len)), rest)
    } else {
        (usize::from(first), rest)
    };
    if rest.len() < exp_len {
        return Err(DnssecError::ValidationFailed(
            "truncated RSA exponent".to_string(),
        ));
    }
    let (e, n) = rest.split_at(exp_len);
    if n.is_empty() {
        return Err(DnssecError::ValidationFailed(
            "empty RSA modulus".to_string(),
        ));
    }
    Ok(RsaPublicKey { n, e })
}

/// Minimum and maximum accepted RSA modulus sizes, in bits.
const RSA_MODULUS_BITS: core::ops::RangeInclusive<usize> = 2048..=8192;

/// Largest accepted RSA public exponent (2^33 - 1).
const RSA_MAX_EXPONENT: u64 = (1 << 33) - 1;

/// Applies the RSA key policy shared by every backend.
///
/// Requires minimally encoded values, a 2048 to 8192-bit modulus, and an odd
/// exponent from 3 to 2^33 - 1. This matches `ring`, so backends agree on
/// which keys are usable.
fn check_rsa_key_bounds(key: RsaPublicKey<'_>) -> Result<RsaPublicKey<'_>, DnssecError> {
    let rejected = |reason: String| {
        DnssecError::ValidationFailed(format!("unsupported RSA public key: {reason}"))
    };
    let (Some(&n0), Some(&e0)) = (key.n.first(), key.e.first()) else {
        return Err(rejected("empty modulus or exponent".to_string()));
    };
    if n0 == 0 || e0 == 0 {
        return Err(rejected("non-minimal encoding".to_string()));
    }
    let bits = key.n.len() * 8 - n0.leading_zeros() as usize;
    if !RSA_MODULUS_BITS.contains(&bits) {
        return Err(rejected(format!("{bits}-bit modulus")));
    }
    let exponent = if key.e.len() <= 8 {
        key.e.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
    } else {
        u64::MAX
    };
    if !(3..=RSA_MAX_EXPONENT).contains(&exponent) || exponent % 2 == 0 {
        return Err(rejected("exponent out of range".to_string()));
    }
    Ok(key)
}

/// Checks the length of RFC 6605 ECDSA DNSKEY public key octets (`X || Y`).
fn check_ecdsa_key(curve: EcdsaCurve, public_key: &[u8]) -> Result<&[u8], DnssecError> {
    if public_key.len() == curve.key_len() {
        Ok(public_key)
    } else {
        Err(DnssecError::ValidationFailed(format!(
            "invalid ECDSA {curve:?} public key length (expected {}, got {})",
            curve.key_len(),
            public_key.len()
        )))
    }
}

/// Parses RFC 8080 Ed25519 DNSKEY public key octets (32 octets).
fn parse_ed25519_public_key(public_key: &[u8]) -> Result<&[u8; 32], DnssecError> {
    public_key.try_into().map_err(|_| {
        DnssecError::ValidationFailed(format!(
            "invalid Ed25519 public key length (expected 32, got {})",
            public_key.len()
        ))
    })
}

/// Deterministic Ed25519 key for signing test fixtures with the active backend.
#[cfg(test)]
pub(crate) struct TestEd25519Key {
    seed: [u8; 32],
}

#[cfg(test)]
impl TestEd25519Key {
    pub(crate) fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    pub(crate) fn public_key(&self) -> Vec<u8> {
        #[cfg(feature = "dnssec-ring")]
        return ring::test_ed25519_public_key(&self.seed);
        #[cfg(not(feature = "dnssec-ring"))]
        return rustcrypto::test_ed25519_public_key(&self.seed);
    }

    pub(crate) fn sign(&self, data: &[u8]) -> Vec<u8> {
        #[cfg(feature = "dnssec-ring")]
        return ring::test_ed25519_sign(&self.seed, data);
        #[cfg(not(feature = "dnssec-ring"))]
        return rustcrypto::test_ed25519_sign(&self.seed, data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dnskey(algorithm: Algorithm, public_key: Vec<u8>) -> DNSKEY {
        DNSKEY {
            flags: 257,
            protocol: 3,
            algorithm,
            public_key,
        }
    }

    #[test]
    fn test_ed25519_roundtrip_verification() {
        let key = TestEd25519Key::from_seed([7; 32]);
        let message = b"hello dnssec";
        let sig = key.sign(message);
        let dnskey = dnskey(Algorithm::ED25519, key.public_key());

        verify_signature(Algorithm::ED25519, &dnskey, message, &sig).expect("valid signature");
        assert!(verify_signature(Algorithm::ED25519, &dnskey, b"tampered", &sig).is_err());
    }

    #[test]
    fn test_parse_rsa_public_key_one_byte_exponent() {
        let raw = [3, 1, 0, 1, 0xAA, 0xBB];
        let key = parse_rsa_public_key(&raw).expect("valid RSA key");
        assert_eq!(key.e, &[1, 0, 1]);
        assert_eq!(key.n, &[0xAA, 0xBB]);
    }

    #[test]
    fn test_parse_rsa_public_key_three_byte_exponent_header() {
        let raw = [0, 0, 3, 1, 0, 1, 0xCC, 0xDD];
        let key = parse_rsa_public_key(&raw).expect("valid RSA key");
        assert_eq!(key.e, &[1, 0, 1]);
        assert_eq!(key.n, &[0xCC, 0xDD]);
    }

    #[test]
    fn test_parse_rsa_public_key_malformed_errors() {
        assert!(parse_rsa_public_key(&[]).is_err());
        assert!(parse_rsa_public_key(&[0, 1]).is_err());
        assert!(parse_rsa_public_key(&[5, 1, 2]).is_err());
        assert!(parse_rsa_public_key(&[3, 1, 0, 1]).is_err());
    }

    #[test]
    fn test_rsa_key_bounds() {
        let n2048 = [0x80; 256];
        let ok = |n: &[u8], e: &[u8]| check_rsa_key_bounds(RsaPublicKey { n, e }).is_ok();
        assert!(ok(&n2048, &[1, 0, 1]));
        assert!(ok(&n2048, &[3]));
        assert!(ok(&[0xFF; 1024], &[1, 0, 1]));
        assert!(!ok(&[0x7F; 256], &[1, 0, 1]), "2047-bit modulus");
        assert!(!ok(&[0x01; 1025], &[1, 0, 1]), "8193-bit modulus");
        assert!(!ok(&[0x00, 0x80], &[1, 0, 1]), "leading zero in modulus");
        assert!(!ok(&n2048, &[0, 3]), "leading zero in exponent");
        assert!(!ok(&n2048, &[1]), "exponent below 3");
        assert!(!ok(&n2048, &[1, 0, 0]), "even exponent");
        assert!(ok(&n2048, &[1, 0xFF, 0xFF, 0xFF, 0xFF]), "2^33 - 1");
        assert!(!ok(&n2048, &[2, 0, 0, 0, 1]), "exponent above 2^33 - 1");
        assert!(!ok(&n2048, &[1; 9]), "oversized exponent");
    }

    #[test]
    fn test_key_length_checks() {
        let p256 = EcdsaCurve::P256Sha256;
        let p384 = EcdsaCurve::P384Sha384;
        assert!(check_ecdsa_key(p256, &[0x42; 64]).is_ok());
        assert!(check_ecdsa_key(p256, &[0; 63]).is_err());
        assert!(check_ecdsa_key(p256, &[0; 65]).is_err());
        assert!(check_ecdsa_key(p384, &[0x55; 96]).is_ok());
        assert!(check_ecdsa_key(p384, &[0; 95]).is_err());
        assert!(check_ecdsa_key(p384, &[0; 97]).is_err());
        assert_eq!(parse_ed25519_public_key(&[0x77; 32]).unwrap(), &[0x77; 32]);
        assert!(parse_ed25519_public_key(&[0; 31]).is_err());
        assert!(parse_ed25519_public_key(&[0; 33]).is_err());
    }

    /// Root zone KSK 20326 (RSA/SHA-256) in RFC 3110 wire format.
    const ROOT_KSK_20326: &str = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=";

    #[test]
    fn test_rsa_rejects_bad_signature() {
        let public_key = crate::util::base64_decode(ROOT_KSK_20326).expect("valid base64");
        let dnskey = dnskey(Algorithm::RSASHA256, public_key);
        let res = verify_signature(Algorithm::RSASHA256, &dnskey, b"data", &[0u8; 256]);
        assert!(res.is_err());
    }

    #[test]
    fn test_unsupported_algorithm() {
        let dnskey = dnskey(Algorithm::RSASHA1, vec![3, 1, 0, 1, 0xAA]);
        assert!(matches!(
            verify_signature(Algorithm::RSASHA1, &dnskey, b"", b""),
            Err(DnssecError::UnsupportedAlgorithm(Algorithm::RSASHA1))
        ));
    }

    #[test]
    fn test_digest_vectors() {
        let cases = [
            (
                HashAlgorithm::Sha1ForLegacyUseOnly,
                "a9993e364706816aba3e25717850c26c9cd0d89d",
            ),
            (
                HashAlgorithm::Sha256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                HashAlgorithm::Sha384,
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                HashAlgorithm::Sha512,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
        ];
        for (algorithm, expected) in cases {
            assert_eq!(
                crate::util::hex_encode(&digest(algorithm, &[b"a", b"bc"])).to_ascii_lowercase(),
                expected
            );
        }
    }

    /// Runs the same signature vectors through every compiled backend so the
    /// backends cannot silently diverge.
    #[cfg(all(feature = "dnssec-ring", feature = "dnssec-rustcrypto"))]
    mod cross_backend {
        use super::super::{ring::Ring, rustcrypto::RustCrypto, *};
        use super::dnskey;

        const RSA_2048: &[u8] = include_bytes!("../fixtures/test-rsa-2048.pkcs1.der");

        /// Ed25519 group order L, little-endian.
        const ED25519_ORDER: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];

        /// Verifies with every backend, asserts they agree, and returns the shared verdict.
        #[track_caller]
        fn agreed(algorithm: Algorithm, key: &DNSKEY, data: &[u8], sig: &[u8]) -> bool {
            let ring = verify_signature_with::<Ring>(algorithm, key, data, sig);
            let rustcrypto = verify_signature_with::<RustCrypto>(algorithm, key, data, sig);
            assert_eq!(
                ring.is_ok(),
                rustcrypto.is_ok(),
                "backends disagree for {algorithm:?}: ring={ring:?}, rustcrypto={rustcrypto:?}"
            );
            ring.is_ok()
        }

        fn flip(bytes: &[u8], index: usize) -> Vec<u8> {
            let mut out = bytes.to_vec();
            out[index] ^= 1;
            out
        }

        #[test]
        fn ecdsa_signatures_agree() {
            let data = b"cross backend";
            for (algorithm, (public_key, sig)) in [
                (Algorithm::ECDSAP256SHA256, rustcrypto::test_p256_sign(data)),
                (Algorithm::ECDSAP384SHA384, rustcrypto::test_p384_sign(data)),
            ] {
                let half = sig.len() / 2;
                let key = dnskey(algorithm, public_key.clone());
                assert!(agreed(algorithm, &key, data, &sig), "{algorithm:?}");
                assert!(!agreed(algorithm, &key, b"other", &sig), "{algorithm:?}");
                assert!(
                    !agreed(algorithm, &key, data, &flip(&sig, 5)),
                    "{algorithm:?}"
                );
                assert!(!agreed(algorithm, &key, data, &sig[1..]), "{algorithm:?}");

                let zero_r = [vec![0; half], sig[half..].to_vec()].concat();
                let zero_s = [sig[..half].to_vec(), vec![0; half]].concat();
                assert!(
                    !agreed(algorithm, &key, data, &zero_r),
                    "{algorithm:?} r = 0"
                );
                assert!(
                    !agreed(algorithm, &key, data, &zero_s),
                    "{algorithm:?} s = 0"
                );
                assert!(
                    !agreed(algorithm, &key, data, &vec![0xFF; sig.len()]),
                    "{algorithm:?} r, s >= n"
                );

                let high_s = rustcrypto::test_ecdsa_negate_s(algorithm, &sig);
                assert_ne!(high_s, sig);
                assert!(
                    agreed(algorithm, &key, data, &high_s),
                    "{algorithm:?} high-S is valid ECDSA"
                );

                let off_curve = dnskey(algorithm, flip(&public_key, public_key.len() - 1));
                assert!(
                    !agreed(algorithm, &off_curve, data, &sig),
                    "{algorithm:?} point off curve"
                );
                let zero_key = dnskey(algorithm, vec![0; public_key.len()]);
                assert!(
                    !agreed(algorithm, &zero_key, data, &sig),
                    "{algorithm:?} zero point"
                );
                let max_key = dnskey(algorithm, vec![0xFF; public_key.len()]);
                assert!(
                    !agreed(algorithm, &max_key, data, &sig),
                    "{algorithm:?} coordinates >= p"
                );
            }
        }

        #[test]
        fn ed25519_signatures_agree() {
            let seed = [9; 32];
            let public_key = ring::test_ed25519_public_key(&seed);
            assert_eq!(public_key, rustcrypto::test_ed25519_public_key(&seed));
            let sig = ring::test_ed25519_sign(&seed, b"data");
            assert_eq!(sig, rustcrypto::test_ed25519_sign(&seed, b"data"));

            let alg = Algorithm::ED25519;
            let key = dnskey(alg, public_key.clone());
            assert!(agreed(alg, &key, b"data", &sig));
            assert!(!agreed(alg, &key, b"date", &sig));
            assert!(!agreed(alg, &key, b"data", &flip(&sig, 3)), "tampered R");
            assert!(!agreed(alg, &key, b"data", &flip(&sig, 40)), "tampered S");
            assert!(!agreed(alg, &key, b"data", &sig[1..]), "truncated");
            assert!(
                !agreed(alg, &key, b"data", &[sig.clone(), vec![0]].concat()),
                "extended"
            );

            // S + L verifies algebraically but is non-canonical (RFC 8032 §5.1.7).
            let mut non_canonical = sig.clone();
            let mut carry = 0u16;
            for (byte, order) in non_canonical[32..].iter_mut().zip(ED25519_ORDER) {
                let sum = u16::from(*byte) + u16::from(order) + carry;
                *byte = sum as u8;
                carry = sum >> 8;
            }
            assert!(
                !agreed(alg, &key, b"data", &non_canonical),
                "non-canonical S"
            );

            let mut identity = [0u8; 32];
            identity[0] = 1;
            for (label, bad_key) in [
                ("tampered key", flip(&public_key, 0)),
                ("all 0xFF", vec![0xFF; 32]),
                ("small y", [&[2u8][..], &[0; 31]].concat()),
                ("identity", identity.to_vec()),
            ] {
                assert!(
                    !agreed(alg, &dnskey(alg, bad_key), b"data", &sig),
                    "{label}"
                );
            }
        }

        #[test]
        fn rsa_signatures_agree() {
            let data: &[u8] = b"cross backend";
            let mut cases = Vec::new();
            for (label, der, algorithm, hash) in [
                (
                    "2048-bit",
                    RSA_2048,
                    Algorithm::RSASHA256,
                    HashAlgorithm::Sha256,
                ),
                (
                    "2048-bit",
                    RSA_2048,
                    Algorithm::RSASHA512,
                    HashAlgorithm::Sha512,
                ),
            ] {
                let (public_key, sig) = ring::test_rsa_sign(der, hash, data);
                cases.push((label, algorithm, public_key, sig, data));
            }
            // ring only signs with e >= 65537 and up to 4096 bits, so these
            // policy-boundary signatures were made by OpenSSL.
            cases.push((
                "e = 3",
                Algorithm::RSASHA256,
                include_bytes!("../fixtures/test-rsa-2048-e3.dnskey").to_vec(),
                include_bytes!("../fixtures/test-rsa-2048-e3-sha256.sig").to_vec(),
                b"rustdns RSA exponent 3 test",
            ));
            cases.push((
                "8192-bit",
                Algorithm::RSASHA512,
                include_bytes!("../fixtures/test-rsa-8192.dnskey").to_vec(),
                include_bytes!("../fixtures/test-rsa-8192-sha512.sig").to_vec(),
                b"rustdns RSA 8192-bit test",
            ));

            for (label, algorithm, public_key, sig, data) in cases {
                let key = dnskey(algorithm, public_key.clone());
                let modulus = parse_rsa_public_key(&public_key).unwrap().n.to_vec();
                assert!(agreed(algorithm, &key, data, &sig), "{label} {algorithm:?}");
                assert!(
                    !agreed(algorithm, &key, b"other", &sig),
                    "{label} other data"
                );
                assert!(
                    !agreed(algorithm, &key, data, &flip(&sig, sig.len() / 2)),
                    "{label} tampered"
                );
                assert!(
                    !agreed(algorithm, &key, data, &sig[1..]),
                    "{label} truncated"
                );
                assert!(
                    !agreed(algorithm, &key, data, &[vec![0], sig.clone()].concat()),
                    "{label} padded"
                );
                assert!(
                    !agreed(algorithm, &key, data, &vec![0; sig.len()]),
                    "{label} zero"
                );
                assert!(
                    !agreed(algorithm, &key, data, &modulus),
                    "{label} signature = n"
                );

                let other = match algorithm {
                    Algorithm::RSASHA256 => Algorithm::RSASHA512,
                    _ => Algorithm::RSASHA256,
                };
                assert!(
                    !agreed(other, &dnskey(other, public_key), data, &sig),
                    "{label} wrong hash"
                );
            }
        }

        #[test]
        fn rsa_key_policy_agrees() {
            // A genuine OpenSSL signature from a 1024-bit key, which the shared policy rejects.
            let public_key = include_bytes!("../fixtures/test-rsa-1024.dnskey").to_vec();
            let sig = include_bytes!("../fixtures/test-rsa-1024-sha256.sig");
            let data = b"rustdns 1024-bit RSA test";
            let small = parse_rsa_public_key(&public_key).unwrap();
            assert!(RustCrypto::verify_rsa_pkcs1(HashAlgorithm::Sha256, small, data, sig).is_ok());
            let key = dnskey(Algorithm::RSASHA256, public_key);
            assert!(!agreed(Algorithm::RSASHA256, &key, data, sig));
            let error = verify_signature_with::<RustCrypto>(Algorithm::RSASHA256, &key, data, sig)
                .unwrap_err();
            assert!(error.to_string().contains("1024-bit modulus"), "{error}");

            let (public_key, sig) = ring::test_rsa_sign(RSA_2048, HashAlgorithm::Sha256, data);
            let RsaPublicKey { n, e } = parse_rsa_public_key(&public_key).unwrap();
            let encode = |e: &[u8], n: &[u8]| [&[e.len() as u8][..], e, n].concat();
            for (label, bad_key) in [
                ("even exponent", encode(&[1, 0, 0], n)),
                ("leading zero exponent", encode(&[&[0][..], e].concat(), n)),
                ("leading zero modulus", encode(e, &[&[0][..], n].concat())),
            ] {
                let key = dnskey(Algorithm::RSASHA256, bad_key);
                assert!(!agreed(Algorithm::RSASHA256, &key, data, &sig), "{label}");
            }
        }

        #[test]
        fn digests_agree() {
            for algorithm in [
                HashAlgorithm::Sha1ForLegacyUseOnly,
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha512,
            ] {
                for parts in [&[][..], &[&b""[..]], &[b"x", b"yz"], &[&[0xA5; 1000][..]]] {
                    assert_eq!(
                        Ring::digest(algorithm, parts),
                        RustCrypto::digest(algorithm, parts)
                    );
                }
            }
        }
    }
}
