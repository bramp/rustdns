//! DNSSEC cryptography backed by pure-Rust [RustCrypto](https://github.com/RustCrypto) crates.
//!
//! Only public-key verification is performed, so the `rsa` crate's private-key
//! timing side channel (RUSTSEC-2023-0071) does not apply.

use super::{Backend, EcdsaCurve, HashAlgorithm, RsaPublicKey};
use sha2::Digest;

/// [`Backend`] implemented with RustCrypto crates.
pub(crate) struct RustCrypto;

fn hash_parts<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = D::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

/// Prefixes a raw `X || Y` key with the SEC 1 uncompressed point tag.
fn sec1_uncompressed(public_key: &[u8]) -> Vec<u8> {
    let mut point = Vec::with_capacity(public_key.len() + 1);
    point.push(0x04);
    point.extend_from_slice(public_key);
    point
}

impl Backend for RustCrypto {
    fn digest(algorithm: HashAlgorithm, parts: &[&[u8]]) -> Vec<u8> {
        match algorithm {
            HashAlgorithm::Sha1ForLegacyUseOnly => hash_parts::<sha1::Sha1>(parts),
            HashAlgorithm::Sha256 => hash_parts::<sha2::Sha256>(parts),
            HashAlgorithm::Sha384 => hash_parts::<sha2::Sha384>(parts),
            HashAlgorithm::Sha512 => hash_parts::<sha2::Sha512>(parts),
        }
    }

    fn verify_rsa_pkcs1(
        hash: HashAlgorithm,
        key: RsaPublicKey<'_>,
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        use rsa::{BoxedUint, Pkcs1v15Sign};

        let uint = |bytes: &[u8]| {
            let bits = u32::try_from(bytes.len() * 8).map_err(|e| e.to_string())?;
            BoxedUint::from_be_slice(bytes, bits).map_err(|e| e.to_string())
        };

        let scheme = match hash {
            HashAlgorithm::Sha256 => Pkcs1v15Sign::new::<sha2::Sha256>(),
            HashAlgorithm::Sha512 => Pkcs1v15Sign::new::<sha2::Sha512>(),
            other => return Err(format!("unsupported RSA hash {other:?}")),
        };
        let public_key = rsa::RsaPublicKey::new_with_max_size(uint(key.n)?, uint(key.e)?, 8192)
            .map_err(|e| e.to_string())?;
        let hashed = Self::digest(hash, &[signed_data]);
        public_key
            .verify(scheme, &hashed, signature)
            .map_err(|e| e.to_string())
    }

    fn verify_ecdsa(
        curve: EcdsaCurve,
        public_key: &[u8],
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        use p256::ecdsa::signature::Verifier;

        let point = sec1_uncompressed(public_key);
        match curve {
            EcdsaCurve::P256Sha256 => {
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                    .map_err(|e| e.to_string())?;
                let signature =
                    p256::ecdsa::Signature::from_slice(signature).map_err(|e| e.to_string())?;
                key.verify(signed_data, &signature)
                    .map_err(|e| e.to_string())
            }
            EcdsaCurve::P384Sha384 => {
                let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                    .map_err(|e| e.to_string())?;
                let signature =
                    p384::ecdsa::Signature::from_slice(signature).map_err(|e| e.to_string())?;
                key.verify(signed_data, &signature)
                    .map_err(|e| e.to_string())
            }
        }
    }

    fn verify_ed25519(
        public_key: &[u8; 32],
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        use ed25519_dalek::Verifier;

        let key = ed25519_dalek::VerifyingKey::from_bytes(public_key).map_err(|e| e.to_string())?;
        let signature =
            ed25519_dalek::Signature::from_slice(signature).map_err(|e| e.to_string())?;
        key.verify(signed_data, &signature)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
pub(super) fn test_ed25519_public_key(seed: &[u8; 32]) -> Vec<u8> {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
        .to_vec()
}

#[cfg(test)]
pub(super) fn test_ed25519_sign(seed: &[u8; 32], data: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer;
    ed25519_dalek::SigningKey::from_bytes(seed)
        .sign(data)
        .to_bytes()
        .to_vec()
}

/// Signs `data` with a fixed P-256 key, returning the raw `X || Y` public key and signature.
#[cfg(all(test, feature = "dnssec-ring"))]
pub(super) fn test_p256_sign(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use p256::ecdsa::signature::Signer;
    let key = p256::ecdsa::SigningKey::from_slice(&[0x11; 32]).expect("valid scalar");
    let signature: p256::ecdsa::Signature = key.sign(data);
    let point = key.verifying_key().to_sec1_point(false);
    (
        point.as_bytes()[1..].to_vec(),
        signature.to_bytes().to_vec(),
    )
}

/// Signs `data` with a fixed P-384 key, returning the raw `X || Y` public key and signature.
#[cfg(all(test, feature = "dnssec-ring"))]
pub(super) fn test_p384_sign(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use p384::ecdsa::signature::Signer;
    let key = p384::ecdsa::SigningKey::from_slice(&[0x22; 48]).expect("valid scalar");
    let signature: p384::ecdsa::Signature = key.sign(data);
    let point = key.verifying_key().to_sec1_point(false);
    (
        point.as_bytes()[1..].to_vec(),
        signature.to_bytes().to_vec(),
    )
}

/// Returns the equivalent ECDSA signature `(r, n - s)`, which is equally valid.
#[cfg(all(test, feature = "dnssec-ring"))]
pub(super) fn test_ecdsa_negate_s(algorithm: crate::types::Algorithm, sig: &[u8]) -> Vec<u8> {
    use crate::types::Algorithm;
    match algorithm {
        Algorithm::ECDSAP256SHA256 => {
            let (r, s) = p256::ecdsa::Signature::from_slice(sig)
                .expect("valid signature")
                .split_scalars();
            p256::ecdsa::Signature::from_scalars(r, -s)
                .expect("valid scalars")
                .to_bytes()
                .to_vec()
        }
        Algorithm::ECDSAP384SHA384 => {
            let (r, s) = p384::ecdsa::Signature::from_slice(sig)
                .expect("valid signature")
                .split_scalars();
            p384::ecdsa::Signature::from_scalars(r, -s)
                .expect("valid scalars")
                .to_bytes()
                .to_vec()
        }
        other => panic!("not an ECDSA algorithm: {other:?}"),
    }
}
