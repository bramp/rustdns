//! DNSSEC cryptography backed by [`ring`](https://docs.rs/ring).

use super::{Backend, EcdsaCurve, HashAlgorithm, RsaPublicKey};
use ring::{digest, signature};

/// [`Backend`] implemented with `ring`.
pub(crate) struct Ring;

impl Backend for Ring {
    fn digest(algorithm: HashAlgorithm, parts: &[&[u8]]) -> Vec<u8> {
        let algorithm = match algorithm {
            HashAlgorithm::Sha1ForLegacyUseOnly => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            HashAlgorithm::Sha256 => &digest::SHA256,
            HashAlgorithm::Sha384 => &digest::SHA384,
            HashAlgorithm::Sha512 => &digest::SHA512,
        };
        let mut ctx = digest::Context::new(algorithm);
        for part in parts {
            ctx.update(part);
        }
        ctx.finish().as_ref().to_vec()
    }

    fn verify_rsa_pkcs1(
        hash: HashAlgorithm,
        key: RsaPublicKey<'_>,
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        let parameters = match hash {
            HashAlgorithm::Sha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            HashAlgorithm::Sha512 => &signature::RSA_PKCS1_2048_8192_SHA512,
            other => return Err(format!("unsupported RSA hash {other:?}")),
        };
        signature::RsaPublicKeyComponents { n: key.n, e: key.e }
            .verify(parameters, signed_data, signature)
            .map_err(|e| e.to_string())
    }

    fn verify_ecdsa(
        curve: EcdsaCurve,
        public_key: &[u8],
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        let algorithm = match curve {
            EcdsaCurve::P256Sha256 => &signature::ECDSA_P256_SHA256_FIXED,
            EcdsaCurve::P384Sha384 => &signature::ECDSA_P384_SHA384_FIXED,
        };
        // ring expects a SEC 1 uncompressed point: 0x04 || X || Y.
        let mut point = Vec::with_capacity(public_key.len() + 1);
        point.push(0x04);
        point.extend_from_slice(public_key);
        signature::UnparsedPublicKey::new(algorithm, point)
            .verify(signed_data, signature)
            .map_err(|e| e.to_string())
    }

    fn verify_ed25519(
        public_key: &[u8; 32],
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
            .verify(signed_data, signature)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
fn test_ed25519_pair(seed: &[u8; 32]) -> signature::Ed25519KeyPair {
    signature::Ed25519KeyPair::from_seed_unchecked(seed).expect("valid Ed25519 seed")
}

#[cfg(test)]
pub(super) fn test_ed25519_public_key(seed: &[u8; 32]) -> Vec<u8> {
    use signature::KeyPair;
    test_ed25519_pair(seed).public_key().as_ref().to_vec()
}

#[cfg(test)]
pub(super) fn test_ed25519_sign(seed: &[u8; 32], data: &[u8]) -> Vec<u8> {
    test_ed25519_pair(seed).sign(data).as_ref().to_vec()
}

/// Signs `data` with a PKCS#1 DER test key, returning RFC 3110 DNSKEY public
/// key octets and the PKCS#1 v1.5 signature.
#[cfg(all(test, feature = "dnssec-rustcrypto"))]
pub(super) fn test_rsa_sign(der: &[u8], hash: HashAlgorithm, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let pair = signature::RsaKeyPair::from_der(der).expect("valid test key");
    let encoding = match hash {
        HashAlgorithm::Sha256 => &signature::RSA_PKCS1_SHA256,
        HashAlgorithm::Sha512 => &signature::RSA_PKCS1_SHA512,
        other => panic!("unsupported RSA test hash {other:?}"),
    };
    let mut sig = vec![0; pair.public().modulus_len()];
    pair.sign(encoding, &ring::rand::SystemRandom::new(), data, &mut sig)
        .expect("signing succeeds");
    let components: signature::RsaPublicKeyComponents<Vec<u8>> = pair.public().into();
    let mut public_key = vec![u8::try_from(components.e.len()).expect("short exponent")];
    public_key.extend_from_slice(&components.e);
    public_key.extend_from_slice(&components.n);
    (public_key, sig)
}
