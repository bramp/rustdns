//! Cryptographic signature verification and public key handling for DNSSEC.
//!
//! Supported DNSSEC algorithms (RFC 4034, 5702, 6605, 8080):
//! - Algorithm 8: RSA/SHA-256
//! - Algorithm 10: RSA/SHA-512
//! - Algorithm 13: ECDSA Curve P-256 with SHA-256
//! - Algorithm 14: ECDSA Curve P-384 with SHA-384
//! - Algorithm 15: Ed25519

use crate::DnssecError;
use crate::resource::DNSKEY;
use crate::types::Algorithm;
use ring::signature;

/// Verifies a cryptographic signature over `signed_data` using the provided DNSKEY.
///
/// # Errors
///
/// Returns [`DnssecError::ValidationFailed`] if the algorithm is unsupported or
/// signature verification fails.
pub(crate) fn verify_signature(
    algorithm: Algorithm,
    dnskey: &DNSKEY,
    signed_data: &[u8],
    signature_bytes: &[u8],
) -> Result<(), DnssecError> {
    match algorithm {
        // Algorithm 8: RSA/SHA-256
        Algorithm::RSASHA256 => verify_rsa(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            &dnskey.public_key,
            signed_data,
            signature_bytes,
        ),
        // Algorithm 10: RSA/SHA-512
        Algorithm::RSASHA512 => verify_rsa(
            &signature::RSA_PKCS1_2048_8192_SHA512,
            &dnskey.public_key,
            signed_data,
            signature_bytes,
        ),
        // Algorithm 13: ECDSA Curve P-256 with SHA-256
        Algorithm::ECDSAP256SHA256 => verify_ecdsa_p256(&dnskey.public_key, signed_data, signature_bytes),
        // Algorithm 14: ECDSA Curve P-384 with SHA-384
        Algorithm::ECDSAP384SHA384 => verify_ecdsa_p384(&dnskey.public_key, signed_data, signature_bytes),
        // Algorithm 15: Ed25519
        Algorithm::ED25519 => verify_ed25519(&dnskey.public_key, signed_data, signature_bytes),
        other => Err(DnssecError::UnsupportedAlgorithm(other)),
    }
}

/// Parses raw RFC 4034 §2.1.4 RSA DNSKEY public key octets into [`signature::RsaPublicKeyComponents`].
///
/// RFC 4034 §2.1.4: DNSKEY public key format for RSA:
/// - Exponent length: 1 octet if exponent <= 255, or 1 octet containing 0 followed by 2 octets of length.
/// - Exponent octets.
/// - Modulus octets.
fn parse_rsa_public_key(public_key: &[u8]) -> Result<signature::RsaPublicKeyComponents<&[u8]>, DnssecError> {
    if public_key.is_empty() {
        return Err(DnssecError::ValidationFailed(
            "empty RSA public key".to_string(),
        ));
    }

    let (exp_len, exp_offset) = if public_key[0] == 0 {
        if public_key.len() < 3 {
            return Err(DnssecError::ValidationFailed(
                "truncated RSA public key".to_string(),
            ));
        }
        let len = (usize::from(public_key[1]) << 8) | usize::from(public_key[2]);
        (len, 3)
    } else {
        (usize::from(public_key[0]), 1)
    };

    if public_key.len() < exp_offset + exp_len {
        return Err(DnssecError::ValidationFailed(
            "truncated RSA exponent".to_string(),
        ));
    }

    let exponent = &public_key[exp_offset..exp_offset + exp_len];
    let modulus = &public_key[exp_offset + exp_len..];

    if modulus.is_empty() {
        return Err(DnssecError::ValidationFailed(
            "empty RSA modulus".to_string(),
        ));
    }

    Ok(signature::RsaPublicKeyComponents {
        n: modulus,
        e: exponent,
    })
}

/// Verifies RSA PKCS#1 v1.5 signature.
fn verify_rsa(
    parameters: &'static signature::RsaParameters,
    public_key: &[u8],
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), DnssecError> {
    parse_rsa_public_key(public_key)?
        .verify(parameters, signed_data, signature)
        .map_err(|e| DnssecError::ValidationFailed(format!("RSA signature verification failed: {e}")))
}

/// Parses raw RFC 6605 ECDSA P-256 DNSKEY public key octets (64 bytes: X || Y) into [`signature::UnparsedPublicKey`].
///
/// Converts to SEC 1 uncompressed point format: `0x04 || X || Y` (65 octets).
fn parse_ecdsa_p256_public_key(
    public_key: &[u8],
) -> Result<signature::UnparsedPublicKey<[u8; 65]>, DnssecError> {
    if public_key.len() != 64 {
        return Err(DnssecError::ValidationFailed(format!(
            "invalid ECDSA P-256 public key length (expected 64, got {})",
            public_key.len()
        )));
    }
    let mut uncompressed = [0u8; 65];
    uncompressed[0] = 0x04;
    uncompressed[1..].copy_from_slice(public_key);
    Ok(signature::UnparsedPublicKey::new(
        &signature::ECDSA_P256_SHA256_FIXED,
        uncompressed,
    ))
}

/// Verifies ECDSA Curve P-256 with SHA-256 (RFC 6605).
///
/// Signature is 64 octets: 32 octets R || 32 octets S (matching ring's fixed-size format).
fn verify_ecdsa_p256(
    public_key: &[u8],
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), DnssecError> {
    parse_ecdsa_p256_public_key(public_key)?
        .verify(signed_data, signature)
        .map_err(|e| DnssecError::ValidationFailed(format!("ECDSA P-256 verification failed: {e}")))
}

/// Parses raw RFC 6605 ECDSA P-384 DNSKEY public key octets (96 bytes: X || Y) into [`signature::UnparsedPublicKey`].
///
/// Converts to SEC 1 uncompressed point format: `0x04 || X || Y` (97 octets).
fn parse_ecdsa_p384_public_key(
    public_key: &[u8],
) -> Result<signature::UnparsedPublicKey<[u8; 97]>, DnssecError> {
    if public_key.len() != 96 {
        return Err(DnssecError::ValidationFailed(format!(
            "invalid ECDSA P-384 public key length (expected 96, got {})",
            public_key.len()
        )));
    }
    let mut uncompressed = [0u8; 97];
    uncompressed[0] = 0x04;
    uncompressed[1..].copy_from_slice(public_key);
    Ok(signature::UnparsedPublicKey::new(
        &signature::ECDSA_P384_SHA384_FIXED,
        uncompressed,
    ))
}

/// Verifies ECDSA Curve P-384 with SHA-384 (RFC 6605).
fn verify_ecdsa_p384(
    public_key: &[u8],
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), DnssecError> {
    parse_ecdsa_p384_public_key(public_key)?
        .verify(signed_data, signature)
        .map_err(|e| DnssecError::ValidationFailed(format!("ECDSA P-384 verification failed: {e}")))
}

/// Parses raw RFC 8080 Ed25519 DNSKEY public key octets (32 bytes) into [`signature::UnparsedPublicKey`].
fn parse_ed25519_public_key(
    public_key: &[u8],
) -> Result<signature::UnparsedPublicKey<&[u8]>, DnssecError> {
    if public_key.len() != 32 {
        return Err(DnssecError::ValidationFailed(format!(
            "invalid Ed25519 public key length (expected 32, got {})",
            public_key.len()
        )));
    }
    Ok(signature::UnparsedPublicKey::new(
        &signature::ED25519,
        public_key,
    ))
}

/// Verifies Ed25519 signature (RFC 8080).
///
/// Public key is raw 32 octets. Signature is raw 64 octets.
fn verify_ed25519(
    public_key: &[u8],
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), DnssecError> {
    parse_ed25519_public_key(public_key)?
        .verify(signed_data, signature)
        .map_err(|e| DnssecError::ValidationFailed(format!("Ed25519 verification failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;

    #[test]
    fn test_ed25519_roundtrip_verification() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_key = key_pair.public_key().as_ref();

        let message = b"hello dnssec";
        let sig = key_pair.sign(message);

        let dnskey = DNSKEY {
            flags: 257,
            protocol: 3,
            algorithm: Algorithm::ED25519,
            public_key: pub_key.to_vec(),
        };

        verify_signature(Algorithm::ED25519, &dnskey, message, sig.as_ref()).expect("valid signature");
    }

    #[test]
    fn test_parse_rsa_public_key_one_byte_exponent() {
        // 1-byte exponent length: exp_len = 3, exp = [1, 0, 1], mod = [0xAA, 0xBB]
        let raw = vec![3, 1, 0, 1, 0xAA, 0xBB];
        let components = parse_rsa_public_key(&raw).expect("valid RSA key");
        assert_eq!(components.e, &[1, 0, 1]);
        assert_eq!(components.n, &[0xAA, 0xBB]);
    }

    #[test]
    fn test_parse_rsa_public_key_three_byte_exponent_header() {
        // 3-byte header: 0, followed by u16 length (e.g. 3)
        let raw = vec![0, 0, 3, 1, 0, 1, 0xCC, 0xDD];
        let components = parse_rsa_public_key(&raw).expect("valid RSA key");
        assert_eq!(components.e, &[1, 0, 1]);
        assert_eq!(components.n, &[0xCC, 0xDD]);
    }

    #[test]
    fn test_parse_rsa_public_key_malformed_errors() {
        // Empty
        assert!(parse_rsa_public_key(&[]).is_err());
        // Truncated 3-byte header
        assert!(parse_rsa_public_key(&[0, 1]).is_err());
        // Truncated exponent
        assert!(parse_rsa_public_key(&[5, 1, 2]).is_err());
        // Empty modulus
        assert!(parse_rsa_public_key(&[3, 1, 0, 1]).is_err());
    }

    #[test]
    fn test_rsa_verification_with_rsa_public_key_components() {
        // Known test vectors for RSA DNSKEY Algorithm 8 (RSASHA256)
        // Public key from root zone KSK 20326 (RFC 4034 wire format)
        let pub_key_base64 = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=";
        let public_key = crate::util::base64_decode(pub_key_base64).expect("valid base64");

        let dnskey = DNSKEY {
            flags: 257,
            protocol: 3,
            algorithm: Algorithm::RSASHA256,
            public_key,
        };

        // Corrupted signature should fail verification
        let dummy_signed_data = b"test signed data";
        let bad_sig = vec![0u8; 256];
        let res = verify_signature(Algorithm::RSASHA256, &dnskey, dummy_signed_data, &bad_sig);
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_ecdsa_and_ed25519_public_keys() {
        // P-256: 64 bytes -> 65 bytes uncompressed (prefixed with 0x04)
        let raw_p256 = [0x42u8; 64];
        let key_p256 = parse_ecdsa_p256_public_key(&raw_p256).expect("valid p256");
        assert_eq!(key_p256.as_ref()[0], 0x04);
        assert_eq!(&key_p256.as_ref()[1..], &raw_p256[..]);
        assert!(parse_ecdsa_p256_public_key(&[0u8; 63]).is_err());
        assert!(parse_ecdsa_p256_public_key(&[0u8; 65]).is_err());

        // P-384: 96 bytes -> 97 bytes uncompressed (prefixed with 0x04)
        let raw_p384 = [0x55u8; 96];
        let key_p384 = parse_ecdsa_p384_public_key(&raw_p384).expect("valid p384");
        assert_eq!(key_p384.as_ref()[0], 0x04);
        assert_eq!(&key_p384.as_ref()[1..], &raw_p384[..]);
        assert!(parse_ecdsa_p384_public_key(&[0u8; 95]).is_err());
        assert!(parse_ecdsa_p384_public_key(&[0u8; 97]).is_err());

        // Ed25519: exactly 32 bytes
        let raw_ed = [0x77u8; 32];
        let key_ed = parse_ed25519_public_key(&raw_ed).expect("valid ed25519");
        assert_eq!(key_ed.as_ref(), &raw_ed[..]);
        assert!(parse_ed25519_public_key(&[0u8; 31]).is_err());
        assert!(parse_ed25519_public_key(&[0u8; 33]).is_err());
    }
}
