//! RRset cryptographic validation against RRSIG and DNSKEY.

use crate::DnssecError;
use crate::dnssec::canonical::append_signed_data_to_vec;
use crate::dnssec::crypto::verify_signature;
use crate::resource::{DNSKEY, RRSIG};
use crate::types::{Algorithm, Record};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A summary report describing the result of validating an RRset against an RRSIG.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationReport {
    /// The signer name specified in the RRSIG.
    pub signer: String,

    /// Key tag of the DNSKEY used for validation.
    pub key_tag: u16,

    /// Algorithm of the key used for validation.
    pub algorithm: Algorithm,

    /// Number of records in the verified RRset.
    pub records_count: usize,
}

/// The temporal validity status of an RRSIG signature (RFC 4034 §3.1.5).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ValidityPeriod {
    /// The signature is currently valid within the inception and expiration window.
    Valid,
    /// The signature is not yet valid: inception is in the future (allowing for clock skew).
    NotYetValid {
        /// The signature inception timestamp.
        inception: SystemTime,
    },
    /// The signature has expired: expiration is in the past (allowing for clock skew).
    Expired {
        /// The signature expiration timestamp.
        expiration: SystemTime,
    },
}

impl ValidityPeriod {
    /// Returns `true` if the signature is within its valid period.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, ValidityPeriod::Valid)
    }
}

/// Allowed clock skew in seconds when checking signature inception and expiration.
pub const DEFAULT_CLOCK_SKEW_SECONDS: u64 = 300;

impl RRSIG {
    /// Evaluates an RRSIG signature's temporal validity window against `now` using
    /// [RFC 1982] Serial Number Arithmetic with the specified `clock_skew` tolerance (RFC 4034 §3.1.5).
    ///
    /// Returns:
    /// - [`ValidityPeriod::Valid`] if `now + clock_skew >= inception` and `expiration >= now - clock_skew`.
    /// - [`ValidityPeriod::NotYetValid`] if `inception` is in the future (even after adding `clock_skew`).
    /// - [`ValidityPeriod::Expired`] if `expiration` is in the past (even after subtracting `clock_skew`).
    ///
    /// # Errors
    ///
    /// Returns [`DnssecError::ValidationFailed`] if `expiration` or `inception` cannot
    /// be converted to 32-bit seconds fields.
    ///
    /// [RFC 1982]: https://datatracker.ietf.org/doc/html/rfc1982#section-3.2
    pub fn check_validity(
        &self,
        now: SystemTime,
        clock_skew: Duration,
    ) -> Result<ValidityPeriod, DnssecError> {
        let now_secs = (now
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            % (1u64 << 32)) as u32;

        let exp_secs = self.expiration_seconds().map_err(|e| {
            DnssecError::ValidationFailed(format!("invalid RRSIG expiration timestamp: {e}"))
        })?;
        let inc_secs = self.inception_seconds().map_err(|e| {
            DnssecError::ValidationFailed(format!("invalid RRSIG inception timestamp: {e}"))
        })?;
        let skew_secs = u32::try_from(clock_skew.as_secs()).unwrap_or(u32::MAX);

        let now_with_skew_past = now_secs.wrapping_add(skew_secs);
        let now_with_skew_future = now_secs.wrapping_sub(skew_secs);

        if crate::util::serial_lt(now_with_skew_past, inc_secs) {
            return Ok(ValidityPeriod::NotYetValid {
                inception: self.inception,
            });
        }
        if crate::util::serial_lt(exp_secs, now_with_skew_future) {
            return Ok(ValidityPeriod::Expired {
                expiration: self.expiration,
            });
        }
        Ok(ValidityPeriod::Valid)
    }

    /// Checks whether this signature is within its validity period at `now` using
    /// [RFC 1982] Serial Number Arithmetic with the specified `clock_skew` tolerance (RFC 4034 §3.1.5).
    ///
    /// Equivalent to `self.check_validity(now, clock_skew).map(|v| v.is_valid())`.
    ///
    /// # Errors
    ///
    /// Returns [`DnssecError::ValidationFailed`] if `expiration` or `inception` cannot
    /// be converted to 32-bit seconds fields.
    ///
    /// [RFC 1982]: https://datatracker.ietf.org/doc/html/rfc1982#section-3.2
    pub fn is_valid_at(&self, now: SystemTime, clock_skew: Duration) -> Result<bool, DnssecError> {
        Ok(self.check_validity(now, clock_skew)?.is_valid())
    }
}

/// Validates an RRset against a covering RRSIG and matching DNSKEY.
///
/// Verifies:
/// 1. `rrsig.key_tag == dnskey.key_tag()` and `rrsig.algorithm == dnskey.algorithm`.
/// 2. Signature temporal validity (`inception <= now <= expiration`, with clock skew allowance).
/// 3. Canonical RRset signed octet construction.
/// 4. Cryptographic signature verification over the signed octets.
///
/// # Errors
///
/// Returns [`DnssecError::ValidationFailed`] if any check fails.
pub fn validate_rrset(
    owner_name: &str,
    rrset: &[Record],
    rrsig: &RRSIG,
    dnskey: &DNSKEY,
    now: SystemTime,
) -> Result<ValidationReport, DnssecError> {
    if rrset.is_empty() {
        return Err(DnssecError::ValidationFailed(
            "empty RRset cannot be validated".to_string(),
        ));
    }

    // 1. Key tag and algorithm match
    if rrsig.algorithm != dnskey.algorithm {
        return Err(DnssecError::ValidationFailed(format!(
            "algorithm mismatch: RRSIG algorithm {} vs DNSKEY algorithm {}",
            rrsig.algorithm, dnskey.algorithm
        )));
    }

    let calculated_key_tag = dnskey.key_tag();
    if rrsig.key_tag != calculated_key_tag {
        return Err(DnssecError::ValidationFailed(format!(
            "key tag mismatch: RRSIG key tag {} vs DNSKEY key tag {}",
            rrsig.key_tag, calculated_key_tag
        )));
    }

    // 2. Validity period check using RFC 1982 Serial Number Arithmetic (RFC 4034 §3.1.5)
    let skew = Duration::from_secs(DEFAULT_CLOCK_SKEW_SECONDS);
    match rrsig.check_validity(now, skew)? {
        ValidityPeriod::Valid => {}
        ValidityPeriod::NotYetValid { inception } => {
            let inc_dt: chrono::DateTime<chrono::Utc> = inception.into();
            let now_dt: chrono::DateTime<chrono::Utc> = now.into();
            return Err(DnssecError::ValidationFailed(format!(
                "signature not yet valid: inception {} is in the future (current time: {})",
                inc_dt.format("%Y-%m-%d %H:%M:%S UTC"),
                now_dt.format("%Y-%m-%d %H:%M:%S UTC"),
            )));
        }
        ValidityPeriod::Expired { expiration } => {
            let exp_dt: chrono::DateTime<chrono::Utc> = expiration.into();
            let now_dt: chrono::DateTime<chrono::Utc> = now.into();
            return Err(DnssecError::ValidationFailed(format!(
                "signature expired: expiration {} is in the past (current time: {})",
                exp_dt.format("%Y-%m-%d %H:%M:%S UTC"),
                now_dt.format("%Y-%m-%d %H:%M:%S UTC"),
            )));
        }
    }

    // 3. Construct canonical signed data
    let mut signed_data = Vec::new();
    append_signed_data_to_vec(&mut signed_data, owner_name, rrsig, rrset).map_err(|e| {
        DnssecError::ValidationFailed(format!("failed to serialize signed data: {e}"))
    })?;

    // 4. Cryptographic verification
    verify_signature(
        rrsig.algorithm,
        dnskey,
        &signed_data,
        &rrsig.signature,
    )?;

    Ok(ValidationReport {
        signer: rrsig.signer_name.clone(),
        key_tag: rrsig.key_tag,
        algorithm: rrsig.algorithm,
        records_count: rrset.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Class, Resource, Type};
    use std::time::UNIX_EPOCH;

    #[test]
    fn test_validate_rrset_checks_validity_period() {
        let dnskey = DNSKEY {
            flags: 256,
            protocol: 3,
            algorithm: Algorithm::RSASHA256,
            public_key: vec![3, 1, 0, 1, 0x12, 0x34], // exp: [1, 0, 1], mod: [0x12, 0x34]
        };

        let rrsig = RRSIG {
            type_covered: Type::A,
            algorithm: Algorithm::RSASHA256,
            labels: 2,
            original_ttl: Duration::from_secs(3600),
            inception: UNIX_EPOCH + Duration::from_secs(1_000_000),
            expiration: UNIX_EPOCH + Duration::from_secs(2_000_000),
            key_tag: dnskey.key_tag(),
            signer_name: "example.com.".to_string(),
            signature: vec![1, 2, 3],
        };

        // Synthesize an RRset with matching owner and type
        let rrset = vec![Record::new(
            "example.com.",
            Class::Internet,
            Duration::from_secs(3600),
            Resource::A("192.0.2.1".parse().unwrap()),
        )];

        // 1. Time before inception -> fails with "not yet valid"
        let too_early = UNIX_EPOCH + Duration::from_secs(500_000);
        let err = validate_rrset("example.com.", &rrset, &rrsig, &dnskey, too_early)
            .unwrap_err();
        assert!(err.to_string().contains("signature not yet valid"));

        // 2. Time after expiration -> fails with "signature expired"
        let too_late = UNIX_EPOCH + Duration::from_secs(3_000_000);
        let err = validate_rrset("example.com.", &rrset, &rrsig, &dnskey, too_late)
            .unwrap_err();
        assert!(err.to_string().contains("signature expired"));
    }

    #[test]
    fn test_check_validity_serial_arithmetic() {
        let rrsig = RRSIG {
            type_covered: Type::A,
            algorithm: Algorithm::RSASHA256,
            labels: 2,
            original_ttl: Duration::from_secs(3600),
            inception: UNIX_EPOCH + Duration::from_secs(1_000_000),
            expiration: UNIX_EPOCH + Duration::from_secs(2_000_000),
            key_tag: 1234,
            signer_name: "example.com.".to_string(),
            signature: vec![1, 2, 3],
        };

        let skew = Duration::from_secs(60);

        // Before inception (not yet valid)
        let too_early = UNIX_EPOCH + Duration::from_secs(900_000);
        assert!(!rrsig.is_valid_at(too_early, skew).unwrap());
        assert_eq!(
            rrsig.check_validity(too_early, skew).unwrap(),
            ValidityPeriod::NotYetValid {
                inception: rrsig.inception
            }
        );

        // Within inception clock skew tolerance
        let near_inception = UNIX_EPOCH + Duration::from_secs(999_950);
        assert!(rrsig.is_valid_at(near_inception, skew).unwrap());
        assert_eq!(
            rrsig.check_validity(near_inception, skew).unwrap(),
            ValidityPeriod::Valid
        );

        // Mid-validity
        let valid_time = UNIX_EPOCH + Duration::from_secs(1_500_000);
        assert!(rrsig.is_valid_at(valid_time, skew).unwrap());
        assert_eq!(
            rrsig.check_validity(valid_time, skew).unwrap(),
            ValidityPeriod::Valid
        );

        // Within expiration clock skew tolerance
        let near_expiration = UNIX_EPOCH + Duration::from_secs(2_000_050);
        assert!(rrsig.is_valid_at(near_expiration, skew).unwrap());
        assert_eq!(
            rrsig.check_validity(near_expiration, skew).unwrap(),
            ValidityPeriod::Valid
        );

        // After expiration (expired)
        let too_late = UNIX_EPOCH + Duration::from_secs(2_100_000);
        assert!(!rrsig.is_valid_at(too_late, skew).unwrap());
        assert_eq!(
            rrsig.check_validity(too_late, skew).unwrap(),
            ValidityPeriod::Expired {
                expiration: rrsig.expiration
            }
        );

        // Test RFC 1982 Serial Number Arithmetic wrapping near 2^32 - 1
        let wrapping_rrsig = RRSIG {
            type_covered: Type::A,
            algorithm: Algorithm::RSASHA256,
            labels: 2,
            original_ttl: Duration::from_secs(3600),
            inception: UNIX_EPOCH + Duration::from_secs(4_294_967_000), // ~2^32 - 296
            expiration: UNIX_EPOCH + Duration::from_secs(10_000),       // Wrapped around 0
            key_tag: 5678,
            signer_name: "example.com.".to_string(),
            signature: vec![4, 5, 6],
        };
        // Time 4_294_967_100 is between 4_294_967_000 and 10_000 in serial arithmetic
        let wrap_mid = UNIX_EPOCH + Duration::from_secs(4_294_967_100);
        assert_eq!(
            wrapping_rrsig.check_validity(wrap_mid, skew).unwrap(),
            ValidityPeriod::Valid
        );

        // Time 50_000 is past the expiration 10_000 in serial arithmetic
        let wrap_expired = UNIX_EPOCH + Duration::from_secs(50_000);
        assert_eq!(
            wrapping_rrsig.check_validity(wrap_expired, skew).unwrap(),
            ValidityPeriod::Expired {
                expiration: wrapping_rrsig.expiration
            }
        );
    }
}
