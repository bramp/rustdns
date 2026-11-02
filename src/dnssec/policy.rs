//! Caller-configurable DNSSEC key policy.

use std::fmt;

/// Range of RSA modulus sizes, in bits, accepted for RSA/SHA-256 and
/// RSA/SHA-512 DNSKEYs.
///
/// [RFC 3110 §2] and [RFC 5702 §2] limit RSA DNSKEYs to at most 4096 bits.
/// Many zones (including several TLDs) still sign with 1024-bit
/// zone-signing keys, which [RFC 6781 §3.4.2] considers acceptable, so the
/// default range is 1024 to 4096 bits. Callers wanting stronger guarantees
/// can raise the minimum, for example to 2048 bits; data signed only by
/// smaller keys then fails validation with [`DnssecError::RsaKeySize`].
///
/// The supported range, [`Self::SUPPORTED_BITS`], is 1024 to 8192 bits.
///
/// # Examples
///
/// ```
/// use rustdns::dnssec::RsaKeySizePolicy;
///
/// let strict = RsaKeySizePolicy::new(2048, 4096)?;
/// assert!(!strict.allows(1024));
/// assert!(RsaKeySizePolicy::default().allows(1024));
/// # Ok::<(), rustdns::Error>(())
/// ```
///
/// [`DnssecError::RsaKeySize`]: crate::DnssecError::RsaKeySize
/// [RFC 3110 §2]: https://datatracker.ietf.org/doc/html/rfc3110#section-2
/// [RFC 5702 §2]: https://datatracker.ietf.org/doc/html/rfc5702#section-2
/// [RFC 6781 §3.4.2]: https://datatracker.ietf.org/doc/html/rfc6781#section-3.4.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RsaKeySizePolicy {
    min_bits: u16,
    max_bits: u16,
}

impl RsaKeySizePolicy {
    /// Smallest and largest RSA modulus sizes the cryptographic backends can verify.
    pub const SUPPORTED_BITS: std::ops::RangeInclusive<u16> = 1024..=8192;

    /// Creates a policy accepting RSA moduli from `min_bits` to `max_bits` inclusive.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedRsaKeySizes`] if `min_bits` exceeds
    /// `max_bits` or either bound is outside [`Self::SUPPORTED_BITS`].
    ///
    /// [`Error::UnsupportedRsaKeySizes`]: crate::Error::UnsupportedRsaKeySizes
    pub fn new(min_bits: u16, max_bits: u16) -> Result<Self, crate::Error> {
        if min_bits > max_bits
            || !Self::SUPPORTED_BITS.contains(&min_bits)
            || !Self::SUPPORTED_BITS.contains(&max_bits)
        {
            return Err(crate::Error::UnsupportedRsaKeySizes { min_bits, max_bits });
        }
        Ok(Self { min_bits, max_bits })
    }

    /// Returns the smallest accepted modulus size, in bits.
    #[must_use]
    pub fn min_bits(&self) -> u16 {
        self.min_bits
    }

    /// Returns the largest accepted modulus size, in bits.
    #[must_use]
    pub fn max_bits(&self) -> u16 {
        self.max_bits
    }

    /// Returns `true` if a modulus of `bits` bits is accepted.
    #[must_use]
    pub fn allows(&self, bits: usize) -> bool {
        (usize::from(self.min_bits)..=usize::from(self.max_bits)).contains(&bits)
    }
}

impl Default for RsaKeySizePolicy {
    fn default() -> Self {
        Self {
            min_bits: 1024,
            max_bits: 4096,
        }
    }
}

impl fmt::Display for RsaKeySizePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..={} bits", self.min_bits, self.max_bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_accepts_deployed_and_rfc_sizes() {
        let policy = RsaKeySizePolicy::default();
        assert!(!policy.allows(1023));
        assert!(policy.allows(1024));
        assert!(policy.allows(4096));
        assert!(!policy.allows(4097));
        assert_eq!(policy.to_string(), "1024..=4096 bits");
    }

    #[test]
    fn new_rejects_empty_or_unsupported_ranges() {
        assert!(RsaKeySizePolicy::new(2048, 2048).is_ok());
        assert!(RsaKeySizePolicy::new(1024, 8192).is_ok());
        for (min, max) in [(2048, 1024), (512, 4096), (1024, 8193), (0, 0)] {
            assert!(
                matches!(
                    RsaKeySizePolicy::new(min, max),
                    Err(crate::Error::UnsupportedRsaKeySizes { min_bits, max_bits })
                        if min_bits == min && max_bits == max
                ),
                "{min}..={max}"
            );
        }
    }
}
