//! Protocol limits, packet length bounds, and validation constants.
//!
//! Defines DNS wire-format limits established by [RFC 1035], [RFC 6891], and [RFC 8900],
//! along with helper functions for validating message, section, and label lengths
//! prior to encoding.
//!
//! [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
//! [RFC 6891]: https://datatracker.ietf.org/doc/html/rfc6891
//! [RFC 8900]: https://datatracker.ietf.org/doc/html/rfc8900

use crate::errors::EncodeError;

/// Length in bytes of a DNS message header.
pub const DNS_HEADER_LEN: usize = 12;

/// Maximum DNS message size carried by the two-byte TCP length prefix.
pub const MAX_DNS_MESSAGE_LEN: usize = u16::MAX as usize;

/// Maximum encoded DNS name length, including label-length bytes and the root label.
pub const MAX_DNS_NAME_WIRE_LEN: usize = 255;

/// Maximum encoded DNS label length.
pub const MAX_DNS_LABEL_WIRE_LEN: usize = 63;

/// Maximum count representable in DNS section count fields.
pub const MAX_DNS_SECTION_COUNT: usize = u16::MAX as usize;

/// Maximum DNS RDATA length representable in a resource record.
pub const MAX_RDATA_LEN: usize = u16::MAX as usize;

/// Maximum EDNS option data length representable in an EDNS option.
pub const MAX_EDNS_OPTION_DATA_LEN: usize = u16::MAX as usize;

/// Recommended EDNS(0) UDP payload size (1232 bytes) to avoid IP fragmentation,
/// per DNS Flag Day 2020 and [RFC 8900].
///
/// Calculated as the minimum IPv6 MTU (1280 bytes per [RFC 8200 §5]) minus the
/// 40-byte IPv6 header and the 8-byte UDP header: `1280 - 40 - 8 = 1232`.
///
/// Advertising a buffer larger than 1232 over UDP can result in IP packet
/// fragmentation when large responses (such as DNSSEC keys and signatures) are
/// returned. Fragmented UDP packets are frequently dropped by firewalls, NATs,
/// and middleboxes, and are vulnerable to cache poisoning injection attacks.
/// A buffer size of 1232 ensures larger responses signal truncation (`TC=1`),
/// allowing the client to safely fallback to TCP.
///
/// [RFC 8200 §5]: https://datatracker.ietf.org/doc/html/rfc8200#section-5
/// [RFC 8900]: https://datatracker.ietf.org/doc/html/rfc8900
pub const EDNS_SAFE_UDP_PAYLOAD_SIZE: u16 = 1232;

// TODO https://datatracker.ietf.org/doc/html/rfc9715#section-3.2 suggests PAYLOAD_SIZE of 1400

/// Recommended EDNS(0) payload size (4096 bytes) for DNS-over-HTTPS (DoH) queries,
/// per [RFC 8484 §4.2.1] and [RFC 6891 §6.2.3].
///
/// In DoH ([RFC 8484]), transport occurs over HTTPS/TCP where IP fragmentation is
/// not a concern. Using a standardized, fixed payload size of 4096 bytes in every
/// query maximizes HTTP cache friendliness and cache-key alignment across clients.
///
/// [RFC 8484]: https://datatracker.ietf.org/doc/html/rfc8484
/// [RFC 8484 §4.2.1]: https://datatracker.ietf.org/doc/html/rfc8484#section-4.2.1
/// [RFC 6891 §6.2.3]: https://datatracker.ietf.org/doc/html/rfc6891#section-6.2.3
pub const EDNS_DOH_PAYLOAD_SIZE: u16 = 4096;

/// Validates that `len` can be represented as one complete DNS message.
///
/// # Errors
///
/// Returns [`EncodeError::MessageTooLong`] when `len` exceeds
/// [`MAX_DNS_MESSAGE_LEN`].
pub fn validate_message_len(len: usize) -> Result<(), EncodeError> {
    if len > MAX_DNS_MESSAGE_LEN {
        return Err(EncodeError::MessageTooLong {
            max: MAX_DNS_MESSAGE_LEN,
        });
    }
    Ok(())
}

/// Validates that `count` can fit in a DNS section count field.
///
/// # Errors
///
/// Returns [`EncodeError::SectionCountTooLarge`] when `count` exceeds
/// [`MAX_DNS_SECTION_COUNT`].
pub fn validate_section_count(count: usize) -> Result<(), EncodeError> {
    if count > MAX_DNS_SECTION_COUNT {
        return Err(EncodeError::SectionCountTooLarge {
            max: MAX_DNS_SECTION_COUNT,
        });
    }
    Ok(())
}

/// Validates that `domain` can be encoded as a DNS name.
///
/// Unicode input is first converted to ASCII using IDNA processing, matching the
/// message encoder.
///
/// # Errors
///
/// Returns [`EncodeError::InvalidName`] when the domain cannot be IDNA-encoded,
/// [`EncodeError::EmptyLabel`] for an empty non-root label,
/// [`EncodeError::LabelTooLong`] for a label longer than
/// [`MAX_DNS_LABEL_WIRE_LEN`], and [`EncodeError::NameTooLong`] when the encoded
/// name exceeds [`MAX_DNS_NAME_WIRE_LEN`].
pub fn validate_name(domain: &str) -> Result<(), EncodeError> {
    let ascii = idna::domain_to_ascii(domain).map_err(|_| EncodeError::InvalidName {
        name: domain.to_string(),
    })?;

    validate_ascii_name(&ascii)
}

pub(crate) fn validate_ascii_name(domain: &str) -> Result<(), EncodeError> {
    if domain.is_empty() || domain == "." {
        return Ok(());
    }

    let mut wire_len = 1_usize;
    for label in domain.split_terminator('.') {
        if label.is_empty() {
            return Err(EncodeError::EmptyLabel {
                name: domain.to_string(),
            });
        }

        if label.len() > MAX_DNS_LABEL_WIRE_LEN {
            return Err(EncodeError::LabelTooLong {
                label: label.to_string(),
                max: MAX_DNS_LABEL_WIRE_LEN,
            });
        }

        let label_wire_len = label.len() + 1;
        if wire_len > MAX_DNS_NAME_WIRE_LEN - label_wire_len {
            return Err(EncodeError::NameTooLong {
                max: MAX_DNS_NAME_WIRE_LEN,
            });
        }
        wire_len += label_wire_len;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_message_len() {
        assert!(validate_message_len(MAX_DNS_MESSAGE_LEN).is_ok());
        assert!(validate_message_len(MAX_DNS_MESSAGE_LEN + 1).is_err());
    }

    #[test]
    fn validates_section_count() {
        assert!(validate_section_count(MAX_DNS_SECTION_COUNT).is_ok());
        assert!(validate_section_count(MAX_DNS_SECTION_COUNT + 1).is_err());
    }

    #[test]
    fn validates_names() {
        assert!(validate_name(".").is_ok());
        assert!(validate_name("example.com.").is_ok());
        assert!(validate_name(&format!("{}.example.com", "a".repeat(64))).is_err());
        assert!(validate_name(&vec!["a".repeat(63); 4].join(".")).is_err());
    }
}
