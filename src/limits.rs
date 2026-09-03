use std::io;

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

/// Validates that `len` can be represented as one complete DNS message.
///
/// # Errors
///
/// Returns an error when `len` exceeds [`MAX_DNS_MESSAGE_LEN`].
pub fn validate_message_len(len: usize) -> io::Result<()> {
    if len > MAX_DNS_MESSAGE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS message is too large",
        ));
    }
    Ok(())
}

/// Validates that `count` can fit in a DNS section count field.
///
/// # Errors
///
/// Returns an error when `count` exceeds [`MAX_DNS_SECTION_COUNT`].
pub fn validate_section_count(count: usize) -> io::Result<()> {
    if count > MAX_DNS_SECTION_COUNT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS section count is too large",
        ));
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
/// Returns an error when the domain cannot be IDNA-encoded, contains an empty
/// non-root label, contains a label longer than [`MAX_DNS_LABEL_WIRE_LEN`], or
/// exceeds [`MAX_DNS_NAME_WIRE_LEN`] when encoded.
pub fn validate_name(domain: &str) -> io::Result<()> {
    let domain = idna::domain_to_ascii(domain).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid dns name '{domain}': {error}"),
        )
    })?;

    validate_ascii_name(&domain)
}

pub(crate) fn validate_ascii_name(domain: &str) -> io::Result<()> {
    if domain.is_empty() || domain == "." {
        return Ok(());
    }

    let mut wire_len = 1_usize;
    for label in domain.split_terminator('.') {
        if label.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("empty label in domain name '{domain}'"),
            ));
        }

        if label.len() > MAX_DNS_LABEL_WIRE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("label '{label}' longer than {MAX_DNS_LABEL_WIRE_LEN} characters"),
            ));
        }

        let label_wire_len = label.len() + 1;
        if wire_len > MAX_DNS_NAME_WIRE_LEN - label_wire_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("domain name is longer than {MAX_DNS_NAME_WIRE_LEN} bytes"),
            ));
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
