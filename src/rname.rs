//! DNS mailbox names used by SOA records.

use crate::{FromStrError, limits};
use std::{fmt, str::FromStr};

/// A validated DNS mailbox name with preserved label boundaries.
///
/// Unlike a hostname, the first label represents an entire mailbox local-part,
/// including any literal dots. Presentation strings use RFC 1035 section 5.1
/// escapes and are normalized to an absolute name with a trailing dot.
/// Root and single-label names are valid DNS names, but cannot be converted to
/// an email address.
///
/// ```
/// use rustdns::Rname;
///
/// let name: Rname = r"Action\.domains.ISI.EDU.".parse()?;
/// assert_eq!(name.to_email()?, "Action.domains@ISI.EDU.");
/// assert_eq!(name.to_string(), r"Action\.domains.ISI.EDU.");
/// # Ok::<(), rustdns::FromStrError>(())
/// ```
///
/// [RFC 1035]: https://www.rfc-editor.org/rfc/rfc1035#section-8
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Rname {
    wire: Vec<u8>,
    presentation: String,
}

impl Rname {
    pub(crate) fn from_wire(wire: Vec<u8>) -> Result<Self, FromStrError> {
        let invalid = |reason| FromStrError::InvalidRname {
            rname: format!("{wire:?}"),
            reason,
        };
        if wire.len() > limits::MAX_DNS_NAME_WIRE_LEN {
            return Err(invalid("name exceeds 255 wire octets"));
        }
        let mut remaining = wire.as_slice();
        loop {
            let Some((&length, rest)) = remaining.split_first() else {
                return Err(invalid("missing root label"));
            };
            if length == 0 {
                if !rest.is_empty() {
                    return Err(invalid("bytes after root label"));
                }
                break;
            }
            if usize::from(length) > limits::MAX_DNS_LABEL_WIRE_LEN {
                return Err(invalid("label exceeds 63 octets"));
            }
            remaining = rest
                .get(usize::from(length)..)
                .ok_or_else(|| invalid("truncated label"))?;
        }
        let presentation = Self::render(&wire);
        Ok(Self { wire, presentation })
    }

    /// Parses an escaped DNS mailbox name, preserving case and label bytes.
    ///
    /// Non-ASCII text is interpreted as UTF-8 label bytes, not IDNA. Use
    /// explicit Punycode for internationalized mailbox domains.
    ///
    /// # Errors
    ///
    /// Returns [`FromStrError::InvalidRname`] for malformed escapes, empty
    /// labels, labels exceeding 63 octets, or names exceeding 255 wire octets.
    pub fn new(text: &str) -> Result<Self, FromStrError> {
        let invalid = |reason| FromStrError::InvalidRname {
            rname: text.to_string(),
            reason,
        };
        if text.is_empty() {
            return Err(invalid("empty name"));
        }
        let mut wire = Vec::new();
        if text != "." {
            let mut chars = text.chars();
            let mut label = Vec::new();
            while let Some(character) = chars.next() {
                match character {
                    '.' => {
                        Self::push_label(&mut wire, &label).map_err(invalid)?;
                        label.clear();
                    }
                    '\\' => {
                        let escaped = chars.next().ok_or_else(|| invalid("trailing backslash"))?;
                        if escaped.is_ascii_digit() {
                            let mut value = escaped as u16 - u16::from(b'0');
                            for _ in 0..2 {
                                let digit =
                                    chars.next().filter(char::is_ascii_digit).ok_or_else(|| {
                                        invalid("decimal escape requires three digits")
                                    })?;
                                value = value * 10 + digit as u16 - u16::from(b'0');
                            }
                            label.push(
                                u8::try_from(value)
                                    .map_err(|_| invalid("decimal escape exceeds 255"))?,
                            );
                        } else {
                            label.extend_from_slice(escaped.encode_utf8(&mut [0; 4]).as_bytes());
                        }
                    }
                    c => label.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
                }
                if label.len() > limits::MAX_DNS_LABEL_WIRE_LEN {
                    return Err(invalid("label exceeds 63 octets"));
                }
            }
            if !label.is_empty() {
                Self::push_label(&mut wire, &label).map_err(invalid)?;
            }
        }
        wire.push(0);
        if wire.len() > limits::MAX_DNS_NAME_WIRE_LEN {
            return Err(invalid("name exceeds 255 wire octets"));
        }
        let presentation = Self::render(&wire);
        Ok(Self { wire, presentation })
    }

    fn push_label(wire: &mut Vec<u8>, label: &[u8]) -> Result<(), &'static str> {
        if label.is_empty() {
            return Err("empty label");
        }
        if label.len() > limits::MAX_DNS_LABEL_WIRE_LEN {
            return Err("label exceeds 63 octets");
        }
        let length = u8::try_from(label.len()).map_err(|_| "label exceeds 63 octets")?;
        wire.push(length);
        wire.extend_from_slice(label);
        if wire.len() >= limits::MAX_DNS_NAME_WIRE_LEN {
            return Err("name exceeds 255 wire octets");
        }
        Ok(())
    }

    fn render(wire: &[u8]) -> String {
        use fmt::Write;
        let mut text = String::new();
        let mut remaining = wire;
        while let Some((&length, rest)) = remaining.split_first() {
            if length == 0 {
                break;
            }
            let (label, rest) = rest.split_at(usize::from(length));
            for &byte in label {
                match byte {
                    b'.' | b'\\' | b'"' | b';' | b'(' | b')' | b'@' => {
                        text.push('\\');
                        text.push(char::from(byte));
                    }
                    0x21..=0x7e => text.push(char::from(byte)),
                    _ => {
                        let _ = write!(text, "\\{byte:03}");
                    }
                }
            }
            text.push('.');
            remaining = rest;
        }
        if text.is_empty() {
            text.push('.');
        }
        text
    }

    /// Returns the normalized escaped presentation string.
    pub fn as_str(&self) -> &str {
        &self.presentation
    }

    /// Converts an email address to a DNS mailbox name.
    ///
    /// This accepts an unquoted local-part and a DNS domain, not a complete RFC
    /// 5322 address with display names or comments.
    ///
    /// # Errors
    ///
    /// Returns [`FromStrError::InvalidRname`] for missing or empty address
    /// parts, multiple `@` separators, or DNS length violations.
    pub fn from_email(email: &str) -> Result<Self, FromStrError> {
        let invalid = || FromStrError::InvalidRname {
            rname: email.to_string(),
            reason: "expected a nonempty local-part and domain separated by one '@'",
        };
        let (local, domain) = email.split_once('@').ok_or_else(invalid)?;
        if local.is_empty() || domain.is_empty() || domain == "." || domain.contains('@') {
            return Err(invalid());
        }
        let mut text = String::new();
        for character in local.chars() {
            if matches!(character, '.' | '\\') {
                text.push('\\');
            }
            text.push(character);
        }
        text.push('.');
        text.push_str(domain);
        Self::new(&text)
    }

    /// Converts the first label to a mailbox local-part and the rest to a domain.
    ///
    /// The domain retains its trailing root dot.
    ///
    /// # Errors
    ///
    /// Returns [`FromStrError::InvalidRname`] if the name has no mailbox/domain
    /// pair or the local-part is not UTF-8.
    pub fn to_email(&self) -> Result<String, FromStrError> {
        let invalid = |reason| FromStrError::InvalidRname {
            rname: self.presentation.clone(),
            reason,
        };
        let length = usize::from(self.wire[0]);
        let end = 1 + length;
        if length == 0 || self.wire[end] == 0 {
            return Err(invalid("missing mailbox or domain"));
        }
        let local = std::str::from_utf8(&self.wire[1..end])
            .map_err(|_| invalid("mailbox local-part is not UTF-8"))?;
        Ok(format!("{local}@{}", Self::render(&self.wire[end..])))
    }

    /// Returns this mailbox name in lowercase DNSSEC canonical form.
    ///
    /// Per RFC 4034, canonicalization lowercases ASCII octets in every label,
    /// including the mailbox local-part label.
    #[must_use]
    pub fn to_canonical(&self) -> Self {
        let wire: Vec<u8> = self.wire.iter().map(u8::to_ascii_lowercase).collect();
        let presentation = Self::render(&wire);
        Self { wire, presentation }
    }

    pub(crate) fn append_to_vec(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.wire);
    }
}

impl FromStr for Rname {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<&str> for Rname {
    type Error = FromStrError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<String> for Rname {
    type Error = FromStrError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(&s)
    }
}

impl From<Rname> for String {
    fn from(name: Rname) -> Self {
        name.presentation
    }
}

impl fmt::Display for Rname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.presentation)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Rname {
    fn arbitrary(input: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Self::new(input.arbitrary::<&str>()?).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_conversions_preserve_labels_and_normalize_escapes() {
        let name: Rname = r"Action\046domains.ISI.EDU".parse().unwrap();
        assert_eq!(name.as_str(), r"Action\.domains.ISI.EDU.");
        assert_eq!(Rname::try_from(name.to_string()).unwrap(), name);
        assert_eq!(Rname::try_from(name.as_str()).unwrap(), name);
        assert_eq!(String::from(name.clone()), name.as_str());
        assert_eq!(Rname::from_email(&name.to_email().unwrap()).unwrap(), name);
        let name = Rname::from_email(r"a\b.c@example.com").unwrap();
        assert_eq!(name.as_str(), r"a\\b\.c.example.com.");
        assert_eq!(name.to_email().unwrap(), "a\\b.c@example.com.");
    }

    #[test]
    fn validates_decoded_boundaries_and_escapes() {
        for text in ["", "..", "a..b", r"a\", r"a\1", r"a\12", r"a\999"] {
            assert!(Rname::new(text).is_err(), "{text:?}");
        }
        assert!(Rname::new(&"a".repeat(63)).is_ok());
        assert!(Rname::new(&"a".repeat(64)).is_err());
        assert!(Rname::new(&r"\065".repeat(63)).is_ok());
        assert!(Rname::new(&r"\065".repeat(64)).is_err());
        let max = [63, 63, 63, 61].map(|n| "a".repeat(n)).join(".");
        assert_eq!(Rname::new(&max).unwrap().wire.len(), 255);
        assert!(Rname::new(&(max + "a")).is_err());
        assert!(Rname::new(".").unwrap().to_email().is_err());
        assert!(Rname::new("single.").unwrap().to_email().is_err());
        for email in ["", "@example.com", "a@", "a@.", "a@b@c"] {
            assert!(Rname::from_email(email).is_err(), "{email:?}");
        }
    }

    #[test]
    fn all_octets_round_trip_without_label_loss() {
        for byte in 0..=u8::MAX {
            let name = Rname::new(&format!(r"\{byte:03}.example.")).unwrap();
            assert_eq!(name.wire[1], byte);
            assert_eq!(name.as_str().parse::<Rname>().unwrap(), name);
            let mut wire = Vec::new();
            name.append_to_vec(&mut wire);
            use crate::io::DNSReadExt;
            let decoded = std::io::Cursor::new(wire.as_slice()).read_rname().unwrap();
            assert_eq!(decoded, name);
            assert_eq!(Rname::from_wire(wire).unwrap(), name);
        }
    }

    #[test]
    fn wire_constructor_rejects_invalid_labels_and_termination() {
        for wire in [
            vec![],
            vec![1],
            vec![1, b'a'],
            vec![0, 0],
            vec![64, 0],
            vec![0; 256],
        ] {
            assert!(Rname::from_wire(wire).is_err());
        }
        assert_eq!(Rname::from_wire(vec![0]).unwrap().as_str(), ".");
    }

    #[test]
    fn canonical_wire_lowercases_without_splitting_labels() {
        let name = Rname::new(r"Action\.domains.ISI.EDU.").unwrap();
        assert_eq!(name.to_canonical().as_str(), r"action\.domains.isi.edu.");
        let mut wire = Vec::new();
        name.to_canonical().append_to_vec(&mut wire);
        assert_eq!(wire, b"\x0eaction.domains\x03isi\x03edu\0");
    }

    #[test]
    fn wire_reader_rejects_malformed_compression_and_oversized_names() {
        use crate::io::DNSReadExt;
        let mut oversized = [vec![63], vec![b'a'; 63]].concat().repeat(4);
        oversized.push(0);
        for bytes in [
            vec![0xc0, 0],
            vec![0xc0, 2],
            vec![0x80],
            vec![3, b'a'],
            oversized,
        ] {
            assert!(std::io::Cursor::new(bytes.as_slice()).read_rname().is_err());
        }
        let mut bytes = vec![0];
        bytes.extend_from_slice(b"\x05local\xc0\x00");
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        cursor.set_position(1);
        assert_eq!(cursor.read_rname().unwrap().as_str(), "local.");
    }
}
