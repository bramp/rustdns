use std::fmt::Write;
use std::net::IpAddr;
use std::net::IpAddr::V4;
use std::net::IpAddr::V6;

#[cfg(test)]
use pretty_assertions::assert_eq;

/// Returns the reverse DNS name for this IP address. Suitable for use with
/// [`Type::PTR`] records. See [rfc1035] and [rfc3596] for IPv4 and IPv6 respectively.
///
/// # Example
///
/// ```rust
/// use rustdns::util::reverse;
///
/// let ip4 = "127.0.0.1".parse().unwrap();
/// let ip6 = "2001:db8::567:89ab".parse().unwrap();
///
/// assert_eq!(reverse(ip4), "1.0.0.127.in-addr.arpa.");
/// assert_eq!(reverse(ip6), "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.");
/// ```
///
/// [`Type::PTR`]: crate::Type::PTR
/// [rfc1035]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.5
/// [rfc3596]: https://datatracker.ietf.org/doc/html/rfc3596#section-2.5
pub fn reverse(ip: IpAddr) -> String {
    match ip {
        V4(ipv4) => {
            let octets = ipv4.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa.",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        V6(ipv6) => {
            let mut result = String::new();
            for o in ipv6.octets().iter().rev() {
                write!(
                    result,
                    "{:x}.{:x}.",
                    o & 0b0000_1111,
                    (o & 0b1111_0000) >> 4
                )
                .unwrap(); // Impossible for write! to fail when appending to a string.
            }
            result.push_str("ip6.arpa.");
            result
        }
    }
}

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

/// Encodes binary data to standard base64 (RFC 4648).
#[must_use]
pub(crate) fn base64_encode(data: &[u8]) -> String {
    BASE64_STANDARD.encode(data)
}

/// Decodes standard base64 data (RFC 4648), ignoring ASCII whitespace.
///
/// # Errors
///
/// Returns an error message if the input contains invalid base64 characters or has an invalid length.
pub(crate) fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    BASE64_STANDARD.decode(&clean).map_err(|e| e.to_string())
}

/// Encodes binary data to an uppercase hexadecimal string.
#[must_use]
pub(crate) fn hex_encode(data: &[u8]) -> String {
    hex::encode_upper(data)
}

/// Decodes a hexadecimal string, ignoring ASCII whitespace.
///
/// # Errors
///
/// Returns an error message if the input contains non-hex characters or has an odd length.
pub(crate) fn hex_decode(input: &str) -> Result<Vec<u8>, String> {
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    hex::decode(&clean).map_err(|e| e.to_string())
}

const BASE32_HEX_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// Encodes binary data to an unpadded uppercase Base32 Extended Hex string (RFC 4648 §7 / RFC 5155).
///
/// Implemented directly in-tree to avoid pulling in an external dependency (e.g. `data-encoding`).
#[must_use]
pub(crate) fn base32hex_encode(data: &[u8]) -> String {
    let mut s = String::new();
    let mut buffer: u64 = 0;
    let mut bits_in_buf = 0;
    for &b in data {
        buffer = (buffer << 8) | u64::from(b);
        bits_in_buf += 8;
        while bits_in_buf >= 5 {
            bits_in_buf -= 5;
            let idx = ((buffer >> bits_in_buf) & 0x1F) as usize;
            s.push(BASE32_HEX_ALPHABET[idx] as char);
        }
    }
    if bits_in_buf > 0 {
        let idx = ((buffer << (5 - bits_in_buf)) & 0x1F) as usize;
        s.push(BASE32_HEX_ALPHABET[idx] as char);
    }
    s
}

/// Decodes an unpadded Base32 Extended Hex string (case-insensitive, ignoring whitespace) per RFC 4648 §7.
///
/// Implemented directly in-tree to avoid pulling in an external dependency.
#[allow(dead_code)]
pub(crate) fn base32hex_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits_in_buf = 0;
    for c in input.chars().filter(|c| !c.is_ascii_whitespace()) {
        let val = match c {
            '0'..='9' => c as u8 - b'0',
            'a'..='v' => c as u8 - b'a' + 10,
            'A'..='V' => c as u8 - b'A' + 10,
            _ => return Err(format!("invalid base32hex character '{c}'")),
        };
        buffer = (buffer << 5) | u64::from(val);
        bits_in_buf += 5;
        if bits_in_buf >= 8 {
            bits_in_buf -= 8;
            out.push(((buffer >> bits_in_buf) & 0xFF) as u8);
        }
    }
    Ok(out)
}

/// Compares two 32-bit serial numbers using [RFC 1982] Serial Number Arithmetic.
///
/// This ordering is used for:
/// - DNS SOA serial numbers ([RFC 1034], [RFC 1982 §3.2])
/// - DNSSEC RRSIG `inception` and `expiration` timestamp comparisons ([RFC 4034 §3.1.5])
///
/// # Definition
/// For two 32-bit serial numbers $s_1$ and $s_2$:
/// - $s_1 == s_2$ if and only if $s_1 = s_2$.
/// - $s_1 < s_2$ if and only if $s_1 \neq s_2$ and $((s_1 < s_2 \text{ and } s_2 - s_1 < 2^{31}) \text{ or } (s_1 > s_2 \text{ and } s_1 - s_2 > 2^{31}))$.
/// - $s_1 > s_2$ if and only if $s_1 \neq s_2$ and $((s_1 < s_2 \text{ and } s_2 - s_1 > 2^{31}) \text{ or } (s_1 > s_2 \text{ and } s_1 - s_2 < 2^{31}))$.
/// - When $|s_1 - s_2| = 2^{31}$, the ordering is undefined per RFC 1982 and `None` is returned.
///
/// # Examples
/// ```rust
/// use rustdns::util::{serial_cmp, serial_lt};
/// use std::cmp::Ordering;
///
/// assert_eq!(serial_cmp(10, 20), Some(Ordering::Less));
/// assert_eq!(serial_cmp(20, 10), Some(Ordering::Greater));
/// assert_eq!(serial_cmp(100, 100), Some(Ordering::Equal));
///
/// // Wrap-around across 2^32:
/// assert!(serial_lt(u32::MAX, 10)); // u32::MAX is 11 steps before 10
/// assert!(!serial_lt(10, u32::MAX));
///
/// // Undefined boundary at distance 2^31:
/// assert_eq!(serial_cmp(0, 1 << 31), None);
/// ```
///
/// [RFC 1034]: https://datatracker.ietf.org/doc/html/rfc1034
/// [RFC 1982]: https://datatracker.ietf.org/doc/html/rfc1982#section-3.2
/// [RFC 1982 §3.2]: https://datatracker.ietf.org/doc/html/rfc1982#section-3.2
/// [RFC 4034 §3.1.5]: https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.5
#[must_use]
pub fn serial_cmp(s1: u32, s2: u32) -> Option<std::cmp::Ordering> {
    if s1 == s2 {
        return Some(std::cmp::Ordering::Equal);
    }
    let diff = s1.wrapping_sub(s2);
    if diff == 1 << 31 {
        None
    } else if (diff as i32) < 0 {
        Some(std::cmp::Ordering::Less)
    } else {
        Some(std::cmp::Ordering::Greater)
    }
}

/// Returns `true` if `s1 < s2` in [RFC 1982] serial number arithmetic.
///
/// [RFC 1982]: https://datatracker.ietf.org/doc/html/rfc1982#section-3.2
#[must_use]
pub fn serial_lt(s1: u32, s2: u32) -> bool {
    serial_cmp(s1, s2) == Some(std::cmp::Ordering::Less)
}

/// Returns `true` if `s1 <= s2` in [RFC 1982] serial number arithmetic.
///
/// [RFC 1982]: https://datatracker.ietf.org/doc/html/rfc1982#section-3.2
#[must_use]
pub fn serial_le(s1: u32, s2: u32) -> bool {
    matches!(
        serial_cmp(s1, s2),
        Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
    )
}

/// Returns `true` if `s1 > s2` in [RFC 1982] serial number arithmetic.
///
/// [RFC 1982]: https://datatracker.ietf.org/doc/html/rfc1982#section-3.2
#[must_use]
pub fn serial_gt(s1: u32, s2: u32) -> bool {
    serial_cmp(s1, s2) == Some(std::cmp::Ordering::Greater)
}

/// Returns `true` if `s1 >= s2` in [RFC 1982] serial number arithmetic.
///
/// [RFC 1982]: https://datatracker.ietf.org/doc/html/rfc1982#section-3.2
#[must_use]
pub fn serial_ge(s1: u32, s2: u32) -> bool {
    matches!(
        serial_cmp(s1, s2),
        Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
    )
}

#[test]
fn test_reverse() {
    let tests: Vec<(IpAddr, &str)> = vec![
        ("127.0.0.1".parse().unwrap(), "1.0.0.127.in-addr.arpa."),
        ("8.8.4.4".parse().unwrap(), "4.4.8.8.in-addr.arpa."),
        (
            "2001:db8::567:89ab".parse().unwrap(),
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        ),
    ];

    for test in tests {
        assert_eq!(reverse(test.0), test.1);
    }
}

#[test]
fn test_base64_roundtrip() {
    let test_cases: &[&[u8]] = &[
        b"",
        b"f",
        b"fo",
        b"foo",
        b"foob",
        b"fooba",
        b"foobar",
        &[0, 1, 2, 255, 254, 128, 64],
    ];

    for &data in test_cases {
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).expect("valid base64 decode");
        assert_eq!(decoded, data);
    }

    // Whitespace tolerance in decoding
    let decoded = base64_decode("Zm9v \n\t YmFy").expect("valid decode with whitespace");
    assert_eq!(decoded, b"foobar");
}

#[test]
fn test_base32hex_roundtrip() {
    let test_cases: &[(&[u8], &str)] = &[
        (b"", ""),
        (b"f", "CO"),
        (b"fo", "CPNG"),
        (b"foo", "CPNMU"),
        (b"foob", "CPNMUOG"),
        (b"fooba", "CPNMUOJ1"),
        (b"foobar", "CPNMUOJ1E8"),
    ];

    for &(data, expected_prefix) in test_cases {
        let encoded = base32hex_encode(data);
        assert_eq!(encoded, expected_prefix);
        let decoded = base32hex_decode(&encoded).expect("valid base32hex decode");
        assert_eq!(decoded, data);
    }

    // Case insensitivity
    let decoded = base32hex_decode("cpnmuoj1e8").expect("valid lowercase base32hex");
    assert_eq!(decoded, b"foobar");
}

#[test]
fn test_hex_roundtrip() {
    let test_cases: &[&[u8]] = &[b"", b"f", b"foobar", &[0x00, 0x0F, 0xFA, 0xCE, 0xFF]];

    for &data in test_cases {
        let encoded = hex_encode(data);
        let decoded = hex_decode(&encoded).expect("valid hex decode");
        assert_eq!(decoded, data);
    }

    // Whitespace tolerance in decoding
    let decoded = hex_decode("46 5d 6f 58").expect("valid decode with whitespace");
    assert_eq!(decoded, &[0x46, 0x5D, 0x6F, 0x58]);
}

#[test]
fn test_serial_arithmetic() {
    use std::cmp::Ordering;

    // Standard ordering
    assert_eq!(serial_cmp(1, 2), Some(Ordering::Less));
    assert_eq!(serial_cmp(2, 1), Some(Ordering::Greater));
    assert_eq!(serial_cmp(42, 42), Some(Ordering::Equal));
    assert!(serial_lt(1, 2));
    assert!(serial_le(1, 2));
    assert!(serial_le(2, 2));
    assert!(serial_gt(2, 1));
    assert!(serial_ge(2, 1));
    assert!(serial_ge(2, 2));

    // Wrap-around across 2^32 boundary
    assert!(serial_lt(u32::MAX, 0));
    assert!(serial_lt(u32::MAX, 100));
    assert!(serial_gt(0, u32::MAX));
    assert!(serial_gt(100, u32::MAX));

    // RFC 1982 examples and distances
    assert!(serial_lt(0, (1 << 31) - 1));
    assert!(serial_gt((1 << 31) - 1, 0));

    // Undefined boundary cases (distance exactly 2^31)
    assert_eq!(serial_cmp(0, 1 << 31), None);
    assert_eq!(serial_cmp(1 << 31, 0), None);
    assert!(!serial_lt(0, 1 << 31));
    assert!(!serial_gt(0, 1 << 31));
}
