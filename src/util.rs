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
