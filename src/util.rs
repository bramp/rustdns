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
///    assert_eq!(reverse("127.0.0.1".parse()?), "1.0.0.127.in-addr.arpa.");
///    assert_eq!(reverse("2001:db8::567:89ab".parse()?), "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.");
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
