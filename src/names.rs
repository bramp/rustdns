//! Domain name manipulation, normalization, and canonical ordering.
//!
//! Provides utilities for:
//! - Normalizing domain names into canonical FQDN representation ([`normalise`]).
//! - Converting between Unicode and ASCII (Punycode / IDNA) formats ([`to_ascii`], [`to_unicode`]).
//! - Comparing domain names according to Canonical DNS Name Order ([RFC 4034 §6.1], [`canonical_cmp`]).
//! - Inspecting domain hierarchy ([`count_labels`], [`parent_zone`], [`parent`], [`is_subdomain_of`]).
//!
//! [RFC 4034 §6.1]: https://datatracker.ietf.org/doc/html/rfc4034#section-6.1

use crate::errors::EncodeError;
use crate::limits;
use std::borrow::Cow;
use std::cmp::Ordering;

/// Normalizes a domain name into standard Fully Qualified Domain Name (FQDN) form.
///
/// Processing:
/// 1. Converts input via IDNA ([`idna::domain_to_ascii`]), enforcing Punycode decoding rules.
/// 2. Validates label length limits (max 63 octets) and total wire name length (max 255 octets).
/// 3. Converts the validated name to Unicode representation ([`idna::domain_to_unicode`]).
/// 4. Ensures the domain has a trailing dot (`.`).
///
/// Root domain inputs (`""` or `"."`) normalize to `"."`.
///
/// # Errors
///
/// Returns [`EncodeError::InvalidName`] if IDNA conversion fails,
/// [`EncodeError::LabelTooLong`] if any label exceeds 63 bytes,
/// [`EncodeError::NameTooLong`] if total wire length exceeds 255 bytes, or
/// [`EncodeError::EmptyLabel`] if an interior label is empty (e.g. `"foo..bar"`).
///
/// # Examples
/// ```rust
/// use rustdns::names::normalise;
///
/// assert_eq!(normalise("example.com").unwrap(), "example.com.");
/// assert_eq!(normalise("EXAMPLE.COM.").unwrap(), "example.com.");
/// assert_eq!(normalise("🍕.ws").unwrap(), "🍕.ws.");
/// assert_eq!(normalise(".").unwrap(), ".");
/// assert_eq!(normalise("").unwrap(), ".");
/// ```
pub fn normalise(domain: &str) -> Result<String, EncodeError> {
    if domain.is_empty() || domain == "." {
        return Ok(".".to_string());
    }

    let ascii = idna::domain_to_ascii(domain).map_err(|_| EncodeError::InvalidName {
        name: domain.to_string(),
    })?;

    limits::validate_ascii_name(&ascii)?;

    let (mut unicode, result) = idna::domain_to_unicode(&ascii);
    if result.is_err() {
        return Err(EncodeError::InvalidName {
            name: domain.to_string(),
        });
    }

    if !unicode.ends_with('.') {
        unicode.push('.');
    }

    Ok(unicode)
}

/// Alias for [`normalise`].
#[inline]
pub fn normalize(domain: &str) -> Result<String, EncodeError> {
    normalise(domain)
}

/// Converts a domain name to lowercase ASCII (Punycode / IDNA) format.
///
/// If `domain` has a trailing dot, the returned ASCII string will also have a trailing dot.
///
/// # Errors
///
/// Returns [`EncodeError::InvalidName`] if `domain` cannot be converted to ASCII by IDNA.
///
/// # Examples
/// ```rust
/// use rustdns::names::to_ascii;
///
/// assert_eq!(to_ascii("example.com").unwrap(), "example.com");
/// assert_eq!(to_ascii("EXAMPLE.COM.").unwrap(), "example.com.");
/// assert_eq!(to_ascii("🍕.ws.").unwrap(), "xn--vi8h.ws.");
/// ```
pub fn to_ascii(domain: &str) -> Result<String, EncodeError> {
    let ascii = idna::domain_to_ascii(domain).map_err(|_| EncodeError::InvalidName {
        name: domain.to_string(),
    })?;
    Ok(ascii.to_ascii_lowercase())
}

/// Converts an ASCII/Punycode domain name into Unicode representation.
///
/// # Errors
///
/// Returns [`EncodeError::InvalidName`] if `domain` cannot be converted to Unicode by IDNA.
///
/// # Examples
/// ```rust
/// use rustdns::names::to_unicode;
///
/// assert_eq!(to_unicode("xn--vi8h.ws.").unwrap(), "🍕.ws.");
/// assert_eq!(to_unicode("example.com").unwrap(), "example.com");
/// ```
pub fn to_unicode(domain: &str) -> Result<String, EncodeError> {
    let (unicode, result) = idna::domain_to_unicode(domain);
    if result.is_err() {
        return Err(EncodeError::InvalidName {
            name: domain.to_string(),
        });
    }
    Ok(unicode)
}

/// Returns a lowercase ASCII key without a trailing dot, suitable for map lookups and caches.
///
/// # Examples
/// ```rust
/// use rustdns::names::canonical_key;
///
/// assert_eq!(canonical_key("Example.COM."), "example.com");
/// assert_eq!(canonical_key("."), "");
/// assert_eq!(canonical_key("🍕.ws."), "xn--vi8h.ws");
/// ```
#[must_use]
pub fn canonical_key(name: &str) -> String {
    let ascii = match idna::domain_to_ascii(name) {
        Ok(ascii) => ascii,
        Err(_) => name.to_string(),
    };
    ascii.trim_end_matches('.').to_ascii_lowercase()
}

/// Compares two domain names according to Canonical DNS Name Order ([RFC 4034 §6.1]).
///
/// Ordering rules:
/// 1. Labels are ordered from right-to-left (most significant to least significant).
/// 2. Within each label, bytes are compared lexicographically as unsigned octets,
///    treating ASCII letters case-insensitively.
/// 3. If all common labels match, the name with fewer labels sorts first (e.g. `example.com` < `a.example.com`).
///
/// Unicode domain names are normalized to wire-equivalent ASCII (Punycode) before comparison,
/// ensuring that `"🍕.ws"` sorts identically to `"xn--vi8h.ws"`.
///
/// # Examples
/// ```rust
/// use rustdns::names::canonical_cmp;
/// use std::cmp::Ordering;
///
/// assert_eq!(canonical_cmp("example.com", "example.com."), Ordering::Equal);
/// assert_eq!(canonical_cmp("a.example.com", "b.example.com"), Ordering::Less);
/// assert_eq!(canonical_cmp("example.com", "a.example.com"), Ordering::Less);
/// assert_eq!(canonical_cmp("🍕.ws", "xn--vi8h.ws"), Ordering::Equal);
/// ```
///
/// [RFC 4034 §6.1]: https://datatracker.ietf.org/doc/html/rfc4034#section-6.1
#[must_use]
pub fn canonical_cmp(a: &str, b: &str) -> Ordering {
    let a_cow = if a.is_ascii() {
        Cow::Borrowed(a)
    } else {
        match idna::domain_to_ascii(a) {
            Ok(ascii) => Cow::Owned(ascii),
            Err(_) => Cow::Borrowed(a),
        }
    };

    let b_cow = if b.is_ascii() {
        Cow::Borrowed(b)
    } else {
        match idna::domain_to_ascii(b) {
            Ok(ascii) => Cow::Owned(ascii),
            Err(_) => Cow::Borrowed(b),
        }
    };

    let a_trimmed = a_cow.trim_matches('.');
    let b_trimmed = b_cow.trim_matches('.');

    if a_trimmed.is_empty() && b_trimmed.is_empty() {
        return Ordering::Equal;
    }
    if a_trimmed.is_empty() {
        return Ordering::Less;
    }
    if b_trimmed.is_empty() {
        return Ordering::Greater;
    }

    let a_count = a_trimmed.split('.').count();
    let b_count = b_trimmed.split('.').count();

    let a_rev = a_trimmed.split('.').rev();
    let b_rev = b_trimmed.split('.').rev();

    for (la, lb) in a_rev.zip(b_rev) {
        let cmp = cmp_label_bytes(la.as_bytes(), lb.as_bytes());
        if cmp != Ordering::Equal {
            return cmp;
        }
    }

    a_count.cmp(&b_count)
}

/// Alias for [`canonical_cmp`], preserving backward compatibility.
#[inline]
#[must_use]
pub fn canonical_name_cmp(a: &str, b: &str) -> Ordering {
    canonical_cmp(a, b)
}

/// Lexicographically compares two label byte slices case-insensitively per RFC 4034 §6.1.
fn cmp_label_bytes(a: &[u8], b: &[u8]) -> Ordering {
    for (&ba, &bb) in a.iter().zip(b.iter()) {
        let la = ba.to_ascii_lowercase();
        let lb = bb.to_ascii_lowercase();
        if la != lb {
            return la.cmp(&lb);
        }
    }
    a.len().cmp(&b.len())
}

/// Computes the number of labels in a domain name, excluding the root label.
///
/// # Examples
/// ```rust
/// use rustdns::names::count_labels;
///
/// assert_eq!(count_labels("."), 0);
/// assert_eq!(count_labels(""), 0);
/// assert_eq!(count_labels("com."), 1);
/// assert_eq!(count_labels("example.com."), 2);
/// assert_eq!(count_labels("a.b.c.example.com"), 5);
/// ```
#[must_use]
pub fn count_labels(name: &str) -> u8 {
    let trimmed = name.trim_matches('.');
    if trimmed.is_empty() {
        0
    } else {
        trimmed.split('.').count().min(255) as u8
    }
}

/// Computes the parent zone name with a trailing dot.
///
/// Returns `""` if `zone` is the root (`"."` or `""`).
///
/// # Examples
/// ```rust
/// use rustdns::names::parent_zone;
///
/// assert_eq!(parent_zone("www.example.com."), "example.com.");
/// assert_eq!(parent_zone("example.com."), "com.");
/// assert_eq!(parent_zone("com."), ".");
/// assert_eq!(parent_zone("."), "");
/// assert_eq!(parent_zone(""), "");
/// ```
#[must_use]
pub fn parent_zone(zone: &str) -> String {
    let trimmed = zone.trim_end_matches('.');
    if trimmed.is_empty() {
        return String::new();
    }
    match trimmed.split_once('.') {
        Some((_, rest)) => format!("{rest}."),
        None => ".".to_string(),
    }
}

/// Returns the parent domain of `name`, or `None` if `name` is the root domain (`"."` or `""`).
///
/// Preserves the presence or absence of a trailing dot from `name`.
///
/// # Examples
/// ```rust
/// use rustdns::names::parent;
///
/// assert_eq!(parent("www.example.com."), Some("example.com."));
/// assert_eq!(parent("example.com"), Some("com"));
/// assert_eq!(parent("com."), Some("."));
/// assert_eq!(parent("."), None);
/// assert_eq!(parent(""), None);
/// ```
#[must_use]
pub fn parent(name: &str) -> Option<&str> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.find('.') {
        Some(idx) => {
            if name.ends_with('.') {
                Some(&name[idx + 1..])
            } else {
                Some(&trimmed[idx + 1..])
            }
        }
        None => {
            if name.ends_with('.') {
                Some(".")
            } else {
                Some("")
            }
        }
    }
}

/// Checks whether `name` is a subdomain of (or equal to) `parent`.
///
/// Comparison is case-insensitive.
///
/// # Examples
/// ```rust
/// use rustdns::names::is_subdomain_of;
///
/// assert!(is_subdomain_of("sub.example.com.", "example.com."));
/// assert!(is_subdomain_of("example.com.", "example.com."));
/// assert!(is_subdomain_of("example.com.", "."));
/// assert!(!is_subdomain_of("notexample.com.", "example.com."));
/// ```
#[must_use]
pub fn is_subdomain_of(name: &str, parent: &str) -> bool {
    let n = name.trim_matches('.');
    let p = parent.trim_matches('.');
    if p.is_empty() {
        return true; // Everything is under root
    }
    if n.eq_ignore_ascii_case(p) {
        return true;
    }
    if let Some(prefix) = n.strip_suffix(p) {
        if prefix.ends_with('.') {
            return true;
        }
    }
    false
}

/// Checks whether `name` represents the DNS root domain (`"."` or `""`).
///
/// # Examples
/// ```rust
/// use rustdns::names::is_root;
///
/// assert!(is_root("."));
/// assert!(is_root(""));
/// assert!(!is_root("com."));
/// ```
#[inline]
#[must_use]
pub fn is_root(name: &str) -> bool {
    name.is_empty() || name == "."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalise_domains() {
        assert_eq!(normalise("example.com").unwrap(), "example.com.");
        assert_eq!(normalise("EXAMPLE.COM.").unwrap(), "example.com.");
        assert_eq!(normalise("🍕.ws").unwrap(), "🍕.ws.");
        assert_eq!(normalise("xn--vi8h.ws").unwrap(), "🍕.ws.");
        assert_eq!(normalise(".").unwrap(), ".");
        assert_eq!(normalise("").unwrap(), ".");

        // Rejection of invalid names
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(normalise(&long_label).is_err());
    }

    #[test]
    fn test_to_ascii_and_to_unicode() {
        assert_eq!(to_ascii("example.com.").unwrap(), "example.com.");
        assert_eq!(to_ascii("🍕.ws").unwrap(), "xn--vi8h.ws");
        assert_eq!(to_unicode("xn--vi8h.ws.").unwrap(), "🍕.ws.");
    }

    #[test]
    fn test_canonical_key() {
        assert_eq!(canonical_key("EXAMPLE.com."), "example.com");
        assert_eq!(canonical_key("."), "");
        assert_eq!(canonical_key("🍕.ws."), "xn--vi8h.ws");
    }

    #[test]
    fn test_canonical_cmp() {
        // Equal
        assert_eq!(
            canonical_cmp("example.com", "example.com."),
            Ordering::Equal
        );
        assert_eq!(canonical_cmp("EXAMPLE.com", "example.COM"), Ordering::Equal);
        assert_eq!(canonical_cmp(".", "."), Ordering::Equal);
        assert_eq!(canonical_cmp("", "."), Ordering::Equal);

        // Unicode vs Punycode equivalence
        assert_eq!(canonical_cmp("🍕.ws", "xn--vi8h.ws"), Ordering::Equal);

        // Hierarchy ordering
        assert_eq!(
            canonical_cmp("example.com", "a.example.com"),
            Ordering::Less
        );
        assert_eq!(
            canonical_cmp("a.example.com", "b.example.com"),
            Ordering::Less
        );

        // Unicode sorting: xn--vi8h.ws < z.ws
        assert_eq!(canonical_cmp("🍕.ws", "z.ws"), Ordering::Less);

        // RFC 4034 §6.1 sorting example
        let sorted = [
            "example",
            "a.example",
            "yljkjljk.a.example",
            "Z.a.example",
            "zABC.a.EXAMPLE",
            "z.example",
            "\x01.z.example",
            "*.z.example",
            "\u{0080}.z.example",
        ];

        for i in 0..sorted.len() {
            for j in 0..sorted.len() {
                let expected = i.cmp(&j);
                let actual = canonical_cmp(sorted[i], sorted[j]);
                assert_eq!(
                    actual, expected,
                    "comparison failed between '{}' and '{}'",
                    sorted[i], sorted[j]
                );
            }
        }
    }

    #[test]
    fn test_count_labels() {
        assert_eq!(count_labels("."), 0);
        assert_eq!(count_labels(""), 0);
        assert_eq!(count_labels("com."), 1);
        assert_eq!(count_labels("example.com."), 2);
        assert_eq!(count_labels("a.b.c.example.com"), 5);
    }

    #[test]
    fn test_parent_and_parent_zone() {
        assert_eq!(parent_zone("www.example.com."), "example.com.");
        assert_eq!(parent_zone("example.com."), "com.");
        assert_eq!(parent_zone("com."), ".");
        assert_eq!(parent_zone("."), "");

        assert_eq!(parent("www.example.com."), Some("example.com."));
        assert_eq!(parent("example.com"), Some("com"));
        assert_eq!(parent("com."), Some("."));
        assert_eq!(parent("."), None);
        assert_eq!(parent(""), None);
    }

    #[test]
    fn test_is_subdomain_of() {
        assert!(is_subdomain_of("sub.example.com.", "example.com."));
        assert!(is_subdomain_of("example.com.", "example.com."));
        assert!(is_subdomain_of("example.com.", "."));
        assert!(!is_subdomain_of("notexample.com.", "example.com."));
        assert!(!is_subdomain_of("com.", "example.com."));
    }

    #[test]
    fn test_is_root() {
        assert!(is_root("."));
        assert!(is_root(""));
        assert!(!is_root("com."));
    }
}
