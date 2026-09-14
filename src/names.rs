//! Domain name modeling, canonical normalization, and RFC 4034 ordering.
//!
//! Provides [`Name`], a strongly-typed representation of a fully-qualified domain name (FQDN)
//! stored in canonical lowercase ASCII Punycode format with:
//! - IDNA Punycode conversion and validation
//! - RFC 1035 wire limits enforcement (labels $\le 63$ octets, names $\le 255$ octets)
//! - Hierarchy inspection ([`Name::parent`], [`Name::count_labels`], [`Name::is_subdomain_of`])
//! - Canonical DNS name ordering ([RFC 4034 §6.1]) via [`Ord`] and [`PartialOrd`]
//!
//! [RFC 4034 §6.1]: https://datatracker.ietf.org/doc/html/rfc4034#section-6.1

use crate::errors::EncodeError;
use crate::limits;
use rand::{Rng, RngExt};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

/// Trait for types that can be converted into a canonical domain [`Name`].
///
/// Implemented for [`Name`], `&Name`, `&str`, `String`, and `&String`.
pub trait IntoName {
    /// Converts `self` into a [`Name`], performing normalization and validation if needed.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if the domain name fails IDNA conversion or exceeds RFC 1035 limits.
    fn into_name(self) -> Result<Name, EncodeError>;
}

impl IntoName for Name {
    #[inline]
    fn into_name(self) -> Result<Name, EncodeError> {
        Ok(self)
    }
}

impl IntoName for &Name {
    #[inline]
    fn into_name(self) -> Result<Name, EncodeError> {
        Ok(self.clone())
    }
}

impl IntoName for &str {
    #[inline]
    fn into_name(self) -> Result<Name, EncodeError> {
        Name::new(self)
    }
}

impl IntoName for String {
    #[inline]
    fn into_name(self) -> Result<Name, EncodeError> {
        Name::new(&self)
    }
}

impl IntoName for &String {
    #[inline]
    fn into_name(self) -> Result<Name, EncodeError> {
        Name::new(self)
    }
}

/// A strongly-typed DNS domain name preserving original casing.
///
/// Encapsulates a fully-qualified domain name (FQDN) in ASCII Punycode wire format,
/// upholding the following invariants and constraints:
/// 1. **Case Preservation**: Preserves the original validated ASCII casing in memory
///    and wire format ([RFC 4343], [RFC 5452 §9]). This enables 0x20-bit case randomization
///    anti-spoofing and preserves author intent in zone files.
/// 2. **Case-Insensitive Equality & Hashing**: Implements [`PartialEq`], [`Eq`], and [`Hash`]
///    case-insensitively per DNS semantics. Two names differing only in ASCII casing
///    compare equal and yield identical hash values for map and set keys.
/// 3. **Canonical Ordering**: Implements [`Ord`] and [`PartialOrd`] per [RFC 4034 §6.1]
///    canonical DNS name order (labels compared right-to-left as lowercase US-ASCII).
/// 4. **ASCII Only Wire Format**: Internationalized Domain Names (IDNs) with non-ASCII
///    labels are converted to ASCII Punycode (`xn--...`) via UTS #46. Pure ASCII labels
///    retain their original casing.
/// 5. **Bounded**: Every label is $\le 63$ octets; total wire format length is $\le 255$ octets
///    per [RFC 1035].
/// 6. **FQDN**: Always terminates with a trailing dot (`.`). The DNS root domain is `"."`.
/// 7. **Explicit Canonical Form**: Provides [`Name::to_canonical`] for DNSSEC wire serialization
///    ([RFC 4034 §6.2]), RRSIG signing, and NSEC3 hashing ([RFC 5155 §5]).
/// 8. **Case-Sensitive Comparison**: Provides [`Name::case_sensitive_eq`] for verifying
///    0x20 query echoes in DNS responses.
///
/// # Examples
/// ```rust
/// use rustdns::names::Name;
///
/// let name = Name::new("EXAMPLE.COM").unwrap();
/// assert_eq!(name.as_ascii(), "EXAMPLE.COM.");
/// assert_eq!(name.to_canonical().as_ascii(), "example.com.");
/// assert_eq!(name.to_unicode(), "EXAMPLE.COM.");
/// assert_eq!(name.count_labels(), 2);
///
/// // Case-insensitive DNS equality
/// assert_eq!(name, Name::new("example.com").unwrap());
///
/// let idn = Name::new("🍕.ws").unwrap();
/// assert_eq!(idn.as_ascii(), "xn--vi8h.ws.");
/// assert_eq!(idn.to_unicode(), "🍕.ws.");
/// ```
///
/// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
/// [RFC 4034 §6.1]: https://datatracker.ietf.org/doc/html/rfc4034#section-6.1
/// [RFC 4034 §6.2]: https://datatracker.ietf.org/doc/html/rfc4034#section-6.2
/// [RFC 4343]: https://datatracker.ietf.org/doc/html/rfc4343
/// [RFC 5155 §5]: https://datatracker.ietf.org/doc/html/rfc5155#section-5
/// [RFC 5452 §9]: https://datatracker.ietf.org/doc/html/rfc5452#section-9
#[derive(Clone)]
pub struct Name {
    /// Wire-format Punycode FQDN ending with a trailing dot (`.`).
    /// Preserves original ASCII casing.
    ascii: String,
}

impl Name {
    /// Creates the DNS root domain (`"."`).
    ///
    /// # Examples
    /// ```rust
    /// use rustdns::names::Name;
    ///
    /// let root = Name::root();
    /// assert_eq!(root.as_ascii(), ".");
    /// assert!(root.is_root());
    /// assert_eq!(root.count_labels(), 0);
    /// ```
    #[must_use]
    pub fn root() -> Self {
        Self {
            ascii: ".".to_string(),
        }
    }

    /// Creates and validates a new domain [`Name`].
    ///
    /// Preserves ASCII casing for anti-spoofing ([RFC 5452 §9]) and zone readability,
    /// while converting any non-ASCII labels to Punycode (IDNA) format. The name is
    /// validated against RFC 1035 wire limits ($\le 63$ octet labels, $\le 255$ octets total)
    /// and ensured to have a trailing dot (`.`).
    ///
    /// Empty string (`""`) or `"."` normalizes to the DNS root domain `"."`.
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
    /// use rustdns::names::Name;
    ///
    /// let name = Name::new("wWw.ExAmPlE.cOm").unwrap();
    /// assert_eq!(name.as_ascii(), "wWw.ExAmPlE.cOm.");
    ///
    /// let idn = Name::new("🍕.ws").unwrap();
    /// assert_eq!(idn.as_ascii(), "xn--vi8h.ws.");
    /// assert_eq!(idn.to_unicode(), "🍕.ws.");
    ///
    /// let root = Name::new(".").unwrap();
    /// assert!(root.is_root());
    /// ```
    pub fn new(domain: &str) -> Result<Self, EncodeError> {
        if domain.is_empty() || domain == "." {
            return Ok(Self::root());
        }

        let mut ascii = String::with_capacity(domain.len() + 1);
        let mut wire_len = 1_usize; // 1 byte for the terminating zero (root label)

        // We split on '.' and process each label individually for two critical reasons:
        // 1. Case preservation (RFC 4343 / RFC 5452 §9): `idna::domain_to_ascii` unconditionally
        //    folds all ASCII uppercase letters to lowercase (`[A-Z]` -> `[a-z]`) per UTS #46.
        //    Passing an entire domain into `domain_to_ascii` would destroy 0x20-bit case randomization
        //    and zone file author casing. By inspecting each label, pure ASCII labels bypass
        //    UTS #46 and retain their exact casing, while non-ASCII IDN labels are converted to Punycode.
        // 2. Single-pass validation: Validates label emptiness, per-label wire length (<= 63 octets,
        //    essential because IDN labels expand significantly after Punycode conversion), and total
        //    wire format length (<= 255 octets) in one pass without a second traversal.
        for label in domain.split_terminator('.') {
            if label.is_empty() {
                return Err(EncodeError::EmptyLabel {
                    name: domain.to_string(),
                });
            }

            let puny;
            let label_ascii = if label.is_ascii() {
                label
            } else {
                puny = idna::domain_to_ascii(label).map_err(|_| EncodeError::InvalidName {
                    name: domain.to_string(),
                })?;
                &puny
            };

            if label_ascii.len() > limits::MAX_DNS_LABEL_WIRE_LEN {
                return Err(EncodeError::LabelTooLong {
                    label: label_ascii.to_string(),
                    max: limits::MAX_DNS_LABEL_WIRE_LEN,
                });
            }

            let label_wire_len = label_ascii.len() + 1;
            if wire_len > limits::MAX_DNS_NAME_WIRE_LEN - label_wire_len {
                return Err(EncodeError::NameTooLong {
                    max: limits::MAX_DNS_NAME_WIRE_LEN,
                });
            }
            wire_len += label_wire_len;

            ascii.push_str(label_ascii);
            ascii.push('.');
        }

        Ok(Self { ascii })
    }

    /// Creates a [`Name`] from an ASCII string that is already in Punycode format.
    ///
    /// Validates that the input consists solely of ASCII characters, satisfies
    /// RFC 1035 wire limits, preserves original casing, and ensures a trailing dot.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::InvalidName`] if `ascii` contains non-ASCII characters,
    /// or other [`EncodeError`] variants if label or name limits are exceeded.
    ///
    /// # Examples
    /// ```rust
    /// use rustdns::names::Name;
    ///
    /// let name = Name::from_ascii("xn--vi8h.ws").unwrap();
    /// assert_eq!(name.to_unicode(), "🍕.ws.");
    /// ```
    pub fn from_ascii(ascii: &str) -> Result<Self, EncodeError> {
        if !ascii.is_ascii() {
            return Err(EncodeError::InvalidName {
                name: ascii.to_string(),
            });
        }
        Self::new(ascii)
    }

    /// Returns the canonical lowercase ASCII (Punycode) representation with a trailing dot.
    ///
    /// # Examples
    /// ```rust
    /// use rustdns::names::Name;
    ///
    /// let name = Name::new("🍕.ws").unwrap();
    /// assert_eq!(name.as_ascii(), "xn--vi8h.ws.");
    /// ```
    #[inline]
    #[must_use]
    pub fn as_ascii(&self) -> &str {
        &self.ascii
    }

    /// Returns the canonical ASCII domain name as a string slice.
    ///
    /// Equivalent to [`as_ascii`](Self::as_ascii).
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.ascii
    }

    /// Returns the byte slice of the canonical ASCII representation.
    ///
    /// # Examples
    /// ```rust
    /// use rustdns::names::Name;
    ///
    /// let name = Name::new("example.com").unwrap();
    /// assert_eq!(name.as_bytes(), b"example.com.");
    /// ```
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.ascii.as_bytes()
    }

    /// Appends this domain name to `buf` in uncompressed DNS wire format.
    ///
    /// The name is serialized as a sequence of length-prefixed octet labels,
    /// terminated by a zero byte (root label).
    ///
    /// # Examples
    /// ```rust
    /// use rustdns::names::Name;
    ///
    /// let name = Name::new("example.com").unwrap();
    /// let mut buf = Vec::new();
    /// name.append_to_vec(&mut buf);
    /// assert_eq!(buf, b"\x07example\x03com\x00");
    /// ```
    pub fn append_to_vec(&self, buf: &mut Vec<u8>) {
        if !self.is_root() {
            for label in self.ascii.split_terminator('.') {
                buf.push(label.len() as u8);
                buf.extend_from_slice(label.as_bytes());
            }
        }
        buf.push(0);
    }

    /// Converts the domain name into its Unicode representation with a trailing dot.
    ///
    /// Preserves original ASCII casing. For IDNs, Punycode labels (e.g. `xn--...`)
    /// are decoded back to Unicode. Non-IDN labels remain unchanged.
    ///
    /// # Examples
    /// ```rust
    /// use rustdns::names::Name;
    ///
    /// let name = Name::new("xn--vi8h.ws").unwrap();
    /// assert_eq!(name.to_unicode(), "🍕.ws.");
    ///
    /// let mixed = Name::new("wWw.ExAmPlE.cOm").unwrap();
    /// assert_eq!(mixed.to_unicode(), "wWw.ExAmPlE.cOm.");
    /// ```
    #[must_use]
    pub fn to_unicode(&self) -> String {
        if !self.ascii.contains("xn--") && !self.ascii.contains("XN--") {
            return self.ascii.clone();
        }
        let mut unicode = String::with_capacity(self.ascii.len());
        for label in self.ascii.split_terminator('.') {
            if label.to_ascii_lowercase().starts_with("xn--") {
                let (decoded, _) = idna::domain_to_unicode(label);
                unicode.push_str(&decoded);
            } else {
                unicode.push_str(label);
            }
            unicode.push('.');
        }
        unicode
    }

    /// Returns `true` if this domain is the DNS root (`"."`).
    ///
    /// # Examples
    /// ```rust
    /// use rustdns::names::Name;
    ///
    /// assert!(Name::root().is_root());
    /// assert!(Name::new(".").unwrap().is_root());
    /// assert!(!Name::new("example.com").unwrap().is_root());
    /// ```
    #[inline]
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.ascii == "."
    }

    /// Computes the number of labels in this domain name, excluding the root label.
    ///
    /// # Examples
    /// ```rust
    /// use rustdns::names::Name;
    ///
    /// assert_eq!(Name::root().count_labels(), 0);
    /// assert_eq!(Name::new("com").unwrap().count_labels(), 1);
    /// assert_eq!(Name::new("example.com").unwrap().count_labels(), 2);
    /// assert_eq!(Name::new("a.b.c.example.com").unwrap().count_labels(), 5);
    /// ```
    #[must_use]
    pub fn count_labels(&self) -> u8 {
        let trimmed = self.ascii.trim_end_matches('.');
        if trimmed.is_empty() {
            0
        } else {
            trimmed.split('.').count().min(255) as u8
        }
    }

    /// Returns the parent domain of this domain name, or `None` if this is the root domain.
    ///
    /// The parent of a top-level domain (e.g. `com.`) is the root domain (`"."`).
    ///
    /// # Examples
    /// ```rust
    /// use rustdns::names::Name;
    ///
    /// let name = Name::new("www.example.com").unwrap();
    /// assert_eq!(name.parent().unwrap().as_ascii(), "example.com.");
    ///
    /// let tld = Name::new("com").unwrap();
    /// assert_eq!(tld.parent().unwrap().as_ascii(), ".");
    ///
    /// assert_eq!(Name::root().parent(), None);
    /// ```
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            return None;
        }
        let trimmed = self.ascii.trim_end_matches('.');
        match trimmed.split_once('.') {
            Some((_, rest)) => Some(Self {
                ascii: format!("{rest}."),
            }),
            None => Some(Self::root()),
        }
    }

    /// Returns a new [`Name`] in lowercase canonical form.
    ///
    /// Converts all ASCII characters to lowercase while preserving FQDN invariants.
    /// Used for DNSSEC canonical wire serialization ([RFC 4034 §6.2]), RRSIG
    /// signing/verification, and NSEC3 hashing ([RFC 5155 §5]).
    ///
    /// # Examples
    /// ```rust
    /// use rustdns::names::Name;
    ///
    /// let name = Name::new("wWw.ExAmPlE.cOm").unwrap();
    /// assert_eq!(name.as_ascii(), "wWw.ExAmPlE.cOm.");
    /// assert_eq!(name.to_canonical().as_ascii(), "www.example.com.");
    /// ```
    #[must_use]
    pub fn to_canonical(&self) -> Self {
        Self {
            ascii: self.ascii.to_ascii_lowercase(),
        }
    }

    /// Returns `true` if this domain name is in lowercase canonical form.
    ///
    /// # Examples
    /// ```rust
    /// use rustdns::names::Name;
    ///
    /// let canonical = Name::new("example.com").unwrap();
    /// assert!(canonical.is_canonical());
    ///
    /// let mixed = Name::new("Example.COM").unwrap();
    /// assert!(!mixed.is_canonical());
    /// ```
    #[must_use]
    pub fn is_canonical(&self) -> bool {
        self.ascii.bytes().all(|b| !b.is_ascii_uppercase())
    }

    /// Performs an exact, case-sensitive comparison of two domain names.
    ///
    /// Unlike [`PartialEq`] (which compares case-insensitively per DNS specifications),
    /// this method compares the raw underlying ASCII representation byte-for-byte.
    /// Useful for verifying 0x20-bit case randomization echoes in DNS responses
    /// ([RFC 5452 §9]).
    ///
    /// # Examples
    /// ```rust
    /// use rustdns::names::Name;
    ///
    /// let a = Name::new("wWw.ExAmPlE.cOm").unwrap();
    /// let b = Name::new("WWW.EXAMPLE.COM").unwrap();
    /// let c = Name::new("wWw.ExAmPlE.cOm").unwrap();
    ///
    /// // DNS equality is case-insensitive
    /// assert_eq!(a, b);
    ///
    /// // Raw equality is case-sensitive
    /// assert!(!a.case_sensitive_eq(&b));
    /// assert!(a.case_sensitive_eq(&c));
    /// ```
    #[inline]
    #[must_use]
    pub fn case_sensitive_eq(&self, other: &Self) -> bool {
        self.ascii == other.ascii
    }

    /// Returns a 0x20-bit randomized variant of this domain name using the default CSPRNG.
    ///
    /// Randomizes the casing of ASCII alphabetic characters per
    /// [draft-vixie-dnsext-dns0x20-00] and [RFC 5452 §9] to enhance transaction identity
    /// against DNS spoofing and cache-poisoning attacks.
    ///
    /// Digits, hyphens, dots, and non-alphabetic characters are left unchanged.
    /// The resulting [`Name`] compares equal (`==`) to `self` under DNS case-insensitivity.
    ///
    /// To use a custom or deterministic random number generator (e.g. for testing),
    /// use [`to_0x20_with_rng`](Self::to_0x20_with_rng).
    ///
    /// # Examples
    /// ```rust
    /// use rustdns::names::Name;
    ///
    /// let name = Name::new("www.example.com").unwrap();
    /// let randomized = name.to_0x20();
    ///
    /// // DNS equality is preserved
    /// assert_eq!(randomized, name);
    /// assert_eq!(randomized.count_labels(), 3);
    /// assert_eq!(randomized.to_canonical(), name.to_canonical());
    /// ```
    ///
    /// [draft-vixie-dnsext-dns0x20-00]: https://datatracker.ietf.org/doc/html/draft-vixie-dnsext-dns0x20-00
    /// [RFC 5452 §9]: https://datatracker.ietf.org/doc/html/rfc5452#section-9
    #[must_use]
    pub fn to_0x20(&self) -> Self {
        self.to_0x20_with_rng(rand::rng())
    }

    /// Returns a 0x20-bit randomized variant of this domain name using the supplied RNG.
    ///
    /// For every ASCII alphabetic character (`[a-zA-Z]`), bit 0x20 (value 32) is
    /// randomly toggled with probability 0.5 using `rng`.
    ///
    /// Non-alphabetic characters (digits, hyphens, and the trailing dot) are preserved.
    ///
    /// # Examples
    /// ```rust
    /// use rand::SeedableRng;
    /// use rand::rngs::StdRng;
    /// use rustdns::names::Name;
    ///
    /// let mut rng = StdRng::seed_from_u64(12345);
    /// let name = Name::new("www.example.com").unwrap();
    /// let randomized = name.to_0x20_with_rng(&mut rng);
    ///
    /// assert_eq!(randomized, name);
    /// assert_eq!(randomized.to_canonical(), name.to_canonical());
    /// ```
    #[must_use]
    pub fn to_0x20_with_rng(&self, mut rng: impl Rng) -> Self {
        let mut ascii = String::with_capacity(self.ascii.len());
        for b in self.ascii.bytes() {
            if b.is_ascii_alphabetic() {
                if rng.random() {
                    ascii.push(b.to_ascii_uppercase() as char);
                } else {
                    ascii.push(b.to_ascii_lowercase() as char);
                }
            } else {
                ascii.push(b as char);
            }
        }
        Self { ascii }
    }

    /// Checks whether this domain name is a subdomain of (or equal to) `parent`.
    ///
    /// Comparison is case-insensitive per DNS specifications.
    ///
    /// # Examples
    /// ```rust
    /// use rustdns::names::Name;
    ///
    /// let parent = Name::new("example.com").unwrap();
    /// let sub = Name::new("SUB.example.com").unwrap();
    /// assert!(sub.is_subdomain_of(&parent));
    /// assert!(parent.is_subdomain_of(&parent));
    /// assert!(parent.is_subdomain_of(&Name::root()));
    /// assert!(!Name::new("notexample.com").unwrap().is_subdomain_of(&parent));
    /// ```
    #[must_use]
    pub fn is_subdomain_of(&self, parent: &Self) -> bool {
        if parent.is_root() {
            return true;
        }
        if self == parent {
            return true;
        }
        let mut self_rev = self.ascii.trim_end_matches('.').split('.').rev();
        let parent_rev = parent.ascii.trim_end_matches('.').split('.').rev();

        for p_label in parent_rev {
            match self_rev.next() {
                Some(s_label) if s_label.eq_ignore_ascii_case(p_label) => {}
                _ => return false,
            }
        }
        true
    }
}

impl PartialEq for Name {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.ascii.eq_ignore_ascii_case(&other.ascii)
    }
}

impl Eq for Name {}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for b in self.ascii.bytes() {
            state.write_u8(b.to_ascii_lowercase());
        }
    }
}

impl Ord for Name {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.ascii.eq_ignore_ascii_case(&other.ascii) {
            return Ordering::Equal;
        }
        let a_trimmed = self.ascii.trim_end_matches('.');
        let b_trimmed = other.ascii.trim_end_matches('.');

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

impl PartialOrd for Name {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_unicode())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Name").field(&self.to_unicode()).finish()
    }
}

impl FromStr for Name {
    type Err = EncodeError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<&str> for Name {
    type Error = EncodeError;

    #[inline]
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<String> for Name {
    type Error = EncodeError;

    #[inline]
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(&s)
    }
}

impl AsRef<str> for Name {
    #[inline]
    fn as_ref(&self) -> &str {
        &self.ascii
    }
}

impl AsRef<[u8]> for Name {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.ascii.as_bytes()
    }
}

impl PartialEq<str> for Name {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        if other.ends_with('.') {
            self.ascii.eq_ignore_ascii_case(other)
        } else {
            let trimmed = self.ascii.trim_end_matches('.');
            trimmed.eq_ignore_ascii_case(other)
        }
    }
}

impl PartialEq<&str> for Name {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        self.eq(*other)
    }
}

impl PartialEq<String> for Name {
    #[inline]
    fn eq(&self, other: &String) -> bool {
        self.eq(other.as_str())
    }
}

impl PartialEq<Name> for str {
    #[inline]
    fn eq(&self, other: &Name) -> bool {
        other.eq(self)
    }
}

impl PartialEq<Name> for &str {
    #[inline]
    fn eq(&self, other: &Name) -> bool {
        other.eq(*self)
    }
}

impl PartialEq<Name> for String {
    #[inline]
    fn eq(&self, other: &Name) -> bool {
        other.eq(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Name {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_ascii())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Name {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Name::new(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Name {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let s = <&str>::arbitrary(u)?;
        Name::new(s).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_root() {
        let root = Name::root();
        assert_eq!(root.as_ascii(), ".");
        assert_eq!(root.to_unicode(), ".");
        assert!(root.is_root());
        assert_eq!(root.count_labels(), 0);
        assert_eq!(root.parent(), None);

        let from_dot = Name::new(".").unwrap();
        assert_eq!(from_dot, root);

        let from_empty = Name::new("").unwrap();
        assert_eq!(from_empty, root);
    }

    #[test]
    fn test_name_new_valid() {
        let n1 = Name::new("example.com").unwrap();
        assert_eq!(n1.as_ascii(), "example.com.");
        assert_eq!(n1.to_unicode(), "example.com.");
        assert_eq!(n1.count_labels(), 2);
        assert!(!n1.is_root());
        assert!(n1.is_canonical());

        let n2 = Name::new("EXAMPLE.com.").unwrap();
        assert_eq!(n2, n1);
        assert_eq!(n2.as_ascii(), "EXAMPLE.com.");
        assert_eq!(n2.to_canonical().as_ascii(), "example.com.");
        assert!(!n2.is_canonical());
        assert!(!n2.case_sensitive_eq(&n1));

        let idn = Name::new("🍕.ws").unwrap();
        assert_eq!(idn.as_ascii(), "xn--vi8h.ws.");
        assert_eq!(idn.to_unicode(), "🍕.ws.");
        assert_eq!(idn.count_labels(), 2);

        let puny = Name::from_ascii("xn--vi8h.ws.").unwrap();
        assert_eq!(puny, idn);

        // Mixed-case ASCII labels surrounding Unicode IDN label
        let mixed_idn = Name::new("aBc.🍕.wS").unwrap();
        assert_eq!(mixed_idn.as_ascii(), "aBc.xn--vi8h.wS.");
        assert_eq!(mixed_idn.to_unicode(), "aBc.🍕.wS.");
        assert_eq!(mixed_idn.to_canonical().as_ascii(), "abc.xn--vi8h.ws.");
        assert!(!mixed_idn.is_canonical());

        let mixed_idn_alt = Name::new("ABC.🍕.ws").unwrap();
        assert_eq!(mixed_idn, mixed_idn_alt);
        assert!(!mixed_idn.case_sensitive_eq(&mixed_idn_alt));

        // IDN labels with spaces and multiple emoji
        let space_idn = Name::new("🍕 🚗.com").unwrap();
        assert_eq!(space_idn.as_ascii(), "xn-- -hr2ss5e.com.");
        assert_eq!(space_idn.to_unicode(), "🍕 🚗.com.");

        // ASCII letters inside the same IDN label are normalized by UTS #46
        let n1 = Name::new("a🍕 🚗.com").unwrap();
        let n2 = Name::new("A🍕 🚗.com").unwrap();
        assert_eq!(n1.as_ascii(), "xn--a -3z62am9f.com.");
        assert_eq!(n2.as_ascii(), "xn--a -3z62am9f.com.");
        assert_eq!(n1, n2);
        assert!(n1.case_sensitive_eq(&n2));
    }

    #[test]
    fn test_name_errors() {
        // Label too long (> 63)
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(matches!(
            Name::new(&long_label),
            Err(EncodeError::LabelTooLong { .. })
        ));

        // Interior empty label
        assert!(matches!(
            Name::new("foo..bar"),
            Err(EncodeError::EmptyLabel { .. })
        ));

        // Non-ASCII in from_ascii
        assert!(matches!(
            Name::from_ascii("🍕.ws"),
            Err(EncodeError::InvalidName { .. })
        ));
    }

    #[test]
    fn test_name_hierarchy() {
        let name = Name::new("a.b.example.com").unwrap();
        assert_eq!(name.count_labels(), 4);

        let p1 = name.parent().unwrap();
        assert_eq!(p1.as_ascii(), "b.example.com.");
        assert_eq!(p1.count_labels(), 3);

        let p2 = p1.parent().unwrap();
        assert_eq!(p2.as_ascii(), "example.com.");

        let p3 = p2.parent().unwrap();
        assert_eq!(p3.as_ascii(), "com.");
        assert_eq!(p3.count_labels(), 1);

        let p4 = p3.parent().unwrap();
        assert_eq!(p4.as_ascii(), ".");
        assert!(p4.is_root());
        assert_eq!(p4.parent(), None);

        // Subdomain checks
        assert!(name.is_subdomain_of(&p1));
        assert!(name.is_subdomain_of(&p2));
        assert!(name.is_subdomain_of(&p3));
        assert!(name.is_subdomain_of(&p4));
        assert!(name.is_subdomain_of(&name));
        assert!(!p1.is_subdomain_of(&name));
        assert!(!Name::new("notexample.com").unwrap().is_subdomain_of(&p2));
    }

    #[test]
    fn test_name_canonical_ordering() {
        // List from https://www.rfc-editor.org/info/rfc4034/
        let sorted = [
            Name::root(),
            Name::new("example").unwrap(),
            Name::new("a.example").unwrap(),
            Name::new("yljkjljk.a.example").unwrap(),
            Name::new("Z.a.example").unwrap(),
            Name::new("zABC.a.EXAMPLE").unwrap(),
            Name::new("z.example").unwrap(),
            Name::new("\x01.z.example").unwrap(),
            Name::new("*.z.example").unwrap(),
        ];

        for i in 0..sorted.len() {
            for j in 0..sorted.len() {
                assert_eq!(
                    sorted[i].cmp(&sorted[j]),
                    i.cmp(&j),
                    "failed between {:?} and {:?}",
                    sorted[i],
                    sorted[j]
                );
            }
        }

        // Unicode and Punycode compare identically
        let unicode = Name::new("🍕.ws").unwrap();
        let puny = Name::new("xn--vi8h.ws").unwrap();
        assert_eq!(unicode.cmp(&puny), Ordering::Equal);
    }

    #[test]
    fn test_name_traits() {
        let name: Name = "example.com".parse().unwrap();
        assert_eq!(name.as_ascii(), "example.com.");
        assert_eq!(format!("{name}"), "example.com.");
        assert_eq!(format!("{name:?}"), "Name(\"example.com.\")");
        assert_eq!(name, "example.com.");
        assert_eq!(name.as_ref() as &str, "example.com.");
        assert_eq!(name.as_bytes(), b"example.com.");
    }

    #[test]
    fn test_name_casing_and_0x20() {
        let mixed = Name::new("wWw.ExAmPlE.cOm").unwrap();
        assert_eq!(mixed.as_ascii(), "wWw.ExAmPlE.cOm.");
        assert_eq!(mixed.to_unicode(), "wWw.ExAmPlE.cOm.");
        assert!(!mixed.is_canonical());

        let lower = Name::new("www.example.com").unwrap();
        let upper = Name::new("WWW.EXAMPLE.COM").unwrap();

        // DNS equality is case-insensitive
        assert_eq!(mixed, lower);
        assert_eq!(mixed, upper);
        assert_eq!(lower, upper);

        // Case-sensitive exact matching
        assert!(mixed.case_sensitive_eq(&mixed));
        assert!(!mixed.case_sensitive_eq(&lower));
        assert!(!mixed.case_sensitive_eq(&upper));
        assert!(lower.case_sensitive_eq(&lower));

        // Canonical normalization
        let canon = mixed.to_canonical();
        assert_eq!(canon.as_ascii(), "www.example.com.");
        assert!(canon.is_canonical());
        assert!(canon.case_sensitive_eq(&lower));

        // Preserves exact casing on wire
        let mut wire = Vec::new();
        mixed.append_to_vec(&mut wire);
        assert_eq!(wire, b"\x03wWw\x07ExAmPlE\x03cOm\x00");

        // Canonical wire serialization
        let mut canon_wire = Vec::new();
        mixed.to_canonical().append_to_vec(&mut canon_wire);
        assert_eq!(canon_wire, b"\x03www\x07example\x03com\x00");

        // IDN with mixed-case ASCII labels
        let idn_mixed = Name::new("wWw.🍕.cOm").unwrap();
        assert_eq!(idn_mixed.as_ascii(), "wWw.xn--vi8h.cOm.");
        assert_eq!(idn_mixed.to_canonical().as_ascii(), "www.xn--vi8h.com.");
    }

    #[test]
    fn test_name_hash_and_collections() {
        use std::collections::{HashMap, HashSet};

        let mut set = HashSet::new();
        set.insert(Name::new("wWw.ExAmPlE.cOm").unwrap());

        // Different casings must match in hash collections
        assert!(set.contains(&Name::new("www.example.com").unwrap()));
        assert!(set.contains(&Name::new("WWW.EXAMPLE.COM").unwrap()));
        assert!(set.contains(&Name::new("wWw.ExAmPlE.cOm").unwrap()));
        assert!(!set.contains(&Name::new("other.example.com").unwrap()));

        let mut map = HashMap::new();
        map.insert(Name::new("ExAmPlE.cOm").unwrap(), 42);
        assert_eq!(map.get(&Name::new("example.com").unwrap()), Some(&42));
        assert_eq!(map.get(&Name::new("EXAMPLE.COM").unwrap()), Some(&42));
    }

    #[test]
    fn test_name_parent_preserves_case() {
        let name = Name::new("Sub.ExAmPlE.cOm").unwrap();
        let parent = name.parent().unwrap();
        assert_eq!(parent.as_ascii(), "ExAmPlE.cOm.");
        assert_eq!(parent.parent().unwrap().as_ascii(), "cOm.");
    }

    #[test]
    fn test_name_is_subdomain_case_insensitive() {
        let sub = Name::new("wWw.ExAmPlE.cOm").unwrap();
        let parent = Name::new("EXAMPLE.COM").unwrap();
        assert!(sub.is_subdomain_of(&parent));
        assert!(parent.is_subdomain_of(&Name::root()));
        assert!(!parent.is_subdomain_of(&sub));
    }

    #[test]
    fn test_name_to_0x20() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        // Root domain has no letters to randomize
        let root = Name::root();
        assert_eq!(root.to_0x20().as_ascii(), ".");

        // Domain with letters, numbers, and hyphens
        let name = Name::new("host-1.sub-2.example.com").unwrap();

        // Test with default CSPRNG
        let rand_name = name.to_0x20();
        assert_eq!(rand_name, name);
        assert_eq!(rand_name.to_canonical(), name.to_canonical());
        assert_eq!(rand_name.count_labels(), name.count_labels());

        // Test with deterministic seeded RNG
        let mut rng = StdRng::seed_from_u64(0x20202020);
        let randomized = name.to_0x20_with_rng(&mut rng);

        // DNS equality still holds
        assert_eq!(randomized, name);
        assert_eq!(
            randomized.to_canonical().as_ascii(),
            "host-1.sub-2.example.com."
        );

        // Check non-alphabetic characters (digits, hyphens, dots) are never modified
        for (orig, rand) in name.as_ascii().chars().zip(randomized.as_ascii().chars()) {
            if !orig.is_ascii_alphabetic() {
                assert_eq!(orig, rand, "non-alphabetic char should never be modified");
            }
        }

        // Verify that 0x20 randomization altered at least some case
        assert_ne!(randomized.as_ascii(), name.as_ascii());
    }
}
