// Represents a domain name
use crate::errors::ParseError;
use crate::parse_error;
use punycode;
use std::fmt;
use std::ops::AddAssign;
use std::str::FromStr;

#[derive(Debug)]
pub struct Name {
    // Internal representation of the domain, stored as (puny encoded) ascii.
    // A vector of labels. Each label is <64 bytes long, and the sum of labels is < 253 bytes.
    labels: Vec<String>,
}

impl Name {
    const MAX_LEN: usize = 253; //

    // Restricts the length of a domain label to 63 characters. [RFC1034]
    const MAX_LABEL_LEN: usize = 63;

    const PUNY_PREFIX: &'static str = "xn--"; // TODO Rename ACE Prefix (ASCII Compatible Encoding)

    pub fn empty() -> Name {
        Name { labels: Vec::new() }
    }

    fn valid_label(mut label: String) -> Result<String, ParseError> {
        // Dig's example errors
        // 'aaa....a' is not a legal name (label too long)
        // 'aaa....a' is not a legal name (ran out of space)
        // 'a....a' is not a legal name (empty label)

        // TODO Check label is ascii, or puny encode it.
        if label.is_empty() {
            return parse_error!("empty labels are not valid");
        }

        // Puny encode as needed.
        if !label.is_ascii() {
            let puny = match punycode::encode(&label) {
                Ok(s) => s,
                Err(_) => {
                    return parse_error!(
                        "label '{}' is not ascii and failed to be puny encoded",
                        label
                    )
                }
            };
            label = Name::PUNY_PREFIX.to_owned() + &puny;
        }

        if label.len() > Name::MAX_LABEL_LEN {
            return parse_error!(
                "label '{}' is not valid longer longer than {}",
                label,
                Name::MAX_LABEL_LEN
            );
        }
        Ok(label)
    }

    // Read a ASCII encoded slice.
    pub fn from_label_slice(buf: &[u8]) -> Result<Name, ParseError> {
        // TODO Only allow ascii!! This presua
        let s = match std::str::from_utf8(buf) {
            Ok(s) => s,
            Err(e) => return parse_error!("{}", e),
        };
        Name::from_str(s)
    }
}

impl FromStr for Name {
    type Err = ParseError;

    // Parses a fully qualified domain name.
    // Supports traditional ASCII or Unicode domains.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let labels: Result<Vec<_>, _> = s
            .split_terminator('.')
            .map(|s| Name::valid_label(s.to_string()))
            .collect();

        let labels = match labels {
            Err(e) => return Err(e),
            Ok(labels) => labels,
        };

        if labels.iter().map(|s| s.len()).sum::<usize>() > Name::MAX_LEN {
            return parse_error!("domain name is too long");
        }

        Ok(Name { labels })
    }
}

#[test]
fn test_from_str() {
    assert_eq!(
        punycode::encode("académie-française").unwrap(),
        "acadmie-franaise-npb1a"
    );
    //assert_eq!(punycode::encode("☺️").unwrap(), "74h");
    //assert_eq!(punycode::encode("☺️.com").unwrap(), "74h");

    assert_eq!(Name::from_str("").unwrap().to_string(), ".");
    //assert_eq!(Name::from_str(".").unwrap().to_string(), "."); // TODO Fix
    assert_eq!(Name::from_str("com").unwrap().to_string(), "com.");
    assert_eq!(Name::from_str("com.").unwrap().to_string(), "com.");
    assert_eq!(Name::from_str("a.b.com").unwrap().to_string(), "a.b.com.");
    assert_eq!(Name::from_str("a.b.com.").unwrap().to_string(), "a.b.com.");

    //assert_eq!(Name::from_str("xn--74h.com").unwrap().to_string(), "xn--74h.com.");
    //assert_eq!(Name::from_str("☺️.com").unwrap().to_string(), "xn--74h.com.");
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.labels.is_empty() {
            return write!(f, ".");
        }

        for label in &self.labels {
            // TODO unpuny code it.
            write!(f, "{}.", label)?
        }

        Ok(())
    }
}

impl AddAssign for Name {
    fn add_assign(&mut self, other: Self) {
        // TODO Check it is still valid
        self.labels.extend_from_slice(&other.labels)
    }
}
