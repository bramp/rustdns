// Represents a domain name
use crate::errors::ParseError;
use crate::parse_error;
use std::fmt;
use std::ops::AddAssign;
use std::str::FromStr;

pub struct Name {
    // Internal representation of the domain.
    // A vector of labels. Each label is <64 bytes long, and the sum of labels is < 253 bytes.
    labels: Vec<String>,
}

impl Name {
    const MAX_LEN: usize = 253; //
    const MAX_LABEL_LEN: usize = 63;

    pub fn empty() -> Name {
        Name { labels: Vec::new() }
    }

    fn valid_label(label: String) -> Result<String, ParseError> {
        // Dig's example errors
        // 'aaa....a' is not a legal name (label too long)
        // 'aaa....a' is not a legal name (ran out of space)
        // 'a....a' is not a legal name (empty label)

        // TODO Check label is ascii, or puny encode it.
        if label.is_empty() {
            return parse_error!("empty label are not valid");
        }
        if label.len() > Name::MAX_LABEL_LEN {
            return parse_error!("labels longer than {} are not valid.", Name::MAX_LABEL_LEN);
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

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.labels.is_empty() {
            return write!(f, ".");
        }

        for label in &self.labels {
            write!(f, "{}.", label)?
        }

        Ok(())
    }
}

impl AddAssign for Name {
    fn add_assign(&mut self, other: Self) {
        self.labels.extend_from_slice(&other.labels)
    }
}
