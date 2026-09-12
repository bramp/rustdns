//! Implements the FromStr trait for the various types, to be able to parse in `dig` style.
// Refer to https://github.com/tigeli/bind-utils/blob/master/bin/dig/dig.c for reference.

use crate::DNSKEY;
use crate::DS;
use crate::MX;
use crate::NSEC;
use crate::RRSIG;
use crate::Resource;
use crate::SOA;
use crate::SRV;
use crate::TXT;
use crate::Type;
use crate::ZONEMD;
use core::num::ParseIntError;
use core::str::FromStr;
use regex::Regex;
use std::net::AddrParseError;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum FromStrError {
    #[error("that resource type doesn't have a text representation")]
    UnsupportedType,

    #[error("string doesn't match expected format")]
    InvalidFormat,

    #[error("invalid rname '{rname}': {reason}")]
    InvalidRname { rname: String, reason: &'static str },

    #[error(transparent)]
    Int(#[from] ParseIntError),

    #[error(transparent)]
    Addr(#[from] AddrParseError),
}

impl Resource {
    /// Parses resource text using the supplied record type.
    ///
    /// # Errors
    ///
    /// Returns an error when the text is not valid for the requested record type,
    /// contains an invalid number or address, or the type has no text representation.
    pub fn parse_text(r#type: Type, s: &str) -> Result<Self, FromStrError> {
        Ok(match r#type {
            // IP Addresses
            Type::A => Resource::A(s.parse()?),
            Type::AAAA => Resource::AAAA(s.parse()?),

            // Simple strings (domains)
            Type::NS => Resource::NS(s.to_string()),
            Type::CNAME => Resource::CNAME(s.to_string()),
            Type::PTR => Resource::PTR(s.to_string()),

            // Complex types
            Type::MX => Resource::MX(s.parse()?),
            Type::SRV => Resource::SRV(s.parse()?),
            Type::SOA => Resource::SOA(s.parse()?),
            Type::SPF => Resource::SPF(s.parse()?),
            Type::TXT => Resource::TXT(s.parse()?),
            Type::DS => Resource::DS(s.parse()?),
            Type::DNSKEY => Resource::DNSKEY(s.parse()?),
            Type::RRSIG => Resource::RRSIG(s.parse()?),
            Type::NSEC => Resource::NSEC(s.parse()?),
            Type::ZONEMD => Resource::ZONEMD(s.parse()?),

            // TODO Implement NSEC3 and NSEC3PARAM parsing
            Type::NSEC3 | Type::NSEC3PARAM | Type::Unknown(_) => {
                return Err(FromStrError::UnsupportedType);
            }

            // This should never appear in a answer record unless we have invalid data.
            Type::Reserved | Type::OPT | Type::ANY => return Err(FromStrError::UnsupportedType),
        })
    }
}

impl FromStr for SOA {
    type Err = FromStrError;

    /// Parses an SOA resource from its text representation.
    ///
    /// # Errors
    ///
    /// Returns an error when the text does not contain the seven required SOA fields
    /// or a numeric field is invalid.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            // "ns1.google.com. dns-admin.google.com. 376337657 900 900 1800 60"
            // "{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}",
            static ref RE: Regex = Regex::new(r"^(\S+) (\S+) (\d+) (\d+) (\d+) (\d+) (\d+)$").unwrap();
        }

        if let Some(caps) = RE.captures(s) {
            Ok(SOA {
                mname: caps[1].to_string(),
                rname: caps[2].to_string(),
                serial: caps[3].parse()?,
                refresh: Duration::from_secs(caps[4].parse()?),
                retry: Duration::from_secs(caps[5].parse()?),
                expire: Duration::from_secs(caps[6].parse()?),
                minimum: Duration::from_secs(caps[7].parse()?),
            })
        } else {
            Err(FromStrError::InvalidFormat)
        }
    }
}

impl FromStr for MX {
    type Err = FromStrError;

    /// Parses an MX resource from its text representation.
    ///
    /// # Errors
    ///
    /// Returns an error when the preference is not a valid integer or the format is invalid.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            // "10 aspmx.l.google.com."
            // "{preference} {exchange}",
            static ref RE: Regex = Regex::new(r"^(\d+) (.+)$").unwrap();
        }
        if let Some(caps) = RE.captures(s) {
            Ok(MX {
                preference: caps[1].parse()?,
                exchange: caps[2].to_string(),
            })
        } else {
            Err(FromStrError::InvalidFormat)
        }
    }
}

impl FromStr for SRV {
    type Err = FromStrError;

    /// Parses an SRV resource from its text representation.
    ///
    /// # Errors
    ///
    /// Returns an error when a priority, weight, or port is not a valid integer or the format is invalid.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            // "5 0 389 ldap.google.com."
            // "{priority} {weight} {port} {name}",
            static ref RE: Regex = Regex::new(r"^(\d+) (\d+) (\d+) (.+)$").unwrap();
        }
        if let Some(caps) = RE.captures(s) {
            Ok(SRV {
                priority: caps[1].parse()?,
                weight: caps[2].parse()?,
                port: caps[3].parse()?,
                name: caps[4].to_string(),
            })
        } else {
            Err(FromStrError::InvalidFormat)
        }
    }
}

impl FromStr for DS {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(FromStrError::InvalidFormat);
        }
        let key_tag = parts[0].parse()?;
        let algorithm = parts[1].parse().map_err(|_| FromStrError::InvalidFormat)?;
        let digest_type = parts[2].parse().map_err(|_| FromStrError::InvalidFormat)?;
        let digest_hex = parts[3..].join("");
        let digest =
            crate::util::hex_decode(&digest_hex).map_err(|_| FromStrError::InvalidFormat)?;
        Ok(DS {
            key_tag,
            algorithm,
            digest_type,
            digest,
        })
    }
}

impl FromStr for DNSKEY {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(FromStrError::InvalidFormat);
        }
        let flags = parts[0].parse()?;
        let protocol = parts[1].parse()?;
        let algorithm = parts[2].parse()?;
        let key_b64 = parts[3..].join("");
        let public_key =
            crate::util::base64_decode(&key_b64).map_err(|_| FromStrError::InvalidFormat)?;
        Ok(DNSKEY {
            flags,
            protocol,
            algorithm,
            public_key,
        })
    }
}

fn parse_rrsig_time(s: &str) -> Result<SystemTime, FromStrError> {
    if s.len() == 14 && s.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y%m%d%H%M%S") {
            return Ok(dt.and_utc().into());
        }
    }
    let secs = s.parse::<u64>().map_err(FromStrError::from)?;
    Ok(UNIX_EPOCH + Duration::from_secs(secs))
}

impl FromStr for RRSIG {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() < 9 {
            return Err(FromStrError::InvalidFormat);
        }
        let type_covered = Type::from_str(parts[0]).map_err(|_| FromStrError::InvalidFormat)?;
        let algorithm = parts[1].parse()?;
        let labels = parts[2].parse()?;
        let original_ttl = Duration::from_secs(parts[3].parse()?);
        let expiration = parse_rrsig_time(parts[4])?;
        let inception = parse_rrsig_time(parts[5])?;
        let key_tag = parts[6].parse()?;
        let signer_name = parts[7].to_string();
        let sig_b64 = parts[8..].join("");
        let signature =
            crate::util::base64_decode(&sig_b64).map_err(|_| FromStrError::InvalidFormat)?;
        Ok(RRSIG {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name,
            signature,
        })
    }
}

impl FromStr for NSEC {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split_whitespace();
        let next_domain = parts.next().ok_or(FromStrError::InvalidFormat)?.to_string();
        let mut types = Vec::new();
        for type_str in parts {
            if let Ok(t) = Type::from_str(type_str) {
                types.push(t);
            }
        }
        Ok(NSEC { next_domain, types })
    }
}

impl FromStr for ZONEMD {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(FromStrError::InvalidFormat);
        }
        let serial = parts[0].parse()?;
        let scheme = parts[1].parse()?;
        let algorithm = parts[2].parse()?;
        let digest_hex = parts[3..].join("");
        let digest =
            crate::util::hex_decode(&digest_hex).map_err(|_| FromStrError::InvalidFormat)?;
        Ok(ZONEMD {
            serial,
            scheme,
            algorithm,
            digest,
        })
    }
}

impl FromStr for TXT {
    type Err = FromStrError;

    /// Parses a TXT resource from its text representation.
    ///
    /// # Errors
    ///
    /// Returns an error when quoted text is malformed or no quoted segments are found.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            // TODO Handle escaped quotes
            static ref RE: Regex = Regex::new(r#""(.*?)""#).unwrap();
        }

        if !s.starts_with('"') && !s.ends_with('"') {
            // Assume a single unquoted string
            return Ok(TXT::from(s));
        }

        // Otherparse parse multiple "..." strings
        let mut txts = Vec::new();
        for caps in RE.captures_iter(s) {
            txts.push(caps[1].as_bytes().to_vec());
        }

        if txts.is_empty() {
            return Err(FromStrError::InvalidFormat);
        }

        // TODO Also check we parsed the full record

        Ok(TXT(txts))
    }
}
