//! Implements the FromStr trait for the various types, to be able to parse in `dig` style.
// Refer to https://github.com/tigeli/bind-utils/blob/master/bin/dig/dig.c for reference.

use crate::TXT;
use crate::Resource;
use crate::Type;
use crate::MX;
use crate::SOA;
use crate::SRV;
use core::num::ParseIntError;
use core::str::FromStr;
use regex::Regex;
use std::net::AddrParseError;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FromStrError {
    #[error("that resource type doesn't have a text representation")]
    UnsupportedType,

    #[error("string doesn't match expected format")]
    InvalidFormat,

    #[error(transparent)]
    ParseIntError(#[from] ParseIntError),

    #[error(transparent)]
    AddrParseError(#[from] AddrParseError),
}

impl Resource {
    // Similar to the FromStr but needs the record Type since they are ambiguous.
    pub fn from_str(r#type: Type, s: &str) -> Result<Self, FromStrError> {
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

            // This should never appear in a answer record unless we have invalid data.
            Type::Reserved | Type::OPT | Type::ANY => return Err(FromStrError::UnsupportedType),
        })
    }
}

impl FromStr for SOA {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            // "ns1.google.com. dns-admin.google.com. 376337657 900 900 1800 60"
            // "{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}",
            static ref RE: Regex = Regex::new(r"^(\S+) (\S+) (\d+) (\d+) (\d+) (\d+) (\d+)$").unwrap();
        }

        if let Some(caps) = RE.captures(s) {
            let rname = caps[2].to_string();
            let rname = match Self::rname_to_email(&rname) {
                Ok(name) => name,
                Err(_) => rname, // Ignore the error
            };

            Ok(SOA {
                mname: caps[1].to_string(),
                rname,
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

impl FromStr for TXT {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            // TODO Handle escaped quotes
            static ref RE: Regex = Regex::new(r#""(.*?)""#).unwrap();
        }
        let mut txts = Vec::new();
        for caps in RE.captures_iter(s) {
            txts.push(caps[1].as_bytes().to_vec());
        };

        if txts.is_empty() {
            return Err(FromStrError::InvalidFormat);
        }

        // TODO Also check we parsed the full record

        Ok(TXT(txts))
    }
}
