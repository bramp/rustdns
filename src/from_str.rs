//! Implements the FromStr trait for the various types, to be able to parse in `dig` style.
// Refer to https://github.com/tigeli/bind-utils/blob/master/bin/dig/dig.c for reference.

use crate::DNSKEY;
use crate::DS;
use crate::MX;
use crate::NSEC;
use crate::Name;
use crate::RRSIG;
use crate::Resource;
use crate::SOA;
use crate::SRV;
use crate::TXT;
use crate::Type;
use crate::ZONEMD;
use core::str::FromStr;
use regex::Regex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(pest_derive::Parser)]
#[grammar = "character_string.pest"]
struct CharacterStringParser;

use crate::FromStrError;

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
            Type::NS => Resource::NS(s.parse().map_err(|_| FromStrError::InvalidFormat)?),
            Type::CNAME => Resource::CNAME(s.parse().map_err(|_| FromStrError::InvalidFormat)?),
            Type::PTR => Resource::PTR(s.parse().map_err(|_| FromStrError::InvalidFormat)?),

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
    /// Returns an error when the text does not contain the seven required SOA fields,
    /// a domain name or `rname` is invalid, or a numeric field is invalid.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            // "ns1.google.com. dns-admin.google.com. 376337657 900 900 1800 60"
            // "{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}",
            static ref RE: Regex = Regex::new(r"^(\S+) (\S+) (\d+) (\d+) (\d+) (\d+) (\d+)$").unwrap();
        }

        if let Some(caps) = RE.captures(s) {
            let rname = caps[2].parse()?;
            Ok(SOA {
                mname: Name::new(&caps[1])?,
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
                exchange: Name::new(&caps[2])?,
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
                name: Name::new(&caps[4])?,
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
        let signer_name = Name::new(parts[7])?;
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
        let next_domain = Name::new(parts.next().ok_or(FromStrError::InvalidFormat)?)?;
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
    /// Quoted strings use the escape syntax from [RFC 1035 §5.1]. Each quoted
    /// segment remains a separate character-string. Text without quotes is
    /// preserved as a single unescaped string for compatibility.
    ///
    /// # Errors
    ///
    /// Returns [`FromStrError::InvalidFormat`] for malformed quoted strings or
    /// escapes, and [`FromStrError::InvalidTxtEscape`] for a decimal escape
    /// outside the octet range.
    ///
    /// [RFC 1035 §5.1]: https://www.rfc-editor.org/rfc/rfc1035#section-5.1
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use pest::Parser;

        if !s.contains('"') {
            return Ok(TXT::from(s));
        }

        let parsed = CharacterStringParser::parse(Rule::txt, s)
            .map_err(|_| FromStrError::InvalidFormat)?
            .next()
            .ok_or(FromStrError::InvalidFormat)?;
        let mut strings = Vec::new();
        for quoted in parsed
            .into_inner()
            .filter(|pair| pair.as_rule() == Rule::quoted)
        {
            let mut bytes = Vec::new();
            for token in quoted.into_inner() {
                match token.as_rule() {
                    Rule::decimal_escape => {
                        let digits = token
                            .as_str()
                            .strip_prefix('\\')
                            .ok_or(FromStrError::InvalidFormat)?;
                        bytes.push(digits.parse::<u8>().map_err(|_| {
                            FromStrError::InvalidTxtEscape {
                                reason: "decimal escape is greater than 255",
                            }
                        })?);
                    }
                    Rule::character_escape => {
                        let character = token
                            .as_str()
                            .strip_prefix('\\')
                            .ok_or(FromStrError::InvalidFormat)?;
                        bytes.extend_from_slice(character.as_bytes());
                    }
                    Rule::text => bytes.extend_from_slice(token.as_str().as_bytes()),
                    _ => return Err(FromStrError::InvalidFormat),
                }
            }
            strings.push(bytes);
        }
        Ok(TXT(strings))
    }
}

#[cfg(test)]
mod tests {
    use super::{FromStrError, Resource, SOA, TXT};
    use crate::Type;

    #[test]
    fn soa_text_rejects_invalid_rnames() {
        for rname in ["", "bad..name", "bad\\", "bad\\12", "bad\\256"] {
            let input = format!("ns.example. {rname} 1 2 3 4 5");
            assert!(
                input.parse::<SOA>().is_err(),
                "accepted invalid SOA rname {rname:?}"
            );
        }

        let soa: SOA = "ns.example. Action\\.domains 1 2 3 4 5"
            .parse()
            .expect("escaped SOA rname should parse");
        assert_eq!(soa.rname.as_str(), r"Action\.domains.");
    }

    #[test]
    fn resource_text_rejects_invalid_domain_names() {
        assert!(Resource::parse_text(Type::CNAME, "bad..example").is_err());
        assert!(
            "ns..example admin.example 1 2 3 4 5"
                .parse::<SOA>()
                .is_err()
        );
    }

    #[test]
    fn txt_text_decodes_escaped_characters_and_decimal_bytes() {
        let txt: TXT = r#""quote: \" slash: \\ byte: \065" "second""#.parse().unwrap();
        assert_eq!(
            txt.0,
            vec![b"quote: \" slash: \\ byte: A".to_vec(), b"second".to_vec()]
        );
    }

    #[test]
    fn txt_text_rejects_malformed_escapes_and_trailing_text() {
        for input in [
            r#""bad\1""#,
            r#""bad\12""#,
            r#""bad\12x""#,
            r#""bad\256""#,
            r#""bad\999""#,
            r#""bad\"#,
            r#""ok" trailing"#,
            r#"leading "ok""#,
            r#""unterminated"#,
            r#""ok" "unterminated"#,
        ] {
            assert!(
                input.parse::<TXT>().is_err(),
                "accepted invalid TXT text {input:?}"
            );
        }

        assert!(matches!(
            r#""bad\256""#.parse::<TXT>(),
            Err(FromStrError::InvalidTxtEscape { .. })
        ));
    }

    #[test]
    fn txt_text_preserves_segments_and_unquoted_compatibility() {
        for (input, expected) in [
            (r#""""#, vec![Vec::new()]),
            (r#""one""two""#, vec![b"one".to_vec(), b"two".to_vec()]),
            (
                " \t\"one\"\n\"\"\r\n\"two\" ",
                vec![b"one".to_vec(), Vec::new(), b"two".to_vec()],
            ),
            (r"unquoted \065 text", vec![br"unquoted \065 text".to_vec()]),
            ("", vec![Vec::new()]),
            ("\"caf\u{e9}\"", vec!["caf\u{e9}".as_bytes().to_vec()]),
            (r#""\0654""#, vec![b"A4".to_vec()]),
            (r#""\n""#, vec![b"n".to_vec()]),
        ] {
            for record_type in [Type::TXT, Type::SPF] {
                let parsed = Resource::parse_text(record_type, input).unwrap();
                let expected_resource = if record_type == Type::TXT {
                    Resource::TXT(TXT(expected.clone()))
                } else {
                    Resource::SPF(TXT(expected.clone()))
                };
                assert_eq!(parsed, expected_resource, "{input:?}");
            }
        }
    }

    #[test]
    fn txt_decimal_escapes_cover_every_octet() {
        for value in 0..=u8::MAX {
            let input = format!(r#""\{value:03}""#);
            let parsed = input.parse::<TXT>().unwrap();
            assert_eq!(parsed.0, vec![vec![value]]);
            assert_eq!(parsed.to_string().parse::<TXT>().unwrap(), parsed);
        }
    }

    #[test]
    fn txt_display_round_trips_escaped_text() {
        let txt = TXT(vec![
            b"quote: \" slash: \\065".to_vec(),
            "caf\u{e9}".as_bytes().to_vec(),
            vec![0, 255],
            Vec::new(),
        ]);
        assert_eq!(txt.to_string().parse::<TXT>().unwrap(), txt);
    }

    #[test]
    #[cfg(feature = "json")]
    fn txt_and_spf_json_round_trip_escaped_bytes() {
        let mut message = crate::Message::default();
        let text = TXT(vec![b"quote: \" slash: \\".to_vec(), vec![0, 255]]);
        for resource in [Resource::TXT(text.clone()), Resource::SPF(text)] {
            message.answers.push(
                crate::Record::try_new(
                    "example.com.",
                    crate::Class::Internet,
                    std::time::Duration::from_secs(60),
                    resource,
                )
                .unwrap(),
            );
        }

        let json = crate::json::to_string(&message).unwrap();
        let decoded = crate::json::from_str(&json).unwrap();
        assert_eq!(decoded.answers, message.answers);
    }
}
