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
use crate::resource::{Mx, Nsec, Rrsig, Soa, Srv};
use crate::{NSEC3, NSEC3PARAM};
use core::str::FromStr;
use pest::Parser;
use pest::iterators::{Pair, Pairs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(pest_derive::Parser)]
#[grammar = "character_string.pest"]
#[grammar = "rdata.pest"]
struct TextParser;

use crate::FromStrError;

fn parse_record_text(input: &str, rule: Rule) -> Result<Pair<'_, Rule>, FromStrError> {
    TextParser::parse(rule, input)
        .map_err(|_| FromStrError::InvalidFormat)?
        .next()
        .ok_or(FromStrError::InvalidFormat)
}

fn next_field<'i>(fields: &mut Pairs<'i, Rule>) -> Result<Pair<'i, Rule>, FromStrError> {
    fields.next().ok_or(FromStrError::InvalidFormat)
}

pub(crate) fn parse_soa(input: &str) -> Result<Soa<&str, &str>, FromStrError> {
    // "ns1.google.com. dns-admin.google.com. 376337657 900 900 1800 60"
    // "{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
    let mut fields = parse_record_text(input, Rule::soa)?.into_inner();
    Ok(Soa {
        mname: next_field(&mut fields)?.as_str(),
        rname: next_field(&mut fields)?.as_str(),
        serial: next_field(&mut fields)?.as_str().parse()?,
        refresh: Duration::from_secs(next_field(&mut fields)?.as_str().parse()?),
        retry: Duration::from_secs(next_field(&mut fields)?.as_str().parse()?),
        expire: Duration::from_secs(next_field(&mut fields)?.as_str().parse()?),
        minimum: Duration::from_secs(next_field(&mut fields)?.as_str().parse()?),
    })
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
            Type::NSEC3 => Resource::NSEC3(s.parse()?),
            Type::NSEC3PARAM => Resource::NSEC3PARAM(s.parse()?),
            Type::ZONEMD => Resource::ZONEMD(s.parse()?),

            Type::Unknown(_) => {
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
        let fields = parse_soa(s)?;

        Ok(SOA {
            mname: fields.mname.parse()?,
            rname: fields.rname.parse()?,
            serial: fields.serial,
            refresh: fields.refresh,
            retry: fields.retry,
            expire: fields.expire,
            minimum: fields.minimum,
        })
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
        let fields = parse_mx(s)?;
        Ok(MX {
            preference: fields.preference,
            exchange: fields.exchange.parse()?,
        })
    }
}

pub(crate) fn parse_mx(input: &str) -> Result<Mx<&str>, FromStrError> {
    // "10 aspmx.l.google.com."
    // "{preference} {exchange}"
    let mut fields = parse_record_text(input, Rule::mx)?.into_inner();
    Ok(Mx {
        preference: next_field(&mut fields)?.as_str().parse()?,
        exchange: next_field(&mut fields)?.as_str(),
    })
}

pub(crate) fn parse_srv(input: &str) -> Result<Srv<&str>, FromStrError> {
    // "5 0 389 ldap.google.com."
    // "{priority} {weight} {port} {name}"
    let mut fields = parse_record_text(input, Rule::srv)?.into_inner();
    Ok(Srv {
        priority: next_field(&mut fields)?.as_str().parse()?,
        weight: next_field(&mut fields)?.as_str().parse()?,
        port: next_field(&mut fields)?.as_str().parse()?,
        name: next_field(&mut fields)?.as_str(),
    })
}

impl FromStr for SRV {
    type Err = FromStrError;

    /// Parses an SRV resource from its text representation.
    ///
    /// # Errors
    ///
    /// Returns an error when a priority, weight, or port is not a valid integer or the format is invalid.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let fields = parse_srv(s)?;
        Ok(SRV {
            priority: fields.priority,
            weight: fields.weight,
            port: fields.port,
            name: fields.name.parse()?,
        })
    }
}

impl FromStr for DS {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
        // "{key_tag} {algorithm} {digest_type} {digest}"
        let mut fields = parse_record_text(s, Rule::ds)?.into_inner();
        let key_tag = next_field(&mut fields)?.as_str().parse()?;
        let algorithm = next_field(&mut fields)?
            .as_str()
            .parse()
            .map_err(|_| FromStrError::InvalidFormat)?;
        let digest_type = next_field(&mut fields)?
            .as_str()
            .parse()
            .map_err(|_| FromStrError::InvalidFormat)?;
        let digest_hex: String = fields.map(|fragment| fragment.as_str()).collect();
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
        // "257 3 8 AwEAAQ=="
        // "{flags} {protocol} {algorithm} {base64_public_key}"
        let mut fields = parse_record_text(s, Rule::dnskey)?.into_inner();
        let flags = next_field(&mut fields)?.as_str().parse()?;
        let protocol = next_field(&mut fields)?.as_str().parse()?;
        let algorithm = next_field(&mut fields)?.as_str().parse()?;
        let key_b64: String = fields.map(|fragment| fragment.as_str()).collect();
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
    UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .ok_or(FromStrError::InvalidFormat)
}

impl FromStr for RRSIG {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let fields = parse_rrsig(s)?;
        Ok(RRSIG {
            type_covered: fields.type_covered,
            algorithm: fields.algorithm,
            labels: fields.labels,
            original_ttl: fields.original_ttl,
            expiration: fields.expiration,
            inception: fields.inception,
            key_tag: fields.key_tag,
            signer_name: fields.signer_name.parse()?,
            signature: fields.signature,
        })
    }
}

pub(crate) fn parse_rrsig(s: &str) -> Result<Rrsig<&str>, FromStrError> {
    // "A 8 2 3600 2000000000 1900000000 12345 example.com. AwEAAQ=="
    // "{type_covered} {algorithm} {labels} {original_ttl} {expiration} {inception} {key_tag} {signer_name} {signature}"
    let mut fields = parse_record_text(s, Rule::rrsig)?.into_inner();
    let type_covered = Type::from_str(next_field(&mut fields)?.as_str())
        .map_err(|_| FromStrError::InvalidFormat)?;
    let algorithm = next_field(&mut fields)?.as_str().parse()?;
    let labels = next_field(&mut fields)?.as_str().parse()?;
    let original_ttl = Duration::from_secs(next_field(&mut fields)?.as_str().parse()?);
    let expiration = parse_rrsig_time(next_field(&mut fields)?.as_str())?;
    let inception = parse_rrsig_time(next_field(&mut fields)?.as_str())?;
    let key_tag = next_field(&mut fields)?.as_str().parse()?;
    let signer_name = next_field(&mut fields)?.as_str();
    let sig_b64: String = fields.map(|fragment| fragment.as_str()).collect();
    let signature =
        crate::util::base64_decode(&sig_b64).map_err(|_| FromStrError::InvalidFormat)?;
    Ok(Rrsig {
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

impl FromStr for NSEC {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let fields = parse_nsec(s)?;
        Ok(NSEC {
            next_domain: fields.next_domain.parse()?,
            types: fields.types,
        })
    }
}

pub(crate) fn parse_nsec(s: &str) -> Result<Nsec<&str>, FromStrError> {
    // "next.example.com. A NS SOA MX RRSIG NSEC DNSKEY"
    // "{next_domain} {type}..."
    let mut fields = parse_record_text(s, Rule::nsec)?.into_inner();
    let next_domain = next_field(&mut fields)?.as_str();
    let mut types = Vec::new();
    for type_field in fields {
        if type_field.as_rule() != Rule::EOI {
            types.push(
                Type::from_str(type_field.as_str()).map_err(|_| FromStrError::InvalidFormat)?,
            );
        }
    }
    Ok(Nsec { next_domain, types })
}

impl FromStr for ZONEMD {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // "2024010100 1 1 AABBCCDDEEFF00112233445566778899"
        // "{serial} {scheme} {algorithm} {digest}"
        let mut fields = parse_record_text(s, Rule::zonemd)?.into_inner();
        let serial = next_field(&mut fields)?.as_str().parse()?;
        let scheme = next_field(&mut fields)?.as_str().parse()?;
        let algorithm = next_field(&mut fields)?.as_str().parse()?;
        let digest_hex: String = fields.map(|fragment| fragment.as_str()).collect();
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

fn parse_nsec3_parameters(fields: &mut Pairs<'_, Rule>) -> Result<NSEC3PARAM, FromStrError> {
    let hash_algorithm = next_field(fields)?.as_str().parse::<u8>()?.into();
    let flags = next_field(fields)?.as_str().parse()?;
    let iterations = next_field(fields)?.as_str().parse()?;
    let salt = next_field(fields)?;
    let salt = if salt.as_str() == "-" {
        Vec::new()
    } else {
        if salt.as_str().len() > usize::from(u8::MAX) * 2 {
            return Err(FromStrError::InvalidFormat);
        }
        crate::util::hex_decode(salt.as_str()).map_err(|_| FromStrError::InvalidFormat)?
    };
    Ok(NSEC3PARAM {
        hash_algorithm,
        flags,
        iterations,
        salt,
    })
}

impl FromStr for NSEC3PARAM {
    type Err = FromStrError;

    /// Parses NSEC3 parameters, accepting `-` for an empty salt.
    ///
    /// # Errors
    ///
    /// Returns an error for missing or extra fields, out-of-range numbers,
    /// malformed hexadecimal salt, or salt longer than 255 octets.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // "1 0 12 aabbccdd"
        // "{hash_algorithm} {flags} {iterations} {salt}"
        let mut fields = parse_record_text(s, Rule::nsec3param)?.into_inner();
        parse_nsec3_parameters(&mut fields)
    }
}

impl FromStr for NSEC3 {
    type Err = FromStrError;

    /// Parses NSEC3 RDATA with an unpadded base32hex next-owner hash.
    ///
    /// Parsing preserves unknown algorithm codes; it does not validate a denial
    /// of existence proof.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or out-of-range fields, invalid salt or
    /// base32hex encoding, salt or hash longer than 255 octets, or unknown type tokens.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // "1 0 12 aabbccdd 0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM A NS SOA MX RRSIG DNSKEY NSEC3PARAM"
        // "{hash_algorithm} {flags} {iterations} {salt} {next_hashed_owner_name} {types...}"
        let mut fields = parse_record_text(s, Rule::nsec3)?.into_inner();
        let parameters = parse_nsec3_parameters(&mut fields)?;
        let next_hash = next_field(&mut fields)?;
        let encoded = next_hash.as_str();
        if encoded.len() > (usize::from(u8::MAX) * 8).div_ceil(5) {
            return Err(FromStrError::InvalidFormat);
        }
        let next_hashed_owner_name =
            crate::util::base32hex_decode(encoded).map_err(|_| FromStrError::InvalidFormat)?;
        // Reject incomplete octets and nonzero padding bits rather than discarding them.
        if !crate::util::base32hex_encode(&next_hashed_owner_name).eq_ignore_ascii_case(encoded) {
            return Err(FromStrError::InvalidFormat);
        }
        let types = fields
            .filter(|field| field.as_rule() != Rule::EOI)
            .map(|field| {
                field
                    .as_str()
                    .parse()
                    .map_err(|_| FromStrError::InvalidFormat)
            })
            .collect::<Result<_, _>>()?;
        Ok(NSEC3 {
            hash_algorithm: parameters.hash_algorithm,
            flags: parameters.flags,
            iterations: parameters.iterations,
            salt: parameters.salt,
            next_hashed_owner_name,
            types,
        })
    }
}

#[cfg(feature = "zones")]
pub(crate) fn parse_zone_txt(input: &str) -> Result<TXT, FromStrError> {
    parse_character_strings(input, Rule::zone_txt)
}

fn parse_character_strings(input: &str, rule: Rule) -> Result<TXT, FromStrError> {
    let parsed = parse_record_text(input, rule)?;
    let mut strings = Vec::new();
    for string in parsed
        .into_inner()
        .filter(|pair| matches!(pair.as_rule(), Rule::quoted | Rule::unquoted))
    {
        let mut bytes = Vec::new();
        for token in string.into_inner() {
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
                Rule::text | Rule::unquoted_text => {
                    bytes.extend_from_slice(token.as_str().as_bytes())
                }
                _ => return Err(FromStrError::InvalidFormat),
            }
        }
        strings.push(bytes);
    }
    Ok(TXT(strings))
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
        // "\"first string\" \"second string\""
        if !s.contains('"') {
            return Ok(TXT::from(s));
        }

        parse_character_strings(s, Rule::txt)
    }
}

#[cfg(test)]
mod tests {
    use super::{DNSKEY, DS, FromStrError, MX, NSEC, RRSIG, Resource, SOA, SRV, TXT, ZONEMD};
    use crate::Type;

    #[test]
    fn nsec3_text_round_trips_and_preserves_type_bitmaps() {
        for text in [
            "1 1 12 aabbccdd 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom A NS SOA MX TXT RRSIG DNSKEY NSEC3PARAM TYPE65400",
            "1 0 0 - 00",
            "255 255 65535 - 00",
        ] {
            let record: crate::NSEC3 = text.parse().unwrap();
            assert_eq!(record, record.to_string().parse().unwrap());
            assert_eq!(
                Resource::parse_text(Type::NSEC3, text).unwrap(),
                Resource::NSEC3(record),
            );
        }
        let record: crate::NSEC3 = "1 1 12 aabbccdd 00 A NS TYPE65400".parse().unwrap();
        assert_eq!(record.salt, [0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(record.next_hashed_owner_name, [0]);
        assert_eq!(record.types, [Type::A, Type::NS, Type::Unknown(65400)]);
        assert!(record.is_opt_out());
        for text in ["1 0 12 aabbccdd", "1 0 0 -", "255 255 65535 FF"] {
            let record: crate::NSEC3PARAM = text.parse().unwrap();
            assert_eq!(record, record.to_string().parse().unwrap());
            assert_eq!(
                Resource::parse_text(Type::NSEC3PARAM, text).unwrap(),
                Resource::NSEC3PARAM(record),
            );
        }
    }

    #[test]
    fn nsec3_text_rejects_malformed_fields_and_enforces_wire_lengths() {
        for text in [
            "",
            "1 0 0 -",
            "256 0 0 - 00",
            "1 256 0 - 00",
            "1 0 65536 - 00",
            "1 0 0 abc 00",
            "1 0 0 gg 00",
            "1 0 0 - W0",
            "1 0 0 - 00=",
            "1 0 0 - 0",
            "1 0 0 - 000",
            "1 0 0 - 01",
            "1 0 0 - 00 INVALID",
            "1 0 0 - 00 TYPE65536",
        ] {
            assert!(text.parse::<crate::NSEC3>().is_err(), "{text}");
        }
        for text in ["", "1 0 0", "1 0 0 abc", "1 0 0 - extra", "1 0 65536 -"] {
            assert!(text.parse::<crate::NSEC3PARAM>().is_err(), "{text}");
        }
        for length in [255, 256] {
            let salt = "ab".repeat(length);
            let hash = crate::util::base32hex_encode(&vec![0xff; length]);
            assert_eq!(
                format!("1 0 0 {salt}").parse::<crate::NSEC3PARAM>().is_ok(),
                length == 255,
            );
            assert_eq!(
                format!("1 0 0 {salt} 00").parse::<crate::NSEC3>().is_ok(),
                length == 255,
            );
            assert_eq!(
                format!("1 0 0 - {hash}").parse::<crate::NSEC3>().is_ok(),
                length == 255,
            );
        }
    }

    #[test]
    fn unresolved_rdata_parsers_borrow_names() {
        let mx = super::parse_mx("10 mail").unwrap();
        assert_eq!(mx.exchange, "mail");
        assert_eq!(mx.preference, 10);
        let srv = super::parse_srv("5 10 389 ldap").unwrap();
        assert_eq!(srv.name, "ldap");
        assert_eq!((srv.priority, srv.weight, srv.port), (5, 10, 389));
        let input = String::from("A 8 2 3600 2000000000 1900000000 12345 signer AQID");
        let rrsig = super::parse_rrsig(&input).unwrap();
        assert_eq!(rrsig.signer_name, "signer");
        let signer_offset = input.find("signer").unwrap();
        assert_eq!(rrsig.signer_name.as_ptr(), input[signer_offset..].as_ptr());
        assert_eq!(rrsig.signature, [1, 2, 3]);
        let nsec = super::parse_nsec("next A AAAA RRSIG").unwrap();
        assert_eq!(nsec.next_domain, "next");
        assert_eq!(nsec.types, [Type::A, Type::AAAA, Type::RRSIG]);
    }

    #[test]
    fn nsec_rejects_unrecognized_type_tokens_instead_of_dropping_them() {
        assert!("next.example. A INVALID AAAA".parse::<NSEC>().is_err());
        assert!("next.example. INVALID".parse::<NSEC>().is_err());
        assert!("next.example.".parse::<NSEC>().unwrap().types.is_empty());
    }

    #[test]
    fn text_rdata_requires_field_separators() {
        for (record_type, input) in [
            (Type::MX, "10mail.example."),
            (Type::SRV, "1 2 389ldap.example."),
            (Type::DS, "12345RSASHA256 2 aabb"),
            (Type::DNSKEY, "257 3ED25519 AQID"),
            (Type::ZONEMD, "1 1 1aabb"),
        ] {
            assert!(Resource::parse_text(record_type, input).is_err(), "{input}");
        }
    }

    #[test]
    fn soa_fields_borrow_names_without_resolving_them() {
        let input = String::from(r"ns Action\.domains 376337657 900 900 1800 60");
        let fields = super::parse_soa(&input).unwrap();
        assert_eq!(fields.mname, "ns");
        assert_eq!(fields.rname, r"Action\.domains");
        assert_eq!(fields.mname.as_ptr(), input.as_ptr());
        assert_eq!(fields.rname.as_ptr(), input[3..].as_ptr());
        assert_eq!(fields.serial, 376337657);
        assert_eq!(fields.refresh.as_secs(), 900);
        assert_eq!(fields.retry.as_secs(), 900);
        assert_eq!(fields.expire.as_secs(), 1800);
        assert_eq!(fields.minimum.as_secs(), 60);
    }

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
    fn rdata_text_parsers_accept_whitespace_and_split_digests() {
        let soa: SOA = "ns.example.\tadmin.example. 1 2 3 4 5"
            .parse()
            .expect("SOA with tab separator should parse");
        assert_eq!(soa.serial, 1);

        let mx: MX = "10\tmail.example.".parse().expect("MX should parse");
        assert_eq!(mx.preference, 10);

        let srv: SRV = "5 0\t389 ldap.example.".parse().expect("SRV should parse");
        assert_eq!(srv.port, 389);

        let ds: DS = "12345 8 2 aabb ccdd".parse().expect("DS should parse");
        assert_eq!(ds.digest, [0xaa, 0xbb, 0xcc, 0xdd]);

        let dnskey: DNSKEY = "257 3 8 AQ ID".parse().expect("DNSKEY should parse");
        assert_eq!(dnskey.public_key, [1, 2, 3]);

        let rrsig: RRSIG = "A 8 2 3600 2000000000 1900000000 12345 example. AQ ID"
            .parse()
            .expect("RRSIG should parse");
        assert_eq!(rrsig.signature, [1, 2, 3]);

        let nsec: NSEC = "next.example. A AAAA RRSIG NSEC DNSKEY"
            .parse()
            .expect("NSEC should parse");
        assert_eq!(
            nsec.types,
            [Type::A, Type::AAAA, Type::RRSIG, Type::NSEC, Type::DNSKEY]
        );

        let zonemd: ZONEMD = "1 1 1 aabb ccdd".parse().expect("ZONEMD should parse");
        assert_eq!(zonemd.digest, [0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn rdata_text_parsers_reject_invalid_or_trailing_fields() {
        assert!(
            "ns.example. admin.example. 1 2 3 4 5 extra"
                .parse::<SOA>()
                .is_err()
        );
        assert!("10 mail.example. extra".parse::<MX>().is_err());
        assert!("5 0 389 ldap.example. extra".parse::<SRV>().is_err());
        assert!("12345 8 2 aabb invalid".parse::<DS>().is_err());
        assert!("257 3 8 AQID invalid".parse::<DNSKEY>().is_err());
        assert!(
            "A 8 2 3600 2000000000 1900000000 12345 example. AQID invalid"
                .parse::<RRSIG>()
                .is_err()
        );
        assert!("1 1 1 aabb invalid".parse::<ZONEMD>().is_err());
        assert!(
            "A 8 2 3600 18446744073709551615 1 12345 example. AQID"
                .parse::<RRSIG>()
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
