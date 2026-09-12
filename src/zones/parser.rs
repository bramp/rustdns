// Parses a Zone File following RFC 1035 (section 5).

use crate::zones::Entry;
use crate::zones::Record;
use crate::zones::Resource;
use crate::Class;
use crate::DNSKEY;
use crate::DS;
use crate::MX;
use crate::NSEC;
use crate::RRSIG;
use crate::SOA;
use crate::Type;
use crate::ZONEMD;
use pest_consume::match_nodes;
use pest_consume::Error;
use pest_consume::Parser;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[grammar = "zones/zones.pest"]
pub(crate) struct ZoneParser;

type Result<T> = std::result::Result<T, Error<Rule>>;
type Node<'i> = pest_consume::Node<'i, Rule, ()>;

#[pest_consume::parser]
impl ZoneParser {
    fn EOI(input: Node<'_>) -> Result<()> {
        assert_eq!(input.as_rule(), Rule::EOI);
        Ok(())
    }

    fn ip4(input: Node<'_>) -> Result<Ipv4Addr> {
        assert_eq!(input.as_rule(), Rule::ip4);

        match Ipv4Addr::from_str(input.as_str()) {
            Ok(ip4) => Ok(ip4),
            Err(e) => Err(input.error(e)),
        }
    }

    fn ip6(input: Node<'_>) -> Result<Ipv6Addr> {
        assert_eq!(input.as_rule(), Rule::ip6);

        match Ipv6Addr::from_str(input.as_str()) {
            Ok(ip6) => Ok(ip6),
            Err(e) => Err(input.error(e)),
        }
    }

    fn duration(input: Node<'_>) -> Result<Duration> {
        assert_eq!(input.as_rule(), Rule::duration);

        // TODO Support more complex duration types (e.g "1d")
        match input.as_str().parse() {
            Ok(i) => Ok(Duration::new(i, 0)),
            Err(e) => Err(input.error(e)),
        }
    }

    fn string(input: Node<'_>) -> Result<&str> {
        assert_eq!(input.as_rule(), Rule::string);

        Ok(input.as_str())
    }

    fn domain(input: Node<'_>) -> Result<&str> {
        assert_eq!(input.as_rule(), Rule::domain);

        // TODO Should I do some validation?
        Ok(input.as_str())
    }

    fn class(input: Node<'_>) -> Result<Class> {
        assert_eq!(input.as_rule(), Rule::class);

        match input.as_str().parse() {
            Ok(class) => Ok(class),
            Err(e) => Err(input.error(e)),
        }
    }

    fn number<T: FromStr>(input: Node<'_>) -> Result<T>
    where
        T::Err: std::fmt::Display,
    {
        assert_eq!(input.as_rule(), Rule::number);

        match input.as_str().parse() {
            Ok(i) => Ok(i),
            Err(e) => Err(input.error(e)),
        }
    }

    fn type_name(input: Node<'_>) -> Result<Type> {
        assert_eq!(input.as_rule(), Rule::type_name);
        match Type::from_str(input.as_str()) {
            Ok(t) => Ok(t),
            Err(e) => Err(input.error(e)),
        }
    }

    fn base64_string(input: Node<'_>) -> Result<Vec<u8>> {
        assert_eq!(input.as_rule(), Rule::base64_string);
        match crate::util::base64_decode(input.as_str()) {
            Ok(bytes) => Ok(bytes),
            Err(e) => Err(input.error(e)),
        }
    }

    fn hex_string(input: Node<'_>) -> Result<Vec<u8>> {
        assert_eq!(input.as_rule(), Rule::hex_string);
        match crate::util::hex_decode(input.as_str()) {
            Ok(bytes) => Ok(bytes),
            Err(e) => Err(input.error(e)),
        }
    }

    fn rrsig_time(input: Node<'_>) -> Result<SystemTime> {
        assert_eq!(input.as_rule(), Rule::rrsig_time);
        let s = input.as_str();
        if s.len() == 14 && s.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y%m%d%H%M%S") {
                return Ok(dt.and_utc().into());
            }
        }
        match s.parse::<u64>() {
            Ok(secs) => Ok(UNIX_EPOCH + Duration::from_secs(secs)),
            Err(e) => Err(input.error(e)),
        }
    }

    #[alias(resource)]
    fn resource_a(input: Node<'_>) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_a);

        Ok(match_nodes!(input.into_children();
            [ip4(ip)] => Resource::A(ip),
        ))
    }

    #[alias(resource)]
    fn resource_aaaa(input: Node<'_>) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_aaaa);

        Ok(match_nodes!(input.into_children();
            [ip6(ip)] => Resource::AAAA(ip),
        ))
    }

    #[alias(resource)]
    fn resource_cname(input: Node<'_>) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_cname);

        Ok(match_nodes!(input.into_children();
            [domain(name)] => Resource::CNAME(name.to_string()),
        ))
    }

    #[alias(resource)]
    fn resource_ns(input: Node<'_>) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_ns);

        Ok(match_nodes!(input.into_children();
            [domain(name)] => Resource::NS(name.to_string()),
        ))
    }

    #[alias(resource)]
    fn resource_mx(input: Node<'_>) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_mx);

        Ok(match_nodes!(input.into_children();
            [number(preference), domain(exchange)] => Resource::MX(MX {
                preference,
                exchange: exchange.to_string()
            }),
        ))
    }

    #[alias(resource)]
    fn resource_ptr(input: Node<'_>) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_ptr);

        Ok(match_nodes!(input.into_children();
            [domain(name)] => Resource::PTR(name.to_string()),
        ))
    }

    #[alias(resource)]
    fn resource_soa(input: Node<'_>) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_soa);

        Ok(match_nodes!(input.into_children();
            [domain(mname), string(rname), number(serial), duration(refresh), duration(retry), duration(expire), duration(minimum)] => Resource::SOA(SOA {
                mname: mname.to_string(),
                rname: rname.to_string(), // TODO Should this actually be a domain?
                serial, refresh, retry, expire, minimum
            }),
        ))
    }

    #[alias(resource)]
    fn resource_ds(input: Node<'_>) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_ds);

        Ok(match_nodes!(input.into_children();
            [number(key_tag), number(algorithm), number(digest_type), hex_string(digest)] => Resource::DS(DS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            }),
        ))
    }

    #[alias(resource)]
    fn resource_dnskey(input: Node<'_>) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_dnskey);

        Ok(match_nodes!(input.into_children();
            [number(flags), number(protocol), number(algorithm), base64_string(public_key)] => Resource::DNSKEY(DNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            }),
        ))
    }

    #[alias(resource)]
    fn resource_rrsig(input: Node<'_>) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_rrsig);

        Ok(match_nodes!(input.into_children();
            [type_name(type_covered), number(algorithm), number(labels), duration(original_ttl), rrsig_time(expiration), rrsig_time(inception), number(key_tag), domain(signer_name), base64_string(signature)] => Resource::RRSIG(RRSIG {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer_name: signer_name.to_string(),
                signature,
            }),
        ))
    }

    #[alias(resource)]
    fn resource_nsec(input: Node<'_>) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_nsec);

        Ok(match_nodes!(input.into_children();
            [domain(next_domain), type_name(types)..] => Resource::NSEC(NSEC {
                next_domain: next_domain.to_string(),
                types: types.collect(),
            }),
        ))
    }

    #[alias(resource)]
    fn resource_zonemd(input: Node<'_>) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_zonemd);

        Ok(match_nodes!(input.into_children();
            [number(serial), number(scheme), number(algorithm), hex_string(digest)] => Resource::ZONEMD(ZONEMD {
                serial,
                scheme,
                algorithm,
                digest,
            }),
        ))
    }

    #[alias(entry)]
    fn origin(input: Node<'_>) -> Result<Entry> {
        assert_eq!(input.as_rule(), Rule::origin);

        Ok(match_nodes!(input.into_children();
            [domain(d)] => Entry::Origin(d.to_string()),
        ))
    }

    #[alias(entry)]
    fn ttl(input: Node<'_>) -> Result<Entry> {
        assert_eq!(input.as_rule(), Rule::ttl);

        Ok(match_nodes!(input.into_children();
            [duration(ttl)] => Entry::TTL(ttl),
        ))
    }

    #[alias(entry)]
    fn record(input: Node<'_>) -> Result<Entry> {
        assert_eq!(input.as_rule(), Rule::record);

        let record = Self::parse_record(input)?;

        // Wrap in a Entry
        Ok(Entry::Record(record))
    }

    pub fn single_record(input: Node<'_>) -> Result<Record> {
        assert_eq!(input.as_rule(), Rule::single_record);

        match_nodes!(input.into_children();
            [record, _EOI] => Ok(Self::parse_record(record)?)
        )
    }

    pub fn file(input: Node<'_>) -> Result<Vec<Entry>> {
        assert_eq!(input.as_rule(), Rule::file);

        match_nodes!(input.into_children();
            [entry(entrys).., _EOI] => Ok(entrys.collect()),
        )
    }
}

impl ZoneParser {
    // parse_record does the heavy lifting parsing a single record entry.
    // This is in a seperate ZoneParser impl, due to limitations with
    // `#[pest_consume::parser]` which does not allow aliased methods to be
    // called, or used in match_nodes.
    fn parse_record(input: Node<'_>) -> Result<Record> {
        assert_eq!(input.as_rule(), Rule::record);

        let mut record = Record {
            name: None,
            ttl: None,
            class: None,
            resource: Resource::ANY,
        };

        // All the assert! are due to programming errors, hopefully
        // never due to a parsing error.

        // We would prefer to use match_nodes! but we need to match the
        // various children in any order. This is due to the near ambigious
        // syntax of the resource record entry.
        for node in input.into_children() {
            let rule = node.as_rule();
            match rule {
                Rule::domain => {
                    assert!(record.name.is_none(), "record domain was set twice");

                    record.name = Some(Self::domain(node)?.to_string())
                }
                Rule::duration => {
                    assert!(record.ttl.is_none(), "record ttl was set twice");

                    record.ttl = Some(Self::duration(node)?)
                }
                Rule::class => {
                    assert!(record.class.is_none(), "record class was set twice");

                    record.class = Some(Self::class(node)?)
                }

                _ => {
                    // Rule::resource have many aliases, try one of them.
                    match Self::rule_alias(rule) {
                        AliasedRule::resource => {
                            assert!(
                                record.resource == Resource::ANY,
                                "record resource was set twice"
                            );

                            record.resource = Self::resource(node)?
                        }

                        _ => panic!("Unexpected token: {:?} '{:?}'", rule, node.as_str()),
                    }
                }
            }
        }

        // By the end atleast this should be set
        assert_ne!(record.resource, Resource::ANY);

        Ok(record)
    }
}
