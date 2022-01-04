extern crate pest;

use crate::zones::preprocessor::preprocess;
use crate::zones::Entry;
use crate::zones::Record;
use crate::zones::Resource;
use crate::Class;
use crate::MX;
use crate::SOA;
use pest_consume::match_nodes;
use pest_consume::Error;
use pest_consume::Parser;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::time::Duration;

#[derive(Parser)]
#[grammar = "zones/zones.pest"]
struct ZoneParser;

type Result<T> = std::result::Result<T, Error<Rule>>;
type Node<'i> = pest_consume::Node<'i, Rule, ()>;

#[pest_consume::parser]
impl ZoneParser {
    fn EOI(input: Node) -> Result<()> {
        assert_eq!(input.as_rule(), Rule::EOI);
        Ok(())
    }

    fn ip4(input: Node) -> Result<Ipv4Addr> {
        assert_eq!(input.as_rule(), Rule::ip4);

        match Ipv4Addr::from_str(input.as_str()) {
            Ok(ip4) => Ok(ip4),
            Err(e) => Err(input.error(e)),
        }
    }

    fn ip6(input: Node) -> Result<Ipv6Addr> {
        assert_eq!(input.as_rule(), Rule::ip6);

        match Ipv6Addr::from_str(input.as_str()) {
            Ok(ip6) => Ok(ip6),
            Err(e) => Err(input.error(e)),
        }
    }

    fn duration(input: Node) -> Result<Duration> {
        assert_eq!(input.as_rule(), Rule::duration);

        // TODO Support more complex duration types (e.g "1d")
        match input.as_str().parse() {
            Ok(i) => Ok(Duration::new(i, 0)),
            Err(e) => Err(input.error(e)),
        }
    }

    fn string(input: Node) -> Result<&str> {
        assert_eq!(input.as_rule(), Rule::string);

        Ok(input.as_str())
    }

    fn domain(input: Node) -> Result<&str> {
        assert_eq!(input.as_rule(), Rule::domain);

        // TODO Should I do some validation?
        Ok(input.as_str())
    }

    fn class(input: Node) -> Result<Class> {
        assert_eq!(input.as_rule(), Rule::class);

        match input.as_str().parse() {
            Ok(class) => Ok(class),
            Err(e) => Err(input.error(e)),
        }
    }

    fn number<T: std::str::FromStr>(input: Node) -> Result<T>
    where
        T::Err: std::fmt::Display,
    {
        assert_eq!(input.as_rule(), Rule::number);

        match input.as_str().parse() {
            Ok(i) => Ok(i),
            Err(e) => Err(input.error(e)),
        }
    }

    #[alias(resource)]
    fn resource_a(input: Node) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_a);

        Ok(match_nodes!(input.into_children();
            [ip4(ip)] => Resource::A(ip),
        ))
    }

    #[alias(resource)]
    fn resource_aaaa(input: Node) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_aaaa);

        Ok(match_nodes!(input.into_children();
            [ip6(ip)] => Resource::AAAA(ip),
        ))
    }

    #[alias(resource)]
    fn resource_cname(input: Node) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_cname);

        Ok(match_nodes!(input.into_children();
            [domain(name)] => Resource::CNAME(name.to_string()),
        ))
    }

    #[alias(resource)]
    fn resource_ns(input: Node) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_ns);

        Ok(match_nodes!(input.into_children();
            [domain(name)] => Resource::NS(name.to_string()),
        ))
    }

    #[alias(resource)]
    fn resource_mx(input: Node) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_mx);

        Ok(match_nodes!(input.into_children();
            [number(preference), domain(exchange)] => Resource::MX(MX {
                preference,
                exchange: exchange.to_string()
            }),
        ))
    }

    #[alias(resource)]
    fn resource_soa(input: Node) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_soa);

        Ok(match_nodes!(input.into_children();
            [domain(mname), string(rname), number(serial), duration(refresh), duration(retry), duration(expire), duration(minimum)] => Resource::SOA(SOA {
                mname: mname.to_string(),
                rname: rname.to_string(), // TODO Should this actually be a domain?
                serial, refresh, retry, expire, minimum
            }),
        ))
    }

    #[alias(entry)]
    fn origin(input: Node) -> Result<Entry> {
        assert_eq!(input.as_rule(), Rule::origin);

        Ok(match_nodes!(input.into_children();
            [domain(d)] => Entry::Origin(d.to_string()),
        ))
    }

    #[alias(entry)]
    fn ttl(input: Node) -> Result<Entry> {
        assert_eq!(input.as_rule(), Rule::ttl);

        Ok(match_nodes!(input.into_children();
            [duration(ttl)] => Entry::Ttl(ttl),
        ))
    }

    #[alias(entry)]
    fn record(input: Node) -> Result<Entry> {
        assert_eq!(input.as_rule(), Rule::record);

        let record = Self::parse_record(input)?;

        // Wrap in a Entry
        Ok(Entry::Record(record))
    }

    fn single_record(input: Node) -> Result<Record> {
        assert_eq!(input.as_rule(), Rule::single_record);

        match_nodes!(input.into_children();
            [record, _EOI] => Ok(Self::parse_record(record)?)
        )
    }

    fn file(input: Node) -> Result<Vec<Entry>> {
        assert_eq!(input.as_rule(), Rule::file);

        Ok(match_nodes!(input.into_children();
            [entry(entrys).., _EOI] => entrys.collect(),
        ))
    }
}

impl ZoneParser {
    // parse_record does the heavy lifting parsing a single record entry.
    // This is in a seperate ZoneParser impl, due to limitations with
    // `#[pest_consume::parser]` which does not allow aliased methods to be
    // called, or used in match_nodes.
    fn parse_record(input: Node) -> Result<Record> {
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

/// Parse a single zone file resource record.
///
/// For example:
///
/// ```
/// use rustdns::Resource;
/// use rustdns::zones::{Record, parse_record};
///
/// let record = parse_record("example.com.  A   192.0.2.1");
/// assert_eq!(record, Ok(Record {
///   name: Some("example.com.".to_string()),
///   ttl: None,
///   class: None,
///   resource: Resource::A("192.0.2.1".parse().unwrap()),
/// }));
/// ```
///
/// This function is mostly useful for test code, or quickly parsing a
/// single record. Please prefer to use [`parse`] to parse full files.
pub fn parse_record(input_str: &str) -> Result<Record> {
    let inputs = ZoneParser::parse(Rule::single_record, input_str)?;
    let input = inputs.single()?;
    ZoneParser::single_record(input)
}

/// Parse a full zone file.
///
/// ```
/// use rustdns::Resource;
/// use rustdns::zones::{Entry, Record, parse};
///
/// let file = parse("$ORIGIN example.com.\n www  A   192.0.2.1");
/// assert_eq!(file, Ok(vec![
///   Entry::Origin("example.com.".to_string()),
///   Entry::Record(Record {
///     name: Some("www".to_string()),
///     ttl: None,
///     class: None,
///     resource: Resource::A("192.0.2.1".parse().unwrap()),
///   }),
/// ]));
/// ```
pub fn parse(input_str: &str) -> Result<Vec<Entry>> {
    // TODO Change this to a File return type
    let input_str = preprocess(input_str).unwrap(); // TODO

    let inputs = ZoneParser::parse(Rule::file, &input_str)?;
    let input = inputs.single()?;
    ZoneParser::file(input)
}
