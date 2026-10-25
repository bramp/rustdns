// Parses a Zone File following [RFC 1035 §5](https://datatracker.ietf.org/doc/html/rfc1035#section-5).

use crate::zones::Entry;
use crate::zones::Record;
use crate::zones::Resource;
use crate::zones::{UnresolvedMx, UnresolvedNsec, UnresolvedRrsig, UnresolvedSoa, UnresolvedSrv};
use crate::Class;
use pest_consume::match_nodes;
use pest_consume::Error;
use pest_consume::Parser;
use std::borrow::Cow;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::time::Duration;

#[derive(Parser)]
#[grammar = "zones/zones.pest"]
#[grammar = "rdata.pest"]
pub(crate) struct ZoneParser;

type Result<T> = std::result::Result<T, Error<Rule>>;
type Node<'i> = pest_consume::Node<'i, Rule, ()>;

fn rdata_text(input: &str) -> Cow<'_, str> {
    // The preprocessor flattens grouped lines but leaves the parentheses.
    if input.contains(['(', ')']) {
        let mut text = String::with_capacity(input.len());
        let mut quoted = false;
        let mut escaped = false;
        for character in input.chars() {
            if escaped {
                text.push(character);
                escaped = false;
                continue;
            }
            match character {
                '\\' => escaped = true,
                '"' => quoted = !quoted,
                '(' | ')' if !quoted => {
                    text.push(' ');
                    continue;
                }
                _ => {}
            }
            text.push(character);
        }
        Cow::Owned(text)
    } else {
        Cow::Borrowed(input)
    }
}

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
            [mx_rdata(mx)] => Resource::MX(mx),
        ))
    }

    fn mx_rdata(input: Node<'_>) -> Result<UnresolvedMx> {
        let text = rdata_text(input.as_str());
        let fields = crate::from_str::parse_mx(&text).map_err(|error| input.error(error))?;
        Ok(UnresolvedMx {
            preference: fields.preference,
            exchange: fields.exchange.to_owned(),
        })
    }

    #[alias(resource)]
    fn resource_srv(input: Node<'_>) -> Result<Resource> {
        Ok(match_nodes!(input.into_children();
            [srv_rdata(srv)] => Resource::SRV(srv),
        ))
    }

    fn srv_rdata(input: Node<'_>) -> Result<UnresolvedSrv> {
        let text = rdata_text(input.as_str());
        let fields = crate::from_str::parse_srv(&text).map_err(|error| input.error(error))?;
        Ok(UnresolvedSrv {
            priority: fields.priority,
            weight: fields.weight,
            port: fields.port,
            name: fields.name.to_owned(),
        })
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
            [soa_rdata(soa)] => Resource::SOA(soa),
        ))
    }

    fn soa_rdata(input: Node<'_>) -> Result<UnresolvedSoa> {
        let text = rdata_text(input.as_str());
        let fields = crate::from_str::parse_soa(&text).map_err(|error| input.error(error))?;
        Ok(UnresolvedSoa {
            mname: fields.mname.to_owned(),
            rname: fields.rname.to_owned(),
            serial: fields.serial,
            refresh: fields.refresh,
            retry: fields.retry,
            expire: fields.expire,
            minimum: fields.minimum,
        })
    }

    #[alias(resource)]
    fn resource_ds(input: Node<'_>) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_ds);

        Ok(match_nodes!(input.into_children();
            [ds_rdata(ds)] => Resource::DS(ds),
        ))
    }

    fn ds_rdata(input: Node<'_>) -> Result<crate::DS> {
        rdata_text(input.as_str()).parse().map_err(|error| input.error(error))
    }

    #[alias(resource)]
    fn resource_dnskey(input: Node<'_>) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_dnskey);

        Ok(match_nodes!(input.into_children();
            [dnskey_rdata(dnskey)] => Resource::DNSKEY(dnskey),
        ))
    }

    fn dnskey_rdata(input: Node<'_>) -> Result<crate::DNSKEY> {
        rdata_text(input.as_str()).parse().map_err(|error| input.error(error))
    }

    #[alias(resource)]
    fn resource_rrsig(input: Node<'_>) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_rrsig);

        Ok(match_nodes!(input.into_children();
            [rrsig_rdata(rrsig)] => Resource::RRSIG(rrsig),
        ))
    }

    fn rrsig_rdata(input: Node<'_>) -> Result<UnresolvedRrsig> {
        let text = rdata_text(input.as_str());
        let fields = crate::from_str::parse_rrsig(&text).map_err(|error| input.error(error))?;
        Ok(UnresolvedRrsig {
            type_covered: fields.type_covered,
            algorithm: fields.algorithm,
            labels: fields.labels,
            original_ttl: fields.original_ttl,
            expiration: fields.expiration,
            inception: fields.inception,
            key_tag: fields.key_tag,
            signer_name: fields.signer_name.to_owned(),
            signature: fields.signature,
        })
    }

    #[alias(resource)]
    fn resource_nsec(input: Node<'_>) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_nsec);

        Ok(match_nodes!(input.into_children();
            [nsec_rdata(nsec)] => Resource::NSEC(nsec),
        ))
    }

    fn nsec_rdata(input: Node<'_>) -> Result<UnresolvedNsec> {
        let text = rdata_text(input.as_str());
        let fields = crate::from_str::parse_nsec(&text).map_err(|error| input.error(error))?;
        Ok(UnresolvedNsec {
            next_domain: fields.next_domain.to_owned(),
            types: fields.types,
        })
    }

    #[alias(resource)]
    fn resource_zonemd(input: Node<'_>) -> Result<Resource> {
        assert_eq!(input.as_rule(), Rule::resource_zonemd);

        Ok(match_nodes!(input.into_children();
            [zonemd_rdata(zonemd)] => Resource::ZONEMD(zonemd),
        ))
    }

    fn zonemd_rdata(input: Node<'_>) -> Result<crate::ZONEMD> {
        rdata_text(input.as_str()).parse().map_err(|error| input.error(error))
    }

    #[alias(resource)]
    fn resource_txt(input: Node<'_>) -> Result<Resource> {
        Ok(match_nodes!(input.into_children();
            [txt_rdata(txt)] => Resource::TXT(txt),
        ))
    }

    #[alias(resource)]
    fn resource_spf(input: Node<'_>) -> Result<Resource> {
        Ok(match_nodes!(input.into_children();
            [txt_rdata(txt)] => Resource::SPF(txt),
        ))
    }

    fn txt_rdata(input: Node<'_>) -> Result<crate::TXT> {
        let txt = crate::from_str::parse_zone_txt(&rdata_text(input.as_str()))
            .map_err(|error| input.error(error))?;
        if txt.0.iter().any(|string| string.len() > usize::from(u8::MAX)) {
            return Err(input.error("TXT/SPF character-string exceeds 255 octets"));
        }
        Ok(txt)
    }

    #[alias(resource)]
    fn resource_nsec3(input: Node<'_>) -> Result<Resource> {
        Ok(match_nodes!(input.into_children();
            [nsec3_rdata(nsec3)] => Resource::NSEC3(nsec3),
        ))
    }

    fn nsec3_rdata(input: Node<'_>) -> Result<crate::NSEC3> {
        rdata_text(input.as_str()).parse().map_err(|error| input.error(error))
    }

    #[alias(resource)]
    fn resource_nsec3param(input: Node<'_>) -> Result<Resource> {
        Ok(match_nodes!(input.into_children();
            [nsec3param_rdata(parameters)] => Resource::NSEC3PARAM(parameters),
        ))
    }

    fn nsec3param_rdata(input: Node<'_>) -> Result<crate::NSEC3PARAM> {
        rdata_text(input.as_str()).parse().map_err(|error| input.error(error))
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

                    // Intentionally preserved as a raw String (not Name). In zone files,
                    // domain names may be relative (e.g. "www"), "@", or inherit from previous
                    // records. They must not be turned into a canonical FQDN `Name` until
                    // resolved against $ORIGIN in `File::try_into_records`.
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
