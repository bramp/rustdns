/// TODO Add comments
///
/// TODO https://github.com/Badcow/DNS-Parser has a nice custom format extension. Perhaps include?
use crate::resource::*;
use crate::Class;
use crate::Resource;
use pest::error::Error;
use pest::error::ErrorVariant;

use pest::Parser;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::result;
use std::str::FromStr;
use std::time::Duration;

extern crate pest;

/// Internal struct for capturing each row.
#[derive(Debug, PartialEq)]
pub enum Row<'a> {
    Origin(String),
    Ttl(Duration),
    // TODO support $INCLUDE
    Record(Record<'a>),
    EmptyLine(),
}

/// Very similar to a [`rustdns::Record`] but allows for
/// optional values. When parsing a full zone file
/// those options can be derived from previous rows.
#[derive(Debug, PartialEq)]
pub struct Record<'a> {
    name: Option<&'a str>,
    ttl: Option<Duration>,
    class: Option<Class>,
    resource: Resource,
}

#[derive(Parser)]
#[grammar = "zones/zones.pest"]
pub struct ZoneParser;

use pest::iterators::Pair;

type Result<T> = result::Result<T, Error<Rule>>;

fn error(pair: Pair<Rule>, message: String) -> Error<Rule> {
    Error::new_from_span(ErrorVariant::CustomError { message }, pair.as_span())
}

fn parse_ipv4(pair: Pair<Rule>) -> Result<Ipv4Addr> {
    assert_eq!(
        pair.as_rule(),
        Rule::ip4,
        "expected ipv4 got '{}'",
        pair.as_str()
    );

    match Ipv4Addr::from_str(pair.as_str()) {
        Ok(ip4) => Ok(ip4),
        Err(e) => Err(error(pair, e.to_string())),
    }
}

fn parse_ipv6(pair: Pair<Rule>) -> Result<Ipv6Addr> {
    assert_eq!(
        pair.as_rule(),
        Rule::ip6,
        "expected ipv6 got '{}'",
        pair.as_str()
    );

    match Ipv6Addr::from_str(pair.as_str()) {
        Ok(ip6) => Ok(ip6),
        Err(e) => Err(error(pair, e.to_string())),
    }
}

fn parse_duration(pair: Pair<Rule>) -> Result<Duration> {
    assert_eq!(pair.as_rule(), Rule::duration); // TODO will we eventually match other rules?

    // TODO Support more complex duration types (e.g "1d")
    match pair.as_str().parse() {
        Ok(i) => Ok(Duration::new(i, 0)),
        Err(e) => Err(error(pair, e.to_string())),
    }
}

fn parse_number<T: std::str::FromStr>(pair: Pair<Rule>) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    assert_eq!(pair.as_rule(), Rule::number);

    match pair.as_str().parse() {
        Ok(i) => Ok(i),
        Err(e) => Err(error(pair, e.to_string())),
    }
}

fn parse_string(pair: Pair<Rule>) -> Result<String> {
    assert_eq!(pair.as_rule(), Rule::string);

    Ok(pair.as_str().to_string())
}

fn parse_domain(pair: Pair<Rule>) -> Result<String> {
    assert_eq!(
        pair.as_rule(),
        Rule::domain,
        "expected domain got '{}'",
        pair.as_str()
    );

    // TODO Should I do some validation?
    Ok(pair.as_str().to_string())
}

fn parse_resource(pair: Pair<Rule>) -> Result<Resource> {
    assert_eq!(pair.as_rule(), Rule::resource);

    let mut inner = pair.into_inner();
    let pair = inner.next().expect("one pair");
    assert_eq!(inner.next(), None);

    // Now parse the specific resource_xxxx rule.
    let rule = pair.as_rule();
    let mut inner = pair.into_inner();

    let resource = match rule {
        Rule::resource_a => Resource::A(parse_ipv4(inner.next().expect("one argument"))?),
        Rule::resource_aaaa => Resource::AAAA(parse_ipv6(inner.next().expect("one argument"))?),
        Rule::resource_ns => Resource::NS(parse_domain(inner.next().expect("one argument"))?),
        Rule::resource_mx => Resource::MX(MX {
            preference: parse_number(inner.next().expect("one argument"))?,
            exchange: parse_domain(inner.next().expect("two argument"))?,
        }),
        Rule::resource_soa => Resource::SOA(SOA {
            mname: parse_domain(inner.next().expect("one argument"))?,

            /// The mailbox of the person responsible for this zone.
            // TODO Convert this to a email address https://datatracker.ietf.org/doc/html/rfc1035#section-8
            rname: parse_string(inner.next().expect("two argument"))?,

            serial: parse_number(inner.next().expect("three argument"))?,
            refresh: parse_duration(inner.next().expect("four argument"))?,
            retry: parse_duration(inner.next().expect("five argument"))?,
            expire: parse_duration(inner.next().expect("six argument"))?,
            minimum: parse_duration(inner.next().expect("seven argument"))?,
        }),

        _ => unreachable!("Unexpected resource: {:?}", rule), // TODO
    };

    // The parser should not have provided any more tokens.
    assert_eq!(inner.next(), None);

    Ok(resource)
}

fn parse_record(pair: Pair<Rule>) -> Result<Record> {
    assert_eq!(pair.as_rule(), Rule::record);

    let pairs = pair.into_inner();

    let mut r = Record {
        name: None,
        ttl: None,
        class: None,
        resource: Resource::ANY,
    };

    for pair in pairs {
        match pair.as_rule() {
            Rule::domain => r.name = Some(pair.as_str()),
            Rule::duration => r.ttl = Some(parse_duration(pair)?),
            Rule::class => r.class = Some(pair.as_str().parse().unwrap()), // TODO
            Rule::resource => r.resource = parse_resource(pair)?,

            _ => unreachable!("Unexpected record: {:?}", pair.as_str()),
        }
    }

    Ok(r)
}

fn parse_row(pair: Pair<Rule>) -> Result<Row> {
    match pair.as_rule() {
        Rule::origin => Ok(Row::Origin(parse_domain(
            pair.into_inner().next().expect("one domain argument"),
        )?)),
        Rule::ttl => Ok(Row::Ttl(parse_duration(
            pair.into_inner().next().expect("one duration argument"),
        )?)),
        Rule::record => Ok(Row::Record(parse_record(pair)?)),

        _ => unreachable!("Unexpected rule: {:?}", pair.as_rule()), // TODO
    }
}

// TODO Change to return a full zone file.
pub fn parse(input: &str) -> Result<Row> {
    let row = ZoneParser::parse(Rule::row, input)?.next().unwrap();
    //println!("{:?}", row);

    // TODO Loop

    parse_row(row.into_inner().next().expect("atleast one row"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_parse_combinations() {
        let tests = vec![
            // All the different combinations of domain/duration/class, with a ambigious domain name (A).
            (
                "A       A       26.3.0.103",
                Row::Record(Record {
                    name: Some("A"),
                    ttl: None,
                    class: None,
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                }),
            ),
            (
                "A       IN       A       26.3.0.103",
                Row::Record(Record {
                    name: Some("A"),
                    ttl: None,
                    class: Some(Class::Internet),
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                }),
            ),
            (
                "A       1       A       26.3.0.103",
                Row::Record(Record {
                    name: Some("A"),
                    ttl: Some(Duration::new(1, 0)),
                    class: None,
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                }),
            ),
            (
                "A       IN       1       A       26.3.0.103",
                Row::Record(Record {
                    name: Some("A"),
                    ttl: Some(Duration::new(1, 0)),
                    class: Some(Class::Internet),
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                }),
            ),
            (
                "A       1       IN       A       26.3.0.103",
                Row::Record(Record {
                    name: Some("A"),
                    ttl: Some(Duration::new(1, 0)),
                    class: Some(Class::Internet),
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                }),
            ),
            (
                // Now without the domain
                "A       26.3.0.103",
                Row::Record(Record {
                    name: None,
                    ttl: None,
                    class: None,
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                }),
            ),

            (
                "IN       A       26.3.0.103",
                Row::Record(Record {
                    name: None, // TODO It thinks IN is the name
                    ttl: None,
                    class: Some(Class::Internet),
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                }),
            ),
            /* TODO FIX
            (
                "1       A       26.3.0.103",
                Row::Record(Record {
                    name: None, // TODO It thinks 1 is the name
                    ttl: Some(Duration::new(1, 0)),
                    class: None,
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                }),
            ),
            (
                "IN       1       A       26.3.0.103",
                Row::Record(Record {
                    name: None, // TODO It thinks IN is the name
                    ttl: Some(Duration::new(1, 0)),
                    class: Some(Class::Internet),
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                }),
            ),
            (
                "1       IN       A       26.3.0.103",
                Row::Record(Record {
                    name: None, // TODO It thinks 1 is the name
                    ttl: Some(Duration::new(1, 0)),
                    class: Some(Class::Internet),
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                }),
            ),
            */
        ];

        for (input, want) in tests {
            match parse(input) {
                Ok(got) => assert_eq!(got, want, "incorrect result for '{}'", input),
                Err(err) => panic!("'{}' failed:\n{}", input, err),
            }
        }
    }

    #[test]
    fn test_parse_row() {
        let tests = vec![
            // All the different record types.
            (
                "A       A       26.3.0.103",
                Row::Record(Record {
                    name: Some("A"),
                    ttl: None,
                    class: None,
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                }),
            ),
            (
                "VENERA  A       10.1.0.52",
                Row::Record(Record {
                    name: Some("VENERA"),
                    ttl: None,
                    class: None,
                    resource: Resource::A("10.1.0.52".parse().unwrap()),
                }),
            ),
            (
                "        A       128.9.0.32",
                Row::Record(Record {
                    name: None,
                    ttl: None,
                    class: None,
                    resource: Resource::A("128.9.0.32".parse().unwrap()),
                }),
            ),
            (
                "        NS      VAXA",
                Row::Record(Record {
                    name: None,
                    ttl: None,
                    class: None,
                    resource: Resource::NS("VAXA".to_string()),
                }),
            ),
            (
                "        MX      20      VAXA",
                Row::Record(Record {
                    name: None,
                    ttl: None,
                    class: None,
                    resource: Resource::MX(MX {
                        preference: 20,
                        exchange: "VAXA".to_string(),
                    }),
                }),
            ),
            (
                "        AAAA    2400:cb00:2049:1::a29f:1804",
                Row::Record(Record {
                    name: None,
                    ttl: None,
                    class: None,
                    resource: Resource::AAAA("2400:cb00:2049:1::a29f:1804".parse().unwrap()),
                }),
            ),
            (
                "@   IN  SOA     VENERA      Action\\.domains 20 7200 600 3600000 60",
                Row::Record(Record {
                    name: Some("@"),
                    ttl: None,
                    class: Some(Class::Internet),
                    resource: Resource::SOA(SOA {
                        mname: "VENERA".to_string(),
                        rname: "Action\\.domains".to_string(), // TODO Fix the \\ thing
                        serial: 20,
                        refresh: Duration::new(7200, 0),
                        retry: Duration::new(600, 0),
                        expire: Duration::new(3600000, 0),
                        minimum: Duration::new(60, 0),
                    }),
                }),
            ),
            // The other Row types
            (
                "$ORIGIN example.org.",
                Row::Origin("example.org.".to_string()),
            ),
            ("$TTL 3600", Row::Ttl(Duration::new(3600, 0))),
        ];

        for (input, want) in tests {
            match parse(input) {
                Ok(got) => assert_eq!(got, want),
                Err(err) => panic!("'{}' ailed:\n{}", input, err),
            }
        }

        // TODO add some bad data examples
        // "$ORIGIN @"
        // "$TTL blah"
    }

    // TODO Take test from https://datatracker.ietf.org/doc/html/rfc2308#section-10

    // Test Full files
    #[test]
    #[ignore] // TODO Re-enable
    fn test_parse() {
        let tests = vec![
            // Examples from https://www.nlnetlabs.nl/documentation/nsd/grammar-for-dns-zone-files/
            "$ORIGIN example.org.
            SOA    soa    soa    ( 1 2 3 4 5 6 )",

            "$ORIGIN example.org.
            SOA    soa    soa    ( 1 2 ) ( 3 4 ) ( 5 ) ( 6 )",

            // Examples from https://datatracker.ietf.org/doc/html/rfc1035#section-5.3
            "$ORIGIN ISI.EDU.
            @   IN  SOA     VENERA      Action\\.domains (
                                             20     ; SERIAL
                                             7200   ; REFRESH
                                             600    ; RETRY
                                             3600000; EXPIRE
                                             60)    ; MINIMUM

                    NS      A.ISI.EDU.
                    NS      VENERA
                    NS      VAXA
                    MX      10      VENERA
                    MX      20      VAXA

            A       A       26.3.0.103

            VENERA  A       10.1.0.52
                    A       128.9.0.32

            VAXA    A       10.2.0.27
                    A       128.9.0.33
            ",

            // Examples from https://en.wikipedia.org/wiki/Zone_file
            "
            $ORIGIN example.com.     ; designates the start of this zone file in the namespace
            $TTL 3600                ; default expiration time (in seconds) of all RRs without their own TTL value
            example.com.  IN  SOA   ns.example.com. username.example.com. ( 2020091025 7200 3600 1209600 3600 )
            example.com.  IN  NS    ns                    ; ns.example.com is a nameserver for example.com
            example.com.  IN  NS    ns.somewhere.example. ; ns.somewhere.example is a backup nameserver for example.com
            example.com.  IN  MX    10 mail.example.com.  ; mail.example.com is the mailserver for example.com
            @             IN  MX    20 mail2.example.com. ; equivalent to above line, '@' represents zone origin
            @             IN  MX    50 mail3              ; equivalent to above line, but using a relative host name
            example.com.  IN  A     192.0.2.1             ; IPv4 address for example.com
                          IN  AAAA  2001:db8:10::1        ; IPv6 address for example.com
            ns            IN  A     192.0.2.2             ; IPv4 address for ns.example.com
                          IN  AAAA  2001:db8:10::2        ; IPv6 address for ns.example.com
            www           IN  CNAME example.com.          ; www.example.com is an alias for example.com
            wwwtest       IN  CNAME www                   ; wwwtest.example.com is another alias for www.example.com
            mail          IN  A     192.0.2.3             ; IPv4 address for mail.example.com
            mail2         IN  A     192.0.2.4             ; IPv4 address for mail2.example.com
            mail3         IN  A     192.0.2.5             ; IPv4 address for mail3.example.com
        "];

        for input in tests {
            match parse(input) {
                Ok(_got) => todo!("add the want"), //assert_eq!(got, want),
                Err(err) => panic!("'{}' ailed:\n{}", input, err),
            }
        }
    }
}
