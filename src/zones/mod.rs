use crate::resource::*;
use crate::Class;
use crate::Resource;

use nom::branch::alt;
use nom::branch::permutation;
use nom::bytes::complete::*;
use nom::character::complete::*;
use nom::combinator::success;

use nom::combinator::all_consuming;
use nom::combinator::{map, opt};
use nom::error::context;
use nom::error::ContextError;

use nom::error::ParseError;
use nom::error::VerboseError;

use nom::sequence::pair;
use nom::sequence::preceded;
use nom::sequence::terminated;
use nom::sequence::tuple;
use nom::IResult;

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::time::Duration;

/// Parse a IPv4 address, that is four octets in decimal notation, seperated by periods (“dot-decimal notation”).
#[allow(clippy::from_str_radix_10)] // It's actually cleaner, due to the lack of type information.
fn ipv4_addr<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    s: &'a str,
) -> IResult<&'a str, Ipv4Addr, E> {
    context(
        "IPv4 address",
        map(
            tuple((digit1, tag("."), digit1, tag("."), digit1, tag("."), digit1)),
            |t| {
                Ipv4Addr::new(
                    // TODO Remove the unwraps
                    u8::from_str_radix(t.0, 10).unwrap(),
                    u8::from_str_radix(t.2, 10).unwrap(),
                    u8::from_str_radix(t.4, 10).unwrap(),
                    u8::from_str_radix(t.6, 10).unwrap(),
                )
            },
        ),
    )(s)
}

// https://datatracker.ietf.org/doc/html/rfc3596#section-2.4
// https://datatracker.ietf.org/doc/html/rfc3513
fn ipv6_addr<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    s: &'a str,
) -> IResult<&'a str, Ipv6Addr, E> {
    context(
        "IPv6 address",
        map(
            take_while1(|c: char| c.is_ascii_hexdigit() || c == ':'),
            // Instead of parsing this myself, I used Ipv6Addr's parser
            // TODO Remove the unwraps
            |ip| Ipv6Addr::from_str(ip).unwrap(),
        ),
    )(s)
}

/// Consumes and discards the prefix, then returns the result of the parser.
pub fn prefixed<T, I, O, E: ParseError<I>, F>(t: T, f: F) -> impl FnMut(I) -> IResult<I, O, E>
where
    F: nom::Parser<I, O, E>,
    I: nom::InputTake + nom::InputTakeAtPosition + nom::Compare<T>,
    <I as nom::InputTakeAtPosition>::Item: nom::AsChar + Clone,
    T: nom::InputLength + Clone,
{
    preceded(pair(tag(t), space1), f)
}

/// Runs the parser and if successful returns the result a [`Option::Some`].
pub fn some<I: Clone, O, E: ParseError<I>, F>(mut f: F) -> impl FnMut(I) -> IResult<I, Option<O>, E>
where
    F: nom::Parser<I, O, E>,
{
    // Based on num::opt()
    move |input: I| match f.parse(input) {
        Ok((i, o)) => Ok((i, Some(o))),
        Err(e) => Err(e),
    }
}

/// Parses a domain name.
fn domain<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    s: &'a str,
) -> IResult<&'a str, &'a str, E> {
    // We could tighten up the defintion, but I don't
    // think it's important.
    context("Domain name", take_while1(|c| c != ' '))(s)
}

/// Parses a domain name, and one more whitespace.
fn domain1<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    s: &'a str,
) -> IResult<&'a str, &'a str, E> {
    terminated(domain, space1)(s)
}

/// Parses a [`Class`], and one more whitespace.
fn class1<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    s: &'a str,
) -> IResult<&'a str, Class, E> {
    context(
        "Class",
        map(
            terminated(alt((tag("IN"), tag("CS"), tag("CH"), tag("HS"))), space1),
            |class| {
                Class::from_str(class).unwrap() // TODO Remove unwrap
            },
        ),
    )(s)
}

/// Parses a TTL, and one more whitespace.
fn ttl1<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    s: &'a str,
) -> IResult<&'a str, Duration, E> {
    // TODO Bind supports different formats of TTL, such as "1d"
    context(
        "TTL",
        map(terminated(digit1, space1), |d: &'a str| {
            Duration::new(d.parse().unwrap(), 0) // TODO Remove the unwrap
        }),
    )(s)
}

/// Internal struct for capturing each row.
///
/// It is very similar to a [`Record`] but allows for
/// optional values. When parsing a full zone file
/// those options can be derived from previous rows.
#[derive(Debug, PartialEq)]
struct Row<'a> {
    name: Option<&'a str>,
    ttl: Option<Duration>,
    class: Option<Class>,
    resource: Resource,
}

fn mx_record<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    s: &'a str,
) -> IResult<&'a str, MX, E> {
    map(tuple((digit1, space1, domain)), |x| MX {
        preference: x.0.parse().unwrap(),
        exchange: x.2.to_string(),
    })(s)
}

/// Parses the type and specific resource data.
///
/// ```text
/// <type> <RDATA>
/// ```
fn parse_rr_data<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    s: &'a str,
) -> IResult<&'a str, Resource, E> {
    context(
        "Resource data",
        alt((
            // TODO Add other type
            prefixed("A", map(ipv4_addr, Resource::A)),
            prefixed("AAAA", map(ipv6_addr, Resource::AAAA)),
            prefixed("NS", map(domain, |x| Resource::NS(x.to_string()))),
            prefixed("CNAME", map(domain, |x| Resource::CNAME(x.to_string()))),
            prefixed("PTR", map(domain, |x| Resource::PTR(x.to_string()))),
            prefixed("MX", map(mx_record, Resource::MX)),
        )),
    )(s)
}

/// Parses a single row from the zone file.
///
/// ```text
/// <blank>[<comment>]
/// $ORIGIN <domain-name> [<comment>]
/// <domain-name><rr> [<comment>]
/// <blank><rr> [<comment>]
/// ```
///
/// Not supported:
/// ```text
/// $INCLUDE <file-name> [<domain-name>] [<comment>]
/// $TTL integer_value ; Sets the default value of TTL for following RRs in file (RFC2308, bind>8.1)
/// ```
///
/// <rr> contents take one of the following forms:
/// ```text
/// [<TTL>] [<class>] <type> <RDATA>
/// [<class>] [<TTL>] <type> <RDATA>
/// ```
/// See https://datatracker.ietf.org/doc/html/rfc1035#section-5
/// More examples: https://datatracker.ietf.org/doc/html/rfc2308#section-10
/// https://web.mit.edu/rhel-doc/5/RHEL-5-manual/Deployment_Guide-en-US/s1-bind-zone.html
fn parse_row<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    s: &'a str,
) -> IResult<&'a str, Row, E> {
    /*
        //let space0 = take_while(|c: char| c.is_whitespace());
        //let space1 = take_while1(|c: char| c.is_whitespace());
        //let not_space = take_while1(|c: char| !c.is_whitespace());

        // TODO Change this to parse across lines
        // TODO Change this to also support the () syntax.
        let (_input, fields) = preceded(
            &space0,
            //separated_list1(space1, map(not_space, |x| Token{t: String::from(x)} ))
            separated_list1(space1, not_space),
        )(s)?;
    */

    // TODO Check if the first field is a special field
    // TODO Make sure this is case insensitive (AAAA is the same as aaaa)

    // Nom is a greedy parser, and doesn't seem to back-track
    // when there is ambiguity. For example, the record:
    //
    //  <blank>   A   1.2.3.4
    //
    // It greedily consumes "A" thinking it is the domain name
    // which causes parsing to fail. To resolve this, we use
    // a table of `alt` paths, each one a different possible
    // combination.  This may not be the best, but it forces
    // Nom to backtrack to the `alt` and keep trying branches.
    // This also allows us to express how to resolve the ambiguity
    // based on the order of the list.
    //
    // The order is as such:
    //   domain, ttl, class    // permutation (of ttl and class)
    //   domain, ttl,
    //   domain,    , class
    //   domain,    ,
    //         , ttl, class    // permutation (of ttl and class)
    //         , ttl,
    //         ,    , class
    //         ,    ,

    all_consuming(preceded(
        space0,
        map(
            alt((
                tuple((some(domain1), permutation((some(ttl1), some(class1))), parse_rr_data)),
                tuple((some(domain1), pair(some(ttl1), success(None)), parse_rr_data)),
                tuple((
                    some(domain1),
                    pair(success(None), some(class1)),
                    parse_rr_data,
                )),
                tuple((
                    some(domain1),
                    pair(success(None), success(None)),
                    parse_rr_data,
                )),
                tuple((success(None), permutation((some(ttl1), some(class1))), parse_rr_data)),
                tuple((
                    success(None),
                    pair(some(ttl1), success(None)),
                    parse_rr_data,
                )),
                tuple((
                    success(None),
                    pair(success(None), some(class1)),
                    parse_rr_data,
                )),
                tuple((
                    success(None),
                    pair(success(None), success(None)),
                    parse_rr_data,
                )),
            )),
            |ret| {
                Row {
                    name: ret.0,
                    ttl : ret.1.0,
                    class : ret.1.1,
                    resource: ret.2,
                }
            },
        ),
    ))(s)
}

pub fn parse(s: &str) {
    // TODO do something with this.
    parse_row::<VerboseError<&str>>(s).unwrap(); // TODO
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::error::convert_error;
    use nom::Err;

    impl Row<'_> {
        fn new(
            name: Option<&str>,
            class: Option<Class>,
            ttl: Option<Duration>,
            resource: Resource,
        ) -> Row {
            Row {
                name,
                ttl,
                class,
                resource,
            }
        }
    }

    #[test]
    fn test() {
        let tests = vec![
            (
                "A       A       26.3.0.103",
                Row::new(
                    Some("A"),
                    None,
                    None,
                    Resource::A("26.3.0.103".parse().unwrap()),
                ),
            ),
            (
                "VENERA  A       10.1.0.52",
                Row::new(
                    Some("VENERA"),
                    None,
                    None,
                    Resource::A("10.1.0.52".parse().unwrap()),
                ),
            ),
            (
                "        A       128.9.0.32",
                Row::new(None, None, None, Resource::A("128.9.0.32".parse().unwrap())),
            ),
            (
                "        NS      VAXA",
                Row::new(None, None, None, Resource::NS("VAXA".to_string())),
            ),
            (
                "        MX      20      VAXA",
                Row::new(
                    None,
                    None,
                    None,
                    Resource::MX(MX {
                        preference: 20,
                        exchange: "VAXA".to_string(),
                    }),
                ),
            ),
            (
                "        AAAA    2400:cb00:2049:1::a29f:1804",
                Row::new(
                    None,
                    None,
                    None,
                    Resource::AAAA("2400:cb00:2049:1::a29f:1804".parse().unwrap()),
                ),
            ),
        ];

        for (input, want) in tests {
            let ret = parse_row::<VerboseError<&str>>(input);

            if ret.is_err() {
                // If there is a error print a nice set of debugging.
                println!("parsed verbose: {:#?}", ret);

                match ret {
                    Err(Err::Error(e)) | Err(Err::Failure(e)) => {
                        println!(
                            "verbose errors - `root::<VerboseError>(data)`:\n{}",
                            convert_error(input, e)
                        );
                    }
                    _ => {}
                }
                panic!("failed '{}'", input)
            }

            let (remaining, got) = ret.unwrap();
            assert_eq!(got, want);
            assert_eq!(remaining, "", "all input should have been consumed.");
        }

        /*
            // https://datatracker.ietf.org/doc/html/rfc1035#section-5.3
            //parse_record().unwrap();

        */
        // TODO add some bad data examples

        /*
        @   IN  SOA     VENERA      Action\.domains (
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
            */

        /*
        ; https://en.wikipedia.org/wiki/Zone_file
        $ORIGIN example.com.     ; designates the start of this zone file in the namespace
        $TTL 3600                ; default expiration time (in seconds) of all RRs without their own TTL value
        example.com.  IN  SOA   ns.example.com. username.example.com. ( 2020091025 7200 3600 1209600 3600 )
        example.com.  IN  NS    ns                    ; ns.example.com is a nameserver for example.com
        example.com.  IN  NS    ns.somewhere.example. ; ns.somewhere.example is a backup nameserver for example.com
        example.com.  IN  MX    10 mail.example.com.  ; mail.example.com is the mailserver for example.com
        @             IN  MX    20 mail2.example.com. ; equivalent to above line, "@" represents zone origin
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
        */

        panic!("blah");
    }
}
