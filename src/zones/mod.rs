/// TODO Document
// TODO https://github.com/Badcow/DNS-Parser has a nice custom format extension. Perhaps include?
use crate::Class;
use crate::Resource;
use std::time::Duration;
use strum_macros::Display;

mod parser;
mod preprocessor;

pub use self::parser::parse;
pub use self::parser::parse_record;

extern crate pest;

/// Internal struct for capturing each entry.
#[derive(Debug, Display, PartialEq)]
pub enum Entry {
    Origin(String),
    Ttl(Duration),
    // TODO support $INCLUDE
    Record(Record),
}

/// Very similar to a [`rustdns::Record`] but allows for
/// optional values. When parsing a full zone file
/// those options can be derived from previous entries.
// TODO Implement a Display to turn this back into Zone format.
#[derive(Debug, PartialEq)]
pub struct Record {
    pub name: Option<String>,
    pub ttl: Option<Duration>,
    pub class: Option<Class>,
    pub resource: Resource,
}

impl Default for Record {
    fn default() -> Self {
        Self {
            name: None,
            ttl: None,
            class: None,
            resource: Resource::ANY, // This is not really a good default, but it's atleast invalid.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::*;
    use crate::zones::parser::parse;
    use crate::zones::parser::parse_record;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_parse_combinations() {
        let tests = vec![
            // All the different combinations of domain/duration/class, with a ambigious domain name (A).
            (
                "A       A       26.3.0.103",
                Record {
                    name: Some("A".to_string()),
                    ttl: None,
                    class: None,
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                },
            ),
            (
                "A       IN       A       26.3.0.103",
                Record {
                    name: Some("A".to_string()),
                    ttl: None,
                    class: Some(Class::Internet),
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                },
            ),
            (
                "A       1       A       26.3.0.103",
                Record {
                    name: Some("A".to_string()),
                    ttl: Some(Duration::new(1, 0)),
                    class: None,
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                },
            ),
            (
                "A       IN       1       A       26.3.0.103",
                Record {
                    name: Some("A".to_string()),
                    ttl: Some(Duration::new(1, 0)),
                    class: Some(Class::Internet),
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                },
            ),
            (
                "A       1       IN       A       26.3.0.103",
                Record {
                    name: Some("A".to_string()),
                    ttl: Some(Duration::new(1, 0)),
                    class: Some(Class::Internet),
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                },
            ),
            (
                // Now without the domain
                "A       26.3.0.103",
                Record {
                    name: None,
                    ttl: None,
                    class: None,
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                },
            ),
            (
                "IN       A       26.3.0.103",
                Record {
                    name: None, // TODO It thinks IN is the name
                    ttl: None,
                    class: Some(Class::Internet),
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                },
            ),
            (
                "1       A       26.3.0.103",
                Record {
                    name: None, // TODO It thinks 1 is the name
                    ttl: Some(Duration::new(1, 0)),
                    class: None,
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                },
            ),
            (
                "IN       1       A       26.3.0.103",
                Record {
                    name: None,
                    ttl: Some(Duration::new(1, 0)),
                    class: Some(Class::Internet),
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                },
            ),
            (
                "1       IN       A       26.3.0.103",
                Record {
                    name: None, // TODO It thinks 1 is the name
                    ttl: Some(Duration::new(1, 0)),
                    class: Some(Class::Internet),
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                },
            ),
        ];

        for (input, want) in tests {
            match parse_record(input) {
                Ok(got) => assert_eq!(got, want, "incorrect result for '{}'", input),
                Err(err) => panic!("'{}' Failed:\n{}", input, err),
            }
        }
    }

    #[test]
    fn test_parse_record() {
        let tests = vec![
            (
                "A       A       26.3.0.103",
                Record {
                    name: Some("A".to_string()),
                    ttl: None,
                    class: None,
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                },
            ),
            (
                "VENERA  A       10.1.0.52",
                Record {
                    name: Some("VENERA".to_string()),
                    ttl: None,
                    class: None,
                    resource: Resource::A("10.1.0.52".parse().unwrap()),
                },
            ),
            // All the different record types.
            (
                "A       128.9.0.32",
                Record {
                    name: None,
                    ttl: None,
                    class: None,
                    resource: Resource::A("128.9.0.32".parse().unwrap()),
                },
            ),
            (
                "AAAA    2400:cb00:2049:1::a29f:1804",
                Record {
                    name: None,
                    ttl: None,
                    class: None,
                    resource: Resource::AAAA("2400:cb00:2049:1::a29f:1804".parse().unwrap()),
                },
            ),
            (
                "CNAME example.com",
                Record {
                    name: None,
                    ttl: None,
                    class: None,
                    resource: Resource::CNAME("example.com".to_string()),
                },
            ),
            (
                "NS      VAXA",
                Record {
                    name: None,
                    ttl: None,
                    class: None,
                    resource: Resource::NS("VAXA".to_string()),
                },
            ),
            (
                "NS      A.ISI.EDU.",
                Record {
                    name: None,
                    ttl: None,
                    class: None,
                    resource: Resource::NS("A.ISI.EDU.".to_string()),
                },
            ),
            (
                "MX      20      VAXA",
                Record {
                    name: None,
                    ttl: None,
                    class: None,
                    resource: Resource::MX(MX {
                        preference: 20,
                        exchange: "VAXA".to_string(),
                    }),
                },
            ),
            (
                "@   IN  SOA     VENERA      Action\\.domains 20 7200 600 3600000 60",
                Record {
                    name: Some("@".to_string()),
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
                },
            ),
            // Whitespace examples
            (
                "   VENERA A 10.1.0.52",
                Record {
                    name: Some("VENERA".to_string()),
                    ttl: None,
                    class: None,
                    resource: Resource::A("10.1.0.52".parse().unwrap()),
                },
            ),
            (
                "VENERA A 10.1.0.52   ",
                Record {
                    name: Some("VENERA".to_string()),
                    ttl: None,
                    class: None,
                    resource: Resource::A("10.1.0.52".parse().unwrap()),
                },
            ),
            (
                "   VENERA A 10.1.0.52   ",
                Record {
                    name: Some("VENERA".to_string()),
                    ttl: None,
                    class: None,
                    resource: Resource::A("10.1.0.52".parse().unwrap()),
                },
            ),
            // Comments
            (
                "VENERA A 10.1.0.52;Blah",
                Record {
                    name: Some("VENERA".to_string()),
                    ttl: None,
                    class: None,
                    resource: Resource::A("10.1.0.52".parse().unwrap()),
                },
            ),
        ];

        for (input, want) in tests {
            match parse_record(input) {
                Ok(got) => assert_eq!(got, want),
                Err(err) => panic!("'{}' Failed:\n{}", input, err),
            }
        }
    }

    #[test]
    fn test_parse_record_errors() {
        let tests = vec![
            // We don't allow blank entries
            "",
            // For sinle records, we don't allow new lines
            "VENERA A 10.1.0.52\n",
            "\nVENERA A 10.1.0.52\n",
        ];

        for input in tests {
            match parse_record(input) {
                Ok(_got) => panic!("'{}' incorrectly parsed correctly", input),
                Err(_err) => (), // Expect a error. TODO Maybe check the error message,
            }
        }
    }

    // TODO Take test from https://datatracker.ietf.org/doc/html/rfc2308#section-10

    // Test Full files
    #[test]
    fn test_parse() {
        // TODO add some bad data examples
        // "$ORIGIN @"
        // "$TTL blah"

        let tests = vec![
            // The control entry types
            ("$ORIGIN 1.example.org.", vec![Entry::Origin("1.example.org.".to_string())]),
            ("$TTL 3600", vec![Entry::Ttl(Duration::new(3600, 0))]),

            // Wrapped with newlines
            ("\n\n$ORIGIN 2.example.org.\n", vec![Entry::Origin("2.example.org.".to_string())]),

            // Wrapped with various whitespace
            ("\n \t \n \t \n \t $ORIGIN 3.example.org.  \n \t \n \t \n  ", vec![Entry::Origin("3.example.org.".to_string())]),

            // TODO Include

            // Examples modified from https://nsd.docs.nlnetlabs.nl/en/latest/reference/grammar.html
            ("SOA    soa    soa    ( 1 2 3 4 5 )",
                vec![
                    Entry::Record(Record {
                        resource: Resource::SOA(SOA {
                            mname: "soa".to_string(),
                            rname: "soa".to_string(),
                            serial: 1,
                            refresh: Duration::new(2, 0),
                            retry: Duration::new(3, 0),
                            expire: Duration::new(4, 0),
                            minimum: Duration::new(5, 0),
                        }),
                        ..Default::default()
                    }),
                ]),

            ("SOA    soa    soa    ( 1 2 ) ( 3 4 ) ( 5 )",
                vec![
                    Entry::Record(Record {
                        resource: Resource::SOA(SOA {
                            mname: "soa".to_string(),
                            rname: "soa".to_string(), // TODO Fix the \\ thing
                            serial: 1,
                            refresh: Duration::new(2, 0),
                            retry: Duration::new(3, 0),
                            expire: Duration::new(4, 0),
                            minimum: Duration::new(5, 0),
                        }),
                        ..Default::default()
                    }),
                ]),

            // Compact together
            ("SOA soa soa (1 2)(3 4)(5)",
                vec![
                    Entry::Record(Record {
                        resource: Resource::SOA(SOA {
                            mname: "soa".to_string(),
                            rname: "soa".to_string(), // TODO Fix the \\ thing
                            serial: 1,
                            refresh: Duration::new(2, 0),
                            retry: Duration::new(3, 0),
                            expire: Duration::new(4, 0),
                            minimum: Duration::new(5, 0),
                        }),
                        ..Default::default()
                    }),
                ]),

            (
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
            ", vec![
                Entry::Origin("ISI.EDU.".to_string()),
                Entry::Record(Record {
                    name: Some("@".to_string()),
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
                Entry::Record(Record {
                    resource: Resource::NS("A.ISI.EDU.".to_string()),
                    ..Default::default()
                }),
                Entry::Record(Record {
                    resource: Resource::NS("VENERA".to_string()),
                    ..Default::default()
                }),
                Entry::Record(Record {
                    resource: Resource::NS("VAXA".to_string()),
                    ..Default::default()
                }),
                Entry::Record(Record {
                    resource: Resource::MX(MX{
                        preference: 10,
                        exchange: "VENERA".to_string()
                    }),
                    ..Default::default()
                }),
                Entry::Record(Record {
                    resource: Resource::MX(MX{
                        preference: 20,
                        exchange: "VAXA".to_string(),
                    }),
                    ..Default::default()
                }),
                Entry::Record(Record {
                    name: Some("A".to_string()),
                    resource: Resource::A("26.3.0.103".parse().unwrap()),
                    ..Default::default()
                }),
                Entry::Record(Record {
                    name: Some("VENERA".to_string()),
                    resource: Resource::A("10.1.0.52".parse().unwrap()),
                    ..Default::default()
                }),
                Entry::Record(Record {
                    resource: Resource::A("128.9.0.32".parse().unwrap()),
                    ..Default::default()
                }),
                Entry::Record(Record {
                    name: Some("VAXA".to_string()),
                    resource: Resource::A("10.2.0.27".parse().unwrap()),
                    ..Default::default()
                }),
                Entry::Record(Record {
                    resource: Resource::A("128.9.0.33".parse().unwrap()),
                    ..Default::default()
                }),
            ]),

            // Examples from https://en.wikipedia.org/wiki/Zone_file
            ("
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
        ", vec![
    Entry::Origin(
        "example.com.".to_string(),
    ),
    Entry::Ttl(
        Duration::new(3600, 0),
    ),
    Entry::Record(Record {
            name: Some(
                "example.com.".to_string(),
            ),
            ttl: None,
            class: Some(
                Class::Internet,
            ),
            resource: Resource::SOA(
                SOA {
                    mname: "ns.example.com.".to_string(),
                    rname: "username.example.com.".to_string(),
                    serial: 2020091025,
                    refresh: Duration::new(7200, 0),
                    retry: Duration::new(3600, 0),
                    expire: Duration::new(1209600, 0),
                    minimum: Duration::new(3600, 0),
                },
            ),
        },
    ),
    Entry::Record(Record {
            name: Some(
                "example.com.".to_string(),
            ),
            ttl: None,
            class: Some(
                Class::Internet,
            ),
            resource: Resource::NS(
                "ns".to_string(),
            ),
        },
    ),
    Entry::Record(Record {
            name: Some(
                "example.com.".to_string(),
            ),
            ttl: None,
            class: Some(
                Class::Internet,
            ),
            resource: Resource::NS(
                "ns.somewhere.example.".to_string(),
            ),
        },
    ),
    Entry::Record(Record {
            name: Some(
                "example.com.".to_string(),
            ),
            ttl: None,
            class: Some(
                Class::Internet,
            ),
            resource: Resource::MX(
                MX {
                    preference: 10,
                    exchange: "mail.example.com.".to_string(),
                },
            ),
        },
    ),
    Entry::Record(Record {
            name: Some(
                "@".to_string(),
            ),
            ttl: None,
            class: Some(
                Class::Internet,
            ),
            resource: Resource::MX(
                MX {
                    preference: 20,
                    exchange: "mail2.example.com.".to_string(),
                },
            ),
        },
    ),
    Entry::Record(Record {
            name: Some(
                "@".to_string(),
            ),
            ttl: None,
            class: Some(
                Class::Internet,
            ),
            resource: Resource::MX(
                MX {
                    preference: 50,
                    exchange: "mail3".to_string(),
                },
            ),
        },
    ),
    Entry::Record(Record {
            name: Some(
                "example.com.".to_string(),
            ),
            ttl: None,
            class: Some(
                Class::Internet,
            ),
            resource: Resource::A(
                "192.0.2.1".parse().unwrap(),
            ),
        },
    ),
    Entry::Record(Record {
            name: None,
            ttl: None,
            class: Some(
                Class::Internet,
            ),
            resource: Resource::AAAA(
                "2001:db8:10::1".parse().unwrap(),
            ),
        },
    ),
    Entry::Record(Record {
            name: Some(
                "ns".to_string(),
            ),
            ttl: None,
            class: Some(
                Class::Internet,
            ),
            resource: Resource::A(
                "192.0.2.2".parse().unwrap(),
            ),
        },
    ),
    Entry::Record(Record {
            name: None,
            ttl: None,
            class: Some(
                Class::Internet,
            ),
            resource: Resource::AAAA(
                "2001:db8:10::2".parse().unwrap(),
            ),
        },
    ),
    Entry::Record(Record {
            name: Some(
                "www".to_string(),
            ),
            ttl: None,
            class: Some(
                Class::Internet,
            ),
            resource: Resource::CNAME(
                "example.com.".to_string(),
            ),
        },
    ),
    Entry::Record(Record {
            name: Some(
                "wwwtest".to_string(),
            ),
            ttl: None,
            class: Some(
                Class::Internet,
            ),
            resource: Resource::CNAME(
                "www".to_string(),
            ),
        },
    ),
    Entry::Record(Record {
            name: Some(
                "mail".to_string(),
            ),
            ttl: None,
            class: Some(
                Class::Internet,
            ),
            resource: Resource::A(
                "192.0.2.3".parse().unwrap(),
            ),
        },
    ),
    Entry::Record(Record {
            name: Some(
                "mail2".to_string(),
            ),
            ttl: None,
            class: Some(
                Class::Internet,
            ),
            resource: Resource::A(
                "192.0.2.4".parse().unwrap(),
            ),
        },
    ),
    Entry::Record(Record {
            name: Some(
                "mail3".to_string(),
            ),
            ttl: None,
            class: Some(
                Class::Internet,
            ),
            resource: Resource::A(
                "192.0.2.5".parse().unwrap(),
            ),
        },
    ),
]),

        ];

        for (input, want) in tests {
            match parse(input) {
                Ok(got) => assert_eq!(got, want),
                Err(err) => panic!("{} Failed:\n{}", input, err),
            }
        }
    }
}
