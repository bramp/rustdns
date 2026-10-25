// Quite a lot of tests, so moved them to a seperate file.

#[cfg(test)]
mod tests {
    use crate::resource::{DNSKEY, DS, ZONEMD};
    use crate::zones::{
        Entry, File, Record, Resource, UnresolvedMx as MX, UnresolvedNsec as NSEC,
        UnresolvedRrsig as RRSIG, UnresolvedSoa as SOA,
    };
    use crate::Class;
    use core::time::Duration;
    use pretty_assertions::assert_eq;
    use std::str::FromStr;
    use std::time::UNIX_EPOCH;

    #[test]
    fn checked_in_fixture_covers_all_supported_zone_record_types() {
        let records = include_str!("fixtures/records.zone")
            .parse::<File>().unwrap().try_into_records().unwrap();
        assert_eq!(records.len(), 21);
        let actual: std::collections::BTreeSet<_> =
            records.iter().map(|record| record.resource.r#type()).collect();
        let expected = [
            crate::Type::A, crate::Type::AAAA, crate::Type::CNAME, crate::Type::PTR,
            crate::Type::NS, crate::Type::MX, crate::Type::SRV, crate::Type::SOA,
            crate::Type::DS, crate::Type::DNSKEY, crate::Type::RRSIG, crate::Type::NSEC,
            crate::Type::ZONEMD, crate::Type::TXT, crate::Type::SPF,
            crate::Type::NSEC3, crate::Type::NSEC3PARAM,
        ].into_iter().collect();
        assert_eq!(actual, expected);
        for record in &records {
            let resource = &record.resource;
            assert_eq!(
                crate::Resource::parse_text(resource.r#type(), &resource.to_string()).unwrap(),
                *resource,
            );
        }
        let message = crate::Message { answers: records, ..Default::default() };
        let encoded = message.to_vec().unwrap();
        assert_eq!(crate::Message::from_slice(&encoded).unwrap(), message);
    }

    #[test]
    fn txt_and_spf_preserve_character_strings_and_punctuation() {
        for (rdata, expected) in [
            (r#""v=spf1 " "ip4:192.0.2.0/24 -all""#,
                vec![b"v=spf1 ".to_vec(), b"ip4:192.0.2.0/24 -all".to_vec()]),
            (r#"("semi;colon (literal)" ; ignored )
                "quote: \" slash: \\ bytes: \000\255")"#,
                vec![b"semi;colon (literal)".to_vec(), b"quote: \" slash: \\ bytes: \0\xff".to_vec()]),
            (r#"hello\ world semi\;colon \(literal\) \065"#,
                vec![b"hello world".to_vec(), b"semi;colon".to_vec(), b"(literal)".to_vec(), b"A".to_vec()]),
            (r#""""#, vec![Vec::new()]),
            (r#""(" ")" "\;" "\(""#, vec![b"(".to_vec(), b")".to_vec(), b";".to_vec(), b"(".to_vec()]),
            ("(\"caf\u{e9};(\"\r\n\"second\")", vec!["caf\u{e9};(".as_bytes().to_vec(), b"second".to_vec()]),
        ] {
            for kind in [crate::Type::TXT, crate::Type::SPF] {
                let line = format!("owner IN {kind} {rdata}");
                let record: Record = line.parse().unwrap();
                let expected_resource = match kind {
                    crate::Type::TXT => Resource::TXT(crate::TXT(expected.clone())),
                    crate::Type::SPF => Resource::SPF(crate::TXT(expected.clone())),
                    _ => unreachable!(),
                };
                assert_eq!(record.resource, expected_resource, "{line}");
                let file: File = format!("$ORIGIN example.\n$TTL 300\n{line}").parse().unwrap();
                assert_eq!(file.entries[2], Entry::Record(record), "{line}");
            }
        }
    }

    #[test]
    fn new_record_types_preserve_owner_type_ambiguity_and_inheritance() {
        for line in [
            r#"TXT TXT "value""#, r#"SPF SPF "value""#,
            "NSEC3 NSEC3 1 0 0 - 00", "NSEC3PARAM NSEC3PARAM 1 0 0 -",
        ] {
            let record: Record = line.parse().unwrap();
            assert_eq!(record.name.as_deref(), line.split_whitespace().next());
            let file: File = format!("$ORIGIN example.\n$TTL 300\n{line}\n IN TXT \"inherited\"")
                .parse().unwrap();
            let records = file.try_into_records().unwrap();
            assert_eq!(records[0].name, records[1].name);
        }
    }

    #[test]
    fn new_zone_records_reject_malformed_input() {
        for line in [
            "@ TXT", "@ SPF", "@ NSEC3", "@ NSEC3PARAM",
            r#"@ TXT "unterminated"#, r#"@ TXT "bad\12""#,
            r#"@ TXT "bad\256""#, "@ TXT trailing\\",
            r#"@ TXT ("unclosed""#, r#"@ TXT "extra")"#,
            "@ NSEC3 1 0 0 - W0", "@ NSEC3 1 0 0 - 0", "@ NSEC3 1 0 0 - 01",
            "@ NSEC3 1 0 0 - 00 NOTATYPE", "@ NSEC3 1 0 0 - 00 TYPE65536",
            "@ NSEC3 1 256 0 - 00", "@ NSEC3 256 0 0 - 00",
            "@ NSEC3 1 0 65536 - 00", "@ NSEC3 1 0 0 abc 00",
            "@ NSEC3PARAM 1 0 0 abc", "@ NSEC3PARAM 1 0 0 - extra",
            "@ NSEC3PARAM 1 0 65536 -",
        ] {
            assert!(line.parse::<Record>().is_err(), "{line}");
            assert!(format!("$ORIGIN example.\n{line}").parse::<File>().is_err(), "{line}");
        }
        for kind in ["TXT", "SPF"] {
            for length in [255, 256] {
                let line = format!("@ {kind} \"{}\"", "x".repeat(length));
                assert_eq!(line.parse::<Record>().is_ok(), length == 255, "{length}");
            }
        }
    }

    #[test]
    fn unresolved_payloads_are_core_record_specializations() {
        for line in [
            "@ MX 10 mail",
            "@ SRV 1 2 389 ldap",
            "@ SOA ns admin 1 2 3 4 5",
            "@ RRSIG A 8 2 300 2000000000 1900000000 12345 signer AQID",
            "@ NSEC next A AAAA",
        ] {
            let record: Record = line.parse().unwrap();
            match record.resource {
                Resource::MX(value) => {
                    let _: crate::resource::Mx<String> = value;
                }
                Resource::SRV(value) => {
                    let _: crate::resource::Srv<String> = value;
                }
                Resource::SOA(value) => {
                    let _: crate::resource::Soa<String, String> = value;
                }
                Resource::RRSIG(value) => {
                    let _: crate::resource::Rrsig<String> = value;
                }
                Resource::NSEC(value) => {
                    let _: crate::resource::Nsec<String> = value;
                }
                _ => panic!("unexpected resource"),
            }
        }
    }

    #[test]
    fn shared_rdata_zone_and_text_parsing_agree() {
        for (kind, rdata) in [
            (crate::Type::MX, "65535 mail.example."),
            (crate::Type::SRV, "65535 65535 65535 ldap.example."),
            (crate::Type::DS, "65535 255 255 aabb ccdd"),
            (crate::Type::DNSKEY, "65535 255 255 AQ ID"),
            (
                crate::Type::RRSIG,
                "A 255 255 3600 20300101000000 20200101000000 65535 example. AQ ID",
            ),
            (crate::Type::NSEC, "next.example. A NS SOA MX RRSIG NSEC DNSKEY"),
            (crate::Type::NSEC, "next.example."),
            (crate::Type::ZONEMD, "4294967295 255 255 aabb ccdd"),
        ] {
            let expected = crate::Resource::parse_text(kind, rdata).unwrap();
            for grouped in [false, true] {
                let rdata = if grouped {
                    format!("(\n{rdata} ; grouped RDATA\n)")
                } else {
                    rdata.to_owned()
                };
                let input = format!(
                    "$TTL 300\nexample. IN {kind} {rdata} ; record\nnext.example. A 192.0.2.1"
                );
                let records = input.parse::<File>().unwrap().try_into_records().unwrap();
                assert_eq!(records.len(), 2, "{input}");
                assert_eq!(records[0].resource, expected, "{input}");
            }
        }
    }

    #[test]
    fn unresolved_resources_preserve_relative_names_and_own_them() {
        for (kind, relative, absolute) in [
            (crate::Type::MX, "10 mail", "10 mail.example."),
            (crate::Type::SRV, "5 10 389 ldap", "5 10 389 ldap.example."),
            (
                crate::Type::RRSIG,
                "A 8 2 3600 2000000000 1900000000 12345 @ AQID",
                "A 8 2 3600 2000000000 1900000000 12345 example. AQID",
            ),
            (crate::Type::NSEC, "next A AAAA", "next.example. A AAAA"),
        ] {
            let file = {
                let input = format!("$ORIGIN example.\n$TTL 300\n@ {kind} {relative}");
                input.parse::<File>().unwrap()
            };
            let Entry::Record(record) = &file.entries[2] else {
                panic!("expected record");
            };
            match &record.resource {
                Resource::MX(mx) => assert_eq!(mx.exchange, "mail"),
                Resource::SRV(srv) => assert_eq!(srv.name, "ldap"),
                Resource::RRSIG(rrsig) => assert_eq!(rrsig.signer_name, "@"),
                Resource::NSEC(nsec) => assert_eq!(nsec.next_domain, "next"),
                _ => panic!("unexpected resource"),
            }
            let records = file.try_into_records().unwrap();
            assert_eq!(
                records[0].resource,
                crate::Resource::parse_text(kind, absolute).unwrap()
            );
        }
    }

    #[test]
    fn shared_rdata_rejects_malformed_values_in_both_entry_points() {
        for (kind, rdata) in [
            (crate::Type::MX, "65536 mail.example."),
            (crate::Type::SRV, "0 0 65536 ldap.example."),
            (crate::Type::DS, "12345 256 2 aabb"),
            (crate::Type::DS, "12345 8 2 abc"),
            (crate::Type::DNSKEY, "257 256 8 AQID"),
            (crate::Type::DNSKEY, "257 3 8 A"),
            (
                crate::Type::RRSIG,
                "A 8 256 3600 20300101000000 20200101000000 12345 example. AQID",
            ),
            (
                crate::Type::RRSIG,
                "A 8 2 3600 18446744073709551615 1 12345 example. AQID",
            ),
            (crate::Type::NSEC, "next.example. A INVALID AAAA"),
            (crate::Type::ZONEMD, "1 256 1 aabb"),
        ] {
            assert!(
                crate::Resource::parse_text(kind, rdata).is_err(),
                "{kind} {rdata}"
            );
            let input = format!("example. {kind} {rdata}");
            assert!(input.parse::<Record>().is_err(), "{input}");
            assert!(input.parse::<File>().is_err(), "{input}");
        }
    }

    #[test]
    fn shared_rdata_record_type_owner_names_remain_unambiguous() {
        for line in [
            "MX MX 10 mail.example.",
            "SRV SRV 1 2 389 ldap.example.",
            "DS DS 12345 8 2 aabb",
            "DNSKEY DNSKEY 257 3 8 AQID",
            "RRSIG RRSIG A 8 2 3600 2000000000 1900000000 12345 example. AQID",
            "NSEC NSEC next.example. A",
            "ZONEMD ZONEMD 1 1 1 aabb",
        ] {
            let record: Record = line.parse().unwrap();
            assert_eq!(record.name.as_deref(), line.split_whitespace().next());
        }
    }

    #[test]
    #[allow(deprecated)]
    fn unresolved_resource_aliases_remain_compatible() {
        let mx: crate::zones::MX = crate::zones::MX {
            preference: 10,
            exchange: "mail".to_owned(),
        };
        let _: crate::zones::UnresolvedMx = mx;
        let srv: crate::zones::SRV = crate::zones::SRV {
            priority: 1,
            weight: 2,
            port: 389,
            name: "ldap".to_owned(),
        };
        let _: crate::zones::UnresolvedSrv = srv;
        let nsec: crate::zones::NSEC = crate::zones::NSEC {
            next_domain: "next".to_owned(),
            types: vec![crate::Type::A],
        };
        let _: crate::zones::UnresolvedNsec = nsec;
        let rrsig: crate::zones::RRSIG = crate::zones::RRSIG {
            type_covered: crate::Type::A,
            algorithm: crate::Algorithm::RSASHA256,
            labels: 2,
            original_ttl: Duration::from_secs(300),
            expiration: UNIX_EPOCH + Duration::from_secs(2000000000),
            inception: UNIX_EPOCH + Duration::from_secs(1900000000),
            key_tag: 12345,
            signer_name: "@".to_owned(),
            signature: vec![1, 2, 3],
        };
        let _: crate::zones::UnresolvedRrsig = rrsig;
    }

    #[test]
    #[allow(deprecated)]
    fn soa_compatibility_alias_accepts_owned_unresolved_fields() {
        let old: crate::zones::SOA = crate::zones::SOA {
            mname: "ns1".to_owned(),
            rname: "dns-admin".to_owned(),
            serial: 376337657,
            refresh: Duration::from_secs(900),
            retry: Duration::from_secs(900),
            expire: Duration::from_secs(1800),
            minimum: Duration::from_secs(60),
        };
        let unresolved: crate::zones::UnresolvedSoa = old;
        let parsed: Record = "@ SOA ns1 dns-admin 376337657 900 900 1800 60"
            .parse()
            .unwrap();
        assert_eq!(parsed.resource, Resource::SOA(unresolved));
    }

    #[test]
    fn soa_zone_and_text_parsing_agree() {
        for rdata in [
            "ns1.google.com. dns-admin.google.com. 376337657 900 900 1800 60",
            r"ns.ISI.EDU. Action\.domains.ISI.EDU. 1 2 3 4 5",
            ". . 4294967295 18446744073709551615 0 0 0",
        ] {
            let core: crate::SOA = rdata.parse().unwrap();
            let input = format!("$TTL 300\nexample.com. IN SOA {rdata}\nnext.example.com. A 192.0.2.1");
            let records = input.parse::<File>().unwrap().try_into_records().unwrap();
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].resource, crate::Resource::SOA(core));
            assert_eq!(
                records[1].resource,
                crate::Resource::A("192.0.2.1".parse().unwrap())
            );
        }
    }

    #[test]
    fn soa_zone_record_owns_names_after_input_is_dropped() {
        let record = {
            let input = String::from("@ SOA ns1 dns-admin 376337657 900 900 1800 60");
            input.parse::<Record>().unwrap()
        };
        let Resource::SOA(soa) = record.resource else {
            panic!("expected SOA data");
        };
        assert_eq!(soa.mname, "ns1");
        assert_eq!(soa.rname, "dns-admin");
        assert_eq!(soa.serial, 376337657);
    }

    #[test]
    fn soa_zone_preserves_relative_names_and_origin_aliases() {
        for (mname, rname) in [("ns1", "dns-admin"), ("@", "@")] {
            let input = format!(
                "$ORIGIN google.com.\n$TTL 900\n@ IN SOA {mname} {rname} 376337657 900 900 1800 60"
            );
            let file: File = input.parse().unwrap();
            let Entry::Record(record) = &file.entries[2] else {
                panic!("expected SOA record");
            };
            let Resource::SOA(soa) = &record.resource else {
                panic!("expected SOA data");
            };
            assert_eq!(soa.mname, mname);
            assert_eq!(soa.rname, rname);

            let resolved = file.try_into_records().unwrap();
            let expected = if mname == "@" {
                "google.com. google.com. 376337657 900 900 1800 60"
            } else {
                "ns1.google.com. dns-admin.google.com. 376337657 900 900 1800 60"
            };
            assert_eq!(
                resolved[0].resource,
                crate::Resource::SOA(expected.parse().unwrap())
            );
        }
    }

    #[test]
    fn soa_zone_grouping_and_comments_preserve_shared_fields() {
        let input = "$ORIGIN google.com.\n$TTL 900\n\
            @ IN SOA ns1 dns-admin (\n\
                376337657 ; serial\n\
                900       ; refresh\n\
                900       ; retry\n\
                1800      ; expire\n\
                60)       ; minimum\n";
        let records = input.parse::<File>().unwrap().try_into_records().unwrap();
        let expected = "ns1.google.com. dns-admin.google.com. 376337657 900 900 1800 60";
        assert_eq!(
            records[0].resource,
            crate::Resource::SOA(expected.parse().unwrap())
        );

        let single: Record = "@ SOA ns1 dns-admin (376337657 900 900 1800 60) ; comment"
            .parse()
            .unwrap();
        let Resource::SOA(soa) = single.resource else {
            panic!("expected SOA data");
        };
        assert_eq!(soa.mname, "ns1");
        assert_eq!(soa.minimum, Duration::from_secs(60));
    }

    #[test]
    fn soa_zone_and_text_reject_malformed_fields() {
        for rdata in [
            "",
            "ns.example. admin.example. 1 2 3 4",
            "ns.example. admin.example. 1 2 3 4 5 extra",
            "ns.example. admin.example. -1 2 3 4 5",
            "ns.example. admin.example. 4294967296 2 3 4 5",
            "ns.example. admin.example. 1 18446744073709551616 3 4 5",
            "ns.example. admin.example. 1 2 nope 4 5",
        ] {
            assert!(rdata.parse::<crate::SOA>().is_err(), "{rdata:?}");
            let single = format!("example. SOA {rdata}");
            assert!(single.parse::<Record>().is_err(), "{rdata:?}");
            assert!(single.parse::<File>().is_err(), "{rdata:?}");
        }

        let input = "$TTL 900\nexample. SOA ns.example. admin.example. 4294967296 2 3 4 5";
        let error = input.parse::<File>().unwrap_err();
        assert!(
            matches!(error.line_col, pest::error::LineColLocation::Span((2, _), _)),
            "{error}"
        );
        assert!(error.to_string().contains("4294967296"), "{error}");
    }

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
            match Record::from_str(input) {
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
            // DNSSEC records
            (
                "aaa. 86400 IN DS 31852 8 2 89F7670AFC091B199B47900E4CE4135B9463B7F74D3D19A1C732E78C345D4DE6",
                Record {
                    name: Some("aaa.".to_string()),
                    ttl: Some(Duration::from_secs(86400)),
                    class: Some(Class::Internet),
                    resource: Resource::DS(DS {
                        key_tag: 31852,
                        algorithm: crate::types::Algorithm::RSASHA256,
                        digest_type: crate::types::DigestType::Sha256,
                        digest: crate::util::hex_decode("89F7670AFC091B199B47900E4CE4135B9463B7F74D3D19A1C732E78C345D4DE6").unwrap(),
                    }),
                },
            ),
            (
                ". 172800 IN DNSKEY 256 3 8 AwEAAeCYD6Z7",
                Record {
                    name: Some(".".to_string()),
                    ttl: Some(Duration::from_secs(172800)),
                    class: Some(Class::Internet),
                    resource: Resource::DNSKEY(DNSKEY {
                        flags: 256,
                        protocol: 3,
                        algorithm: crate::types::Algorithm::RSASHA256,
                        public_key: crate::util::base64_decode("AwEAAeCYD6Z7").unwrap(),
                    }),
                },
            ),
            (
                ". 86400 IN RRSIG SOA 8 0 86400 20260920050000 20260907040000 57780 . XfzAJ3WNy9rp+A==",
                Record {
                    name: Some(".".to_string()),
                    ttl: Some(Duration::from_secs(86400)),
                    class: Some(Class::Internet),
                    resource: Resource::RRSIG(RRSIG {
                        type_covered: crate::Type::SOA,
                        algorithm: crate::types::Algorithm::RSASHA256,
                        labels: 0,
                        original_ttl: Duration::from_secs(86400),
                        expiration: UNIX_EPOCH + Duration::from_secs(1789880400), // 2026-09-20 05:00:00 UTC
                        inception: UNIX_EPOCH + Duration::from_secs(1788753600),  // 2026-09-07 04:00:00 UTC
                        key_tag: 57780,
                        signer_name: ".".to_string(),
                        signature: crate::util::base64_decode("XfzAJ3WNy9rp+A==").unwrap(),
                    }),
                },
            ),
            (
                ". 86400 IN NSEC aaa. NS SOA RRSIG NSEC DNSKEY ZONEMD",
                Record {
                    name: Some(".".to_string()),
                    ttl: Some(Duration::from_secs(86400)),
                    class: Some(Class::Internet),
                    resource: Resource::NSEC(NSEC {
                        next_domain: "aaa.".to_string(),
                        types: vec![
                            crate::Type::NS,
                            crate::Type::SOA,
                            crate::Type::RRSIG,
                            crate::Type::NSEC,
                            crate::Type::DNSKEY,
                            crate::Type::ZONEMD,
                        ],
                    }),
                },
            ),
            (
                ". 86400 IN ZONEMD 2026090700 1 1 465D6F58F8298D0227",
                Record {
                    name: Some(".".to_string()),
                    ttl: Some(Duration::from_secs(86400)),
                    class: Some(Class::Internet),
                    resource: Resource::ZONEMD(ZONEMD {
                        serial: 2026090700,
                        scheme: 1,
                        algorithm: 1,
                        digest: crate::util::hex_decode("465D6F58F8298D0227").unwrap(),
                    }),
                },
            ),
        ];

        for (input, want) in tests {
            match Record::from_str(input) {
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
            match Record::from_str(input) {
                Ok(_got) => panic!("'{}' incorrectly parsed correctly", input),
                Err(_err) => (), // Expect a error. TODO Maybe check the error message,
            }
        }
    }

    #[test]
    fn test_parse_file_errors() {
        let tests = vec![
            "invalid record syntax that cannot parse",
            "$ORIGIN",
            "$ORIGIN relative_domain",
            "$TTL",
            "$TTL not_a_number",
        ];

        for input in tests {
            assert!(
                File::from_str(input).is_err(),
                "expected error for '{}'",
                input
            );
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
            ("$TTL 3600", vec![Entry::TTL(Duration::new(3600, 0))]),

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
                        exchange: "VENERA".to_string(),
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
            mail3         IN  A     192.0.2.5             ; IPv4 address for mail3.example.com",
            vec![
                Entry::Origin("example.com.".to_string()),
                Entry::TTL(Duration::new(3600, 0)),
                Entry::Record(Record {
                        name: Some("example.com.".to_string(),),
                        ttl: None,
                        class: Some(Class::Internet,),
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
                        name: Some("example.com.".to_string(),),
                        ttl: None,
                        class: Some(Class::Internet,),
                        resource: Resource::NS(
                            "ns".to_string(),
                        ),
                    },
                ),
                Entry::Record(Record {
                        name: Some("example.com.".to_string(),),
                        ttl: None,
                        class: Some(Class::Internet,),
                        resource: Resource::NS(
                            "ns.somewhere.example.".to_string(),
                        ),
                    },
                ),
                Entry::Record(Record {
                        name: Some("example.com.".to_string(),),
                        ttl: None,
                        class: Some(Class::Internet,),
                        resource: Resource::MX(
                            MX {
                                preference: 10,
                                exchange: "mail.example.com.".to_string(),
                            },
                        ),
                    },
                ),
                Entry::Record(Record {
                        name: Some("@".to_string(),),
                        ttl: None,
                        class: Some(Class::Internet,),
                        resource: Resource::MX(
                            MX {
                                preference: 20,
                                exchange: "mail2.example.com.".to_string(),
                            },
                        ),
                    },
                ),
                Entry::Record(Record {
                        name: Some("@".to_string(),),
                        ttl: None,
                        class: Some(Class::Internet,),
                        resource: Resource::MX(
                            MX {
                                preference: 50,
                                exchange: "mail3".to_string(),
                            },
                        ),
                    },
                ),
                Entry::Record(Record {
                        name: Some("example.com.".to_string(),),
                        ttl: None,
                        class: Some(Class::Internet,),
                        resource: Resource::A(
                            "192.0.2.1".parse().unwrap(),
                        ),
                    },
                ),
                Entry::Record(Record {
                        name: None,
                        ttl: None,
                        class: Some(Class::Internet,),
                        resource: Resource::AAAA(
                            "2001:db8:10::1".parse().unwrap(),
                        ),
                    },
                ),
                Entry::Record(Record {
                        name: Some("ns".to_string(),),
                        ttl: None,
                        class: Some(Class::Internet,),
                        resource: Resource::A(
                            "192.0.2.2".parse().unwrap(),
                        ),
                    },
                ),
                Entry::Record(Record {
                        name: None,
                        ttl: None,
                        class: Some(Class::Internet,),
                        resource: Resource::AAAA(
                            "2001:db8:10::2".parse().unwrap(),
                        ),
                    },
                ),
                Entry::Record(Record {
                        name: Some("www".to_string(),),
                        ttl: None,
                        class: Some(Class::Internet,),
                        resource: Resource::CNAME(
                            "example.com.".to_string(),
                        ),
                    },
                ),
                Entry::Record(Record {
                        name: Some("wwwtest".to_string(),),
                        ttl: None,
                        class: Some(Class::Internet,),
                        resource: Resource::CNAME(
                            "www".to_string(),
                        ),
                    },
                ),
                Entry::Record(Record {
                        name: Some("mail".to_string(),),
                        ttl: None,
                        class: Some(Class::Internet,),
                        resource: Resource::A(
                            "192.0.2.3".parse().unwrap(),
                        ),
                    },
                ),
                Entry::Record(Record {
                        name: Some("mail2".to_string(),),
                        ttl: None,
                        class: Some(Class::Internet,),
                        resource: Resource::A(
                            "192.0.2.4".parse().unwrap(),
                        ),
                    },
                ),
                Entry::Record(Record {
                        name: Some("mail3".to_string(),),
                        ttl: None,
                        class: Some(Class::Internet,),
                        resource: Resource::A(
                            "192.0.2.5".parse().unwrap(),
                        ),
                    },
                ),
            ]),

            ("$ORIGIN localhost.
            @  86400  IN  SOA   @  root (
                              1999010100 ; serial
                                   10800 ; refresh (3 hours)
                                     900 ; retry (15 minutes)
                                  604800 ; expire (1 week)
                                   86400 ; minimum (1 day)
                                )
            @  86400  IN  NS    @
            @  86400  IN  A     127.0.0.1
            @  86400  IN  AAAA  ::1", vec![
                Entry::Origin("localhost.".to_string()),
                Entry::Record(Record {
                        name: Some("@".to_string(),),
                        ttl: Some(Duration::new(86400, 0)),
                        class: Some(Class::Internet),
                        resource: Resource::SOA(
                            SOA {
                                mname: "@".to_string(),
                                rname: "root".to_string(),
                                serial: 1999010100,
                                refresh: Duration::new(10800, 0),
                                retry: Duration::new(900, 0),
                                expire: Duration::new(604800, 0),
                                minimum: Duration::new(86400, 0),
                            },
                        ),
                    },
                ),

                Entry::Record(Record {
                        name: Some("@".to_string(),),
                        ttl: Some(Duration::new(86400, 0)),
                        class: Some(Class::Internet),
                        resource: Resource::NS("@".to_string()),
                    },
                ),
                Entry::Record(Record {
                        name: Some("@".to_string(),),
                        ttl: Some(Duration::new(86400, 0)),
                        class: Some(Class::Internet),
                        resource: Resource::A("127.0.0.1".parse().unwrap()),
                    },
                ),
                Entry::Record(Record {
                        name: Some("@".to_string(),),
                        ttl: Some(Duration::new(86400, 0)),
                        class: Some(Class::Internet),
                        resource: Resource::AAAA("::1".parse().unwrap()),
                    },
                ),
                ]
            ),

            (";; reverse zone file for 127.0.0.1 and ::1
            $TTL 1814400 ; 3 weeks
            @  1814400  IN  SOA     localhost. root.localhost.  (
                                  1999010100 ; serial
                                       10800 ; refresh (3 hours)
                                         900 ; retry (15 minutes)
                                      604800 ; expire (1 week)
                                       86400 ; minimum (1 day)
                                    )
            @  1814400  IN  NS      localhost.
            1  1814400  IN  PTR     localhost.", vec![
                Entry::TTL(Duration::new(1814400, 0)),
                Entry::Record(Record {
                        name: Some("@".to_string(),),
                        ttl: Some(Duration::new(1814400, 0)),
                        class: Some(Class::Internet),
                        resource: Resource::SOA(
                            SOA {
                                mname: "localhost.".to_string(),
                                rname: "root.localhost.".to_string(),
                                serial: 1999010100,
                                refresh: Duration::new(10800, 0),
                                retry: Duration::new(900, 0),
                                expire: Duration::new(604800, 0),
                                minimum: Duration::new(86400, 0),
                            },
                        ),
                    },
                ),
                Entry::Record(Record {
                        name: Some("@".to_string()
                            ),
                        ttl: Some(Duration::new(1814400, 0)),
                        class: Some(Class::Internet),
                        resource: Resource::NS("localhost.".to_string()),
                    },
                ),
                Entry::Record(Record {
                        name: Some("1".to_string()),
                        ttl: Some(Duration::new(1814400, 0)),
                        class: Some(Class::Internet),
                        resource: Resource::PTR("localhost.".to_string()),
                    },
                ),
            ]),
        ];

        for (input, want) in tests {
            match File::from_str(input) {
                Ok(got) => assert_eq!(got.entries, want),
                Err(err) => panic!("{} Failed:\n{}", input, err),
            }
        }
    }
}
