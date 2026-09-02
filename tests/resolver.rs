#[cfg(test)]
#[cfg(feature = "udp")]
mod tests {
    use pretty_assertions::assert_eq;
    use rustdns::clients::Exchanger;
    use rustdns::clients::Resolver;
    use rustdns::types::*;
    use rustdns::Message;
    use rustdns::Record;
    use rustdns::Resource;
    use std::net::IpAddr;
    use std::time::Duration;

    struct MockClient {}

    impl Exchanger for MockClient {
        /// Returns mock DNS answers for test records.
        fn exchange(&self, query: &Message) -> Result<Message, rustdns::Error> {
            let mut resp = Message::default();
            resp.rcode = Rcode::NoError;

            for question in &query.questions {
                match (question.name.trim_end_matches('.'), question.r#type) {
                    ("a.bramp.net", Type::A) => {
                        resp.answers.push(Record {
                            name: question.name.clone(),
                            class: Class::Internet,
                            ttl: Duration::from_secs(10),
                            resource: Resource::A("127.0.0.1".parse().unwrap()),
                        });
                    }
                    ("aaaa.bramp.net", Type::AAAA) => {
                        resp.answers.push(Record {
                            name: question.name.clone(),
                            class: Class::Internet,
                            ttl: Duration::from_secs(10),
                            resource: Resource::AAAA("::1".parse().unwrap()),
                        });
                    }
                    ("aaaaa.bramp.net", Type::A) => {
                        resp.answers.push(Record {
                            name: question.name.clone(),
                            class: Class::Internet,
                            ttl: Duration::from_secs(10),
                            resource: Resource::A("127.0.0.1".parse().unwrap()),
                        });
                    }
                    ("aaaaa.bramp.net", Type::AAAA) => {
                        resp.answers.push(Record {
                            name: question.name.clone(),
                            class: Class::Internet,
                            ttl: Duration::from_secs(10),
                            resource: Resource::AAAA("::1".parse().unwrap()),
                        });
                    }
                    ("cname.bramp.net", Type::A) => {
                        resp.answers.push(Record {
                            name: question.name.clone(),
                            class: Class::Internet,
                            ttl: Duration::from_secs(10),
                            resource: Resource::A("127.0.0.1".parse().unwrap()),
                        });
                    }
                    _ => {}
                }
            }

            Ok(resp)
        }
    }

    #[test]
    fn test_resolver() {
        struct TestCase<'a> {
            name: &'a str,
            want: Vec<&'a str>,
        }

        let tests = vec![
            TestCase {
                name: "a.bramp.net",
                want: vec!["127.0.0.1"],
            },
            TestCase {
                name: "aaaa.bramp.net",
                want: vec!["::1"],
            },
            TestCase {
                name: "aaaaa.bramp.net",
                want: vec!["::1", "127.0.0.1"],
            },
            TestCase {
                name: "cname.bramp.net",
                want: vec!["127.0.0.1"],
            },
        ];

        let resolver = Resolver::new_with_client(MockClient {});

        for test in tests {
            let mut want: Vec<IpAddr> = test
                .want
                .iter()
                .map(|x| x.parse().expect("invalid test input"))
                .collect();
            let mut got = resolver.lookup(test.name).expect("failed to lookup");

            // Sort because ::1 and 127.0.0.1 may switch places.
            want.sort();
            got.sort();

            assert_eq!(got, want, "when resolving {}", test.name);
        }
    }
}