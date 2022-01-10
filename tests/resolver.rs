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
        /// Sends the query [`Message`] to the `server` via UDP and returns the result.
        fn exchange(&self, _query: &Message) -> Result<Message, rustdns::Error> {
            //let mut records = HashMap::new();

            // TODO FINISH!
            let _a = Record {
                name: "a.bramp.net".to_string(),
                class: Class::Internet,
                ttl: Duration::new(10, 0),
                resource: Resource::A("127.0.0.1".parse().unwrap()),
            };

            /*
                    records.insert("aaaa.bramp.net", Resource::A("127.0.0.1".parse()));
                    records.insert("aaaaa.bramp.net", Resource::A("127.0.0.1".parse()));
                    records.insert("aaaaa.bramp.net", Resource::AAAA("::1".parse()));
            */

            panic!()
        }
    }

    // This test may be flakly, if it is running in an environment that doesn't
    // have both IPv4 and IPv6, and has DNS queries that can fail.
    // TODO Mock out the client.
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

        let resolver = Resolver::new();

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