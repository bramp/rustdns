#[cfg(test)]
#[cfg(feature = "resolver")]
mod tests {
    use async_trait::async_trait;
    use pretty_assertions::assert_eq;
    use rustdns::Message;
    use rustdns::Record;
    use rustdns::Resource;
    use rustdns::clients::{AsyncExchanger, AsyncResolver, Resolver, WireResponse};
    use rustdns::types::*;
    use std::net::IpAddr;
    use std::time::Duration;

    /// Returns a well-formed response echoing `query`'s single question, so it
    /// correlates. `answer`, if any, is added to the answer section.
    fn respond(query: &Message, answer: Option<Resource>) -> Message {
        let mut resp = Message {
            id: query.id,
            qr: QR::Response,
            rcode: Rcode::NoError,
            questions: query.questions.clone(),
            ..Default::default()
        };

        if let Some(resource) = answer {
            resp.answers.push(Record {
                name: query.questions[0].name.clone(),
                class: Class::Internet,
                ttl: Duration::from_secs(10),
                resource,
            });
        }

        resp
    }

    #[allow(dead_code)]
    struct MockClient {}

    #[async_trait]
    impl AsyncExchanger for MockClient {
        fn endpoint(&self) -> std::sync::Arc<str> {
            "mock".into()
        }

        /// Returns mock DNS answers for test records.
        async fn exchange(&self, query: &Message) -> Result<WireResponse, rustdns::Error> {
            let question = &query.questions[0];
            let answer = match (question.name.trim_end_matches('.'), question.r#type) {
                ("a.bramp.net", Type::A) => Some(Resource::A("127.0.0.1".parse().unwrap())),
                ("aaaa.bramp.net", Type::AAAA) => Some(Resource::AAAA("::1".parse().unwrap())),
                ("aaaaa.bramp.net", Type::A) => Some(Resource::A("127.0.0.1".parse().unwrap())),
                ("aaaaa.bramp.net", Type::AAAA) => Some(Resource::AAAA("::1".parse().unwrap())),
                ("cname.bramp.net", Type::A) => Some(Resource::A("127.0.0.1".parse().unwrap())),
                _ => None,
            };

            Ok(WireResponse::test(
                respond(query, answer),
                ChannelSecurity::Loopback,
            ))
        }
    }

    #[tokio::test]
    async fn test_resolver() {
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

        let resolver = Resolver::builder()
            .upstream(MockClient {})
            .build()
            .expect("valid resolver");

        for test in tests {
            let mut want: Vec<IpAddr> = test
                .want
                .iter()
                .map(|x| x.parse().expect("invalid test input"))
                .collect();
            let mut got = resolver.lookup(test.name).await.expect("failed to lookup");

            // Sort because ::1 and 127.0.0.1 may switch places.
            want.sort();
            got.sort();

            assert_eq!(got, want, "when resolving {}", test.name);
        }
    }

    /// An upstream that always fails, so the resolver must fail over.
    struct FailingClient;

    #[async_trait]
    impl AsyncExchanger for FailingClient {
        fn endpoint(&self) -> std::sync::Arc<str> {
            "failing".into()
        }

        async fn exchange(&self, _query: &Message) -> Result<WireResponse, rustdns::Error> {
            Err(std::io::Error::other("simulated transport failure").into())
        }
    }

    /// An upstream that always answers with a fixed `rcode`.
    struct RcodeClient(Rcode);

    #[async_trait]
    impl AsyncExchanger for RcodeClient {
        fn endpoint(&self) -> std::sync::Arc<str> {
            "rcode".into()
        }

        async fn exchange(&self, query: &Message) -> Result<WireResponse, rustdns::Error> {
            let mut resp = respond(query, None);
            resp.rcode = self.0;
            Ok(WireResponse::test(resp, ChannelSecurity::Loopback))
        }
    }

    #[tokio::test]
    async fn failover_tries_the_next_upstream_after_a_transport_error() {
        let resolver = Resolver::builder()
            .upstream(FailingClient)
            .upstream(MockClient {})
            .retries(0)
            .build()
            .expect("valid resolver");

        let got = resolver
            .lookup("a.bramp.net")
            .await
            .expect("failed to lookup");
        assert_eq!(got, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn servfail_fails_over_to_the_next_upstream() {
        let resolver = Resolver::builder()
            .upstream(RcodeClient(Rcode::ServFail))
            .upstream(MockClient {})
            .retries(0)
            .build()
            .expect("valid resolver");

        let got = resolver
            .lookup("a.bramp.net")
            .await
            .expect("failed to lookup");
        assert_eq!(got, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn nxdomain_is_definitive_and_is_not_retried() {
        let mut query = Message::default();
        query
            .try_add_question("nx.bramp.net", Type::A, Class::Internet)
            .expect("valid question");

        let resolver = Resolver::builder()
            .upstream(RcodeClient(Rcode::NXDomain))
            // Would error if the resolver kept trying upstreams after a definitive rcode.
            .upstream(FailingClient)
            .retries(0)
            .build()
            .expect("valid resolver");

        let response = resolver.exchange(&query).await.expect("exchange succeeds");
        assert_eq!(response.message.rcode, Rcode::NXDomain);
        assert_eq!(&*response.meta.upstream, "rcode");
    }

    #[tokio::test]
    async fn retry_exhaustion_returns_an_error() {
        let resolver = Resolver::builder()
            .upstream(FailingClient)
            .retries(0)
            .timeout(Duration::from_secs(2))
            .build()
            .expect("valid resolver");

        let result = resolver.lookup("a.bramp.net").await;
        assert!(result.is_err());
    }

    /// Simulates a transport with its own internal timeout: it waits, then
    /// reports failure itself, rather than the resolver timing it out.
    struct TransportOwnedTimeoutClient(Duration);

    #[async_trait]
    impl AsyncExchanger for TransportOwnedTimeoutClient {
        fn endpoint(&self) -> std::sync::Arc<str> {
            "timeout".into()
        }

        async fn exchange(&self, _query: &Message) -> Result<WireResponse, rustdns::Error> {
            tokio::time::sleep(self.0).await;
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "transport's own timeout fired",
            )
            .into())
        }
    }

    #[tokio::test]
    async fn failover_proceeds_once_a_transports_own_timeout_fires() {
        let resolver = Resolver::builder()
            .upstream(TransportOwnedTimeoutClient(Duration::from_millis(20)))
            .upstream(MockClient {})
            .retries(0)
            .timeout(Duration::from_secs(5))
            .build()
            .expect("valid resolver");

        let got = resolver
            .lookup("a.bramp.net")
            .await
            .expect("failed to lookup");
        assert_eq!(got, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    /// An upstream that responds after a delay, to test deadline propagation.
    struct SlowClient(Duration);

    #[async_trait]
    impl AsyncExchanger for SlowClient {
        fn endpoint(&self) -> std::sync::Arc<str> {
            "slow".into()
        }

        async fn exchange(&self, query: &Message) -> Result<WireResponse, rustdns::Error> {
            tokio::time::sleep(self.0).await;
            Ok(WireResponse::test(
                respond(query, Some(Resource::A("127.0.0.1".parse().unwrap()))),
                ChannelSecurity::Loopback,
            ))
        }
    }

    #[tokio::test]
    async fn exchange_with_deadline_honors_a_caller_supplied_budget() {
        let mut query = Message::default();
        query
            .try_add_question("a.bramp.net", Type::A, Class::Internet)
            .expect("valid question");

        // A generous default `timeout`, but the caller's own deadline (e.g.
        // from an enclosing request) has effectively already expired.
        let resolver = Resolver::builder()
            .upstream(SlowClient(Duration::from_secs(5)))
            .timeout(Duration::from_secs(30))
            .retries(0)
            .build()
            .expect("valid resolver");

        let deadline = std::time::Instant::now() + Duration::from_millis(10);
        let result = resolver.exchange_with_deadline(&query, deadline).await;
        assert!(result.is_err());
    }

    #[test]
    fn builder_accepts_url_and_ip_strings() {
        let resolver = Resolver::builder()
            .upstream("8.8.8.8:53")
            .upstream("udp://8.8.8.8:53")
            .upstream("tcp://8.8.8.8:53")
            .build();

        assert!(resolver.is_ok());
    }

    struct DnssecClient {
        // TODO Should this be called FakeDnssecClient or something?
        secure: bool,
        ad: bool,
    }

    #[async_trait]
    impl AsyncExchanger for DnssecClient {
        fn endpoint(&self) -> std::sync::Arc<str> {
            "dnssec-upstream".into()
        }

        fn channel_security(&self) -> ChannelSecurity {
            if self.secure {
                ChannelSecurity::Encrypted
            } else {
                ChannelSecurity::Insecure
            }
        }

        async fn exchange(&self, query: &Message) -> Result<WireResponse, rustdns::Error> {
            let mut resp = respond(query, Some(Resource::A("127.0.0.1".parse().unwrap())));
            resp.ad = self.ad;
            Ok(WireResponse::test(resp, self.channel_security()))
        }
    }

    #[tokio::test]
    async fn test_resolver_dnssec_trust_upstream() {
        // Secure channel with AD=1 -> Secure
        let resolver = Resolver::builder()
            .dnssec_mode(DnssecMode::TrustUpstream {
                require_secure: true,
            })
            .upstream(DnssecClient {
                secure: true,
                ad: true,
            })
            .build()
            .unwrap();
        let resp = resolver.query("a.bramp.net", Type::A).await.unwrap();
        assert_eq!(resp.meta.security_status, SecurityStatus::Secure);
        let ips = resolver.lookup("a.bramp.net").await.unwrap();
        assert_eq!(ips, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);

        // Secure channel with AD=0 and require_secure=true -> fails with InsecureResponse
        let resolver_strict = Resolver::builder()
            .dnssec_mode(DnssecMode::TrustUpstream {
                require_secure: true,
            })
            .upstream(DnssecClient {
                secure: true,
                ad: false,
            })
            .build()
            .unwrap();
        assert!(matches!(
            resolver_strict.query("a.bramp.net", Type::A).await,
            Err(rustdns::Error::Dnssec(
                rustdns::DnssecError::InsecureResponse
            ))
        ));
        assert!(matches!(
            resolver_strict.lookup("a.bramp.net").await,
            Err(rustdns::Error::Dnssec(
                rustdns::DnssecError::InsecureResponse
            ))
        ));

        // Insecure channel with AD=1 under SecureTransportOnly -> fails with UntrustedChannel
        let resolver_untrusted = Resolver::builder()
            .dnssec_mode(DnssecMode::TrustUpstream {
                require_secure: false,
            })
            .upstream(DnssecClient {
                secure: false,
                ad: true,
            })
            .build()
            .unwrap();
        assert!(matches!(
            resolver_untrusted.query("a.bramp.net", Type::A).await,
            Err(rustdns::Error::Dnssec(
                rustdns::DnssecError::UntrustedChannel
            ))
        ));
        assert!(matches!(
            resolver_untrusted.lookup("a.bramp.net").await,
            Err(rustdns::Error::Dnssec(
                rustdns::DnssecError::UntrustedChannel
            ))
        ));
    }

    /// An upstream that verifies A and AAAA queries are in-flight concurrently
    /// using a barrier that requires 2 waiters to proceed.
    struct ConcurrentBarrierClient {
        barrier: std::sync::Arc<tokio::sync::Barrier>,
    }

    #[async_trait]
    impl AsyncExchanger for ConcurrentBarrierClient {
        fn endpoint(&self) -> std::sync::Arc<str> {
            "concurrent_barrier".into()
        }

        async fn exchange(&self, query: &Message) -> Result<WireResponse, rustdns::Error> {
            self.barrier.wait().await;
            let question = &query.questions[0];
            let answer = match question.r#type {
                Type::A => Some(Resource::A("127.0.0.1".parse().unwrap())),
                Type::AAAA => Some(Resource::AAAA("::1".parse().unwrap())),
                _ => None,
            };
            Ok(WireResponse::test(
                respond(query, answer),
                ChannelSecurity::Loopback,
            ))
        }
    }

    #[tokio::test]
    async fn lookup_dispatches_a_and_aaaa_concurrently() {
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let resolver = Resolver::builder()
            .upstream(ConcurrentBarrierClient {
                barrier: barrier.clone(),
            })
            .retries(0)
            .timeout(Duration::from_secs(2))
            .build()
            .expect("valid resolver");

        let mut ips = resolver
            .lookup("example.com")
            .await
            .expect("lookup should succeed via concurrent dispatch");
        ips.sort();

        let mut want: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()];
        want.sort();

        assert_eq!(ips, want);
    }

    struct TypeFailingClient {
        fail_type: Type,
    }

    #[async_trait]
    impl AsyncExchanger for TypeFailingClient {
        fn endpoint(&self) -> std::sync::Arc<str> {
            "type_failing".into()
        }

        async fn exchange(&self, query: &Message) -> Result<WireResponse, rustdns::Error> {
            let question = &query.questions[0];
            if question.r#type == self.fail_type {
                Err(std::io::Error::other("simulated query type failure").into())
            } else {
                Ok(WireResponse::test(
                    respond(query, Some(Resource::A("127.0.0.1".parse().unwrap()))),
                    ChannelSecurity::Loopback,
                ))
            }
        }
    }

    #[tokio::test]
    async fn lookup_fails_if_either_concurrent_query_fails() {
        for fail_type in [Type::A, Type::AAAA] {
            let resolver = Resolver::builder()
                .upstream(TypeFailingClient { fail_type })
                .retries(0)
                .timeout(Duration::from_secs(1))
                .build()
                .expect("valid resolver");

            assert!(resolver.lookup("example.com").await.is_err());
        }
    }
}
