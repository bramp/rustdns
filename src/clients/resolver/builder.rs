use super::{Backoff, Resolver, Strategy};
use crate::clients::{AsyncExchanger, IntoAsyncExchanger};
use crate::types::*;
use std::time::Duration;

/// Builder for [`Resolver`].
pub struct ResolverBuilder {
    upstreams: Vec<Box<dyn AsyncExchanger + Send + Sync>>,
    error: Option<crate::Error>,
    strategy: Strategy,
    timeout: Duration,
    retries: u32,
    backoff: Backoff,
    dnssec_mode: DnssecMode,
    upstream_trust_policy: UpstreamTrustPolicy,
    payload_size: u16,
}

impl Default for ResolverBuilder {
    fn default() -> Self {
        Self {
            upstreams: Vec::new(),
            error: None,
            strategy: Strategy::default(),
            timeout: Duration::from_secs(5),
            retries: 2,
            backoff: Backoff::default(),
            dnssec_mode: DnssecMode::default(),
            upstream_trust_policy: UpstreamTrustPolicy::default(),
            payload_size: crate::limits::EDNS_SAFE_UDP_PAYLOAD_SIZE,
        }
    }
}

impl ResolverBuilder {
    /// Adds an upstream. Accepts any target implementing [`IntoAsyncExchanger`]:
    /// a transport, an address ([`SocketAddr`](std::net::SocketAddr) or [`IpAddr`](std::net::IpAddr)), or a URL or address string (`"8.8.8.8"`, `"https://..."`).
    pub fn upstream(mut self, upstream: impl IntoAsyncExchanger) -> Self {
        if self.error.is_none() {
            match upstream.into_async_exchanger() {
                Ok(transport) => self.upstreams.push(transport),
                Err(err) => self.error = Some(err),
            }
        }
        self
    }

    /// Sets the upstream selection strategy. Defaults to [`Strategy::Failover`].
    pub fn strategy(mut self, strategy: Strategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Sets the default resolution budget used by [`Resolver::exchange`] and
    /// [`Resolver::lookup`]. Defaults to 5 seconds.
    ///
    /// This is only a default: it is not a property of any one exchange.
    /// When DNS resolution is one step inside a larger, already deadline-bound
    /// operation (for example an incoming request with its own SLA), use
    /// [`Resolver::exchange_with_deadline`] or [`Resolver::lookup_with_deadline`]
    /// to pass the caller's actual remaining budget instead.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the number of retries per upstream, in addition to the first attempt. Defaults to 2.
    pub fn retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    /// Sets the delay strategy applied between retries against the same
    /// upstream. Defaults to exponential backoff with full jitter (200ms
    /// base, factor 2, capped at 2 seconds).
    pub fn backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// Sets the DNSSEC validation mode. Defaults to [`DnssecMode::Off`].
    pub fn dnssec_mode(mut self, mode: DnssecMode) -> Self {
        self.dnssec_mode = mode;
        self
    }

    /// Sets the policy for trusting upstream `AD` (Authenticated Data) assertions.
    /// Defaults to [`UpstreamTrustPolicy::SecureTransportOnly`].
    pub fn upstream_trust_policy(mut self, policy: UpstreamTrustPolicy) -> Self {
        self.upstream_trust_policy = policy;
        // TODO If this is SecureTransportOnly should we reject non-secure upstreams when building?
        self
    }

    /// Sets the advertised EDNS(0) UDP payload size in bytes.
    ///
    /// Defaults to [`crate::limits::EDNS_SAFE_UDP_PAYLOAD_SIZE`] (1232 bytes),
    /// which eliminates IP packet fragmentation over IPv6 links ([RFC 8200 §5],
    /// [RFC 8900], and DNS Flag Day 2020).
    pub fn payload_size(mut self, size: u16) -> Self {
        self.payload_size = size;
        self
    }

    /// Builds the [`Resolver`].
    ///
    /// # Errors
    ///
    /// Returns an error if an upstream target failed to parse, or if no upstream was added.
    pub fn build(self) -> Result<Resolver, crate::Error> {
        if let Some(err) = self.error {
            return Err(err);
        }

        if self.upstreams.is_empty() {
            return Err(crate::Error::InvalidArgument(
                "at least one upstream is required".to_string(),
            ));
        }

        Ok(Resolver {
            upstreams: self.upstreams,
            strategy: self.strategy,
            timeout: self.timeout,
            retries: self.retries,
            backoff: self.backoff,
            dnssec_mode: self.dnssec_mode,
            upstream_trust_policy: self.upstream_trust_policy,
            payload_size: self.payload_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Message;
    use std::sync::Arc;

    struct Noop;

    #[async_trait::async_trait]
    impl AsyncExchanger for Noop {
        async fn exchange(&self, _query: &Message) -> Result<crate::clients::WireResponse, crate::Error> {
            unreachable!("not called by this test")
        }

        fn endpoint(&self) -> Arc<str> {
            "noop".into()
        }
    }

    #[test]
    fn builder_rejects_empty_upstreams() {
        assert!(ResolverBuilder::default().build().is_err());
    }

    #[test]
    fn builder_accepts_various_upstream_types() {
        let resolver = Resolver::builder()
            .upstream(Noop)
            .upstream("8.8.8.8:53")
            .upstream("dns://8.8.8.8:53")
            .upstream("udp://8.8.8.8:53")
            .upstream("tcp://8.8.8.8:53")
            .build();

        assert!(resolver.is_ok());
    }

    #[test]
    fn builder_rejects_invalid_upstream_string() {
        let result = Resolver::builder().upstream("invalid://foo").build();

        assert!(result.is_err());
    }

    #[test]
    fn upstream_endpoints_are_roundtrippable() {
        let inputs = [
            "dns://8.8.8.8:53",
            "udp://8.8.8.8:53",
            "tcp://8.8.8.8:53",
            #[cfg(feature = "dot")]
            "tls://dns.google:853",
            #[cfg(feature = "doh")]
            "https://dns.google/dns-query",
        ];

        for &input in &inputs {
            let upstream = input
                .into_async_exchanger()
                .unwrap_or_else(|e| panic!("failed into_async_exchanger for '{input}': {e}"));
            let endpoint = upstream.endpoint();
            assert_eq!(
                &*endpoint, input,
                "endpoint for '{input}' did not match input"
            );

            // Round trip: feeding the endpoint back into into_async_exchanger must succeed
            // and produce an identical endpoint.
            let roundtripped = (&*endpoint).into_async_exchanger().unwrap_or_else(|e| {
                panic!("failed roundtrip into_async_exchanger for '{endpoint}': {e}")
            });
            assert_eq!(
                roundtripped.endpoint(),
                endpoint,
                "roundtripped endpoint did not match original"
            );
        }
    }

    #[test]
    fn bare_ip_assumes_do53_scheme() {
        let upstream = "8.8.8.8:53".into_async_exchanger().expect("valid address");
        assert_eq!(&*upstream.endpoint(), "dns://8.8.8.8:53");

        let upstream_default_port = "8.8.8.8".into_async_exchanger().expect("valid IP");
        assert_eq!(&*upstream_default_port.endpoint(), "dns://8.8.8.8:53");
    }

    #[test]
    fn resolver_payload_size_configuration() {
        let default_resolver = Resolver::builder().upstream(Noop).build().unwrap();
        assert_eq!(
            default_resolver.payload_size(),
            crate::limits::EDNS_SAFE_UDP_PAYLOAD_SIZE
        );
        assert_eq!(default_resolver.payload_size(), 1232);

        let custom_resolver = Resolver::builder()
            .upstream(Noop)
            .payload_size(4096)
            .build()
            .unwrap();
        assert_eq!(custom_resolver.payload_size(), 4096);
    }
}
