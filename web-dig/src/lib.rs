//! WebAssembly DNS dig client using `rustdns`.
//!
//! Provides browser-based DNS resolution using DNS-over-HTTPS ([RFC 8484])
//! or DNS-over-HTTPS JSON (Google / Cloudflare format), wrapping each
//! in a transport client and formatting results like traditional `dig`.
//!
//! [RFC 8484]: https://datatracker.ietf.org/doc/html/rfc8484

#[cfg(target_arch = "wasm32")]
pub mod exchangers;
#[cfg(target_arch = "wasm32")]
pub mod fetch;
#[cfg(target_arch = "wasm32")]
pub mod resolver;
pub mod trace;

#[cfg(target_arch = "wasm32")]
use crate::exchangers::BrowserClient;
#[cfg(target_arch = "wasm32")]
pub use crate::exchangers::{BrowserDohClient, BrowserJsonClient, DohMethod};
use rustdns::Message;
#[cfg(target_arch = "wasm32")]
use rustdns::clients::AsyncExchanger;
use rustdns::limits::EDNS_DOH_PAYLOAD_SIZE;
#[cfg(target_arch = "wasm32")]
use rustdns::types::DnssecMode;
use rustdns::types::{Class, Extension, Type};
use std::str::FromStr;
use wasm_bindgen::prelude::*;

/// Returns a list of commonly queried DNS record types.
#[wasm_bindgen]
pub fn supported_record_types() -> Vec<String> {
    vec![
        "A", "AAAA", "CAA", "CNAME", "DNSKEY", "DS", "MX", "NS", "PTR", "SOA", "SRV", "TXT", "ANY",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Builds a DNS query message configured with standard EDNS(0) options.
pub fn create_query(domain: &str, rtype: &str) -> Result<Message, String> {
    let rtype = Type::from_str(rtype).map_err(|_| format!("invalid DNS record type: {rtype}"))?;

    let mut query = Message::default();
    query
        .try_add_question(domain, rtype, Class::Internet)
        .map_err(|e| format!("invalid domain name: {e}"))?;

    let extension = Extension {
        payload_size: EDNS_DOH_PAYLOAD_SIZE,
        ..Default::default()
    };
    query.set_extension(extension);

    Ok(query)
}

/// Pure Rust implementation of `dig` execution over an [`AsyncExchanger`].
#[cfg(target_arch = "wasm32")]
pub async fn dig_with_exchanger(
    domain: &str,
    rtype: &str,
    exchanger: &impl AsyncExchanger,
) -> Result<String, String> {
    let query = create_query(domain, rtype)?;

    let response = exchanger
        .exchange(&query)
        .await
        .map_err(|e| format!("exchange failed: {e}"))?;

    Ok(format!("{}\n{}", response.message, response.meta))
}

/// Performs an in-browser DNS query using [`BrowserClient`] (static dispatch) and returns formatted `dig` output.
///
/// - `domain`: domain name to query (e.g. "example.com").
/// - `rtype`: record type (e.g. "A", "AAAA", "MX", "TXT").
/// - `server`: DoH HTTPS endpoint URL (e.g. `<https://cloudflare-dns.com/dns-query>`).
/// - `protocol`: "doh" ([RFC 8484] binary wire POST), "doh-get" ([RFC 8484] binary wire GET with base64url), or "json" (DNS-over-HTTPS JSON GET).
///
/// [RFC 8484]: https://datatracker.ietf.org/doc/html/rfc8484
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn dig(
    domain: &str,
    rtype: &str,
    server: &str,
    protocol: &str,
) -> Result<String, JsValue> {
    let client = BrowserClient::try_new(protocol, server).map_err(|e| JsValue::from_str(&e))?;

    dig_with_exchanger(domain, rtype, &client)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

/// Dig-style output plus the DNS exchanges made to produce it.
#[wasm_bindgen(getter_with_clone)]
pub struct DigResult {
    /// Dig-style output for the requested query.
    pub output: String,
    /// Exchanges made during local DNSSEC validation, in start order. Empty
    /// for other modes.
    pub trace: Vec<trace::TraceEntry>,
    /// Why DNSSEC validation failed, if it was requested and failed.
    pub dnssec_error: Option<String>,
}

/// Performs a DoH query with upstream or local DNSSEC validation.
///
/// `mode` is `"off"`, `"upstream"`, or `"local"`. Local validation fetches
/// DNSKEY and DS dependencies over the same DoH endpoint and validates them
/// against the built-in IANA root trust anchors.
///
/// # Errors
///
/// Returns an error if `mode` is unknown, the query is invalid, the browser
/// clock is unavailable, or the primary exchange fails. DNSSEC validation
/// failures are reported in [`DigResult::output`] instead.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn dig_dnssec(
    domain: &str,
    rtype: &str,
    server: &str,
    protocol: &str,
    mode: &str,
) -> Result<DigResult, JsValue> {
    let mode = match mode {
        "off" => DnssecMode::Off,
        "upstream" => DnssecMode::TrustUpstream {
            require_secure: false,
        },
        "local" => DnssecMode::ValidateLocal,
        _ => return Err(JsValue::from_str("invalid DNSSEC mode")),
    };
    if mode == DnssecMode::Off {
        return Ok(DigResult {
            output: dig(domain, rtype, server, protocol).await?,
            trace: Vec::new(),
            dnssec_error: None,
        });
    }
    let client = BrowserClient::try_new(protocol, server).map_err(|e| JsValue::from_str(&e))?;
    let resolver = crate::resolver::BrowserResolver::new(client);
    let clock = crate::resolver::BrowserClock;
    let now = rustdns::dnssec::Clock::now(&clock)
        .ok_or_else(|| JsValue::from_str("browser monotonic clock is unavailable"))?;
    let deadline =
        rustdns::dnssec::Clock::checked_add(&clock, now, std::time::Duration::from_secs(20))
            .ok_or_else(|| JsValue::from_str("DNSSEC deadline overflow"))?;

    let mut query = create_query(domain, rtype).map_err(|e| JsValue::from_str(&e))?;
    // Trust upstream asks only for the AD result (RFC 6840 §5.7); local
    // validation needs signatures (DO) and unfiltered data (CD).
    let validate_local = mode == DnssecMode::ValidateLocal;
    if let Some(extension) = &mut query.extension {
        extension.dnssec_ok = validate_local;
    }
    query.ad = !validate_local;
    query.cd = validate_local;

    let mut response =
        rustdns::clients::AsyncResolver::exchange_with_deadline(&resolver, &query, deadline)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Failures are recorded in the response metadata and shown in the output.
    let trace = match mode {
        DnssecMode::Off => Vec::new(),
        DnssecMode::TrustUpstream { require_secure } => {
            let _ = response.trust_upstream(require_secure);
            Vec::new()
        }
        DnssecMode::ValidateLocal => {
            let cache = rustdns::dnssec::DnssecCache::with_clock(clock);
            let trust_store = rustdns::dnssec::TrustStore::default();
            let validation_time = crate::resolver::browser_system_time()
                .ok_or_else(|| JsValue::from_str("browser wall clock is unavailable"))?;
            let _ = rustdns::dnssec::ChainValidator::new(&resolver, &trust_store, &cache, deadline)
                .validate_response_mut(&mut response, validation_time)
                .await;
            resolver.take_trace()
        }
    };

    Ok(DigResult {
        output: response.to_string(),
        trace,
        dnssec_error: response.meta.dnssec_error.map(|error| error.to_string()),
    })
}

/// Returns the git commit hash embedded at build time.
#[wasm_bindgen]
pub fn build_commit() -> String {
    env!("BUILD_COMMIT").into()
}

/// Returns the UTC timestamp embedded at build time.
#[wasm_bindgen]
pub fn build_time() -> String {
    env!("BUILD_TIME").into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_record_types() {
        let types = supported_record_types();
        assert!(types.contains(&"A".to_string()));
        assert!(types.contains(&"AAAA".to_string()));
        assert!(types.contains(&"MX".to_string()));
        assert!(types.contains(&"TXT".to_string()));
    }

    #[test]
    fn test_create_query_valid() {
        let msg = create_query("example.com", "A").expect("create query should succeed");
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "example.com.");
        assert_eq!(msg.questions[0].r#type, Type::A);

        let ext = msg.extension.as_ref().expect("extension should be set");
        assert_eq!(ext.payload_size, EDNS_DOH_PAYLOAD_SIZE);

        let wire = msg
            .to_vec()
            .expect("encoding to wire format should succeed");
        assert!(!wire.is_empty());
    }

    #[test]
    fn test_create_query_unicode_domain() {
        let msg = create_query("🍕.ws", "A").expect("create query should succeed");
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name.to_unicode(), "🍕.ws.");
        assert_eq!(msg.questions[0].name.as_ascii(), "xn--vi8h.ws.");
    }

    #[test]
    fn test_create_query_invalid_type() {
        let err = create_query("example.com", "NOT_A_REAL_TYPE");
        assert!(err.is_err());
    }

    #[test]
    fn test_create_query_invalid_domain() {
        let invalid_domain = format!("{}.example.com", "a".repeat(64));
        let err = create_query(&invalid_domain, "A");
        assert!(err.is_err());
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_exchangers_metadata() {
        let doh = BrowserDohClient::new("https://cloudflare-dns.com/dns-query");
        assert_eq!(
            doh.endpoint().as_ref(),
            "https://cloudflare-dns.com/dns-query"
        );
        assert!(doh.is_secure_channel());

        let json_client = BrowserJsonClient::new("https://dns.google/resolve");
        assert_eq!(
            json_client.endpoint().as_ref(),
            "https://dns.google/resolve"
        );
        assert!(json_client.is_secure_channel());
    }

    #[test]
    fn test_build_info() {
        assert!(!build_commit().is_empty());
        assert!(!build_time().is_empty());
    }
}
