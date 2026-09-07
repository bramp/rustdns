//! WebAssembly DNS dig client using `rustdns`.
//!
//! Provides browser-based DNS resolution using DNS-over-HTTPS (RFC 8484)
//! or DNS-over-HTTPS JSON (Google / Cloudflare format), wrapping each
//! in a transport client and formatting results like traditional `dig`.

#[cfg(target_arch = "wasm32")]
pub mod exchangers;
#[cfg(target_arch = "wasm32")]
pub mod fetch;

#[cfg(target_arch = "wasm32")]
use crate::exchangers::BrowserClient;
#[cfg(target_arch = "wasm32")]
pub use crate::exchangers::{BrowserDohClient, BrowserJsonClient};
use rustdns::Message;
#[cfg(target_arch = "wasm32")]
use rustdns::clients::AsyncExchanger;
use rustdns::limits::EDNS_DOH_PAYLOAD_SIZE;
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
/// - `protocol`: "doh" (RFC 8484 binary wire POST) or "json" (DNS-over-HTTPS JSON GET).
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
}
