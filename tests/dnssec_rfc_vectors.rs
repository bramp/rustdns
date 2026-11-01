//! Validates the published DNSSEC examples from [RFC 6605] (ECDSA) and
//! [RFC 8080] (Ed25519) with the active crypto backend.
//!
//! Records are built from the published field values rather than parsed as
//! zone text, so this test needs only the `dnssec` feature. CI runs it once per
//! backend, and on `wasm32-unknown-unknown` under `wasm-bindgen-test` to
//! exercise the pure-Rust backend in WebAssembly.
//!
//! [RFC 6605]: https://datatracker.ietf.org/doc/html/rfc6605#section-6
//! [RFC 8080]: https://datatracker.ietf.org/doc/html/rfc8080#section-6
#![cfg(feature = "dnssec")]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rustdns::dnssec::validate_rrset;
use rustdns::types::{Algorithm, Class, DigestType};
use rustdns::{DNSKEY, DS, MX, Name, RRSIG, Record, Resource};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

/// A signed RRset and its key, using the published presentation-format values.
struct Example {
    zone: &'static str,
    owner: &'static str,
    resource: Resource,
    algorithm: Algorithm,
    labels: u8,
    dnskey: &'static str,
    ds_digest_type: DigestType,
    ds_digest: &'static str,
    expiration: &'static str,
    inception: &'static str,
    key_tag: u16,
    signature: &'static str,
}

/// Parses an RRSIG time as `YYYYMMDDHHmmSS` or seconds since the epoch (RFC 4034 §3.2).
fn rrsig_time(value: &str) -> SystemTime {
    let seconds = if value.len() == 14 {
        chrono::NaiveDateTime::parse_from_str(value, "%Y%m%d%H%M%S")
            .expect("valid RRSIG time")
            .and_utc()
            .timestamp()
            .try_into()
            .expect("time after the epoch")
    } else {
        value.parse().expect("valid RRSIG epoch seconds")
    };
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn check(example: Example) {
    let ttl = Duration::from_secs(3600);
    let dnskey = DNSKEY {
        flags: 257,
        protocol: 3,
        algorithm: example.algorithm,
        public_key: BASE64.decode(example.dnskey).expect("valid DNSKEY base64"),
    };
    let rrsig = RRSIG {
        type_covered: example.resource.r#type(),
        algorithm: example.algorithm,
        labels: example.labels,
        original_ttl: ttl,
        expiration: rrsig_time(example.expiration),
        inception: rrsig_time(example.inception),
        key_tag: example.key_tag,
        signer_name: Name::new(example.zone).expect("valid zone"),
        signature: BASE64
            .decode(example.signature)
            .expect("valid RRSIG base64"),
    };
    let record = |resource| {
        Record::try_new(example.owner, Class::Internet, ttl, resource).expect("valid record")
    };

    assert_eq!(dnskey.key_tag(), example.key_tag, "published key tag");
    let ds = DS::from_dnskey(example.zone, &dnskey, example.ds_digest_type).expect("DS digest");
    assert_eq!(ds.key_tag, example.key_tag);
    assert_eq!(
        hex::encode(ds.digest),
        example.ds_digest,
        "published DS digest"
    );

    let now = rrsig.inception + Duration::from_secs(86_400);
    let validate =
        |rrset: &[Record], rrsig: &RRSIG| validate_rrset(example.owner, rrset, rrsig, &dnskey, now);
    let rrset = [record(example.resource.clone())];
    validate(&rrset, &rrsig).expect("published signature validates");

    let mut tampered_signature = rrsig.clone();
    tampered_signature.signature[10] ^= 1;
    assert!(validate(&rrset, &tampered_signature).is_err());

    let mut aged = rrset.clone();
    aged[0].ttl = Duration::from_secs(1);
    validate(&aged, &rrsig).expect("received TTLs are not signed");

    let tampered = match &example.resource {
        Resource::A(_) => Resource::A("192.0.2.2".parse().expect("valid address")),
        Resource::MX(mx) => Resource::MX(MX {
            preference: mx.preference + 1,
            exchange: mx.exchange.clone(),
        }),
        other => panic!("unexpected record {other:?}"),
    };
    assert!(validate(&[record(tampered)], &rrsig).is_err());
}

fn www_example_net_a() -> Resource {
    Resource::A("192.0.2.1".parse().expect("valid address"))
}

fn example_com_mx() -> Resource {
    Resource::MX(MX {
        preference: 10,
        exchange: Name::new("mail.example.com.").expect("valid name"),
    })
}

#[test]
fn rfc6605_p256_example() {
    check(Example {
        zone: "example.net.",
        owner: "www.example.net.",
        resource: www_example_net_a(),
        algorithm: Algorithm::ECDSAP256SHA256,
        labels: 3,
        dnskey: concat!(
            "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb",
            "krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==",
        ),
        ds_digest_type: DigestType::Sha256,
        ds_digest: concat!(
            "b4c8c1fe2e7477127b27115656ad6256f424625bf5c1",
            "e2770ce6d6e37df61d17"
        ),
        expiration: "20100909100439",
        inception: "20100812100439",
        key_tag: 55648,
        signature: concat!(
            "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA",
            "yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==",
        ),
    });
}

#[test]
fn rfc6605_p384_example() {
    check(Example {
        zone: "example.net.",
        owner: "www.example.net.",
        resource: www_example_net_a(),
        algorithm: Algorithm::ECDSAP384SHA384,
        labels: 3,
        dnskey: concat!(
            "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1",
            "w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8",
            "/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40",
        ),
        ds_digest_type: DigestType::Sha384,
        ds_digest: concat!(
            "72d7b62976ce06438e9c0bf319013cf801f09ecc84b8",
            "d7e9495f27e305c6a9b0563a9b5f4d288405c3008a94",
            "6df983d6",
        ),
        expiration: "20100909102025",
        inception: "20100812102025",
        key_tag: 10771,
        signature: concat!(
            "/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP",
            "95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz",
            "WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm",
        ),
    });
}

/// RFC 8080 §6.1, as corrected by verified [Errata ID 4935].
///
/// The published RRSIGs omitted the algorithm and used a label count of 3,
/// so the original signatures are invalid.
///
/// [Errata ID 4935]: https://www.rfc-editor.org/errata/eid4935
#[test]
fn rfc8080_ed25519_examples() {
    check(Example {
        zone: "example.com.",
        owner: "example.com.",
        resource: example_com_mx(),
        algorithm: Algorithm::ED25519,
        labels: 2,
        dnskey: "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=",
        ds_digest_type: DigestType::Sha256,
        ds_digest: concat!(
            "3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79",
            "a304b"
        ),
        expiration: "1440021600",
        inception: "1438207200",
        key_tag: 3613,
        signature: concat!(
            "oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3f",
            "x8A4M3e23mRZ9VrbpMngwcrqNAg==",
        ),
    });
    check(Example {
        zone: "example.com.",
        owner: "example.com.",
        resource: example_com_mx(),
        algorithm: Algorithm::ED25519,
        labels: 2,
        dnskey: "zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=",
        ds_digest_type: DigestType::Sha256,
        ds_digest: concat!(
            "401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c",
            "6614c"
        ),
        expiration: "1440021600",
        inception: "1438207200",
        key_tag: 35217,
        signature: concat!(
            "zXQ0bkYgQTEFyfLyi9QoiY6D8ZdYo4wyUhVioYZXFdT410QPRITQSqJSnzQ",
            "oSm5poJ7gD7AQR0O7KuI5k2pcBg==",
        ),
    });
}
