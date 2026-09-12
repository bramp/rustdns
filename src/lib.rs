#![allow(
    unexpected_cfgs,
    non_local_definitions,
    clippy::result_unit_err,
    clippy::result_large_err
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
//! # rustdns
//!
//! rustdns is a simple, fast, and fully fledged DNS library for interacting
//! with domain name services at a high or low level.
//!
//! # Features
//! * Parsing and generating record types: A, AAAA, CNAME, DNSKEY, DS, MX, NS, NSEC, NSEC3, NSEC3PARAM, OPT, PTR, RRSIG, SOA, SPF, SRV, TXT, and ZONEMD (plus raw/unrecognized record fallback).
//! * Multiple client transports ([`clients::Exchanger`] / [`clients::AsyncExchanger`]): UDP, TCP, combined Do53, DNS-over-TLS (DoT, [RFC 7858]), DNS-over-HTTPS (DoH, [RFC 8484]), and DNS-over-HTTPS JSON.
//! * High-level asynchronous [`Resolver`] with multi-upstream failover, exponential backoff, deadline budgets, and concurrent dual-stack address lookups.
//! * Full DNSSEC cryptographic validation ([RFC 4034], [RFC 4035], [RFC 5155], [RFC 6840]) with built-in IANA root trust anchors and delegation chain verification.
//! * Extension Mechanisms for DNS ([EDNS(0)]).
//! * Support [International Domain Names (IDNA)](https://en.wikipedia.org/wiki/Internationalized_domain_name) - Different scripts, alphabets, and even emojis!
//! * WebAssembly (WASM) support: message encoding/decoding, JSON DoH parsing, and the [`clients::Exchanger`]/[`clients::AsyncExchanger`] traits compile to `wasm32-unknown-unknown`. Try the [live in-browser dig demo](https://dig.bramp.net).
//! * Sample `dig` and `nslookup` style [command line tools](#usage-cli).
//! * Fully [tested](#testing), and [fuzzed](#fuzzing).
//!
//! # Usage (high-level async resolver)
//!
//! For most applications, [`Resolver`] is the recommended way to resolve DNS queries.
//! It handles multi-server failover, retries with backoff, EDNS sizing, and DNSSEC validation.
//!
//! ```rust,no_run
//! # #[cfg(feature = "resolver")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use rustdns::prelude::*;
//! use std::time::Duration;
//!
//! // Build a resolver with multiple upstream servers and failover:
//! let resolver = Resolver::builder()
//!     .upstream("8.8.8.8:53")
//!     .upstream("1.1.1.1:53")
//!     .timeout(Duration::from_secs(5))
//!     .build()?;
//!
//! // Look up IPv4 and IPv6 addresses concurrently:
//! let addrs = resolver.lookup("bramp.net").await?;
//! println!("Addresses: {addrs:?}");
//!
//! // Or query for a specific record type with full response metadata:
//! let response = resolver.query("bramp.net", Type::MX).await?;
//! println!("DNS Response:\n{}", response.message);
//! # Ok(())
//! # }
//! ```
//!
//! ### Low-level query with an Exchanger
//!
//! If you only need a single point-to-point query without failover, retries, or DNSSEC validation,
//! an [`clients::AsyncExchanger`] client can be used directly:
//!
//! ```rust,no_run
//! # #[cfg(feature = "do53")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use rustdns::clients::udp;
//! use rustdns::prelude::*;
//!
//! let mut query = Message::default();
//! query.try_add_question("bramp.net", Type::A, Class::Internet)?;
//!
//! let client = udp::Client::new("8.8.8.8:53".parse()?);
//! let response = client.exchange(&query).await?;
//! println!("DNS Response:\n{}", response.message);
//! # Ok(())
//! # }
//! ```
//!
//! ## Resolver vs. Exchanger
//!
//! `rustdns` distinguishes between low-level transport exchangers and high-level resolvers:
//!
//! - **[`clients::Exchanger`] / [`clients::AsyncExchanger`]**: Point-to-point transports
//!   (e.g., raw UDP, TCP, DoT, DoH). An exchanger takes a verbatim [`Message`] and
//!   sends it to a single server endpoint without retries, failover, deadline
//!   tracking, or validation.
//! - **[`Resolver`]**: High-level, production-grade resolution engine built on top of
//!   exchangers:
//!   - **Multi-Upstream Orchestration & Failover**: Configures multiple upstreams
//!     with automated failover strategies (`Strategy::Failover`).
//!   - **Retry & Exponential Backoff**: Automatically handles transient network errors
//!     and retryable upstream errors (such as `SERVFAIL`) with customizable backoff and jitter.
//!   - **Deadline & Budget Management**: Bounds the entire resolution process—including all
//!     attempts and retries—by an overall deadline (`query_with_deadline`, `lookup_with_deadline`).
//!   - **Automated EDNS & Buffer Sizing**: Sets safe EDNS(0) buffer limits (1232 bytes per
//!     DNS Flag Day recommendations) and appropriate query flags.
//!   - **DNSSEC Validation**: Enforces configurable DNSSEC policies, including full local
//!     cryptographic chain-of-trust validation down to IANA root anchors (`DnssecMode::ValidateLocal`).
//!   - **Concurrent Dual-Stack Lookups**: `lookup` concurrently resolves `A` and `AAAA`
//!     records, returning unified IP addresses.
//!
//! # Usage (low-level message & socket API)
//!
//! For custom protocols, specialized transports, or offline packet manipulation,
//! the low-level [`Message`] and [`Extension`] types can be used directly:
//!
//! ```rust
//! use rustdns::prelude::*;
//! use std::net::UdpSocket;
//! use std::time::Duration;
//!
//! fn udp_example() -> Result<(), Box<dyn std::error::Error>> {
//!     // A DNS Message can be easily constructed
//!     let mut m = Message::default();
//!     m.try_add_question("bramp.net", Type::A, Class::Internet)?;
//!     m.set_extension(Extension {   // Optionally add a EDNS extension
//!         payload_size: 4096,       // which supports a larger payload size.
//!         ..Default::default()
//!     });
//!
//!     // Setup a UDP socket for sending to a DNS server.
//!     let socket = UdpSocket::bind("0.0.0.0:0")?;
//!     socket.set_read_timeout(Some(Duration::new(5, 0)))?;
//!     socket.connect("8.8.8.8:53")?; // Google's Public DNS Servers
//!
//!     // Encode the DNS Message as a Vec<u8>.
//!     // Use append_to_vec when appending to an existing Vec<u8>.
//!     let question = m.to_vec()?;
//!
//!     // Send to the server.
//!     socket.send(&question)?;
//!
//!     // Wait for a response from the DNS server.
//!     let mut resp = [0; 4096];
//!     let len = socket.recv(&mut resp)?;
//!
//!     // Take the response bytes and turn it into another DNS Message.
//!     let answer = Message::from_slice(&resp[0..len])?;
//!
//!     // Now do something with `answer`, in this case print it!
//!     println!("DNS Response:\n{}", answer);
//!
//!     Ok(())
//! }
//! ```
//!
//! If successful something like the following will be printed:
//!
//! ```text
//! ;; ->>HEADER<<- opcode: Query, status: NoError, id: 44857
//! ;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
//!
//! ;; OPT PSEUDOSECTION:
//! ; EDNS: version: 0, flags:; udp: 512
//! ;; QUESTION SECTION:
//! ; bramp.net.              IN   A
//!
//! ; ANSWER SECTION:
//! bramp.net.            299 IN   A      104.21.62.200
//! bramp.net.            299 IN   A      172.67.138.196
//! ```
//!
//! # Features
//! The following optional features are available:
//!
//! - `clients`: Enables high-level clients and transports (Do53, DoT, DoH, DoH JSON, and Resolver).
//!   - `do53`: Classic DNS (Do53) asynchronous UDP and TCP clients with automatic TCP retry on truncation.
//!   - `dot`: DNS-over-TLS (DoT) client ([RFC 7858]).
//!   - `doh`: DNS-over-HTTPS (DoH) binary wire client ([RFC 8484]).
//!   - `doh-json`: DNS-over-HTTPS JSON client (Google / Cloudflare JSON schema).
//!   - `resolver`: High-level asynchronous [`Resolver`] with multi-upstream failover, retries, and DNSSEC validation.
//!   - `dnssec`: Local DNSSEC cryptographic signature and chain-of-trust verification using `ring`.
//!   - `exchanger`: Generic [`clients::Exchanger`] and [`clients::AsyncExchanger`] traits without Tokio/HTTP dependencies (WASM compatible).
//!   - `sync`: Synchronous blocking variants of enabled clients under `rustdns::clients::sync`.
//! - `json`: DNS-over-HTTPS JSON parsing and serialization (WASM compatible, no network/HTTP dependencies).
//! - `zones`: RFC 1035 zone file master format parser.
//!
//! # WebAssembly (WASM) & In-Browser Support
//!
//! `rustdns` core message encoding, decoding, JSON format serialization, and the [`clients::AsyncExchanger`] trait are compatible with the `wasm32-unknown-unknown` target without requiring Tokio or OS sockets.
//!
//! An in-browser DNS lookup web app powered by `rustdns` compiled to WebAssembly is running live:
//!
//! - **Live Demo:** <https://dig.bramp.net>
//! - **Source Code:** [web-dig/](https://github.com/bramp/rustdns/tree/main/web-dig)
//!
//! # Usage (cli)
//!
//! To use the [demo CLI](https://github.com/bramp/rustdns/blob/main/dig/main.rs):
//!
//! ```shell
//! $ cargo run -p dig -- A www.google.com
//! ...
//! ;; ->>HEADER<<- opcode: Query, status: NoError, id: 34327
//! ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
//!
//! ;; OPT PSEUDOSECTION:
//! ; EDNS: version: 0, flags:; udp: 512
//! ;; QUESTION SECTION:
//! ; www.google.com.         IN   A
//!
//! ; ANSWER SECTION:
//! www.google.com.       110 IN   A      142.250.72.196
//!
//! # More examples
//! $ cargo run -p dig -- AAAA www.google.com
//! $ cargo run -p dig -- ANY www.google.com
//! $ cargo run -p dig -- CNAME code.google.com
//! $ cargo run -p dig -- MX google.com
//! $ cargo run -p dig -- PTR 4.4.8.8.in-addr.arpa
//! $ cargo run -p dig -- SOA google.com
//! $ cargo run -p dig -- SRV _ldap._tcp.google.com
//! $ cargo run -p dig -- TXT google.com
//! $ cargo run -p dig -- +dot @dns.google google.com A
//! $ cargo run -p dig -- +verbose +dot @dns.google google.com A
//! ```
//!
//! To use the `nslookup` CLI:
//!
//! ```shell
//! $ cargo run -p nslookup -- www.google.com
//! Server:         8.8.8.8:53
//! Address:        8.8.8.8:53
//!
//! Non-authoritative answer:
//! Name:   www.google.com
//! Address: 142.250.72.196
//! Address: 2607:f8b0:4005:809::2004
//! ```
//! # Testing
//!
//! ```shell
//! $ cargo test --all
//!
//! # or the handy
//! $ cargo watch -- cargo test --all -- --nocapture
//! ```
//!
//! The test suite is full of stored real life examples, from querying real DNS records.
//! This was generated with `cargo run -p generate_tests`.
//!
//! ## Fuzzing
//!
//! The library has been extensively fuzzed. You can run all fuzzers using the
//! provided helper script or with `cargo-fuzz` directly:
//!
//! ```shell
//! $ cargo install cargo-fuzz
//! $ rustup toolchain install nightly
//! $ rustup component add llvm-tools-preview --toolchain nightly
//!
//! # Run all fuzz targets (defaults to 15m each with safe worker & memory limits):
//! $ ./fuzz/fuzz.sh
//!
//! # Or run a specific target for a custom duration (in seconds):
//! $ ./fuzz/fuzz.sh 60 from-slice
//! $ ./fuzz/fuzz.sh 60 encode
//! $ ./fuzz/fuzz.sh 60 from-str
//! $ ./fuzz/fuzz.sh 60 json
//! $ ./fuzz/fuzz.sh 60 edns
//!
//! # Or run cargo-fuzz directly:
//! $ cargo +nightly fuzz run from-slice
//! $ cargo +nightly fuzz run encode
//! $ cargo +nightly fuzz run from-str
//! $ cargo +nightly fuzz run json
//! $ cargo +nightly fuzz run edns
//! ```
//!
//! If `cargo` is installed outside rustup, such as through Homebrew, use
//! nightly's Cargo explicitly:
//!
//! ```shell
//! $ nightly_bin="$(dirname "$(rustup which --toolchain nightly cargo)")"
//! $ PATH="$nightly_bin:$PATH" ./fuzz/fuzz.sh
//! ```
//! ## Test Data
//!
//! To aid in testing features, I have a set of pre-configured records setup:
//!
//! | Domain                | Description |
//! | --------------------- | ----------- |
//! | a.bramp.net           | Single A record pointing at 127.0.0.1 |
//! | aaaa.bramp.net        | Single AAAA record pointing at ::1 |
//! | aaaaa.bramp.net       | One A record, and one AAAA record resolving to 127.0.0.1 and ::1 |
//! | cname.bramp.net       | Single CNAME record pointing at a.bramp.net |
//! | cname-loop1.bramp.net | Single CNAME record pointing at cname-loop2.bramp.net |
//! | cname-loop2.bramp.net | Single CNAME record pointing at cname-loop1.bramp.net |
//! | mx.bramp.net          | Single MX record pointing at a.bramp.net |
//! | ns.bramp.net          | Single NS record pointing at a.bramp.net |
//! | txt.bramp.net         | Single TXT Record "A TXT record!" |
//!
//! # Minimum Supported Rust Version (MSRV)
//!
//! This crate requires Rust **1.86.0** or later.
//!
//! Increasing the MSRV is considered a breaking change and will only be done in
//! a minor version bump (or major version bump after 1.0.0), never in a patch
//! release.
//!
//! # Releasing
//!
//! Releases are published by GitHub Actions when a `v*` tag is pushed. The
//! workflow checks the tag matches `Cargo.toml`, publishes to crates.io via
//! [Trusted Publishing](https://crates.io/docs/trusted-publishing) (no API
//! token stored), and creates a GitHub release.
//!
//! ```shell
//! $ cargo set-version 0.6.0   # or edit Cargo.toml by hand
//! $ cargo readme -o README.md
//! $ git commit -am "Release v0.6.0" && git push
//! $ git tag v0.6.0 && git push origin v0.6.0
//! ```
//!
//! # Reference
//!
//! * [RFC 1034]: DOMAIN NAMES - CONCEPTS AND FACILITIES
//! * [RFC 1035]: DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
//! * [RFC 4034]: Resource Records for the DNS Security Extensions
//! * [RFC 4035]: Protocol Modifications for the DNS Security Extensions
//! * [RFC 5155]: DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
//! * [RFC 6840]: Clarifications and Implementation Notes for DNS Security (DNSSEC)
//! * [RFC 6895]: Domain Name System (DNS) IANA Considerations
//! * [RFC 7858]: Specification for DNS over Transport Layer Security (TLS)
//! * [RFC 8484]: DNS Queries over HTTPS (DoH)
//! * [IANA Domain Name System (DNS) Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
//! * [Computer Networks CPS365 FALL 2016](https://courses.cs.duke.edu//fall16/compsci356/DNS/DNS-primer.pdf)
//! * [miekg's Go DNS Library](https://github.com/miekg/dns)
//!
//! [EDNS(0)]: https://en.wikipedia.org/wiki/Extension_Mechanisms_for_DNS
//! [RFC 1034]: https://datatracker.ietf.org/doc/html/rfc1034
//! [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
//! [RFC 4034]: https://datatracker.ietf.org/doc/html/rfc4034
//! [RFC 4035]: https://datatracker.ietf.org/doc/html/rfc4035
//! [RFC 5155]: https://datatracker.ietf.org/doc/html/rfc5155
//! [RFC 6840]: https://datatracker.ietf.org/doc/html/rfc6840
//! [RFC 6895]: https://datatracker.ietf.org/doc/html/rfc6895
//! [RFC 7858]: https://datatracker.ietf.org/doc/html/rfc7858
//! [RFC 8484]: https://datatracker.ietf.org/doc/html/rfc8484

#[macro_use]
mod cfg;

#[cfg(any(
    feature = "doh",
    feature = "doh-json",
    feature = "do53",
    feature = "dot",
    feature = "sync",
    feature = "resolver",
    feature = "exchanger"
))]
pub mod clients;

mod display;
mod dns;
mod edns;
mod errors;
mod from_str;
mod io;
pub mod limits;
pub mod names;
pub mod resource;
pub mod types;
pub mod util;

cfg_feature! {
    #![feature = "zones"]

    #[macro_use]
    extern crate pest_derive;

    pub mod zones;
}

cfg_feature! {
    #![feature = "json"]

    pub mod json;
}

cfg_feature! {
    #![feature = "dnssec"]

    pub mod dnssec;
}

#[macro_use]
extern crate num_derive;

#[macro_use]
extern crate lazy_static;

// Pull up the various types that should be on the front page of the docs.
#[doc(inline)]
pub use crate::types::*;

#[doc(inline)]
pub use crate::edns::*;

#[doc(inline)]
pub use crate::resource::*;

#[doc(inline)]
#[cfg(feature = "resolver")]
pub use crate::clients::{AsyncResolver, Resolver};

pub use crate::errors::DecodeError;
pub use crate::errors::DnssecError;
pub use crate::errors::EncodeError;
pub use crate::errors::Error;
#[cfg(feature = "json")]
pub use crate::errors::JsonError;
pub use crate::errors::Result;
pub use crate::from_str::FromStrError;

/// The `rustdns` prelude.
///
/// Convenient glob-import (`use rustdns::prelude::*;`) bringing core traits and
/// common types into scope.
pub mod prelude {
    #[doc(no_inline)]
    pub use crate::types::*;

    #[doc(no_inline)]
    pub use crate::Message;
    #[doc(no_inline)]
    pub use crate::Record;
    #[doc(no_inline)]
    pub use crate::Resource;

    #[cfg(feature = "resolver")]
    #[doc(no_inline)]
    pub use crate::clients::{AsyncResolver, Resolver};

    #[cfg(any(feature = "clients", feature = "resolver"))]
    #[doc(no_inline)]
    pub use crate::clients::IntoAsyncExchanger;

    #[cfg(any(feature = "clients", feature = "exchanger"))]
    #[doc(no_inline)]
    pub use crate::clients::AsyncExchanger;

    #[cfg(any(feature = "sync", feature = "exchanger"))]
    #[doc(no_inline)]
    pub use crate::clients::Exchanger;
}
