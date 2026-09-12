# Changelog

All notable changes to rustdns are documented here.

## [Unreleased]

### Added

- Added `web-dig`, an in-browser WebAssembly DNS query tool supporting DoH
  (RFC 8484) and JSON DoH APIs with authentic dig output formatting.
- Added `exchanger` feature to `rustdns` providing the `AsyncExchanger` trait,
  `Exchanger`, `WireResponse`, and protocol content-type constants on WebAssembly
  without Tokio or native HTTP dependencies.
- Added `EDNS_DOH_PAYLOAD_SIZE` (4096 bytes) constant per RFC 8484 §4.2.1 and
  RFC 6891 §6.2.3 in `rustdns::limits`.
- Added WebAssembly (`wasm32-unknown-unknown`, `wasm32-wasip1`) support for core
  DNS wire parsing and encoding (`--no-default-features`), zone file parsing
  (`zones`), and pure JSON serialization (`json`).
- Added standalone `rustdns::json` module exposing `from_slice`, `from_str`,
  `to_string`, and `to_string_pretty` with zero networking or asynchronous runtime
  dependencies.
- Extended `MessageJson` schema to support `Authority` and `Additional` record
  arrays from Google and Cloudflare DNS-over-HTTPS JSON responses.
- Added `doh-json` feature for the HTTP-based DNS-over-HTTPS JSON client
  (`rustdns::clients::json::Client`), decoupling it from pure serde serialization.
- Added a declared minimum supported Rust version of 1.86.
- Added `DecodeError` and `EncodeError`, structured error types for DNS
  wire-format decoding and encoding, replacing the previous `std::io::Error`
  values. Both implement `From<..> for std::io::Error` so existing callers can
  migrate with a single `?` or `.into()`.
- Added `JsonError` for DNS-over-HTTPS JSON responses, and `Error::Decode`,
  `Error::Encode`, `Error::FromStr`, and `Error::Json` variants.
- Added `Error::MissingContentType` and `Error::UnexpectedContentType` in place
  of stringly-typed HTTP content-type failures.
- Added a `rustdns::Result<T, E = Error>` type alias.
- Marked `Error`, `DecodeError`, `EncodeError`, `FromStrError`, and `JsonError`
  as `#[non_exhaustive]` so future variants are not breaking changes.
- Added an async, multi-upstream `Resolver` under the new `resolver` feature
  (included by `clients`), configured with `Resolver::builder()`. It supports
  prioritized failover across upstreams using any `AsyncExchanger` transport
  (UDP, TCP, DoH, DoT, JSON), retries with jittered backoff, and `ServFail`
  failover. Each transport is responsible for bounding how long one exchange
  may take (via its own phase timeouts) and for `TC=1` retries; the resolver
  only enforces the overall deadline, not a separate per-attempt timeout.
  `Resolver::exchange`/`Resolver::lookup` use the resolver's configured
  default budget; `Resolver::exchange_with_deadline`/
  `Resolver::lookup_with_deadline` accept an explicit `Instant` deadline, so
  DNS resolution can share a caller's own remaining budget when it is one
  step inside a larger, already deadline-bound operation. `exchange` returns
  a `Response` containing the decoded `Message` plus `ResponseMeta`.
- Added an `nslookup` CLI tool in the workspace for high-level host address
  resolution using `Resolver::lookup`.
- Added `WireResponse` and `WireResponseMeta` for transport-level message exchanges.
  Captures transport execution metadata for a single attempt (server address,
  elapsed duration, bytes sent/received, channel security classification, and
  TLS details).
- Added `Response` and `ResponseMeta` for multi-attempt resolver resolutions.
  `ResponseMeta` captures resolution-level metrics (upstream endpoint, total
  attempts across all upstreams, `when` timestamp, total elapsed duration, evaluated DNSSEC
  security status, channel security) and retains transport-level metrics from
  every attempt in `wire: Vec<WireResponseMeta>` (with `winning_wire()`
  convenience accessor for the winning attempt). Display formatting includes the
  standard `dig`-style `;; WHEN: ...` timestamp line.
- Added `Deref<Target = Message>` and `DerefMut` implementations to both
  `WireResponse` and `Response`, allowing direct access to `Message` fields
  (`answers`, `rcode`, `questions`, etc.).
- Added the `IntoAsyncExchanger` trait for converting transports, `SocketAddr`,
  `IpAddr`, `Url`, or URI strings (`dns://`, `udp://`, `tcp://`, `tls://`,
  `https://`, and `json+https://`) directly into an `AsyncExchanger`, used by
  `ResolverBuilder::upstream()`.
- Added a classic DNS ("Do53") client under the new `do53` feature, combining
  UDP and TCP for a single server. Queries go out over UDP; a truncated
  (`TC=1`) response is re-sent over TCP to the *same* server, as required by
  [RFC 2181 §9](https://datatracker.ietf.org/doc/html/rfc2181#section-9) and
  [RFC 7766 §5](https://datatracker.ietf.org/doc/html/rfc7766#section-5). Because
  both transports are built from one `SocketAddr`, the "same server"
  requirement holds by construction. The truncated response is never returned
  to the caller: if the TCP retry fails, that failure is returned instead.
- Added an `endpoint(&self) -> Arc<str>` method to both `AsyncExchanger` and
  `Exchanger` returning a canonical address or URL string for the target
  server across all transports (`dns://`, `udp://`, `tcp://`, `tls://`,
  `https://`, and `json+https://`).
- Added a `Backoff` enum (`None`, `Constant`, `Linear`, `Exponential`,
  `ExponentialFullJitter`, `DecorrelatedJitter`) selecting the delay strategy
  `Resolver` applies between retries against the same upstream, set via
  `ResolverBuilder::backoff`. Jitter is part of the chosen strategy rather
  than a separate resolver-level setting, since named backoff algorithms
  (see AWS's "Exponential Backoff And Jitter") define delay and jitter
  together. Defaults to exponential backoff with full jitter (200ms base,
  factor 2, capped at 2 seconds).
- Added `SOA::email` to convert `SOA.rname` into an email address per RFC 1035 §8.
- Added a dedicated `rname` fuzz target testing `SOA::rname_to_email` and
  `SOA::email_to_rname` conversion and safety.
- Added `ChannelSecurity` classification (`Insecure`, `Loopback`, `Encrypted`) and
  `channel_security()` / `is_secure_channel()` methods on `AsyncExchanger` and
  `Exchanger`.
- Added `EDNS_SAFE_UDP_PAYLOAD_SIZE` (1232 bytes) limit per RFC 8900 and DNS Flag Day 2020
  to prevent IP fragmentation over IPv6 links.
- Added `DnssecMode`, `UpstreamTrustPolicy`, `SecurityStatus`, and `DnssecError` for
  DNSSEC validation policies and error reporting.
- Added transport-guarded upstream DNSSEC validation in `Resolver::query` and
  `Resolver::lookup`, with configurable `payload_size` defaulting to 1232 bytes.
- Separated `Resolver::exchange` (low-level, sends messages verbatim without mutation) from
  `Resolver::query` and `Resolver::lookup` (which manage EDNS options and enforce DNSSEC policy).
- Added `scripts/fetch_root_fixtures.sh` to download and cache IANA root hints (`named.root`) and
  authoritative root zone (`root.zone`) fixtures for offline-friendly testing and CI caching.
- Added root hints and root zone integration tests in `tests/zones.rs`, verifying parsing of canonical
  `named.root` (extracting all 13 root name servers and glue records) and `root.zone` (all 24.8k records).
- Added DNSSEC and zone digest record types (`DS`, `DNSKEY`, `RRSIG`, `NSEC`, `ZONEMD`) to `Type`,
  `Resource`, wire-format encoding/decoding, text parsing (`Resource::parse_text`), presentation formatting (`Display`),
  and zone grammar (`zones.pest`).
- Integrated standard `base64` and `hex` ecosystem crates for base64 and hexadecimal encoding and decoding.

### Changed

- Dispatched `A` and `AAAA` queries concurrently in `Resolver::lookup_with_deadline`
  instead of sequentially.
- Decoupled `json` Cargo feature into pure serde parsing and serialization (`serde`,
  `serde_json`), while `doh-json` guards the Tokio and Hyper-based client transport.
  `clients` continues to include `doh-json` by default.
- Moved `socket2` dependency to `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]`
  and enabled `getrandom` with `wasm_js` on `wasm32-unknown-unknown` to support WebAssembly.
- `File::try_into_records` now defaults an unspecified `<class>` field to `Class::Internet`
  (`IN`) per RFC 1035 §5.1 when no previous record class exists to inherit.
- `Exchanger::exchange` and `AsyncExchanger::exchange` now return
  `Result<WireResponse, Error>` rather than `Result<Message, Error>`, separating
  transport execution metadata (`WireResponseMeta`) from the DNS wire message.
- `Resolver::exchange` now returns `Result<Response, Error>`, separating
  resolver execution metadata (`ResponseMeta`) from the DNS wire message.
- `SOA.rname` is now stored as a domain name (`<domain-name>`) per RFC 1035 §3.3.13
  rather than an email address containing `@`, ensuring wire-format decoding and
  encoding are lossless and idempotent.
- `SOA::rname_to_email` and `SOA::email_to_rname` now treat only `\.` as an escaped
  dot in the mailbox local part per RFC 1035 §8, preserving backslashes in other
  contexts.
- `FromStrError::InvalidRname` now provides `{ rname: String, reason: &'static str }`
  describing the failure reason.
- `doh::Client` and `json::Client` now store a single server `Url` instead of a
  vector. Added `try_new(Url)`, `try_from_url(&str)`, and `new(&str)` (convenience
  alias).
- Added `.server()` getters to all clients (`udp::Client`, `tcp::Client`,
  `dot::Client`, `doh::Client`, `json::Client`, and `do53::Client`), plus
  `.server_name()` to `dot::Client`.
- Clients are now asynchronous by default. `rustdns::clients::udp`,
  `rustdns::clients::tcp`, and `rustdns::clients::dot` are the asynchronous
  clients; the blocking variants moved to `rustdns::clients::sync::{udp, tcp,
  dot, do53}` behind the new `sync` feature. The async UDP and TCP clients are
  now named `Client` rather than `AsyncClient`.
- Replaced the `udp`, `tcp`, `async-udp`, and `async-tcp` features with a
  single `do53` feature covering classic DNS over UDP and TCP, and added the
  `sync` feature for the blocking variants. `dot` no longer implies `tcp`.
- Added an asynchronous DNS-over-TLS client, so DoT is no longer blocking-only.
  This adds a `tokio-rustls` dependency.
- The `udp`, `tcp`, and `do53` clients under `rustdns::clients::sync` now take
  a single already-resolved `SocketAddr` via `new`, instead of collecting
  addresses from a generic `ToSocketAddrs` argument (only the first was ever
  used). Hostname resolution moved to the explicit, always-fallible
  `try_from_host_port`.
- Replaced DoT's `new`/`new_with_server_name` constructors (both the async and
  sync clients) with `try_new(server_name, server: SocketAddr)`, which never
  performs a DNS lookup, and `try_from_host_port(server: &str)`, which
  resolves `server` with the system resolver. This matches the `new`/
  `try_new`/`try_from_host_port` convention now documented on the `clients`
  module.
- Restored read and write timeouts on the async UDP, TCP, and DoT clients.
  Previously only a connect timeout existed for TCP/DoT, and the async UDP
  client had no timeout at all, so an unanswered query could hang forever.
- Unified async clients directly under `AsyncExchanger` by giving `udp`,
  `tcp`, `do53`, and `dot` internal synchronization for connection state,
  allowing concurrent `&self` usage without requiring `&mut self` or external
  pooling wrappers.
- Reorganized client modules into per-transport directories (`clients/{udp,
  tcp, do53, dot, doh, json}`) co-locating async and sync implementations, with
  private shared helpers in `clients::common`.
- Updated `dig` to use `Resolver` for resolution, adding support for `-h`/`--help`,
  `+tries=N`, `+retry=N`, `+time=secs`, and `+ignore`/`+noignore` flags.
- Migrated `rustdns`, `dig`, and `generate_tests` to the 2024 edition.
- Set the Cargo resolver to version 3 at the workspace level, so dependency
  resolution respects the declared minimum supported Rust version.
- Upgraded dependencies to their latest versions compatible with Rust 1.85. This
  pins `educe` to 0.6 and `time` to 0.3.45, because later releases require newer
  toolchains.
- `Message::from_slice` and `TryFrom<&[u8]> for Message` now return
  `DecodeError`; `Message::to_vec`, the `append_to_vec` family, and
  `limits::validate_*` now return `EncodeError`.
- Renamed `ParseError` to `JsonError` and narrowed it to JSON response decoding.
  Its `Int`, `Addr`, and `InvalidRname` variants moved to `FromStrError`, which
  is now the single error type for text parsing.
- Renamed error variants that stuttered with their enum name, for example
  `Error::HttpError` to `Error::Http` and `Error::IoError` to `Error::Io`.
- `JsonError::InvalidResource` and `DecodeError::InvalidRname` now expose their
  cause through `Error::source` instead of formatting it into the message.
- Documented the specific error variants returned by the public decoding,
  encoding, and validation entry points.

### Removed

- Removed the deprecated `Message::add_question`. Use `Message::try_add_question`.
- Removed the deprecated `Message::add_extension`. Use `Message::set_extension`.
- Removed the deprecated `Extension::parse`. The cursor-oriented wire parser is
  now crate-private.
- Removed the deprecated `Extension::write`. Use `Extension::append_to_vec`.
- Removed the deprecated `Resource::from_str`. Use `Resource::parse_text`.
- Removed the deprecated `QR::from_bool` and `QR::to_bool`. Use the `From<bool>`
  and `From<QR>` conversions.
- Removed the deprecated `zones::File::new`. Use `zones::File::try_new`.
- Removed the deprecated `zones::File::into_records`, which discarded error
  detail behind `Result<Vec<Record>, ()>`. Use `File::try_into_records`.
- Removed the exported `bail!` macro, along with the macro itself.
- Removed the `ToUrls` trait and helper module; web clients now configure a
  single `Url`.
- Removed the blocking, single-client `Resolver` (`Resolver::new`,
  `Resolver::new_with_client`, and the synchronous `Exchanger`-based
  `Resolver::lookup`). Use the new async `Resolver::builder()` API.
- Removed `Message.stats` and the `Stats` struct. Transport and connection
  metadata are no longer stored on `Message`, restoring `Message` as a pure DNS
  wire-format struct and eliminating custom equality/hashing workarounds.
  Single-attempt transport metadata is now accessed via `WireResponse.meta`, and
  multi-attempt resolver metadata via `Response.meta.wire`.

## [0.7.0] - 2026-09-03

### Added

- Added asynchronous TCP and UDP clients under the `async-tcp` and `async-udp`
  features, included by the `clients` feature.
- Added persistent TCP connection reuse with keepalive and idle expiry.
- Added reusable HTTP client pools for DoH and JSON clients.
- Added DNS wire encoding for supported answer, authority, and additional records.
- Added opt-in EDNS(0) option encoding for NSID, Client Subnet, COOKIE, TCP
  Keepalive, Padding, and unknown options.
- Added an opt-in DNS-over-TLS client under the `dot` feature, included by the
  `clients` feature, with TLS server-name extraction from `host:port` inputs.
- Added `dig` flags and display output for sending and receiving EDNS(0)
  options.
- Added `dig +dot` support for DNS-over-TLS queries.
- Added client trace logging for transport connection details, HTTP metadata,
  selected server addresses, and request/response sizes, surfaced by
  `dig +verbose`.
- Added `Message::set_extension` as the preferred API for the single EDNS(0)
  extension record.
- Added `Message::append_to_vec`, `Question::append_to_vec`,
  `Record::append_to_vec`, and `Extension::append_to_vec` for appending DNS
  wire-format bytes to caller-provided buffers.
- Added `TryFrom<&[u8]> for Message` as a trait-based companion to
  `Message::from_slice`.
- Added `Resource::parse_text` as the preferred type-disambiguated parser for
  resource text.
- Added regression coverage for transport reuse and reconnect-after-failure behavior.
- Uploaded CI code coverage to Codecov and added a coverage badge to the README.

### Changed

- Deprecated `Extension::write`, `Resource::from_str`, `QR::from_bool`, and
  `QR::to_bool` in favor of naming-guide-compliant alternatives.

## [0.6.0] - 2026-09-02

### Added

- Added fallible `Message::try_add_question`, `File::try_new`, and
  `File::try_into_records` APIs.
- Added typed zone-processing errors with entry and record context.
- Added configurable read and write timeouts for the blocking TCP client and a
  read timeout setter for the UDP client.
- Added parser, client, zone, TCP framing, and malformed-input regression tests.
- Added bounded DoH and JSON response-body handling.
- Added a fuzz smoke test to the standard Rust CI workflow.
- Added all-target and all-feature checks to CI.

### Changed

- Deprecated infallible compatibility APIs while retaining them for migration.
- DoH and JSON clients now require HTTPS and validate response content types.
- DNS serialization now returns errors for unsupported record sections instead of
  panicking.
- Public constructors, parsers, and client behavior now have documented error
  contracts.
- Zone processing errors preserve useful entry and record context.

### Fixed

- Rejected malformed DNS record lengths, EDNS option lengths, compression
  pointers, and oversized encoded names.
- Prevented parser and client paths from panicking on several malformed or empty
  inputs.

## [0.5.1] - 2026-09-02

### Added

- Added deterministic regression tests for malformed DNS packets, compression
  pointers, EDNS data, client configuration, and malformed SOA records.
- Added reproducible nightly `cargo-fuzz` setup and a CI fuzz smoke test.

### Fixed

- Hardened DNS cursor bounds and compressed-name traversal.
- Rejected truncated EDNS option data and malformed DNS record data.
- Rejected invalid URLs and empty DNS client configurations.
- Required HTTPS for DoH and DoH JSON clients.
- Prevented malformed SOA RNAME data from causing a panic.
- Fixed the docs.rs build by enabling `doc_cfg` for docs.rs builds.
- Corrected the `from_slice` fuzz target to call `Message::from_slice`.

## [0.5.0] - 2026-09-02

### Added

- Published the initial documented `0.5.0` release of the DNS parsing library.
- Supported parsing and formatting common DNS record types, IDNA names, EDNS,
  zone files, and the UDP, TCP, DoH, and JSON clients.
- Included stored DNS response test data, integration tests, and fuzzing support.

[Unreleased]: https://github.com/bramp/rustdns/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/bramp/rustdns/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/bramp/rustdns/releases/tag/v0.6.0
[0.5.1]: https://github.com/bramp/rustdns/releases/tag/v0.5.1
[0.5.0]: https://github.com/bramp/rustdns/releases/tag/v0.5.0
