# Changelog

All notable changes to rustdns are documented here.

## [Unreleased]

### Added

- Added asynchronous TCP and UDP clients under the `async-tcp` and `async-udp`
  features, included by the `clients` feature.
- Added persistent TCP connection reuse with keepalive and idle expiry.
- Added reusable HTTP client pools for DoH and JSON clients.
- Added DNS wire encoding for supported answer, authority, and additional records.
- Added regression coverage for transport reuse and reconnect-after-failure behavior.
- Uploaded CI code coverage to Codecov and added a coverage badge to the README.

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

[Unreleased]: https://github.com/bramp/rustdns/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/bramp/rustdns/releases/tag/v0.6.0
[0.5.1]: https://github.com/bramp/rustdns/releases/tag/v0.5.1
[0.5.0]: https://github.com/bramp/rustdns/releases/tag/v0.5.0
