# Rustdns Release Plan

This plan separates compatibility and security fixes from new functionality.
The current baseline is `0.5.1`.

## Release Policy

- `0.5.1`: Security, parser, client, and fuzzing fixes. Complete.
- `0.6.0`: Compatibility-preserving fixes and API documentation. Existing public
  APIs remain available.
- `0.7.0`: New additive features. Existing public APIs, defaults, and data-shape
  compatibility must remain stable.
- `1.0.0`: Deliberate breaking cleanup, Rust 1.85.0, edition 2024, and Cargo
  resolver 3.

For `0.7.0`, do not remove public APIs, change existing method signatures,
change default behavior, add fields that break public struct literals, or add
enum variants that break exhaustive matches. New behavior should be opt-in or
backward-compatible.

## Completed Fixes

- [x] Harden cursor, record-length, EDNS, compression-pointer, and fuzz parsing paths.
- [x] Reject malformed pointers, truncated records, and oversized encoded names.
- [x] Add parser, client, zone, and TCP framing regression tests.
- [x] Add HTTPS-only DoH support and bounded DoH/JSON response bodies.
- [x] Add fallible `try_add_question`, `try_new`, and `try_into_records` APIs.
- [x] Add typed zone-processing errors and contextual diagnostics.
- [x] Replace serialization assertions with returned errors.
- [x] Add fuzz smoke testing to the normal Rust CI workflow.
- [x] Document public constructor and parser error behavior.
- [x] Deprecate infallible compatibility APIs while retaining them for migration.
- [x] Add blocking TCP and UDP timeout configuration.
- [x] Release and tag `0.5.1`.

## Version 0.6.0: Compatibility Fixes

These items improve safety, diagnostics, documentation, and quality without
removing or changing existing public APIs.

### Error Handling And Documentation

- [ ] Complete the remaining compatibility-safe replacement of input-dependent
  panics in client and zone paths.
- [ ] Continue replacing `bail!` in paths where existing typed errors can be used
  without changing public contracts.
- [ ] Document all timeout, retry, server-selection, blocking, and async behavior.
- [ ] Preserve source, entry, record, and parse context in all newly exposed errors.
- [ ] Keep deprecated wrappers documented with their panic/error behavior.

### Quality And Release Gates

- [x] Test all workspace crates with default, no-default, and all-feature configurations.
- [ ] Add MSRV, stable, and beta CI jobs without changing the current MSRV yet.
- [x] Add `cargo check --workspace --all-targets --all-features` to CI.
- [ ] Add dependency advisory, license, and source checks with `cargo-deny` or equivalent.
- [ ] Add a meaningful coverage threshold.
- [ ] Run regular fuzz regressions and retain the bounded CI smoke test.
- [x] Keep `README.md` generated and synchronized with crate documentation.
- [ ] Add `0.6.0` migration notes and release notes.
- [x] Run all test, lint, documentation, audit, and fuzz smoke-test gates.
- [x] Run `cargo publish --dry-run` for `0.6.0`.
- [x] Release and tag `0.6.0`.

## Version 0.7.0: New Additive Features

All features in this section must preserve the existing public API and defaults.
Use new methods, types, modules, or opt-in builders rather than changing public
struct layouts or enum exhaustiveness.

### Network Clients

- [x] Define each low-level client as a single-server, single-protocol exchanger.
- [x] Keep accepting vectors of servers for compatibility, while documenting that
  only the first resolved server is used.
- [x] Add HTTP status-response tests for DoH and JSON clients.
- [ ] Add timeout and retry configuration for HTTP clients.
- [x] Keep one reusable socket or HTTP client per low-level client instance.
- [x] Reuse persistent TCP connections and HTTP connection pools across exchanges.
- [ ] Add additive response and transport metadata accessors.
- [ ] Add new client configuration builders without removing existing constructors.
- [x] Add async TCP and UDP clients as `async-tcp` and `async-udp` features,
  included by `clients`, with mutable sequential exchange APIs.

### DNS And Protocol Features

- [x] Add encoding support for answer, authority, and additional records.
- [x] Add further EDNS options through additive methods or option types.
- [x] Hide low-level EDNS cursor parsers from the public API.
- [x] Add `Message::append_to_vec` as the caller-provided-buffer companion to
  `Message::to_vec`.
- [ ] `Message`: add `TryFrom<&[u8]>` delegating to `Message::from_slice`.
- [ ] `Message`: add focused tests showing `Message::append_to_vec` appends to an existing
  buffer and produces the same message bytes as `Message::to_vec`.
- [ ] `Message`: review public documentation and examples so wire-format encoding is
  described as `to_vec` for allocation and `append_to_vec` for caller-provided
  buffers.
- [ ] Add opt-in DNS-over-TLS or other new transport modules if justified.
- [ ] Review and expose DNS name, question-count, and message-size limits through
  additive validation helpers.
- [ ] Add convenience getters and inspection methods for messages and records.

### Tests And Release

- [ ] Add focused tests for every new feature and every opt-in/default behavior.
- [ ] Complete response status, content type, body size, framing, and malformed
  network-response integration tests.
- [ ] Run `cargo-semver-checks` against `0.6.0` and confirm no unintended breaks.
- [ ] Add `0.7.0` migration notes and release notes.
- [ ] Run the complete quality gates and `cargo publish --dry-run`.
- [ ] Release and tag `0.7.0`.

## Version 1.0.0: Breaking Modernization

### Public API Cleanup

- [ ] Remove deprecated infallible APIs after the migration period.
- [ ] Make fallible APIs the primary constructors and builders.
- [ ] Audit all public methods against the method naming style guide in
  `DEVELOPERS.md` before the `1.0.0` API freeze.
- [ ] `Message`: keep `from_slice`, `to_vec`, and `append_to_vec` as the public
  wire-format naming pattern unless the final API review finds a stronger name.
- [ ] `Extension`: replace public `write(&mut Vec<u8>)` with `append_to_vec` or
  make it crate-private if callers should only encode extensions through
  `Message`.
- [ ] `EdnsOption`: rename crate-private `write(&mut Vec<u8>)` to
  `append_to_vec`.
- [ ] `Record`: keep crate-private `parse` for wire-format parsing, and review
  whether record-level wire encoding should expose `append_to_vec`.
- [ ] `Resource`: decide whether `Resource::from_str(Type, &str)` should remain as the
  context-requiring exception or be replaced with a clearer text-specific name
  such as `parse_text` or `from_str_for_type`.
- [ ] `Resource`: rename crate-private `write_rdata(&mut Vec<u8>)` to
  `append_rdata_to_vec`.
- [ ] `TXT`: keep `FromStr` for text parsing, keep crate-private `parse` for
  wire-format parsing, and rename `write_rdata` to `append_rdata_to_vec`.
- [ ] `SOA`: keep `FromStr` for text parsing, keep crate-private `parse` for
  wire-format parsing, and rename `write_rdata` to `append_rdata_to_vec`.
- [ ] `SOA`: review `rname_to_email` and `email_to_rname` as domain-specific
  conversion helpers; keep them named helpers unless trait conversions become clearer.
- [ ] `MX`: keep `FromStr` for text parsing, keep crate-private `parse` for
  wire-format parsing, and rename `write_rdata` to `append_rdata_to_vec`.
- [ ] `SRV`: keep `FromStr` for text parsing, keep crate-private `parse` for
  wire-format parsing, and rename `write_rdata` to `append_rdata_to_vec`.
- [ ] `Question`: replace the `Question::as_vec()` TODO with a naming-guide-compliant
  API, such as `append_to_vec`, if question-level encoding remains useful.
- [ ] `QR`: add `From<bool> for QR` and `From<QR> for bool`, then decide whether to
  retain or deprecate `QR::from_bool` and `QR::to_bool`.
- [ ] `DNSReadExt`: keep `read_qname`, `read_type`, and `read_class` as the
  low-level cursor-reading convention.
- [ ] `Message::write_qname`: rename crate-private qname encoding to
  `append_qname_to_vec` or move it onto the future encoder abstraction.
- [ ] Zone `File`: keep `try_new` for fallible construction and `FromStr` for
  zone-file text parsing; do not add inherent `parse` aliases.
- [ ] Zone `Record`: keep `FromStr` for zone-file text parsing; do not add
  inherent `parse` aliases.
- [ ] Replace multi-server low-level clients with single-server client types or
  constructors, with migration guidance for existing callers.
- [ ] Add a higher-level resolver/orchestration client for server pools, retries,
  failover, concurrent queries, and Happy Eyeballs-style address selection.
- [ ] Keep UDP-to-TCP fallback in the higher-level DNS orchestration layer rather
  than embedding it in the low-level UDP client.
- [ ] Replace the stateless DNS encoding helpers with a message encoder that can
  own compression state, message-size limits, EDNS-aware sizing, and canonical
  DNSSEC-style encoding options.
- [ ] Add an explicit DNS encoding options API, including opt-in name
  compression, while preserving semantic message round trips.
- [ ] Replace `Result<T, ()>` and remaining compatibility wrappers with structured
  public errors.
- [ ] Replace remaining macro-backed parser and protocol errors with structured
  `thiserror` errors, then remove or privatize the exported `bail!` macro.
- [ ] Complete removal of input-dependent `expect`, `unwrap`, assertions, and
  unchecked indexing from production input paths.
- [ ] Perform a final public API and semver compatibility review.

### Rust Platform Migration

- [ ] Set `rust-version = "1.85"` for the root crate and workspace tools.
- [ ] Migrate the root crate and workspace tools from edition 2018 to edition 2024.
- [ ] Set Cargo resolver 3 at the workspace level.
- [ ] Resolve edition migration diagnostics without unrelated refactoring.
- [ ] Move lint policy into workspace configuration where supported.
- [ ] Ratchet toward `missing_docs`, `missing_debug_implementations`, and
  `unsafe_code = "forbid"`.
- [ ] Replace `lazy_static` with `std::sync::LazyLock` if compatible with the MSRV.
- [ ] Review whether `byteorder`, `num-derive`, `educe`, and `async-trait` remain needed.
- [ ] Run `cargo tree --duplicates` and remove avoidable duplicate dependency versions.

### Final Quality And Release

- [ ] Add and enforce the Rust 1.85 MSRV, stable, and beta CI jobs.
- [ ] Complete the full feature matrix, fuzz regressions, coverage, and dependency checks.
- [ ] Run `cargo-semver-checks` against the previous release.
- [ ] Add `1.0.0` migration notes and release notes.
- [ ] Run `cargo publish --dry-run` for `1.0.0`.
- [ ] Release and tag `1.0.0`.

## Definition Of Done

- Compatibility fixes are clearly separated from new features.
- `0.7.0` adds functionality without breaking existing callers or defaults.
- Security and parser protections remain covered by deterministic tests and fuzzing.
- Public errors, timeout behavior, and client semantics are documented.
- Every release passes formatting, Clippy, rustdoc, tests, dependency checks, and
  the relevant semver review.
