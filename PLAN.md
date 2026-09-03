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

- [ ] Decide and document server-selection, timeout, retry, and failover semantics.
- [ ] Add opt-in client failover without changing current default server behavior.
- [ ] Add HTTP status-response integration tests for DoH and JSON clients.
- [ ] Add timeout and retry configuration for HTTP clients.
- [ ] Reuse persistent TCP connections and HTTP connection pools across exchanges.
- [ ] Add additive response and transport metadata accessors.
- [ ] Add new client configuration builders without removing existing constructors.

### DNS And Protocol Features

- [ ] Add encoding support for answer, authority, and additional records.
- [ ] Add further EDNS options through additive methods or option types.
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
