# Rust Modernization Plan

This plan brings rustdns up to modern Rust standards while preserving a clear compatibility path from the current `0.5.0` release.

## Goals

- Make malformed DNS input unable to panic or cause unbounded work.
- Make public and network-facing APIs return useful errors instead of panicking.
- Improve client security, especially DoH transport and response handling.
- Establish an explicit MSRV, edition, lint, dependency, and CI policy.
- Improve test coverage and document the resulting API contracts.
- Make intentional breaking API changes in a well-defined major release.

## Release Strategy

- `0.5.1`: Security and panic fixes that preserve existing public signatures where practical.
- `0.6.0`: Additive APIs, typed-error alternatives, lint, CI, and compatibility improvements while retaining the existing edition/toolchain policy.
- `1.0.0`: Adopt Rust 1.85.0 and edition 2024, then remove deprecated APIs and make breaking API improvements permanent.

The `1.0.0` compatibility baseline is **Rust 1.85.0 with edition 2024**. These are intentionally adopted together: Rust 1.85.0 is the first stable compiler supporting edition 2024. The complete modernization requires a major version because changing methods such as `Message::add_question` to return `Result`, replacing `Result<T, ()>` with a structured error, removing legacy APIs, and raising the MSRV changes the public contract. Use `cargo-semver-checks` before the `1.0.0` release.

## Phase 1: Compatibility and Baseline Policy

- [ ] Choose and document the target `1.0.0` MSRV: Rust 1.85.0.
- [ ] Record supported operating systems, runtimes, and feature combinations.
- [ ] Add `rust-version = "1.85"` to package metadata as part of the `1.0.0` migration.
- [ ] Add CI jobs for MSRV, stable, and beta Rust.
- [ ] Add `cargo check --workspace --all-targets --all-features`.
- [ ] Add dependency advisory, license, and source checks with `cargo-deny` or an equivalent tool.
- [ ] Record baseline test, documentation, Clippy, and coverage results.

## Phase 2: Parser Safety and Robustness

These changes should happen before broad API or edition work because they address untrusted DNS input.

- [x] Replace unchecked cursor arithmetic in `src/io.rs` with checked bounds handling.
- [ ] Validate every length before advancing or consuming packet data.
- [x] Validate EDNS `RDLEN` against the remaining packet bytes.
- [x] Rewrite compressed-name traversal iteratively, or enforce a strict pointer/depth/work budget.
- [ ] Reject invalid forward pointers, pointer loops, unsupported label encodings, and out-of-range pointers.
- [ ] Validate both per-label and total DNS name lengths when encoding and decoding.
- [x] Add regression tests for truncated packets, oversized lengths, malformed pointers, pointer loops, and long pointer chains.
- [ ] Extend the fuzz target with assertions that parsing never panics or performs unbounded work.

## Phase 3: Remove Input-Dependent Panics

- [ ] Replace `expect`, `unwrap`, assertions, and unchecked indexing on input-dependent paths.
- [ ] Make invalid domains return an error from the message-building API.
- [x] Reject empty server collections in TCP, UDP, DoH, and JSON client constructors.
- [x] Make URL parsing return its existing `io::Result` or a more specific error instead of unwrapping.
- [ ] Handle malformed SOA RNAME values without panicking.
- [ ] Replace serialization assertions for unsupported record sections with returned errors.
- [x] Add tests for invalid URLs, empty client configuration, and malformed records. Add invalid-domain and unsupported-message tests with the fallible API changes.

## Phase 4: Network Client Security and Behavior

- [x] Require `https` URLs in the DoH client and use an HTTPS-only connector.
- [x] Add a test proving that an `http://` DoH endpoint is rejected.
- [ ] Bound DoH and JSON response bodies before collecting them.
- [ ] Validate response status, content type, DNS message size, framing, and question consistency.
- [ ] Decide whether clients fail over across configured servers; implement and document that behavior.
- [ ] Document timeout, connection, retry, and server-selection semantics.
- [ ] Add TCP framing tests, including truncated and oversized frames.

## Phase 5: Error Model and API Design

- [ ] Replace `Result<Vec<Record>, ()>` in zone processing with a structured error type.
- [ ] Preserve zone source context, record context, and useful parse locations in errors.
- [ ] Replace panic-based handling of missing `$ORIGIN`, TTL, class, and invalid relative names with typed errors.
- [ ] Introduce additive fallible APIs where possible, such as a fallible question-builder method.
- [ ] Deprecate incompatible infallible APIs before removing them in `1.0.0`.
- [ ] Replace the custom `bail!` macro incrementally with typed `thiserror` variants where this improves the public contract.
- [ ] Document error behavior for every public constructor and parser.

## Phase 6: Tests, Fuzzing, and Quality Gates

- [x] Add focused unit tests for parser boundaries, compression, EDNS, and error preservation. Add name-validation tests with the fallible API changes.
- [x] Add client tests for URL validation and empty configuration. Add response-limit, content-type, and status tests when body bounding is implemented.
- [x] Add a zone-processing test for malformed SOA RNAME panic prevention. Add tests for the remaining formerly panicking conditions with typed zone errors.
- [ ] Test all workspace crates with default, no-default, and all-feature configurations.
- [ ] Run fuzzing regularly and add scheduled CI fuzz jobs if runtime permits.
- [ ] Set a meaningful coverage threshold after the new cases are in place.
- [ ] Keep formatting, Clippy, rustdoc warnings, and audit checks as required CI gates.

## Phase 7: Rust Edition and Dependency Modernization

Do this after behavior and API contracts are covered by tests, as part of the `1.0.0` compatibility migration.

- [ ] Migrate the root crate and workspace tools from edition 2018 to edition 2024.
- [ ] Set `rust-version = "1.85"` for the root crate and workspace tools.
- [ ] Set Cargo resolver 3 at the workspace level.
- [ ] Resolve edition migration diagnostics without unrelated refactoring.
- [ ] Move lint policy into workspace configuration where supported.
- [ ] Ratchet toward `missing_docs`, `missing_debug_implementations`, and `unsafe_code = "forbid"`.
- [ ] Replace `lazy_static` with `std::sync::LazyLock` if compatible with the chosen MSRV.
- [ ] Review whether `byteorder`, `num-derive`, `educe`, and `async-trait` are still needed.
- [ ] Run `cargo tree --duplicates` and remove avoidable duplicate dependency versions.

## Phase 8: Documentation and Release

- [ ] Document public types, constructors, feature flags, runtime requirements, and security expectations.
- [ ] Update examples to demonstrate proper error handling.
- [ ] Keep `README.md` generated and synchronized with the crate documentation.
- [ ] Add migration notes for deprecated and changed APIs.
- [ ] Run the complete CI matrix, fuzz regressions, and documentation tests.
- [ ] Run `cargo semver-checks` against the previous release.
- [ ] Review the changelog and publish release notes.
- [ ] Release `0.5.1` with safe compatible fixes, then `0.6.0` for additive modernization.
- [ ] Release `1.0.0` with Rust 1.85.0, edition 2024, and the finalized breaking API cleanup.

## Definition of Done

- No parser or client path panics on malformed or user-provided input.
- DNS parsing has explicit bounds and compression-work limits.
- DoH cannot silently use plaintext HTTP and HTTP bodies are bounded.
- Zone processing returns actionable typed errors.
- MSRV, edition, feature support, and lint policy are documented and enforced in CI.
- The focused tests, fuzz regressions, full workspace tests, Clippy, rustdoc, formatting, and dependency checks pass.
- Public API changes have deprecations or migration guidance and are released under the appropriate semver version.
