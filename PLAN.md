# Rust Modernization Plan

This plan takes rustdns from the current `0.5.1` release through an additive
`0.6.0` release and then a breaking `1.0.0` release.

## Release Policy

- `0.5.1`: Compatible parser, client, and fuzzing safety fixes. Complete.
- `0.6.0`: Additive APIs, stronger behavior, documentation, tests, and tooling.
  Existing public APIs and the current edition/toolchain policy remain usable.
- `1.0.0`: Breaking API cleanup, Rust 1.85.0, edition 2024, and Cargo resolver 3.

The `1.0.0` compatibility baseline is **Rust 1.85.0 with edition 2024**. Rust
1.85.0 is the first stable compiler supporting edition 2024. Use
`cargo-semver-checks` before the major release.

## Completed Baseline

- [x] Harden cursor, record-length, EDNS, compression-pointer, and fuzz parsing paths.
- [x] Add parser, client, zone, and TCP framing regression tests.
- [x] Add HTTPS-only DoH support and bounded DoH/JSON response bodies.
- [x] Add fallible `try_add_question`, `try_new`, and `try_into_records` APIs.
- [x] Add typed zone-processing errors and replace serialization assertions with errors.
- [x] Add fuzz smoke testing to the normal Rust CI workflow.
- [x] Release and tag `0.5.1`.

## Version 0.6.0: Additive Modernization

All work in this section should preserve existing public APIs unless an additive
alternative is provided first.

### API And Error Handling

- [x] Deprecate infallible compatibility APIs such as `Message::add_question` and
  `File::new`, directing callers to their fallible alternatives.
- [ ] Preserve zone source context, record context, and useful parse locations in errors.
- [ ] Replace remaining input-dependent panics in client and zone paths with
  fallible alternatives where possible.
- [ ] Replace the custom `bail!` macro incrementally with typed `thiserror` variants
  where this improves the public contract.
- [ ] Document error behavior for every public constructor and parser.

### Network Clients

- [ ] Decide and document server-selection, timeout, retry, and failover semantics.
- [ ] Add opt-in client failover without changing current default server behavior.
- [ ] Add HTTP status-response integration tests for DoH and JSON clients.
- [ ] Add public client configuration methods or builders for timeouts and retries.
- [ ] Add useful response and transport metadata accessors without changing existing
  struct literals or enum matching behavior.

### DNS And Protocol Features

- [ ] Add encoding support for currently unsupported answer, authority, and
  additional records without changing existing parsing APIs.
- [ ] Add further EDNS option support through additive methods or option types.
- [ ] Add validation tests for response status, content type, body size, framing,
  and malformed network responses.
- [ ] Review DNS name, question-count, and message-size limits at API boundaries.

### Tests, Fuzzing, And Quality Gates

- [ ] Test all workspace crates with default, no-default, and all-feature configurations.
- [ ] Run fuzzing regularly and retain the CI smoke test with an explicit input bound.
- [ ] Add a meaningful coverage threshold after the important cases are covered.
- [ ] Add dependency advisory, license, and source checks with `cargo-deny` or equivalent.
- [ ] Add CI checks for `cargo check --workspace --all-targets --all-features`.
- [ ] Record baseline test, documentation, Clippy, and coverage results.

### Documentation And Release

- [ ] Document public types, constructors, feature flags, runtime requirements,
  security guarantees, and blocking/async behavior.
- [ ] Update examples to demonstrate fallible APIs and proper error handling.
- [ ] Keep `README.md` generated and synchronized with crate documentation.
- [ ] Add `0.6.0` migration notes and release notes.
- [ ] Run the complete test, lint, documentation, audit, and fuzz smoke-test gates.
- [ ] Run `cargo publish --dry-run` for `0.6.0`.
- [ ] Release and tag `0.6.0`.

## Version 1.0.0: Breaking Modernization

### Public API Cleanup

- [ ] Remove deprecated infallible APIs after the `0.6.0` deprecation period.
- [ ] Make fallible APIs the primary constructors and builders.
- [ ] Replace `Result<T, ()>` and remaining compatibility error wrappers with
  structured public errors.
- [ ] Decide whether public enum and struct changes require a final compatibility
  review or additional migration types.
- [ ] Complete removal of input-dependent `expect`, `unwrap`, assertions, and
  unchecked indexing from production input paths.

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

- [ ] Add and enforce MSRV, stable, and beta CI jobs.
- [ ] Complete the full feature matrix, fuzz regressions, coverage, and dependency checks.
- [ ] Run `cargo-semver-checks` against the previous release.
- [ ] Add `1.0.0` migration notes and release notes.
- [ ] Run `cargo publish --dry-run` for `1.0.0`.
- [ ] Release and tag `1.0.0`.

## Definition Of Done

- No production parser or client path panics on malformed or user-provided input.
- DNS parsing has explicit bounds and compression-work limits.
- DoH cannot silently use plaintext HTTP and HTTP bodies are bounded.
- Fallible APIs and typed errors are documented and available before breaking cleanup.
- MSRV, edition, feature support, and lint policy are documented and enforced in CI.
- Public API changes have migration guidance and are released under the appropriate
  semver version.
