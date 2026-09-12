# Rustdns Release Plan

This plan tracks remaining implementation tasks and release milestones for `rustdns`.
For architectural specifications, invariants, and design contracts, see [DESIGN.md](DESIGN.md).

The current baseline is `0.7.0`.

## Release Policy

- `0.5.1`: Security, parser, client, and fuzzing fixes. *(Complete)*
- `0.6.0`: Compatibility-preserving fixes and API documentation. *(Complete)*
- `0.7.0`: Additive features (resolver, DNSSEC trust, WASM JSON decoupling). *(In progress)*
- `1.0.0`: Deliberate breaking cleanup, Rust 1.85.0, edition 2024, and Cargo resolver 3.

---

## 1. Version 1.0.0: Public API Cleanup

- [ ] Enforce `MAX_DNS_MESSAGE_LEN` in `Message::to_vec` and document across transports.
- [ ] Tighten text resource parsing: validate domain names, SOA rnames, and TXT escapes.
- [ ] Deprecate [src/from_str.rs](src/from_str.rs) and unify text RDATA parsing with `zones::parse_rdata`.
- [ ] Add validated constructors/builders for public DNS and EDNS structs.
- [ ] Replace broad `Error::InvalidArgument(String)` with typed error variants.
- [ ] Audit all public methods against naming conventions in [DEVELOPERS.md](DEVELOPERS.md).
- [ ] Replace stateless encoding helpers with a stateful message encoder (compression, size limits, EDNS sizing).
- [ ] Add explicit DNS encoding options API (opt-in name compression).
- [ ] Complete removal of input-dependent `expect`, `unwrap`, and assertions in production paths.
- [ ] Final public API and semver compatibility audit.
- [ ] Switch the features tcp/udp and async-tcp/async-udp. The default tcp should be async like all the others.
- [ ] Let's move the EDNS types into a edns submodule (e.g EdnsCookie -> edns::Cookie)
- [ ] Change the API to have getters and setters (encapsulate struct fields where appropriate). - Is this a good idea?

---

## 2. Resolver Milestones

The core resolver architecture, deadline propagation, response correlation, failover, backoff, and verbatim exchange are implemented (see [DESIGN.md](DESIGN.md#1-resolver-architecture--design-contract)). The remaining resolver work is organized into the following feature milestones:

### 2.1 Cache And Negative Caching (RFC 1035 / RFC 2308)

- [ ] Define pluggable `DnsCache` trait supporting in-memory and external cache backends.
- [ ] Generate cache keys from question name, type, class, and relevant query flags.
- [ ] Support positive TTL caching with configurable min/max TTL clamps and expiration.
- [ ] Implement negative caching for `NXDomain` and NODATA (`NoError` with empty answers) using SOA minimum TTL (RFC 2308).
- [ ] Short-circuit network attempts on cache hit and set `from_cache: true` in `ResponseMeta`.

### 2.2 RFC 8914 Extended DNS Errors (EDE) & Classification

- [ ] Add EDNS Option 15 (`ExtendedDnsError`) parsing and serialization in [src/edns.rs](src/edns.rs).
- [ ] Integrate EDE into `classify()` in [src/clients/resolver/async.rs](src/clients/resolver/async.rs):
  - EDE 22 (`No Reachable Authority`): trigger upstream failover.
  - EDE 18 (`Prohibited`) / EDE 19 (`Blocked`): treat as definitive policy signals without retrying.
- [ ] Surface EDE information in `ResponseMeta` and `dig` CLI output.

### 2.3 Upstream Health & Circuit Breaking

- [ ] Track smoothed round-trip time (SRTT), latency history, and error counts per upstream.
- [ ] Implement circuit breaker state machine (Closed, Open, Half-Open probe) with configurable failure thresholds and cooldown.
- [ ] Wire circuit breaker state into `Resolver::is_eligible`.

### 2.4 Advanced Resolution Strategies

- [ ] `Strategy::Fastest`: Route queries to the upstream with the lowest decayed SRTT.
- [ ] `Strategy::Race`: Query multiple eligible upstreams in parallel; return the first valid answer and cancel losing attempts.
- [ ] `Strategy::Staggered`: Query the primary upstream and launch backup queries after a configured delay.

### 2.5 Upstream Configuration & Bootstrap Decoupling

- [ ] Define structured `Upstream` configuration type (stable ID, endpoint, bootstrap IPs, TLS settings, weight, preferences).
- [ ] Decouple bootstrap resolution for DoH/DoT hostnames to prevent circular resolution dependencies.

### 2.6 Concurrency & Ergonomics Enhancements

- [x] Dispatch `A` and `AAAA` queries concurrently in `Resolver::lookup_with_deadline`.
- [ ] Add convenience getters on `Message` and `Response` (e.g. filtered records, IPs, CNAME chains).
- [ ] Introduce typed `TransportError` context reporting endpoint, protocol, and I/O cause.

---

## 3. DNSSEC & Upstream Trust

Core trust model, transport security classifications, and fail-closed resolution are complete (see [DESIGN.md](DESIGN.md#2-dnssec-support--upstream-trust-architecture)). Remaining tasks:

- [x] Add `Type::Unknown(u16)` to `Type` with `code()` and `From<u16>` / `From<Type>`, and `Resource::Raw` fallback in [src/types.rs](src/types.rs) so unknown type codes decode safely when `DO=1` is set.
- [x] Add `Type::NSEC3` (50) and `Type::NSEC3PARAM` (51) to `Type`.
- [x] Implement wire encoding and decoding for `NSEC3` and `NSEC3PARAM` (RFC 5155) in [src/resource.rs](src/resource.rs).
- [x] Implement `DNSKEY::key_tag()` (RFC 4034 Appendix B) and `DS::calculate()` for SHA-1, SHA-256, and SHA-384.
- [x] Canonical RRset wire serialization (`canonical_name_wire`, `canonical_owner_for_rrsig`, `construct_signed_data`) in `src/dnssec/canonical.rs`.
- [x] Cryptographic signature verification using `ring` (Algorithms 8, 10, 13, 14, 15) in `src/dnssec/crypto.rs` and `src/dnssec/rrset_validator.rs`.
- [x] Official IANA Root Zone Trust Anchors (KSK 20326 and KSK 38636) and `TrustStore` in `src/dnssec/anchor.rs`.
- [x] Iterative chain-of-trust delegation validator and DNSKEY/DS caching in `src/dnssec/chain.rs`.
- [x] Wire `DnssecMode::ValidateLocal` into `Resolver` with automatic chain validation.
- [x] Add CLI flags to [dig/main.rs](dig/main.rs) (`+dnssec`, `+ad`, `+noad`, `+cd`, `+validate`) and display `SecurityStatus`.
- [x] Unit tests for `is_secure_channel` across all clients.
- [x] Round-trip wire tests for `NSEC3`, `NSEC3PARAM`, and `Resource::Raw`.
- [x] Authenticated Denial of Existence proofs (NSEC and NSEC3 closest encloser / wildcard proofs) in `src/dnssec/denial.rs`.
- [ ] DNSSEC signing and key generation for RSA, ECDSA, and Ed25519 (cryptographic validation is complete).

---

## 4. Domain Name Modeling (`Name` Type)

Transition from stringly-typed domain names (`String` / `&str`) to a strongly-typed, canonical wire-first `Name` abstraction (Pattern 1):

### Design: Canonical Wire-First `Name`

- **Representation**: Internally stores a normalized, lowercase, wire-format ASCII (Punycode) FQDN ending with a trailing dot (`.`):
  ```rust
  #[derive(Clone, Eq, PartialEq, Hash)]
  pub struct Name {
      ascii: String,
  }
  ```
- **Invariants**:
  1. Valid IDNA / Punycode: 100% ASCII octets.
  2. Lowercase: Case-normalized per RFC 4034 §6.1.
  3. Bounded: Validated against DNS label ($\le 63$ octets) and name ($\le 255$ octets) limits.
  4. FQDN: Always has a trailing dot (`.`), with root represented as `"."`.
- **Ordering**: Naturally implements `Ord` and `PartialOrd` via Canonical DNS Name Order (RFC 4034 §6.1, `crate::names::canonical_cmp`).
- **Ergonomics & Performance**:
  - `as_ascii(&self) -> &str` / `as_bytes(&self) -> &[u8]`: Zero-cost access for wire encoders and crypto hashers.
  - `to_unicode(&self) -> String`: Converts back to user-friendly Unicode representation on demand (e.g. `🍕.ws.`).
  - Implements `Display` (displaying Unicode for human readability), `FromStr`, and `TryFrom<&str>`.
  - Hierarchy methods: `parent(&self) -> Option<Name>`, `count_labels(&self) -> u8`, `is_subdomain_of(&self, &Name) -> bool`.

### Tasks

- [ ] Implement `Name` struct in [src/names.rs](src/names.rs) upholding all canonical wire invariants.
- [ ] Add unit tests for `Name` parsing, validation bounds, IDNA roundtrips, and RFC 4034 canonical ordering.
- [ ] Adopt `Name` in internal DNSSEC modules (`ChainValidator`, `DnssecCache`, `rrset_validator`) to eliminate repeated normalization and string allocations.
- [ ] Plan public API evolution: migrate `Question.name` and `Record.name` from `String` to `Name` (or accept `Into<Name>`).

---

## 5. Zone File Parser Enhancements (RFC Conformance)

Authoritative root zone (`root.zone`) and root hints (`named.root`) are supported (see [DESIGN.md](DESIGN.md#5-zone-file-parser--rfc-conformance-specification)). Remaining tasks for general master files:

- [ ] Support `$INCLUDE <path> [<domain>]` directive with cyclic include guards (RFC 1035 §5).
- [ ] Add quoted string parsing and character escape sequences (`\`, `\DDD`) in [src/zones/zones.pest](src/zones/zones.pest).
- [ ] Support standard BIND duration abbreviations (`w`, `d`, `h`, `m`, `s`) in `$TTL` and record TTLs.
- [ ] Add `TXT`, `SPF`, `SRV`, `NSEC3`, and `NSEC3PARAM` grammar to [src/zones/zones.pest](src/zones/zones.pest) and AST parser.
- [ ] Enforce RFC 2181 §5.2 TTL consistency across RRsets in [src/zones/process.rs](src/zones/process.rs).
- [ ] Unify [src/from_str.rs](src/from_str.rs) with `zones::parse_rdata` and deprecate duplicate regex parsers.
- [ ] Validate domain label ($\le 63$) and name ($\le 255$) lengths during zone processing.
- [ ] Add streaming `File::from_reader` iterator for memory-efficient large zone parsing.

---

## 6. Performance Benchmarking & Allocation Profiling

Harness and profiling architecture defined in [DESIGN.md](DESIGN.md#4-performance-benchmarking--allocation-profiling-design).

- [ ] Add `criterion` and `dhat` to `[dev-dependencies]` in [Cargo.toml](Cargo.toml).
- [ ] Define `dns_pipeline` and `allocations` bench targets in [Cargo.toml](Cargo.toml).
- [ ] Implement end-to-end and micro benchmarks in pipeline suite (in-memory roundtrip, loopback UDP).
- [ ] Implement allocation tracker and DHAT profiler runner (call counts, cumulative and peak bytes).
- [ ] Run baseline benchmarks and profile string allocations in `normalise_domain` and `read_qname`.

---

## 7. Fuzzing Strategy

- [ ] **Zone File Fuzzing (`fuzz_zones`)**: Fuzz Pest grammar, preprocessor bracket counting, and `Record::from_str`.
- [x] **Round-Trip Serialization (`from_slice`)**: Exercised in [fuzz/fuzz_targets/from_slice.rs](fuzz/fuzz_targets/from_slice.rs).
- [x] **Structured Encoding and Limits (`encode`)**: Exercised in [fuzz/fuzz_targets/encode.rs](fuzz/fuzz_targets/encode.rs).
- [x] **Text Resource Parsing (`from-str`)**: Exercised in [fuzz/fuzz_targets/from-str.rs](fuzz/fuzz_targets/from-str.rs).
- [x] **DoH JSON Client Parsing (`json`)**: Exercised in [fuzz/fuzz_targets/json.rs](fuzz/fuzz_targets/json.rs).
- [x] **EDNS Option Parsing (`edns`)**: Exercised in [fuzz/fuzz_targets/edns.rs](fuzz/fuzz_targets/edns.rs).
- [ ] **Display / Formatter Safety**: Verify `Display` and `Debug` never panic on arbitrary parsed records.
- [ ] **Continuous Fuzzing Integration**: Expand corpus seeds and CI smoke tests.

---

## 8. Rust Platform & Release Milestones

- [ ] Move lint policy into workspace configuration.
- [ ] Ratchet toward `missing_docs`, `missing_debug_implementations`, and `unsafe_code = "forbid"`.
- [ ] Replace `lazy_static` with `std::sync::LazyLock`.
- [ ] Review necessity of `byteorder`, `num-derive`, `educe`, and `async-trait`.
- [ ] Clean up duplicate dependency versions (`cargo tree --duplicates`).
- [ ] Add dependency license and source auditing via `cargo-deny`.
- [ ] Enforce test coverage threshold in CI.
- [ ] Run `cargo-semver-checks` against previous release.
- [ ] Publish `1.0.0` release notes and tag.

---

## 9. Advanced Protocol Extensions

- [ ] Implement zone transfer protocols: AXFR (RFC 5936) and IXFR (RFC 1995).
- [ ] Implement transaction signatures: TSIG (RFC 2845) and SIG(0) (RFC 2931).
- [x] EDNS(0) NSID (RFC 7873) and COOKIE (RFC 7873) options.

---

## 10. Tooling, Examples, and Architecture

- [ ] Server-side examples: demonstrate handling, routing, and responding to incoming DNS queries with `rustdns`.
- [ ] Implement more `dig` CLI features, such as iterative delegation tracing (`+trace`).
- [ ] Runtime-independence: decouple core transports from Tokio to support alternative async runtimes (e.g. `smol`, `async-std`) and pure WASM environments.
- [ ] Evaluate converting binary parsing from manual byteorder readers to a zero-copy parser (e.g., `nom` or `winnow`).

## Definition Of Done

- Compatibility fixes are clearly separated from new features.
- `0.7.0` adds functionality without breaking existing callers or defaults.
- Security and parser protections remain covered by deterministic tests and fuzzing.
- Public errors, timeout behavior, and client semantics are documented.
- Every release passes formatting, Clippy, rustdoc, tests, dependency checks, and
  the relevant semver review.
