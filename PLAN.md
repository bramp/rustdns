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

- [x] Enforce `MAX_DNS_MESSAGE_LEN` in `Message::to_vec` and document across transports.
- [x] Tighten text resource parsing: validate domain names, SOA rnames, and TXT escapes.
  - [x] Parse TXT/SPF quoting and RFC 1035 escapes with Pest.
  - [x] Validate SOA mailbox labels with `Rname`, preserving escaped octets through text, zone, wire, and DNSSEC paths.
- [x] Make record text parsing opt-in via `text` for wire-only builds, with `zones` and `json` enabling it automatically.
- [x] Migrate the remaining RDATA text parsers to Pest, sharing grammar with zone parsing where appropriate and retaining `FromStr` entry points (TXT/SPF already use Pest).
- [x] Consolidate text and zone RDATA parsing under `text`, retaining `FromStr` entry points and unresolved zone names.
  - [x] Share borrowed SOA fields and numeric parsing between core and zone records.
  - [x] Share MX, SRV, RRSIG, and NSEC fields; reuse core DS, DNSKEY, and ZONEMD parsers.
- [ ] Add validated constructors/builders for public DNS and EDNS structs.
- [ ] Replace broad `Error::InvalidArgument(String)` with typed error variants.
- [ ] Audit all public methods against naming conventions in [DEVELOPERS.md](DEVELOPERS.md).
- [ ] Replace stateless encoding helpers with a stateful message encoder (compression, size limits, EDNS sizing).
- [ ] Add explicit DNS encoding options API (opt-in name compression).
- [ ] Complete removal of input-dependent `expect`, `unwrap`, and assertions in production paths.
- [ ] Final public API and semver compatibility audit.
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

The core APIs and cryptographic verification are implemented (see [DESIGN.md](DESIGN.md#2-dnssec-support--upstream-trust-architecture)).
Completion requires executable evidence for the trust boundaries below, not just isolated cryptographic tests.
Use test-driven development: add a focused failing regression or conformance test before each behavior change, then implement and run the relevant feature matrix.

- [x] Add `Type::Unknown(u16)` to `Type` with `code()` and `From<u16>` / `From<Type>`, and `Resource::Raw` fallback in [src/types.rs](src/types.rs) so unknown type codes decode safely when `DO=1` is set.
- [x] Add `Type::NSEC3` (50) and `Type::NSEC3PARAM` (51) to `Type`.
- [x] Implement wire encoding and decoding for `NSEC3` and `NSEC3PARAM` (RFC 5155) in [src/resource.rs](src/resource.rs).
- [x] Implement `DNSKEY::key_tag()` (RFC 4034 Appendix B) and `DS::calculate()` for SHA-1, SHA-256, and SHA-384.
- [ ] Verify and finish canonical RRset wire serialization in `src/dnssec/canonical.rs`.
  - [x] Sort by canonical RDATA octets, not the preceding RDLENGTH field, and suppress duplicate RRs.
  - Test against independent signed-data vectors, including variable-length RDATA, escaped labels, mixed case, and wildcard owners.
- [ ] Verify RRset metadata and DNSKEY eligibility before signature validation.
  - Test owner/class/type consistency, RRSIG label counts and signer scope, TTL bounds, protocol and zone-key/revoke flags, and serial-time validity boundaries.
- [x] Cryptographic signature verification using `ring` (Algorithms 8, 10, 13, 14, 15) in `src/dnssec/crypto.rs` and `src/dnssec/rrset_validator.rs`.
  - [x] Verify a frozen, independently published root DNSKEY RRset/RRSIG against the IANA KSK-2017 anchor at a fixed historical validation time; reject a tampered signature.
  - [ ] Add independent positive interoperability vectors for every supported algorithm, not just successful self-generated signatures or malformed-key tests.
- [x] Official IANA Root Zone Trust Anchors (KSK 20326 and KSK 38636) and `TrustStore` in `src/dnssec/anchor.rs`.
- [ ] Finish and verify the chain-of-trust delegation validator and DNSKEY/DS caching in `src/dnssec/chain.rs`.
  - [x] Authenticate every DS RRset at the child owner using a strictly ancestral signer; never accept a missing DS signature.
  - [x] Try all eligible keys and signatures during rollovers, including key-tag collisions.
  - [x] Require authenticated denial of DS at a delegation before classifying unsigned answers as insecure; never let parent Opt-Out proofs override a more-specific local trust anchor.
  - [x] Bound cache size and lifetime and revalidate cached data against the current trust store and signature validity period.
  - [x] Bound recursive query, proof scanning, and signature-verification work using a shared deadline and work budget.
- [x] Verify `DnssecMode::ValidateLocal` integration with `Resolver` using local signed delegation fixtures.
  - Cover secure positive answers, authenticated unsigned delegations, NODATA/NXDOMAIN, aliases, wildcard expansion, stripped signatures, forged AD flags, and bogus chains.
  - Dependency and primary queries set CD/DO; local validation ignores upstream AD.
- [x] Verify upstream-trust policy for both AD=0 and AD=1 on authenticated, loopback, untrusted, and explicitly trusted transports.
  - Exercise the full transport/AD/policy/require-secure matrix through exchange, query, and lookup; test failover, SERVFAIL precedence, and DNSSEC-off behavior.
  - Derive classification from the winning wire response, not the exchanger's advertised security or earlier attempts.
  - Preserve caller-selected AD=0 acceptance with `require_secure: false`, including on plaintext; document the AD-stripping limitation.
- [x] Add CLI flags to [dig/main.rs](dig/main.rs) (`+dnssec`, `+ad`, `+noad`, `+cd`, `+validate`) and display `SecurityStatus`.
- [x] Unit tests for `is_secure_channel` across all clients.
- [x] Round-trip wire tests for `NSEC3`, `NSEC3PARAM`, and `Resource::Raw`.
- [x] Integrate authenticated NSEC/NSEC3 denial into local response validation in `src/dnssec/denial.rs`.
  - Local signed regressions cover closest-encloser, next-closer, wildcard, NODATA, NXDOMAIN, unsigned delegation, and NSEC3 Opt-Out cases.
  - Reject mismatched proof parameters, unsupported flags, invalid hash lengths, missing/tampered proofs, CNAME loops, and conflicting alias targets.
  - Test NSEC3 boundaries at 128/129 proof records and 150/151 iterations. A validator has a shared 1,024-unit work budget.
- [ ] Broaden denial interoperability/conformance coverage before claiming full DNSSEC support.
  - External fixture suites are deferred; retain conservative rejection of unsupported shapes, including negative ANY proofs and DNAME substitution.
- [ ] DNSSEC signing and key generation for RSA, ECDSA, and Ed25519 behind a separate opt-in `dnssec-signing` feature.
  - Keep key-generation dependencies out of validation-only builds and retain MSRV compatibility.
  - Test each supported algorithm against independent vectors or implementations, including malformed keys, invalid RRsets, validity bounds, and tampering.

### Post-quantum DNSSEC

Reference: Cloudflare, [1.1.1.1 now supports post-quantum DNSSEC, all 2,420 bytes of it](https://blog.cloudflare.com/post-quantum-dnssec-1111/).
Implement the same resolver capabilities, not merely a new algorithm enum value.
The article describes ML-DSA-44 (algorithm 18), 1,312-byte public keys, and 2,420-byte signatures.
Verify the current IANA assignment and [ML-DSA DNSSEC specification](https://datatracker.ietf.org/doc/draft-westerbaan-dnssec-mldsa/) before implementation; distinguish standardized behavior from draft encoding and optional local policy.

- [ ] <a id="dnssec-post-quantum"></a> Add ML-DSA-44 DNSKEY/RRSIG algorithm handling and local signature verification.
  - Select a maintained cryptographic implementation after checking MSRV, licenses, advisories, feature flags, and target support.
  - Preserve validation-only dependency boundaries; do not implement cryptographic primitives ourselves.
  - Start with independent known-answer and cross-implementation fixtures; test malformed keys/signatures, exact length boundaries, tampering, and unsupported-algorithm behavior.
- [ ] Add an explicit, opt-in post-quantum downgrade-protection policy.
  - An authenticated DS RRset advertising a supported post-quantum algorithm must require a valid post-quantum path for that delegation; a classical-only path must not satisfy that policy.
  - Test valid dual-signing, missing or invalid ML-DSA signatures, classical fallback without the authenticated signal, and key/algorithm rollovers.
  - Apply policy consistently through DNSKEY, DS, answer, and denial validation. Never derive the requirement from unauthenticated records.
  - Preserve the existing default policy unless a breaking change is explicitly approved; make clear that end-to-end post-quantum assurance requires protection from the trust anchor through every delegation.
- [ ] Verify large post-quantum DNS responses end to end.
  - Add realistic mixed classical/ML-DSA DNSKEY and RRSIG fixtures, including rollover-sized responses.
  - Test UDP truncation followed by TCP retry, bounded TCP/DoT/DoH response handling, deadlines, and configured response limits without weakening parser or transport bounds.
- [ ] Extend opt-in signing/key generation to ML-DSA-44 after validation and downgrade policy are verified.
  - Verify DNSKEY encoding, DS derivation, RRSIG interoperability, and generated-key round trips against an independent implementation.

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

- [x] Implement `Name` struct in [src/names.rs](src/names.rs) upholding all canonical wire invariants.
- [x] Add unit tests for `Name` parsing, validation bounds, IDNA roundtrips, and RFC 4034 canonical ordering.
- [x] Adopt `Name` in `Question.name`, `Record.name`, `NS`, `CNAME`, `PTR`, and `TrustAnchor.zone`.
- [x] Migrate RDATA domain name fields from `String` to `Name`:
  - [x] `MX.exchange`
  - [x] `SOA.mname`
  - [x] `SOA.rname` uses the dedicated, label-preserving `Rname` type; zone AST fields remain strings.
  - [x] `SRV.name`
  - [x] `RRSIG.signer_name`
  - [x] `NSEC.next_domain`
- [x] Remove `Message::append_qname_to_vec` in favor of direct `name.append_to_vec(buf)`.
- [x] Simplify infallible `append_rdata_to_vec(&self, buf: &mut Vec<u8>)` on `MX`, `SRV`, `DS`, `DNSKEY`, `NSEC`, and `ZONEMD`.
- [x] Migrate DNSSEC verification APIs to accept `&Name` / `impl IntoName`:
  - [x] `ValidationReport.signer: Name`
  - [x] `ChainValidator` methods (`validate_rrset_chain`, `get_zone_dnskeys`, `get_zone_ds`, `verify_key_against_parent_or_anchor`)
  - [x] `DnssecCache` methods (`insert_dnskeys`, `get_dnskeys`, `insert_ds`, `get_ds`)
  - [x] `denial.rs` methods (`nsec_covers`, `verify_nsec_nodata`, `verify_nsec_nxdomain`, `nsec3_hash`)
- [x] Update `Resolver::query` and `Resolver::lookup` in [src/clients/resolver/async.rs](src/clients/resolver/async.rs) to accept `impl IntoName`.
- [ ] Deprecate or remove `Name::as_str` in favor of explicit `Name::as_ascii` and `Name::to_unicode`.
- [x] Support 0x20-bit case preservation and randomization ([draft-vixie-dnsext-dns0x20-00]) via case-preserving `Name`, case-insensitive equality/hashing, `Name::to_0x20()`, `Name::to_canonical()`, and `case_sensitive_eq`.

---

## 5. Zone File Parser Enhancements (RFC Conformance)

Authoritative root zone (`root.zone`) and root hints (`named.root`) are supported (see [DESIGN.md](DESIGN.md#5-zone-file-parser--rfc-conformance-specification)). Remaining tasks for general master files:

- [x] Establish a pinned BIND checkzone acceptance/rejection baseline with
  [per-file exceptions](tests/bind_checkzone.yaml), feature-linked TODOs, and an
  explicit CI run. This does not include all BIND policy or harness tests.
- [ ] <a id="zone-includes"></a> Support `$INCLUDE <path> [<domain>]` directive with cyclic include guards (RFC 1035 §5).
- [x] Add quoted and unquoted TXT/SPF character-string parsing with RFC 1035 escapes (`\`, `\DDD`), preserving quoted punctuation during preprocessing.
- [x] <a id="zone-names"></a> Support escaped domain names consistently in [src/zones/zones.pest](src/zones/zones.pest).
  - Accept service labels, wildcard owners, and other legal DNS presentation characters.
- [ ] <a id="zone-record-types"></a> Extend typed zone RDATA support to BIND fixture record types not yet implemented
  (retain explicit exclusions for types outside the intended library scope).
  - [x] <a id="zone-dname"></a> Add DNAME records and origin resolution (not resolver-side subtree substitution).
  - [ ] <a id="zone-cds"></a> Add CDS and CDNSKEY RDATA parsing.
  - [ ] <a id="zone-svcb"></a> Add SVCB/HTTPS service binding RDATA parsing and parameter validation.
  - [ ] <a id="zone-deleg"></a> Evaluate DELEG/DELEGPARAM support against the pinned BIND syntax.
  - [ ] <a id="zone-nsap"></a> Evaluate NSAP presentation support and hexadecimal syntax validation.
  - [ ] Add RFC 3597 generic RDATA parsing and triage remaining legacy types individually.
- [ ] <a id="zone-generate"></a> Support BIND `$GENERATE` syntax with explicit expansion limits.
- [ ] <a id="zone-nsec3-validation"></a> Validate NSEC3 algorithm-dependent hash lengths and owner syntax without
  mistaking general domain-name grammar rejection for NSEC3 validation.
- [ ] Support standard BIND duration abbreviations (`w`, `d`, `h`, `m`, `s`) in `$TTL` and record TTLs.
- [x] Add `SRV` grammar to [src/zones/zones.pest](src/zones/zones.pest) and AST parser.
- [x] Add `TXT`, `SPF`, `NSEC3`, and `NSEC3PARAM` grammar to [src/zones/zones.pest](src/zones/zones.pest) and AST parser.
- [ ] Enforce RFC 2181 §5.2 TTL consistency across RRsets in [src/zones/process.rs](src/zones/process.rs).
- [x] Share the overlapping text/zone RDATA parsers as tracked in section 1.
- [x] Validate domain label ($\le 63$) and name ($\le 255$) lengths during zone processing.
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

- [x] **Zone File Fuzzing (`zones`)**: Exercise single-record and full-file parsing, quote-safe preprocessing, origin resolution, and wire encoding with a 16 KiB input bound.
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
- [x] Add dependency license and source auditing via `cargo-deny`.
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
