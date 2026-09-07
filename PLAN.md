# Rustdns Release Plan

This plan separates compatibility and security fixes from new functionality.
The current baseline is `0.7.0`.

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

## Version 1.0.0: Breaking Modernization

### Public API Cleanup

- [ ] Enforce `MAX_DNS_MESSAGE_LEN` in `Message::to_vec` and document the
  behavior consistently across all transports.
- [ ] Tighten text resource parsing so domain names, SOA rnames, TXT escapes,
  and trailing input are either validated or exposed through an explicit raw
  parsing API.
- [ ] Deprecate `src/from_str.rs` and unify text RDATA parsing with the zone parser:
  refactor `zones.pest` into standalone `rdata_*` rules, enable `zones` from the
  `json` feature (or make `zones` standard), and replace regex-based text parsing
  with the canonical PEG parser for DoH JSON and presentation round-tripping.
- [ ] Add validated constructors/builders for public DNS and EDNS structs while
  documenting that direct public-field mutation is unchecked.
- [ ] Replace broad `Error::InvalidArgument(String)` uses with typed errors for
  invalid names, invalid responses, missing servers, and DNS response rcodes.
- [ ] Audit all public methods against the method naming style guide in
  `DEVELOPERS.md` before the `1.0.0` API freeze.
- [ ] Replace the stateless DNS encoding helpers with a message encoder that can
  own compression state, message-size limits, EDNS-aware sizing, and canonical
  DNSSEC-style encoding options.
- [ ] Add an explicit DNS encoding options API, including opt-in name
  compression, while preserving semantic message round trips.
- [ ] Complete removal of input-dependent `expect`, `unwrap`, assertions, and
  unchecked indexing from production input paths.
- [ ] Perform a final public API and semver compatibility review.

### Resolver Architecture And Policy

The resolver should be the orchestration layer above single-target transports.
Transport implementations own protocol mechanics; the resolver owns upstream
selection, retries, failover, response policy, and high-level lookup helpers.

This section is the design contract for the 1.0 resolver. The implementation
may be delivered incrementally, but each step should preserve these boundaries.
The central rule is that a transport answers the question "how do I exchange
this DNS message with this endpoint?" while the resolver answers "which
endpoint or transport should I use, and what should I do after the result?"

#### Design Vocabulary

Use these terms consistently in the implementation and public documentation:

- A **message** is the existing DNS wire-format model, including header,
  questions, records, and EDNS data. It has no network policy or retry state.
- A **transport** is a protocol-specific, single-target exchange pipeline. Its
  target is fixed after construction, although it may maintain pooled sockets,
  streams, or connections internally.
- An **upstream** is a resolver service configuration. It identifies a target,
  transport, trust/bootstrap settings, and operational preferences. One
  upstream may own one or more transport instances when fallback requires it.
- An **attempt** is one transport exchange, including its attempt-local timeout
  and timing. A retry is a new attempt for the same logical query.
- A **resolution** is the complete logical operation, from the caller's query
  until a suitable response, cache result, definitive DNS result, or exhausted
  budget is returned.
- A **response** is the decoded DNS message together with resolver execution
  metadata. The DNS message remains the source of truth for protocol contents.

#### Core Invariants

The following invariants should be testable and should not depend on the chosen
resolution strategy:

- Every resolution has one caller-visible deadline or total budget. No retry,
  fallback, race, cache lookup, or health probe may extend it implicitly.
- A transport never selects a different upstream, changes retry policy, or
  interprets a DNS RCODE as a reason to fail over.
- The resolver never reaches into transport internals to implement framing,
  TLS, HTTP, QUIC, socket pooling, or connection reuse.
- Only responses correlated to the request and accepted by response policy may
  update the cache or upstream health as successful results.
- A definitive DNS response and a transport failure are different outcomes.
  `NXDomain`, `NoError` with an empty answer, `Refused`, and `ServFail` must not
  be collapsed into a generic I/O error.
- Losing attempts in a race must be cancelled or allowed to finish without
  changing the result, cache entry, or health state selected by the winner.
- Resolver state such as SRTT, circuit status, and cache contents is owned by
  the resolver and is safe to access according to the selected blocking or
  async concurrency model.

#### Ownership And Construction

The resolver should be built from explicit upstream definitions or injected
transport implementations. Construction should validate static configuration
such as endpoint shape, supported protocol, TLS requirements, and non-empty
upstream IDs before any query is attempted. Dynamic failures such as hostname
bootstrap resolution, connection failure, and server health belong to runtime
resolution errors.

Transport construction should be cheap enough to permit a pool of transports,
but the resolver must not assume that every transport is cheap, clonable, or
thread-safe. Prefer an explicit capability or ownership model over requiring
all transports to implement `Clone` and `Sync`. The blocking and async APIs may
share policy types and response models while using separate transport traits
where their execution and cancellation semantics genuinely differ.

The first implementation should make the policy engine transport-agnostic by
injecting a small exchange adapter. Concrete UDP, TCP, DoT, and DoH clients can
then be tested independently, while resolver tests use deterministic scripted
adapters. DoQ and HTTP/3 should fit the same boundary without requiring a
rewrite of retry or selection policy.

#### Logical Resolution Lifecycle

Every `exchange` should follow the same conceptual lifecycle, even when a
strategy skips some stages:

1. Validate the request shape that the resolver promises to support and derive
   a cache key without mutating the caller's message.
2. Check the cache if enabled. A hit returns a response marked `FromCache` and
   does not update upstream health or consume the network budget.
3. Select eligible upstreams using configured ordering, health, SRTT, weight,
   and strategy. Open circuit breakers are excluded except for probes.
4. Start one or more attempts, assigning each the remaining resolution budget
   and an attempt timeout no longer than that remainder.
5. Parse and correlate each response before classifying it as usable, retryable,
   definitive, truncated, or invalid.
6. For a truncated UDP response, perform the configured TCP escalation while
   retaining the logical query identity and recording the fallback in metadata.
7. Update health and cache state only after classification, then return the
   winning response or an error containing the attempted-upstream context.

The lifecycle should be represented by internal state and outcome types rather
than a chain of stringly-typed errors. This makes it possible to add metrics,
logging, tracing, and alternative selection strategies without changing the
transport contracts.

#### Retry And Failure Semantics

Retry policy must distinguish the logical query from its attempts. Retries are
appropriate for timeouts, dropped UDP packets, connection establishment errors,
and explicitly retryable transport failures. They are not automatically
appropriate for malformed DNS messages, mismatched responses, unsupported
configuration, or definitive policy responses from an upstream.

The policy should define whether a DNS response is retryable independently from
whether the transport succeeded. For example, `ServFail` may trigger failover
when no stronger EDE signal is present, while `Refused` or EDE `Prohibited`
should normally be returned or surfaced as policy information. These decisions
must be documented and configurable only where changing them is safe.

Backoff applies between attempts and must be capped by the remaining deadline.
Jitter should be generated by the resolver policy, bounded by the configured
ratio, and testable without relying on wall-clock sleeps. Health accounting
should record the reason for an outcome, not merely increment one undifferentiated
failure counter.

#### Concurrency And Cancellation

Async resolution should use caller cancellation and deadlines as the authority;
internal timers must not outlive a cancelled resolution. Staggered races need
to cancel scheduled backup attempts when the primary succeeds, and all races
need to cancel losing exchanges after a winner is selected. Blocking resolution
can use bounded worker threads or sequential execution initially, but its API
must retain the same total-budget and result-selection semantics.

Happy Eyeballs applies at two distinct levels and they should not be confused:

- **Endpoint address racing** chooses between IPv4 and IPv6 addresses for one
  upstream transport connection.
- **Upstream racing** chooses between independent resolver services or
  protocols. This is a resolver strategy and consumes resolution resources.

The implementation should expose these as separate policies so users can enable
address racing without unexpectedly querying multiple DNS providers.

#### Compatibility And Evolution

The existing `Message`, `Record`, and resource types remain the wire-level API.
Resolver response metadata should be additive and should not require callers to
give up access to the decoded message. Low-level transport clients should gain
single-target constructors before the resolver depends on them; compatibility
constructors can remain temporarily deprecated with explicit first-server
semantics.

New transports such as DoQ should implement the transport boundary first and
should not add protocol-specific branches throughout the resolver. New policy
features should be expressed as strategy, selection, retry, cache, or health
components so they can be composed and tested independently.

#### Remaining Resolver Tasks

- **Transport Interface**:
  - [ ] Require transports to report protocol, endpoint, and transport errors with
    typed context, without deciding whether an error is retryable.
  - [ ] Specify connection lifecycle semantics, including `close`, idle pooling,
    concurrent exchanges, and whether transaction IDs may be multiplexed.
  - [ ] Document transport capabilities and limitations for UDP, TCP, DoT, DoH,
    and DoQ, including HTTP/2, HTTP/3, and QUIC support as they are implemented.

- **Upstreams And Resolver Configuration**:
  - [ ] Add an upstream definition containing a stable ID, transport protocol,
    endpoint, optional bootstrap addresses, TLS settings, weight, and per-upstream
    limits or preferences.
  - [ ] Separate bootstrap resolution for DoH/DoT hostnames from DNS resolution
    performed by the resolver itself, preventing bootstrap dependency loops.
  - [ ] Add opt-in circuit-breaker settings: failure threshold, cooldown period,
    half-open probing, and optional canary probe scheduling.

- **Resolution Strategies**:
  - [ ] Support fastest-upstream selection using decayed SRTT and recent health,
    while retaining deterministic tie-breaking.
  - [ ] Support racing multiple eligible upstreams and returning the first suitable
    response, cancelling losing attempts.
  - [ ] Support staggered racing: start with the best candidate and launch backups
    after a configurable delay when no response arrives.
  - [ ] Record success, latency, timeout, protocol failure, and DNS response status
    in per-upstream health state used by SRTT and circuit breaking.

- **Public Resolver API**:
  - [ ] Add a low-level `query` operation for name, type, and class, and an
    `exchange` operation for caller-constructed messages with custom flags, EDNS,
    or DNSSEC settings.
  - [ ] Add convenience getters and inspection methods for messages and records.

- **Cache And Extended DNS Errors**:
  - [ ] Define a pluggable cache interface suitable for in-memory and external
    implementations, with cache keys covering question name, type, class, and
    relevant query options.
  - [ ] Specify positive TTL handling, minimum/maximum TTL clamps, expiration, and
    negative caching using SOA-derived TTLs from RFC 2308.
  - [ ] Ensure cached responses preserve enough message and metadata information
    for callers while marking cache hits explicitly.
  - [ ] Parse and expose RFC 8914 Extended DNS Error (EDE) options through EDNS
    types, preserving unknown EDE information for forward compatibility.
  - [ ] Use EDE and RCODE together in resolver policy: for example, EDE 22
    (`No Reachable Authority`) can justify failover, while EDE 18 (`Prohibited`)
    should be surfaced as a policy signal rather than blindly retried.

- **Testing And Migration**:
  - [ ] Test cache TTL expiry, negative caching, EDE-aware decisions, and metadata.

### DNSSEC Support & Upstream Trust Architecture

This architecture adds DNSSEC validation support and upstream trust policies to `rustdns`
across two incremental phases, deferring local cryptographic chain-of-trust verification
(RFC 4034/4035) to a future milestone.

#### 1. Background & Threat Model

DNSSEC (RFC 4033, 4034, 4035, 6840) authenticates DNS resource record sets using cryptographic
signatures (`RRSIG`) anchored in delegations (`DS`) up to the root key-signing key (KSK).

When a client queries a validating recursive resolver:
- The resolver fetches signatures and keys, verifies the chain of trust, and sets the `AD`
  (Authentic Data) bit in the DNS response header if the response is proven authentic.
- If signature verification fails (tampered records, expired signatures, broken chain), the
  upstream recursive resolver returns `SERVFAIL` (`Bogus`).
- If a zone is unsigned (no `DS` record in parent zone), it returns `NoError` with `AD=0` (`Insecure`).

**Security Boundary**:
The `AD` bit is a single unencrypted flag in the DNS header. Over plaintext transports (`UDP/53`
or `TCP/53`), an on-path attacker can easily forge responses with `AD=1`. Therefore, a stub client
can only trust the upstream `AD` bit when:
1. The transport is authenticated and encrypted (DNS-over-HTTPS, DNS-over-TLS), OR
2. The transport runs over a secure local loopback (`127.0.0.1` or `::1`) to a trusted local
   validating resolver daemon (such as `systemd-resolved` or `unbound`), OR
3. The administrator explicitly overrides transport validation via configuration (`AlwaysTrust`).

#### 2. Architecture & API Specification

```text
+-------------------------------------------------------------+
|                      Application API                        |
|   lookup(name) -> IP   /   query(name, type) -> Response    |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                      Resolver Engine                        |
|  - Sets EDNS(0) DO=1 when DNSSEC is enabled                 |
|  - Evaluates AD bit + transport security -> SecurityStatus  |
|  - Enforces fail-closed validation on lookup()              |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                AsyncExchanger / Transports                  |
|  - is_secure_channel() -> bool                              |
|    - DoT / DoH / JSON: true                                 |
|    - UDP / TCP / Do53: true if loopback, else false         |
+-------------------------------------------------------------+
```

##### 2.1 Transport Security Contract
Extend `AsyncExchanger` and `Exchanger` traits in `src/clients/mod.rs`:
```rust
pub trait Exchanger {
    fn exchange(&self, query: &Message) -> Result<Message, crate::Error>;
    fn endpoint(&self) -> Arc<str>;
    fn is_secure_channel(&self) -> bool { false }
}

#[async_trait]
pub trait AsyncExchanger {
    async fn exchange(&self, query: &Message) -> Result<Message, crate::Error>;
    fn endpoint(&self) -> Arc<str>;
    fn is_secure_channel(&self) -> bool { false }
}
```
- Implementations:
  - `doh::Client`, `dot::Client`, `json::Client`: `true`
  - `udp::Client`, `tcp::Client`, `do53::Client`: `self.server.ip().is_loopback()`

##### 2.2 Security Status & DNSSEC Modes
In `src/types.rs`:
```rust
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum SecurityStatus {
    Secure,        // Validated cryptographic authenticity (AD=1 over trusted channel)
    Insecure,      // Valid unsigned zone (AD=0, NoError)
    Bogus,         // Validation failed upstream (SERVFAIL or explicit DNSSEC validation failure)
    Indeterminate, // Validation status cannot be asserted (e.g. AD=1 over insecure plaintext transport)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DnssecMode {
    #[default]
    Off,
    TrustUpstream { require_secure: bool },
    StrictLocal, // Reserved for local cryptographic verification
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UpstreamTrustPolicy {
    #[default]
    SecureTransportOnly,
    AlwaysTrust,
}
```

##### 2.3 Resolver API Integration
In `ResolverBuilder`:
- `dnssec_mode(mut self, mode: DnssecMode) -> Self`
- `upstream_trust_policy(mut self, policy: UpstreamTrustPolicy) -> Self`

In `ResponseMeta`:
- `pub security_status: SecurityStatus`

In `Resolver`:
- High-level `lookup` / `lookup_with_deadline`: Enforces fail-closed semantics. If `DnssecMode::TrustUpstream { require_secure: true }`, any response that is not `SecurityStatus::Secure` returns an error. If `require_secure: false`, `SecurityStatus::Insecure` is accepted, while `Bogus` or `Indeterminate` (under `SecureTransportOnly`) returns an error.
- Low-level `query(&self, name: &str, rtype: Type) -> Result<Response, crate::Error>`: Returns the full `Response` allowing inspection of `Message`, answer records, authority records, and `meta.security_status`.

##### 2.4 Wire Parsing & Unknown Record Resilience
1. **Fallback `Resource::Raw`**:
   ```rust
   pub enum Resource {
       ...
       Raw { type_code: u16, data: Vec<u8> },
   }
   ```
   Ensures unknown record types (e.g., DNSSEC records returned when `DO=1` is sent) do not cause `DecodeError::InvalidType`.
2. **DNSSEC Record Types**:
   - `Type::DS (43)`
   - `Type::RRSIG (46)`
   - `Type::NSEC (47)`
   - `Type::DNSKEY (48)`
   - `Type::NSEC3 (50)`
   - `Type::NSEC3PARAM (51)`
   Structured types in `src/resource.rs` implementing RFC 4034 and RFC 5155 wire serialization and deserialization.

#### Remaining DNSSEC Tasks

- [ ] Add `Resource::Raw` fallback in `src/types.rs` and update `src/resource.rs` / `src/dns.rs` so unhandled type codes decode into raw bytes without failing.
- [ ] Add remaining DNSSEC variants to `Type` (`NSEC3=50`, `NSEC3PARAM=51`).
- [ ] Implement wire decoding and encoding for `NSEC3` and `NSEC3PARAM` per RFC 5155 in `src/resource.rs`.
- [ ] Add CLI flags to `dig/main.rs` (`+dnssec`, `+ad`, `+noad`, `+cd`) and display `SecurityStatus` in output.
- [ ] Add unit tests for `is_secure_channel` across all clients.
- [ ] Add mock resolver tests for `DO=1`, `AD=1` secure vs plaintext, unsigned `AD=0` (standard vs strict), and `SERVFAIL` (bogus).
- [ ] Add round-trip wire encoding/decoding tests for `NSEC3`, `NSEC3PARAM`, and raw fallback.

### WebAssembly (WASM) Support & DNS-over-JSON Decoupling

This design addresses [GitHub Issue #7](https://github.com/bramp/rustdns/issues/7),
enabling pure DNS-over-JSON parsing and serialization on WebAssembly targets
(`wasm32-unknown-unknown`, `wasm32-wasip1`) and in environments without native
networking or Tokio runtimes.

#### 1. Background & Problem Statement

Currently, the `json` Cargo feature bundles both data-format handling (Serde) and
the HTTP client transport:
```toml
json = ["http_deps", "serde", "serde_json"]
```
Because `http_deps` pulls in `hyper`, `hyper-util`, `hyper-rustls`, `tokio`, and
socket-oriented dependencies, enabling `json` causes compilation to fail on
WebAssembly targets (`wasm32-unknown-unknown`).

In addition:
1. **Private Parsing Logic**: JSON parsing (`MessageJson`, `parse_response`) is
   an unexported internal detail inside [src/clients/json/async.rs](src/clients/json/async.rs). Callers
   executing inside WASM (e.g., in a web browser or Cloudflare Worker) fetching
   DNS responses via host APIs (such as `web_sys::fetch`, `reqwest`, or JS fetch)
   have no way to decode JSON payloads into a `Message`.
2. **Runtime Panic Hazard (`rand::rng()`)**: `Message::default()` populates
   `id: Message::random_id()`, which calls `rand::rng()`. On bare
   `wasm32-unknown-unknown` targets lacking a configured `getrandom` backend,
   instantiating messages via default construction can panic at runtime.
3. **Incomplete Schema Coverage**: The internal `MessageJson` only decodes
   `Question` and `Answer` fields, ignoring `Authority` and `Additional` records
   present in Google and Cloudflare DNS-over-HTTPS JSON responses (RFC 8427).

#### 2. Architecture & Design

```text
+------------------------------------------------------------------------+
|                            Application Layer                           |
|   - Browser / WASM: fetches JSON via host API (fetch / web-sys)        |
|   - Native CLI / Server: uses Resolver or async clients                |
+------------------------------------------------------------------------+
              |                                          |
  (pure serde / wasm friendly)               (network I/O via hyper)
              v                                          v
+-----------------------------+            +-----------------------------+
|     rustdns::json           |            | rustdns::clients::json      |
|  - Feature: "json"          |            |  - Feature: "json-client"   |
|  - from_slice / from_str    |<-----------|  - Client::try_new(Url)     |
|  - to_string / to_writer    | (delegates |  - Implements AsyncExchanger|
|  - Zero I/O dependencies    |  parsing)  |  - Requires "http_deps"     |
+-----------------------------+            +-----------------------------+
              |
              v
+-----------------------------+
|       rustdns::Message      |
|  - In-memory DNS model      |
|  - Explicit response fields |
|  - Zero WASM runtime panics |
+-----------------------------+
```

##### 2.1 Feature Decoupling
Split the responsibilities into two distinct Cargo features:
- `json`: Enables pure data serialization and deserialization via `serde` and
  `serde_json`. Zero network or Tokio dependencies. Compiles cleanly on
  `wasm32-unknown-unknown` and `no_std`+alloc environments.
- `json-client`: Enables the HTTP client transport (`rustdns::clients::json::Client`)
  and `IntoAsyncExchanger` support for `json+https://`. Depends on `json` and
  `http_deps`.
- `clients`: Preserves backward compatibility by bundling `json-client` (alongside
  `doh`, `do53`, `dot`, `resolver`, and `sync`). Default crate configurations
  continue to compile all clients without breaking changes.

##### 2.2 Core JSON Module ([src/json.rs](src/json.rs))
Extract and elevate JSON handling into a top-level module:
- Types: `MessageJson`, `QuestionJson`, `RecordJson`, and error types.
- Extended Schema: Add `Authority` and `Additional` sections with `#[serde(default)]`
  to support complete responses from Google and Cloudflare.
- Safe Response Conversion:
  ```rust
  impl TryFrom<MessageJson> for Message { ... }
  impl TryFrom<&Message> for MessageJson { ... }
  ```
  In `TryFrom<MessageJson>`, explicitly set `id: 0`, `qr: QR::Response`, and other
  DNS header fields without delegating to `Message::default()`, guaranteeing no
  implicit `rand::rng()` calls during decoding.
- Public Helpers:
  - `rustdns::json::from_slice(body: &[u8]) -> Result<Message, JsonError>`
  - `rustdns::json::from_str(s: &str) -> Result<Message, JsonError>`
  - `rustdns::json::to_string(msg: &Message) -> Result<String, JsonError>`

##### 2.3 Ergonomic `Message` Methods
Behind `#[cfg(feature = "json")]` in [src/dns.rs](src/dns.rs):
- `Message::from_json_slice(bytes: &[u8]) -> Result<Message, JsonError>`
- `Message::from_json_str(s: &str) -> Result<Message, JsonError>`
- `Message::to_json_string(&self) -> Result<String, JsonError>`

##### 2.4 Transport Integration
In [src/clients/json/async.rs](src/clients/json/async.rs):
- Keep `Client` and `AsyncExchanger` intact, guarded by `#[cfg(feature = "json-client")]`.
- Replace the internal `parse_response` implementation with a call to
  `crate::json::from_slice(body)`.
- Retain `fuzz_parse_response` for compatibility with existing fuzz targets.
- Update [src/clients/into_exchanger.rs](src/clients/into_exchanger.rs) to guard `json+https://` scheme handling
  under `feature = "json-client"`.

#### WASM Support Implementation Checklist

- [ ] **Phase 1: Feature Decoupling in Cargo.toml**
  - [ ] Redefine `json = ["dep:serde", "dep:serde_json"]` in [Cargo.toml](Cargo.toml).
  - [ ] Add `json-client = ["json", "http_deps"]` to [Cargo.toml](Cargo.toml).
  - [ ] Update `clients = ["doh", "json-client", "do53", "dot", "resolver", "sync"]` in [Cargo.toml](Cargo.toml).
  - [ ] Update `Cargo.toml` `cargo-all-features` metadata to include `json-client`.
- [ ] **Phase 2: Core JSON Serialization & Deserialization Module**
  - [ ] Create [src/json.rs](src/json.rs) containing `MessageJson`, `QuestionJson`, and `RecordJson`.
  - [ ] Add support for `Authority` and `Additional` record arrays in `MessageJson`.
  - [ ] Implement `TryFrom<MessageJson> for Message` without calling `Message::default()` or `rand::rng()`.
  - [ ] Implement `TryFrom<&Message> for MessageJson` for serializing outbound DNS messages to JSON.
  - [ ] Expose `from_slice`, `from_str`, and `to_string` functions in [src/json.rs](src/json.rs).
  - [ ] Export `pub mod json;` in [src/lib.rs](src/lib.rs) gated on `feature = "json"`.
  - [ ] Add `from_json_slice`, `from_json_str`, and `to_json_string` to `Message` in [src/dns.rs](src/dns.rs) gated on `feature = "json"`.
  - [ ] Ensure `JsonError` and `Error::Json` remain transparent and gated on `feature = "json"` in [src/errors.rs](src/errors.rs).
- [ ] **Phase 3: Client & Transports Integration**
  - [ ] Update [src/clients/mod.rs](src/clients/mod.rs) to gate `pub mod json;` on `feature = "json-client"`.
  - [ ] Update [src/clients/json/async.rs](src/clients/json/async.rs) to delegate body decoding to `crate::json::from_slice`.
  - [ ] Update [src/clients/into_exchanger.rs](src/clients/into_exchanger.rs) to guard `json+https://` under `feature = "json-client"`.
  - [ ] Update [src/clients/common/mod.rs](src/clients/common/mod.rs) HTTP feature guards from `feature = "json"` to `feature = "json-client"`.
- [ ] **Phase 4: Testing, Fuzzing, & Verification**
  - [ ] Add unit tests in [src/json.rs](src/json.rs) and [tests/dns.rs](tests/dns.rs) verifying JSON decoding of real Google and Cloudflare responses with zero network dependencies.
  - [ ] Update [tests/clients.rs](tests/clients.rs) to run JSON client tests under `feature = "json-client"`.
  - [ ] Update [fuzz/fuzz_targets/json.rs](fuzz/fuzz_targets/json.rs) to test `rustdns::json::from_slice`.
  - [ ] Verify clean compilation on `wasm32-unknown-unknown`:
        `cargo check --target wasm32-unknown-unknown --no-default-features --features json`
  - [ ] Verify feature matrix:
        `cargo test --no-default-features --features json`
        `cargo test --no-default-features --features json-client`
        `cargo test --workspace --all-features`
  - [ ] Document changes in [CHANGELOG.md](CHANGELOG.md) under `[Unreleased]`.

### End-to-End Performance Benchmarking & Allocation Profiling

This section outlines the plan to benchmark end-to-end DNS flows in `rustdns` and
systematically measure string copies and heap allocations.

#### 1. Motivation & Problem Statement

In a typical DNS resolver or proxy flow, an application performs a sequence of
operations:
1. **Create Message**: instantiate a query `Message` and call `try_add_question`.
2. **Send Request (Encode)**: serialize the message to wire-format bytes (`to_vec` / `append_to_vec`).
3. **Transport (I/O)**: transmit over the network (e.g. UDP loopback) and receive a wire-format datagram.
4. **Receive Request / Response (Parse)**: decode wire-format bytes into a structured `Message` (`Message::from_slice`).

Currently, there are concerns that too many heap allocations and intermediate string copies occur
across this typical flow, in particular:
- **`try_add_question`**: calls `normalise_domain` which invokes `idna::domain_to_ascii`
  allocating a `String`, followed by `idna::domain_to_unicode` allocating another `String`,
  and then a second `idna::domain_to_ascii` call before storing an owned `String` in `Question`.
- **`append_qname_to_vec`**: calls `idna::domain_to_ascii(domain)` on every domain name serialization,
  allocating a temporary `String` per domain encoded.
- **`read_qname` / `read_qname_at_depth`**: builds up domain names by creating temporary
  `vec![0; len]`, validating UTF-8, calling `idna::domain_to_unicode` (allocating a decoded `String`),
  and concatenating into a newly allocated `String` per name. No zero-copy slicing or string interning
  is used.
- **Missing name compression during encoding**: repeatedly serialized domain names in responses are
  written out fully rather than using compressed wire pointers.

To evaluate whether CPU or RAM is being wasted in production use cases, we need:
1. High-level, end-to-end macro benchmarks modeling realistic client-server flows.
2. Micro-benchmarks isolating each individual phase (`create`, `encode`, `loopback transport`, `parse`).
3. Allocation tracking (allocation counts, cumulative bytes, peak memory) and DHAT heap profiling
   to attribute allocations directly to call stacks.

#### 2. Architecture & Design

```text
+-----------------------------------------------------------------------------------------+
|                                     Benchmark Suite                                     |
+-----------------------------------------------------------------------------------------+
                    |                                                   |
                    v                                                   v
+---------------------------------------+               +---------------------------------------+
|  Criterion Harness                    |               |  Allocation Tracker & DHAT Profiler   |
|  (benches/dns_pipeline.rs)            |               |  (benches/allocations.rs)             |
|                                       |               |                                       |
|  1. End-to-End Workflows:             |               |  1. Tracking Global Allocator:        |
|     - Complete In-Memory Flow         |               |     - Tracks alloc/dealloc counts     |
|       (create -> encode -> parse)     |               |     - Tracks cumulative bytes         |
|     - Complete Loopback UDP Flow      |               |     - Quantifies memory per stage     |
|       (create -> encode -> UDP send   |               |                                       |
|        -> UDP recv -> parse)          |               |  2. Step-by-Step Breakdown:           |
|                                       |               |     - Message creation & QNAME        |
|  2. Phase-by-Phase Micro-benchmarks:  |               |     - Request encoding                |
|     - Message creation                |               |     - Wire parsing                    |
|       (ASCII, subdomains, IDNA)       |               |     - End-to-end exchange             |
|     - Request encoding                |               |                                       |
|       (to_vec vs append_to_vec)       |               |  3. DHAT Heap Profiler:               |
|     - Response parsing                |               |     - Dumps dhat-heap.json            |
|       (A, CNAME+A, MX, TXT/SOA)       |               |     - Flamegraph/stack attribution    |
+---------------------------------------+               +---------------------------------------+
```

##### 2.1 High-Level End-to-End Scenarios
The benchmark suite models real end-to-end interactions using realistic queries and real-world response
wire payloads (drawn from [tests/test_data.yaml](tests/test_data.yaml)):
- **In-Memory Roundtrip**: Creates a query message (`www.google.com`, `A`), serializes it to wire
  bytes via `to_vec`, mock-resolves by substituting a representative response payload, and decodes
  via `Message::from_slice`. Measures the pure CPU latency and memory allocation of the library
  without network noise.
- **Loopback UDP Roundtrip**: Leverages `Client::exchange` from [src/clients/udp/sync.rs](src/clients/udp/sync.rs)
  communicating with an in-process loopback UDP server on `127.0.0.1`. Compares socket syscall overhead
  against protocol parsing and serialization overhead.

##### 2.2 Micro-Benchmarking Individual Pipeline Stages
- **Stage 1 (Create Message)**:
  - Simple ASCII domain (`example.com.`, 1 question).
  - Deep subdomain (`a.b.c.d.sub.example.com.`, 1 question).
  - Internationalized domain name (IDNA, e.g. `münchen.de.` / `xn--mnchen-3ya.de.`).
  - EDNS(0) extension creation (options: NSID, ECS, cookie, padding).
- **Stage 2 (Encode Request)**:
  - `to_vec()`: standard path allocating a 512-byte vector.
  - `append_to_vec(&mut buf)`: reused preallocated buffer to measure pure serialization cost without
    buffer reallocations.
- **Stage 3 (Parse Response)**:
  - Single A record response.
  - CNAME + A record response.
  - Multi-answer MX response with domain name compression pointers.
  - Large TXT / SOA response with multiple string chunks.

##### 2.3 Memory & String Copy Quantification
- A custom tracking allocator (`TrackingAllocator`) wraps `std::alloc::System`, recording:
  - Allocation calls (`alloc_count`).
  - Deallocation calls (`dealloc_count`).
  - Total bytes requested (`total_bytes_allocated`).
  - Peak live bytes (`peak_memory_bytes`).
- A dedicated runner executable prints a markdown/text summary table reporting exact numbers per
  operation.
- DHAT integration enables dumping heap profiling graphs (`dhat-heap.json`) to confirm exactly which
  lines in `normalise_domain`, `append_qname_to_vec`, and `read_qname` allocate strings.

#### Benchmarking & Profiling Implementation Checklist

- [ ] **Phase 1: Dependencies and Cargo Configuration**
  - [ ] Add `criterion = { version = "0.5", features = ["html_reports"] }` to `[dev-dependencies]` in [Cargo.toml](Cargo.toml).
  - [ ] Add `dhat = "0.3"` to `[dev-dependencies]` in [Cargo.toml](Cargo.toml).
  - [ ] Define `[[bench]]` target for `dns_pipeline` with `harness = false` in [Cargo.toml](Cargo.toml).
  - [ ] Define `[[bench]]` target for `allocations` with `harness = false` in [Cargo.toml](Cargo.toml).
- [ ] **Phase 2: High-Level End-to-End & Micro Criterion Benchmarks**
  - [ ] Implement `benches/dns_pipeline.rs`:
    - [ ] End-to-end in-memory pipeline benchmark (create query -> encode wire -> decode response).
    - [ ] End-to-end loopback UDP benchmark using in-process UDP socket responder and `rustdns::clients::sync::udp::Client`.
    - [ ] Micro-benchmarks for `create_message` (ASCII, subdomain, IDNA, EDNS).
    - [ ] Micro-benchmarks for `encode_request` (`to_vec` vs `append_to_vec` buffer reuse).
    - [ ] Micro-benchmarks for `parse_response` (A, CNAME+A, MX with compression, TXT/SOA).
- [ ] **Phase 3: Heap Allocation & String Copy Profiler**
  - [ ] Implement `benches/allocations.rs`:
    - [ ] Create `TrackingAllocator` to count allocation invocations and cumulative bytes allocated per operation.
    - [ ] Measure and report allocation counts and total bytes for message creation, encoding, parsing, and full exchange.
    - [ ] Add DHAT support behind an opt-in CLI flag or environment variable (`DHAT=1`) to export `dhat-heap.json`.
- [ ] **Phase 4: Execution, Baseline Analysis, & Verification**
  - [ ] Verify compilation: `cargo check --benches --all-features`.
  - [ ] Run benchmark smoketest: `cargo bench --bench dns_pipeline -- --test`.
  - [ ] Run allocation breakdown: `cargo run --bench allocations`.
  - [ ] Record baseline CPU timings and allocation numbers in project notes to guide zero-copy optimizations.

### Zone File Parser Enhancements & RFC Conformance

With root hints (`named.root`) and authoritative root zone (`root.zone`) parsing implemented
and validated in CI, this section specifies the remaining work to make the zone parser fully
feature-complete and standards-compliant for arbitrary zone files.

#### Remaining Tasks & Technical Scope

1. **`$INCLUDE` Directive Support (RFC 1035 §5)**:
   - Grammar: support `$INCLUDE <path> [<domain>]` in `zones.pest`.
   - Preprocessor / Parser: recursively read and splice included files into the entry stream.
   - Include Depth Guard: track path recursion stack to detect and reject cyclic includes.

2. **Quoted Strings and Character Escape Sequences (RFC 1035 §5.1)**:
   - Grammar: extend string and domain rules in `zones.pest` to accept double quotes (`"..."`)
     and escape sequences (`\` followed by any character, or `\DDD` decimal byte octets).
   - Unescaping: unescape characters during token transformation in `zones/parser.rs`.

3. **Duration Suffixes in TTL Fields**:
   - Support standard BIND duration abbreviations in `$TTL` and record TTL fields:
     `w` (weeks = 604,800s), `d` (days = 86,400s), `h` (hours = 3,600s), `m` (minutes = 60s),
     and `s` (seconds), including composite forms (e.g. `1d12h`).

4. **Additional Record Types in Grammar**:
   - Add grammar and AST handlers for:
     - `TXT`: Quoted strings and multi-string arrays.
     - `SPF`: Text-based SPF records.
     - `SRV`: `priority weight port target`.
     - `NSEC3` / `NSEC3PARAM`: Hashed denial-of-existence records (RFC 5155).

5. **RFC 2181 §5.2 TTL Consistency Verification**:
   - In `File::try_into_records`, verify that all records within the same RRset (matching
     name, class, and type) declare identical TTL values. Return a typed error on mismatch.

6. **Unified RDATA Parsing & Deprecation of `src/from_str.rs`**:
   - Decompose `zones.pest` resource rules into standalone `rdata_*` rules without leading
     type keywords.
   - Expose `zones::parse_rdata(r#type: Type, text: &str) -> Result<Resource, ...>`.
   - Migrate `src/json.rs` and `Resource::parse_text` to call `zones::parse_rdata`, deprecating
     and removing the duplicate regexes in `src/from_str.rs`.

7. **Domain Name Syntax & Label Length Validation**:
   - Validate that domain labels do not exceed 63 octets and total name length does not exceed
     255 octets during zone resolution in `src/zones/process.rs`.

8. **Streaming Record Iterator**:
   - Provide `File::from_reader<R: BufRead>(reader: R) -> impl Iterator<Item = Result<Record, ProcessError>>`
     or an incremental entry parser so arbitrary multi-gigabyte zone files (e.g. `.com` TLD)
     can be streamed record-by-record with constant memory overhead.

#### Zone Parser Checklist

- [ ] Support `$INCLUDE <filename> [<domain>]` directive in zone files (RFC 1035 §5).
- [ ] Add quoted string parsing and character escape sequences (`\`, `\DDD`) in `zones.pest`.
- [ ] Support standard duration abbreviations (`1w`, `2d`, `3h`, `4m`) in `$TTL` and record TTLs.
- [ ] Add `TXT`, `SPF`, `SRV`, `NSEC3`, and `NSEC3PARAM` record grammar to `zones.pest` and parser.
- [ ] Enforce RFC 2181 §5.2 TTL consistency across RRsets in `src/zones/process.rs`.
- [ ] Unify `src/from_str.rs` with `zones::parse_rdata` and remove duplicate regexes.
- [ ] Validate domain label (<= 63) and name (<= 255) lengths during zone processing.
- [ ] Add streaming `File::from_reader` iterator for memory-efficient large zone parsing.

### Rust Platform Migration

- [ ] Move lint policy into workspace configuration where supported.
- [ ] Ratchet toward `missing_docs`, `missing_debug_implementations`, and
  `unsafe_code = "forbid"`.
- [ ] Replace `lazy_static` with `std::sync::LazyLock` if compatible with the MSRV.
- [ ] Review whether `byteorder`, `num-derive`, `educe`, and `async-trait` remain needed.
- [ ] Run `cargo tree --duplicates` and remove avoidable duplicate dependency versions.

### Final Quality And Release

- [ ] Add and enforce the Rust 1.85 MSRV, stable, and beta CI jobs; MSRV and
  stable coverage are already present.
- [ ] Add dependency license and source checks with `cargo-deny` or equivalent;
  retain the existing advisory audit.
- [ ] Add and enforce a meaningful coverage threshold.
- [ ] Run regular fuzz regressions in addition to the bounded CI smoke test.
- [ ] Complete the full feature matrix and dependency checks.
- [ ] Run `cargo-semver-checks` against the previous release.
- [ ] Add `1.0.0` migration notes and release notes.
- [ ] Run `cargo publish --dry-run` for `1.0.0`.
- [ ] Release and tag `1.0.0`.

## Fuzzing Strategy

Expand fuzz testing beyond the single `Message::from_slice` smoke fuzzer to cover
all untrusted input parsing, serialization invariants, and structured round-trips:

- [ ] **Zone File and Preprocessor Fuzzing (`fuzz_zones`):**
  - Fuzz `File::from_str` with arbitrary strings to exercise both the Pest
    grammar parser and semantic processing (`try_into_records`).
  - Fuzz the zone `preprocess` routine directly with arbitrary parenthesized,
    quoted, and comment-heavy input to ensure brace counter arithmetic and
    token replacement never underflow or panic.
  - Fuzz single `Record::from_str` parses across malformed zone entries.
- [x] **Round-Trip Serialization Invariants (`from_slice`):**
  - For any valid message decoded by `Message::from_slice`, assert that
    `to_vec()` or `append_to_vec()` executes without panicking.
  - If encoding succeeds, verify that decoding the encoded bytes produces an
    equivalent or canonicalized message (`from_slice(data) -> to_vec() -> from_slice()`).
  - Exercised directly in `fuzz_targets/from_slice.rs` across the full seed corpus.
- [x] **Structured Encoding and Limits (`encode`):**
  - Use structured generation (`arbitrary::Arbitrary`) to generate arbitrary
    in-memory `Message`, `Question`, `Record`, and `Edns` structs.
  - Assert that serialization through `to_vec()` and `append_to_vec()`
    strictly returns `Result::Err(EncodeError)` on boundary conditions (e.g.
    `MAX_DNS_LABEL_WIRE_LEN`, `MAX_DNS_NAME_WIRE_LEN`, `OPT` data length,
    `TXT` chunk limits) without panic or integer overflow.
  - Implemented in `fuzz_targets/encode.rs`.
- [x] **Text Resource Parsing (`from-str`):**
  - Fuzz `Resource::parse_text(record_type, input_str)` across all `Type`
    variants to test regexes, integer ranges, IPv4/IPv6 parsers, and SOA rname
    email conversions against malformed text representations.
  - Implemented in `fuzz_targets/from-str.rs`.
- [x] **DoH JSON Client Parsing (`json`):**
  - Fuzz the JSON response parser (`serde_json::from_slice::<MessageJson>`
    followed by `TryInto::<Message>::try_into`) with arbitrary payload bytes to
    ensure invalid RCODEs, malformed questions/answers, and unexpected types are
    safely rejected without panics.
  - Implemented in `fuzz_targets/json.rs` via `rustdns::clients::json::parse_response`.
- [x] **EDNS Option Binary Parsing (`edns`):**
  - Fuzz `EdnsOption::from_slice`, `EdnsOption::from_code_and_data`, and subsequent
    serialization across all supported options (ECS, Cookie, Keepalive, Padding, NSID)
    with malformed option payloads, truncated addresses, and invalid masks.
  - Implemented in `fuzz_targets/edns.rs`.
- [ ] **Display / Formatter Safety:**
  - Verify that successfully parsed `Message`, `Record`, `Resource`, and `File`
    instances can be formatted via `Display` (`"{}"`) and `Debug` (`"{:?}"`)
    without panicking on non-UTF-8 bytes or extreme values.
- [ ] **Continuous Fuzzing Integration:**
  - Maintain fuzz corpus seeds for newly added targets under `fuzz/corpus/`.
  - Add quick fuzz smoke tests to CI for each target.

## Definition Of Done

- Compatibility fixes are clearly separated from new features.
- `0.7.0` adds functionality without breaking existing callers or defaults.
- Security and parser protections remain covered by deterministic tests and fuzzing.
- Public errors, timeout behavior, and client semantics are documented.
- Every release passes formatting, Clippy, rustdoc, tests, dependency checks, and
  the relevant semver review.
