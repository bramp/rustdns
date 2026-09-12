# Rustdns Architecture and Design Specification

This document defines the architectural boundaries, design contracts, invariants, and specifications for `rustdns`.

---

## 1. Resolver Architecture & Design Contract

The resolver is the orchestration layer above single-target transports. Transport implementations own protocol mechanics; the resolver owns upstream selection, retries, failover, response policy, and high-level lookup helpers.

A transport answers *"how do I exchange this DNS message with this endpoint?"* while the resolver answers *"which endpoint or transport should I use, and what should I do after the result?"*

### 1.1 Design Vocabulary

- **Message**: The wire-format model (`Message`), including header, questions, records, and EDNS data. Has no network policy or retry state.
- **Transport**: A protocol-specific, single-target exchange pipeline (`AsyncExchanger` / `Exchanger`). Its target is fixed after construction, although it may maintain pooled sockets, streams, or connections internally.
- **Upstream**: A resolver service configuration. Identifies a target, transport, trust/bootstrap settings, and operational preferences.
- **Attempt**: One transport exchange, including its attempt-local timeout and timing. A retry is a new attempt for the same logical query.
- **Resolution**: The complete logical operation, from the caller's query until a suitable response, cache result, definitive DNS result, or exhausted budget is returned.
- **Response**: The decoded DNS message together with resolver execution metadata (`Response` / `ResponseMeta`). The DNS message remains the source of truth for protocol contents.

### 1.2 Core Invariants

- **Single Overall Deadline**: Every resolution has one caller-visible deadline or total budget. No retry, fallback, race, cache lookup, or health probe may extend it implicitly.
- **Transport Isolation**: A transport never selects a different upstream, changes retry policy, or interprets a DNS RCODE as a reason to fail over.
- **Protocol Separation**: The resolver never reaches into transport internals to implement framing, TLS, HTTP, QUIC, socket pooling, or connection reuse.
- **Strict Correlation**: Only responses correlated to the request (matching ID, QR=Response, question count, and question tuples) and accepted by response policy may update cache or upstream health.
- **Semantic Classification**: A definitive DNS response and a transport failure are different outcomes. `NXDomain`, `NoError` (including NODATA empty answers), `Refused`, and `ServFail` must not be collapsed into generic I/O errors.
- **Race Cancellation**: Losing attempts in a race must be cancelled or discarded without mutating the result, cache entry, or health state selected by the winner.
- **State Ownership**: Resolver state such as SRTT, circuit breaker status, and cache contents is owned by the resolver and safe across concurrent tasks.

### 1.3 Logical Resolution Lifecycle

```text
+-----------------------------------------------------------------------------+
|                         Logical Resolution Lifecycle                        |
+-----------------------------------------------------------------------------+
                                       |
                   1. Validate request & derive cache key
                                       v
                             2. Cache Lookup?
                            /                \
                    (Hit)  /                  \  (Miss / Disabled)
                          v                    v
                  Return FromCache      3. Select eligible upstreams
                                        (Health, SRTT, Circuit Breaker)
                                               |
                                               v
                                        4. Dispatch Attempt(s)
                                        (Bounded by remaining budget)
                                               |
                                               v
                                        5. Correlate & Classify
                                        (Definitive vs Retryable)
                                               |
                        +----------------------+----------------------+
                        | (Truncated UDP)                             | (Valid Response)
                        v                                             v
              6. Escalation to TCP                           7. Record Health/Cache
              (Same server, RFC 7766)                                 |
                        |                                             v
                        +-------------------------------------> Return Response
```

1. **Validation & Cache Key**: Validate request shape and derive cache key without mutating the caller's message.
2. **Cache Check**: If enabled, a cache hit returns immediately with metadata marked `FromCache` without consuming network budget or updating upstream health.
3. **Upstream Selection**: Select eligible upstreams according to configured strategy, SRTT, health, and weights. Upstreams with open circuit breakers are excluded except for half-open probes.
4. **Attempt Dispatch**: Dispatch one or more attempts, assigning each an attempt timeout capped by the remaining resolution deadline.
5. **Correlation & Classification**: Verify response correlation (RFC 5452 §4.3 & RFC 1035 §4.1.1 error responses). Classify as definitive, retryable, truncated, or invalid.
6. **Truncation Escalation**: If a UDP response is truncated (`TC=1`), escalate to TCP against the same upstream per RFC 2181 / RFC 7766 while retaining the logical query identity.
7. **Post-Processing**: Update upstream health and cache state, then return the winning response or a structured error with attempted-upstream context.

### 1.4 Retry, Failure, & Backoff Semantics

- **Retry Applicability**: Retries apply to transport timeouts, dropped UDP packets, connection errors, and explicitly retryable upstream codes (`ServFail` without conflicting EDE). Retries do not apply to definitive DNS answers (`NXDomain`, `NoError`, `Refused`) or client configuration errors.
- **Backoff & Jitter**: Exponential backoff with full jitter must be applied between retries against the same upstream, capped by the remaining resolution deadline.
- **Happy Eyeballs Separation**:
  - *Endpoint Address Racing*: Chooses between IPv4 and IPv6 addresses for a single upstream transport connection.
  - *Upstream Racing*: Chooses between distinct upstream services/protocols at the resolver level.

---

## 2. DNSSEC Support & Upstream Trust Architecture

DNSSEC (RFC 4033, 4034, 4035, 6840) authenticates DNS resource record sets using cryptographic signatures (`RRSIG`) anchored in delegations (`DS`) up to the root key-signing key (KSK).

### 2.1 Threat Model & Security Boundaries

When a client queries a validating recursive resolver:
- The resolver fetches signatures and keys, verifies the chain of trust, and sets the `AD` (Authentic Data) bit in the DNS response header if the response is authentic.
- If signature verification fails, the recursive resolver returns `SERVFAIL` (`Bogus`).
- If a zone is unsigned (no `DS` in parent), it returns `NoError` with `AD=0` (`Insecure`).

**Security Boundary**:
The `AD` bit is an unencrypted bit in the DNS header. Over plaintext transports (`UDP/53` or `TCP/53`), an on-path attacker can easily forge responses with `AD=1`. Therefore, a stub client can only trust the upstream `AD` bit when:
1. The transport is authenticated and encrypted (DNS-over-HTTPS, DNS-over-TLS), OR
2. The transport runs over a secure local loopback (`127.0.0.1` or `::1`) to a trusted local validating daemon (e.g. `systemd-resolved`, `unbound`), OR
3. The administrator explicitly overrides transport validation via configuration (`UpstreamTrustPolicy::AlwaysTrust`).

### 2.2 System Architecture

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
|  - channel_security() -> ChannelSecurity                    |
|    - DoT / DoH / JSON: Encrypted                            |
|    - UDP / TCP / Do53: Loopback if local, else Insecure     |
+-------------------------------------------------------------+
```

### 2.3 Status & Policy Types

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
    ValidateLocal, // Full local cryptographic verification down to trust anchors (RFC 4035)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UpstreamTrustPolicy {
    #[default]
    SecureTransportOnly,
    AlwaysTrust,
}
```

### 2.4 Record & Data Type Representation

Public DNSSEC and DNS resource records model fields with rich Rust standard and domain types:
- **Intervals and TTLs**: Represented with `std::time::Duration` (e.g., `Record.ttl`, `SOA.refresh`, `RRSIG.original_ttl`).
- **Dates and Timestamps**: Represented with `std::time::SystemTime` (e.g., `RRSIG.expiration`, `RRSIG.inception`).
- **Protocol Enums**: Represented with strongly-typed enums (`Type`, `Class`, `Algorithm`, `DigestType`, `Nsec3HashAlgorithm`) paired with numeric `.code()` methods and non-failing `Unknown(u8|u16)` variants for forward compatibility.
- **Wire Conversion Helpers**: Records provide bounded conversion methods (e.g., `RRSIG::expiration_seconds(&self) -> Result<u32, EncodeError>`) ensuring checked conversion during wire serialization.

---

## 3. WebAssembly (WASM) Support & Feature Decoupling

Pure DNS data serialization and deserialization (including DNS-over-JSON) must compile cleanly to WebAssembly (`wasm32-unknown-unknown`, `wasm32-wasip1`) and `no_std`+alloc environments without native networking or Tokio runtimes.

### 3.1 Feature Separation

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
|  - Feature: "json"          |            |  - Feature: "doh-json"       |
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

- `json`: Enables pure data serialization/deserialization via `serde` and `serde_json`. Zero network or Tokio dependencies. Compiles on `wasm32-unknown-unknown`.
- `doh-json`: Enables the HTTP transport client (`rustdns::clients::json::Client`) and `IntoAsyncExchanger` support for `json+https://`. Depends on `json` and `http_deps`.
- `clients`: Bundles all client transports (`doh`, `doh-json`, `do53`, `dot`, `resolver`, `sync`).

### 3.2 In-Memory Conversion Safety

In `TryFrom<MessageJson> for Message`, header fields (`id: 0`, `qr: QR::Response`) must be set explicitly without delegating to `Message::default()`, preventing runtime panics from unconfigured `rand::rng()` on WASM targets.

---

## 4. Performance Benchmarking & Allocation Profiling Design

### 4.1 Pipeline Architecture

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

### 4.2 Measurement Targets

- **In-Memory Roundtrip**: Create query -> wire serialize (`to_vec`) -> wire parse (`Message::from_slice`).
- **Loopback UDP Flow**: In-process UDP client-server flow quantifying kernel syscall overhead vs. protocol encoding/decoding.
- **String Copy & Allocation Attribution**: Quantify allocations in `normalise_domain`, `append_qname_to_vec`, and `read_qname` using a tracking allocator and DHAT heap profiler.

---

## 5. Zone File Parser & RFC Conformance Specification

### 5.1 Standards Conformance Scope

- **RFC 1035 §5**: Master file format, `$ORIGIN`, `$TTL`, `$INCLUDE`, domain name resolution, and quoted character-strings with escape sequences (`\DDD` decimal octets, `\X` character escapes).
- **RFC 2181 §5.2**: RRset TTL consistency enforcement (all records with identical name, class, and type in a zone must share the same TTL).
- **RFC 2308**: Negative caching and SOA minimum TTL semantics.
- **RFC 5155**: NSEC3 and NSEC3PARAM resource record parsing.
- **Memory Efficiency**: Streaming record iterator (`File::from_reader`) allowing multi-gigabyte zone files (such as root or TLD zones) to be processed with $O(1)$ memory.
