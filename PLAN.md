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

- [ ] Replace `Resolver::new`'s hardcoded Google resolvers with system DNS
  configuration, or rename the constructor to make the Google default explicit.
- [ ] Validate DNS response correlation in a shared helper: transaction ID,
  response bit, question name/type/class, and response suitability.
- [ ] Propagate zone preprocessing errors instead of using an input-dependent
  `unwrap` in `File::from_str`.
- [ ] Enforce `MAX_DNS_MESSAGE_LEN` in `Message::to_vec` and document the
  behavior consistently across all transports.
- [ ] Remove unsolicited stdout output from `Resolver::lookup`; use tracing or
  return diagnostics through an explicit API.
- [ ] Tighten text resource parsing so domain names, SOA rnames, TXT escapes,
  and trailing input are either validated or exposed through an explicit raw
  parsing API.
- [ ] Add validated constructors/builders for public DNS and EDNS structs while
  documenting that direct public-field mutation is unchecked.
- [ ] Replace broad `Error::InvalidArgument(String)` uses with typed errors for
  invalid names, invalid responses, missing servers, and DNS response rcodes.
- [ ] Add explicit server-selection and failover policy APIs, or restrict the
  1.0 low-level client constructors to one endpoint.
- [ ] Add regression tests for response correlation, malformed zone input,
  oversized messages, strict text parsing, and resolver output behavior.
- [ ] Audit all public methods against the method naming style guide in
  `DEVELOPERS.md` before the `1.0.0` API freeze.
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

#### Layer Boundaries

- [ ] Keep wire-format models and parsing independent of transport and resolver
  policy.
- [ ] Define a transport abstraction for one endpoint that exchanges DNS
  messages, handles protocol-specific framing, and supports explicit shutdown.
- [ ] Make UDP, TCP, DoT, DoH, and future DoQ implementations single-target
  transports. Do not expose server pools from low-level transport constructors.
- [ ] Keep transport-local concerns in transports: UDP socket behavior, TCP
  framing and connection pooling, HTTP stream handling, TLS, and QUIC streams.
- [ ] Keep resolver concerns in the orchestration layer: retries, backoff,
  SRTT, failover, circuit breaking, response validation, and cache policy.
- [ ] Keep UDP truncation fallback to TCP in the resolver or a transport policy
  wrapper, rather than making the UDP transport select another protocol itself.

#### Transport Interface

- [ ] Design a Rust transport trait with an explicit cancellation/timeout
  mechanism compatible with both blocking and async clients.
- [ ] Define whether the trait exchanges `Message` values or a response wrapper;
  preserve access to raw DNS fields while allowing resolver metadata to be added.
- [ ] Require transports to report protocol, endpoint, and transport errors with
  typed context, without deciding whether an error is retryable.
- [ ] Specify connection lifecycle semantics, including `close`, idle pooling,
  concurrent exchanges, and whether transaction IDs may be multiplexed.
- [ ] Add configurable request and response timeouts to the HTTP clients, with
  blocking and async behavior documented consistently.
- [ ] Document transport capabilities and limitations for UDP, TCP, DoT, DoH,
  and DoQ, including HTTP/2, HTTP/3, and QUIC support as they are implemented.

#### Upstreams And Resolver Configuration

- [ ] Add an upstream definition containing a stable ID, transport protocol,
  endpoint, optional bootstrap addresses, TLS settings, weight, and per-upstream
  limits or preferences.
- [ ] Represent endpoint forms with typed Rust values where practical instead of
  requiring every caller to pass an unvalidated string.
- [ ] Separate bootstrap resolution for DoH/DoT hostnames from DNS resolution
  performed by the resolver itself, preventing bootstrap dependency loops.
- [ ] Add resolver configuration for upstreams, strategy, overall resolution
  timeout, per-attempt timeout, retry count, exponential backoff, and jitter.
- [ ] Add opt-in circuit-breaker settings: failure threshold, cooldown period,
  half-open probing, and optional canary probe scheduling.
- [ ] Make defaults conservative and document which settings apply to blocking,
  async, and pooled transports.

#### Resolution Strategies

- [ ] Support prioritized failover: try eligible upstreams in configured order
  and move on immediately for retryable failures.
- [ ] Support fastest-upstream selection using decayed SRTT and recent health,
  while retaining deterministic tie-breaking.
- [ ] Support racing multiple eligible upstreams and returning the first suitable
  response, cancelling losing attempts.
- [ ] Support staggered racing: start with the best candidate and launch backups
  after a configurable delay when no response arrives.
- [ ] Ensure all strategies share one end-to-end query budget and never allow
  retries or races to exceed the caller's deadline.
- [ ] Define retryability explicitly: dropped packets, timeouts, connection
  failures, and selected transport errors may retry; malformed responses and
  definitive DNS policy responses generally should not.
- [ ] Preserve the original query ID across retries and TCP fallback, while
  validating response ID, `QR`, question name/type/class, and suitability.
- [ ] Treat `TC=1` as a transport escalation signal and retry over TCP without
  consuming the user-level retry budget.
- [ ] Record success, latency, timeout, protocol failure, and DNS response status
  in per-upstream health state used by SRTT and circuit breaking.

#### Public Resolver API

- [ ] Add a configurable resolver constructor or builder with unexported state
  for upstream pools, transport instances, health metrics, and cache integration.
- [ ] Add ergonomic high-level helpers for A/AAAA lookup, TXT, MX, SRV, CNAME,
  and reverse lookups, with explicit context/deadline support in async APIs.
- [ ] Add a low-level `query` operation for name, type, and class, and an
  `exchange` operation for caller-constructed messages with custom flags, EDNS,
  or DNSSEC settings.
- [ ] Return a response type that contains the decoded `Message` plus metadata:
  upstream ID, protocol, server address, round-trip time, retry count,
  truncation/fallback state, and cache status.
- [ ] Keep high-level helpers ergonomic while allowing low-level callers to
  inspect RCODEs, TTLs, authority/additional records, EDNS options, and metadata.
- [ ] Add convenience getters and inspection methods for messages and records.
- [ ] Replace resolver stdout diagnostics with logging or structured response
  metadata.

#### Cache And Extended DNS Errors

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

#### Testing And Migration

- [ ] Provide injectable transport implementations or mocks so resolver tests do
  not require real network sockets.
- [ ] Test retry budgets, exponential backoff and jitter bounds, failover,
  circuit transitions, SRTT ordering, racing cancellation, and deadline expiry.
- [ ] Test transaction/question validation and UDP-to-TCP fallback with mocked
  upstreams, including malformed, truncated, stale, and mismatched responses.
- [ ] Test cache TTL expiry, negative caching, EDE-aware decisions, and metadata.
- [ ] Add integration tests for each transport independently from resolver policy.
- [ ] Migrate existing multi-server low-level constructors toward single-target
  transports with deprecation guidance before the 1.0 API freeze.

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

## Definition Of Done

- Compatibility fixes are clearly separated from new features.
- `0.7.0` adds functionality without breaking existing callers or defaults.
- Security and parser protections remain covered by deterministic tests and fuzzing.
- Public errors, timeout behavior, and client semantics are documented.
- Every release passes formatting, Clippy, rustdoc, tests, dependency checks, and
  the relevant semver review.
