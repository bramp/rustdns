---
title: "feat: integrate Deckard conformance testing"
type: feat
date: 2026-10-26
---

# Deckard adoption and conformance test plan

## 1. Decision and scope

Adopt a pinned Deckard release or commit as an opt-in, Linux-container test
runner. Start with a curated suite for rustdns transports, configured-upstream
resolution, and local DNSSEC validation. Keep existing unit tests, integration
tests, and fuzz targets.

Do not build a competing scenario engine, turn rustdns into a production DNS
server, or make the entire upstream resolver suite a compatibility requirement.
Deckard supplies the simulated network, scripted messages, fake time, process
management, and packet capture. rustdns supplies a small test-only target adapter
and explicit expectations for its supported behavior.

This document is a plan, not an implementation. The experiment described below
ran Deckard against Unbound, **not rustdns**. No rustdns conformance result exists
yet.

### Architectural boundary

The [resolver design](../../DESIGN.md#1-resolver-architecture--design-contract)
places upstream selection and retries above single-target transports. The
current resolver sends queries to configured recursive upstreams. Its DNSSEC
validator walks a chain of trust by issuing DNSKEY and DS queries through those
upstreams; it does not walk authoritative-server referrals from root hints.

Therefore:

- Test DNSSEC dependency lookups through one or more scripted recursive
  upstream endpoints.
- Do not configure a simulated root server and expect rustdns to perform
  Unbound-style iterative resolution.
- Do not add iterative recursion merely to reuse upstream tests.
- Distinguish the adapter's DNS listener from the rustdns client APIs under test.

## 2. Evidence from the Docker experiment

### Environment and provenance

The experiment ran on October 25, 2026:

| Component | Observed configuration |
|---|---|
| Host | macOS, Apple Silicon |
| Container architecture | Native Linux ARM64; no x86 emulation |
| Runtime | Docker Desktop; server reported Docker 27.4.0 |
| Base image | `debian:bookworm-slim` |
| Deckard revision | `e51f539570a2ccfd9d32e01281ade6fdbc76d185` |
| Reference target | Debian Unbound 1.17.1 |
| Python packages | Python 3.11, dnspython 2.3.0, pytest 7.2.1, pyroute2 0.7.2 |
| Additional package | LIEF 0.16.7, installed in a virtual environment |
| Time and capture | libfaketime 0.9.10; tshark 4.0.17 |
| Runtime isolation | `--privileged --network none`; no host-network mode |
| Main repository | No integration code added by the experiment |

The base tag and Debian package repositories were mutable. This identifies the
experiment but does not make its image bit-for-bit reproducible. Productionizing
the runner requires an image digest, dependency lock/provenance, and a controlled
update procedure. Debian had no `python3-lief` package for this build, so the
experiment used a pinned ARM64 wheel.

### What passed

- Deckard's own unit tests: **9 passed**.
- Linux user/network namespace creation inside the privileged container.
- Two upstream iterative-resolution smoke scenarios against Unbound.
- A valid DNSSEC scenario with static anchors, including a captured root DNSKEY
  lookup and an authenticated final response.
- A custom scenario marking the root DNSKEY mock entry `MANDATORY`.
- A custom malformed-query scenario followed by successful valid resolution.
- Two negative controls: an unused mandatory entry and an intentionally incorrect
  final-answer expectation both produced the intended assertion failures.

The observed DNSSEC transcript was:

```text
driver -> Unbound             . NS
Unbound -> simulated server   . NS
Unbound -> simulated server   . DNSKEY
Unbound -> simulated server   root-server A
Unbound -> driver             . NS, AD=1
```

This proves a DNSKEY dependency interaction, **not a child/parent DS chain**.
The malformed input went into Unbound's server listener; it did not exercise
rustdns parsing of a malformed upstream response.

### Upstream scenario results

These are scenario-file outcomes, not a percentage of DNS standards covered.
Deckard can parameterize a file for QNAME minimization on/off; skipped variants
are not additional passing scenarios.

| Scenario file | Original Unbound template | Static-anchor template | Interpretation |
|---|---|---|---|
| `iter_hint_lame.rpl` | Pass | Pass | Reference iterative-resolution smoke |
| `iter_lame_root.rpl` | Pass | Pass | Reference iterative-resolution smoke |
| `iter_badraw.rpl` | Fail | Fail | Timed out; smaller custom recovery probe passed |
| `val_minimal_noerror.rpl` | Fail | Pass | Static anchors removed startup-probe interference |
| `val_minimal_expiredsignature.rpl` | Pass | Fail | Static run returned Secure within Unbound's skew tolerance |
| `val_minimal_beforeinception.rpl` | Pass | Pass | Expected rejection observed; add positive controls before crediting validation coverage |
| `val_minimal_badrrsigsignature.rpl` | Pass | Pass | Expected rejection observed; require key-fetch evidence in curated replacement |
| `val_minimal_baddsdigest.rpl` | Pass | Pass | Tests anchor/DS digest mismatch, not a demonstrated child DS lookup |
| `nsec_no_data_response.rpl` | Fail | Fail | Missing answers for additional queries; expected result not established |
| `nsec_name_error_response.rpl` | Fail | Fail | Undefined extra queries caused scenario failure |
| `nsec3_wildcard_no_data_response.rpl` | Fail | Fail | Missing root-priming responses, among other setup limitations |

Both configurations passed 6 of 11 selected files, but not the same six.
The original template's rejection cases are weak evidence: a setup failure can
produce the expected SERVFAIL without reaching the intended cryptographic check.
The positive control and dependency assertions must run beside every negative
test family.

The checked-out upstream tree contains 193 `.rpl` files under `sets/`: 191 under
`sets/resolver` and two under `sets/knotd`. That inventory is not a claim that
all files are suitable for rustdns, run successfully, or cover distinct features.

## 3. Running Deckard

### Immediate experiment reproduction

The experiment remains in session storage:

```sh
EXPERIMENT=/Users/bramp/.copilot/session-state/5d4f6215-37ed-4ece-a54f-2a86c3575131/files
bash "$EXPERIMENT/deckard-check.sh"
```

That script builds the image, runs nine Deckard unit tests, and runs four focused
probes. It checks that both deliberate failures fail for the expected reason.
It does **not** run rustdns or the complete 11-file sample.

To repeat the wider sample with the static-anchor adjustment:

```sh
EXPERIMENT=/Users/bramp/.copilot/session-state/5d4f6215-37ed-4ece-a54f-2a86c3575131/files
DECKARD_CONFIG=configs/unbound-static.yaml \
DECKARD_RESULTS="$EXPERIMENT/deckard-static-results" \
  bash "$EXPERIMENT/deckard-smoke.sh"
```

The latter command currently exits nonzero because five sample files fail.
Preserve separate results directories when comparing runs. Session storage is
temporary project provenance, not the permanent CI dependency source.

### Permanent operating model

1. Fetch the exact Deckard revision during setup/build, with HTTPS and commit
   verification. Retain its license and notices. Follow the existing
   [external-fixture policy](../../DEVELOPERS.md#bind-checkzone-conformance).
2. Build a Linux image containing Python dependencies, libfaketime, capture tools,
   reference Unbound, and a Linux-built rustdns target. Never use a macOS binary
   in the container.
3. Build with network access; execute tests with `--network none`.
4. Start one ephemeral container per suite invocation, initially serial.
5. Use `--privileged` only on a dedicated local Docker VM or disposable CI runner.
   Mount only a results directory at runtime, plus explicitly needed read-only
   test data. Never mount the Docker socket, home directory, or credentials.
6. Give every run a unique results directory. Record image ID/digest, Deckard and
   rustdns revisions, dirty-state indicator, tool versions, selected cases, and
   exact invocation.
7. Apply an outer real-time timeout, independent of libfaketime. Clean up the
   container on success, failure, interruption, and timeout.
8. Preserve the rendered config, anchors, scenario, stdout/stderr, target
   JSONL results, JUnit, packet captures, and decoded DNS transcript.

Linux is an execution requirement. macOS developers can author cases and run the
same Linux image through Docker Desktop. Do not change host DNS, root hints,
routes, or firewall rules.

### Proposed command interface

Implement one repository entry point, `scripts/run_deckard.sh`, rather than
several overlapping launchers. The following commands are **planned, not
available yet**:

```sh
./scripts/run_deckard.sh build
./scripts/run_deckard.sh inventory --check
./scripts/run_deckard.sh self-test
./scripts/run_deckard.sh reference --suite smoke
./scripts/run_deckard.sh rustdns --suite smoke
./scripts/run_deckard.sh rustdns --suite smoke --repeat 10
./scripts/run_deckard.sh controls
```

`self-test` covers Deckard, reference fake-time behavior, and the independent
packet analyzer; after Phase 2 it must also probe the Rust target's clocks.
`reference` uses Unbound; `rustdns` uses the target adapter. Neither
target's pass substitutes for the other's. `controls` succeeds only when each
deliberately broken case produces its specified assertion failure, not an
unrelated crash, missing fixture, or timeout.

`inventory --check` validates all selected cases, expectations, source hashes,
and exclusions without Docker or downloading fixtures. During execution,
missing Docker, missing fixtures, zero collected cases, unexpected skips, stale
expected failures, and missing artifacts must fail explicitly.

## 4. Deckard limitations and upstream improvement requests

The findings below apply to the pinned revision. Recheck them before reporting.
Search the canonical [upstream tracker](https://gitlab.nic.cz/knot/deckard/-/issues)
for duplicates. Do not file issues automatically as part of this plan.

| Priority | Finding and evidence | What to ask upstream | Local approach |
|---|---|---|---|
| P0: before trusting network assertions | `TCPDump.check_for_unknown_server()` skips packets when protocol is not TCP **or** not UDP; this is always true. A captured DNS exchange passed with an empty allowed-address set. | Fix protocol selection, add positive/negative regression PCAPs, and test IPv4/IPv6 packet decoding. Report the exact commit and minimal empty-allowlist reproduction. | Keep `--network none`; add an independently tested analyzer for allowed destinations. Never describe the existing check as working. |
| P1: prevent false confidence | `CHECK_OUT_QUERY` is accepted by the grammar but ignored by `Step.play()`. | Implement it with defined matching/count semantics, or reject it clearly. Document `MANDATORY` and add tests showing missing lookups fail. | Reject selected scenarios containing ignored assertions. Use mandatory entries plus transcript checks. |
| P1: reliable DNSSEC startup | The Unbound template uses `auto-trust-anchor-file`; probes can start before fake endpoints are ready. Static anchors made the valid case pass. | Support static anchors for fixed-fixture tests; consider preparing fake endpoints before starting daemons. Keep RFC 5011/automatic-anchor tests as a separate capability. | Use a small static-anchor wrapper template for reference calibration; retain the original result. Do not claim a proven general fix for startup ordering. |
| P1: diagnosis | Undefined queries and ICMP can be reported as "under load," masking fixture gaps and triggering retries. | Classify unexpected queries, ICMP, actual scheduling delays, and response mismatches separately; include destination, transport, question, and step. | Run gating tests with `--retries=0`; retain first failure and artifacts. Track reruns as diagnostics, not passes. |
| P1: expectations | A raw SERVFAIL expectation can pass because of a setup error rather than the intended DNSSEC defect. | Add paired positive/negative examples, required dependency queries, and rejection-stage evidence where practical. | Add controls and structured target error categories. Require no undefined upstream queries. |
| P2: interaction precision | `MANDATORY` checks that an entry fired at least once, not exact counts, forbidden queries, or general ordering. Transport is absent from the RPL match-option list. | Add/document min/max counts, forbidden interactions, partial ordering, and transport-aware matching. | Analyze PCAPs; avoid exact ordering unless required by the behavior under test. |
| P2: fixture portability | Reference fixtures can omit legal auxiliary queries; clock-skew and resolver policy differ. | Add scenario capability/policy metadata, target compatibility notes, and explicit supported reference profiles. | Curate cases; declare policy differences and missing-feature exclusions. Never weaken expected DNSSEC results just to turn a run green. |
| P2: installation | Linux namespaces require a capable Linux kernel; documented Docker use is privileged. ARM64 setup needed a separate LIEF wheel. | Publish versioned ARM64/AMD64 images, dependency locks, a Docker quickstart, and documented minimum privileges validated by tests. | Keep a pinned local recipe; do not promise unprivileged or native macOS execution. |
| P2: runner/reporting | `run.sh` executes monotonic and non-monotonic groups separately; the same JUnit path can be overwritten. QMIN variants inflate counts. | Publish separate or aggregated reports with unique scenario IDs and explicit skip reasons. | Use distinct group report paths; aggregate in the wrapper and validate expected execution counts. |

For each report, supply a minimal standalone reproduction, observed and expected
behavior, versions/architecture, and proposed regression test. Verify corrected
upstream revisions before removing any local workaround. Keep any temporary patch
small, commit-pinned, documented, and covered by the same negative control.

### Limitations that need a local design, not an upstream bug report

- A library has no DNS listening process. We must supply an adapter.
- Most iterative-recursion cases do not match rustdns's configured-upstream role.
- `RAW` permits malformed DNS payloads, but does not imply arbitrary TCP
  segmentation, TLS failure injection, or programmable packet scheduling.
- Raw-query steps send data without waiting for an answer. Follow-up liveness is
  useful, but does not prove a particular rejection code or error path.
- Linux fake-time success with Unbound does not establish fake-time success with
  Rust's `SystemTime` and `Instant`; test both in the actual Linux target.
- Neither reference implementations nor majority voting define correctness.
  Expected behavior comes from RFCs and rustdns's explicit API/policy contract.

## 5. rustdns integration design

### Test-only target, not a new production server

Add `examples/deckard_target.rs`, registered as an example in
[Cargo.toml](../../Cargo.toml), with
`required-features = ["resolver", "do53", "json"]`. Reuse existing Tokio,
serialization, message, transport, and trust-anchor types. Keep the example out
of default builds when those features are disabled; preserve MSRV 1.86.

The adapter binds Deckard's rendered `SELF_ADDR` on UDP/TCP port 53 inside the
isolated container. Deckard checks TCP readiness and sends DNS queries to it.
The adapter calls rustdns and exposes results to Deckard. Its own listener and
response encoding are test plumbing, not newly certified server behavior.

```text
Deckard driver
    |
    | trigger query
    v
test-only adapter listener
    |
    +-- resolver mode --> Resolver::query_with_deadline
    |                         |
    |                         +-- primary query --> scripted recursive upstream
    |                         +-- DNSKEY / DS ----> same configured upstream
    |
    +-- transport mode -> AsyncExchanger::exchange --> scripted upstream
    |
    +-- JSONL: actual library outcome, status, error category, timing
    +-- DNS response: narrowly defined projection for CHECK_ANSWER
```

Use numeric upstream addresses, not hostnames requiring bootstrap DNS. Every
endpoint is explicit. One scripted endpoint may answer many zones. For failover,
use two distinct configured endpoints, with independently asserted traffic.

### Configuration and entry points

Render a small JSON config with:

- Listener address, operation mode, transport, and allowed upstream endpoints.
- DNSSEC mode: Off, TrustUpstream, or ValidateLocal.
- Upstream trust policy and `require_secure`, when applicable.
- Explicit fixture trust anchors, deadline, retries, and output path.

Represent fixture anchors as typed fields and validated digest bytes. Construct
a fresh `TrustStore::empty()` and add only those anchors; never silently fall
back to built-in live root anchors on an input error. Avoid a new trust-anchor
file parser if JSON can map directly to the existing public types.

Two modes are necessary:

1. **Resolver mode:** Accept only the supported trigger shape: one IN question,
   QUERY opcode. Call
   [query_with_deadline](../../src/clients/resolver/async.rs), not `exchange`.
   The latter does not enforce local validation. This mode tests the public
   query API; it does not preserve caller-selected CD/DO flags or arbitrary
   classes. Reject unsupported triggers explicitly.
2. **Transport mode:** Forward the trigger message through the selected existing
   UDP, TCP, or Do53 exchanger. This tests transport parsing and correlation,
   without claiming local DNSSEC validation.

The initial listener needs only the bounded framing/dispatch required to drive
these cases. Reuse framing helpers if publicly available; otherwise keep any
necessary framing logic local and small. Do not expose production internals
solely for this example. Add unit tests for adapter configuration, projection,
and framing boundaries.

### Outcome handling: preserve the distinction between result and projection

Every trigger emits exactly one machine-readable terminal JSONL event, flushed
before sending its projected DNS response:

- Case/query identity, requested operation, and selected mode.
- `ok` versus typed library error category and useful error context.
- `security_status` only when the library provides one or a DNSSEC error has an
  existing classification. Never invent Secure/Insecure/Bogus for I/O failures.
- Observed upstream endpoint/metadata where available, elapsed monotonic time,
  and the original decoded response before adapter header changes on success.

For successful resolver queries, copy the returned DNS message, restore trigger
ID/question correlation, and derive the adapter AD bit from the library's
`SecurityStatus::Secure`, never from upstream AD. Label every other header
projection and test it. Error projection may use SERVFAIL to unblock
`CHECK_ANSWER`, but the result checker must also match the JSONL error category;
a generic SERVFAIL is never enough to pass a negative test.

Configuration errors, adapter crashes, missing terminal events, malformed logs,
and unsupported triggers are infrastructure failures, not expected target
rejections. Preserve source errors and log them; do not catch everything and
return a success-shaped response.

### State, time, and safety

- Create a fresh process/resolver per cold-cache scenario. Retain it across
  steps only for explicit cache/reuse tests.
- Keep one deadline through primary and dependency queries. Bound listener
  buffers, TCP frame sizes, concurrent work, retries, and artifact growth.
- Bind a non-loopback documentation address for untrusted-AD tests. rustdns
  treats loopback as a trusted channel; a loopback-only fixture would miss that
  branch. Do not change production trust policy to accommodate the test.
- Probe `SystemTime::now()` under libfaketime using the actual target binary.
  Verify wall-clock jumps affect signature checks while the default
  non-monotonic-faking mode leaves `Instant` deadlines progressing normally.
- Keep wall-clock validity and cache-TTL/monotonic tests separate. Do not enable
  monotonic faking for every case.
- If Rust bypasses the interception on a platform, stop and report unsupported
  fake time. First use a compatible dynamically linked Linux build; only plan
  an additive clock seam if evidence shows it is necessary.

## 6. Test coverage contract

### Initial rustdns smoke suite: 12 proposed scenarios

None of these rustdns scenarios has run yet. All require an explicit outcome,
allowed-query set, positive/negative controls where applicable, and captured
traffic. IDs below are proposed permanent case IDs.

| ID | Behavior and assertions | Layer / prerequisite |
|---|---|---|
| R01 | Valid A response returned with the expected data; primary query reaches only the configured endpoint | Resolver Off; baseline for transport/configuration |
| R02 | Valid root-anchored signed RRset returns Secure; root DNSKEY fetch is mandatory | ValidateLocal; independent signed fixture |
| R03 | Valid child-zone RRset returns Secure; child DNSKEY, child DS, and parent DNSKEY dependency fetches are mandatory | ValidateLocal; cold cache, one existing DS-digest anchor for the parent, no child anchor or prefetched keys |
| R04 | Same fixture as R03, one signature corrupted; specific DNSSEC failure, never Secure | ValidateLocal; pair with R03 |
| R05 | Same fixture as R03, DS digest mismatch; expected chain failure after the intended dependency exchanges | ValidateLocal; pair with R03 |
| R06 | Expired signature fails at a controlled time outside the documented tolerance; paired in-window R03 passes | ValidateLocal; proven fake-time support |
| R07 | Signature before inception fails outside tolerance; paired in-window R03 passes | ValidateLocal; proven fake-time support |
| R08 | Upstream AD=1 with cryptographically bogus data still fails local validation | ValidateLocal; no upstream-AD shortcut |
| R09 | Otherwise-valid AD=1 response over non-loopback plaintext is Indeterminate/untrusted in default upstream-trust policy | TrustUpstream; non-loopback endpoint, expected typed error |
| R10 | Structurally malformed upstream DNS response causes the specified parse/transport error; no accepted answer | Transport mode; raw response with matching ID where necessary |
| R11 | Wrong-ID response is never accepted as success; record current API rejection behavior and deadline | UDP transport; do not assume "ignore then accept later" without a documented contract |
| R12 | First upstream withholds answers; second returns valid data; success, observed failover, and bounded overall time | Resolver Off; two endpoints and explicit retry/deadline settings |

R03 must make each required dependency unavoidable: use two zones with a direct
parent/child delegation, start with empty caches, provide no prefetched keys in
the primary response, and anchor only the parent. Existing `TrustAnchor` values
already store DS-digest fields, not a choice between DS and DNSKEY anchor types.
The current chain validator fetches zone DNSKEYs before comparing a key's digest
with an anchor; without a child anchor, it fetches the child's DS RRset and
validates that RRset through the parent keys. Prove this path in the actual
fixture rather than crediting code inspection as executed coverage. Do not
require an irrelevant query that a correct implementation can avoid.
`MANDATORY` proves at least one matching exchange; the transcript checker
enforces forbidden queries and justified count bounds.

### Follow-on coverage, after the initial gates

| Family | Cases to add | What remains to prove |
|---|---|---|
| Authenticated denial | Secure NXDOMAIN and NODATA, invalid/missing NSEC proofs, NSEC3 closest-encloser/next-closer/wildcard failures | Repair/replace incompatible fixtures; distinguish validation from retrieval failures |
| Insecure delegation | Authenticated absence of DS, forged absence, NSEC3 Opt-Out, more-specific trust-anchor precedence | Insecure requires a valid proof; unsigned data alone is insufficient |
| Aliases/wildcards | CNAME to signed/unsigned target, missing terminal denial, valid wildcard and missing expansion proof | Queries, owner names, signer scopes, and status propagation |
| Key handling | Multiple signatures, rollover, wrong key tag, unsupported algorithms/digests | Explicit supported-algorithm and RFC policy; do not turn unsupported into Secure |
| Cache behavior | Repeated query reuses DNSKEY/DS, expiry fetches again, invalid signatures remain invalid with cached keys | Assert counts and timing; no claim of a general answer cache |
| EDNS | DO/CD on primary and dependencies, payload size, malformed OPT, extended RCODE | Packet-based field assertions, not just presence of any query |
| Transport fallback | UDP TC=1 followed by successful TCP fetch | RPL matching cannot distinguish transport; likely needs a small protocol-aware fixture responder or upstream extension |
| Correlation/bounds | Wrong question/QR, short headers, bad RDLENGTH, compression loops, oversize work | Exact error expectations, target remains responsive, input/work limits preserved |
| Deadlines | Delayed dependency consumes remaining budget; no nested timeout extension | Monotonic measurement in target plus outer real-time watchdog |
| Upstream policy | Trusted loopback AD, untrusted plaintext AD, AD=0 with both require-secure settings | Policy cases are not cryptographic validation cases |
| IPv6 | IPv6 endpoints and capture decoding | Current UDP implementation binds an IPv4 socket; treat IPv6 support as a separate compatibility gate, not presumed coverage |

For UDP-to-TCP fallback, simply returning TC=1 from one generic mock for both
protocols cannot prove success. Keep the test deferred until the TCP reply can
be configured independently. Similarly, partial TCP frames, out-of-order or
duplicate timed replies, DoT/DoH errors, and adversarial TLS need capabilities
beyond the verified RPL feature set.

### Explicitly outside this suite

- Iterative referral walking, root-hints selection, bailiwick/glue policy,
  QNAME-minimization algorithms, and authoritative/secondary server behavior.
- DNAME substitution and negative ANY proofs, currently unsupported by local
  validation. Track these as unsupported, not as passing conformance tests.
- Zone-file parser conformance, browser/WASM behavior, full algorithm
  certification, automatic trust-anchor rollover, and arbitrary network stacks.
- High-volume load, latency benchmarking, memory-exhaustion certification, and
  exhaustive fuzzing. Preserve dedicated benchmarks and fuzz targets.
- Full DoT/DoH/TLS conformance without a separate controlled endpoint.

### Query oracle and coverage accounting

Maintain `tests/deckard/cases.yaml` as a small explicit inventory, not a new
general-purpose scenario language. Each entry records:

- Stable ID, source revision/hash/license, execution target, and upstream file
  or local `.rpl` path.
- Requirement/RFC basis, operation mode, transport, DNSSEC/trust settings, and
  expected typed outcome.
- Required and forbidden query tuples, destination/transport expectations,
  justified count bounds, and cache/time preconditions.
- `enabled`, `expected-failure`, or `excluded`, with a reason and linked
  follow-up for every non-enabled case.

Expected failures must match a specific failure stage/category. Unexpected pass,
new failure reason, infrastructure failure, or expiry of the exception fails
the run. Report totals separately: enabled pass/fail, expected failures,
excluded, and infrastructure errors. Never count controls, skipped QMIN
variants, or reference passes as rustdns feature coverage.

All initial rustdns cases must select QNAME minimization off; rustdns does not
implement iterative QNAME minimization. Reject a selected rustdns scenario that
requests it. Preserve upstream variants only in the reference inventory and
verify that the expected off variant actually ran.

Parse captures independently with dnspython/dpkt or tshark. Check queries to
destination port 53 against explicit endpoints, distinguish target traffic from
driver traffic, normalize DNS names, and preserve protocol/transaction context.
Handle IPv4/IPv6, capture link types, retransmissions, and TCP framing explicitly.
Fail on undecodable or incomplete evidence when that evidence is required.
Do not compare a set of questions alone when counts, destinations, or ordering
matter. Validate the analyzer with synthetic forbidden-destination, missing
dependency, duplicate-count, and incorrect-flag captures.

## 7. Implementation phases

Each phase is independently reviewable. Do not mix unrelated resolver fixes into
the runner integration. If a scenario exposes a rustdns defect, preserve its
failing evidence, add a focused regression, and fix it in a separate change.

### Phase 1: Preserve and harden the experiment

**Status:** Not started in the repository; session prototype exists.

**Scope:** Move the recipe, focused probes, and reference calibration into a
repeatable opt-in runner. Fix or independently guard harness false negatives
before using the runner as a gate.

**Files touched:**

- `scripts/run_deckard.sh`: single entry point, dependency fetch/build, cleanup.
- `tests/deckard/Dockerfile`: digest-pinned Linux environment and build stage.
- `tests/deckard/cases.yaml`: tool pins and explicit scenario dispositions.
- `tests/deckard/check_results.py`: small runner-level checker, capture
  assertions, control checks, and inventory validation.
- `tests/deckard/configs/` and `tests/deckard/scenarios/`: reference config,
  static-anchor wrapper, focused controls, and license notices as needed.
- [DEVELOPERS.md](../../DEVELOPERS.md): setup, runtime privileges, reproduction,
  results, and known limitations.
- [.gitignore](../../.gitignore): named Deckard download/results paths only.

**Tasks:**

- [ ] Verify canonical revision and dependency/image provenance.
- [ ] Preserve license/attribution and fixture hashes.
- [ ] Add a namespace preflight and reference fake-time/monotonic probes; the
  Rust-specific probe belongs to Phase 2.
- [ ] Implement analyzer regressions, including the empty-allowlist failure.
- [ ] Test checker behavior using synthetic events/captures independently of
  Unbound, including missing events, wrong categories, and ignored assertions.
- [ ] Aggregate distinct JUnit reports; disallow zero-test success.
- [ ] Use zero automatic retries for gates and unique artifact directories.
- [ ] Reproduce the positive reference and deliberate-failure controls.

**Validation:** `inventory --check`, `self-test`, `reference --suite smoke`, and
`controls` commands defined above must pass. Deliberate negative controls pass
only by detecting the specified failure.

### Phase 2: Add the rustdns adapter and smoke suite

**Status:** Not started. Depends on Phase 1.

**Scope:** Add the test-only example and R01-R12. Preserve public APIs and
production defaults.

**Files touched:**

- `examples/deckard_target.rs` and [Cargo.toml](../../Cargo.toml).
- [Cargo.lock](../../Cargo.lock) only if dependency resolution actually changes.
- `tests/deckard/configs/rustdns.yaml` and a JSON Jinja template.
- `tests/deckard/scenarios/`, `tests/deckard/cases.yaml`, and result checks.
- [DEVELOPERS.md](../../DEVELOPERS.md) and
  [CHANGELOG.md](../../CHANGELOG.md) under `[Unreleased]` for the new opt-in tooling.

**Tasks:**

- [ ] Build the example in Linux and prove readiness, termination, and log flush.
- [ ] Cover adapter config/error/projection/framing behavior with focused tests.
- [ ] Verify actual Rust wall-clock interception and progressing deadlines.
- [ ] Enable resolver and transport modes with explicit feature gates.
- [ ] Add paired signed fixtures from an independent generator; preserve source,
  signing inputs, fixed validation time, algorithms, and regeneration command.
- [ ] Prove R03 DNSKEY/DS/parent dependencies from a cold cache.
- [ ] Match JSONL results and PCAPs; reject undefined upstream questions.
- [ ] Run all 12 enabled cases ten times serially, with no automatic retries.

**Validation:** `rustdns --suite smoke --repeat 10` must execute exactly 120
enabled rustdns cases with no unexpected failures/skips; run controls separately.
All R01-R12 must be enabled to complete this phase. An expected-failure or
excluded disposition may document an intermediate result, but cannot satisfy
this gate; reducing the initial scope requires an explicit plan change. Run the
Rust checks in Section 8 before merging.

### Phase 3: Gate the curated suite in CI

**Status:** Not started. Depends on Phase 2.

**Scope:** Add a separate Linux job so ordinary Cargo tests remain Docker-free.
Keep privileged execution away from credentials and shared runners.

**Files touched:**

- `.github/workflows/deckard.yml`.
- `scripts/run_deckard.sh`, only for CI-specific artifact/report integration.
- [DEVELOPERS.md](../../DEVELOPERS.md).

**Tasks:**

- [ ] Use a disposable Linux runner capable of privileged namespaces.
- [ ] Use read-only repository permissions, no publish credentials, no Docker
  socket mount, and no privileged `pull_request_target` execution.
- [ ] Build/fetch before isolated execution; record provenance and cache keys.
- [ ] Run inventory, harness controls, reference calibration, and rustdns smoke.
- [ ] Upload diagnostics on success/failure with bounded size and retention.
- [ ] Test AMD64 in CI and keep the native ARM64 local recipe working.
- [ ] Run the adapter build/check on stable and MSRV 1.86; runtime coverage can
  initially use one toolchain if the report states that limitation.

**Validation:** Manual: (1) run the workflow on a branch, (2) inspect exact case
counts and artifacts, (3) inject one deliberate expectation failure and confirm
the job fails, (4) remove it and rerun, (5) inspect permissions and cleanup.

### Phase 4: Expand only from measured gaps

**Status:** Deferred. Depends on the first three phases.

Add denial proofs, insecure delegation, aliases/wildcards, cache timing, and
more malformed responses in small batches. Calibrate each fixture on a suitable
reference profile, then test rustdns independently. Treat transport-aware
fallback and TLS as separate additions requiring a proven stimulus mechanism.

Success is coverage of explicit requirements with reliable evidence, not the
number of upstream files imported.

## 8. Success criteria and validation

The commands below are an implementation contract for the proposed runner.
They do not exist merely because this planning document names them.

```success-criteria
GOAL: Run a curated, independent Deckard suite against rustdns in an isolated Linux container, with explicit coverage and trustworthy failures.

SUCCESS CRITERIA:
- Every selected fixture has a pinned source, disposition, requirement, mode, and expected outcome; ignored assertions and incomplete entries fail validation. | verify: ./scripts/run_deckard.sh inventory --check
- Namespace, fake-time, monotonic-deadline, analyzer, and upstream unit probes pass without external networking during execution. | verify: ./scripts/run_deckard.sh self-test
- The calibrated Unbound reference subset passes with static anchors and retained diagnostics. | verify: ./scripts/run_deckard.sh reference --suite smoke
- All 12 enabled rustdns smoke cases pass ten serial runs, including required child DS/DNSKEY dependencies and typed rejection outcomes; skips and missing evidence fail. | verify: ./scripts/run_deckard.sh rustdns --suite smoke --repeat 10
- Missing mandatory queries, wrong outcomes, forbidden traffic, and incorrect flags/counts produce their specified assertion failures; crashes and timeouts do not satisfy controls. | verify: ./scripts/run_deckard.sh controls
- The adapter preserves the declared feature matrix and MSRV, and remains test-only. | verify: cargo check --workspace --all-targets --all-features && cargo +1.86 check --workspace --all-targets --all-features
- Privileged CI runs on disposable Linux infrastructure with read-only permissions, complete artifacts, and verified cleanup. | verify: manual 1. Run the dedicated workflow. 2. Inspect permissions and case counts. 3. Confirm injected failure detection. 4. Inspect diagnostics and absence of leftover containers.

NON-GOALS:
- Iterative recursion, production DNS serving, complete upstream-suite compatibility, native macOS Deckard execution, or DNS conformance certification.
- Replacing fuzzing, load benchmarks, zone parser tests, or TLS-specific suites.

VERIFICATION COMMAND: ./scripts/run_deckard.sh inventory --check && ./scripts/run_deckard.sh self-test && ./scripts/run_deckard.sh reference --suite smoke && ./scripts/run_deckard.sh rustdns --suite smoke --repeat 10 && ./scripts/run_deckard.sh controls && cargo check --workspace --all-targets --all-features && cargo +1.86 check --workspace --all-targets --all-features
```

For implementation phases touching Rust, first run focused adapter and regression
tests, then the repository's normal validation:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test --workspace --no-default-features
cargo test --workspace --all-features
cargo check --workspace --all-targets --all-features
cargo +1.86 check --workspace --all-targets --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
```

Run the adapter's focused tests with its required features enabled. If crate
documentation changes, regenerate and verify the README using the repository's
existing process. This documentation-only plan does not require running Cargo.

## 9. Risks and stop conditions

- **Wrong target abstraction:** Stop importing iterative scenarios when they
  require a recursive server. Rewrite the stimulus for a forwarding upstream;
  do not simulate recursion in the adapter.
- **False negative controls:** Stop gating on a case if its expected failure
  also occurs when the fixture/server is broken. Add the paired positive and
  dependency/error-stage evidence first.
- **Unverified time:** Stop expired/inception/cache-time claims if the Rust
  target's wall/monotonic probes fail.
- **Unreliable observation:** Stop query-count/egress claims if required captures
  are incomplete or the analyzer cannot decode them.
- **Platform gaps:** Record unsupported capabilities explicitly. Do not silently
  drop IPv6, TLS, or unsupported record-shape tests while reporting full coverage.
- **Scope growth:** Keep the core integration in Phases 1-3; Phase 4 is follow-up,
  not a reason to delay a reliable small suite.

## 10. Sources and handoff

### Project sources

- [Resolver contract and DNSSEC scope](../../DESIGN.md).
- [Resolver query API and local validation](../../src/clients/resolver/async.rs).
- [Resolver configuration](../../src/clients/resolver/builder.rs).
- [Dependency lookups and cache](../../src/dnssec/chain.rs).
- [Trust anchors](../../src/dnssec/anchor.rs) and
  [security/trust modes](../../src/types.rs).
- [Do53 UDP/TCP fallback](../../src/clients/do53/async.rs).
- [Existing client integration tests](../../tests/clients.rs),
  [resolver tests](../../tests/resolver.rs), and
  [fuzz targets](../../fuzz/fuzz_targets).
- [Fixture maintenance and MSRV policy](../../DEVELOPERS.md).

### Upstream sources pinned to the experiment

- [Canonical Deckard project](https://gitlab.nic.cz/knot/deckard).
- [README and Linux requirements](https://github.com/CZ-NIC/deckard/blob/e51f539570a2ccfd9d32e01281ade6fdbc76d185/README.rst).
- [Program/configuration contract](https://github.com/CZ-NIC/deckard/blob/e51f539570a2ccfd9d32e01281ade6fdbc76d185/doc/user_guide.rst).
- [Scenario guide and RAW entries](https://github.com/CZ-NIC/deckard/blob/e51f539570a2ccfd9d32e01281ade6fdbc76d185/doc/scenario_guide.rst).
- [Packet capture and unknown-destination check](https://github.com/CZ-NIC/deckard/blob/e51f539570a2ccfd9d32e01281ade6fdbc76d185/deckard_pytest.py).
- [Ignored query step and mandatory-entry enforcement](https://github.com/CZ-NIC/deckard/blob/e51f539570a2ccfd9d32e01281ade6fdbc76d185/pydnstest/scenario.py).
- [RPL match grammar](https://github.com/CZ-NIC/deckard/blob/e51f539570a2ccfd9d32e01281ade6fdbc76d185/pydnstest/deckard.aug).
- [Runner and fake-time groups](https://github.com/CZ-NIC/deckard/blob/e51f539570a2ccfd9d32e01281ade6fdbc76d185/run.sh).
- [Unbound template](https://github.com/CZ-NIC/deckard/blob/e51f539570a2ccfd9d32e01281ade6fdbc76d185/template/unbound.j2).

### Experiment evidence

The session experiment path in Section 3 contains:

- `deckard.Dockerfile`, `deckard-check.sh`, `deckard-smoke.sh`, and
  `deckard-probes.py`.
- `deckard-results/summary.tsv`: original-template results.
- `deckard-static-results/summary.tsv`: static-anchor results.
- `deckard-static-results/probes/summary.json`: four focused control outcomes.
- `deckard-static-results/dns-transcript.tsv`: decoded valid DNSSEC exchange.
- Per-scenario logs, JUnit files, rendered configs, anchors, and PCAPs.

Port these artifacts selectively into the repository during Phase 1. Do not
depend on the absolute session path in permanent tooling. No upstream issues,
commits, tags, or pushes are authorized by this plan.
