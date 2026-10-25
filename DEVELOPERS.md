# Developer Guide

## Dependency Updates

[Dependabot](.github/dependabot.yml) checks the main Cargo workspace and the
standalone `fuzz/` workspace together every Friday. Version updates are grouped
by dependency name across both workspaces, with up to 20 open update PRs.
The main workspace includes `dig`, `nslookup`, `generate_tests`, and `web-dig`;
these members do not need separate Dependabot entries.

Existing release cooldowns still apply. Cross-directory grouping applies only
to version updates, not security updates. Incompatible version constraints can
also cause Dependabot to open separate PRs for the same dependency.

## Method Naming Style Guide

Use method names to distinguish the format being converted and whether the
method allocates output or appends to caller-owned storage.

- Use `from_slice` for public fallible decoding from a complete DNS wire-format
  byte slice. Add `TryFrom<&[u8]>` where trait-based construction improves
  ergonomics without replacing the named constructor.
- Use `parse` for crate-internal parsing of a complete typed value from an
  already-positioned parser or bounded wire-format cursor. Do not expose
  cursor-oriented `parse` methods as public APIs unless there is a clear public
  low-level parser abstraction.
- Use `FromStr` and `.parse()` for human-readable text formats, including
  zone-file and dig-style representations. Avoid inherent public `from_str`
  methods unless additional context is required.
- Use `read_*` for low-level reader or cursor extension methods that consume
  primitive DNS wire fields and advance the input position.
- Use `to_vec` for public fallible encoding that allocates and returns a new DNS
  wire-format `Vec<u8>`.
- Use `append_to_vec` for public or crate-visible fallible encoding that appends
  DNS wire-format bytes to a caller-provided `Vec<u8>`.
- Use `write_*` only for crate-internal encoding helpers or `std::io::Write`-style
  APIs. If a method appends specifically to a `Vec<u8>`, prefer `append_to_vec`
  or a more specific `append_*_to_vec` name.
- Use `try_*` for fallible construction or mutation when the non-`try_` spelling
  would look infallible, and keep panicking compatibility wrappers deprecated.
- Use `new` for constructors from already-typed arguments. Use `try_new` when
  validation happens at construction time.
- Prefer standard conversion traits such as `From`, `TryFrom`, and `FromStr` for
  primitive or textual conversions, while retaining named helpers when they are
  clearer or needed for compatibility.

## Record Field Modeling

Prefer rich, idiomatic Rust types over raw primitive integers in resource record structs:
- Use `std::time::Duration` for TTLs and time intervals (e.g., `Record.ttl`, `SOA.refresh`, `RRSIG.original_ttl`).
- Use `std::time::SystemTime` for wall-clock dates and timestamps (e.g., `RRSIG.expiration`, `RRSIG.inception`).
- Use strongly-typed enums for protocol codes (`Type`, `Class`, `Algorithm`, `DigestType`, `Nsec3HashAlgorithm`) with `Unknown(u8|u16)` fallback variants.
- Provide helper methods (such as `expiration_seconds(&self) -> Result<u32, EncodeError>`) when wire or protocol operations require converted primitives.

## RFC Citation And Link Style Guide

When citing RFCs and RFC sections across documentation, code comments, and guides:
- Standardize on uppercase with a space: `"RFC 1234"` (never `"rfc1234"` or `"rfc 1234"`).
- When referencing a specific section, use `"§"` directly attached or spaced with the section number: e.g. `"RFC 1035 §4.1.2"`, `"[RFC 1035 §4.1.2]"`.
- For appendices, use `"Appendix"`: e.g. `"[RFC 4034 Appendix B]"`.
- All RFC references in documentation must link directly to the official IETF Datatracker:
  - RFC root: `https://datatracker.ietf.org/doc/html/rfc1234`
  - Specific section: `https://datatracker.ietf.org/doc/html/rfc1234#section-4.1.2`
  - Specific appendix: `https://datatracker.ietf.org/doc/html/rfc1234#appendix-B`

## Testing Fixtures

Root hint (`named.root`), root zone (`root.zone`), and IANA trust anchor (`root-anchors.xml`) test fixtures can be downloaded or updated using `./scripts/fetch_root_fixtures.sh`:
- Download only root trust anchors:
  ```sh
  ./scripts/fetch_root_fixtures.sh --anchors-only
  ```
- Download all root fixtures (`named.root`, `root.zone`, and `root-anchors.xml`):
  ```sh
  ./scripts/fetch_root_fixtures.sh
  ```
- Force refresh regardless of file age:
  ```sh
  ./scripts/fetch_root_fixtures.sh --force
  ```

### BIND Checkzone Conformance

Fetch the pinned upstream master files and run the opt-in conformance suite:

```sh
./scripts/fetch_bind_fixtures.sh
cargo test -p rustdns --test bind_checkzone -- --include-ignored --nocapture
```

The script downloads the exact BIND commit in [tests/bind_checkzone.yaml](tests/bind_checkzone.yaml)
to ignored `tests/fixtures/bind-checkzone/`, retaining upstream `LICENSE`,
`COPYRIGHT`, and `tests.sh`. Repeat fetches reuse complete matching fixtures;
`--force` refreshes them. No BIND executable or network access is needed by the
tests. CI fetches and explicitly runs the suite on stable Rust and the MSRV.
Ordinary test runs validate the configuration without requiring downloaded data;
the corpus test is explicitly ignored, not silently skipped when fixtures are absent.

The inventory covers every `good*.db` and `bad*.db` in BIND's checkzone `zones/`
directory. Binary files, generated templates, and unrelated inputs used by the
rest of BIND's shell harness are outside this initial suite.

Every file has an explicit disposition:

- `accept`: parsing and origin resolution must succeed and produce records.
- `reject`: parsing/RDATA validation must fail at the configured `error_line`,
  rather than passing because of an unrelated processing error or later record.
- `todo`: a valid upstream fixture currently fails in the specified `failure`
  stage (`parse` or `process`). Unexpected success or a stage change fails the
  test, requiring the exception to be reviewed.
- `excluded`: not executed. Reasons distinguish authoritative-zone/BIND policy
  from deferred negative tests for unsupported functionality. Deferred cases
  carry a `TODO` and a link to a specific [PLAN.md](PLAN.md) feature anchor; do
  not count their unsupported-syntax errors as correct RDATA validation.

Origins default to `example.`; special origins from BIND's runner are explicit.
Missing fixtures, revision mismatches, unlisted files, stale/duplicate entries,
unknown configuration fields, and broken TODO anchors fail the suite.

When updating the pin, fetch again and account for every added or removed master
file. Review upstream `tests.sh` for changed expectations and special options.
When implementing a feature, promote passing TODOs to `accept` and review its
deferred negative cases for promotion to `reject`. Rejection locations alone are
not a substitute for checking BIND's intended failure reason. This is an
acceptance/rejection baseline, not full BIND policy or normalized-record equivalence.

## Minimum Supported Rust Version (MSRV) Policy

`rustdns` targets a modern and predictable Rust baseline:

- **Current MSRV**: Rust **1.86.0**.
- **Scope**: Applies to the `rustdns` library crate and all workspace crates (`dig`, `nslookup`, `generate_tests`, `web-dig`).
- **SemVer Policy**:
  - An MSRV increase is treated as a breaking change for versioning purposes.
  - MSRV will **never** be increased in a patch release (`0.x.Y` or `X.Y.Z`).
  - MSRV increases require at least a **minor version bump** (`0.X.0` pre-1.0, or `X.Y.0` post-1.0) and must be accompanied by an entry in `CHANGELOG.md`.
- **Adherence and Enforcement**:
  - **Manifests**: Every package in the workspace must specify `rust-version = "..."` matching the declared MSRV in its `Cargo.toml`.
  - **CI Validation**: The GitHub Actions workflow (`.github/workflows/rust.yml`) tests against the declared MSRV in its matrix (`matrix.rust: ["1.86", "stable"]`) across all feature flags (`--no-default-features`, default, and `--all-features`) as well as `cargo check --workspace --all-targets --all-features`.
  - **Dependency Additions**: Any new dependency or version bump must compile on the declared MSRV. Check dependency MSRV impact before adopting new crates or versions.
  - **Verification**: Verify compatibility prior to release by testing against the MSRV toolchain:
    ```sh
    cargo +1.86 test --workspace --all-features
    cargo +1.86 check --workspace --all-targets --all-features
    ```
