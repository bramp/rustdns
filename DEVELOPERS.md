# Developer Guide

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
