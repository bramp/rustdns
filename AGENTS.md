# Rustdns Development And Release Instructions

These instructions apply to all development work in this repository.

## Development Principles

- Prefer simple, idiomatic, secure Rust over clever or speculative abstractions.
- Inspect the nearest owning abstraction, tests, and call sites before editing.
- Form a concrete hypothesis about the behavior and identify a focused check that
  could disprove it.
- Fix root causes rather than symptoms.
- Prefer existing project patterns and standard library APIs over new dependencies.
- Use meaningful names, explicit error propagation, checked arithmetic for
  untrusted input, and minimal cloning.
- Do not use input-dependent `unwrap`, `expect`, assertions, or unchecked indexing
  in production paths.
- Keep comments short and explain only non-obvious decisions.

## API And Compatibility

- Preserve existing public APIs, defaults, feature behavior, and data-shape
  compatibility unless a breaking change is explicitly planned.
- Add new behavior through new methods, types, modules, or opt-in builders.
- Keep fallible APIs as the preferred path for caller-provided or untrusted input.
- Preserve useful error context, including source, entry, record, and parse data.

## Testing And Validation

- Add focused regression tests for changed behavior, boundary conditions, malformed
  input, error cases, and feature-gated paths.
- Keep parser and protocol fuzz targets current; retain explicit input/work bounds.
- After each substantive edit, run the narrowest useful validation first.
- Before finishing Rust changes, run as appropriate:
  - `cargo fmt --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - focused tests, then `cargo test --workspace`
  - `cargo test --workspace --no-default-features`
  - `cargo test --workspace --all-features`
  - `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps`
- Run `cargo check --workspace --all-targets --all-features` for release and CI
  changes.
- Do not claim a task is complete until the relevant executable checks pass.

## Documentation

- Document errors and panics for public constructors, parsers, and fallible APIs.
- Keep examples compiling and demonstrate fallible APIs where appropriate.
- When crate documentation changes, regenerate the README:
  `cargo readme -o README.md`.
- Verify generated README changes with `git diff --exit-code -- README.md`.
- Maintain `CHANGELOG.md` using Keep a Changelog categories.
- Keep an `[Unreleased]` section at the top of `CHANGELOG.md`.
- Describe user-visible changes in the release that contains them.
- Add release dates only when a version is released.
- Include GitHub release or comparison links.

## Dependencies And Security

- Add dependencies only when they remove meaningful complexity or provide needed
  functionality.
- Check dependency feature flags, MSRV impact, security advisories, licenses,
  sources, and duplicate versions.
- Do not weaken HTTPS, parser bounds, response limits, or fuzzing protections to
  make tests pass.
- Preserve caller control over semantic response suitability unless the protocol
  requires a transport or syntax validation.

## Commits And Git

- Keep commits small, focused, and independently understandable.
- Separate implementation, tests, documentation, plan, and release metadata when
  that improves reviewability.
- Use explicit file lists with `git add`; never use `git add .`.
- Do not revert user changes or unrelated worktree changes.
- Run validation before committing.
- Ask the user for permission before creating a commit unless the current request
  explicitly authorizes committing.
- Do not commit, tag, or push while merely proposing work or reporting results.
- Do not push or create tags unless the user explicitly asks.
- Before rewriting history, explain that descendant commit IDs and remote history
  will change; use `--force-with-lease` for an approved remote update.

## Release Workflow

1. Confirm the worktree, current version, recent history, and existing tags.
2. Decide whether the changes are a patch, minor, or major release.
3. Update `Cargo.toml` and lockfiles when the package version changes.
4. Update crate release instructions and regenerate `README.md`.
5. Update `CHANGELOG.md` with the release summary and date.
6. Run formatting, Clippy, documentation, the complete feature matrix, fuzz smoke
   tests, and `cargo publish --dry-run`.
7. Ask for commit permission if it has not already been granted for the current
   request.
8. Create a small release commit, then verify the clean worktree and package
   version.
9. Create the matching annotated `vX.Y.Z` tag only with explicit permission.
10. Push the branch and tag only with explicit permission.

Before publishing, verify that the Cargo package version, changelog heading,
README instructions, release commit, tag, and release workflow all agree.
