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