//! DNSSEC cryptographic validation, canonicalization, and chain-of-trust verification.
//!
//! Implements local validation of DNS Resource Record Sets (RRsets) against
//! cryptographic signatures (RRSIG) anchored in delegations (DS) up to root
//! Key-Signing Keys (KSK) per [RFC 4033], [RFC 4034], [RFC 4035], and [RFC 6840].
//!
//! Cryptographic verification requires a backend feature: `dnssec-ring`
//! (uses `ring`) or `dnssec-rustcrypto` (pure Rust, no C toolchain). Both
//! produce identical results; `ring` is used when both are enabled.
//! Chain-of-trust validation works with the runtime-independent
//! [`crate::clients::AsyncResolver`] interface; native resolver orchestration
//! additionally requires `resolver`.
//!
//! [RFC 4033]: https://datatracker.ietf.org/doc/html/rfc4033
//! [RFC 4034]: https://datatracker.ietf.org/doc/html/rfc4034
//! [RFC 4035]: https://datatracker.ietf.org/doc/html/rfc4035
//! [RFC 6840]: https://datatracker.ietf.org/doc/html/rfc6840

pub mod anchor;
pub mod clock;
pub(crate) mod canonical;
pub mod chain;
pub(crate) mod crypto;
pub mod denial;
pub mod policy;
pub mod rrset_validator;

pub use anchor::{TrustAnchor, TrustStore};
pub use clock::{Clock, SystemClock};
pub use chain::{ChainValidator, DnssecCache};
pub use policy::RsaKeySizePolicy;
pub use rrset_validator::{
    ValidationReport, ValidityPeriod, validate_rrset, validate_rrset_with_policy,
};
