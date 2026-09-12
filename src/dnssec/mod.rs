//! DNSSEC cryptographic validation, canonicalization, and chain-of-trust verification.
//!
//! Implements local validation of DNS Resource Record Sets (RRsets) against
//! cryptographic signatures (RRSIG) anchored in delegations (DS) up to root
//! Key-Signing Keys (KSK) per [RFC 4033], [RFC 4034], [RFC 4035], and [RFC 6840].
//!
//! [RFC 4033]: https://datatracker.ietf.org/doc/html/rfc4033
//! [RFC 4034]: https://datatracker.ietf.org/doc/html/rfc4034
//! [RFC 4035]: https://datatracker.ietf.org/doc/html/rfc4035
//! [RFC 6840]: https://datatracker.ietf.org/doc/html/rfc6840

pub mod anchor;
pub(crate) mod canonical;
pub mod chain;
pub(crate) mod crypto;
pub mod denial;
pub mod rrset_validator;

pub use anchor::{TrustAnchor, TrustStore};
pub use chain::{ChainValidator, DnssecCache};
pub use rrset_validator::{ValidationReport, ValidityPeriod, validate_rrset};
