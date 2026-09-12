//! DNSSEC cryptographic validation, canonicalization, and chain-of-trust verification.
//!
//! Implements local validation of DNS Resource Record Sets (RRsets) against
//! cryptographic signatures (RRSIG) anchored in delegations (DS) up to root
//! Key-Signing Keys (KSK) per RFC 4033, 4034, 4035, and 6840.

pub mod anchor;
pub(crate) mod canonical;
pub mod chain;
pub(crate) mod crypto;
pub mod denial;
pub mod rrset_validator;

pub use anchor::{TrustAnchor, TrustStore};
pub use chain::{ChainValidator, DnssecCache};
pub use rrset_validator::{ValidationReport, ValidityPeriod, validate_rrset};
