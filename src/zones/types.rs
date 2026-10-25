//! Zone file AST data structures before directive inheritance and name resolution.

use crate::resource::{A, AAAA, DNSKEY, DS, NSEC3, NSEC3PARAM, RawResource, TXT, ZONEMD};
use crate::from_str::{UnresolvedMx, UnresolvedNsec, UnresolvedRrsig, UnresolvedSoa, UnresolvedSrv};

/// An unprocessed zone file resource record data payload before origin resolution.
///
/// In an unprocessed zone file, domain names in records (such as `NS`, `CNAME`, `MX`, etc.)
/// can be relative (e.g. `"www"`), origin shortcuts (`"@"`), or omitted. These are preserved
/// as [`String`]s until resolved against `$ORIGIN` via [`crate::zones::File::try_into_records`].
#[derive(Clone, Debug, PartialEq)]
pub enum Resource {
    /// IPv4 Address (A) record.
    A(A),
    /// IPv6 Address (AAAA) record.
    AAAA(AAAA),
    /// Canonical name (CNAME) record before origin resolution.
    CNAME(String),
    /// Name Server (NS) record before origin resolution.
    NS(String),
    /// Pointer (PTR) record before origin resolution.
    PTR(String),
    /// Text (TXT) record.
    TXT(TXT),
    /// Sender Policy Framework (SPF) record.
    SPF(TXT),
    /// Mail EXchanger (MX) record before origin resolution.
    MX(UnresolvedMx),
    /// Start of Authority (SOA) record before origin resolution.
    SOA(UnresolvedSoa),
    /// Service (SRV) record before origin resolution.
    SRV(UnresolvedSrv),
    /// Delegation Signer (DS) record.
    DS(DS),
    /// DNS Key (DNSKEY) record.
    DNSKEY(DNSKEY),
    /// DNSSEC Signature (RRSIG) record before origin resolution.
    RRSIG(UnresolvedRrsig),
    /// Next Secure (NSEC) record before origin resolution.
    NSEC(UnresolvedNsec),
    /// Next Secure version 3 (NSEC3) record.
    NSEC3(NSEC3),
    /// Next Secure version 3 Parameters (NSEC3PARAM) record.
    NSEC3PARAM(NSEC3PARAM),
    /// Message Digest for DNS Zones (ZONEMD) record.
    ZONEMD(ZONEMD),
    /// EDNS(0) OPT pseudo-record.
    OPT,
    /// Wildcard / any-type query pseudo-record.
    ANY,
    /// Unrecognized or raw resource record data.
    Raw(RawResource),
}
