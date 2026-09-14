//! Zone file AST data structures before directive inheritance and name resolution.

use crate::resource::{A, AAAA, DNSKEY, DS, NSEC3, NSEC3PARAM, RawResource, TXT, ZONEMD};
use crate::types::{Algorithm, Type};
use core::time::Duration;
use std::time::SystemTime;

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
    MX(MX),
    /// Start of Authority (SOA) record before origin resolution.
    SOA(SOA),
    /// Service (SRV) record before origin resolution.
    SRV(SRV),
    /// Delegation Signer (DS) record.
    DS(DS),
    /// DNS Key (DNSKEY) record.
    DNSKEY(DNSKEY),
    /// DNSSEC Signature (RRSIG) record before origin resolution.
    RRSIG(RRSIG),
    /// Next Secure (NSEC) record before origin resolution.
    NSEC(NSEC),
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

/// Unprocessed MX record data before zone origin resolution.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MX {
    /// The preference given to this RR among others at the same owner.
    pub preference: u16,
    /// A host willing to act as a mail exchange (may be relative, `"@"`, or FQDN).
    pub exchange: String,
}

/// Unprocessed SOA record data before zone origin resolution.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SOA {
    /// The primary master nameserver domain (may be relative, `"@"`, or FQDN).
    pub mname: String,
    /// The mailbox domain name of the responsible person (may be relative, `"@"`, or FQDN).
    pub rname: String,
    /// Serial version number.
    pub serial: u32,
    /// Refresh interval.
    pub refresh: Duration,
    /// Retry interval.
    pub retry: Duration,
    /// Expiration limit.
    pub expire: Duration,
    /// Minimum TTL.
    pub minimum: Duration,
}

/// Unprocessed SRV record data before zone origin resolution.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SRV {
    /// Priority of this target host.
    pub priority: u16,
    /// Relative weight.
    pub weight: u16,
    /// Port number.
    pub port: u16,
    /// Target hostname (may be relative, `"@"`, or FQDN).
    pub name: String,
}

/// Unprocessed RRSIG record data before zone origin resolution.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RRSIG {
    /// Covered RR type.
    pub type_covered: Type,
    /// Cryptographic algorithm number.
    pub algorithm: Algorithm,
    /// Label count.
    pub labels: u8,
    /// Original TTL.
    pub original_ttl: Duration,
    /// Expiration timestamp.
    pub expiration: SystemTime,
    /// Inception timestamp.
    pub inception: SystemTime,
    /// Key tag.
    pub key_tag: u16,
    /// Signer domain name (may be relative, `"@"`, or FQDN).
    pub signer_name: String,
    /// Signature bytes.
    pub signature: Vec<u8>,
}

/// Unprocessed NSEC record data before zone origin resolution.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NSEC {
    /// Next owner name in canonical order (may be relative, `"@"`, or FQDN).
    pub next_domain: String,
    /// Type bit map.
    pub types: Vec<Type>,
}
