use std::fmt;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::time::Duration;
use strum_macros::{Display, EnumString};

#[derive(Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Packet {
    // A 16 bit identifier assigned by the program that generates any kind of
    // query. This identifier is copied the corresponding reply and can be used
    // by the requester to match up replies to outstanding queries.
    pub id: u16,

    // Recursion Desired - this bit directs the name server to pursue the query
    // recursively.
    pub rd: bool,

    // Truncation - specifies that this message was truncated.
    pub tc: bool,

    // Authoritative Answer - Specifies that the responding name server is an
    // authority for the domain name in question section.
    pub aa: bool,

    // Specifies kind of query in this message. 0 represents a standard query.
    // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
    pub opcode: Opcode,

    // TODO Change with enum.
    // Specifies whether this message is a query (0), or a response (1).
    pub qr: QR,

    // Response code.
    pub rcode: Rcode,

    // Checking Disabled - [RFC4035][RFC6840][RFC Errata 4927]
    pub cd: bool,

    // Authentic Data - [RFC4035][RFC6840][RFC Errata 4924]
    pub ad: bool,

    // Z Reserved for future use. You must set this field to 0.
    pub z: bool,

    // Recursion Available - this be is set or cleared in a response, and
    // denotes whether recursive query support is available in the name server.
    pub ra: bool,

    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authoritys: Vec<Record>,
    pub additionals: Vec<Record>,

    pub extension: Option<Extension>,
}

/// A DNS Question.
#[derive(Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Question {
    /// A valid UTF-8 encoded domain name.
    pub name: String,
    pub r#type: QType,
    pub class: QClass,
}

// RR or Resource Record
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Record {
    pub name: String,

    pub r#type: QType,
    pub class: QClass, // TODO Really a Class (which is a subset of QClass)

    // The number of seconds that the resource record may be cached
    // before the source of the information should again be consulted.
    // Zero is interpreted to mean that the RR can only be used for the
    // transaction in progress.
    pub ttl: Duration,

    pub resource: Resource,
}

// EDNS(0) extension record [rfc6891]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Extension {
    //pub name: String,  // Always "."
    //pub r#type: QType, // Always OPT(41)
    pub payload_size: u16, // Requestor's UDP payload size

    pub extend_rcode: u8,
    pub version: u8,

    pub dnssec_ok: bool, // DNSSEC OK bit as defined by [RFC3225].

                         // TODO pub record: Record,
}

impl Default for Extension {
    fn default() -> Self {
        Extension {
            payload_size: 512, // The min valid size.
            extend_rcode: 0,
            version: 0,
            dnssec_ok: false,
        }
    }
}

#[derive(Copy, Clone, Debug, EnumString, PartialEq)]
pub enum QR {
    Query = 0,
    Response = 1,
}

impl Default for QR {
    fn default() -> Self {
        QR::Query
    }
}

impl QR {
    pub fn from_bool(b: bool) -> QR {
        match b {
            false => QR::Query,
            true => QR::Response,
        }
    }

    pub fn to_bool(self) -> bool {
        match self {
            QR::Query => false,
            QR::Response => true,
        }
    }
}

#[derive(Copy, Clone, Debug, Display, EnumString, FromPrimitive, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
#[repr(u8)] // Really only 4 bits
pub enum Opcode {
    Query = 0,  // [RFC1035]
    IQuery = 1, // Inverse Query (OBSOLETE)    [RFC3425]
    Status = 2, // [RFC1035]
    Notify = 4, // [RFC1996]
    Update = 5, // [RFC2136]
    DSO = 6,    // DNS Stateful Operations (DSO)   [RFC8490]
                // 3  Unassigned
                // 7-15  Unassigned
}
impl Default for Opcode {
    fn default() -> Self {
        Opcode::Query
    }
}

#[derive(Copy, Clone, Debug, Display, EnumString, FromPrimitive, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
#[repr(u16)] // In headers it is 4 bits, in extended opts it is 16.
pub enum Rcode {
    NoError = 0,  // No Error    [RFC1035]
    FormErr = 1,  // Format Error    [RFC1035]
    ServFail = 2, // Server Failure  [RFC1035]
    NXDomain = 3, // Non-Existent Domain [RFC1035]
    NotImp = 4,   // Not Implemented [RFC1035]
    Refused = 5,  // Query Refused   [RFC1035]
    YXDomain = 6, // Name Exists when it should not  [RFC2136][RFC6672]
    YXRRSet = 7,  // RR Set Exists when it should not    [RFC2136]
    NXRRSet = 8,  // RR Set that should exist does not   [RFC2136]

    // Note on error number 9 (NotAuth): This error number means either
    // "Not Authoritative" [RFC2136] or "Not Authorized" [RFC2845].  If 9
    // appears as the RCODE in the header of a DNS response without a
    // TSIG RR or with a TSIG RR having a zero error field, then it means
    // "Not Authoritative".  If 9 appears as the RCODE in the header of a
    // DNS response that includes a TSIG RR with a non-zero error field,
    //  then it means "Not Authorized".
    NotAuth = 9,

    NotZone = 10, // Name not contained in zone  [RFC2136]
    DSOTYPENI = 11, // DSO-TYPE Not Implemented  [RFC8490]

                  // 12-15    Unassigned
}

impl Default for Rcode {
    fn default() -> Self {
        Rcode::NoError
    }
}
/*
pub enum ExtendedRcode {
    Rcode,
    BADVERS_or_BADSIG = 16  //  Bad OPT Version [RFC6891] or TSIG Signature Failure  [RFC8945]
    BADKEY = 17  //   Key not recognized  [RFC8945]
    BADTIME = 18  //  Signature out of time window    [RFC8945]
    BADMODE = 19  //  Bad TKEY Mode   [RFC2930]
    BADNAME = 20  //  Duplicate key name  [RFC2930]
    BADALG = 21  //   Algorithm not supported [RFC2930]
    BADTRUNC = 22  //     Bad Truncation  [RFC8945]
    BADCOOKIE = 23  //    Bad/missing Server Cookie   [RFC7873]
    // 24-3840  Unassigned
    // 3841-4095     Reserved for Private Use        [RFC6895]
    // 4096-65534    Unassigned
    // 65535 = Reserved Can be allocated by Standards Action      [RFC6895]
}
*/

// When adding a QType, a parsing funcion must be added in resource.rs.
// TODO Rename to ResourceType
#[derive(Copy, Clone, Debug, Display, EnumString, FromPrimitive, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
#[repr(u16)]
pub enum QType {
    Reserved = 0,

    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,  // A domain name pointer
    MX = 15,   // A mail exchange
    TXT = 16,  // Text strings
    AAAA = 28, // IP6 Address
    SRV = 33,  // Server Selection

    OPT = 41, // Opt type [RFC3225][RFC6891]

    // This is not a valid Resource Type, but is a valid Question Type
    ANY = 255,
}

impl Default for QType {
    fn default() -> Self {
        QType::A
    }
}

#[derive(Copy, Clone, Debug, Display, EnumString, FromPrimitive, PartialEq)]
#[repr(u16)]
pub enum QClass {
    Reserved = 0, // [RFC6895]

    #[strum(serialize = "IN")]
    Internet = 1, // (IN) The Internet [RFC1035]

    #[strum(serialize = "CS")]
    CsNet = 2, // (CS) The CSNET class (Obsolete - used only for examples in some obsolete RFCs)

    #[strum(serialize = "CH")]
    Chaos = 3, // (CH) The Chaos class [D. Moon, "Chaosnet", A.I. Memo 628, Massachusetts Institute of Technology Artificial Intelligence Laboratory, June 1981.]

    #[strum(serialize = "HS")]
    Hesiod = 4, // (HS) [Dyer, S., and F. Hsu, "Hesiod", Project Athena Technical Plan - Name Service, April 1987.]

    // QCLASS fields below
    None = 254, // NONE [RFC2136]

    #[strum(serialize = "*")]
    Any = 255, // * (ANY)  [RFC1035]
               //     5-253     Unassigned
               //   256-65279   Unassigned
               // 65280-65534   Reserved for Private Use    [RFC6895]
               // 65535         Reserved    [RFC6895]
}

impl Default for QClass {
    fn default() -> Self {
        QClass::Internet
    }
}

// This should be kept in sync with QType.
// TODO Can we merge this and QType? (when https://github.com/rust-lang/rust/issues/60553 is finished we can)
#[allow(clippy::upper_case_acronyms)]
pub enum Resource {
    A(Ipv4Addr), // TODO Is this always a IpAddress for non-Internet classes?
    AAAA(Ipv6Addr),

    CNAME(String),
    NS(String),
    PTR(String),

    // TODO Implement RFC 1464 for further parsing of the text
    TXT(Vec<String>), // TODO Maybe change this to byte/u8/something

    MX(Mx),
    SOA(Soa),
    SRV(Srv),

    OPT,

    ANY,  // Not a valid Record Type, but is a QType
    TODO, // TODO Remove this placeholder. Figure out how to hide this type.
}

pub struct Mx {
    pub preference: u16, // The preference given to this RR among others at the same owner.  Lower values are preferred.
    pub exchange: String, // A host willing to act as a mail exchange for the owner name.
}

pub struct Soa {
    pub mname: String, // The name server that was the original or primary source of data for this zone.
    pub rname: String, // The mailbox of the person responsible for this zone.

    pub serial: u32,

    pub refresh: Duration,
    pub retry: Duration,
    pub expire: Duration,
    pub minimum: Duration,
}

// https://datatracker.ietf.org/doc/html/rfc2782
pub struct Srv {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub name: String,
}

// TODO Can I move these into resources.rs

impl fmt::Display for Mx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // "10 aspmx.l.google.com."
        write!(
            f,
            "{preference} {exchange}",
            preference = self.preference,
            exchange = self.exchange,
        )
    }
}

impl fmt::Display for Soa {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // "ns1.google.com. dns-admin.google.com. 376337657 900 900 1800 60"
        write!(
            f,
            "{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}",
            mname = self.mname,
            rname = self.rname,
            serial = self.serial,
            refresh = self.refresh.as_secs(),
            retry = self.retry.as_secs(),
            expire = self.expire.as_secs(),
            minimum = self.minimum.as_secs(),
        )
    }
}

impl fmt::Display for Srv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // "5 0 389 ldap.google.com."
        write!(
            f,
            "{priority} {weight} {port} {name}",
            priority = self.priority,
            weight = self.weight,
            port = self.port,
            name = self.name,
        )
    }
}
