use modular_bitfield::prelude::*;
use strum_macros::{Display, EnumString};

// TODO Replace these with bits(endian=big)
pub struct BeB16 {}
pub struct BeB32 {}

impl modular_bitfield::Specifier for BeB16 {
    type Bytes = u16;
    type InOut = u16;

    const BITS: usize = 16;

    #[inline]
    fn into_bytes(
        input: Self::InOut,
    ) -> Result<Self::Bytes, ::modular_bitfield::error::OutOfBounds> {
        ::core::result::Result::Ok((input as Self::Bytes).to_be())
    }

    #[inline]
    fn from_bytes(
        bytes: Self::Bytes,
    ) -> Result<Self::InOut, ::modular_bitfield::error::InvalidBitPattern<Self::Bytes>> {
        ::core::result::Result::Ok(Self::Bytes::from_be(bytes))
    }
}

impl modular_bitfield::Specifier for BeB32 {
    type Bytes = u32;
    type InOut = u32;

    const BITS: usize = 32;

    #[inline]
    fn into_bytes(
        input: Self::InOut,
    ) -> Result<Self::Bytes, ::modular_bitfield::error::OutOfBounds> {
        ::core::result::Result::Ok((input as Self::Bytes).to_be())
    }

    #[inline]
    fn from_bytes(
        bytes: Self::Bytes,
    ) -> Result<Self::InOut, ::modular_bitfield::error::InvalidBitPattern<Self::Bytes>> {
        ::core::result::Result::Ok(Self::Bytes::from_be(bytes))
    }
}

#[derive(BitfieldSpecifier, Debug, EnumString)]
#[bits = 1]
pub enum QR {
    Query = 0,
    Response = 1,
}

#[derive(BitfieldSpecifier, Debug, Display, EnumString)]
#[bits = 4]
#[allow(clippy::upper_case_acronyms)]
pub enum Opcode {
    Query = 0,  // [RFC1035]
    IQuery = 1, // Inverse Query (OBSOLETE)    [RFC3425]
    Status = 2, //  [RFC1035]
    Notify = 4, // [RFC1996]
    Update = 5, // [RFC2136]
    DSO = 6,    // DNS Stateful Operations (DSO)   [RFC8490]
                // 3  Unassigned
                // 7-15  Unassigned
}

#[derive(BitfieldSpecifier, Debug, Display, EnumString)]
#[bits = 4]
#[allow(clippy::upper_case_acronyms)]
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

#[bitfield(bits = 96)]
#[derive(Copy, Clone, Debug)]
pub struct Header {
    // A 16 bit identifier assigned by the program that generates any kind of
    // query. This identifier is copied the corresponding reply and can be used
    // by the requester to match up replies to outstanding queries.
    pub id: BeB16,

    // Recursion Desired - this bit directs the name server to pursue the query
    // recursively.
    pub rd: bool, // bit 7

    // Truncation - specifies that this message was truncated.
    pub tc: bool, // bit 6

    // Authoritative Answer - Specifies that the responding name server is an
    // authority for the domain name in question section.
    pub aa: bool, // bit 5

    // Specifies kind of query in this message. 0 represents a standard query.
    // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
    pub opcode: Opcode, // bit 1-4

    // TODO Change with enum.
    // Specifies whether this message is a query (0), or a response (1).
    pub qr: QR, // bit 0

    // Response code.
    pub rcode: Rcode, // bit 4-7

    // Checking Disabled - [RFC4035][RFC6840][RFC Errata 4927]
    pub cd: bool, // bit 3

    // Authentic Data - [RFC4035][RFC6840][RFC Errata 4924]
    pub ad: bool, // bit 2

    #[skip]
    // Z Reserved for future use. You must set this field to 0.
    z: B1, // bit 1

    // Recursion Available - this be is set or cleared in a response, and
    // denotes whether recursive query support is available in the name server.
    pub ra: bool, // bit 0

    // Number of entries in the question section.
    pub qd_count: BeB16,

    // Number of resource records in the answer section.
    pub an_count: BeB16,

    // Number of name server resource records in the authority records section.
    pub ns_count: BeB16,

    // Number of resource records in the additional records section
    pub ar_count: BeB16,
}

// When adding a QType, a parsing funcion must be added in resource.rs.
// TODO Should we split this into Type and QType?
#[derive(BitfieldSpecifier, Debug, Display, EnumString)]
#[bits = 16]
#[endian = 1]
#[allow(clippy::upper_case_acronyms)]
pub enum QType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,  // A domain name pointer
    MX = 15,   // A mail exchange
    TXT = 16,  // Text strings
    AAAA = 28, // IP6 Address
    SRV = 33,  // Server Selection

    // This is not a valid RType
    ANY = 255,
}

#[derive(BitfieldSpecifier, Debug, Display, EnumString)]
#[bits = 16]
#[endian = 1]
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

#[bitfield(bits = 32)] // Excluding the variable length qname
#[derive(Copy, Clone, Debug)]
pub struct QuestionHeader {
    // QNAME:...
    pub qtype: QType,
    pub qclass: QClass,
}

#[bitfield(bits = 80)] // Excluding the variable length name and rdata fields
#[derive(Copy, Clone, Debug)]
pub struct AnswerHeader {
    // name:...
    pub r#type: QType,
    pub class: QClass, // TODO Really a Class (which is a subset of QClass)

    // The number of seconds that the resource record may be cached
    // before the source of the information should again be consulted.
    // Zero is interpreted to mean that the RR can only be used for the
    // transaction in progress.
    pub ttl: BeB32,

    // Specifies the length in octets of the RDATA field.
    pub rd_length: BeB16,
    // rdata:...
}
