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

#[derive(Copy, Clone, Debug, EnumString)]
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

    pub fn to_bool(&self) -> bool {
        match self {
            QR::Query => false,
            QR::Response => true,
        }
    }
}

#[derive(Copy, Clone, Debug, Display, EnumString, FromPrimitive)]
#[allow(clippy::upper_case_acronyms)]
#[repr(u8)] // Really only 4 bits
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
impl Default for Opcode {
    fn default() -> Self {
        Opcode::Query
    }
}

#[derive(Copy, Clone, Debug, Display, EnumString, FromPrimitive)]
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
// TODO Should we split this into Type and QType?
#[derive(Copy, Clone, Debug, Display, EnumString, FromPrimitive)]
#[allow(clippy::upper_case_acronyms)]
#[repr(u16)]
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

#[derive(Copy, Clone, Debug, Display, EnumString, FromPrimitive)]
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
