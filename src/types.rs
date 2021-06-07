use crate::resource::{MX, SOA, SRV};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use strum_macros::{Display, EnumString};

/// DNS Message that serves as the root of all DNS requests and responses.
///
/// # Examples
///
/// For constructing a message and encoding:
///
/// ```rust
/// use rustdns::Message;
/// use rustdns::types::*;
/// use std::net::UdpSocket;
/// use std::time::Duration;
///
/// // Setup some UDP socket for sending to a DNS server.
/// let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
/// socket.set_read_timeout(Some(Duration::new(5, 0))).expect("set_read_timeout call failed");
/// socket.connect("8.8.8.8:53").expect("connect function failed");
///
/// // Construct a simple query.
/// let mut m = Message::default();
/// m.add_question("bramp.net", Type::A, Class::Internet);
///
/// // Encode the query as a Vec<u8>.
/// let req = m.to_vec().expect("failed to encode DNS request");
///
/// // Send to the server
/// socket.send(&req).expect("failed to send request");
///
/// // Some time passes
///
/// // Receive a response from the DNS server
/// let mut resp = [0; 4096];
/// let len = socket.recv(&mut resp).expect("failed to receive response");
///
/// // Take a Vec<u8> and turn it into a message.
/// let m = Message::from_slice(&resp[0..len]).expect("invalid response");
///
/// // Now do something with `m`, in this case print it!
/// println!("DNS Response:\n{}", m);
/// ```
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Message {
    /// 16-bit identifier assigned by the program that generates any kind of
    /// query. This identifier is copied into the corresponding reply and can be
    /// used by the requester to match up replies to outstanding queries.
    pub id: u16,

    /// Recursion Desired - this bit directs the name server to pursue the query
    /// recursively.
    pub rd: bool,

    /// Truncation - specifies that this message was truncated.
    pub tc: bool,

    /// Authoritative Answer - Specifies that the responding name server is an
    /// authority for the domain name in question section.
    pub aa: bool,

    /// Specifies kind of query in this message. 0 represents a standard query.
    /// See <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5>
    pub opcode: Opcode,

    /// Specifies whether this message is a query (0), or a response (1).
    pub qr: QR,

    /// Response code.
    pub rcode: Rcode,

    /// Checking Disabled. See [RFC4035] and [RFC6840].
    ///
    /// [rfc4035]: https://datatracker.ietf.org/doc/html/rfc4035
    /// [rfc6840]: https://datatracker.ietf.org/doc/html/rfc6840
    pub cd: bool,

    /// Authentic Data. See [RFC4035] and [RFC6840].
    ///
    /// [rfc4035]: https://datatracker.ietf.org/doc/html/rfc4035
    /// [rfc6840]: https://datatracker.ietf.org/doc/html/rfc6840
    pub ad: bool,

    /// Z Reserved for future use. You must set this field to 0.
    pub z: bool,

    /// Recursion Available - this be is set or cleared in a response, and
    /// denotes whether recursive query support is available in the name server.
    pub ra: bool,

    /// The questions.
    pub questions: Vec<Question>,

    /// The answer records.
    pub answers: Vec<Record>,

    /// The authoritive records.
    pub authoritys: Vec<Record>,

    /// The additional records.
    pub additionals: Vec<Record>,

    /// Optional EDNS(0) record.
    pub extension: Option<Extension>,
}

/// DNS Question.
#[derive(Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Question {
    /// A valid UTF-8 encoded domain name.
    pub name: String,
    pub r#type: Type,
    pub class: Class,
}

/// Resource Record (RR)
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Record {
    pub name: String,

    pub r#type: Type,
    pub class: Class,

    /// The number of seconds that the resource record may be cached
    /// before the source of the information should again be consulted.
    /// Zero is interpreted to mean that the RR can only be used for the
    /// transaction in progress.
    pub ttl: Duration,

    pub resource: Resource,
}

/// EDNS(0) extension record as defined in [rfc2671] and [rfc6891].
///
/// [rfc2671]: https://datatracker.ietf.org/doc/html/rfc2671
/// [rfc6891]: https://datatracker.ietf.org/doc/html/rfc6891
//
// TODO Support EDNS0_NSID (RFC 5001) and EDNS0_SUBNET (RFC 7871) records within the extension.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Extension {
    /// Requestor's UDP payload size.
    pub payload_size: u16,

    pub extend_rcode: u8,
    pub version: u8,

    /// DNSSEC OK bit as defined by [rfc3225].
    ///
    /// [rfc3225]: https://datatracker.ietf.org/doc/html/rfc3225
    pub dnssec_ok: bool,
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

/// Specifies kind of query in this message. See [rfc1035], [rfc6895] and <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5>
///
/// [rfc1035]: https://datatracker.ietf.org/doc/html/rfc1035
/// [rfc6895]: https://datatracker.ietf.org/doc/html/rfc6895
#[derive(Copy, Clone, Debug, Display, EnumString, FromPrimitive, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
#[repr(u8)] // Really only 4 bits
pub enum Opcode {
    /// Query.
    Query = 0,

    /// Inverse Query (OBSOLETE). See [rfc3425].
    ///
    /// [rfc3425]: https://datatracker.ietf.org/doc/html/rfc3425
    IQuery = 1,
    Status = 2,

    /// See [rfc1996]
    ///
    /// [rfc1996]: https://datatracker.ietf.org/doc/html/rfc1996
    Notify = 4,

    /// See [rfc2136]
    ///
    /// [rfc2136]: https://datatracker.ietf.org/doc/html/rfc2136
    Update = 5,

    /// DNS Stateful Operations (DSO). See [rfc8490]
    ///
    /// [rfc8490]: https://datatracker.ietf.org/doc/html/rfc8490
    DSO = 6,
    // 3 and 7-15 Remain unassigned.
}
impl Default for Opcode {
    fn default() -> Self {
        Opcode::Query
    }
}

/// Response Codes.
/// See [rfc1035] and <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6>
///
/// [rfc1035]: https://datatracker.ietf.org/doc/html/rfc1035
#[derive(Copy, Clone, Debug, Display, EnumString, FromPrimitive, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
#[repr(u16)] // In headers it is 4 bits, in extended OPTS it is 16.
pub enum Rcode {
    /// No Error
    NoError = 0,

    /// Format Error
    FormErr = 1,

    /// Server Failure
    ServFail = 2,

    /// Non-Existent Domain
    NXDomain = 3,

    /// Not Implemented
    NotImp = 4,

    /// Query Refused
    Refused = 5,

    /// Name Exists when it should not. See [rfc2136] and [rfc6672].
    ///
    /// [rfc2136]: https://datatracker.ietf.org/doc/html/rfc2136
    /// [rfc6672]: https://datatracker.ietf.org/doc/html/rfc6672
    YXDomain = 6,

    /// RR Set Exists when it should not. See [rfc2136].
    ///
    /// [rfc2136]: https://datatracker.ietf.org/doc/html/rfc2136
    YXRRSet = 7,

    /// RR Set that should exist does not. See [rfc2136].
    ///
    /// [rfc2136]: https://datatracker.ietf.org/doc/html/rfc2136
    NXRRSet = 8,

    /// Note on error number 9 (NotAuth): This error number means either
    /// "Not Authoritative" [rfc2136] or "Not Authorized" [rfc2845].
    /// If 9 appears as the RCODE in the header of a DNS response without a
    /// TSIG RR or with a TSIG RR having a zero error field, then it means
    /// "Not Authoritative".  If 9 appears as the RCODE in the header of a
    /// DNS response that includes a TSIG RR with a non-zero error field,
    /// then it means "Not Authorized".
    ///
    /// [rfc2136]: https://datatracker.ietf.org/doc/html/rfc2136
    /// [rfc2845]: https://datatracker.ietf.org/doc/html/rfc2845
    NotAuth = 9,

    /// Name not contained in zone. See [rfc2136].
    ///
    /// [rfc2136]: https://datatracker.ietf.org/doc/html/rfc2136
    NotZone = 10,

    /// DSO-TYPE Not Implemented. See [rfc8490].
    ///
    /// [rfc8490]: https://datatracker.ietf.org/doc/html/rfc8490
    DSOTYPENI = 11,
    // 12-15 Unassigned
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

/// Resource Record Type, for example, A, CNAME or SOA.
///
// When adding a Type, a parsing funcion must be added in resource.rs.
#[derive(Copy, Clone, Debug, Display, EnumString, FromPrimitive, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
#[repr(u16)]
pub enum Type {
    Reserved = 0,

    /// (Default) IPv4 Address.
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,

    /// Domain name pointer.
    PTR = 12,

    /// Mail exchange.
    MX = 15,

    /// Text strings.
    TXT = 16,

    /// IPv6 Address.
    AAAA = 28,

    /// Server Selection
    SRV = 33,

    /// EDNS(0) Opt type. See [rfc3225] and [rfc6891].
    ///
    /// [rfc3225]: https://datatracker.ietf.org/doc/html/rfc3225
    /// [rfc6891]: https://datatracker.ietf.org/doc/html/rfc6891
    OPT = 41,

    /// Any record type.
    /// Only valid as a Question Type.
    ANY = 255,
}

impl Default for Type {
    fn default() -> Self {
        Type::A
    }
}

/// Resource Record Class, for example Internet.
#[derive(Copy, Clone, Debug, Display, EnumString, FromPrimitive, PartialEq)]
#[repr(u16)]
pub enum Class {
    /// Reserved per [RFC6895]
    ///
    /// [rfc6895]: https://datatracker.ietf.org/doc/html/rfc6895
    Reserved = 0,

    /// (Default) The Internet (IN), see [rfc1035].
    ///
    /// [rfc1035]: https://datatracker.ietf.org/doc/html/rfc1035
    #[strum(serialize = "IN")]
    Internet = 1,

    /// CSNET (CS), obsolete (used only for examples in some obsolete RFCs).
    #[strum(serialize = "CS")]
    CsNet = 2,

    /// Chaosnet (CH), obsolete LAN protocol created at MIT in the mid-1970s. See [D. Moon, "Chaosnet", A.I. Memo 628, Massachusetts Institute of Technology Artificial Intelligence Laboratory, June 1981.]
    #[strum(serialize = "CH")]
    Chaos = 3,

    /// Hesiod (HS), an information service developed by MIT’s Project Athena. See [Dyer, S., and F. Hsu, "Hesiod", Project Athena Technical Plan - Name Service, April 1987.]
    #[strum(serialize = "HS")]
    Hesiod = 4,

    None = 254, // NONE [RFC2136]

    /// * (ANY) See [rfc1035]
    ///
    /// [rfc1035]: https://datatracker.ietf.org/doc/html/rfc1035
    #[strum(serialize = "*")]
    Any = 255,
    //     5-253     Unassigned
    //   256-65279   Unassigned
    // 65280-65534   Reserved for Private Use    [RFC6895]
    // 65535         Reserved    [RFC6895]
}

impl Default for Class {
    fn default() -> Self {
        Class::Internet
    }
}

// This should be kept in sync with Type.
// TODO Merge this with Type (when https://github.com/rust-lang/rust/issues/60553 is finished).
#[allow(clippy::upper_case_acronyms)]
pub enum Resource {
    A(Ipv4Addr), // Support non-Internet classes?
    AAAA(Ipv6Addr),

    CNAME(String),
    NS(String),
    PTR(String),

    // TODO Implement RFC 1464 for further parsing of the text
    // TODO per RFC 4408 a TXT record is allowed to contain multiple strings
    TXT(Vec<Vec<u8>>),

    MX(MX),
    SOA(SOA),
    SRV(SRV),

    OPT,

    ANY, // Not a valid Record Type, but is a Type
}
