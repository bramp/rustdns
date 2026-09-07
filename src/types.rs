pub use crate::edns::{
    EDNS_OPTION_CLIENT_SUBNET, EDNS_OPTION_COOKIE, EDNS_OPTION_NSID, EDNS_OPTION_PADDING,
    EDNS_OPTION_TCP_KEEPALIVE, EdnsClientSubnet, EdnsCookie, EdnsOption,
};
use crate::resource::*;
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
/// fn main() -> Result<(), rustdns::Error> {
/// // Setup some UDP socket for sending to a DNS server.
/// let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
/// socket.set_read_timeout(Some(Duration::new(5, 0))).expect("set_read_timeout call failed");
/// socket.connect("8.8.8.8:53").expect("connect call failed");
///
/// // Construct a simple query.
/// let mut m = Message::default();
/// m.try_add_question("bramp.net", Type::A, Class::Internet)?;
///
/// // Encode the query as a Vec<u8>.
/// // Use append_to_vec when appending to an existing Vec<u8>.
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
/// Ok(())
/// }
/// ```
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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

/// Question struct containing a domain name, question [`Type`] and question [`Class`].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Question {
    /// The domain name in question. Must be a valid UTF-8 encoded domain name.
    pub name: String,

    /// The question's type.
    ///
    /// All Type's are valid, including the pseudo types (e.g [`Type::ANY`]).
    pub r#type: Type,

    /// The question's class.
    pub class: Class,
}

/// Resource Record (RR) returned by DNS servers containing a answer to the question.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Record {
    /// A valid UTF-8 encoded domain name.
    pub name: String,

    /// The resource's class.
    pub class: Class,

    /// The number of seconds that the resource record may be cached
    /// before the source of the information should again be consulted.
    /// Zero is interpreted to mean that the RR can only be used for the
    /// transaction in progress.
    pub ttl: Duration,

    /// The actual resource.
    pub resource: Resource,
}

impl Record {
    pub fn new(name: &str, class: Class, ttl: Duration, resource: Resource) -> Self {
        Self {
            name: name.to_owned(),
            class,
            ttl,
            resource,
        }
    }

    pub fn r#type(&self) -> Type {
        self.resource.r#type()
    }
}

/// EDNS(0) extension record as defined in [rfc2671] and [rfc6891].
///
/// Use [`Message::set_extension`](crate::Message::set_extension) to attach an
/// extension to a DNS message. Use [`Extension::add_option`] when mutating an
/// existing extension, or [`Extension::with_option`] when building an extension
/// inline before passing it to `set_extension`.
///
/// ```rust
/// use rustdns::{EdnsOption, Extension, Message};
///
/// let mut message = Message::default();
/// message.set_extension(
///     Extension::default().with_option(EdnsOption::client_subnet(
///         "192.0.2.129".parse().unwrap(),
///         24,
///         0,
///     )),
/// );
/// ```
///
/// [rfc2671]: https://datatracker.ietf.org/doc/html/rfc2671
/// [rfc6891]: https://datatracker.ietf.org/doc/html/rfc6891
//
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Extension {
    /// Requestor's UDP payload size.
    ///
    /// In queries, this advertises the largest DNS response payload the sender
    /// can receive over UDP. Larger values allow servers to return responses
    /// bigger than the original 512-byte DNS UDP limit, but callers should still
    /// choose a value that fits their transport and path MTU assumptions. The
    /// default is 4096 bytes.
    pub payload_size: u16,

    /// Extended response code.
    ///
    /// EDNS extends the DNS header's four-bit response code with this upper
    /// eight-bit field. Query messages normally leave this as `0`; response
    /// messages can use it to represent extended error codes such as BADVERS.
    pub extend_rcode: u8,

    /// EDNS version.
    ///
    /// EDNS(0) uses version `0`. Queries should leave this as `0` unless they
    /// deliberately implement a later EDNS version. A responder can reject
    /// unsupported versions with the appropriate extended response code.
    pub version: u8,

    /// DNSSEC OK bit as defined by [rfc3225].
    ///
    /// Set this to `true` when the sender wants DNSSEC records such as RRSIG,
    /// DNSKEY, and related authentication data to be included in responses when
    /// available. Leave it `false` for ordinary queries that do not request
    /// DNSSEC data.
    ///
    /// [rfc3225]: https://datatracker.ietf.org/doc/html/rfc3225
    pub dnssec_ok: bool,

    /// EDNS(0) options carried by this extension record.
    ///
    /// Options are encoded in order into the OPT record RDATA. Use
    /// [`Extension::add_option`] or [`Extension::with_option`] to add typed
    /// options such as [`EdnsOption::nsid`], [`EdnsOption::cookie`],
    /// [`EdnsOption::tcp_keepalive`], or [`EdnsOption::padding`]. Unknown option
    /// codes can be preserved with [`EdnsOption::unknown`].
    pub options: Vec<EdnsOption>,
}

impl Default for Extension {
    fn default() -> Self {
        Extension {
            payload_size: 4096,
            extend_rcode: 0,
            version: 0,
            dnssec_ok: false,
            options: Vec::new(),
        }
    }
}

impl Extension {
    /// Adds an EDNS(0) option to this extension record.
    ///
    /// Use this when an extension value already exists and should be mutated in
    /// place.
    pub fn add_option(&mut self, option: EdnsOption) {
        self.options.push(option);
    }

    /// Returns this extension record with an EDNS(0) option added.
    ///
    /// Use this when constructing an extension inline, especially before passing
    /// it to [`Message::set_extension`](crate::Message::set_extension).
    pub fn with_option(mut self, option: EdnsOption) -> Self {
        self.add_option(option);
        self
    }
}

/// The transport security classification of a communication channel.
#[derive(Copy, Clone, Debug, Display, EnumString, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum ChannelSecurity {
    /// Insecure, unencrypted plaintext transport across a network (e.g. UDP or TCP on non-loopback).
    Insecure,

    /// Unencrypted communication restricted to the local loopback interface (`127.0.0.0/8` or `::1`),
    /// typically connecting to a trusted local validating resolver daemon (e.g. `unbound` or `systemd-resolved`).
    Loopback,

    /// Cryptographically encrypted and authenticated transport (e.g. DNS-over-HTTPS or DNS-over-TLS).
    Encrypted,
}

impl ChannelSecurity {
    /// Returns whether this channel provides transport-layer confidentiality or local host isolation
    /// sufficient to guard against on-path spoofing of DNS responses.
    #[inline]
    pub fn is_secure(&self) -> bool {
        matches!(self, ChannelSecurity::Loopback | ChannelSecurity::Encrypted)
    }
}

/// Transport-layer TLS connection information.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct TlsInfo {
    /// Negotiated TLS protocol version (e.g. `"TLSv1.3"` or `"TLSv1.2"`).
    pub version: String,

    /// Negotiated cipher suite name (e.g. `"TLS_AES_256_GCM_SHA384"`).
    pub cipher_suite: Option<String>,

    /// TLS Server Name Indication (SNI) or peer hostname.
    pub server_name: Option<String>,

    /// Negotiated ALPN protocol (e.g. `"dot"`, `"h2"`, `"http/1.1"`), if any.
    pub alpn: Option<String>,
}

/// The DNSSEC security status of a response.
#[derive(Copy, Clone, Debug, Display, EnumString, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum SecurityStatus {
    /// Authenticity was cryptographically validated (e.g. `AD=1` from a trusted secure channel).
    Secure,

    /// The zone is proven or indicated to be unsigned (e.g. `AD=0` with `NoError`).
    Insecure,

    /// DNSSEC validation failed (e.g. `SERVFAIL` returned by an upstream validator, or tampered data).
    Bogus,

    /// DNSSEC validation status cannot be established (e.g. `AD=1` received over an unencrypted,
    /// non-loopback plaintext channel under [`UpstreamTrustPolicy::SecureTransportOnly`]).
    Indeterminate,
}

/// The DNSSEC validation policy configured on a resolver.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum DnssecMode {
    /// DNSSEC validation is disabled (default). The resolver does not set `DO=1`
    /// and accepts responses without validation.
    #[default]
    Off,

    /// Relies on upstream recursive resolver DNSSEC validation.
    ///
    /// Sets the EDNS(0) `DO=1` (DNSSEC OK) bit on queries. When receiving responses:
    /// - If `require_secure` is `true`, lookups only succeed if `security_status` is [`SecurityStatus::Secure`].
    ///   Unsigned domains ([`SecurityStatus::Insecure`]), bogus, or indeterminate responses fail the lookup.
    /// - If `require_secure` is `false`, unsigned domains ([`SecurityStatus::Insecure`]) are also accepted,
    ///   while bogus or indeterminate responses fail the lookup.
    TrustUpstream {
        /// Whether only cryptographically secure (signed) domains are accepted.
        require_secure: bool,
    },

    /// Performs strict local DNSSEC validation down to configured trust anchors.
    /// (Reserved for future local validation).
    StrictLocal,
}

/// Policy dictating when upstream `AD` (Authenticated Data) assertions are trusted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum UpstreamTrustPolicy {
    /// Honor the upstream `AD=1` bit only if the transport is secure (DoH, DoT, or loopback).
    /// If received over an unencrypted non-loopback transport, the status is treated as [`SecurityStatus::Indeterminate`].
    #[default]
    SecureTransportOnly,

    /// Always honor `AD=1` regardless of transport security.
    ///
    /// Intended for trusted private networks, lab environments, or testing.
    AlwaysTrust,
}

/// Query or Response bit.
#[derive(Copy, Clone, Debug, EnumString, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum QR {
    Query = 0,
    Response = 1,
}

/// Defaults to [`QR::Query`].
impl Default for QR {
    fn default() -> Self {
        QR::Query
    }
}

impl From<bool> for QR {
    fn from(b: bool) -> Self {
        match b {
            false => QR::Query,
            true => QR::Response,
        }
    }
}

impl From<QR> for bool {
    fn from(qr: QR) -> Self {
        match qr {
            QR::Query => false,
            QR::Response => true,
        }
    }
}

/// Specifies kind of query in this message. See [rfc1035], [rfc6895] and [DNS Parameters].
///
/// [rfc1035]: https://datatracker.ietf.org/doc/html/rfc1035
/// [rfc6895]: https://datatracker.ietf.org/doc/html/rfc6895
/// [DNS Parameters]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
#[derive(Copy, Clone, Debug, Display, EnumString, Eq, Hash, FromPrimitive, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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

/// Defaults to [`Opcode::Query`].
impl Default for Opcode {
    fn default() -> Self {
        Opcode::Query
    }
}

/// Response Codes.
/// See [rfc1035] and [DNS Parameters].
///
/// [rfc1035]: https://datatracker.ietf.org/doc/html/rfc1035
/// [DNS Parameters]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
#[derive(Copy, Clone, Debug, Display, EnumString, Eq, Hash, FromPrimitive, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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

/// Defaults to [`Rcode::NoError`].
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
#[derive(Copy, Clone, Debug, Display, EnumString, Eq, FromPrimitive, Hash, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u16)]
pub enum Type {
    Reserved = 0,

    /// (Default) IPv4 Address.
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,

    /// Domain name pointer. See [`util::reverse()`] to create a valid domain name from a IP address.
    ///
    /// [`util::reverse()`]: crate::util::reverse()
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

    /// Sender Policy Framework. See [rfc4408]
    /// Discontinued in [rfc7208] due to widespread lack of support.
    ///
    /// [rfc4408]: https://datatracker.ietf.org/doc/html/rfc4408
    /// [rfc7208]: https://datatracker.ietf.org/doc/html/rfc7208
    SPF = 99,

    /// Any record type.
    /// Only valid as a Question Type.
    ANY = 255,
}

/// Defaults to [`Type::ANY`].
impl Default for Type {
    fn default() -> Self {
        Type::ANY
    }
}

/// Resource Record Class, for example Internet.
#[derive(Copy, Clone, Debug, Display, EnumString, Eq, FromPrimitive, Hash, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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

    /// No class specified, see [rfc2136]
    ///
    /// [rfc2136]: https://datatracker.ietf.org/doc/html/rfc2136
    None = 254,

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

/// Defaults to [`Class::Internet`].
impl Default for Class {
    fn default() -> Self {
        Class::Internet
    }
}

/// Recource Record Definitions.
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum Resource {
    A(A), // Support non-Internet classes?
    AAAA(AAAA),

    CNAME(CNAME),
    NS(NS),
    PTR(PTR),

    // TODO Implement RFC 1464 for further parsing of the text
    // TODO per RFC 4408 a TXT record is allowed to contain multiple strings
    TXT(TXT),
    SPF(TXT),

    MX(MX),
    SOA(SOA),
    SRV(SRV),

    OPT,

    ANY, // Not a valid Record Type, but is a Type
}

impl Resource {
    pub fn r#type(&self) -> Type {
        // This should be kept in sync with Type.
        // TODO Determine if I can generate this with a macro.
        match self {
            Resource::A(_) => Type::A,
            Resource::AAAA(_) => Type::AAAA,
            Resource::CNAME(_) => Type::CNAME,
            Resource::NS(_) => Type::NS,
            Resource::PTR(_) => Type::PTR,
            Resource::TXT(_) => Type::TXT,
            Resource::MX(_) => Type::MX,
            Resource::SOA(_) => Type::SOA,
            Resource::SRV(_) => Type::SRV,
            Resource::SPF(_) => Type::SPF,
            Resource::OPT => Type::OPT,
            Resource::ANY => Type::ANY,
        }
    }
}
