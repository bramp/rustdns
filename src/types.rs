//! Core DNS protocol types, packet structures, and enums.
//!
//! Defines the foundational types for DNS messages:
//! - [`Message`]: Top-level DNS message header and sections (questions, answers, authorities, additionals).
//! - [`Question`]: Query specification containing domain name, [`Type`], and [`Class`].
//! - [`Record`]: Concrete resource record associating a domain name, class, TTL, and [`Resource`] data.
//! - [`Extension`]: EDNS(0) pseudo-record options and UDP buffer size parameters.
//! - Protocol code enums: [`Type`], [`Class`], [`Opcode`], [`Rcode`], [`Algorithm`], [`DigestType`].

pub use crate::edns::{
    EDNS_OPTION_CLIENT_SUBNET, EDNS_OPTION_COOKIE, EDNS_OPTION_NSID, EDNS_OPTION_PADDING,
    EDNS_OPTION_TCP_KEEPALIVE, EdnsClientSubnet, EdnsCookie, EdnsOption,
};
use crate::resource::{
    A, AAAA, CNAME, DNSKEY, DS, MX, NS, NSEC, NSEC3, NSEC3PARAM, PTR, RRSIG, RawResource, SOA, SRV,
    TXT, ZONEMD,
};
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

    /// Checking Disabled. See [RFC 4035] and [RFC 6840].
    ///
    /// [RFC 4035]: https://datatracker.ietf.org/doc/html/rfc4035
    /// [RFC 6840]: https://datatracker.ietf.org/doc/html/rfc6840
    pub cd: bool,

    /// Authentic Data. See [RFC 4035] and [RFC 6840].
    ///
    /// [RFC 4035]: https://datatracker.ietf.org/doc/html/rfc4035
    /// [RFC 6840]: https://datatracker.ietf.org/doc/html/rfc6840
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
    ///
    /// Prefer calling [`Question::ascii_name`] to get the ASCII (Punycode / IDNA) representation
    /// of the name, which is typically used in DNS wire-format queries.
    pub name: String,

    /// The question's type.
    ///
    /// All [`Type`] variants are valid, including pseudo types (e.g. [`Type::ANY`]).
    pub r#type: Type,

    /// The question's class.
    pub class: Class,
}

/// Resource Record (RR) returned by DNS servers containing an answer to the question.
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
    /// Creates a new resource record from components.
    pub fn new(name: &str, class: Class, ttl: Duration, resource: Resource) -> Self {
        Self {
            name: name.to_owned(),
            class,
            ttl,
            resource,
        }
    }

    /// Returns the record [`Type`] of this resource record.
    pub fn r#type(&self) -> Type {
        self.resource.r#type()
    }
}

/// EDNS(0) extension record as defined in [RFC 2671] and [RFC 6891].
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
/// [RFC 2671]: https://datatracker.ietf.org/doc/html/rfc2671
/// [RFC 6891]: https://datatracker.ietf.org/doc/html/rfc6891
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
    /// default is 1232 bytes ([`crate::limits::EDNS_SAFE_UDP_PAYLOAD_SIZE`]).
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

    /// DNSSEC OK bit as defined by [RFC 3225].
    ///
    /// Set this to `true` when the sender wants DNSSEC records such as RRSIG,
    /// DNSKEY, and related authentication data to be included in responses when
    /// available. Leave it `false` for ordinary queries that do not request
    /// DNSSEC data.
    ///
    /// [RFC 3225]: https://datatracker.ietf.org/doc/html/rfc3225
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
            payload_size: crate::limits::EDNS_SAFE_UDP_PAYLOAD_SIZE,
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
    /// Sets the EDNS(0) `DO=1` (DNSSEC OK) bit on queries. Upstream `AD`
    /// (Authenticated Data) assertions are evaluated against the configured
    /// [`UpstreamTrustPolicy`] and transport security:
    /// - Responses with `AD=1` over a trusted channel evaluate to [`SecurityStatus::Secure`].
    /// - Responses with `AD=1` over an untrusted channel evaluate to [`SecurityStatus::Indeterminate`].
    /// - Responses with `AD=0` evaluate to [`SecurityStatus::Insecure`].
    /// - `SERVFAIL` responses evaluate to [`SecurityStatus::Bogus`].
    ///
    /// Both `Bogus` and `Indeterminate` responses fail closed.
    TrustUpstream {
        /// Whether the resolver requires upstream validation (`SecurityStatus::Secure`).
        ///
        /// When `true`, queries fail if the upstream did not validate the response
        /// (`SecurityStatus::Insecure`, such as for an unsigned zone).
        /// When `false` (default), unsigned responses are accepted.
        require_secure: bool,
    },

    /// Performs full local cryptographic DNSSEC chain-of-trust validation down to
    /// configured trust anchors (e.g. root anchors), verifying signatures and keys
    /// independently of upstream trust assertions.
    ValidateLocal,
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
    /// A DNS query message (0).
    Query = 0,
    /// A DNS response message (1).
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

/// Specifies kind of query in this message. See [RFC 1035], [RFC 6895] and [DNS Parameters].
///
/// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
/// [RFC 6895]: https://datatracker.ietf.org/doc/html/rfc6895
/// [DNS Parameters]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
#[derive(Copy, Clone, Debug, Display, EnumString, Eq, Hash, FromPrimitive, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)] // Really only 4 bits
pub enum Opcode {
    /// Query.
    Query = 0,

    /// Inverse Query (OBSOLETE). See [RFC 3425].
    ///
    /// [RFC 3425]: https://datatracker.ietf.org/doc/html/rfc3425
    IQuery = 1,

    /// Server status request.
    Status = 2,

    /// See [RFC 1996].
    ///
    /// [RFC 1996]: https://datatracker.ietf.org/doc/html/rfc1996
    Notify = 4,

    /// See [RFC 2136].
    ///
    /// [RFC 2136]: https://datatracker.ietf.org/doc/html/rfc2136
    Update = 5,

    /// DNS Stateful Operations (DSO). See [RFC 8490].
    ///
    /// [RFC 8490]: https://datatracker.ietf.org/doc/html/rfc8490
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
/// See [RFC 1035] and [DNS Parameters].
///
/// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
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

    /// Name Exists when it should not. See [RFC 2136] and [RFC 6672].
    ///
    /// [RFC 2136]: https://datatracker.ietf.org/doc/html/rfc2136
    /// [RFC 6672]: https://datatracker.ietf.org/doc/html/rfc6672
    YXDomain = 6,

    /// RR Set Exists when it should not. See [RFC 2136].
    ///
    /// [RFC 2136]: https://datatracker.ietf.org/doc/html/rfc2136
    YXRRSet = 7,

    /// RR Set that should exist does not. See [RFC 2136].
    ///
    /// [RFC 2136]: https://datatracker.ietf.org/doc/html/rfc2136
    NXRRSet = 8,

    /// Note on error number 9 (NotAuth): This error number means either
    /// "Not Authoritative" [RFC 2136] or "Not Authorized" [RFC 2845].
    /// If 9 appears as the RCODE in the header of a DNS response without a
    /// TSIG RR or with a TSIG RR having a zero error field, then it means
    /// "Not Authoritative".  If 9 appears as the RCODE in the header of a
    /// DNS response that includes a TSIG RR with a non-zero error field,
    /// then it means "Not Authorized".
    ///
    /// [RFC 2136]: https://datatracker.ietf.org/doc/html/rfc2136
    /// [RFC 2845]: https://datatracker.ietf.org/doc/html/rfc2845
    NotAuth = 9,

    /// Name not contained in zone. See [RFC 2136].
    ///
    /// [RFC 2136]: https://datatracker.ietf.org/doc/html/rfc2136
    NotZone = 10,

    /// DSO-TYPE Not Implemented. See [RFC 8490].
    ///
    /// [RFC 8490]: https://datatracker.ietf.org/doc/html/rfc8490
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
// TODO Implement this?
pub enum ExtendedRcode {
    Rcode,
    BADVERS_or_BADSIG = 16  //  Bad OPT Version [RFC 6891] or TSIG Signature Failure  [RFC 8945]
    BADKEY = 17  //   Key not recognized  [RFC 8945]
    BADTIME = 18  //  Signature out of time window    [RFC 8945]
    BADMODE = 19  //  Bad TKEY Mode   [RFC 2930]
    BADNAME = 20  //  Duplicate key name  [RFC 2930]
    BADALG = 21  //   Algorithm not supported [RFC 2930]
    BADTRUNC = 22  //     Bad Truncation  [RFC 8945]
    BADCOOKIE = 23  //    Bad/missing Server Cookie   [RFC 7873]
    // 24-3840  Unassigned
    // 3841-4095     Reserved for Private Use        [RFC 6895]
    // 4096-65534    Unassigned
    // 65535 = Reserved Can be allocated by Standards Action      [RFC 6895]
}
*/

/// Resource Record Type, for example, A, CNAME or SOA.
///
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(clippy::upper_case_acronyms)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum Type {
    /// Reserved type code (0).
    Reserved,

    /// (Default) IPv4 Address.
    A,

    /// Authoritative name server.
    NS,

    /// Canonical name for an alias.
    CNAME,

    /// Start of a zone of authority.
    SOA,

    /// Domain name pointer. See [`util::reverse()`] to create a valid domain name from a IP address.
    ///
    /// [`util::reverse()`]: crate::util::reverse()
    PTR,

    /// Mail exchange.
    MX,

    /// Text strings.
    TXT,

    /// IPv6 Address.
    AAAA,

    /// Server Selection
    SRV,

    /// EDNS(0) Opt type. See [RFC 3225] and [RFC 6891].
    ///
    /// [RFC 3225]: https://datatracker.ietf.org/doc/html/rfc3225
    /// [RFC 6891]: https://datatracker.ietf.org/doc/html/rfc6891
    OPT,

    /// Delegation Signer. See [RFC 4034].
    ///
    /// [RFC 4034]: https://datatracker.ietf.org/doc/html/rfc4034
    DS,

    /// Signature for an RRset. See [RFC 4034].
    ///
    /// [RFC 4034]: https://datatracker.ietf.org/doc/html/rfc4034
    RRSIG,

    /// Next Secure name. See [RFC 4034].
    ///
    /// [RFC 4034]: https://datatracker.ietf.org/doc/html/rfc4034
    NSEC,

    /// DNS Key. See [RFC 4034].
    ///
    /// [RFC 4034]: https://datatracker.ietf.org/doc/html/rfc4034
    DNSKEY,

    /// Next Secure version 3 (NSEC3). See [RFC 5155].
    ///
    /// [RFC 5155]: https://datatracker.ietf.org/doc/html/rfc5155
    NSEC3,

    /// Next Secure version 3 Parameters (NSEC3PARAM). See [RFC 5155].
    ///
    /// [RFC 5155]: https://datatracker.ietf.org/doc/html/rfc5155
    NSEC3PARAM,

    /// Message Digest for DNS Zones. See [RFC 8976].
    ///
    /// [RFC 8976]: https://datatracker.ietf.org/doc/html/rfc8976
    ZONEMD,

    /// Sender Policy Framework. See [RFC 4408].
    /// Discontinued in [RFC 7208] due to widespread lack of support.
    ///
    /// [RFC 4408]: https://datatracker.ietf.org/doc/html/rfc4408
    /// [RFC 7208]: https://datatracker.ietf.org/doc/html/rfc7208
    SPF,

    /// Any record type.
    /// Only valid as a Question Type.
    ANY,

    /// Unassigned, unrecognized, or private resource record type.
    Unknown(u16),
}

impl Type {
    /// Returns the 16-bit numeric type code for this resource record type.
    #[must_use]
    pub const fn code(&self) -> u16 {
        match self {
            Type::Reserved => 0,
            Type::A => 1,
            Type::NS => 2,
            Type::CNAME => 5,
            Type::SOA => 6,
            Type::PTR => 12,
            Type::MX => 15,
            Type::TXT => 16,
            Type::AAAA => 28,
            Type::SRV => 33,
            Type::OPT => 41,
            Type::DS => 43,
            Type::RRSIG => 46,
            Type::NSEC => 47,
            Type::DNSKEY => 48,
            Type::NSEC3 => 50,
            Type::NSEC3PARAM => 51,
            Type::ZONEMD => 63,
            Type::SPF => 99,
            Type::ANY => 255,
            Type::Unknown(code) => *code,
        }
    }
}

impl From<u16> for Type {
    fn from(code: u16) -> Self {
        match code {
            0 => Type::Reserved,
            1 => Type::A,
            2 => Type::NS,
            5 => Type::CNAME,
            6 => Type::SOA,
            12 => Type::PTR,
            15 => Type::MX,
            16 => Type::TXT,
            28 => Type::AAAA,
            33 => Type::SRV,
            41 => Type::OPT,
            43 => Type::DS,
            46 => Type::RRSIG,
            47 => Type::NSEC,
            48 => Type::DNSKEY,
            50 => Type::NSEC3,
            51 => Type::NSEC3PARAM,
            63 => Type::ZONEMD,
            99 => Type::SPF,
            255 => Type::ANY,
            other => Type::Unknown(other),
        }
    }
}

impl std::fmt::Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Type::Reserved => "Reserved",
            Type::A => "A",
            Type::NS => "NS",
            Type::CNAME => "CNAME",
            Type::SOA => "SOA",
            Type::PTR => "PTR",
            Type::MX => "MX",
            Type::TXT => "TXT",
            Type::AAAA => "AAAA",
            Type::SRV => "SRV",
            Type::OPT => "OPT",
            Type::DS => "DS",
            Type::RRSIG => "RRSIG",
            Type::NSEC => "NSEC",
            Type::DNSKEY => "DNSKEY",
            Type::NSEC3 => "NSEC3",
            Type::NSEC3PARAM => "NSEC3PARAM",
            Type::ZONEMD => "ZONEMD",
            Type::SPF => "SPF",
            Type::ANY => "ANY",
            Type::Unknown(code) => return f.pad(&format!("TYPE{code}")),
        };
        f.pad(s)
    }
}

impl std::str::FromStr for Type {
    type Err = strum::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let upper = s.to_ascii_uppercase();
        match upper.as_str() {
            "RESERVED" => Ok(Type::Reserved),
            "A" => Ok(Type::A),
            "NS" => Ok(Type::NS),
            "CNAME" => Ok(Type::CNAME),
            "SOA" => Ok(Type::SOA),
            "PTR" => Ok(Type::PTR),
            "MX" => Ok(Type::MX),
            "TXT" => Ok(Type::TXT),
            "AAAA" => Ok(Type::AAAA),
            "SRV" => Ok(Type::SRV),
            "OPT" => Ok(Type::OPT),
            "DS" => Ok(Type::DS),
            "RRSIG" => Ok(Type::RRSIG),
            "NSEC" => Ok(Type::NSEC),
            "DNSKEY" => Ok(Type::DNSKEY),
            "NSEC3" => Ok(Type::NSEC3),
            "NSEC3PARAM" => Ok(Type::NSEC3PARAM),
            "ZONEMD" => Ok(Type::ZONEMD),
            "SPF" => Ok(Type::SPF),
            "ANY" | "*" => Ok(Type::ANY),
            _ => {
                if let Some(num) = upper.strip_prefix("TYPE") {
                    if let Ok(code) = num.parse::<u16>() {
                        return Ok(Type::from(code));
                    }
                }
                Err(strum::ParseError::VariantNotFound)
            }
        }
    }
}

impl From<Type> for u16 {
    fn from(t: Type) -> Self {
        t.code()
    }
}

/// Defaults to [`Type::ANY`].
impl Default for Type {
    fn default() -> Self {
        Type::ANY
    }
}

/// DNSSEC signing and authentication algorithm numbers as defined by IANA and [RFC 8624].
///
/// [RFC 8624]: https://datatracker.ietf.org/doc/html/rfc8624#section-3.1
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(clippy::upper_case_acronyms)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum Algorithm {
    /// RSA/MD5 [RFC 2537, RFC 4034] - Deprecated, MUST NOT be used.
    RSAMD5,

    /// Diffie-Hellman [RFC 2539].
    DH,

    /// DSA/SHA1 [RFC 2536, RFC 3755].
    DSA,

    /// RSA/SHA-1 [RFC 3110, RFC 4034].
    RSASHA1,

    /// DSA-NSEC3-SHA1 [RFC 5155].
    DSANSEC3SHA1,

    /// RSASHA1-NSEC3-SHA1 [RFC 5155].
    RSASHA1NSEC3SHA1,

    /// RSA/SHA-256 [RFC 5702].
    RSASHA256,

    /// RSA/SHA-512 [RFC 5702].
    RSASHA512,

    /// GOST R 34.10-2001 [RFC 5933].
    ECCGOST,

    /// ECDSA Curve P-256 with SHA-256 [RFC 6605].
    ECDSAP256SHA256,

    /// ECDSA Curve P-384 with SHA-384 [RFC 6605].
    ECDSAP384SHA384,

    /// Ed25519 [RFC 8080].
    ED25519,

    /// Ed448 [RFC 8080].
    ED448,

    /// Unrecognized, private, or reserved algorithm number.
    Unknown(u8),
}

impl Algorithm {
    /// Returns the 8-bit numeric algorithm code.
    #[must_use]
    pub const fn code(&self) -> u8 {
        match self {
            Algorithm::RSAMD5 => 1,
            Algorithm::DH => 2,
            Algorithm::DSA => 3,
            Algorithm::RSASHA1 => 5,
            Algorithm::DSANSEC3SHA1 => 6,
            Algorithm::RSASHA1NSEC3SHA1 => 7,
            Algorithm::RSASHA256 => 8,
            Algorithm::RSASHA512 => 10,
            Algorithm::ECCGOST => 12,
            Algorithm::ECDSAP256SHA256 => 13,
            Algorithm::ECDSAP384SHA384 => 14,
            Algorithm::ED25519 => 15,
            Algorithm::ED448 => 16,
            Algorithm::Unknown(code) => *code,
        }
    }
}

impl From<u8> for Algorithm {
    fn from(code: u8) -> Self {
        match code {
            1 => Algorithm::RSAMD5,
            2 => Algorithm::DH,
            3 => Algorithm::DSA,
            5 => Algorithm::RSASHA1,
            6 => Algorithm::DSANSEC3SHA1,
            7 => Algorithm::RSASHA1NSEC3SHA1,
            8 => Algorithm::RSASHA256,
            10 => Algorithm::RSASHA512,
            12 => Algorithm::ECCGOST,
            13 => Algorithm::ECDSAP256SHA256,
            14 => Algorithm::ECDSAP384SHA384,
            15 => Algorithm::ED25519,
            16 => Algorithm::ED448,
            other => Algorithm::Unknown(other),
        }
    }
}

impl From<Algorithm> for u8 {
    fn from(a: Algorithm) -> Self {
        a.code()
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}

impl std::str::FromStr for Algorithm {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if let Ok(num) = trimmed.parse::<u8>() {
            return Ok(Algorithm::from(num));
        }
        let upper = trimmed.to_ascii_uppercase().replace(['-', '_'], "");
        Ok(match upper.as_str() {
            "RSAMD5" => Algorithm::RSAMD5,
            "DH" => Algorithm::DH,
            "DSA" => Algorithm::DSA,
            "RSASHA1" => Algorithm::RSASHA1,
            "DSANSEC3SHA1" => Algorithm::DSANSEC3SHA1,
            "RSASHA1NSEC3SHA1" => Algorithm::RSASHA1NSEC3SHA1,
            "RSASHA256" => Algorithm::RSASHA256,
            "RSASHA512" => Algorithm::RSASHA512,
            "ECCGOST" => Algorithm::ECCGOST,
            "ECDSAP256SHA256" | "ECDSAP256" => Algorithm::ECDSAP256SHA256,
            "ECDSAP384SHA384" | "ECDSAP384" => Algorithm::ECDSAP384SHA384,
            "ED25519" => Algorithm::ED25519,
            "ED448" => Algorithm::ED448,
            _ => {
                return trimmed.parse::<u8>().map(Algorithm::from);
            }
        })
    }
}

/// DNSSEC Delegation Signer (DS) digest algorithm numbers as defined by IANA and [RFC 4034], [RFC 4509], [RFC 6605].
///
/// [RFC 4034]: https://datatracker.ietf.org/doc/html/rfc4034#section-5.1.4
/// [RFC 4509]: https://datatracker.ietf.org/doc/html/rfc4509
/// [RFC 6605]: https://datatracker.ietf.org/doc/html/rfc6605
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(clippy::upper_case_acronyms)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum DigestType {
    /// SHA-1 [RFC 4034] - Mandatory for historical validation.
    Sha1,

    /// SHA-256 [RFC 4509] - Standard for modern DNSSEC.
    Sha256,

    /// GOST R 34.11-94 [RFC 5933].
    GostR3411_94,

    /// SHA-384 [RFC 6605].
    Sha384,

    /// Unrecognized, private, or reserved digest type.
    Unknown(u8),
}

impl DigestType {
    /// Returns the 8-bit numeric digest type code.
    #[must_use]
    pub const fn code(&self) -> u8 {
        match self {
            DigestType::Sha1 => 1,
            DigestType::Sha256 => 2,
            DigestType::GostR3411_94 => 3,
            DigestType::Sha384 => 4,
            DigestType::Unknown(code) => *code,
        }
    }
}

impl From<u8> for DigestType {
    fn from(code: u8) -> Self {
        match code {
            1 => DigestType::Sha1,
            2 => DigestType::Sha256,
            3 => DigestType::GostR3411_94,
            4 => DigestType::Sha384,
            other => DigestType::Unknown(other),
        }
    }
}

impl From<DigestType> for u8 {
    fn from(d: DigestType) -> Self {
        d.code()
    }
}

impl std::fmt::Display for DigestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}

impl std::str::FromStr for DigestType {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if let Ok(num) = trimmed.parse::<u8>() {
            return Ok(DigestType::from(num));
        }
        let upper = trimmed.to_ascii_uppercase().replace(['-', '_'], "");
        Ok(match upper.as_str() {
            "SHA1" => DigestType::Sha1,
            "SHA256" => DigestType::Sha256,
            "GOSTR341194" | "GOST" => DigestType::GostR3411_94,
            "SHA384" => DigestType::Sha384,
            _ => {
                return trimmed.parse::<u8>().map(DigestType::from);
            }
        })
    }
}

/// Cryptographic hash algorithm used for NSEC3 hashed owner names ([RFC 5155 §11.4]).
///
/// [RFC 5155 §11.4]: https://datatracker.ietf.org/doc/html/rfc5155#section-11.4
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(clippy::upper_case_acronyms)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum Nsec3HashAlgorithm {
    /// SHA-1 [RFC 5155] - Currently the only standardized NSEC3 hash algorithm.
    ///
    /// [RFC 5155]: https://datatracker.ietf.org/doc/html/rfc5155
    Sha1,

    /// Unassigned, reserved, or private hash algorithm.
    Unknown(u8),
}

impl Nsec3HashAlgorithm {
    /// Returns the 8-bit numeric hash algorithm code.
    #[must_use]
    pub const fn code(&self) -> u8 {
        match self {
            Nsec3HashAlgorithm::Sha1 => 1,
            Nsec3HashAlgorithm::Unknown(code) => *code,
        }
    }
}

impl From<u8> for Nsec3HashAlgorithm {
    fn from(code: u8) -> Self {
        match code {
            1 => Nsec3HashAlgorithm::Sha1,
            other => Nsec3HashAlgorithm::Unknown(other),
        }
    }
}

impl From<Nsec3HashAlgorithm> for u8 {
    fn from(a: Nsec3HashAlgorithm) -> Self {
        a.code()
    }
}

impl std::fmt::Display for Nsec3HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}

impl std::str::FromStr for Nsec3HashAlgorithm {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if let Ok(num) = trimmed.parse::<u8>() {
            return Ok(Nsec3HashAlgorithm::from(num));
        }
        let upper = trimmed.to_ascii_uppercase().replace(['-', '_'], "");
        Ok(match upper.as_str() {
            "SHA1" => Nsec3HashAlgorithm::Sha1,
            _ => {
                return trimmed.parse::<u8>().map(Nsec3HashAlgorithm::from);
            }
        })
    }
}

/// Resource Record Class, for example Internet.
#[derive(
    Copy, Clone, Debug, Display, EnumString, Eq, FromPrimitive, Hash, Ord, PartialEq, PartialOrd,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u16)]
pub enum Class {
    /// Reserved per [RFC 6895].
    ///
    /// [RFC 6895]: https://datatracker.ietf.org/doc/html/rfc6895
    Reserved = 0,

    /// (Default) The Internet (IN), see [RFC 1035].
    ///
    /// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
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

    /// No class specified, see [RFC 2136].
    ///
    /// [RFC 2136]: https://datatracker.ietf.org/doc/html/rfc2136
    None = 254,

    /// * (ANY) See [RFC 1035].
    ///
    /// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
    #[strum(serialize = "*")]
    Any = 255,
    //     5-253     Unassigned
    //   256-65279   Unassigned
    // 65280-65534   Reserved for Private Use    [RFC 6895]
    // 65535         Reserved    [RFC 6895]
}

/// Defaults to [`Class::Internet`].
impl Default for Class {
    fn default() -> Self {
        Class::Internet
    }
}

/// Resource record definitions.
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum Resource {
    /// IPv4 Address (A) record.
    A(A),
    /// IPv6 Address (AAAA) record.
    AAAA(AAAA),

    /// Canonical name (CNAME) record, for aliasing one name to another.
    CNAME(CNAME),
    /// Name Server (NS) record for delegating to the given authoritative name servers.
    NS(NS),
    /// Pointer (PTR) record most commonly used for implementing reverse DNS lookups.
    PTR(PTR),

    // TODO Implement RFC 1464 for further parsing of the text
    // TODO per RFC 4408 a TXT record is allowed to contain multiple strings
    /// Text (TXT) record for arbitrary human-readable text in a DNS record.
    TXT(TXT),
    /// Sender Policy Framework (SPF) record.
    SPF(TXT),

    /// Mail EXchanger (MX) record specifying the mail server responsible for accepting email messages on behalf of a domain name.
    MX(MX),
    /// Start of Authority (SOA) record containing administrative information about the zone.
    SOA(SOA),
    /// Service (SRV) record containing hostname and port number information of specified services.
    SRV(SRV),

    /// Delegation Signer (DS) record.
    DS(DS),
    /// DNS Key (DNSKEY) record.
    DNSKEY(DNSKEY),
    /// DNSSEC Signature (RRSIG) record.
    RRSIG(RRSIG),
    /// Next Secure (NSEC) record.
    NSEC(NSEC),
    /// Next Secure version 3 (NSEC3) record.
    NSEC3(NSEC3),
    /// Next Secure version 3 Parameters (NSEC3PARAM) record.
    NSEC3PARAM(NSEC3PARAM),
    /// Message Digest for DNS Zones (ZONEMD) record.
    ZONEMD(ZONEMD),

    /// EDNS(0) OPT pseudo-record.
    OPT,

    /// Wildcard / any-type query pseudo-record (valid only in queries).
    ANY,

    /// Unrecognized or raw resource record data.
    Raw(RawResource),
}

impl Resource {
    /// Returns the record [`Type`] associated with this resource record payload.
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
            Resource::DS(_) => Type::DS,
            Resource::DNSKEY(_) => Type::DNSKEY,
            Resource::RRSIG(_) => Type::RRSIG,
            Resource::NSEC(_) => Type::NSEC,
            Resource::NSEC3(_) => Type::NSEC3,
            Resource::NSEC3PARAM(_) => Type::NSEC3PARAM,
            Resource::ZONEMD(_) => Type::ZONEMD,
            Resource::OPT => Type::OPT,
            Resource::ANY => Type::ANY,
            Resource::Raw(raw) => Type::from(raw.rtype),
        }
    }
}
