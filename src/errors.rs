use crate::Class;
use crate::Type;
use crate::from_str::FromStrError;
use thiserror::Error;

/// A convenient alias for results returned by this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// An error decoding DNS wire-format data.
///
/// Returned by [`Message::from_slice`](crate::Message::from_slice) and the other
/// wire-format decoding entry points. Decoding reads from an in-memory buffer, so
/// these describe malformed or truncated input rather than I/O failures.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input ended before the value being decoded was complete.
    #[error("input ended before the DNS message was complete")]
    UnexpectedEof,

    /// Decoding finished with bytes still remaining.
    #[error("finished decoding with {count} bytes left over")]
    TrailingBytes {
        /// Number of bytes remaining after the decoded value.
        count: u64,
    },

    /// The header contained an opcode this crate does not know.
    #[error("invalid opcode '{0}'")]
    InvalidOpcode(u8),

    /// The header contained an rcode this crate does not know.
    #[error("invalid rcode '{0}'")]
    InvalidRcode(u8),

    /// A record or question declared a type this crate does not know.
    #[error("invalid record type '{0}'")]
    InvalidType(u16),

    /// A record or question declared a class this crate does not know.
    #[error("invalid class '{0}'")]
    InvalidClass(u16),

    /// A record declared a type that cannot appear in that position.
    #[error("record type '{0}' is not valid in this position")]
    UnexpectedType(Type),

    /// An address record declared a class this crate cannot decode.
    #[error("unsupported class '{class}' for a '{record_type}' record")]
    UnsupportedClass {
        /// The record type being decoded.
        record_type: Type,
        /// The unsupported class.
        class: Class,
    },

    /// A compressed name chased more pointers than the maximum depth allows.
    #[error("compressed name exceeded the maximum pointer depth of {max}")]
    NamePointerDepthExceeded {
        /// The maximum supported pointer depth.
        max: usize,
    },

    /// A compressed name pointed forwards, which would allow decoding loops.
    #[error("compressed name pointer refers to later bytes")]
    NamePointerNotBackwards,

    /// A name label used compression bits this crate does not support.
    #[error("unsupported name compression bits '{bits:02b}'")]
    UnsupportedNameCompression {
        /// The two high bits of the label length byte.
        bits: u8,
    },

    /// A name label was not valid UTF-8.
    #[error("name label is not valid UTF-8")]
    LabelNotUtf8(#[source] std::str::Utf8Error),

    /// A name label contained non-ASCII bytes.
    #[error("name label '{label}' is not valid ASCII")]
    LabelNotAscii {
        /// The offending label.
        label: String,
    },

    /// A name label could not be decoded as an internationalized domain name.
    #[error("name label '{label}' is not a valid internationalized domain name")]
    LabelNotIdna {
        /// The offending label.
        label: String,
    },

    /// An EDNS(0) extension was decoded from a record that is not an OPT record.
    #[error("expected an EDNS(0) OPT record")]
    ExpectedOptRecord,

    /// An EDNS(0) OPT record used a name other than the root name.
    #[error("expected the root name for an EDNS(0) OPT record, got '{name}'")]
    OptRecordNotRoot {
        /// The name found on the OPT record.
        name: String,
    },

    /// An EDNS(0) OPT record declared more data than the message contains.
    #[error("EDNS(0) data extends past the end of the message")]
    OptDataTooLong,

    /// The message contained more than one EDNS(0) OPT record.
    #[error("message contains more than one EDNS(0) OPT record")]
    MultipleOptRecords,

    /// An EDNS(0) option header or its declared data was truncated.
    #[error("EDNS(0) option is truncated")]
    OptionTruncated,

    /// An EDNS(0) option's data length is not valid for that option.
    #[error("EDNS(0) {option} option has an invalid length")]
    OptionLength {
        /// The name of the option, such as `COOKIE`.
        option: &'static str,
    },

    /// An EDNS(0) Client Subnet option used an address family this crate does not know.
    #[error("unsupported EDNS(0) Client Subnet address family '{family}'")]
    UnsupportedAddressFamily {
        /// The declared address family.
        family: u16,
    },

    /// An EDNS(0) Client Subnet prefix length exceeded the address family's maximum.
    #[error("EDNS(0) Client Subnet prefix length is longer than {max} bits")]
    SubnetPrefixTooLong {
        /// The maximum prefix length for the address family.
        max: u8,
    },

    /// A length or offset in the message did not fit this platform's `usize`.
    #[error("a DNS message offset did not fit in a usize")]
    OffsetOverflow,

    /// An SOA record's rname could not be converted to an email address.
    #[error("invalid SOA rname")]
    InvalidRname(#[source] FromStrError),

    /// The underlying reader failed.
    #[error("failed to read the DNS message")]
    Read(#[source] std::io::Error),
}

/// An error encoding DNS wire-format data.
///
/// Returned by [`Message::to_vec`](crate::Message::to_vec) and the `append_to_vec`
/// family. These describe values that cannot be represented in DNS wire format.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum EncodeError {
    /// A domain name could not be converted to ASCII by IDNA processing.
    #[error("'{name}' is not a valid internationalized domain name")]
    InvalidName {
        /// The offending name.
        name: String,
    },

    /// A domain name contained an empty non-root label.
    #[error("empty label in domain name '{name}'")]
    EmptyLabel {
        /// The offending name.
        name: String,
    },

    /// A label was longer than DNS wire format allows.
    #[error("label '{label}' is longer than {max} bytes")]
    LabelTooLong {
        /// The offending label.
        label: String,
        /// The maximum encoded label length.
        max: usize,
    },

    /// A domain name was longer than DNS wire format allows.
    #[error("domain name is longer than {max} bytes")]
    NameTooLong {
        /// The maximum encoded name length.
        max: usize,
    },

    /// The message was longer than DNS wire format allows.
    #[error("DNS message is longer than {max} bytes")]
    MessageTooLong {
        /// The maximum message length.
        max: usize,
    },

    /// A section contained more entries than its count field can hold.
    #[error("DNS section count is larger than {max}")]
    SectionCountTooLarge {
        /// The maximum section count.
        max: usize,
    },

    /// A record's data was longer than its length field can hold.
    #[error("record data is longer than {max} bytes")]
    RdataTooLong {
        /// The maximum record data length.
        max: usize,
    },

    /// An EDNS(0) option's data was longer than its length field can hold.
    #[error("EDNS(0) option data is longer than {max} bytes")]
    OptionDataTooLong {
        /// The maximum option data length.
        max: usize,
    },

    /// A record's TTL did not fit in the 32-bit TTL field.
    #[error("record TTL is longer than {max} seconds")]
    TtlTooLong {
        /// The maximum TTL in seconds.
        max: u64,
    },

    /// An SOA duration did not fit in its 32-bit field.
    #[error("SOA duration is longer than {max} seconds")]
    DurationTooLong {
        /// The maximum duration in seconds.
        max: u64,
    },

    /// A TXT character-string was longer than its length byte can hold.
    #[error("TXT string is longer than {max} bytes")]
    TxtStringTooLong {
        /// The maximum character-string length.
        max: usize,
    },

    /// An SOA record's email address could not be converted to an rname.
    #[error("invalid SOA email address '{email}'")]
    InvalidRname {
        /// The offending email address.
        email: String,
    },

    /// This crate cannot encode the given record type.
    #[error("record type '{0}' cannot be encoded")]
    UnsupportedType(Type),

    /// An EDNS(0) option value cannot be represented on the wire.
    #[error("EDNS(0) {option} option cannot be encoded: {reason}")]
    InvalidOption {
        /// The name of the option, such as `COOKIE`.
        option: &'static str,
        /// Why the value cannot be encoded.
        reason: &'static str,
    },
}

/// Maps reader failures onto [`DecodeError`].
///
/// Decoding reads from an in-memory cursor, so the only expected failure is
/// running off the end of the buffer.
impl From<std::io::Error> for DecodeError {
    fn from(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::UnexpectedEof => DecodeError::UnexpectedEof,
            _ => DecodeError::Read(error),
        }
    }
}

/// Eases migration from the pre-1.0 API, which returned [`std::io::Error`].
impl From<DecodeError> for std::io::Error {
    fn from(error: DecodeError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, error)
    }
}

/// Eases migration from the pre-1.0 API, which returned [`std::io::Error`].
impl From<EncodeError> for std::io::Error {
    fn from(error: EncodeError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
    }
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// An HTTP response did not include a `content-type` header.
    #[cfg(feature = "http")]
    #[error("HTTP response is missing a content-type header")]
    MissingContentType,

    /// An HTTP response used a `content-type` this client does not accept.
    #[cfg(feature = "http")]
    #[error("unexpected content-type '{actual}', expected {expected}")]
    UnexpectedContentType {
        /// The content-type the server sent.
        actual: String,
        /// The content-types this client accepts.
        expected: &'static str,
    },

    #[error(transparent)]
    Decode(#[from] DecodeError),

    #[error(transparent)]
    Encode(#[from] EncodeError),

    #[error(transparent)]
    FromStr(#[from] FromStrError),

    #[cfg(feature = "json")]
    #[error(transparent)]
    Json(#[from] JsonError),

    #[cfg(feature = "http")]
    #[error(transparent)]
    Http(#[from] http::Error),

    #[cfg(feature = "hyper")]
    #[error(transparent)]
    Hyper(#[from] hyper::Error),

    #[cfg(feature = "hyper-util")]
    #[error(transparent)]
    HyperLegacy(#[from] hyper_util::client::legacy::Error),

    #[cfg(feature = "http")]
    #[error(transparent)]
    InvalidUri(#[from] http::uri::InvalidUri),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// An error decoding a DNS-over-HTTPS JSON response.
#[cfg(feature = "json")]
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum JsonError {
    /// The response body was not valid JSON, or did not match the expected shape.
    #[error(transparent)]
    Serde(#[from] serde_json::Error),

    /// The response declared an rcode this crate does not know.
    #[error("invalid rcode status: '{0}'")]
    InvalidStatus(u32),

    /// The response declared a record type this crate does not know.
    #[error("invalid record type: '{0}'")]
    InvalidType(u16),

    /// The response contained resource text that is not valid for its type.
    #[error("invalid {0} resource")]
    InvalidResource(Type, #[source] FromStrError),
}
