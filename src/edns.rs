use crate::errors::{DecodeError, EncodeError};
use std::convert::TryFrom;
use std::fmt;
use std::io::{Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// EDNS(0) NSID option code as defined in [rfc5001].
///
/// [rfc5001]: https://datatracker.ietf.org/doc/html/rfc5001
pub const EDNS_OPTION_NSID: u16 = 3;

/// EDNS(0) Client Subnet option code as defined in [rfc7871].
///
/// [rfc7871]: https://datatracker.ietf.org/doc/html/rfc7871
pub const EDNS_OPTION_CLIENT_SUBNET: u16 = 8;

/// EDNS(0) COOKIE option code as defined in [rfc7873].
///
/// [rfc7873]: https://datatracker.ietf.org/doc/html/rfc7873
pub const EDNS_OPTION_COOKIE: u16 = 10;

/// EDNS(0) TCP keepalive option code as defined in [rfc7828].
///
/// [rfc7828]: https://datatracker.ietf.org/doc/html/rfc7828
pub const EDNS_OPTION_TCP_KEEPALIVE: u16 = 11;

/// EDNS(0) Padding option code as defined in [rfc7830].
///
/// [rfc7830]: https://datatracker.ietf.org/doc/html/rfc7830
pub const EDNS_OPTION_PADDING: u16 = 12;

/// EDNS(0) option data as defined in [rfc6891].
///
/// Use typed constructors such as [`EdnsOption::nsid`],
/// [`EdnsOption::client_subnet`], [`EdnsOption::cookie`],
/// [`EdnsOption::tcp_keepalive`], and [`EdnsOption::padding`] when constructing
/// a query. Use [`EdnsOption::unknown`] for options that do not yet have a typed
/// variant.
///
/// [rfc6891]: https://datatracker.ietf.org/doc/html/rfc6891
#[non_exhaustive]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum EdnsOption {
    /// Name Server Identifier option as defined in [rfc5001].
    ///
    /// [rfc5001]: https://datatracker.ietf.org/doc/html/rfc5001
    Nsid(Vec<u8>),

    /// Client Subnet option as defined in [rfc7871].
    ///
    /// [rfc7871]: https://datatracker.ietf.org/doc/html/rfc7871
    ClientSubnet(EdnsClientSubnet),

    /// COOKIE option as defined in [rfc7873].
    ///
    /// [rfc7873]: https://datatracker.ietf.org/doc/html/rfc7873
    Cookie(EdnsCookie),

    /// TCP keepalive option as defined in [rfc7828].
    ///
    /// The duration is encoded in units of 100 milliseconds. `None` encodes an
    /// empty option, which requests TCP keepalive support without suggesting a
    /// timeout.
    ///
    /// [rfc7828]: https://datatracker.ietf.org/doc/html/rfc7828
    TcpKeepalive(Option<Duration>),

    /// Padding option as defined in [rfc7830].
    ///
    /// [`EdnsOption::padding`] creates zero-filled padding bytes. Parsed padding
    /// data is preserved as received.
    ///
    /// [rfc7830]: https://datatracker.ietf.org/doc/html/rfc7830
    Padding(Vec<u8>),

    /// Unknown EDNS(0) option, preserved as raw option data.
    Unknown { code: u16, data: Vec<u8> },
}

impl EdnsOption {
    /// Creates an EDNS(0) NSID option.
    ///
    /// Use an empty value to request that the server include its NSID in the
    /// response. Use a non-empty value when sending an explicit NSID payload.
    pub fn nsid(data: impl Into<Vec<u8>>) -> Self {
        Self::Nsid(data.into())
    }

    /// Creates an EDNS(0) Client Subnet option.
    ///
    /// Use this when a query should include an address prefix for resolver
    /// geolocation or policy. Host bits beyond `source_prefix_len` are cleared
    /// before encoding.
    pub fn client_subnet(address: IpAddr, source_prefix_len: u8, scope_prefix_len: u8) -> Self {
        Self::ClientSubnet(EdnsClientSubnet::new(
            address,
            source_prefix_len,
            scope_prefix_len,
        ))
    }

    /// Creates an EDNS(0) COOKIE option with only a client cookie.
    pub fn cookie(client_cookie: [u8; 8]) -> Self {
        Self::Cookie(EdnsCookie::new(client_cookie, Vec::new()))
    }

    /// Creates an EDNS(0) COOKIE option with a client cookie and server cookie.
    ///
    /// The server cookie must be empty or between 8 and 32 bytes when encoded.
    pub fn cookie_with_server(client_cookie: [u8; 8], server_cookie: impl Into<Vec<u8>>) -> Self {
        Self::Cookie(EdnsCookie::new(client_cookie, server_cookie))
    }

    /// Creates an EDNS(0) TCP keepalive option.
    ///
    /// Use `None` to request TCP keepalive support without suggesting a timeout.
    /// Use `Some(duration)` to include a timeout, which must be representable in
    /// 100 millisecond units when encoded.
    pub fn tcp_keepalive(timeout: Option<Duration>) -> Self {
        Self::TcpKeepalive(timeout)
    }

    /// Creates an EDNS(0) Padding option with `len` zero bytes.
    pub fn padding(len: u16) -> Self {
        Self::Padding(vec![0; usize::from(len)])
    }

    /// Creates an unknown EDNS(0) option from its option code and raw data.
    ///
    /// Use this for EDNS options that do not yet have a typed variant.
    pub fn unknown(code: u16, data: impl Into<Vec<u8>>) -> Self {
        Self::Unknown {
            code,
            data: data.into(),
        }
    }

    /// Returns the EDNS(0) option code.
    pub fn code(&self) -> u16 {
        match self {
            Self::Nsid(_) => EDNS_OPTION_NSID,
            Self::ClientSubnet(_) => EDNS_OPTION_CLIENT_SUBNET,
            Self::Cookie(_) => EDNS_OPTION_COOKIE,
            Self::TcpKeepalive(_) => EDNS_OPTION_TCP_KEEPALIVE,
            Self::Padding(_) => EDNS_OPTION_PADDING,
            Self::Unknown { code, .. } => *code,
        }
    }

    /// Parses a single EDNS(0) option from an OPT RDATA cursor.
    ///
    /// Use this inside the OPT record RDATA loop. It reads the option code,
    /// option length, and exactly that many payload bytes from `cur`.
    ///
    /// # Errors
    ///
    /// Returns an error when an option header or declared option data is
    /// truncated, or when a known option is malformed.
    pub(crate) fn parse(cur: &mut Cursor<&[u8]>) -> Result<Self, DecodeError> {
        let mut header = [0; 4];
        cur.read_exact(&mut header)
            .map_err(|_| DecodeError::OptionTruncated)?;

        let code = u16::from_be_bytes([header[0], header[1]]);
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let mut data = vec![0; len];
        cur.read_exact(&mut data)
            .map_err(|_| DecodeError::OptionTruncated)?;

        Self::parse_data(code, &data)
    }

    fn parse_data(code: u16, data: &[u8]) -> Result<Self, DecodeError> {
        match code {
            EDNS_OPTION_NSID => Ok(Self::Nsid(data.to_vec())),
            EDNS_OPTION_CLIENT_SUBNET => EdnsClientSubnet::parse(data).map(Self::ClientSubnet),
            EDNS_OPTION_COOKIE => EdnsCookie::parse(data).map(Self::Cookie),
            EDNS_OPTION_TCP_KEEPALIVE => parse_tcp_keepalive(data).map(Self::TcpKeepalive),
            EDNS_OPTION_PADDING => Ok(Self::Padding(data.to_vec())),
            code => Ok(Self::Unknown {
                code,
                data: data.to_vec(),
            }),
        }
    }

    pub(crate) fn append_to_vec(&self, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        let mut data = Vec::new();
        match self {
            Self::Nsid(value) => data.extend_from_slice(value),
            Self::ClientSubnet(subnet) => subnet.append_data_to_vec(&mut data)?,
            Self::Cookie(cookie) => cookie.append_data_to_vec(&mut data)?,
            Self::TcpKeepalive(timeout) => append_tcp_keepalive_to_vec(&mut data, *timeout)?,
            Self::Padding(value) => data.extend_from_slice(value),
            Self::Unknown { data: value, .. } => data.extend_from_slice(value),
        }

        let data_len = u16::try_from(data.len()).map_err(|_| EncodeError::OptionDataTooLong {
            max: crate::limits::MAX_EDNS_OPTION_DATA_LEN,
        })?;
        buf.extend_from_slice(&self.code().to_be_bytes());
        buf.extend_from_slice(&data_len.to_be_bytes());
        buf.extend_from_slice(&data);
        Ok(())
    }
}

impl fmt::Display for EdnsOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nsid(value) => write!(f, "NSID {}", hex(value)),
            Self::ClientSubnet(subnet) => write!(
                f,
                "CLIENT-SUBNET {}/{}/{}",
                subnet.address, subnet.source_prefix_len, subnet.scope_prefix_len
            ),
            Self::Cookie(cookie) => {
                write!(f, "COOKIE client={}", hex(&cookie.client_cookie))?;
                if !cookie.server_cookie.is_empty() {
                    write!(f, " server={}", hex(&cookie.server_cookie))?;
                }
                Ok(())
            }
            Self::TcpKeepalive(None) => write!(f, "TCP-KEEPALIVE"),
            Self::TcpKeepalive(Some(timeout)) => {
                write!(f, "TCP-KEEPALIVE timeout={}", display_duration(*timeout))
            }
            Self::Padding(value) => write!(f, "PADDING {} bytes", value.len()),
            Self::Unknown { code, data } => write!(f, "OPTION-CODE {} {}", code, hex(data)),
        }
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|value| format!("{value:02x}")).collect()
}

fn display_duration(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis % 1000 == 0 {
        format!("{}s", millis / 1000)
    } else {
        format!("{millis}ms")
    }
}

/// EDNS(0) COOKIE option data as defined in [rfc7873].
///
/// Use [`EdnsOption::cookie`] for client-only cookies and
/// [`EdnsOption::cookie_with_server`] when a server cookie is available.
///
/// [rfc7873]: https://datatracker.ietf.org/doc/html/rfc7873
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct EdnsCookie {
    /// Client cookie. Always exactly 8 bytes.
    pub client_cookie: [u8; 8],

    /// Server cookie. Empty for client-only cookies; otherwise 8 to 32 bytes.
    pub server_cookie: Vec<u8>,
}

impl EdnsCookie {
    /// Creates EDNS(0) COOKIE option data.
    ///
    /// The server cookie is validated when the option is encoded.
    pub fn new(client_cookie: [u8; 8], server_cookie: impl Into<Vec<u8>>) -> Self {
        Self {
            client_cookie,
            server_cookie: server_cookie.into(),
        }
    }

    fn parse(data: &[u8]) -> Result<Self, DecodeError> {
        if data.len() < 8 || data.len() > 40 || (data.len() > 8 && data.len() < 16) {
            return Err(DecodeError::OptionLength { option: "COOKIE" });
        }

        let mut client_cookie = [0; 8];
        client_cookie.copy_from_slice(&data[..8]);

        Ok(Self {
            client_cookie,
            server_cookie: data[8..].to_vec(),
        })
    }

    fn append_data_to_vec(&self, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        validate_server_cookie_len(self.server_cookie.len())?;
        buf.extend_from_slice(&self.client_cookie);
        buf.extend_from_slice(&self.server_cookie);
        Ok(())
    }
}

fn validate_server_cookie_len(len: usize) -> Result<(), EncodeError> {
    if len != 0 && !(8..=32).contains(&len) {
        return Err(EncodeError::InvalidOption {
            option: "COOKIE",
            reason: "server cookie must be empty or 8 to 32 bytes",
        });
    }
    Ok(())
}

fn parse_tcp_keepalive(data: &[u8]) -> Result<Option<Duration>, DecodeError> {
    match data.len() {
        0 => Ok(None),
        2 => {
            let units = u16::from_be_bytes([data[0], data[1]]);
            Ok(Some(Duration::from_millis(u64::from(units) * 100)))
        }
        _ => Err(DecodeError::OptionLength {
            option: "TCP KEEPALIVE",
        }),
    }
}

fn append_tcp_keepalive_to_vec(
    buf: &mut Vec<u8>,
    timeout: Option<Duration>,
) -> Result<(), EncodeError> {
    let Some(timeout) = timeout else {
        return Ok(());
    };

    let millis = timeout.as_millis();
    if millis % 100 != 0 {
        return Err(EncodeError::InvalidOption {
            option: "TCP KEEPALIVE",
            reason: "timeout must be a whole number of 100ms units",
        });
    }
    let units = u16::try_from(millis / 100).map_err(|_| EncodeError::InvalidOption {
        option: "TCP KEEPALIVE",
        reason: "timeout is too large",
    })?;
    buf.extend_from_slice(&units.to_be_bytes());
    Ok(())
}

/// EDNS(0) Client Subnet option data as defined in [rfc7871].
///
/// Use [`EdnsOption::client_subnet`] for normal construction. Use this type
/// directly when matching parsed EDNS options or when the address, source prefix,
/// and scope prefix need to be inspected separately.
///
/// [rfc7871]: https://datatracker.ietf.org/doc/html/rfc7871
#[non_exhaustive]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct EdnsClientSubnet {
    /// Client address prefix.
    pub address: IpAddr,

    /// Number of significant leading address bits.
    pub source_prefix_len: u8,

    /// Number of significant leading address bits in the response scope.
    pub scope_prefix_len: u8,
}

impl EdnsClientSubnet {
    /// Creates EDNS(0) Client Subnet option data.
    ///
    /// Use [`EdnsOption::client_subnet`] when constructing an EDNS option. This
    /// constructor is useful when the subnet data itself needs to be stored or
    /// inspected before wrapping it in [`EdnsOption::ClientSubnet`]. Host bits
    /// beyond `source_prefix_len` are cleared.
    pub fn new(address: IpAddr, source_prefix_len: u8, scope_prefix_len: u8) -> Self {
        Self {
            address: truncate_address(address, source_prefix_len),
            source_prefix_len,
            scope_prefix_len,
        }
    }

    fn parse(data: &[u8]) -> Result<Self, DecodeError> {
        if data.len() < 4 {
            return Err(DecodeError::OptionLength {
                option: "CLIENT SUBNET",
            });
        }

        let family = u16::from_be_bytes([data[0], data[1]]);
        let source_prefix_len = data[2];
        let scope_prefix_len = data[3];
        let max_prefix_len = match family {
            1 => 32,
            2 => 128,
            _ => {
                return Err(DecodeError::UnsupportedAddressFamily { family });
            }
        };
        if !subnet_prefix_valid(source_prefix_len, scope_prefix_len, max_prefix_len) {
            return Err(DecodeError::SubnetPrefixTooLong {
                max: max_prefix_len,
            });
        }

        let address_len = prefix_byte_len(source_prefix_len);
        if data.len() != 4 + address_len {
            return Err(DecodeError::OptionLength {
                option: "CLIENT SUBNET",
            });
        }

        let address = match family {
            1 => {
                let mut octets = [0; 4];
                octets[..address_len].copy_from_slice(&data[4..]);
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            2 => {
                let mut octets = [0; 16];
                octets[..address_len].copy_from_slice(&data[4..]);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => unreachable!(),
        };

        Ok(Self {
            address,
            source_prefix_len,
            scope_prefix_len,
        })
    }

    fn append_data_to_vec(&self, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        let (family, max_prefix_len, mut address) = match self.address {
            IpAddr::V4(address) => (1_u16, 32, address.octets().to_vec()),
            IpAddr::V6(address) => (2_u16, 128, address.octets().to_vec()),
        };
        if !subnet_prefix_valid(
            self.source_prefix_len,
            self.scope_prefix_len,
            max_prefix_len,
        ) {
            return Err(EncodeError::InvalidOption {
                option: "CLIENT SUBNET",
                reason: "prefix length is longer than the address family allows",
            });
        }

        let address_len = prefix_byte_len(self.source_prefix_len);
        clear_unused_prefix_bits(&mut address, self.source_prefix_len);

        buf.extend_from_slice(&family.to_be_bytes());
        buf.push(self.source_prefix_len);
        buf.push(self.scope_prefix_len);
        buf.extend_from_slice(&address[..address_len]);
        Ok(())
    }
}

fn subnet_prefix_valid(source_prefix_len: u8, scope_prefix_len: u8, max: u8) -> bool {
    source_prefix_len <= max && scope_prefix_len <= max
}

fn prefix_byte_len(prefix_len: u8) -> usize {
    usize::from(prefix_len).div_ceil(8)
}

fn clear_unused_prefix_bits(address: &mut [u8], prefix_len: u8) {
    for value in &mut address[prefix_byte_len(prefix_len)..] {
        *value = 0;
    }

    let remainder = prefix_len % 8;
    if remainder == 0 || prefix_len == 0 {
        return;
    }

    let index = prefix_byte_len(prefix_len) - 1;
    address[index] &= 0xff_u8 << (8 - remainder);
}

fn truncate_address(address: IpAddr, prefix_len: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) if prefix_len <= 32 => {
            let mut octets = address.octets();
            clear_unused_prefix_bits(&mut octets, prefix_len);
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        IpAddr::V6(address) if prefix_len <= 128 => {
            let mut octets = address.octets();
            clear_unused_prefix_bits(&mut octets, prefix_len);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        address => address,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EDNS_OPTION_CLIENT_SUBNET, EDNS_OPTION_COOKIE, EDNS_OPTION_NSID, EDNS_OPTION_PADDING,
        EDNS_OPTION_TCP_KEEPALIVE, EdnsOption,
    };
    use std::io::{self, Cursor};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn parse_options(buf: &[u8]) -> io::Result<Vec<EdnsOption>> {
        let mut cur = Cursor::new(buf);
        let mut options = Vec::new();
        while cur.position() < buf.len() as u64 {
            options.push(EdnsOption::parse(&mut cur)?);
        }
        Ok(options)
    }

    #[test]
    fn parse_reads_known_and_unknown_options() {
        let options = parse_options(&[
            0, 3, 0, 3, b'a', b'b', b'c', // NSID
            0xfe, 0xed, 0, 2, 1, 2, // unknown
        ])
        .expect("options should parse");

        assert_eq!(
            options,
            vec![
                EdnsOption::Nsid(b"abc".to_vec()),
                EdnsOption::Unknown {
                    code: 0xfeed,
                    data: vec![1, 2],
                },
            ]
        );
        assert_eq!(options[0].code(), EDNS_OPTION_NSID);
    }

    #[test]
    fn parse_reads_client_subnet() {
        let options = parse_options(&[
            0, 8, 0, 7, // option header
            0, 1, 24, 0, 192, 0, 2, // IPv4 family, source/scope prefix, address
        ])
        .expect("client subnet should parse");

        assert_eq!(options[0].code(), EDNS_OPTION_CLIENT_SUBNET);
        assert_eq!(
            options[0],
            EdnsOption::client_subnet(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24, 0)
        );
    }

    #[test]
    fn parse_reads_cookie_tcp_keepalive_and_padding() {
        let options = parse_options(&[
            0, 10, 0, 8, b'c', b'l', b'i', b'e', b'n', b't', b'0', b'1', // COOKIE
            0, 11, 0, 2, 0, 100, // TCP keepalive, 10 seconds
            0, 12, 0, 4, 0, 0, 0, 0, // Padding
        ])
        .expect("options should parse");

        assert_eq!(options[0].code(), EDNS_OPTION_COOKIE);
        assert_eq!(options[1].code(), EDNS_OPTION_TCP_KEEPALIVE);
        assert_eq!(options[2].code(), EDNS_OPTION_PADDING);
        assert_eq!(
            options,
            vec![
                EdnsOption::cookie(*b"client01"),
                EdnsOption::tcp_keepalive(Some(Duration::from_secs(10))),
                EdnsOption::padding(4),
            ]
        );
    }

    #[test]
    fn append_to_vec_round_trips_cookie_tcp_keepalive_and_padding() {
        let options = vec![
            EdnsOption::cookie(*b"client01"),
            EdnsOption::cookie_with_server(*b"client02", b"server01".to_vec()),
            EdnsOption::tcp_keepalive(None),
            EdnsOption::tcp_keepalive(Some(Duration::from_secs(30))),
            EdnsOption::padding(4),
        ];
        let mut buf = Vec::new();
        for option in &options {
            option
                .append_to_vec(&mut buf)
                .expect("option should encode");
        }

        assert_eq!(parse_options(&buf).unwrap(), options);
    }

    #[test]
    fn rejects_malformed_cookie_and_tcp_keepalive_options() {
        assert!(
            EdnsOption::parse(&mut Cursor::new(&[
                0, 10, 0, 5, b's', b'h', b'o', b'r', b't'
            ]))
            .is_err()
        );
        assert!(EdnsOption::parse(&mut Cursor::new(&[0, 11, 0, 1, 0])).is_err());

        let mut buf = Vec::new();
        assert!(
            EdnsOption::cookie_with_server(*b"client01", b"short".to_vec())
                .append_to_vec(&mut buf)
                .is_err()
        );
        assert!(
            EdnsOption::tcp_keepalive(Some(Duration::from_millis(150)))
                .append_to_vec(&mut buf)
                .is_err()
        );
    }

    #[test]
    fn parse_rejects_truncated_option_data() {
        assert!(EdnsOption::parse(&mut Cursor::new(&[0, 3, 0, 2, b'a'])).is_err());
    }
}
