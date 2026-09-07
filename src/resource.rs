use crate::FromStrError;
use crate::errors::{DecodeError, EncodeError};
use crate::io::{CursorExt, DNSReadExt, SeekExt};
use crate::types::*;
use byteorder::{BE, ReadBytesExt};
use std::convert::TryFrom;
use std::io;
use std::io::Cursor;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// IPv4 Address (A) record.
pub type A = Ipv4Addr;

/// IPv6 Address (AAAA) record.
#[allow(clippy::upper_case_acronyms)]
pub type AAAA = Ipv6Addr;

/// Name Server (NS) record for delegating a the given authoritative name
/// servers.
pub type NS = String;

/// Canonical name (CNAME) record, for aliasing one name to another.
#[allow(clippy::upper_case_acronyms)]
pub type CNAME = String;

/// Pointer (PTR) record most commonly used for most common use is for
/// implementing reverse DNS lookups.
#[allow(clippy::upper_case_acronyms)]
pub type PTR = String;

/// Text (TXT) record for arbitrary human-readable text in a DNS record.
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct TXT(pub Vec<Vec<u8>>);

impl Resource {
    pub(crate) fn append_rdata_to_vec(&self, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Resource::A(address) => buf.extend_from_slice(&address.octets()),
            Resource::AAAA(address) => buf.extend_from_slice(&address.octets()),
            Resource::CNAME(name) | Resource::NS(name) | Resource::PTR(name) => {
                Message::append_qname_to_vec(buf, name)?;
            }
            Resource::TXT(txt) | Resource::SPF(txt) => txt.append_rdata_to_vec(buf)?,
            Resource::MX(mx) => mx.append_rdata_to_vec(buf)?,
            Resource::SOA(soa) => soa.append_rdata_to_vec(buf)?,
            Resource::SRV(srv) => srv.append_rdata_to_vec(buf)?,
            Resource::DS(ds) => ds.append_rdata_to_vec(buf)?,
            Resource::DNSKEY(dnskey) => dnskey.append_rdata_to_vec(buf)?,
            Resource::RRSIG(rrsig) => rrsig.append_rdata_to_vec(buf)?,
            Resource::NSEC(nsec) => nsec.append_rdata_to_vec(buf)?,
            Resource::ZONEMD(zonemd) => zonemd.append_rdata_to_vec(buf)?,
            Resource::OPT | Resource::ANY => {
                return Err(EncodeError::UnsupportedType(self.r#type()));
            }
        }
        Ok(())
    }
}

impl Record {
    /// Appends this resource record as DNS wire-format bytes to `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::TtlTooLong`] when the TTL exceeds the 32-bit TTL
    /// field, [`EncodeError::RdataTooLong`] when the encoded resource data
    /// exceeds the record's length field, and [`EncodeError::UnsupportedType`]
    /// for `OPT` and `ANY`, which have no record encoding. Name failures produce
    /// the [`EncodeError`] name variants.
    pub fn append_to_vec(&self, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        Message::append_qname_to_vec(buf, &self.name)?;
        buf.extend_from_slice(&(self.r#type() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.class as u16).to_be_bytes());
        let ttl = u32::try_from(self.ttl.as_secs()).map_err(|_| EncodeError::TtlTooLong {
            max: u64::from(u32::MAX),
        })?;
        buf.extend_from_slice(&ttl.to_be_bytes());

        let rdata_length_pos = buf.len();
        buf.extend_from_slice(&0_u16.to_be_bytes());
        let rdata_start = buf.len();

        self.resource.append_rdata_to_vec(buf)?;

        let rdata_length =
            u16::try_from(buf.len() - rdata_start).map_err(|_| EncodeError::RdataTooLong {
                max: crate::limits::MAX_RDATA_LEN,
            })?;
        buf[rdata_length_pos..rdata_start].copy_from_slice(&rdata_length.to_be_bytes());
        Ok(())
    }

    pub(crate) fn parse(
        cur: &mut Cursor<&[u8]>,
        name: String,
        r#type: Type,
        class: Class,
    ) -> Result<Record, DecodeError> {
        let ttl = cur.read_u32::<BE>()?;
        let len = cur.read_u16::<BE>()?;

        // Create a new Cursor that is limited to the len field.
        //
        // cur     [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10...]
        //                      ^ pos & len = 2
        //
        // record  [0, 1, 2, 3, 4, 5, 6]
        //                      ^ pos
        //
        // The record starts from zero, instead of being [4,6], this is
        // so it can jump backwards for a qname (or similar) read.

        let pos = cur.position();
        let end = pos
            .checked_add(u64::from(len))
            .ok_or(DecodeError::OffsetOverflow)?;
        let end = usize::try_from(end).map_err(|_| DecodeError::OffsetOverflow)?;
        let mut record = cur.sub_cursor(0, end)?;
        record.set_position(pos);

        // If parsing fails for this record, (and the length seems correct),
        // we could turn this into a warning instead of a full error.

        // TODO Consider changing these parse methods to some kind of common function
        // that accepts Cursor and Class.
        let resource = match r#type {
            Type::A => Resource::A(parse_a(&mut record, class)?),
            Type::AAAA => Resource::AAAA(parse_aaaa(&mut record, class)?),

            Type::NS => Resource::NS(record.read_qname()?),
            Type::SOA => Resource::SOA(SOA::parse(&mut record)?),
            Type::CNAME => Resource::CNAME(record.read_qname()?),
            Type::PTR => Resource::PTR(record.read_qname()?),
            Type::MX => Resource::MX(MX::parse(&mut record)?),
            Type::TXT => Resource::TXT(TXT::parse(&mut record)?),
            Type::SPF => Resource::SPF(TXT::parse(&mut record)?),
            Type::SRV => Resource::SRV(SRV::parse(&mut record)?),
            Type::DS => Resource::DS(DS::parse(&mut record)?),
            Type::DNSKEY => Resource::DNSKEY(DNSKEY::parse(&mut record)?),
            Type::RRSIG => Resource::RRSIG(RRSIG::parse(&mut record)?),
            Type::NSEC => Resource::NSEC(NSEC::parse(&mut record)?),
            Type::ZONEMD => Resource::ZONEMD(ZONEMD::parse(&mut record)?),

            // This should never appear in a answer record unless we have invalid data.
            Type::Reserved | Type::OPT | Type::ANY => {
                // TODO This could be a warning, instead of a full error.
                return Err(DecodeError::UnexpectedType(r#type));
            }
        };

        let remaining = record.remaining()?;
        if remaining > 0 {
            return Err(DecodeError::TrailingBytes { count: remaining });
        }

        // Now catch up (this is safe since record.len() < cur.len())
        cur.set_position(record.position());

        Ok(Record {
            name,
            class,
            ttl: Duration::from_secs(ttl.into()),
            resource,
        })
    }
}

/// Mail EXchanger (MX) record specifies the mail server responsible
/// for accepting email messages on behalf of a domain name.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct MX {
    /// The preference given to this RR among others at the same owner.
    /// Lower values are preferred.
    pub preference: u16,

    /// A host willing to act as a mail exchange for the owner name.
    pub exchange: String,
}

/// Start of Authority (SOA) record containing administrative information
/// about the zone. See [rfc1035].
///
/// [rfc1035]: https://datatracker.ietf.org/doc/html/rfc1035
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SOA {
    /// The name server that was the original or primary source of data for this zone.
    pub mname: String,

    /// The mailbox domain name of the person responsible for this zone,
    /// e.g. "dns-admin.google.com.". This is an encoded email address "dns-admin@google.com".
    /// Use [`SOA::email`] or [`SOA::rname_to_email`] to convert to an email address, or [`SOA::email_to_rname`] to construct
    /// an `rname` from an email address.
    pub rname: String,

    pub serial: u32,

    pub refresh: Duration,
    pub retry: Duration,
    pub expire: Duration,
    pub minimum: Duration,
}

/// Service (SRV) record, containg hostname and port number information of specified services. See [rfc2782].
///
/// [rfc2782]: <https://datatracker.ietf.org/doc/html/rfc2782>
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SRV {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub name: String,
}

/// Delegation Signer (DS) record. See [RFC 4034 §5].
///
/// [RFC 4034 §5]: https://datatracker.ietf.org/doc/html/rfc4034#section-5
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct DS {
    /// The Key Tag of the DNSKEY RR referred to by the DS RR.
    pub key_tag: u16,

    /// The algorithm number of the DNSKEY RR referred to by the DS RR.
    pub algorithm: u8,

    /// The digest type used to calculate the digest.
    pub digest_type: u8,

    /// The cryptographic digest of the DNSKEY RR.
    pub digest: Vec<u8>,
}

impl DS {
    pub(crate) fn append_rdata_to_vec(&self, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        buf.extend_from_slice(&self.key_tag.to_be_bytes());
        buf.push(self.algorithm);
        buf.push(self.digest_type);
        buf.extend_from_slice(&self.digest);
        Ok(())
    }

    pub(crate) fn parse(cur: &mut Cursor<&[u8]>) -> Result<DS, DecodeError> {
        let key_tag = cur.read_u16::<BE>()?;
        let algorithm = cur.read_u8()?;
        let digest_type = cur.read_u8()?;
        let mut digest = Vec::new();
        cur.read_to_end(&mut digest)?;
        Ok(DS {
            key_tag,
            algorithm,
            digest_type,
            digest,
        })
    }
}

/// DNS Key (DNSKEY) record. See [RFC 4034 §2].
///
/// [RFC 4034 §2]: https://datatracker.ietf.org/doc/html/rfc4034#section-2
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct DNSKEY {
    /// Bit flags (e.g. 256 for ZSK, 257 for KSK).
    pub flags: u16,

    /// Protocol field, must be 3.
    pub protocol: u8,

    /// Algorithm number of the public key.
    pub algorithm: u8,

    /// Public key data.
    pub public_key: Vec<u8>,
}

impl DNSKEY {
    pub(crate) fn append_rdata_to_vec(&self, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.push(self.protocol);
        buf.push(self.algorithm);
        buf.extend_from_slice(&self.public_key);
        Ok(())
    }

    pub(crate) fn parse(cur: &mut Cursor<&[u8]>) -> Result<DNSKEY, DecodeError> {
        let flags = cur.read_u16::<BE>()?;
        let protocol = cur.read_u8()?;
        let algorithm = cur.read_u8()?;
        let mut public_key = Vec::new();
        cur.read_to_end(&mut public_key)?;
        Ok(DNSKEY {
            flags,
            protocol,
            algorithm,
            public_key,
        })
    }
}

/// DNSSEC Signature (RRSIG) record. See [RFC 4034 §3].
///
/// [RFC 4034 §3]: https://datatracker.ietf.org/doc/html/rfc4034#section-3
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct RRSIG {
    /// The RR type covered by this signature.
    pub type_covered: Type,

    /// The cryptographic algorithm used to create the signature.
    pub algorithm: u8,

    /// The number of labels in the original RRSIG RR owner name.
    pub labels: u8,

    /// The original TTL of the covered RRset.
    pub original_ttl: u32,

    /// Signature expiration time (seconds since UNIX epoch).
    pub expiration: u32,

    /// Signature inception time (seconds since UNIX epoch).
    pub inception: u32,

    /// The key tag of the DNSKEY RR that validates this signature.
    pub key_tag: u16,

    /// The domain name of the signer generating the signature.
    pub signer_name: String,

    /// The cryptographic signature.
    pub signature: Vec<u8>,
}

impl RRSIG {
    pub(crate) fn append_rdata_to_vec(&self, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        buf.extend_from_slice(&(self.type_covered as u16).to_be_bytes());
        buf.push(self.algorithm);
        buf.push(self.labels);
        buf.extend_from_slice(&self.original_ttl.to_be_bytes());
        buf.extend_from_slice(&self.expiration.to_be_bytes());
        buf.extend_from_slice(&self.inception.to_be_bytes());
        buf.extend_from_slice(&self.key_tag.to_be_bytes());
        Message::append_qname_to_vec(buf, &self.signer_name)?;
        buf.extend_from_slice(&self.signature);
        Ok(())
    }

    pub(crate) fn parse(cur: &mut Cursor<&[u8]>) -> Result<RRSIG, DecodeError> {
        let type_code = cur.read_u16::<BE>()?;
        let type_covered = num_traits::FromPrimitive::from_u16(type_code).unwrap_or(Type::Reserved);
        let algorithm = cur.read_u8()?;
        let labels = cur.read_u8()?;
        let original_ttl = cur.read_u32::<BE>()?;
        let expiration = cur.read_u32::<BE>()?;
        let inception = cur.read_u32::<BE>()?;
        let key_tag = cur.read_u16::<BE>()?;
        let signer_name = cur.read_qname()?;
        let mut signature = Vec::new();
        cur.read_to_end(&mut signature)?;
        Ok(RRSIG {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name,
            signature,
        })
    }
}

/// Next Secure (NSEC) record. See [RFC 4034 §4].
///
/// [RFC 4034 §4]: https://datatracker.ietf.org/doc/html/rfc4034#section-4
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct NSEC {
    /// The next owner name in canonical order.
    pub next_domain: String,

    /// The RR types that exist at the owner name.
    pub types: Vec<Type>,
}

impl NSEC {
    pub(crate) fn append_rdata_to_vec(&self, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        Message::append_qname_to_vec(buf, &self.next_domain)?;
        Self::encode_type_bit_maps(&self.types, buf);
        Ok(())
    }

    /// Encodes a list of DNS record types into the windowed Type Bit Maps wire format
    /// defined in [RFC 4034 §4.1.2].
    ///
    /// The 16-bit type space (0–65535) is partitioned into up to 256 window blocks of 256 types
    /// each. For each window containing at least one present type, this emits:
    /// - 1 octet window block number (`window = type / 256`)
    /// - 1 octet bitmap length (1 to 32 octets, truncated after the highest set bit in the window)
    /// - 1 to 32 octets of bitmap data where bit `i` (left-to-right, MSB to LSB) represents
    ///   the presence of type `window * 256 + i`
    ///
    /// [RFC 4034 §4.1.2]: https://datatracker.ietf.org/doc/html/rfc4034#section-4.1.2
    pub(crate) fn encode_type_bit_maps(types: &[Type], buf: &mut Vec<u8>) {
        if types.is_empty() {
            return;
        }
        let mut codes: Vec<u16> = types.iter().map(|t| *t as u16).collect();
        codes.sort_unstable();
        codes.dedup();

        let mut cur_window: Option<u8> = None;
        let mut bitmap = [0_u8; 32];
        let mut max_byte_idx = 0;

        for code in codes {
            let window = (code / 256) as u8;
            let bit_offset = (code % 256) as usize;
            let byte_idx = bit_offset / 8;
            let bit_idx = 7 - (bit_offset % 8);

            if Some(window) != cur_window {
                if let Some(w) = cur_window {
                    let len = max_byte_idx + 1;
                    buf.push(w);
                    buf.push(len as u8);
                    buf.extend_from_slice(&bitmap[..len]);
                }
                cur_window = Some(window);
                bitmap = [0_u8; 32];
                max_byte_idx = 0;
            }

            bitmap[byte_idx] |= 1 << bit_idx;
            if byte_idx > max_byte_idx {
                max_byte_idx = byte_idx;
            }
        }

        if let Some(w) = cur_window {
            let len = max_byte_idx + 1;
            buf.push(w);
            buf.push(len as u8);
            buf.extend_from_slice(&bitmap[..len]);
        }
    }

    /// Decodes DNS record types from the windowed Type Bit Maps wire format per [RFC 4034 §4.1.2].
    ///
    /// Parses consecutive window blocks until the end of the RDATA cursor is reached:
    /// - 1 octet window block number
    /// - 1 octet bitmap length (must be between 1 and 32 octets)
    /// - Bitmap octets where each set bit corresponds to `(window << 8) | (byte_index * 8 + bit_index)`
    ///
    /// Any unassigned or unrecognized type codes that do not map to known [`Type`] variants
    /// are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] if a window block or its bitmap is truncated,
    /// or if the bitmap length byte is invalid (`0` or greater than `32`).
    ///
    /// [RFC 4034 §4.1.2]: https://datatracker.ietf.org/doc/html/rfc4034#section-4.1.2
    pub(crate) fn decode_type_bit_maps(cur: &mut Cursor<&[u8]>) -> Result<Vec<Type>, DecodeError> {
        let mut types = Vec::new();
        while cur.remaining()? > 0 {
            let window = cur.read_u8()?;
            let len = cur.read_u8()? as usize;
            if len == 0 || len > 32 {
                return Err(DecodeError::UnexpectedEof);
            }
            if cur.remaining()? < len as u64 {
                return Err(DecodeError::UnexpectedEof);
            }
            let mut bitmap = vec![0_u8; len];
            cur.read_exact(&mut bitmap)?;

            for (byte_idx, &byte) in bitmap.iter().enumerate() {
                for bit_idx in 0..8 {
                    if (byte >> (7 - bit_idx)) & 1 == 1 {
                        let type_code =
                            (u16::from(window) << 8) | ((byte_idx as u16) * 8 + bit_idx as u16);
                        if let Some(t) = num_traits::FromPrimitive::from_u16(type_code) {
                            types.push(t);
                        }
                    }
                }
            }
        }
        Ok(types)
    }

    pub(crate) fn parse(cur: &mut Cursor<&[u8]>) -> Result<NSEC, DecodeError> {
        let next_domain = cur.read_qname()?;
        let types = Self::decode_type_bit_maps(cur)?;
        Ok(NSEC { next_domain, types })
    }
}

/// Message Digest for DNS Zones (ZONEMD) record. See [RFC 8976].
///
/// [RFC 8976]: https://datatracker.ietf.org/doc/html/rfc8976
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ZONEMD {
    /// The SOA serial number of the zone at the time the digest was generated.
    pub serial: u32,

    /// The verification scheme (e.g. 1 for simple).
    pub scheme: u8,

    /// The cryptographic hash algorithm.
    pub algorithm: u8,

    /// The zone message digest.
    pub digest: Vec<u8>,
}

impl ZONEMD {
    pub(crate) fn append_rdata_to_vec(&self, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        buf.extend_from_slice(&self.serial.to_be_bytes());
        buf.push(self.scheme);
        buf.push(self.algorithm);
        buf.extend_from_slice(&self.digest);
        Ok(())
    }

    pub(crate) fn parse(cur: &mut Cursor<&[u8]>) -> Result<ZONEMD, DecodeError> {
        let serial = cur.read_u32::<BE>()?;
        let scheme = cur.read_u8()?;
        let algorithm = cur.read_u8()?;
        let mut digest = Vec::new();
        cur.read_to_end(&mut digest)?;
        Ok(ZONEMD {
            serial,
            scheme,
            algorithm,
            digest,
        })
    }
}

fn parse_a(cur: &mut Cursor<&[u8]>, class: Class) -> Result<A, DecodeError> {
    let mut buf = [0_u8; 4];
    cur.read_exact(&mut buf)?;

    match class {
        Class::Internet => Ok(A::new(buf[0], buf[1], buf[2], buf[3])),

        _ => Err(DecodeError::UnsupportedClass {
            record_type: Type::A,
            class,
        }),
    }
}

fn parse_aaaa(cur: &mut Cursor<&[u8]>, class: Class) -> Result<AAAA, DecodeError> {
    let mut buf = [0_u8; 16];
    cur.read_exact(&mut buf)?;

    match class {
        Class::Internet => Ok(AAAA::from(buf)),

        _ => Err(DecodeError::UnsupportedClass {
            record_type: Type::AAAA,
            class,
        }),
    }
}

impl TXT {
    fn parse(cur: &mut Cursor<&[u8]>) -> Result<TXT, DecodeError> {
        let mut txts = Vec::new();

        loop {
            // Keep reading until EOF is reached.
            let len = match cur.read_u8() {
                Ok(len) => len,
                Err(e) => match e.kind() {
                    io::ErrorKind::UnexpectedEof => break,
                    _ => return Err(e.into()),
                },
            };

            let mut txt = vec![0; len.into()];
            cur.read_exact(&mut txt)?;
            txts.push(txt)
        }

        Ok(TXT(txts))
    }

    pub(crate) fn append_rdata_to_vec(&self, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        for value in &self.0 {
            let length = u8::try_from(value.len()).map_err(|_| EncodeError::TxtStringTooLong {
                max: usize::from(u8::MAX),
            })?;
            buf.push(length);
            buf.extend_from_slice(value);
        }
        Ok(())
    }
}

impl SOA {
    pub(crate) fn parse(cur: &mut Cursor<&[u8]>) -> Result<SOA, DecodeError> {
        let mname = cur.read_qname()?;
        let rname = cur.read_qname()?;

        let serial = cur.read_u32::<BE>()?;
        let refresh = cur.read_u32::<BE>()?;
        let retry = cur.read_u32::<BE>()?;
        let expire = cur.read_u32::<BE>()?;
        let minimum = cur.read_u32::<BE>()?;

        Ok(SOA {
            mname,
            rname,

            serial,
            refresh: Duration::from_secs(refresh.into()),
            retry: Duration::from_secs(retry.into()),
            expire: Duration::from_secs(expire.into()),
            minimum: Duration::from_secs(minimum.into()),
        })
    }

    pub(crate) fn append_rdata_to_vec(&self, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        Message::append_qname_to_vec(buf, &self.mname)?;
        Message::append_qname_to_vec(buf, &self.rname)?;

        let duration_to_u32 = |duration: Duration| {
            u32::try_from(duration.as_secs()).map_err(|_| EncodeError::DurationTooLong {
                max: u64::from(u32::MAX),
            })
        };
        for value in [
            self.serial,
            duration_to_u32(self.refresh)?,
            duration_to_u32(self.retry)?,
            duration_to_u32(self.expire)?,
            duration_to_u32(self.minimum)?,
        ] {
            buf.extend_from_slice(&value.to_be_bytes());
        }
        Ok(())
    }

    /// Converts the `rname` domain name to an email address per RFC 1035 §8.
    ///
    /// For example, `"dns-admin.google.com."` becomes `"dns-admin@google.com."`.
    ///
    /// # Errors
    ///
    /// Returns [`FromStrError::InvalidRname`] if `rname` does not contain an
    /// unescaped dot separating the mailbox local-part from the domain.
    pub fn email(&self) -> Result<String, FromStrError> {
        Self::rname_to_email(&self.rname)
    }

    /// Converts rnames to email address, for example, "admin.example.com" is
    /// converted to "admin@example.com", per the rules in
    /// <https://datatracker.ietf.org/doc/html/rfc1035#section-8>
    pub fn rname_to_email(domain: &str) -> Result<String, FromStrError> {
        // Find the first unescaped dot and replace with '@'.
        // RFC 1035 §8: only '\.' is an escaped dot in the mailbox local-part.
        let mut result = String::with_capacity(domain.len());
        let mut chars = domain.chars().peekable();
        let mut done = false;

        while let Some(c) = chars.next() {
            if c == '\\' && chars.peek() == Some(&'.') {
                // '\.' escapes a dot: emit literal '.' without treating it as the '@' delimiter.
                chars.next();
                result.push('.');
            } else if c == '.' && !done {
                result.push('@');
                done = true;
            } else {
                result.push(c);
            }
        }

        if !done || result.starts_with('@') || result.ends_with('@') {
            return Err(FromStrError::InvalidRname {
                rname: domain.to_string(),
                reason: "missing unescaped dot separating mailbox and domain",
            });
        }

        Ok(result)
    }

    pub fn email_to_rname(email: &str) -> Result<String, FromStrError> {
        match email.split_once('@') {
            None => Err(FromStrError::InvalidRname {
                rname: email.to_string(),
                reason: "missing '@' separator",
            }),
            Some((left, right)) if left.is_empty() || right.is_empty() => {
                Err(FromStrError::InvalidRname {
                    rname: email.to_string(),
                    reason: "empty mailbox or domain in email address",
                })
            }

            // RFC 1035 §8: escape all the dots to the left of the '@',
            // and replace the '@' with a '.'.
            Some((left, right)) => Ok(left.replace('.', "\\.") + "." + right),
        }
    }
}

impl MX {
    pub(crate) fn parse(cur: &mut Cursor<&[u8]>) -> Result<MX, DecodeError> {
        let preference = cur.read_u16::<BE>()?;
        let exchange = cur.read_qname()?;

        Ok(MX {
            preference,
            exchange,
        })
    }

    pub(crate) fn append_rdata_to_vec(&self, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        buf.extend_from_slice(&self.preference.to_be_bytes());
        Message::append_qname_to_vec(buf, &self.exchange)
    }
}

impl SRV {
    pub(crate) fn parse(cur: &mut Cursor<&[u8]>) -> Result<SRV, DecodeError> {
        let priority = cur.read_u16::<BE>()?;
        let weight = cur.read_u16::<BE>()?;
        let port = cur.read_u16::<BE>()?;

        let name = cur.read_qname()?;

        Ok(SRV {
            priority,
            weight,
            port,
            name,
        })
    }

    pub(crate) fn append_rdata_to_vec(&self, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        buf.extend_from_slice(&self.priority.to_be_bytes());
        buf.extend_from_slice(&self.weight.to_be_bytes());
        buf.extend_from_slice(&self.port.to_be_bytes());
        Message::append_qname_to_vec(buf, &self.name)
    }
}

impl From<&str> for TXT {
    fn from(txt: &str) -> TXT {
        TXT(vec![txt.as_bytes().to_vec()])
    }
}

impl From<&[&str]> for TXT {
    fn from(txts: &[&str]) -> TXT {
        TXT(txts.iter().map(|row| row.as_bytes().to_vec()).collect())
    }
}

#[cfg(test)]
mod tests {
    use crate::SOA;
    use pretty_assertions::assert_eq;
    use std::io::Cursor;
    use std::time::Duration;

    static RNAME_TESTS: &[(&str, &str)] = &[
        ("username.example.com", "username@example.com"),
        ("root.localhost", "root@localhost"),
        ("Action\\.domains.ISI.EDU", "Action.domains@ISI.EDU"),
        ("a\\.b\\.c.ISI.EDU", "a.b.c@ISI.EDU"),
        // Edge cases found by fuzzing:
        ("\\..example.com", ".@example.com"),
        ("\\0.example.com", "\\0@example.com"), // 0 should not be unescaped.
    ];

    #[test]
    fn test_soa_rname_to_email() {
        for (domain, email) in RNAME_TESTS {
            match SOA::rname_to_email(domain) {
                Ok(got) => assert_eq!(got, *email, "incorrect result for '{}'", domain),
                Err(err) => panic!("'{}' Failed:\n{:?}", domain, err),
            }
        }
    }

    #[test]
    fn test_soa_rname_from_email() {
        for (domain, email) in RNAME_TESTS {
            match SOA::email_to_rname(email) {
                Ok(got) => assert_eq!(got, *domain, "incorrect result for '{}'", email),
                Err(err) => panic!("'{}' Failed:\n{:?}", email, err),
            }
        }
    }

    #[test]
    fn test_soa_rname_roundtrip() {
        for (domain, email) in RNAME_TESTS {
            let got_email = SOA::rname_to_email(domain).expect("rname_to_email failed");
            assert_eq!(&got_email, email);
            let got_rname = SOA::email_to_rname(&got_email).expect("email_to_rname failed");
            assert_eq!(&got_rname, domain, "round-trip mismatch for '{}'", domain);
        }
    }

    #[test]
    fn invalid_soa_email_returns_error() {
        let input = [
            2, b'n', b's', 0, // mname: "ns."
            5, b'n', b'o', b't', b'a', b'n',
            0, // rname: "notan." (no dot to separate mailbox and domain)
            0, 0, 0, 1, // serial
            0, 0, 0, 1, // refresh
            0, 0, 0, 1, // retry
            0, 0, 0, 1, // expire
            0, 0, 0, 1, // minimum
        ];

        let soa = SOA::parse(&mut Cursor::new(&input)).expect("wire parsing should succeed");
        assert_eq!(soa.rname, "notan.");
        assert!(soa.email().is_err());
    }

    #[test]
    fn test_soa_email_and_email_to_rname() {
        let mut soa = SOA {
            mname: "ns1.example.com.".to_string(),
            rname: "root.localhost.".to_string(),
            serial: 1,
            refresh: Duration::from_secs(3600),
            retry: Duration::from_secs(600),
            expire: Duration::from_secs(86400),
            minimum: Duration::from_secs(300),
        };

        soa.rname = SOA::email_to_rname("admin@example.com").expect("email_to_rname failed");
        assert_eq!(soa.rname, "admin.example.com");
        assert_eq!(soa.email().unwrap(), "admin@example.com");

        soa.rname = SOA::email_to_rname("Action.domains@ISI.EDU").expect("email_to_rname failed");
        assert_eq!(soa.rname, "Action\\.domains.ISI.EDU");
        assert_eq!(soa.email().unwrap(), "Action.domains@ISI.EDU");

        assert!(SOA::email_to_rname("invalid_no_at").is_err());
    }
}
