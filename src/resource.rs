use crate::as_array;
use crate::dns::read_qname;
use crate::errors::ParseError;
use crate::parse_error;
use crate::types::{BeB16, BeB32};

use crate::types::{QClass, QType};
use modular_bitfield::prelude::*;
use std::convert::TryInto;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

// This should be kept in sync with QType.
// TODO Can we merge this and QType? (when https://github.com/rust-lang/rust/issues/60553 is finished we can)
#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
pub enum Record {
    A(Ipv4Addr), // TODO Is this always a IpAddress for non-Internet classes?
    AAAA(Ipv6Addr),

    // QNames
    CNAME(String),
    NS(String),
    PTR(String),

    // TODO Implement RFC 1464 for further parsing of the text
    TXT(Vec<String>),

    MX(Mx),
    SOA(Soa),
    SRV(Srv),

    ANY,  // Not a valid Record Type, but is a QType
    TODO, // TODO Remove this placeholder. Figure out how to hide this type.
}

impl Record {
    pub fn from_slice(
        r#type: QType,
        class: QClass,
        buf: &[u8],
        start: usize,
        len: usize,
    ) -> Result<Record, ParseError> {
        if buf.len() < start + len {
            return parse_error!("invalid record length");
        }

        match r#type {
            QType::A => Ok(Record::A(parse_a(class, &buf[start..start + len])?)),
            QType::NS => Ok(Record::NS(parse_qname(buf, start, len)?)),
            QType::SOA => Ok(Record::SOA(Soa::from_slice(buf, start, len)?)),
            QType::CNAME => Ok(Record::CNAME(parse_qname(buf, start, len)?)),
            QType::PTR => Ok(Record::PTR(parse_qname(buf, start, len)?)),
            QType::MX => Ok(Record::MX(Mx::from_slice(buf, start, len)?)),
            QType::TXT => Ok(Record::TXT(parse_txt(&buf[start..start + len])?)),
            QType::AAAA => Ok(Record::AAAA(parse_aaaa(class, &buf[start..start + len])?)),
            QType::SRV => Ok(Record::SRV(Srv::from_slice(buf, start, len)?)),
            QType::ANY => Ok(Record::ANY), // This should never happen unless we have invalid data.
        }
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Record::A(ip) => ip.fmt(f),
            Record::AAAA(ip) => ip.fmt(f),

            Record::NS(name) => name.fmt(f),
            Record::CNAME(name) => name.fmt(f),
            Record::PTR(name) => name.fmt(f),

            Record::SOA(soa) => soa.fmt(f),
            Record::TXT(txts) => write!(f, "\"{}\"", txts.join(" ")), // TODO I'm not sure the right way to display this
            Record::MX(mx) => mx.fmt(f),
            Record::SRV(srv) => srv.fmt(f),

            Record::TODO => write!(f, "TODO"),
            Record::ANY => write!(f, "*"),
        }
    }
}

fn parse_a(class: QClass, buf: &[u8]) -> Result<Ipv4Addr, ParseError> {
    match class {
        QClass::Internet => {
            if buf.len() != 4 {
                return parse_error!("invalid A record length ({}) expected 4", buf.len());
            }
            Ok(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]))
        }

        _ => return parse_error!("unsupported A record class '{}'", class),
    }
}

fn parse_aaaa(class: QClass, buf: &[u8]) -> Result<Ipv6Addr, ParseError> {
    match class {
        QClass::Internet => {
            if buf.len() != 16 {
                return parse_error!("invalid AAAA record length ({}) expected 16", buf.len());
            }
            let ip: [u8; 16] = buf.try_into().expect("record length is not 16 bytes");
            Ok(Ipv6Addr::from(ip))
        }

        _ => return parse_error!("unsupported A record class '{:?}'", class),
    }
}

fn parse_qname(buf: &[u8], start: usize, len: usize) -> Result<String, ParseError> {
    let (qname, size) = read_qname(&buf, start)?;
    if len != size {
        return parse_error!(
            "qname length ({}) did not match expected record len ({})",
            size,
            len
        );
    }
    Ok(qname)
}

fn parse_txt(buf: &[u8]) -> Result<Vec<String>, ParseError> {
    let mut txts = Vec::new();
    let mut offset = 0;

    while let Some(len) = buf.get(offset) {
        let len = *len as usize;
        offset += 1;

        match buf.get(offset..offset + len) {
            None => return parse_error!("TXT record too short"), // TODO standardise the too short error
            Some(txt) => {
                // This string doesn't strictly need to be UTF-8, but I'm assuming it is.
                // TODO maybe change this to just be byte arrays, and let the reader decide the encoding.
                match String::from_utf8(txt.to_vec()) {
                    Ok(s) => txts.push(s),
                    Err(e) => return parse_error!("unable to parse TXT: {}", e),
                }
            }
        }

        offset += len;
    }

    Ok(txts)
}

#[derive(Debug)]
pub struct Soa {
    pub mname: String, // The <domain-name> of the name server that was the original or primary source of data for this zone.
    pub rname: String, // A <domain-name> which specifies the mailbox of the person responsible for this zone.

    pub header: SoaHeader, // TODO Somehow hoist this up, so it's methods are on Soa directly, and header is private.
}

impl Soa {
    pub fn from_slice(buf: &[u8], start: usize, _len: usize) -> Result<Soa, ParseError> {
        let mut offset = start;

        let (mname, size) = read_qname(&buf, offset)?;
        offset += size;

        let (rname, size) = read_qname(&buf, offset)?;
        offset += size;

        // TODO How do we catch errors if from_bytes fails?
        let header = SoaHeader::from_bytes(*as_array![buf, offset, 20]);

        Ok(Soa {
            mname,
            rname,
            header,
        })
    }
}

#[bitfield(bits = 160)]
#[derive(Debug)]
pub struct SoaHeader {
    serial: BeB32,
    refresh: BeB32, // in seconds
    retry: BeB32,   // in seconds
    expire: BeB32,  // in seconds
    minimum: BeB32, // in seconds
}

impl fmt::Display for Soa {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // "ns1.google.com. dns-admin.google.com. 376337657 900 900 1800 60"
        write!(
            f,
            "{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}",
            mname = self.mname,
            rname = self.rname,
            serial = self.header.serial(),
            refresh = self.header.refresh(),
            retry = self.header.retry(),
            expire = self.header.expire(),
            minimum = self.header.minimum(),
        )
    }
}

#[derive(Debug)]
pub struct Mx {
    pub preference: u16, // A 16 bit integer which specifies the preference given to this RR among others at the same owner.  Lower values                are preferred.
    pub exchange: String, // A <domain-name> which specifies a host willing to act as a mail exchange for the owner name.
}

impl Mx {
    pub fn from_slice(buf: &[u8], start: usize, len: usize) -> Result<Mx, ParseError> {
        let preference = u16::from_be_bytes(*as_array![buf, 0, 2]);
        let (exchange, size) = read_qname(buf, start + 2)?;

        if len != 2 + size {
            // TODO Standardise his kind of error.
            return parse_error!("failed to read full MX record");
        }

        Ok(Mx {
            preference,
            exchange,
        })
    }
}

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

// https://datatracker.ietf.org/doc/html/rfc2782
#[derive(Debug)]
pub struct Srv {
    pub header: SrvHeader,
    pub name: String,
}

#[bitfield(bits = 48)]
#[derive(Debug)]
pub struct SrvHeader {
    pub priority: BeB16,
    pub weight: BeB16,
    pub port: BeB16,
}

impl Srv {
    pub fn from_slice(buf: &[u8], start: usize, len: usize) -> Result<Srv, ParseError> {
        if len < 7 {
            return parse_error!("SRV record too short");
        }

        let header = SrvHeader::from_bytes(*as_array![buf, start, 6]);
        let (name, size) = read_qname(buf, start + 6)?;

        if len != 6 + size {
            // TODO Standardise his kind of error.
            return parse_error!("failed to read full SRV record");
        }

        Ok(Srv { header, name })
    }
}

impl fmt::Display for Srv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // "5 0 389 ldap.google.com."
        write!(
            f,
            "{priority} {weight} {port} {name}",
            priority = self.header.priority(),
            weight = self.header.weight(),
            port = self.header.port(),
            name = self.name,
        )
    }
}
