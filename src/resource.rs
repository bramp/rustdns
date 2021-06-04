use crate::as_array;
use crate::dns::read_qname;
use crate::errors::{ParseError, WriteError};
use crate::parse_error;
use crate::types::*;
use std::convert::TryInto;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

// TODO Consider moving Mx, SOA, and SRV to types.rs

impl Record {
    pub fn from_slice(
        name: String,
        r#type: QType,
        class: QClass,
        buf: &[u8],
        start: usize,
    ) -> Result<(Record, usize), ParseError> {
        let mut offset = start;

        let ttl = u32::from_be_bytes(*as_array![buf, offset, 4]);
        offset += 4;

        let len = u16::from_be_bytes(*as_array![buf, offset, 2]) as usize;
        offset += 2;

        if buf.len() < offset + len {
            return parse_error!("record too short");
        }

        let resource = match r#type {
            QType::A => Resource::A(parse_a(class, &buf[offset..offset + len])?),
            QType::NS => Resource::NS(parse_qname(buf, offset, len)?),
            QType::SOA => Resource::SOA(Soa::from_slice(buf, offset, len)?),
            QType::CNAME => Resource::CNAME(parse_qname(buf, offset, len)?),
            QType::PTR => Resource::PTR(parse_qname(buf, offset, len)?),
            QType::MX => Resource::MX(Mx::from_slice(buf, offset, len)?),
            QType::TXT => Resource::TXT(parse_txt(&buf[offset..offset + len])?),
            QType::AAAA => Resource::AAAA(parse_aaaa(class, &buf[offset..offset + len])?),
            QType::SRV => Resource::SRV(Srv::from_slice(buf, offset, len)?),

            // This should never appear in a answer record unless we have invalid data.
            QType::Reserved | QType::OPT | QType::ANY => {
                return parse_error!("invalid record type '{}'", r#type)
            }
        };

        let answer = Record {
            name,

            r#type,
            class,

            ttl: Duration::from_secs(ttl.into()),

            resource,
        };

        Ok((answer, 4 + 2 + len))
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Resource::A(ip) => ip.fmt(f),
            Resource::AAAA(ip) => ip.fmt(f),

            Resource::NS(name) => name.fmt(f),
            Resource::CNAME(name) => name.fmt(f),
            Resource::PTR(name) => name.fmt(f),

            Resource::SOA(soa) => soa.fmt(f),
            Resource::TXT(txts) => write!(f, "\"{}\"", txts.join(" ")), // TODO I'm not sure the right way to display this
            Resource::MX(mx) => mx.fmt(f),
            Resource::SRV(srv) => srv.fmt(f),

            Resource::OPT => write!(f, "OPT"),

            Resource::TODO => write!(f, "TODO"),
            Resource::ANY => write!(f, "*"),
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

        _ => return parse_error!("unsupported A record class '{}'", class),
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

impl Soa {
    pub fn from_slice(buf: &[u8], start: usize, len: usize) -> Result<Soa, ParseError> {
        let mut offset = start;

        let (mname, size) = read_qname(&buf, offset)?;
        offset += size;

        let (rname, size) = read_qname(&buf, offset)?;
        offset += size;

        let serial = u32::from_be_bytes(*as_array![buf, offset, 4]);
        offset += 4;

        let refresh = u32::from_be_bytes(*as_array![buf, offset, 4]);
        offset += 4;

        let retry = u32::from_be_bytes(*as_array![buf, offset, 4]);
        offset += 4;

        let expire = u32::from_be_bytes(*as_array![buf, offset, 4]);
        offset += 4;

        let minimum = u32::from_be_bytes(*as_array![buf, offset, 4]);
        offset += 4;

        if offset - start != len {
            return parse_error!("failed to parse full SOA record");
        }

        Ok(Soa {
            mname,
            rname,

            serial,
            refresh: Duration::from_secs(refresh.into()),
            retry: Duration::from_secs(retry.into()),
            expire: Duration::from_secs(expire.into()),
            minimum: Duration::from_secs(minimum.into()),
        })
    }
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

impl Srv {
    pub fn from_slice(buf: &[u8], start: usize, len: usize) -> Result<Srv, ParseError> {
        if len < 7 {
            return parse_error!("SRV record too short");
        }

        let priority = u16::from_be_bytes(*as_array![buf, start, 2]);
        let weight = u16::from_be_bytes(*as_array![buf, start + 2, 2]);
        let port = u16::from_be_bytes(*as_array![buf, start + 4, 2]);

        let (name, size) = read_qname(buf, start + 6)?;

        if len != 6 + size {
            // TODO Standardise his kind of error.
            return parse_error!("failed to read full SRV record");
        }

        Ok(Srv {
            priority,
            weight,
            port,
            name,
        })
    }
}

impl Extension {
    pub fn from_slice(
        domain: String,
        r#type: QType,
        buf: &[u8],
        start: usize,
    ) -> Result<(Extension, usize), ParseError> {
        assert!(r#type == QType::OPT);

        if domain != "." {
            return parse_error!(
                "expected root domain for EDNS(0) extension, got '{}'",
                domain
            );
        }

        let mut offset = start;

        let payload_size = u16::from_be_bytes(*as_array![buf, offset, 2]);
        offset += 2;

        let extend_rcode = buf[offset];
        offset += 1;

        let version = buf[offset];
        offset += 1;

        let b = buf[offset];
        offset += 1;

        let _z = buf[offset];
        offset += 1;

        let _rd_len = u16::from_be_bytes(*as_array![buf, offset, 2]);
        offset += 2;

        Ok((
            Extension {
                payload_size,
                extend_rcode,
                version,
                dnssec_ok: b & 0b1000_0000 == 0b1000_0000,
            },
            offset - start,
        ))
    }

    pub fn write(&self, buf: &mut Vec<u8>) -> Result<(), WriteError> {
        buf.push(0); // A single "." domain name         // 0-1
        buf.extend_from_slice(&(QType::OPT as u16).to_be_bytes()); // 1-3
        buf.extend_from_slice(&(self.payload_size as u16).to_be_bytes()); // 3-5

        buf.push(self.extend_rcode); // 5-6
        buf.push(self.version); // 6-7

        let mut b = 0_u8;
        b |= if self.dnssec_ok { 0b1000_0000 } else { 0 };

        // 16 bits
        buf.push(b);
        buf.push(0);

        // 16 bit RDLEN - TODO
        buf.push(0);
        buf.push(0);

        Ok(())
    }
}
