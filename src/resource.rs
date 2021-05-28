use crate::dns::read_qname;
use crate::dns::ParseError;
use crate::parse_error;
use crate::types::{QClass, QType};
use std::net::{Ipv4Addr, Ipv6Addr};

use std::fmt;

#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
pub enum Record {
    A(Ipv4Addr), // TODO Is this always a IpAddress for non-Internet classes?
    CNAME(String),
    AAAA(Ipv6Addr),

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
        let f = match r#type {
            QType::A => parse_a,
            QType::NS => todo,
            QType::SOA => todo,
            QType::CNAME => parse_cname,

            QType::ANY => any, // This should never happen unless we have invalid data.
        };

        // Call the appropriate parser function.
        f(class, buf, start, len)
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Record::A(ip) => ip.fmt(f),
            Record::AAAA(ip) => ip.fmt(f),
            //Record::NS => write!(f, "todo"),
            //Record::SOA => write!(f, "todo"),
            Record::CNAME(name) => name.fmt(f),

            Record::TODO => write!(f, "TODO"),
            Record::ANY => write!(f, "*"),
        }
    }
}

fn todo(_class: QClass, _buf: &[u8], _start: usize, _len: usize) -> Result<Record, ParseError> {
    Ok(Record::TODO)
}

fn any(_class: QClass, _buf: &[u8], _start: usize, _len: usize) -> Result<Record, ParseError> {
    Ok(Record::ANY)
}

fn parse_a(class: QClass, buf: &[u8], start: usize, len: usize) -> Result<Record, ParseError> {
    match class {
        QClass::Internet => {
            if len != 4 {
                return parse_error!("invalid A record length ({}) expected 4", len);
            }
            Ok(Record::A(Ipv4Addr::new(
                buf[start],
                buf[start + 1],
                buf[start + 2],
                buf[start + 3],
            )))
        }

        _ => return parse_error!("unsupported A record class '{:?}'", class),
    }
}

fn parse_cname(_class: QClass, buf: &[u8], start: usize, len: usize) -> Result<Record, ParseError> {
    let (qname, size) = read_qname(&buf, start)?;
    if len != size {
        return parse_error!(
            "qname length ({}) did not match expected record len ({})",
            size,
            len
        );
    }
    Ok(Record::CNAME(qname))
}
