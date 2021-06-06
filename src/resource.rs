use crate::types::*;
use std::io;

use crate::bail;
use crate::dns::{DNSReadExt, SeekExt};
use byteorder::{ReadBytesExt, BE};
use std::fmt;
use std::io::Cursor;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

impl Record {
    pub(crate) fn parse(
        cur: &mut Cursor<&[u8]>,
        name: String,
        r#type: QType,
        class: QClass,
    ) -> io::Result<Record> {
        let ttl = cur.read_u32::<BE>()?;
        let len = cur.read_u16::<BE>()?;

        // Create a new Cursor that is limited to the len field.
        let pos = cur.position();
        let end = pos as usize + len as usize;
        let buf = cur.get_ref();

        let mut record = Cursor::new(&buf[0..end]);
        record.set_position(pos);

        let resource = match r#type {
            QType::A => Resource::A(parse_a(&mut record, class)?),
            QType::AAAA => Resource::AAAA(parse_aaaa(&mut record, class)?),

            QType::NS => Resource::NS(parse_qname(&mut record)?),
            QType::SOA => Resource::SOA(Soa::parse(&mut record)?),
            QType::CNAME => Resource::CNAME(parse_qname(&mut record)?),
            QType::PTR => Resource::PTR(parse_qname(&mut record)?),
            QType::MX => Resource::MX(Mx::parse(&mut record)?),
            QType::TXT => Resource::TXT(parse_txt(&mut record, len.into())?),
            QType::SRV => Resource::SRV(Srv::parse(&mut record)?),

            // This should never appear in a answer record unless we have invalid data.
            QType::Reserved | QType::OPT | QType::ANY => {
                bail!(InvalidData, "invalid record type '{}'", r#type);
            }
        };

        // TODO This could be a warning, instead of a full error.
        if record.remaining()? > 0 {
            bail!(
                Other,
                "finished '{}' parsing record with {} bytes left over",
                r#type,
                record.remaining()?
            );
        }

        // Now catch up
        cur.set_position(record.position());

        Ok(Record {
            name,

            r#type,
            class,

            ttl: Duration::from_secs(ttl.into()),

            resource,
        })
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

fn parse_a(cur: &mut Cursor<&[u8]>, class: QClass) -> io::Result<Ipv4Addr> {
    let mut buf = [0_u8; 4];
    cur.read_exact(&mut buf)?;

    match class {
        QClass::Internet => Ok(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])),

        _ => bail!(InvalidData, "unsupported A record class '{}'", class),
    }
}

fn parse_aaaa(cur: &mut Cursor<&[u8]>, class: QClass) -> io::Result<Ipv6Addr> {
    let mut buf = [0_u8; 16];
    cur.read_exact(&mut buf)?;

    match class {
        QClass::Internet => Ok(Ipv6Addr::from(buf)),

        _ => bail!(InvalidData, "unsupported AAAA record class '{}'", class),
    }
}

// TODO Remove parse_qname we don't need it
fn parse_qname(cur: &mut Cursor<&[u8]>) -> io::Result<String> {
    let qname = cur.read_qname()?;
    /* TODO
    if len != size {
        return parse_error!(
            "qname length ({}) did not match expected record len ({})",
            size,
            len
        );
    }
    */
    Ok(qname)
}

fn parse_txt(cur: &mut Cursor<&[u8]>, mut size: usize) -> io::Result<Vec<String>> {
    let mut txts = Vec::new();

    // Read each record, prefixed by a 1-byte length.
    while size > 0 {
        // TODO Change this so it doesn't need size passed in, and instead hits EOF
        let len = cur.read_u8()?;

        let mut txt = vec![0; len.into()];
        cur.read_exact(&mut txt)?;

        size = size - 1 - len as usize;

        // This string doesn't strictly need to be UTF-8, but I'm assuming it is.
        // TODO maybe change this to just be byte arrays, and let the reader decide the encoding.
        match String::from_utf8(txt) {
            Ok(s) => txts.push(s),
            Err(e) => bail!(InvalidData, "unable to parse TXT: {}", e),
        }
    }

    Ok(txts)
}

impl Soa {
    pub(crate) fn parse(cur: &mut Cursor<&[u8]>) -> io::Result<Soa> {
        let mname = cur.read_qname()?;
        let rname = cur.read_qname()?;

        let serial = cur.read_u32::<BE>()?;
        let refresh = cur.read_u32::<BE>()?;
        let retry = cur.read_u32::<BE>()?; // u32::from_be_bytes(*as_array![parser.buf, offset, 4]);
        let expire = cur.read_u32::<BE>()?; // u32::from_be_bytes(*as_array![parser.buf, offset, 4]);
        let minimum = cur.read_u32::<BE>()?; // u32::from_be_bytes(*as_array![parser.buf, offset, 4]);

        // TODO
        /*
        if offset - start != len {
            return parse_error!("failed to parse full SOA record");
        }
        */

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
    pub(crate) fn parse(cur: &mut Cursor<&[u8]>) -> io::Result<Mx> {
        let preference = cur.read_u16::<BE>()?; // u16::from_be_bytes(*as_array![parser.buf, 0, 2]);
        let exchange = cur.read_qname()?;

        /* TODO
        if len != 2 + size {
            // TODO Standardise his kind of error.
            return parse_error!("failed to read full MX record");
        }
        */

        Ok(Mx {
            preference,
            exchange,
        })
    }
}

impl Srv {
    pub(crate) fn parse(cur: &mut Cursor<&[u8]>) -> io::Result<Srv> {
        /* TODO
        if len < 7 {
            return parse_error!("SRV record too short");
        }
        */

        let priority = cur.read_u16::<BE>()?; // u16::from_be_bytes(*as_array![parser.buf, start, 2]);
        let weight = cur.read_u16::<BE>()?; // u16::from_be_bytes(*as_array![parser.buf, start + 2, 2]);
        let port = cur.read_u16::<BE>()?; // u16::from_be_bytes(*as_array![parser.buf, start + 4, 2]);

        let name = cur.read_qname()?;

        /* TODO
        if len != 6 + size {
            // TODO Standardise his kind of error.
            return parse_error!("failed to read full SRV record");
        }
        */

        Ok(Srv {
            priority,
            weight,
            port,
            name,
        })
    }
}

impl Extension {
    pub fn parse(cur: &mut Cursor<&[u8]>, domain: String, r#type: QType) -> io::Result<Extension> {
        assert!(r#type == QType::OPT);

        if domain != "." {
            bail!(
                InvalidData,
                "expected root domain for EDNS(0) extension, got '{}'",
                domain
            );
        }

        let payload_size = cur.read_u16::<BE>()?;
        let extend_rcode = cur.read_u8()?;

        let version = cur.read_u8()?;
        let b = cur.read_u8()?;
        let dnssec_ok = b & 0b1000_0000 == 0b1000_0000;

        let _z = cur.read_u8()?;

        let _rd_len = cur.read_u16::<BE>()?; // TODO!

        Ok(Extension {
            payload_size,
            extend_rcode,
            version,
            dnssec_ok,
        })
    }

    pub fn write(&self, buf: &mut Vec<u8>) -> io::Result<()> {
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
