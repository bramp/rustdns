use crate::bail;
use crate::io::{CursorExt, DNSReadExt, SeekExt};
use crate::types::*;
use crate::ParseError;
use byteorder::{ReadBytesExt, BE};
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
pub struct TXT(pub Vec<Vec<u8>>);

impl Record {
    pub(crate) fn parse(
        cur: &mut Cursor<&[u8]>,
        name: String,
        r#type: Type,
        class: Class,
    ) -> io::Result<Record> {
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
        let end = pos as usize + len as usize;
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
            Type::TXT => Resource::TXT(parse_txt(&mut record)?),
            Type::SPF => Resource::SPF(parse_txt(&mut record)?),
            Type::SRV => Resource::SRV(SRV::parse(&mut record)?),

            // This should never appear in a answer record unless we have invalid data.
            Type::Reserved | Type::OPT | Type::ANY => {
                // TODO This could be a warning, instead of a full error.
                bail!(InvalidData, "invalid record type '{}'", r#type);
            }
        };

        if record.remaining()? > 0 {
            bail!(
                Other,
                "finished '{}' parsing record with {} bytes left over",
                r#type,
                record.remaining()?
            );
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
pub struct SOA {
    /// The name server that was the original or primary source of data for this zone.
    pub mname: String,

    /// The mailbox of the person responsible for this zone.
    ///
    /// This is stored as a valid email address, e.g "dns.admin@example.com", as opposed
    /// to the format it's typically stored in SOA records "dns\.admin.example.com". Use
    /// [`rname_to_email`] and [`rname_to_email`] to convert between the formats.
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
pub struct SRV {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub name: String,
}

fn parse_a(cur: &mut Cursor<&[u8]>, class: Class) -> io::Result<A> {
    let mut buf = [0_u8; 4];
    cur.read_exact(&mut buf)?;

    match class {
        Class::Internet => Ok(A::new(buf[0], buf[1], buf[2], buf[3])),

        _ => bail!(InvalidData, "unsupported A record class '{}'", class),
    }
}

fn parse_aaaa(cur: &mut Cursor<&[u8]>, class: Class) -> io::Result<AAAA> {
    let mut buf = [0_u8; 16];
    cur.read_exact(&mut buf)?;

    match class {
        Class::Internet => Ok(AAAA::from(buf)),

        _ => bail!(InvalidData, "unsupported AAAA record class '{}'", class),
    }
}

fn parse_txt(cur: &mut Cursor<&[u8]>) -> io::Result<TXT> {
    let mut txts = Vec::new();

    loop {
        // Keep reading until EOF is reached.
        let len = match cur.read_u8() {
            Ok(len) => len,
            Err(e) => match e.kind() {
                io::ErrorKind::UnexpectedEof => break,
                _ => return Err(e),
            },
        };

        let mut txt = vec![0; len.into()];
        cur.read_exact(&mut txt)?;
        txts.push(txt)
    }

    Ok(TXT(txts))
}

impl SOA {
    pub(crate) fn parse(cur: &mut Cursor<&[u8]>) -> io::Result<SOA> {
        let mname = cur.read_qname()?;
        let rname = Self::rname_to_email(&cur.read_qname()?).unwrap(); // TODO error handling

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

    /// Converts rnames to email address, for example, "admin.example.com" is
    /// converted to "admin@example.com", per the rules in
    /// https://datatracker.ietf.org/doc/html/rfc1035#section-8
    pub fn rname_to_email(domain: &str) -> Result<String, ParseError> {
        // The logic is simple.
        // Find first unescaped dot and replace with a @

        // Handle the escaping. Replace the first . which isn't escapated with a \
        let mut result = String::with_capacity(domain.len());
        let mut last_char = ' ';
        let mut done = false;
        for c in domain.chars() {
            if last_char == '\\' {
                // Last character was escape, so always append this one.
                result.push(c);
            } else if c == '.' && !done {
                result.push('@');
                done = true;
            } else if c != '\\' {
                // Otherwise append if not an escape.
                result.push(c);
            }

            last_char = c;
        }

        if !done {
            return Err(ParseError::InvalidRname(domain.to_string()));
        }

        Ok(result)
    }

    pub fn email_to_rname(email: &str) -> Result<String, ParseError> {
        match email.split_once('@') {
            None => Err(ParseError::InvalidRname(email.to_string())),

            // Escape all the dots to the left of the '@',
            // replace the '@' with a '.', and leave everything after the '@' alone.
            Some((left, right)) => Ok(left.replace('.', "\\.") + "." + right),
        }
    }
}

impl MX {
    pub(crate) fn parse(cur: &mut Cursor<&[u8]>) -> io::Result<MX> {
        let preference = cur.read_u16::<BE>()?;
        let exchange = cur.read_qname()?;

        Ok(MX {
            preference,
            exchange,
        })
    }
}

impl SRV {
    pub(crate) fn parse(cur: &mut Cursor<&[u8]>) -> io::Result<SRV> {
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

    static RNAME_TESTS: &[(&str, &str)] = &[
        ("username.example.com", "username@example.com"),
        ("root.localhost", "root@localhost"),
        ("Action\\.domains.ISI.EDU", "Action.domains@ISI.EDU"),
        ("a\\.b\\.c.ISI.EDU", "a.b.c@ISI.EDU"),
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
}
