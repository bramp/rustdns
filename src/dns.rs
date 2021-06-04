use num_traits::FromPrimitive;
use std::convert::TryInto;
use std::fmt;

use crate::as_array;
use crate::errors::ParseError;
use crate::errors::WriteError;
use crate::parse_error;
use crate::types::Record;
use crate::types::*;

/// Reads a ASCII qname from a byte array.
///
/// Used for extracting a encoding ASCII domain name from a DNS packet. Will
/// returns the Unicode domain name, as well as the length of this qname (ignoring
/// any compressed pointers) in bytes.
///
/// # Errors
///
/// Will return a [`ParseError`] if the qname is invalid as a domain name.
// TODO Move into Packet
pub(crate) fn read_qname(buf: &[u8], start: usize) -> Result<(String, usize), ParseError> {
    let mut qname = String::new();
    let mut offset = start;

    // Read each label one at a time, to build up the full domain name.
    loop {
        // Length of the first label
        let len = *match buf.get(offset) {
            Some(len) => len,
            None => return parse_error!("qname failed to read label length"),
        } as usize;

        offset += 1;
        if len == 0 {
            break;
        }

        match len & 0xC0 {
            // No compression
            0x00 => {
                let label = match buf.get(offset..offset + len) {
                    None => return parse_error!("qname field too short"), // TODO standardise the too short error
                    Some(label) => label,
                };

                // Really this is meant to be ASCII, but we read as utf8 (as that what Rust provides).
                let label = match std::str::from_utf8(label) {
                    Err(e) => return parse_error!("unable to read qname: {}", e), // TODO standardise the too short error
                    Ok(s) => s,
                };

                // Decode this label into the original unicode.
                let label = match idna::domain_to_unicode(label) {
                    (label, Err(e)) => return parse_error!("invalid label '{:}': {}", label, e),
                    (label, Ok(_)) => label,
                };

                qname.push_str(&label);
                qname.push('.');

                offset += len;
            }

            // Compression
            0xC0 => {
                let b2 = *match buf.get(offset) {
                    Some(b) => b,
                    None => return parse_error!("qname too short missing compressed pointer"),
                } as usize;

                let ptr = (len & !0xC0) << 8 | b2;
                offset += 1;

                if ptr >= start {
                    return parse_error!(
                        "qname invalid compressed pointer pointing to future bytes"
                    );
                }

                // Read the qname from elsewhere in the packet ignoring
                // the length of that segment.
                qname.push_str(&read_qname(buf, ptr)?.0);
                break;
            }

            // Unknown
            _ => return parse_error!("qname unsupported compression type {0:b}", len & 0xC0),
        }
    }

    if qname.is_empty() {
        qname = ".".to_string() // Root domain
    }

    Ok((qname, offset - start))
}

impl Packet {
    pub fn from_slice(buf: &[u8]) -> Result<Packet, ParseError> {
        let header = as_array![buf, 0, 12];

        let id = u16::from_be_bytes(*as_array![header, 0, 2]);

        let b = header[2];
        let qr = QR::from_bool(0b1000_0000 & b != 0);
        let opcode = (0b0111_1000 & b) >> 3;
        let aa = (0b0000_0100 & b) != 0;
        let tc = (0b0000_0010 & b) != 0;
        let rd = (0b0000_0001 & b) != 0;

        let opcode = match FromPrimitive::from_u8(opcode) {
            Some(t) => t,
            None => return parse_error!("invalid Opcode({})", opcode),
        };

        let b = header[3];
        let ra = (0b1000_0000 & b) != 0;
        let z = (0b0100_0000 & b) != 0; // Unused
        let ad = (0b0010_0000 & b) != 0;
        let cd = (0b0001_0000 & b) != 0;
        let rcode = 0b0000_1111 & b;

        let rcode = match FromPrimitive::from_u8(rcode) {
            Some(t) => t,
            None => return parse_error!("invalid RCode({})", rcode),
        };

        let qd_count = u16::from_be_bytes(*as_array![header, 4, 2]);
        let an_count = u16::from_be_bytes(*as_array![header, 6, 2]);
        let ns_count = u16::from_be_bytes(*as_array![header, 8, 2]);
        let ar_count = u16::from_be_bytes(*as_array![header, 10, 2]);

        let mut offset = 12;

        let (questions, len) = Packet::read_questions(&buf, offset, qd_count)?;
        offset += len;

        let (answers, _, len) = Packet::read_records(&buf, offset, an_count, false)?;
        offset += len;

        let (authoritys, _, len) = Packet::read_records(&buf, offset, ns_count, false)?;
        offset += len;

        let (additionals, extension, len) = Packet::read_records(&buf, offset, ar_count, true)?;
        offset += len;

        if offset != buf.len() {
            return parse_error!(
                "failed to read full packet expected {} read {}",
                buf.len(),
                offset
            );
        }

        Ok(Packet {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,

            ra,
            z,
            ad,
            cd,
            rcode,

            questions,
            answers,
            authoritys,
            additionals,

            extension,
        })
    }

    // TODO Move into the QType.
    fn read_type(buf: [u8; 2]) -> Result<QType, ParseError> {
        let r#type = u16::from_be_bytes(buf);
        let r#type = match FromPrimitive::from_u16(r#type) {
            Some(t) => t,
            None => return parse_error!("invalid Type({})", r#type),
        };

        Ok(r#type)
    }

    // TODO Move into the QClass.
    fn read_class(buf: [u8; 2]) -> Result<QClass, ParseError> {
        let class = u16::from_be_bytes(buf);
        let class = match FromPrimitive::from_u16(class) {
            Some(t) => t,
            None => return parse_error!("invalid Class({})", class),
        };

        Ok(class)
    }

    fn read_questions(
        buf: &[u8],
        start: usize,
        count: u16,
    ) -> Result<(Vec<Question>, usize), ParseError> {
        let mut offset = start;
        let mut questions = Vec::with_capacity(count.into());
        for _ in 0..count {
            // TODO Move into Question::from_slice()

            let (name, len) = read_qname(&buf, offset)?;
            offset += len;

            let r#type = Packet::read_type(*as_array![buf, offset, 2])?;
            offset += 2;

            let class = Packet::read_class(*as_array![buf, offset, 2])?;
            offset += 2;

            questions.push(Question {
                name: name.to_string(), // TODO Fix
                r#type,
                class,
            });
        }

        Ok((questions, offset - start))
    }

    fn read_records(
        buf: &[u8],
        start: usize,
        count: u16,
        allow_extension: bool,
    ) -> Result<(Vec<Record>, Option<Extension>, usize), ParseError> {
        let mut offset = start;
        let mut answers = Vec::with_capacity(count.into());
        let mut extension = None;

        for _ in 0..count {
            let (name, len) = read_qname(&buf, offset)?;
            offset += len;

            let r#type = Packet::read_type(*as_array![buf, offset, 2])?;
            offset += 2;

            if allow_extension && r#type == QType::OPT {
                if extension.is_some() {
                    return parse_error!("multiple EDNS(0) extensions. Expected only one.");
                }

                let (ext, len) = Extension::from_slice(name, r#type, buf, offset)?;
                offset += len;

                extension = Some(ext);
            } else {
                let class = Packet::read_class(*as_array![buf, offset, 2])?;
                offset += 2;

                let (record, len) = Record::from_slice(name, r#type, class, &buf, offset)?;
                offset += len;

                answers.push(record);
            }
        }

        Ok((answers, extension, offset - start))
    }

    pub fn add_question(&mut self, domain: &str, r#type: QType, class: QClass) {
        let mut domain = domain.to_string();
        if !domain.ends_with('.') {
            domain.push('.')
        }

        // TODO Don't allow more than 255 questions.
        let q = Question {
            name: domain,
            r#type,
            class,
        };

        self.questions.push(q);
    }

    /// Adds an EDNS(0) extension record, as defined by [rfc6891](https://datatracker.ietf.org/doc/html/rfc6891)
    pub fn add_extension(&mut self, ext: Extension) {
        // Don't allow if self.additionals.len() + 1 > 255
        self.extension = Some(ext);
    }

    // Returns this DNS packet as a Vec<u8>.
    // TODO Rename this to_vec()
    pub fn as_vec(&self) -> Result<Vec<u8>, WriteError> {
        let mut req = Vec::<u8>::with_capacity(512); // TODO Guess the best size

        req.extend_from_slice(&(self.id as u16).to_be_bytes());

        let mut b = 0_u8;
        b |= if self.qr.to_bool() { 0b1000_0000 } else { 0 };
        b |= ((self.opcode as u8) << 3) & 0b0111_1000;
        b |= if self.aa { 0b0000_0100 } else { 0 };
        b |= if self.tc { 0b0000_0010 } else { 0 };
        b |= if self.rd { 0b0000_0001 } else { 0 };
        req.push(b);

        let mut b = 0_u8;
        b |= if self.ra { 0b1000_0000 } else { 0 };
        b |= if self.z { 0b0100_0000 } else { 0 };
        b |= if self.ad { 0b0010_0000 } else { 0 };
        b |= if self.cd { 0b0001_0000 } else { 0 };
        b |= (self.rcode as u8) & 0b0000_1111;

        req.push(b);

        let ar_count = self.additionals.len() as u16 + self.extension.is_some() as u16;

        req.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        req.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        req.extend_from_slice(&(self.authoritys.len() as u16).to_be_bytes());
        req.extend_from_slice(&ar_count.to_be_bytes());

        for question in &self.questions {
            // TODO use Question::as_vec()
            Packet::write_qname(&mut req, &question.name)?;

            req.extend_from_slice(&(question.r#type as u16).to_be_bytes());
            req.extend_from_slice(&(question.class as u16).to_be_bytes());
        }

        // TODO Implement answers, etc types.
        assert!(self.answers.is_empty());
        assert!(self.authoritys.is_empty());
        assert!(self.additionals.is_empty());

        if let Some(e) = &self.extension {
            e.write(&mut req)?
        }

        // TODO if the Vec<u8> is too long, truncate the request.

        Ok(req)
    }

    /// Reads a Unicode domain name into the supplied `Vec<u8>`.
    ///
    /// Used for writing out a encoded ASCII domain name into a DNS packet. Will
    /// returns the Unicode domain name, as well as the length of this qname (ignoring
    /// any compressed pointers) in bytes.
    ///
    /// # Errors
    ///
    /// Will return a [`WriteError`] if the domain name is invalid.
    // TODO Support compression.
    fn write_qname(buf: &mut Vec<u8>, domain: &str) -> Result<(), WriteError> {
        // Decode this label into the original unicode.
        // TODO Switch to using our own idna::Config. (but we can't use disallowed_by_std3_ascii_rules).
        let domain = match idna::domain_to_ascii(domain) {
            Err(e) => {
                return Err(WriteError {
                    msg: format!("invalid dns name '{0}': {1}", domain, e),
                })
            }
            Ok(domain) => domain,
        };

        if !domain.is_empty() && domain != "." {
            for label in domain.split_terminator('.') {
                if label.is_empty() {
                    return Err(WriteError {
                        msg: "double dot found in domain name".to_string(),
                    });
                }

                if label.len() > 63 {
                    return Err(WriteError {
                        msg: format!("label '{0}' longer than 63 characters", label),
                    });
                }

                // Write the length.
                buf.push(label.len() as u8);

                // Then the actual label.
                buf.extend_from_slice(label.as_bytes());
            }
        }

        buf.push(0);

        Ok(())
    }
}

impl Packet {
    fn fmt_header(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            ";; ->>HEADER<<- opcode: {opcode}, status: {rcode}, id: {id}",
            opcode = self.opcode,
            rcode = self.rcode,
            id = self.id,
        )?;

        let mut flags = String::new();

        if self.qr.to_bool() {
            flags.push_str(" qr")
        }
        if self.aa {
            flags.push_str(" aa")
        }
        if self.tc {
            flags.push_str(" tc")
        }
        if self.rd {
            flags.push_str(" rd")
        }
        if self.ra {
            flags.push_str(" ra")
        }
        if self.ad {
            flags.push_str(" ad")
        }
        if self.cd {
            flags.push_str(" cd")
        }

        let ar_count = self.additionals.len() as u16 + self.extension.is_some() as u16;

        writeln!(f, ";; flags:{flags}; QUERY: {qd_count}, ANSWER: {an_count}, AUTHORITY: {ns_count}, ADDITIONAL: {ar_count}", 
            flags = flags,
            qd_count = self.questions.len(),
            an_count = self.answers.len(),
            ns_count = self.authoritys.len(),
            ar_count = ar_count,
        )?;

        writeln!(f)
    }
}

impl fmt::Display for Packet {
    // TODO Convert to dig format
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_header(f)?;

        // ;; OPT PSEUDOSECTION:
        // ; EDNS: version: 0, flags:; udp: 512
        if let Some(e) = &self.extension {
            writeln!(f, ";; OPT PSEUDOSECTION:")?;
            writeln!(
                f,
                "; EDNS: version: {version}, flags:; udp: {payload_size}",
                version = e.version,
                payload_size = e.payload_size,
            )?;
        }

        // Always display the question section, but optionally display
        // the other sections.
        writeln!(f, ";; QUESTION SECTION:")?;
        for question in &self.questions {
            question.fmt(f)?;
        }
        writeln!(f)?;

        if !self.answers.is_empty() {
            writeln!(f, "; ANSWER SECTION:")?;
            for answer in &self.answers {
                answer.fmt(f)?;
            }
            writeln!(f)?;
        }

        if !self.authoritys.is_empty() {
            writeln!(f, "; AUTHORITY SECTION:")?;
            for answer in &self.authoritys {
                answer.fmt(f)?;
            }
            writeln!(f)?;
        }

        if !self.additionals.is_empty() {
            writeln!(f, "; ADDITIONAL SECTION:")?;
            for answer in &self.additionals {
                answer.fmt(f)?;
            }
            writeln!(f)?;
        }

        // TODO
        // ;; Query time: 46 msec
        // ;; SERVER: 2601:646:ca00:43c::1#53(2601:646:ca00:43c::1)
        // ;; WHEN: Fri May 28 14:06:26 PDT 2021
        // ;; MSG SIZE  rcvd: 63

        writeln!(f)
    }
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "; {name:<18}      {class:4} {type:6}\n",
            name = self.name,
            class = self.class,
            r#type = self.r#type,
        )
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "{name:<20} {ttl:>4} {class:4} {type:6} {resource}",
            name = self.name,
            ttl = self.ttl.as_secs(),
            class = self.class,
            r#type = self.r#type,
            resource = self.resource,
        )
    }
}
