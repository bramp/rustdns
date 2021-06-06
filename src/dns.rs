use crate::bail;
use crate::types::Record;
use crate::types::*;
use byteorder::{ReadBytesExt, BE};
use num_traits::FromPrimitive;
use std::convert::TryInto;
use std::fmt;
use std::io;
use std::io::Cursor;
use std::io::SeekFrom;


pub trait SeekExt: io::Seek {
    /// Returns the number of bytes remaining to be consumed.
    /// This is used as a way to check for malformed input.
    fn remaining(&mut self) -> io::Result<u64> {
        let pos = self.stream_position()?;
        let len = self.seek(SeekFrom::End(0))?;

        // reset position
        self.seek(SeekFrom::Start(pos))?;

        Ok(len - pos)
    }
}

impl<'a> SeekExt for Cursor<&'a [u8]> {
    fn remaining(self: &mut std::io::Cursor<&'a [u8]>) -> io::Result<u64> {
        let pos = self.position() as usize;
        let len = self.get_ref().len() as usize;

        Ok((len - pos).try_into().unwrap())
    }
}

pub trait CursorExt<T> {
    /// Return a cursor that is bounded over the original cursor by start-end.
    ///
    /// The returned cursor contains all values with start <= x < end. It is empty if start >= end.
    /// 
    /// Similar to `Take` but allows the start-end range to be specified, instead of just the next
    /// N values.
    fn sub_cursor(&mut self, start: usize, end: usize) -> io::Result<std::io::Cursor<T>>;
}

impl<'a> CursorExt<&'a [u8]> for Cursor<&'a [u8]> {
    fn sub_cursor(&mut self, start: usize, end: usize) -> io::Result<std::io::Cursor<&'a [u8]>> {
        //if start >= end {
        //    end = start;
        //}
        // Create a new Cursor that is limited to the len field.
        //let pos = self.position();
        //let end = pos as usize + len as usize;
        let buf = self.get_ref();

        let start = num::clamp(start, 0, buf.len());
        let end   = num::clamp(end, start, buf.len());

        let record = Cursor::new(&buf[start..end]);
        //record.set_position(self.pos); // TODO Check this pos is within the buf
        Ok(record)
    }
}

/// All types that implement `Read` and `Seek` get methods defined
// in `DNSReadExt` for free.
impl<R: io::Read + ?Sized + io::Seek> DNSReadExt for R {}

/// Extensions to io::Read to add some DNS specific types.
pub trait DNSReadExt: io::Read + io::Seek {
    /// Reads a puny encoded domain name from a byte array.
    ///
    /// Used for extracting a encoding ASCII domain name from a DNS message. Will
    /// returns the Unicode domain name, as well as the length of this name (ignoring
    /// any compressed pointers) in bytes.
    ///
    /// # Errors
    ///
    /// Will return a io::Error(InvalidData) if the read domain name is invalid, or
    /// a more general io::Error on any other read failure.
    fn read_qname(&mut self) -> io::Result<String> {
        let mut qname = String::new();
        let start = self.stream_position()?;

        // Read each label one at a time, to build up the full domain name.
        loop {
            // Length of the first label
            let len = self.read_u8()?;
            if len == 0 {
                if qname.is_empty() {
                    qname.push('.') // Root domain
                }
                break;
            }

            match len & 0xC0 {
                // No compression
                0x00 => {
                    let mut label = vec![0; len.into()];
                    self.read_exact(&mut label)?;

                    // Really this is meant to be ASCII, but we read as utf8
                    // (as that what Rust provides).
                    let label = match std::str::from_utf8(&label) {
                        Err(e) => bail!(InvalidData, "invalid label: {}", e),
                        Ok(s) => s,
                    };

                    if !label.is_ascii() {
                        bail!(InvalidData, "invalid label '{:}': not valid ascii", label);
                    }

                    // Now puny decode this label returning its original unicode.
                    let label = match idna::domain_to_unicode(label) {
                        (label, Err(e)) => bail!(InvalidData, "invalid label '{:}': {}", label, e),
                        (label, Ok(_)) => label,
                    };

                    qname.push_str(&label);
                    qname.push('.');
                }

                // Compression
                0xC0 => {
                    // Read the 14 bit pointer.
                    let b2 = self.read_u8()? as u16;
                    let ptr = ((len as u16 & !0xC0) << 8 | b2) as u64;

                    // Make sure we don't get into a loop.
                    if ptr >= start {
                        bail!(
                            InvalidData,
                            "invalid compressed pointer pointing to future bytes"
                        );
                    }

                    // We are going to jump backwards, so record where we
                    // currently are. So we can reset it later.
                    let current = self.stream_position()?;

                    // Jump and start reading the qname again.
                    self.seek(SeekFrom::Start(ptr))?;
                    qname.push_str(&self.read_qname()?);

                    // Reset ourselves.
                    self.seek(SeekFrom::Start(current))?;

                    break;
                }

                // Unknown
                _ => bail!(
                    InvalidData,
                    "unsupported compression type {0:b}",
                    len & 0xC0
                ),
            }
        }

        Ok(qname)
    }

    /// Reads a Type.
    fn read_type(&mut self) -> io::Result<QType> {
        let r#type = self.read_u16::<BE>()?;
        let r#type = match FromPrimitive::from_u16(r#type) {
            Some(t) => t,
            None => bail!(InvalidData, "invalid Type({})", r#type),
        };

        Ok(r#type)
    }

    /// Reads a Class.
    fn read_class(&mut self) -> io::Result<QClass> {
        let class = self.read_u16::<BE>()?;
        let class = match FromPrimitive::from_u16(class) {
            Some(t) => t,
            None => bail!(InvalidData, "invalid Class({})", class),
        };

        Ok(class)
    }
}

// A helper class to hold state while the parsing is happening.
pub(crate) struct MessageParser<'a> {
    cur: Cursor<&'a [u8]>,

    m: Message,
    // TODO add list of parse errors
}

#[derive(Copy, Clone, PartialEq)]
enum RecordSection {
    Answers,
    Authorities,
    Additionals,
}

impl<'a> MessageParser<'a> {
    fn new(buf: &[u8]) -> MessageParser {
        MessageParser {
            cur: Cursor::new(buf),
            m: Message::default(),
        }
    }

    /// Consume the MessageParser and returned the resulting Message.
    fn parse(mut self) -> io::Result<Message> {
        self.m.id = self.cur.read_u16::<BE>()?;

        let b = self.cur.read_u8()?;
        self.m.qr = QR::from_bool(0b1000_0000 & b != 0);
        let opcode = (0b0111_1000 & b) >> 3;
        self.m.aa = (0b0000_0100 & b) != 0;
        self.m.tc = (0b0000_0010 & b) != 0;
        self.m.rd = (0b0000_0001 & b) != 0;

        self.m.opcode = match FromPrimitive::from_u8(opcode) {
            Some(t) => t,
            None => bail!(InvalidData, "invalid Opcode({})", opcode),
        };

        let b = self.cur.read_u8()?;
        self.m.ra = (0b1000_0000 & b) != 0;
        self.m.z = (0b0100_0000 & b) != 0; // Unused
        self.m.ad = (0b0010_0000 & b) != 0;
        self.m.cd = (0b0001_0000 & b) != 0;
        let rcode = 0b0000_1111 & b;

        self.m.rcode = match FromPrimitive::from_u8(rcode) {
            Some(t) => t,
            None => bail!(InvalidData, "invalid RCode({})", opcode),
        };

        let qd_count = self.cur.read_u16::<BE>()?;
        let an_count = self.cur.read_u16::<BE>()?;
        let ns_count = self.cur.read_u16::<BE>()?;
        let ar_count = self.cur.read_u16::<BE>()?;

        self.read_questions(qd_count)?;
        self.read_records(an_count, RecordSection::Answers)?;
        self.read_records(ns_count, RecordSection::Authorities)?;
        self.read_records(ar_count, RecordSection::Additionals)?;

        if self.cur.remaining()? > 0 {
            bail!(
                Other,
                "finished parsing with {} bytes left over",
                self.cur.remaining()?
            );
        }

        Ok(self.m)
    }

    fn read_questions(&mut self, count: u16) -> io::Result<()> {
        self.m.questions.reserve_exact(count.into());

        for _ in 0..count {
            let name = self.cur.read_qname()?;
            let r#type = self.cur.read_type()?;
            let class = self.cur.read_class()?;

            self.m.questions.push(Question {
                name,
                r#type,
                class,
            });
        }

        Ok(())
    }

    fn read_records(&mut self, count: u16, section: RecordSection) -> io::Result<()> {
        let records = match section {
            RecordSection::Answers => &mut self.m.answers,
            RecordSection::Authorities => &mut self.m.authoritys,
            RecordSection::Additionals => &mut self.m.additionals,
        };
        records.reserve_exact(count.into());

        for _ in 0..count {
            let name = self.cur.read_qname()?;
            let r#type = self.cur.read_type()?;

            if section == RecordSection::Additionals && r#type == QType::OPT {
                if self.m.extension.is_some() {
                    bail!(
                        InvalidData,
                        "multiple EDNS(0) extensions. Expected only one."
                    );
                }

                let ext = Extension::parse(&mut self.cur, name, r#type)?;

                self.m.extension = Some(ext);
            } else {
                let class = self.cur.read_class()?;
                let record = Record::parse(&mut self.cur, name, r#type, class)?;

                records.push(record);
            }
        }

        Ok(())
    }
}

impl Message {
    pub fn from_slice(buf: &[u8]) -> io::Result<Message> {
        MessageParser::new(&buf).parse()
    }

    // Takes a unicode domain, converts to ascii, and back to unicode.
    // This has the effective of normalising it, so its easier to compare
    // what was queried, and what was returned.
    fn normalsie_domain(&mut self, domain: &str) -> Result<String, idna::Errors> {
        let ascii = idna::domain_to_ascii(domain)?;
        let (mut unicode, result) = idna::domain_to_unicode(&ascii);
        match result {
            Ok(_) => {
                if !unicode.ends_with('.') {
                    unicode.push('.')
                }
                Ok(unicode)
            }
            Err(errors) => Err(errors),
        }
    }

    pub fn add_question(&mut self, domain: &str, r#type: QType, class: QClass) {
        let domain = self.normalsie_domain(domain).expect("invalid domain"); // TODO fix

        // TODO Don't allow more than 255 questions.
        let q = Question {
            name: domain,
            r#type,
            class,
        };

        self.questions.push(q);
    }

    /// Adds an EDNS(0) extension record, as defined by [rfc6891](https://datatracker.ietf.org/doc/html/rfc6891).
    pub fn add_extension(&mut self, ext: Extension) {
        // Don't allow if self.additionals.len() + 1 > 255
        self.extension = Some(ext);
    }

    /// Returns this DNS Message as a Vec<u8> ready to be sent, as defined by [rfc1035](https://datatracker.ietf.org/doc/html/rfc1035).
    pub fn to_vec(&self) -> io::Result<Vec<u8>> {
        let mut req = Vec::<u8>::with_capacity(512);

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
            Message::write_qname(&mut req, &question.name)?;

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

    /// Writes a Unicode domain name into the supplied `Vec<u8>`.
    ///
    /// Used for writing out a encoded ASCII domain name into a DNS message. Will
    /// returns the Unicode domain name, as well as the length of this qname (ignoring
    /// any compressed pointers) in bytes.
    ///
    // TODO Support compression.
    fn write_qname(buf: &mut Vec<u8>, domain: &str) -> io::Result<()> {
        // Decode this label into the original unicode.
        // TODO Switch to using our own idna::Config. (but we can't use disallowed_by_std3_ascii_rules).
        let domain = match idna::domain_to_ascii(domain) {
            Err(e) => {
                bail!(InvalidData, "invalid dns name '{0}': {1}", domain, e);
            }
            Ok(domain) => domain,
        };

        if !domain.is_empty() && domain != "." {
            for label in domain.split_terminator('.') {
                if label.is_empty() {
                    bail!(InvalidData, "empty label in domain name '{}'", domain);
                }

                if label.len() > 63 {
                    bail!(InvalidData, "label '{0}' longer than 63 characters", label);
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

/// Displays this message in a format resembling `dig` output.
impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_header(f)?;

        // ;; OPT PSEUDOSECTION:
        // ; EDNS: version: 0, flags:; udp: 512
        if let Some(e) = &self.extension {
            writeln!(f, ";; OPT PSEUDOSECTION:")?;
            // TODO Support tthe flags
            writeln!(
                f,
                "; EDNS: version: {version}, flags:; udp: {payload_size}",
                version = e.version,
                payload_size = e.payload_size,
            )?;
        }

        // Always display the question section, but optionally
        // display the other sections.
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

impl Message {
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
