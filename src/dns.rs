use std::io::SeekFrom;
use num_traits::FromPrimitive;
use std::fmt;
use std::io;
use std::io::Cursor;
use crate::bail;
use crate::types::Record;
use crate::types::*;
use byteorder::{ReadBytesExt, BE};

/// All types that implement `Read` and `Seek` methods defined in `DNSReadExt`
/// for free.
impl<R: io::Read + ?Sized + io::Seek> DNSReadExt for R {}

pub trait DNSReadExt: std::io::Read + std::io::Seek {
    /// Reads a ASCII domain name from a byte array.
    ///
    /// Used for extracting a encoding ASCII domain name from a DNS packet. Will
    /// returns the Unicode domain name, as well as the length of this name (ignoring
    /// any compressed pointers) in bytes.
    ///
    /// # Errors
    ///
    /// TODO Will return a [`ParseError`] if the qname is invalid as a domain name.
    fn read_qname(&mut self) -> io::Result<String> {
        let mut qname = String::new();
        let start = self.seek(SeekFrom::Current(0))?;

        // Read each label one at a time, to build up the full domain name.
        loop {
            // Length of the first label
            let len = self.read_u8()?;
            if len == 0 {
                break;
            }

            match len & 0xC0 {
                // No compression
                0x00 => {
                    let mut label = vec![0; len.into()];
                    self.read_exact(&mut label)?;

                    // Really this is meant to be ASCII, but we read as utf8 (as that what Rust provides).
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
                    let b2 = self.read_u8()? as u16;
                    let ptr = ((len as u16 & !0xC0) << 8 | b2) as u64;

                    if ptr >= start {
                        bail!(InvalidData, 
                            "invalid compressed pointer pointing to future bytes"
                        );
                    }

                    // We are going to jump backwards, so record where we currently
                    // are. So we can reset it later.
                    let current = self.seek(SeekFrom::Current(0))?;

                    // Jump and start reading the qname again.
                    self.seek(SeekFrom::Start(ptr))?;
                    qname.push_str(&self.read_qname()?);

                    // Reset ourselves.
                    self.seek(SeekFrom::Start(current))?;

                    break;
                }

                // Unknown
                _ => bail!(InvalidData, "qname unsupported compression type {0:b}", len & 0xC0),
            }
        }

        if qname.is_empty() {
            qname = ".".to_string() // Root domain
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
pub(crate) struct PacketParser<'a> {
    cur: Cursor<&'a [u8]>,

    p: Packet,
    // TODO add list of parse errors
}

impl<'a> PacketParser<'a> {
    fn new(buf: &[u8]) -> PacketParser {
        PacketParser {
            cur: Cursor::new(buf),
            p: Packet::default(),
        }
    }

    fn parse(mut self) -> io::Result<Packet> {
        self.p.id = self.cur.read_u16::<BE>()?;

        let b = self.cur.read_u8()?;
        self.p.qr = QR::from_bool(0b1000_0000 & b != 0);
        let opcode = (0b0111_1000 & b) >> 3;
        self.p.aa = (0b0000_0100 & b) != 0;
        self.p.tc = (0b0000_0010 & b) != 0;
        self.p.rd = (0b0000_0001 & b) != 0;

        self.p.opcode = match FromPrimitive::from_u8(opcode) {
            Some(t) => t,
            None => bail!(InvalidData, "invalid Opcode({})", opcode),
        };

        let b = self.cur.read_u8()?;
        self.p.ra = (0b1000_0000 & b) != 0;
        self.p.z = (0b0100_0000 & b) != 0; // Unused
        self.p.ad = (0b0010_0000 & b) != 0;
        self.p.cd = (0b0001_0000 & b) != 0;
        let rcode = 0b0000_1111 & b;

        self.p.rcode = match FromPrimitive::from_u8(rcode) {
            Some(t) => t,
            None => bail!(InvalidData, "invalid RCode({})", opcode),
        };

        let qd_count = self.cur.read_u16::<BE>()?;
        let an_count = self.cur.read_u16::<BE>()?;
        let ns_count = self.cur.read_u16::<BE>()?;
        let ar_count = self.cur.read_u16::<BE>()?;
        // This assumes the current reservation is zero.
        self.p.questions.reserve_exact(qd_count.into());
        self.p.answers.reserve_exact(an_count.into());
        self.p.authoritys.reserve_exact(ns_count.into());
        self.p.additionals.reserve_exact(ar_count.into());

        self.read_questions(qd_count)?;

        let records = self.read_records(an_count, false)?;
        self.p.answers = records;

        let records = self.read_records(ns_count, false)?;
        self.p.authoritys = records;

        let records = self.read_records(ar_count, true)?;
        self.p.additionals = records;

        /*
        // TODO
        if offset != buf.len() {
            return parse_error!(
                "failed to read full packet expected {} read {}",
                buf.len(),
                offset
            );
        }
        */

        Ok(self.p)
    }

    fn read_questions(&mut self, count: u16) -> io::Result<()> {
        for _ in 0..count {
            // TODO Move into Question::from_slice()
            let name = self.cur.read_qname()?;

            let r#type = self.cur.read_type()?;
            let class = self.cur.read_class()?;

            self.p.questions.push(Question {
                name: name.to_string(), // TODO Fix
                r#type,
                class,
            });
        }

        Ok(())
    }

    fn read_records(
        &mut self,
        count: u16,
        allow_extension: bool,
    ) -> io::Result<Vec<Record>> {
        let mut records = Vec::with_capacity(count.into());

        for _ in 0..count {
            let name = self.cur.read_qname()?;
            let r#type = self.cur.read_type()?;

            if allow_extension && r#type == QType::OPT {
                if self.p.extension.is_some() {
                    bail!(InvalidData, "multiple EDNS(0) extensions. Expected only one.");
                }

                let ext = Extension::parse(&mut self.cur, name, r#type)?;

                self.p.extension = Some(ext);
            } else {
                let class = self.cur.read_class()?;
                let record = Record::parse(&mut self.cur, name, r#type, class)?;

                records.push(record);
            }
        }

        Ok(records)
    }
}

impl Packet {
    pub fn from_slice(buf: &[u8]) -> io::Result<Packet> {
        PacketParser::new(&buf).parse()
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

    /// Adds an EDNS(0) extension record, as defined by [rfc6891](https://datatracker.ietf.org/doc/html/rfc6891)
    pub fn add_extension(&mut self, ext: Extension) {
        // Don't allow if self.additionals.len() + 1 > 255
        self.extension = Some(ext);
    }

    // Returns this DNS packet as a Vec<u8>.
    // TODO Rename this to_vec()
    pub fn as_vec(&self) -> io::Result<Vec<u8>> {
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

    /// Writes a Unicode domain name into the supplied `Vec<u8>`.
    ///
    /// Used for writing out a encoded ASCII domain name into a DNS packet. Will
    /// returns the Unicode domain name, as well as the length of this qname (ignoring
    /// any compressed pointers) in bytes.
    ///
    /// # Errors
    ///
    /// Will return a [`WriteError`] if the domain name is invalid.
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
                    bail!(InvalidData, "double dot found in domain name");
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
