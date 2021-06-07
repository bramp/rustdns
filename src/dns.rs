use crate::bail;
use crate::io::{DNSReadExt, SeekExt};
use crate::types::Record;
use crate::types::*;
use byteorder::{ReadBytesExt, BE};
use num_traits::FromPrimitive;
use rand::Rng;
use std::io;
use std::io::BufRead;
use std::io::Cursor;

#[derive(Copy, Clone, PartialEq)]
enum RecordSection {
    Answers,
    Authorities,
    Additionals,
}

/// A helper class to hold state while the parsing is happening.
// TODO add list of parse errors
pub(crate) struct MessageParser<'a> {
    cur: Cursor<&'a [u8]>,

    m: Message,
}

impl<'a> MessageParser<'a> {
    fn new(buf: &[u8]) -> MessageParser {
        MessageParser {
            cur: Cursor::new(buf),
            m: Message::default(),
        }
    }

    /// Consume the [`MessageParser`] and returned the resulting Message.
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

            if section == RecordSection::Additionals && r#type == Type::OPT {
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

/// Defaults to a [`Message`] with sensibles values for querying.
impl Default for Message {
    fn default() -> Self {
        Message {
            id: Message::random_id(),
            rd: true,
            tc: false,
            aa: false,
            opcode: Opcode::Query,
            qr: QR::Query,
            rcode: Rcode::NoError,
            cd: false,
            ad: true,
            z: false,
            ra: false,

            questions: Vec::default(),
            answers: Vec::default(),
            authoritys: Vec::default(),
            additionals: Vec::default(),
            extension: None,
        }
    }
}

impl Message {
    /// Returns a random u16 suitable for the [`Message`] id field.
    ///
    /// This is generated with the [`rand::rngs::StdRng`] which is a suitable
    /// cryptographically secure pseudorandom number generator.
    pub fn random_id() -> u16 {
        rand::thread_rng().gen()
    }

    /// Decodes the supplied buffer and returns a [`Message`].
    pub fn from_slice(buf: &[u8]) -> io::Result<Message> {
        MessageParser::new(&buf).parse()
    }

    /// Takes a unicode domain, converts to ascii, and back to unicode.
    /// This has the effective of normalising it, so its easier to compare
    /// what was queried, and what was returned.
    fn normalise_domain(&mut self, domain: &str) -> Result<String, idna::Errors> {
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

    /// Adds a question to the message.
    pub fn add_question(&mut self, domain: &str, r#type: Type, class: Class) {
        let domain = self.normalise_domain(domain).expect("invalid domain"); // TODO fix

        // TODO Don't allow more than 255 questions.
        let q = Question {
            name: domain,
            r#type,
            class,
        };

        self.questions.push(q);
    }

    /// Adds a EDNS(0) extension record, as defined by [rfc6891](https://datatracker.ietf.org/doc/html/rfc6891).
    pub fn add_extension(&mut self, ext: Extension) {
        // Don't allow if self.additionals.len() + 1 > 255
        self.extension = Some(ext);
    }

    /// Encodes this DNS [`Message`] as a [`Vec<u8>`] ready to be sent, as defined by [rfc1035].
    ///
    /// [rfc1035]: https://datatracker.ietf.org/doc/html/rfc1035
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

    /// Writes a Unicode domain name into the supplied [`Vec<u8>`].
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

impl Extension {
    pub fn parse(cur: &mut Cursor<&[u8]>, domain: String, r#type: Type) -> io::Result<Extension> {
        assert!(r#type == Type::OPT);

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

        // TODO implement this
        let rd_len = cur.read_u16::<BE>()?;
        cur.consume(rd_len.into());

        Ok(Extension {
            payload_size,
            extend_rcode,
            version,
            dnssec_ok,
        })
    }

    pub fn write(&self, buf: &mut Vec<u8>) -> io::Result<()> {
        buf.push(0); // A single "." domain name                          // 0-1
        buf.extend_from_slice(&(Type::OPT as u16).to_be_bytes()); // 1-3
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
