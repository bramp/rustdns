use crate::bail;
use crate::io::{CursorExt, DNSReadExt, SeekExt};
use crate::limits;
use crate::types::Record;
use crate::types::*;
use byteorder::{ReadBytesExt, BE};
use num_traits::FromPrimitive;
use rand::RngExt;
use std::convert::TryFrom;
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
    // TODO Once https://github.com/tokio-rs/bytes/issues/330 is resolved, consider
    // switching to bytes:Buf
    cur: Cursor<&'a [u8]>,
    m: Message,
}

impl<'a> MessageParser<'a> {
    fn new(buf: &[u8]) -> MessageParser<'_> {
        MessageParser {
            cur: Cursor::new(buf),
            m: Message::default(),
        }
    }

    /// Consume the [`MessageParser`] and returned the resulting Message.
    fn parse(mut self) -> io::Result<Message> {
        self.m.id = self.cur.read_u16::<BE>()?;

        let b = self.cur.read_u8()?;
        self.m.qr = QR::from(0b1000_0000 & b != 0);
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

                let ext = Extension::parse_internal(&mut self.cur, name, r#type)?;

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

            stats: None,
        }
    }
}

impl Message {
    /// Returns a random u16 suitable for the [`Message`] id field.
    ///
    /// This is generated with the [`rand::rngs::StdRng`] which is a suitable
    /// cryptographically secure pseudorandom number generator.
    pub fn random_id() -> u16 {
        rand::rng().random()
    }

    /// Decodes the supplied buffer and returns a [`Message`].
    ///
    /// # Errors
    ///
    /// Returns an error when the buffer is truncated, contains invalid DNS
    /// fields, or violates message, record, EDNS, or compression bounds.
    pub fn from_slice(buf: &[u8]) -> io::Result<Message> {
        MessageParser::new(buf).parse()
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
    ///
    /// Note: DNS servers typically do not support more than one question. There is ambiguity in how to handle
    /// rcode, etc. See [§4.1.2 of rfc1035] or <https://datatracker.ietf.org/doc/html/draft-bellis-dnsext-multi-qtypes-03>
    ///
    /// [§4.1.2 of rfc1035]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2.
    #[deprecated(note = "use try_add_question to handle invalid domains")]
    ///
    /// # Panics
    ///
    /// Panics when `domain` cannot be normalized. Prefer [`Self::try_add_question`]
    /// for caller-provided input.
    pub fn add_question(&mut self, domain: &str, r#type: Type, class: Class) {
        self.try_add_question(domain, r#type, class)
            .expect("invalid domain");
    }

    /// Adds a question to the message, returning an error if the domain is invalid.
    pub fn try_add_question(
        &mut self,
        domain: &str,
        r#type: Type,
        class: Class,
    ) -> Result<(), crate::Error> {
        let domain = self
            .normalise_domain(domain)
            .map_err(|error| crate::Error::InvalidArgument(error.to_string()))?;
        let ascii_domain = idna::domain_to_ascii(&domain)
            .map_err(|error| crate::Error::InvalidArgument(error.to_string()))?;

        limits::validate_ascii_name(&ascii_domain)
            .map_err(|error| crate::Error::InvalidArgument(error.to_string()))?;

        // TODO Don't allow more than 255 questions.
        let q = Question {
            name: domain,
            r#type,
            class,
        };

        self.questions.push(q);

        Ok(())
    }

    /// Sets the EDNS(0) extension record, as defined by [rfc6891].
    ///
    /// Use this when a query should advertise EDNS support, a larger UDP payload
    /// size, DNSSEC OK, or EDNS options. DNS messages can contain at most one
    /// EDNS(0) OPT record, so calling this again replaces the previous extension.
    /// The extension is encoded by [`Self::to_vec`].
    ///
    /// ```rust
    /// use rustdns::{EdnsOption, Extension, Message};
    /// use std::time::Duration;
    ///
    /// let mut message = Message::default();
    /// message.set_extension(
    ///     Extension::default()
    ///         .with_option(EdnsOption::nsid(Vec::new()))
    ///         .with_option(EdnsOption::client_subnet(
    ///             "192.0.2.129".parse().unwrap(), 24, 0
    ///         ))
    ///         .with_option(EdnsOption::cookie(*b"client01"))
    ///         .with_option(EdnsOption::tcp_keepalive(Some(Duration::from_secs(30))))
    ///         .with_option(EdnsOption::padding(16))
    ///         .with_option(EdnsOption::unknown(65001, vec![1, 2, 3])),
    /// );
    /// ```
    ///
    /// [rfc6891]: https://datatracker.ietf.org/doc/html/rfc6891
    pub fn set_extension(&mut self, ext: Extension) {
        // Don't allow if self.additionals.len() + 1 > 255
        self.extension = Some(ext);
    }

    /// Adds an EDNS(0) extension record, as defined by [rfc6891].
    ///
    /// This is kept for compatibility. Prefer [`Self::set_extension`] because a
    /// DNS message can contain at most one EDNS(0) extension record, and calling
    /// this method replaces any previous extension.
    ///
    /// [rfc6891]: https://datatracker.ietf.org/doc/html/rfc6891
    #[deprecated(
        note = "use set_extension because a message can contain at most one EDNS(0) extension"
    )]
    pub fn add_extension(&mut self, ext: Extension) {
        self.set_extension(ext);
    }

    /// Encodes this DNS [`Message`] as a [`Vec<u8>`] ready to be sent, as defined by [rfc1035].
    ///
    /// # Errors
    ///
    /// Returns an error when a domain is invalid, a name exceeds DNS wire limits,
    /// or the message contains record sections that are not yet supported for encoding.
    ///
    /// [rfc1035]: https://datatracker.ietf.org/doc/html/rfc1035
    pub fn to_vec(&self) -> io::Result<Vec<u8>> {
        let mut req = Vec::<u8>::with_capacity(512);
        self.append_to_vec(&mut req)?;
        Ok(req)
    }

    /// Appends this DNS [`Message`] as DNS wire-format bytes to `buf`.
    ///
    /// # Errors
    ///
    /// Returns an error when a domain is invalid, a name exceeds DNS wire limits,
    /// or the message contains record sections that are not yet supported for encoding.
    pub fn append_to_vec(&self, buf: &mut Vec<u8>) -> io::Result<()> {
        buf.extend_from_slice(&self.id.to_be_bytes());

        let mut b = 0_u8;
        b |= if bool::from(self.qr) { 0b1000_0000 } else { 0 };
        b |= ((self.opcode as u8) << 3) & 0b0111_1000;
        b |= if self.aa { 0b0000_0100 } else { 0 };
        b |= if self.tc { 0b0000_0010 } else { 0 };
        b |= if self.rd { 0b0000_0001 } else { 0 };
        buf.push(b);

        let mut b = 0_u8;
        b |= if self.ra { 0b1000_0000 } else { 0 };
        b |= if self.z { 0b0100_0000 } else { 0 };
        b |= if self.ad { 0b0010_0000 } else { 0 };
        b |= if self.cd { 0b0001_0000 } else { 0 };
        b |= (self.rcode as u8) & 0b0000_1111;

        buf.push(b);

        limits::validate_section_count(self.questions.len())?;
        limits::validate_section_count(self.answers.len())?;
        limits::validate_section_count(self.authoritys.len())?;
        limits::validate_section_count(self.additionals.len() + self.extension.is_some() as usize)?;

        let ar_count = self.additionals.len() as u16 + self.extension.is_some() as u16;

        buf.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.authoritys.len() as u16).to_be_bytes());
        buf.extend_from_slice(&ar_count.to_be_bytes());

        for question in &self.questions {
            question.append_to_vec(buf)?;
        }

        for record in self
            .answers
            .iter()
            .chain(self.authoritys.iter())
            .chain(self.additionals.iter())
        {
            record.append_to_vec(buf)?;
        }

        if let Some(e) = &self.extension {
            e.append_to_vec(buf)?
        }

        // TODO Replace this stateless writer with a message encoder that handles
        // message-size limits, EDNS-aware sizing, and canonical DNSSEC-style encoding.

        Ok(())
    }

    /// Appends a Unicode domain name as DNS wire-format bytes to `buf`.
    ///
    /// Used for writing out a encoded ASCII domain name into a DNS message. Will
    /// returns the Unicode domain name, as well as the length of this qname (ignoring
    /// any compressed pointers) in bytes.
    ///
    // TODO Support DNS name compression through message-level encoder state.
    pub(crate) fn append_qname_to_vec(buf: &mut Vec<u8>, domain: &str) -> io::Result<()> {
        // Decode this label into the original unicode.
        // TODO Switch to using our own idna::Config. (but we can't use disallowed_by_std3_ascii_rules).
        let domain = match idna::domain_to_ascii(domain) {
            Err(e) => {
                bail!(InvalidData, "invalid dns name '{0}': {1}", domain, e);
            }
            Ok(domain) => domain,
        };

        if !domain.is_empty() && domain != "." {
            limits::validate_ascii_name(&domain)?;
            for label in domain.split_terminator('.') {
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

impl Question {
    /// Appends this question as DNS wire-format bytes to `buf`.
    ///
    /// # Errors
    ///
    /// Returns an error if the question name cannot be represented in DNS wire
    /// format.
    pub fn append_to_vec(&self, buf: &mut Vec<u8>) -> io::Result<()> {
        Message::append_qname_to_vec(buf, &self.name)?;
        buf.extend_from_slice(&(self.r#type as u16).to_be_bytes());
        buf.extend_from_slice(&(self.class as u16).to_be_bytes());
        Ok(())
    }
}

impl TryFrom<&[u8]> for Message {
    type Error = io::Error;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(buf)
    }
}

impl Extension {
    /// Parses an EDNS(0) OPT record from a DNS message.
    ///
    /// # Errors
    ///
    /// Returns an error when the record is not an OPT record, does not use the
    /// root name, is truncated, declares options beyond the remaining message,
    /// or contains malformed known options.
    #[deprecated(note = "this low-level cursor parser is retained for compatibility")]
    pub fn parse(cur: &mut Cursor<&[u8]>, domain: String, r#type: Type) -> io::Result<Extension> {
        Self::parse_internal(cur, domain, r#type)
    }

    /// Parses an EDNS(0) OPT record from a DNS message.
    ///
    /// # Errors
    ///
    /// Returns an error when the record is not an OPT record, does not use the
    /// root name, is truncated, declares options beyond the remaining message,
    /// or contains malformed known options.
    pub(crate) fn parse_internal(
        cur: &mut Cursor<&[u8]>,
        domain: String,
        r#type: Type,
    ) -> io::Result<Extension> {
        if r#type != Type::OPT {
            bail!(InvalidInput, "expected EDNS(0) OPT record");
        }

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

        let rd_len = cur.read_u16::<BE>()?;
        if cur.remaining()? < u64::from(rd_len) {
            bail!(InvalidData, "EDNS(0) data exceeds the remaining message");
        }
        let rd_len = usize::from(rd_len);
        let pos = usize::try_from(cur.position()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "EDNS(0) cursor position is invalid",
            )
        })?;
        let end = pos
            .checked_add(rd_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "EDNS(0) length overflow"))?;
        let mut option_cur = cur.sub_cursor(pos, end)?;
        let mut options = Vec::new();
        while option_cur.position() < rd_len as u64 {
            options.push(EdnsOption::parse(&mut option_cur)?);
        }
        cur.consume(rd_len);

        Ok(Extension {
            payload_size,
            extend_rcode,
            version,
            dnssec_ok,
            options,
        })
    }

    /// Appends this EDNS(0) extension as DNS wire-format bytes to `buf`.
    ///
    /// # Errors
    ///
    /// Returns an error if the extension cannot be represented in the output
    /// message.
    pub fn append_to_vec(&self, buf: &mut Vec<u8>) -> io::Result<()> {
        buf.push(0); // A single "." domain name                          // 0-1
        buf.extend_from_slice(&(Type::OPT as u16).to_be_bytes()); // 1-3
        buf.extend_from_slice(&self.payload_size.to_be_bytes()); // 3-5

        buf.push(self.extend_rcode); // 5-6
        buf.push(self.version); // 6-7

        let mut b = 0_u8;
        b |= if self.dnssec_ok { 0b1000_0000 } else { 0 };

        // 16 bits
        buf.push(b);
        buf.push(0);

        let mut option_data = Vec::new();
        for option in &self.options {
            option.append_to_vec(&mut option_data)?;
        }

        let option_data_len = u16::try_from(option_data.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "EDNS(0) option data is too long",
            )
        })?;
        buf.extend_from_slice(&option_data_len.to_be_bytes());
        buf.extend_from_slice(&option_data);

        Ok(())
    }

    /// Writes this EDNS(0) extension to a DNS message.
    ///
    /// # Errors
    ///
    /// Returns an error if the extension cannot be represented in the output
    /// message.
    #[deprecated(note = "use append_to_vec")]
    pub fn write(&self, buf: &mut Vec<u8>) -> io::Result<()> {
        self.append_to_vec(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::Message;
    use crate::{
        Class, EdnsOption, Extension, Question, Record, Resource, Type, MX, SOA, SRV, TXT,
    };
    use std::convert::TryFrom;

    #[test]
    fn truncated_dns_messages_return_errors() {
        let cases = [
            vec![],
            vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
            vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'a'],
        ];

        for input in cases {
            assert!(
                Message::from_slice(&input).is_err(),
                "accepted truncated input"
            );
        }
    }

    #[test]
    fn truncated_edns_options_return_error() {
        let input = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // header, one additional record
            0, 0, 41, 0x10, 0, 0, 0, 0, 0, 1, // OPT with one byte declared
        ];

        assert!(Message::from_slice(&input).is_err());
    }

    #[test]
    fn to_vec_encodes_edns_options() {
        let mut message = Message {
            id: 0x1234,
            ..Default::default()
        };
        message.set_extension(
            Extension::default()
                .with_option(EdnsOption::nsid(b"abc".to_vec()))
                .with_option(EdnsOption::client_subnet(
                    "192.0.2.129".parse().unwrap(),
                    24,
                    0,
                )),
        );

        let encoded = message.to_vec().expect("EDNS options should encode");

        assert_eq!(
            encoded,
            vec![
                0x12, 0x34, // id
                0x01, 0x20, // flags
                0x00, 0x00, // questions
                0x00, 0x00, // answers
                0x00, 0x00, // authorities
                0x00, 0x01, // additionals
                0x00, // root name
                0x00, 0x29, // OPT
                0x10, 0x00, // payload size
                0x00, // extended rcode
                0x00, // version
                0x00, 0x00, // flags
                0x00, 0x12, // option data length
                0x00, 0x03, 0x00, 0x03, b'a', b'b', b'c', // NSID
                0x00, 0x08, 0x00, 0x07, 0x00, 0x01, 24, 0, 192, 0, 2, // ECS
            ]
        );
        let decoded = Message::from_slice(&encoded).expect("encoded message should parse");
        assert_eq!(
            decoded.extension.expect("extension should parse").options,
            message.extension.unwrap().options
        );
    }

    #[test]
    fn append_to_vec_appends_encoded_message() {
        let mut message = Message {
            id: 0x1234,
            ..Default::default()
        };
        message
            .try_add_question("example.com", Type::A, Class::Internet)
            .expect("question should be valid");

        let encoded = message.to_vec().expect("message should encode");
        let mut buf = vec![0xaa, 0xbb];
        message
            .append_to_vec(&mut buf)
            .expect("message should append to buffer");

        assert_eq!(&buf[..2], &[0xaa, 0xbb]);
        assert_eq!(&buf[2..], encoded);

        let decoded = Message::try_from(&buf[2..]).expect("appended message should decode");
        assert_eq!(decoded.questions, message.questions);
    }

    #[test]
    fn question_append_to_vec_encodes_question() {
        let question = Question {
            name: "example.com.".to_string(),
            r#type: Type::A,
            class: Class::Internet,
        };

        let mut buf = Vec::new();
        question
            .append_to_vec(&mut buf)
            .expect("question should encode");

        assert_eq!(
            buf,
            vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,]
        );
    }

    #[test]
    fn to_vec_encodes_extension_options() {
        let mut message = Message {
            id: 0x1234,
            ..Default::default()
        };
        message.set_extension(Extension::default().with_option(EdnsOption::nsid(Vec::new())));

        let encoded = message
            .to_vec()
            .expect("EDNS extension options should encode");

        assert_eq!(&encoded[10..12], &[0x00, 0x01]);
        assert_eq!(
            &encoded[12..],
            &[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 4, 0, 3, 0, 0]
        );
    }

    #[test]
    fn to_vec_rejects_malformed_edns_options() {
        let mut message = Message::default();
        message.set_extension(Extension::default().with_option(EdnsOption::client_subnet(
            "192.0.2.1".parse().unwrap(),
            33,
            0,
        )));

        assert!(message.to_vec().is_err());
    }

    #[test]
    fn truncated_record_data_returns_error() {
        let input = [
            0, 0, 0, 0, 0, 0, 0, 1, // header, one answer
            0, 0, 1, 0, 0, 0, 0, 0, 0, 4, // A record declares four bytes
            192, 0, 2, // but supplies only three
        ];

        assert!(Message::from_slice(&input).is_err());
    }

    #[test]
    fn try_add_question_rejects_invalid_domain() {
        let mut message = Message::default();
        let invalid_domain = format!("{}.example.com", "a".repeat(64));

        assert!(message
            .try_add_question(&invalid_domain, Type::A, Class::Internet)
            .is_err());
        assert!(message.questions.is_empty());
    }

    #[test]
    fn to_vec_rejects_oversized_domain_name() {
        let domain = vec!["a".repeat(63); 4].join(".");
        let mut message = Message::default();
        message.questions.push(Question {
            name: domain,
            r#type: Type::A,
            class: Class::Internet,
        });

        assert!(message.to_vec().is_err());
    }

    #[test]
    fn to_vec_round_trips_records() {
        let mut message = Message::default();
        message.answers.push(Record::new(
            "example.com.",
            Class::Internet,
            std::time::Duration::from_secs(60),
            Resource::A("192.0.2.1".parse().unwrap()),
        ));

        let encoded = message.to_vec().expect("records should be encoded");
        let decoded = Message::from_slice(&encoded).expect("encoded records should parse");

        assert_eq!(decoded.answers, message.answers);
    }

    #[test]
    fn to_vec_round_trips_supported_resources() {
        let resources = vec![
            Resource::A("192.0.2.1".parse().unwrap()),
            Resource::AAAA("2001:db8::1".parse().unwrap()),
            Resource::CNAME("target.example.com.".to_string()),
            Resource::NS("ns.example.com.".to_string()),
            Resource::PTR("ptr.example.com.".to_string()),
            Resource::TXT(TXT::from("text")),
            Resource::SPF(TXT::from("v=spf1 -all")),
            Resource::MX(MX {
                preference: 10,
                exchange: "mail.example.com.".to_string(),
            }),
            Resource::SOA(SOA {
                mname: "ns.example.com.".to_string(),
                rname: "admin@example.com".to_string(),
                serial: 1,
                refresh: std::time::Duration::from_secs(2),
                retry: std::time::Duration::from_secs(3),
                expire: std::time::Duration::from_secs(4),
                minimum: std::time::Duration::from_secs(5),
            }),
            Resource::SRV(SRV {
                priority: 1,
                weight: 2,
                port: 443,
                name: "service.example.com.".to_string(),
            }),
        ];

        for resource in resources {
            let mut message = Message::default();
            message.answers.push(Record::new(
                "example.com.",
                Class::Internet,
                std::time::Duration::from_secs(60),
                resource.clone(),
            ));

            let encoded = message.to_vec().expect("resource should be encoded");
            let decoded = Message::from_slice(&encoded).expect("encoded resource should parse");

            let decoded_resource = match &decoded.answers[0].resource {
                Resource::SOA(soa) => Resource::SOA(SOA {
                    rname: soa.rname.trim_end_matches('.').to_string(),
                    ..soa.clone()
                }),
                resource => resource.clone(),
            };
            assert_eq!(decoded_resource, resource);
        }
    }
}
