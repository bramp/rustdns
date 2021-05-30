use crate::errors::ParseError;
use crate::errors::WriteError;
use num_traits::FromPrimitive;
use std::convert::TryInto;
use std::fmt;
use std::str;

use crate::as_array;
use crate::parse_error;
use crate::resource::Record;
use crate::types::*;

pub(crate) fn read_qname(buf: &[u8], start: usize) -> Result<(String, usize), ParseError> {
    let mut qname = String::new();
    let mut offset = start;

    loop {
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
                match buf.get(offset..offset + len) {
                    None => return parse_error!("qname too short"), // TODO standardise the too short error
                    Some(label) => {
                        // TODO I don't think this is meant to be UTF-8.
                        let s = match str::from_utf8(label) {
                            Ok(s) => s,
                            Err(e) => return parse_error!("qname invalid label: {}", e),
                        };
                        qname.push_str(s);
                        qname.push('.');
                    }
                }

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
                qname += &read_qname(buf, ptr)?.0;
                break;
            }

            // Unknown
            _ => return parse_error!("qname unsupported compression type {0:b}", len & 0xC0),
        }
    }

    Ok((qname, offset - start))
}

pub struct Question {
    pub name: String,
    pub r#type: QType,
    pub class: QClass,
}

pub struct Answer {
    pub name: String,

    pub r#type: QType,
    pub class: QClass, // TODO Really a Class (which is a subset of QClass)

    // The number of seconds that the resource record may be cached
    // before the source of the information should again be consulted.
    // Zero is interpreted to mean that the RR can only be used for the
    // transaction in progress.
    pub ttl: u32,

    // Specifies the length in octets of the RDATA field.
    pub rd_length: u16,

    pub record: Record,
}

#[derive(Default)]
pub struct Packet {
    // A 16 bit identifier assigned by the program that generates any kind of
    // query. This identifier is copied the corresponding reply and can be used
    // by the requester to match up replies to outstanding queries.
    pub id: u16,

    // Recursion Desired - this bit directs the name server to pursue the query
    // recursively.
    pub rd: bool, // bit 7

    // Truncation - specifies that this message was truncated.
    pub tc: bool, // bit 6

    // Authoritative Answer - Specifies that the responding name server is an
    // authority for the domain name in question section.
    pub aa: bool, // bit 5

    // Specifies kind of query in this message. 0 represents a standard query.
    // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
    pub opcode: Opcode, // bit 1-4

    // TODO Change with enum.
    // Specifies whether this message is a query (0), or a response (1).
    pub qr: QR, // bit 0

    // Response code.
    pub rcode: Rcode, // bit 4-7

    // Checking Disabled - [RFC4035][RFC6840][RFC Errata 4927]
    pub cd: bool, // bit 3

    // Authentic Data - [RFC4035][RFC6840][RFC Errata 4924]
    pub ad: bool, // bit 2

    // Z Reserved for future use. You must set this field to 0.
    pub z: bool, // bit 1

    // Recursion Available - this be is set or cleared in a response, and
    // denotes whether recursive query support is available in the name server.
    pub ra: bool, // bit 0

    pub questions: Vec<Question>,
    pub answers: Vec<Answer>,
    pub authoritys: Vec<Answer>,
    pub additionals: Vec<Answer>,
}

impl Packet {
    /*
    pub fn new() -> Packet {
        Packet {
            questions: Vec::new(),
            answers: Vec::new(),
            authoritys: Vec::new(),
            additionals: Vec::new(),

            ..Default::default()
        }
    }
    */

    pub fn from_slice(buf: &[u8]) -> Result<Packet, ParseError> {
        // TODO Maybe we should take ownership of the buf
        // Then read_qname, and similar is "easier".

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

        let (answers, len) = Packet::read_answers(&buf, offset, an_count)?;
        offset += len;

        let (authoritys, len) = Packet::read_answers(&buf, offset, ns_count)?;
        offset += len;

        let (additionals, _) = Packet::read_answers(&buf, offset, ar_count)?;
        offset += len;

        if offset != buf.len() {
            return parse_error!("failed to read full packet");
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
        })
    }

    fn read_type_class(buf: [u8; 4]) -> Result<(QType, QClass), ParseError> {
        let r#type = u16::from_be_bytes(*as_array![buf, 0, 2]);
        let r#type = match FromPrimitive::from_u16(r#type) {
            Some(t) => t,
            None => return parse_error!("invalid Type({})", r#type),
        };

        let class = u16::from_be_bytes(*as_array![buf, 2, 2]);
        let class = match FromPrimitive::from_u16(class) {
            Some(t) => t,
            None => return parse_error!("invalid Class({})", class),
        };

        Ok((r#type, class))
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

            let (r#type, class) = Packet::read_type_class(*as_array![buf, offset, 4])?;
            offset += 4;

            questions.push(Question {
                name,
                r#type,
                class,
            });
        }

        Ok((questions, offset - start))
    }

    fn read_answers(
        buf: &[u8],
        start: usize,
        count: u16,
    ) -> Result<(Vec<Answer>, usize), ParseError> {
        let mut offset = start;
        let mut answers = Vec::with_capacity(count.into());

        for _ in 0..count {
            let (name, len) = read_qname(&buf, offset)?;
            offset += len;

            let (r#type, class) = Packet::read_type_class(*as_array![buf, offset, 4])?;
            offset += 4;

            let ttl = u32::from_be_bytes(*as_array![buf, offset, 4]);
            offset += 4;

            let rd_length = u16::from_be_bytes(*as_array![buf, offset, 2]);
            offset += 2;

            // TODO Check for errors, and skip over them if possible!
            let record = Record::from_slice(r#type, class, &buf, offset, rd_length as usize)?;
            offset += rd_length as usize;

            answers.push(Answer {
                name,

                r#type,
                class,

                ttl,
                rd_length,

                record,
            });
        }

        Ok((answers, offset - start))
    }

    // TODO Consider accepting just a normal Question.
    pub fn add_question(&mut self, domain: &str, r#type: QType, class: QClass) {
        // TODO Don't allow more than 255 questions.

        let q = Question {
            name: domain.to_string(),
            r#type,
            class,
        };

        self.questions.push(q);
    }

    // Returns this DNS packet as a Vec<u8>.
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

        req.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        req.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        req.extend_from_slice(&(self.authoritys.len() as u16).to_be_bytes());
        req.extend_from_slice(&(self.additionals.len() as u16).to_be_bytes());

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

        // TODO if the vector is too long, truncate the request.

        Ok(req)
    }

    fn write_qname(buf: &mut Vec<u8>, domain: &str) -> Result<(), WriteError> {
        for part in domain.split_terminator('.') {
            assert!(part.len() < 64); // TODO

            if part.is_empty() {
                return Err(WriteError {
                    msg: format!("invalid dns name '{0}'", domain),
                });
            }

            buf.push(part.len() as u8);
            buf.extend_from_slice(part.as_bytes());
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

        writeln!(f, ";; flags:{flags}; QUERY: {qd_count}, ANSWER: {an_count}, AUTHORITY: {ns_count}, ADDITIONAL: {ar_count}", 
            flags = flags,
            qd_count = self.questions.len(),
            an_count = self.answers.len(),
            ns_count = self.authoritys.len(),
            ar_count = self.additionals.len(),
        )?;

        writeln!(f)
    }
}

impl fmt::Display for Packet {
    // TODO Convert to dig format
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_header(f)?;

        // TODO ;; OPT PSEUDOSECTION:

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
            "; {name:<18}      {qclass:4} {qtype:6}\n",
            name = self.name,
            qclass = self.class,
            qtype = self.r#type,
        )
    }
}

impl fmt::Display for Answer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "{name:<20} {ttl:>4} {class:4} {type:6} {record}",
            name = self.name,
            ttl = self.ttl,
            class = self.class,
            r#type = self.r#type,
            record = self.record,
        )
    }
}
