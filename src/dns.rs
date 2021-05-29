use crate::errors::ParseError;
use crate::errors::WriteError;
use std::convert::TryInto;
use std::fmt;
use std::str;

use crate::resource::Record;
use crate::types::*;
use crate::parse_error;
use crate::as_array;

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
                        qname.push_str( s );
                        qname.push('.');
                    }
                }

                offset += len;
            },

            // Compression
            0xC0 => {
                let b2 = *match buf.get(offset) {
                    Some(b) => b,
                    None => return parse_error!("qname too short missing compressed pointer"),
                } as usize;

                let ptr = (len & !0xC0) << 8 | b2;
                offset += 1;

                if ptr >= start {
                    return parse_error!("qname invalid compressed pointer pointing to future bytes");
                }

                // Read the qname from elsewhere in the packet ignoring
                // the length of that segment.
                qname += &read_qname(buf, ptr)?.0;
                break;
            },

             // Unknown
            _ => {
                return parse_error!("qname unsupported compression type {0:b}", len & 0xC0)
            }
        }
    }

    Ok((qname, offset - start))
}

pub struct Question {
    pub header: QuestionHeader,
    pub name: String,
}

pub struct Answer {
    pub header: AnswerHeader,
    pub name: String,
    pub record: Record,
}

pub struct DnsPacket {
    // TODO Should this just be called dns::Packet?
    pub header: Header,

    pub questions: Vec<Question>,
    pub answers: Vec<Answer>,
    pub authoritys: Vec<Answer>,
    pub additionals: Vec<Answer>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: Header::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authoritys: Vec::new(),
            additionals: Vec::new(),
        }
    }

    pub fn from_slice(buf: &[u8]) -> Result<DnsPacket, ParseError> {
        let mut offset = 0;

        // TODO I think this copies the buffer, it would be nice if it
        // could just sit ontop of buf
        // TODO Check for error!
        let header = Header::from_bytes(*as_array![buf, 0, 12]);
        offset += 12;

        let (questions, len) = DnsPacket::read_questions(&buf, offset, header.qd_count())?;
        offset += len;

        let (answers, len) = DnsPacket::read_answers(&buf, offset, header.an_count())?;
        offset += len;

        let (authoritys, len) = DnsPacket::read_answers(&buf, offset, header.ns_count())?;
        offset += len;

        let (additionals, _) = DnsPacket::read_answers(&buf, offset, header.ar_count())?;

        Ok(DnsPacket {
            //buf,
            header,
            questions,
            answers,
            authoritys,
            additionals,
        })
    }

    fn read_questions(
        buf: &[u8],
        start: usize,
        count: u16,
    ) -> Result<(Vec<Question>, usize), ParseError> {
        let mut offset = start;
        let mut questions = Vec::with_capacity(count.into());
        for _ in 0..count {
            let (name, len) = read_qname(&buf, offset)?;
            offset += len;

            // TODO Check for errors!
            let header = QuestionHeader::from_bytes(*as_array![buf, offset, 4]);
            offset += 4;

            questions.push(Question { header, name });
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

            // TODO Check for bounds and errors!
            let header = AnswerHeader::from_bytes(*as_array![buf, offset, 10]);
            offset += 10; // a.bytes.len();

            // TODO Check for errors, and skip over them if possible!
            let record = Record::from_slice(
                header.r#type(),
                header.class(),
                &buf,
                offset,
                header.rd_length() as usize,
            )?;

            offset += header.rd_length() as usize;
            answers.push(Answer {
                header,
                name,
                record,
            });
        }

        Ok((answers, offset - start))
    }

    fn update_counts(&mut self) {
        self.header
            .set_qd_count(self.questions.len().try_into().unwrap()); // TODO Don't panic
        self.header
            .set_an_count(self.answers.len().try_into().unwrap()); // TODO Don't panic
        self.header
            .set_ns_count(self.authoritys.len().try_into().unwrap()); // TODO Don't panic
        self.header
            .set_ar_count(self.additionals.len().try_into().unwrap()); // TODO Don't panic
    }

    pub fn add_question(&mut self, domain: &str, qtype: QType, qclass: QClass) {
        let q = Question {
            name: domain.to_string(),
            header: QuestionHeader::new().with_qtype(qtype).with_qclass(qclass),
        };

        self.questions.push(q);
        self.update_counts();
    }

    // Returns this DNS packet as a Vec<u8>.
    pub fn as_vec(&mut self) -> Result<Vec<u8>, WriteError> {
        let mut req = Vec::<u8>::with_capacity(512); // TODO Guess the best size

        self.update_counts();

        req.extend_from_slice(&self.header.into_bytes());

        for question in &self.questions {
            DnsPacket::write_qname(&mut req, &question.name)?;
            req.extend_from_slice(&question.header.into_bytes());
        }

        // TODO Add answers, etc types.
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

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45463
        writeln!(
            f,
            ";; ->>HEADER<<- opcode: {opcode}, status: {rcode}, id: {id}",
            opcode = self.opcode(),
            rcode = self.rcode(),
            id = self.id(),
        )?;

        let mut flags = String::new();

        if let QR::Response = self.qr() {
            flags.push_str(" qr")
        }
        if self.aa() {
            flags.push_str(" aa")
        }
        if self.tc() {
            flags.push_str(" tc")
        }
        if self.rd() {
            flags.push_str(" rd")
        }
        if self.ra() {
            flags.push_str(" ra")
        }
        if self.ad() {
            flags.push_str(" ad")
        }
        if self.cd() {
            flags.push_str(" cd")
        }

        // ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
        writeln!(f, ";; flags:{flags}; QUERY: {qd_count}, ANSWER: {an_count}, AUTHORITY: {ns_count}, ADDITIONAL: {ar_count}", 
            flags = flags,
            qd_count = self.qd_count(),
            an_count = self.an_count(),
            ns_count = self.ns_count(),
            ar_count = self.ar_count(),
        )?;

        writeln!(f)
    }
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "; {name:<18}      {qclass:4} {qtype:6}\n",
            name = self.name,
            qclass = self.header.qclass(),
            qtype = self.header.qtype()
        )
    }
}

impl fmt::Display for Answer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "{name:<20} {ttl:>4} {class:4} {type:6} {record}",
            name = self.name,
            ttl = self.header.ttl(),
            class = self.header.class(),
            r#type = self.header.r#type(),
            record = self.record,
        )
    }
}

impl fmt::Display for DnsPacket {
    // TODO Convert to dig format
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.header.fmt(f)?;

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
