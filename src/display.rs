//! Implements the Display trait for the various types, so they output
//! in `dig` style.
// Refer to https://github.com/tigeli/bind-utils/blob/master/bin/dig/dig.c for reference.

use crate::resource::MX;
use crate::resource::SOA;
use crate::resource::SRV;
use crate::Message;
use crate::Question;
use crate::Record;
use crate::Resource;
use crate::Stats;
use chrono::prelude::*;
use std::fmt;

/// Displays this message in a format resembling `dig` output.
impl fmt::Display for Message {
    // TODO There seems to be whitespace/newlines in this output. Fix.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_header(f)?;

        // ;; OPT PSEUDOSECTION:
        // ; EDNS: version: 0, flags:; udp: 512
        if let Some(e) = &self.extension {
            writeln!(f, ";; OPT PSEUDOSECTION:")?;
            // TODO Support the flags
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

        if let Some(stats) = &self.stats {
            stats.fmt(f)?;
        }

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

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, ";; Query time: {} msec", self.duration.as_millis())?; // TODO Support usec as well
        writeln!(f, ";; SERVER: {}", self.server)?;

        let start: chrono::DateTime<Local> = self.start.into();
        // ;; WHEN: Sat Jun 12 12:14:21 PDT 2021
        writeln!(f, ";; WHEN: {}", start.format("%a %b %-d %H:%M:%S %z %-Y"))?;
        writeln!(
            f,
            ";; MSG SIZE sent: {} rcvd: {}",
            self.request_size, self.response_size
        )
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
            r#type = self.r#type(),
            resource = self.resource,
        )
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
            Resource::TXT(txts) => {
                let output = txts
                    .iter()
                    .map(|txt| {
                        match std::str::from_utf8(&txt) {
                            // TODO Escape the " character (and maybe others)
                            Ok(txt) => txt,

                            // TODO Try our best to convert this to valid UTF, and use
                            // https://doc.rust-lang.org/std/str/struct.Utf8Error.html to show what we can.
                            Err(_e) => "invalid",
                        }
                    })
                    .collect::<Vec<&str>>()
                    .join(" ");

                write!(f, "{}", output)
            }
            Resource::MX(mx) => mx.fmt(f),
            Resource::SRV(srv) => srv.fmt(f),

            Resource::OPT => write!(f, "OPT (TODO)"),
            Resource::ANY => write!(f, "*"),
        }
    }
}

impl fmt::Display for MX {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // "10 aspmx.l.google.com."
        write!(
            f,
            "{preference} {exchange}",
            preference = self.preference,
            exchange = self.exchange,
        )
    }
}

impl fmt::Display for SOA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // "ns1.google.com. dns-admin.google.com. 376337657 900 900 1800 60"
        write!(
            f,
            "{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}",
            mname = self.mname,
            rname = self.rname,
            serial = self.serial,
            refresh = self.refresh.as_secs(),
            retry = self.retry.as_secs(),
            expire = self.expire.as_secs(),
            minimum = self.minimum.as_secs(),
        )
    }
}

impl fmt::Display for SRV {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // "5 0 389 ldap.google.com."
        write!(
            f,
            "{priority} {weight} {port} {name}",
            priority = self.priority,
            weight = self.weight,
            port = self.port,
            name = self.name,
        )
    }
}
