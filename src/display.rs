//! Implements the Display trait for the various types, so they output
//! in `dig` style.
// Refer to https://github.com/tigeli/bind-utils/blob/master/bin/dig/dig.c for reference.

use crate::resource::TXT;
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
            Resource::TXT(txts) | Resource::SPF(txts) => txts.fmt(f),
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

        // It's arguable that dns-admin@google.com looks better, but
        // for now we'll keep the format dns-admin.google.com.
        let rname = match Self::email_to_rname(&self.rname) {
            Ok(name) => name,
            Err(_) => self.rname.to_owned(), // Ignore the error
        };

        write!(
            f,
            "{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}",
            mname = self.mname,
            rname = rname,
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

impl fmt::Display for TXT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = self.0
            .iter()
            .map(|txt| {
                match std::str::from_utf8(txt) {
                    // TODO Escape the " character (and maybe others)
                    Ok(txt) => "\"".to_owned() + txt + "\"",

                    // TODO Try our best to convert this to valid UTF, and use
                    // https://doc.rust-lang.org/std/str/struct.Utf8Error.html to show what we can.
                    Err(_e) => "invalid".to_string(),
                }
            })
            .collect::<Vec<String>>()
            .join(" ");

        write!(f, "{}", output)
    }
}

#[cfg(test)]
mod tests {
    use crate::TXT;
    use crate::Resource;
    use crate::MX;
    use crate::SOA;
    use crate::SRV;
    use core::time::Duration;
    use pretty_assertions::assert_eq;

    lazy_static! {
        static ref DISPLAY_TESTS : Vec<(Resource, &'static str)> = {
            vec![
                (
                    Resource::A("172.217.164.100".parse().unwrap()),
                    "172.217.164.100",
                ),
                (
                    Resource::AAAA("2607:f8b0:4005:805::2004".parse().unwrap()),
                    "2607:f8b0:4005:805::2004",
                ),
                (
                    Resource::CNAME("code.l.google.com.".to_string()),
                    "code.l.google.com.",
                ),
                (
                    Resource::NS("ns4.google.com.".to_string()),
                    "ns4.google.com.",
                ),
                (Resource::PTR("dns.google.".to_string()), "dns.google."),
                (
                    Resource::SOA(SOA {
                        mname: "ns1.google.com.".to_string(),
                        rname: "dns-admin@google.com.".to_string(),

                        serial: 379031418,

                        refresh: Duration::from_secs(900),
                        retry: Duration::from_secs(900),
                        expire: Duration::from_secs(1800),
                        minimum: Duration::from_secs(60),
                    }),
                    "ns1.google.com. dns-admin.google.com. 379031418 900 900 1800 60",
                ),
                (
                    Resource::MX(MX {
                        preference: 10,
                        exchange: "aspmx.l.google.com.".to_string(),
                    }),
                    "10 aspmx.l.google.com.",
                ),
                (
                    Resource::SRV(SRV {
                        priority: 5,
                        weight: 0,
                        port: 389,
                        name: "ldap.google.com.".to_string(),
                    }),
                    "5 0 389 ldap.google.com.",
                ),
                (
                    Resource::TXT(TXT::from("v=spf1 include:_spf.google.com ~all")),
                    "\"v=spf1 include:_spf.google.com ~all\"",
                ),
                (
                    // Example from TXT s1024._domainkey.yahoo.com.
                    Resource::TXT(TXT::from(&[
                        "k=rsa;  p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDrEee0Ri4Juz+QfiWYui/E9UGSXau/2P8LjnTD8V4Unn+2FAZVGE3kL23bzeoULYv4PeleB3gfm",
                        "JiDJOKU3Ns5L4KJAUUHjFwDebt0NP+sBK0VKeTATL2Yr/S3bT/xhy+1xtj4RkdV7fVxTn56Lb4udUnwuxK4V5b5PdOKj/+XcwIDAQAB; n=A 1024 bit key;"
                    ][..])),
                    "\"k=rsa;  p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDrEee0Ri4Juz+QfiWYui/E9UGSXau/2P8LjnTD8V4Unn+2FAZVGE3kL23bzeoULYv4PeleB3gfm\" \"JiDJOKU3Ns5L4KJAUUHjFwDebt0NP+sBK0VKeTATL2Yr/S3bT/xhy+1xtj4RkdV7fVxTn56Lb4udUnwuxK4V5b5PdOKj/+XcwIDAQAB; n=A 1024 bit key;\"",
                ),
            ]
        };
    }

    #[test]
    fn test_display() {
        for (resource, display) in (*DISPLAY_TESTS).iter() {
            assert_eq!(format!("{}", resource), *display);
        }
    }

    #[test]
    fn test_from_str() {
        for (resource, display) in (*DISPLAY_TESTS).iter() {
            match Resource::from_str(resource.r#type(), display) {
                Ok(got) => assert_eq!(&got, resource),
                Err(err) => panic!(
                    "from_str({}, '{}') failed: {}",
                    resource.r#type(),
                    display,
                    err
                ),
            }
        }
    }

    /// Test resource->display->from_string to make sure we can round trip between types.
    #[test]
    fn test_identity() {
        for (resource, _) in (*DISPLAY_TESTS).iter() {
            let display = format!("{}", resource);
            match Resource::from_str(resource.r#type(), &display) {
                Ok(got) => assert_eq!(&got, resource),
                Err(err) => panic!(
                    "from_str({}, '{}') failed: {}",
                    resource.r#type(),
                    display,
                    err
                ),
            }
        }
    }
}
