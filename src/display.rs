//! Implements the Display trait for the various types, so they output
//! in `dig` style.
// Refer to https://github.com/tigeli/bind-utils/blob/master/bin/dig/dig.c for reference.

use crate::Message;
use crate::Question;
use crate::Record;
use crate::Resource;
use crate::resource::DNSKEY;
use crate::resource::DS;
use crate::resource::MX;
use crate::resource::NSEC;
use crate::resource::NSEC3;
use crate::resource::NSEC3PARAM;
use crate::resource::RRSIG;
use crate::resource::SOA;
use crate::resource::SRV;
use crate::resource::TXT;
use crate::resource::ZONEMD;
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
            for option in &e.options {
                writeln!(f, "; EDNS Option: {option}")?;
            }
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

        if bool::from(self.qr) {
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

        writeln!(
            f,
            ";; flags:{flags}; QUERY: {qd_count}, ANSWER: {an_count}, AUTHORITY: {ns_count}, ADDITIONAL: {ar_count}",
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
            Resource::DS(ds) => ds.fmt(f),
            Resource::DNSKEY(dnskey) => dnskey.fmt(f),
            Resource::RRSIG(rrsig) => rrsig.fmt(f),
            Resource::NSEC(nsec) => nsec.fmt(f),
            Resource::NSEC3(nsec3) => nsec3.fmt(f),
            Resource::NSEC3PARAM(param) => param.fmt(f),
            Resource::ZONEMD(zonemd) => zonemd.fmt(f),
            Resource::Raw(raw) => write!(
                f,
                "TYPE{} \\# {} {}",
                raw.rtype,
                raw.data.len(),
                crate::util::hex_encode(&raw.data)
            ),

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
        // TODO Would be nice to display the rname as an email address (if possible).

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

impl fmt::Display for DS {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{key_tag} {algorithm} {digest_type} {digest}",
            key_tag = self.key_tag,
            algorithm = self.algorithm,
            digest_type = self.digest_type,
            digest = crate::util::hex_encode(&self.digest),
        )
    }
}

impl fmt::Display for DNSKEY {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{flags} {protocol} {algorithm} {key}",
            flags = self.flags,
            protocol = self.protocol,
            algorithm = self.algorithm,
            key = crate::util::base64_encode(&self.public_key),
        )
    }
}

impl fmt::Display for RRSIG {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let exp_dt: chrono::DateTime<chrono::Utc> = self.expiration.into();
        let inc_dt: chrono::DateTime<chrono::Utc> = self.inception.into();
        write!(
            f,
            "{type_covered} {algorithm} {labels} {original_ttl} {expiration} {inception} {key_tag} {signer_name} {signature}",
            type_covered = self.type_covered,
            algorithm = self.algorithm,
            labels = self.labels,
            original_ttl = self.original_ttl.as_secs(),
            expiration = exp_dt.format("%Y%m%d%H%M%S"),
            inception = inc_dt.format("%Y%m%d%H%M%S"),
            key_tag = self.key_tag,
            signer_name = self.signer_name,
            signature = crate::util::base64_encode(&self.signature),
        )
    }
}

impl fmt::Display for NSEC {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{next_domain}", next_domain = self.next_domain)?;
        for t in &self.types {
            write!(f, " {t}")?;
        }
        Ok(())
    }
}

impl fmt::Display for NSEC3 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let salt = if self.salt.is_empty() {
            "-".to_string()
        } else {
            crate::util::hex_encode(&self.salt)
        };
        write!(
            f,
            "{algo} {flags} {iterations} {salt} {next_hash}",
            algo = self.hash_algorithm,
            flags = self.flags,
            iterations = self.iterations,
            salt = salt,
            next_hash = crate::util::base32hex_encode(&self.next_hashed_owner_name),
        )?;
        for t in &self.types {
            write!(f, " {t}")?;
        }
        Ok(())
    }
}

impl fmt::Display for NSEC3PARAM {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let salt = if self.salt.is_empty() {
            "-".to_string()
        } else {
            crate::util::hex_encode(&self.salt)
        };
        write!(
            f,
            "{algo} {flags} {iterations} {salt}",
            algo = self.hash_algorithm,
            flags = self.flags,
            iterations = self.iterations,
            salt = salt,
        )
    }
}

impl fmt::Display for ZONEMD {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{serial} {scheme} {algorithm} {digest}",
            serial = self.serial,
            scheme = self.scheme,
            algorithm = self.algorithm,
            digest = crate::util::hex_encode(&self.digest),
        )
    }
}

impl fmt::Display for TXT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = self
            .0
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
    use crate::DNSKEY;
    use crate::DS;
    use crate::EdnsOption;
    use crate::Extension;
    use crate::MX;
    use crate::Message;
    use crate::NSEC;
    use crate::RRSIG;
    use crate::Resource;
    use crate::SOA;
    use crate::SRV;
    use crate::TXT;
    use crate::Type;
    use crate::ZONEMD;
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
                        rname: "dns-admin.google.com.".to_string(),

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
                (
                    Resource::DS(DS {
                        key_tag: 31852,
                        algorithm: crate::types::Algorithm::RSASHA256,
                        digest_type: crate::types::DigestType::Sha256,
                        digest: vec![0x89, 0xF7, 0x67, 0x0A],
                    }),
                    "31852 8 2 89F7670A",
                ),
                (
                    Resource::DNSKEY(DNSKEY {
                        flags: 256,
                        protocol: 3,
                        algorithm: crate::types::Algorithm::RSASHA256,
                        public_key: vec![1, 2, 3, 4],
                    }),
                    "256 3 8 AQIDBA==",
                ),
                (
                    Resource::RRSIG(RRSIG {
                        type_covered: Type::A,
                        algorithm: crate::types::Algorithm::RSASHA256,
                        labels: 2,
                        original_ttl: std::time::Duration::from_secs(3600),
                        expiration: std::time::UNIX_EPOCH
                            + std::time::Duration::from_secs(1789880400),
                        inception: std::time::UNIX_EPOCH
                            + std::time::Duration::from_secs(1788753600),
                        key_tag: 12345,
                        signer_name: "example.com.".to_string(),
                        signature: vec![10, 20, 30, 40],
                    }),
                    "A 8 2 3600 20260920050000 20260907040000 12345 example.com. ChQeKA==",
                ),
                (
                    Resource::NSEC(NSEC {
                        next_domain: "next.example.com.".to_string(),
                        types: vec![Type::A, Type::NS, Type::SOA],
                    }),
                    "next.example.com. A NS SOA",
                ),
                (
                    Resource::ZONEMD(ZONEMD {
                        serial: 2026090700,
                        scheme: 1,
                        algorithm: 1,
                        digest: vec![0x46, 0x5D, 0x6F, 0x58],
                    }),
                    "2026090700 1 1 465D6F58",
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
    fn displays_edns_options() {
        let mut message = Message::default();
        message.set_extension(
            Extension::default()
                .with_option(EdnsOption::nsid(Vec::new()))
                .with_option(EdnsOption::tcp_keepalive(Some(Duration::from_secs(30))))
                .with_option(EdnsOption::padding(4)),
        );

        let display = format!("{}", message);

        assert!(display.contains("; EDNS Option: NSID "));
        assert!(display.contains("; EDNS Option: TCP-KEEPALIVE timeout=30s"));
        assert!(display.contains("; EDNS Option: PADDING 4 bytes"));
    }

    #[test]
    fn test_from_str() {
        for (resource, display) in (*DISPLAY_TESTS).iter() {
            match Resource::parse_text(resource.r#type(), display) {
                Ok(got) => assert_eq!(&got, resource),
                Err(err) => panic!(
                    "parse_text({}, '{}') failed: {}",
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
            match Resource::parse_text(resource.r#type(), &display) {
                Ok(got) => assert_eq!(&got, resource),
                Err(err) => panic!(
                    "parse_text({}, '{}') failed: {}",
                    resource.r#type(),
                    display,
                    err
                ),
            }
        }
    }
}
