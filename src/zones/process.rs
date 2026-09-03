// Process a Zone File turning it into actual Records.

use crate::resource::*;
use crate::zones::Entry;
use crate::zones::File;
use crate::Class;
use crate::Record;
use crate::Resource;
use core::time::Duration;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProcessError {
    #[error("entry {entry_index}: $ORIGIN '{origin}' must be an absolute domain")]
    OriginNotAbsolute { entry_index: usize, origin: String },
    #[error("entry {entry_index}: record is missing a name and has no previous name")]
    MissingName { entry_index: usize },
    #[error("entry {entry_index} ({record_name}): record is missing a TTL and no default TTL is set")]
    MissingTtl { entry_index: usize, record_name: String },
    #[error("entry {entry_index} ({record_name}): record is missing a class and has no previous class")]
    MissingClass { entry_index: usize, record_name: String },
    #[error("entry {entry_index} ({record_name}): relative domain '{name}' has no origin")]
    RelativeNameWithoutOrigin {
        entry_index: usize,
        record_name: String,
        name: String,
    },
    #[error("entry {entry_index} ({record_name}): invalid SOA rname '{rname}'")]
    InvalidRname {
        entry_index: usize,
        record_name: String,
        rname: String,
    },
}

impl File {
    /// Resolves this zone file into records, returning details for invalid state.
    ///
    /// # Errors
    ///
    /// Returns a [`ProcessError`] with the entry index and record context when
    /// required inherited zone state is missing or a relative resource name is invalid.
    pub fn try_into_records(self) -> Result<Vec<Record>, ProcessError> {
        self.into_records_impl()
    }

    /// Errors are discarded by this compatibility method. Prefer
    /// [`File::try_into_records`] to retain error context.
    #[deprecated(note = "use try_into_records to retain processing errors")]
    pub fn into_records(self) -> Result<Vec<Record>, ()> {
        self.try_into_records().map_err(|_| ())
    }

    fn into_records_impl(self) -> Result<Vec<Record>, ProcessError> {
        let mut results = Vec::<Record>::new();

        // Useful to refer to:
        // https://datatracker.ietf.org/doc/html/rfc1035#section-5.1
        // https://datatracker.ietf.org/doc/html/rfc2308#section-4
        // https://www-uxsup.csx.cam.ac.uk/pub/doc/redhat/redhat7.3/rhl-rg-en-7.3/s1-bind-configuration.html

        // TODO Implement:
        // TTL in RSet must match https://datatracker.ietf.org/doc/html/rfc2181#section-5.2
        // Duration times https://www-uxsup.csx.cam.ac.uk/pub/doc/redhat/redhat7.3/rhl-rg-en-7.3/s1-bind-configuration.html

        let mut origin: Option<&str> = self.origin.as_deref();
        let mut default_ttl: Option<&Duration> = None;

        let mut last_name: Option<String> = None;
        let mut last_class: Option<&Class> = None;

        for (entry_index, entry) in self.entries.iter().enumerate() {
            match entry {
                Entry::Origin(new_origin) => {
                    // Always trim the dot from the end.
                    if let Some(new_origin) = new_origin.strip_suffix('.') {
                        origin = Some(new_origin)
                    } else {
                        return Err(ProcessError::OriginNotAbsolute {
                            entry_index,
                            origin: new_origin.to_string(),
                        });
                    }
                }
                Entry::TTL(ttl) => default_ttl = Some(ttl),
                Entry::Record(record) => {
                    let full_name: String = match record.name.as_ref() {
                        Some(name) => Self::resolve_name(name, origin, entry_index, name)?,
                        None => {
                            last_name.clone().ok_or(ProcessError::MissingName { entry_index })?
                        }
                    };
                    let record_name = full_name.clone();
                    last_name = Some(full_name.to_owned());

                    let ttl = record
                        .ttl
                        .as_ref()
                        .or(default_ttl)
                        .ok_or_else(|| ProcessError::MissingTtl {
                            entry_index,
                            record_name: record_name.clone(),
                        })?;

                    let class = record
                        .class
                        .as_ref()
                        .or(last_class)
                        .ok_or_else(|| ProcessError::MissingClass {
                            entry_index,
                            record_name: record_name.clone(),
                        })?;

                    last_class = Some(class);

                    results.push(crate::Record {
                        name: full_name,
                        class: *class,
                        ttl: *ttl,
                        resource: Self::resolve_resource(
                            &record.resource,
                            origin,
                            entry_index,
                            &record_name,
                        )?,
                    })
                }
            }
        }

        Ok(results)
    }

    fn resolve_name(
        name: &str,
        origin: Option<&str>,
        entry_index: usize,
        record_name: &str,
    ) -> Result<String, ProcessError> {
        // Absolute domain name
        if let Some(name) = name.strip_suffix('.') {
            return Ok(name.to_string());
        }

        // Everything past here requires a origin
        let origin = origin.ok_or_else(|| ProcessError::RelativeNameWithoutOrigin {
            entry_index,
            record_name: record_name.to_string(),
            name: name.to_string(),
        })?;

        if name == "@" {
            return Ok(origin.to_string());
        }

        // Relative domain name
        Ok(name.to_owned() + "." + origin)
    }

    fn resolve_resource(
        resource: &Resource,
        origin: Option<&str>,
        entry_index: usize,
        record_name: &str,
    ) -> Result<Resource, ProcessError> {
        match resource {
            // These types don't include a domain, so clone as is.
            Resource::A(_)
            | Resource::AAAA(_)
            | Resource::TXT(_)
            | Resource::SPF(_)
            | Resource::OPT
            | Resource::ANY => Ok(resource.clone()),

            // The rest need some kind of tweaking
            Resource::CNAME(domain) => Ok(Resource::CNAME(Self::resolve_name(
                domain, origin, entry_index, record_name,
            )?)),
            Resource::NS(domain) => Ok(Resource::NS(Self::resolve_name(
                domain, origin, entry_index, record_name,
            )?)),
            Resource::PTR(domain) => Ok(Resource::PTR(Self::resolve_name(
                domain, origin, entry_index, record_name,
            )?)),
            Resource::MX(mx) => Ok(Resource::MX(MX {
                preference: mx.preference,
                exchange: Self::resolve_name(
                    &mx.exchange,
                    origin,
                    entry_index,
                    record_name,
                )?,
            })),
            Resource::SOA(soa) => {
                let rname = Self::resolve_name(&soa.rname, origin, entry_index, record_name)?;
                let rname = SOA::rname_to_email(&rname)
                    .map_err(|_| ProcessError::InvalidRname {
                        entry_index,
                        record_name: record_name.to_string(),
                        rname,
                    })?;
                Ok(Resource::SOA(SOA {
                mname: Self::resolve_name(&soa.mname, origin, entry_index, record_name)?,
                rname,
                serial: soa.serial,
                refresh: soa.refresh,
                retry: soa.retry,
                expire: soa.expire,
                minimum: soa.minimum,
                }))
            }
            Resource::SRV(srv) => Ok(Resource::SRV(SRV {
                priority: srv.priority,
                weight: srv.weight,
                port: srv.port,
                name: Self::resolve_name(&srv.name, origin, entry_index, record_name)?,
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::resource::*;
    use crate::zones::{Entry, File, ProcessError, Record as ZoneRecord};
    use crate::Class;
    use crate::Record;
    use crate::Resource;
    use core::time::Duration;
    use pretty_assertions::assert_eq;
    use std::str::FromStr;

    #[test]
    fn test_into_records() {
        let tests = vec![
    		("
    		$ORIGIN example.com.     ; designates the start of this zone file in the namespace
            $TTL 3600                ; default expiration time (in seconds) of all RRs without their own TTL value
            example.com.  IN  SOA   ns.example.com. username.example.com. ( 2020091025 7200 3600 1209600 3600 )
            example.com.  IN  NS    ns                    ; ns.example.com is a nameserver for example.com
            example.com.  IN  NS    ns.somewhere.example. ; ns.somewhere.example is a backup nameserver for example.com
            example.com.  IN  MX    10 mail.example.com.  ; mail.example.com is the mailserver for example.com
            @             IN  MX    20 mail2.example.com. ; equivalent to above line, '@' represents zone origin
            @             IN  MX    50 mail3              ; equivalent to above line, but using a relative host name
            example.com.  IN  A     192.0.2.1             ; IPv4 address for example.com
                          IN  AAAA  2001:db8:10::1        ; IPv6 address for example.com
            ns            IN  A     192.0.2.2             ; IPv4 address for ns.example.com
                          IN  AAAA  2001:db8:10::2        ; IPv6 address for ns.example.com
            www           IN  CNAME example.com.          ; www.example.com is an alias for example.com
            wwwtest       IN  CNAME www                   ; wwwtest.example.com is another alias for www.example.com
            ",
            vec![
            	Record::new("example.com", Class::Internet, Duration::new(3600, 0), Resource::SOA(SOA {
	                mname: "ns.example.com".to_string(),
	                rname: "username@example.com".to_string(),
	                serial: 2020091025,
	                refresh: Duration::new(7200, 0),
	                retry: Duration::new(3600, 0),
	                expire: Duration::new(1209600, 0),
	                minimum: Duration::new(3600, 0),
	            })),
            	Record::new("example.com", Class::Internet, Duration::new(3600, 0), Resource::NS("ns.example.com".to_string())),
            	Record::new("example.com", Class::Internet, Duration::new(3600, 0), Resource::NS("ns.somewhere.example".to_string())),
				Record::new("example.com", Class::Internet, Duration::new(3600, 0), Resource::MX(MX{
					preference: 10,
					exchange: "mail.example.com".to_string()
				})),
				Record::new("example.com", Class::Internet, Duration::new(3600, 0), Resource::MX(MX{
					preference: 20,
					exchange: "mail2.example.com".to_string()
				})),
				Record::new("example.com", Class::Internet, Duration::new(3600, 0), Resource::MX(MX{
					preference: 50,
					exchange: "mail3.example.com".to_string()
				})),
				Record::new("example.com", Class::Internet, Duration::new(3600, 0), Resource::A("192.0.2.1".parse().unwrap())),
				Record::new("example.com", Class::Internet, Duration::new(3600, 0), Resource::AAAA("2001:db8:10::1".parse().unwrap())),
				Record::new("ns.example.com", Class::Internet, Duration::new(3600, 0), Resource::A("192.0.2.2".parse().unwrap())),
				Record::new("ns.example.com", Class::Internet, Duration::new(3600, 0), Resource::AAAA("2001:db8:10::2".parse().unwrap())),
				Record::new("www.example.com", Class::Internet, Duration::new(3600, 0), Resource::CNAME("example.com".parse().unwrap())),
				Record::new("wwwtest.example.com", Class::Internet, Duration::new(3600, 0), Resource::CNAME("www.example.com".to_string())),
            ])
    	];

        for (input, want) in tests {
            match File::from_str(input)
                .expect("failed to parse")
                .try_into_records()
            {
                Ok(got) => assert_eq!(got, want),
                Err(err) => panic!("{} Failed:\n{:?}", input, err), // TODO Make a error and no need to use "{:?}"
            }
        }
    }

    #[test]
    fn try_into_records_reports_missing_ttl() {
        let file = File {
            origin: Some("example.com".to_string()),
            entries: vec![Entry::Record(ZoneRecord {
                name: Some("example.com.".to_string()),
                ttl: None,
                class: Some(Class::Internet),
                resource: Resource::A("192.0.2.1".parse().unwrap()),
            })],
        };

        assert_eq!(
            file.try_into_records(),
            Err(ProcessError::MissingTtl {
                entry_index: 0,
                record_name: "example.com".to_string(),
            })
        );
    }

    #[test]
    fn try_into_records_reports_missing_name() {
        let file = File {
            origin: Some("example.com".to_string()),
            entries: vec![Entry::Record(ZoneRecord {
                name: None,
                ttl: Some(Duration::from_secs(300)),
                class: Some(Class::Internet),
                resource: Resource::A("192.0.2.1".parse().unwrap()),
            })],
        };

        assert_eq!(
            file.try_into_records(),
            Err(ProcessError::MissingName { entry_index: 0 })
        );
    }

    #[test]
    fn try_into_records_reports_relative_name_without_origin() {
        let file = File {
            origin: None,
            entries: vec![Entry::Record(ZoneRecord {
                name: Some("www".to_string()),
                ttl: Some(Duration::from_secs(300)),
                class: Some(Class::Internet),
                resource: Resource::A("192.0.2.1".parse().unwrap()),
            })],
        };

        assert_eq!(
            file.try_into_records(),
            Err(ProcessError::RelativeNameWithoutOrigin {
                entry_index: 0,
                record_name: "www".to_string(),
                name: "www".to_string(),
            })
        );
    }

    #[test]
    fn process_errors_include_entry_and_record_context() {
        let file = File {
            origin: Some("example.com".to_string()),
            entries: vec![
                Entry::TTL(Duration::from_secs(300)),
                Entry::Record(ZoneRecord {
                    name: Some("www".to_string()),
                    ttl: None,
                    class: None,
                    resource: Resource::A("192.0.2.1".parse().unwrap()),
                }),
            ],
        };

        let error = file.try_into_records().expect_err("missing class accepted");
        assert_eq!(error.to_string(), "entry 1 (www.example.com): record is missing a class and has no previous class");
    }

    #[test]
    fn try_new_reports_relative_origin() {
        assert_eq!(
            File::try_new(Some("example.com".to_string()), Vec::new()),
            Err(ProcessError::OriginNotAbsolute {
                entry_index: 0,
                origin: "example.com".to_string(),
            })
        );
    }
}
