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
    #[error("$ORIGIN must be an absolute domain")]
    OriginNotAbsolute,
    #[error("record is missing a name and has no previous name")]
    MissingName,
    #[error("record is missing a TTL and no default TTL is set")]
    MissingTtl,
    #[error("record is missing a class and has no previous class")]
    MissingClass,
    #[error("relative domain '{0}' has no origin")]
    RelativeNameWithoutOrigin(String),
    #[error("invalid SOA rname '{0}'")]
    InvalidRname(String),
}

impl File {
    /// Resolves this zone file into records, returning details for invalid state.
    pub fn try_into_records(self) -> Result<Vec<Record>, ProcessError> {
        self.into_records_impl()
    }

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

        for entry in self.entries.iter() {
            match entry {
                Entry::Origin(new_origin) => {
                    // Always trim the dot from the end.
                    if let Some(new_origin) = new_origin.strip_suffix('.') {
                        origin = Some(new_origin)
                    } else {
                        return Err(ProcessError::OriginNotAbsolute);
                    }
                }
                Entry::TTL(ttl) => default_ttl = Some(ttl),
                Entry::Record(record) => {
                    let full_name: String = match record.name.as_ref() {
                        Some(name) => Self::resolve_name(name, origin)?,
                        None => {
                            last_name.clone().ok_or(ProcessError::MissingName)?
                        }
                    };
                    last_name = Some(full_name.to_owned());

                    let ttl = record
                        .ttl
                        .as_ref()
                        .or(default_ttl)
                        .ok_or(ProcessError::MissingTtl)?;

                    let class = record
                        .class
                        .as_ref()
                        .or(last_class)
                        .ok_or(ProcessError::MissingClass)?;

                    last_class = Some(class);

                    results.push(crate::Record {
                        name: full_name,
                        class: *class,
                        ttl: *ttl,
                        resource: Self::resolve_resource(&record.resource, origin)?,
                    })
                }
            }
        }

        Ok(results)
    }

    fn resolve_name(name: &str, origin: Option<&str>) -> Result<String, ProcessError> {
        // Absolute domain name
        if let Some(name) = name.strip_suffix('.') {
            return Ok(name.to_string());
        }

        // Everything past here requires a origin
        let origin = origin.ok_or_else(|| ProcessError::RelativeNameWithoutOrigin(name.to_string()))?;

        if name == "@" {
            return Ok(origin.to_string());
        }

        // Relative domain name
        Ok(name.to_owned() + "." + origin)
    }

    fn resolve_resource(
        resource: &Resource,
        origin: Option<&str>,
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
            Resource::CNAME(domain) => Ok(Resource::CNAME(Self::resolve_name(domain, origin)?)),
            Resource::NS(domain) => Ok(Resource::NS(Self::resolve_name(domain, origin)?)),
            Resource::PTR(domain) => Ok(Resource::PTR(Self::resolve_name(domain, origin)?)),
            Resource::MX(mx) => Ok(Resource::MX(MX {
                preference: mx.preference,
                exchange: Self::resolve_name(&mx.exchange, origin)?,
            })),
            Resource::SOA(soa) => {
                let rname = Self::resolve_name(&soa.rname, origin)?;
                let rname = SOA::rname_to_email(&rname)
                    .map_err(|_| ProcessError::InvalidRname(rname))?;
                Ok(Resource::SOA(SOA {
                mname: Self::resolve_name(&soa.mname, origin)?,
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
                name: Self::resolve_name(&srv.name, origin)?,
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
                .into_records()
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

        assert_eq!(file.try_into_records(), Err(ProcessError::MissingTtl));
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

        assert_eq!(file.try_into_records(), Err(ProcessError::MissingName));
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
            Err(ProcessError::RelativeNameWithoutOrigin("www".to_string()))
        );
    }
}
