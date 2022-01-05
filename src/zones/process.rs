// Process a Zone File turning it into actual Records.

use crate::resource::*;
use crate::zones::Entry;
use crate::zones::File;
use crate::Class;
use crate::Record;
use crate::Resource;
use core::time::Duration;

impl File {
    pub fn into_records(self) -> Result<Vec<Record>, ()> {
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
                        panic!("TODO Origin wasn't a absolute domain");
                    }
                }
                Entry::TTL(ttl) => default_ttl = Some(ttl),
                Entry::Record(record) => {
                    let full_name: String = match record.name.as_ref() {
                        Some(name) => Self::resolve_name(name, origin),
                        None => {
                            if last_name.is_none() {
                                // TODO What's the behaviour if $origin is set?
                                panic!("TODO Blank domain without a previous domain set");
                            }
                            last_name.unwrap().to_string()
                        }
                    };
                    last_name = Some(full_name.to_owned());

                    let ttl = record
                        .ttl
                        .as_ref()
                        .or(default_ttl)
                        .expect("TODO Blank ttl without a default TTL set"); // TODO Turn these into errors

                    let class = record
                        .class
                        .as_ref()
                        .or(last_class)
                        .expect("TODO Blank Class without a previous Class set"); // TODO Turn these into errors

                    last_class = Some(class);

                    results.push(crate::Record {
                        name: full_name,
                        class: *class,
                        ttl: *ttl,
                        resource: Self::resolve_resource(&record.resource, origin),
                    })
                }
            }
        }

        Ok(results)
    }

    fn resolve_name(name: &str, origin: Option<&str>) -> String {
        // Absolute domain name
        if let Some(name) = name.strip_suffix('.') {
            return name.to_string();
        }

        // Everything past here requires a origin
        if origin.is_none() {
            panic!("TODO Relative domain without a origin set");
        }

        if name == "@" {
            return origin.unwrap().to_string();
        }

        // Relative domain name
        name.to_owned() + "." + origin.unwrap()
    }

    fn resolve_resource(resource: &Resource, origin: Option<&str>) -> Resource {
        match resource {
            // These types don't include a domain, so clone as is.
            Resource::A(_)
            | Resource::AAAA(_)
            | Resource::TXT(_)
            | Resource::OPT
            | Resource::ANY => resource.clone(),

            // The rest need some kind of tweaking
            Resource::CNAME(domain) => Resource::CNAME(Self::resolve_name(domain, origin)),
            Resource::NS(domain) => Resource::NS(Self::resolve_name(domain, origin)),
            Resource::PTR(domain) => Resource::PTR(Self::resolve_name(domain, origin)),
            Resource::MX(mx) => Resource::MX(MX {
                preference: mx.preference,
                exchange: Self::resolve_name(&mx.exchange, origin),
            }),
            Resource::SOA(soa) => Resource::SOA(SOA {
                mname: Self::resolve_name(&soa.mname, origin),
                rname: SOA::rname_to_email(&Self::resolve_name(&soa.rname, origin)).unwrap(),
                serial: soa.serial,
                refresh: soa.refresh,
                retry: soa.retry,
                expire: soa.expire,
                minimum: soa.minimum,
            }),
            Resource::SRV(srv) => Resource::SRV(SRV {
                priority: srv.priority,
                weight: srv.weight,
                port: srv.port,
                name: Self::resolve_name(&srv.name, origin),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::resource::*;
    use crate::zones::File;
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
}
