#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustdns;

use rustdns::{Class, Message, Name, Record, Resource, Rname, SOA};
use std::time::Duration;

fuzz_target!(|data: &str| {
    if data.len() > 4096 {
        return;
    }
    if let Ok(name) = data.parse::<Rname>() {
        assert_eq!(name.as_str().parse::<Rname>().unwrap(), name);
        let _ = name.to_email();
        let mut message = Message::default();
        message.answers.push(Record::new(
            Name::root(),
            Class::Internet,
            Duration::from_secs(60),
            Resource::SOA(SOA {
                mname: Name::root(),
                rname: name,
                serial: 1,
                refresh: Duration::from_secs(2),
                retry: Duration::from_secs(3),
                expire: Duration::from_secs(4),
                minimum: Duration::from_secs(5),
            }),
        ));
        let wire = message.to_vec().unwrap();
        assert_eq!(Message::from_slice(&wire).unwrap(), message);
    }
    if let Ok(name) = Rname::from_email(data) {
        assert_eq!(name.to_string().parse::<Rname>().unwrap(), name);
    }
    // 1. Parsing as rname and converting to email must never panic.
    if let Ok(email) = SOA::rname_to_email(data) {
        let _ = SOA::email_to_rname(&email);
    }

    // 2. Parsing as email and converting to rname must never panic.
    if let Ok(rname) = SOA::email_to_rname(data) {
        let _ = SOA::rname_to_email(&rname);
    }
});
