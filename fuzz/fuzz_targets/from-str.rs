#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate arbitrary;
extern crate rustdns;

use arbitrary::Arbitrary;
use rustdns::{Class, Record, Resource, Type};
use std::time::Duration;

#[derive(Arbitrary, Debug)]
struct FuzzInput<'a> {
    record_type: Type,
    text: &'a str,
}

fuzz_target!(|input: FuzzInput<'_>| {
    // Parse through Resource::parse_text, which dispatches to the individual
    // FromStr parsers (A, AAAA, NS, CNAME, PTR, MX, SRV, SOA, SPF, TXT).
    if let Ok(resource) = Resource::parse_text(input.record_type, input.text) {
        let _ = format!("{resource}");
        let _ = format!("{resource:?}");

        // If parsed, wrapping in a Record and serializing must not panic.
        let record = Record::new(
            "example.com.",
            Class::Internet,
            Duration::from_secs(300),
            resource,
        );
        let mut buf = Vec::new();
        let _ = record.append_to_vec(&mut buf);
    }
});
