#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustdns;

use rustdns::SOA;

fuzz_target!(|data: &str| {
    // 1. Parsing as rname and converting to email must never panic.
    if let Ok(email) = SOA::rname_to_email(data) {
        let _ = SOA::email_to_rname(&email);
    }

    // 2. Parsing as email and converting to rname must never panic.
    if let Ok(rname) = SOA::email_to_rname(data) {
        let _ = SOA::rname_to_email(&rname);
    }
});
