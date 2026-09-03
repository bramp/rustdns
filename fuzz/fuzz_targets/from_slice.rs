#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustdns;

fuzz_target!(|data: &[u8]| {
    #[allow(unused_must_use)]
    {
        rustdns::Message::from_slice(data);
    }
});
