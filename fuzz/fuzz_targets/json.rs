#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustdns;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = rustdns::json::from_slice(data) {
        let _ = format!("{msg}");
        let _ = format!("{msg:?}");

        // If it parses to a valid Message, serializing to wire format must not panic.
        let mut buf = Vec::new();
        let _ = msg.append_to_vec(&mut buf);
    }
});
