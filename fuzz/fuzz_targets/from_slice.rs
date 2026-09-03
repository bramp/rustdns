#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustdns;

fuzz_target!(|data: &[u8]| {
    assert!(std::panic::catch_unwind(|| rustdns::Message::from_slice(data)).is_ok());
});
