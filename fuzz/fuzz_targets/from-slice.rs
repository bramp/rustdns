#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustdns;

fuzz_target!(|data: &[u8]| {
    let msg = match rustdns::Message::from_slice(data) {
        Ok(msg) => msg,
        Err(_) => return,
    };

    let _ = format!("{msg}");
    let _ = format!("{msg:?}");

    if let Ok(encoded) = msg.to_vec() {
        let decoded = rustdns::Message::from_slice(&encoded)
            .expect("re-decoding encoded message must succeed");
        let _ = format!("{decoded}");
        let _ = format!("{decoded:?}");

        if let Ok(re_encoded) = decoded.to_vec() {
            assert_eq!(encoded, re_encoded, "re-encoding must be idempotent");
        }
    }
});
