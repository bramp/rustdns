#![no_main]

use libfuzzer_sys::fuzz_target;
use rustdns::zones::{File, Record};

fuzz_target!(|input: &str| {
    if input.len() > 16 * 1024 {
        return;
    }
    let _ = input.parse::<Record>();
    if let Ok(file) = input.parse::<File>() {
        if let Ok(records) = file.try_into_records() {
            let message = rustdns::Message {
                answers: records,
                ..Default::default()
            };
            let _ = message.to_vec();
        }
    }
});
