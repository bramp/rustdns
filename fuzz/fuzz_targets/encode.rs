#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate arbitrary;
extern crate rustdns;

use arbitrary::Arbitrary;
use rustdns::{Extension, Message, Question, Record};

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    message: Message,
    record: Record,
    question: Question,
    extension: Extension,
}

fuzz_target!(|input: FuzzInput| {
    // 1. Formatting on arbitrary structures must never panic.
    let _ = format!("{}", input.message);
    let _ = format!("{:?}", input.message);
    let _ = format!("{}", input.record);
    let _ = format!("{:?}", input.record);
    let _ = format!("{}", input.question);
    let _ = format!("{:?}", input.question);

    // 2. Individual component serialization must never panic.
    let mut buf = Vec::new();
    let _ = input.question.append_to_vec(&mut buf);

    buf.clear();
    let _ = input.record.append_to_vec(&mut buf);

    buf.clear();
    let _ = input.extension.append_to_vec(&mut buf);

    // 3. Message serialization (to_vec and append_to_vec) must never panic.
    buf.clear();
    let append_res = input.message.append_to_vec(&mut buf);
    let to_vec_res = input.message.to_vec();

    match (&append_res, &to_vec_res) {
        (Ok(()), Ok(bytes)) => {
            assert_eq!(&buf, bytes, "append_to_vec and to_vec outputs must match");

            // If serialization succeeded, parsing back through from_slice must not panic.
            if let Ok(decoded) = Message::from_slice(bytes) {
                let _ = format!("{decoded}");
                let _ = format!("{decoded:?}");

                // Re-encoding decoded message must succeed and match.
                if let Ok(re_encoded) = decoded.to_vec() {
                    assert_eq!(bytes, &re_encoded, "re-encoding must be idempotent");
                }
            }
        }
        (Err(e1), Err(e2)) => {
            assert_eq!(e1, e2, "append_to_vec and to_vec errors must match");
        }
        _ => panic!(
            "append_to_vec and to_vec had inconsistent results: append={append_res:?}, to_vec={to_vec_res:?}"
        ),
    }
});
