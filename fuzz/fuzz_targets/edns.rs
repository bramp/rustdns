#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate arbitrary;
extern crate rustdns;

use arbitrary::Arbitrary;
use rustdns::{EdnsOption, Extension, Type};
use std::io::Cursor;

#[derive(Arbitrary, Debug)]
enum FuzzInput<'a> {
    // Arbitrary wire bytes for an individual EDNS option parsed via Cursor
    RawOption(&'a [u8]),
    // Arbitrary option code with arbitrary raw data
    CodeAndData { code: u16, data: &'a [u8] },
    // Arbitrary wire bytes for an OPT record parsed via Cursor
    RawExtension(&'a [u8]),
    // In-memory structured option
    StructuredOption(EdnsOption),
}

fuzz_target!(|input: FuzzInput<'_>| {
    match input {
        FuzzInput::RawOption(bytes) => {
            let mut cur = Cursor::new(bytes);
            if let Ok(opt) = EdnsOption::fuzz_parse(&mut cur) {
                let _ = format!("{opt}");
                let _ = format!("{opt:?}");

                let mut buf = Vec::new();
                if opt.fuzz_append_to_vec(&mut buf).is_ok() {
                    let mut re_cur = Cursor::new(buf.as_slice());
                    let re_decoded = EdnsOption::fuzz_parse(&mut re_cur)
                        .expect("re-decoding encoded EDNS option must succeed");
                    let mut buf2 = Vec::new();
                    if re_decoded.fuzz_append_to_vec(&mut buf2).is_ok() {
                        assert_eq!(buf, buf2, "EDNS option re-encoding must be idempotent");
                    }
                }
            }
        }
        FuzzInput::CodeAndData { code, data } => {
            if let Ok(opt) = EdnsOption::fuzz_parse_data(code, data) {
                let _ = format!("{opt}");
                let _ = format!("{opt:?}");

                let mut buf = Vec::new();
                if opt.fuzz_append_to_vec(&mut buf).is_ok() {
                    let mut re_cur = Cursor::new(buf.as_slice());
                    let re_decoded = EdnsOption::fuzz_parse(&mut re_cur)
                        .expect("re-decoding encoded EDNS option must succeed");
                    let mut buf2 = Vec::new();
                    if re_decoded.fuzz_append_to_vec(&mut buf2).is_ok() {
                        assert_eq!(buf, buf2, "EDNS option re-encoding must be idempotent");
                    }
                }
            }
        }
        FuzzInput::RawExtension(bytes) => {
            let mut cur = Cursor::new(bytes);
            if let Ok(ext) = Extension::fuzz_parse(&mut cur, ".".to_string(), Type::OPT) {
                let mut buf = Vec::new();
                if ext.append_to_vec(&mut buf).is_ok() {
                    // Prepend root name and OPT type as expected by parse_internal
                    let mut re_cur = Cursor::new(&buf[3..]); // skip root (.) and OPT type u16
                    let re_decoded = Extension::fuzz_parse(&mut re_cur, ".".to_string(), Type::OPT)
                        .expect("re-decoding encoded Extension must succeed");
                    let mut buf2 = Vec::new();
                    if re_decoded.append_to_vec(&mut buf2).is_ok() {
                        assert_eq!(buf, buf2, "Extension re-encoding must be idempotent");
                    }
                }
            }
        }
        FuzzInput::StructuredOption(opt) => {
            let _ = format!("{opt}");
            let _ = format!("{opt:?}");

            let mut buf = Vec::new();
            if opt.fuzz_append_to_vec(&mut buf).is_ok() {
                let mut re_cur = Cursor::new(buf.as_slice());
                if let Ok(re_decoded) = EdnsOption::fuzz_parse(&mut re_cur) {
                    let mut buf2 = Vec::new();
                    let _ = re_decoded.fuzz_append_to_vec(&mut buf2);
                }
            }

            // Also test wrapping in an Extension
            let mut ext = Extension::default();
            ext.add_option(opt);
            let mut ext_buf = Vec::new();
            let _ = ext.append_to_vec(&mut ext_buf);
        }
    }
});
