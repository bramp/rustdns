// TODO Switch this to use datatest after 0.6.3 (which is broken):
// https://github.com/commure/datatest/pull/30
// and custom_test_frameworks is supported https://github.com/rust-lang/rust/issues/50297
use pretty_assertions::assert_eq;
use regex::Regex;
use rustdns::Message;
use serde::Deserialize;
use std::fs;

const TEST_DATA_FILENAME: &str = "tests/test_data.yaml";

#[derive(Deserialize)]
struct TestCase {
    // Name of the test case.
    name: String,

    // Hex encoded binary string.
    // TODO Change this to a binary type, when serde_yaml supports it: https://github.com/dtolnay/serde-yaml/issues/91
    binary: String,

    // Dig-ish formatted output.
    // TODO Change this to a multi-line string type, for easier viewing in the generated YAML.
    string: String,
}

#[test]
fn tests() {
    let s = fs::read(TEST_DATA_FILENAME).expect("failed read test input");
    let tests: Vec<TestCase> =
        yaml_serde::from_slice(&s).expect("failed to deserialise test input");

    for case in tests {
        test_from_slice(case);
    }
}

fn normalise_whitespace(s: &str) -> String {
    let re = Regex::new(r"[ ]+").unwrap();
    re.replace_all(s, " ").to_string()
}

fn test_from_slice(case: TestCase) {
    let input = match hex::decode(case.binary) {
        Err(e) => panic!("{}: Invalid test case input: {}", case.name, e),
        Ok(i) => i,
    };
    let m = match Message::from_slice(&input) {
        Err(e) => panic!("{}: Unable to parse: {}", case.name, e),
        Ok(p) => p,
    };

    // TODO Split this into a few tests. from_slice(), fmt(), to_vec()

    // Normalise the formatted output a little (to allow little whitespace changes).
    let got = normalise_whitespace(&format!("{}", m));
    let want = normalise_whitespace(&case.string);

    assert_eq!(got, want, "{}: Formatted string doesn't match", case.name);

    // TODO Test writing the result back out.
}

#[test]
fn test_soa_rname_reencode_idempotence() {
    // Minimal reproduction of fuzz artifact crash-82b2b77d60157c1c052e3251e7cee7bb14311fa2
    // An SOA record whose RNAME contains a backslash.
    let wire = [
        47, 207, 7, 128, 0, 0, 0, 1, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 254, 0, 0, 48, 8,
        0, 60, 0, 8, 92, 48, 0, 0, 0, 111, 0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 216, 220, 245, 59, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 39, 238,
    ];

    let decoded = Message::from_slice(&wire).expect("failed to parse message");
    let re_encoded = decoded.to_vec().expect("failed to re-encode message");
    assert_eq!(
        wire.as_slice(),
        re_encoded.as_slice(),
        "re-encoding must be idempotent"
    );
}
