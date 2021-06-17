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
        serde_yaml::from_slice(&s).expect("failed to deserialise test input");

    for case in tests {
        test_from_slice(case);
    }
}

fn normalise_whitespace(s: &str) -> String {
    let re = Regex::new(r"[ ]+").unwrap();
    return re.replace_all(s, " ").to_string();
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
