#![feature(custom_test_frameworks)]

use rustdns::dns::Packet;
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

// TODO Switch this to use datatest after 0.6.3 (which is broken): https://github.com/commure/datatest/pull/30
fn test_from_slice(case: TestCase) {
    let input = match hex::decode(case.binary) {
        Err(e) => panic!("{}: Invalid test case input: {}", case.name, e),
        Ok(i) => i,
    };
    let packet = match Packet::from_slice(&input) {
        Err(e) => panic!("{}: Unable to parse: {}", case.name, e),
        Ok(p) => p,
    };

    assert_eq!(
        case.string,
        format!("{}", packet),
        "{}: Formatted string doesn't match",
        case.name
    );
}
