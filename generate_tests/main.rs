/// Simple tool that issues multiple DNS requests, captures their output
/// and writes out test data.
///
/// # Example
///
/// ```
/// cargo run --bin generate_tests
/// ```
/// If the tool fails, that indicates maybe a problem with the library.
use serde::Serialize;
use std::fs;
use std::net::UdpSocket;
use std::str::FromStr;

use rustdns::types::*;

const TEST_DATA_FILENAME: &str = "tests/test_data.yaml";

// Set of actual queries we do, to get example output.
const TESTS: [&str; 11] = [
    "A www.google.com",
    "AAAA www.google.com",
    "ANY www.google.com",
    "CNAME code.google.com",
    "MX google.com",
    "PTR 4.4.8.8.in-addr.arpa",
    "SOA google.com",
    "SRV _ldap._tcp.google.com",
    "TXT google.com",
    "A ☺️.com",
    "A a", // Invalid TLD
];

#[derive(Serialize)]
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

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");

    let mut output = Vec::new();

    for test in TESTS {
        println!("Running {}", test);

        let args: Vec<&str> = test.split_whitespace().collect();

        if args.len() != 2 {
            panic!("invalid number of arguments");
        }

        let qtype = QType::from_str(&args[0]).expect("invalid qtype");
        let domain = &args[1];

        let mut req = Message {
            id: 0xeccb, // randomise
            qr: QR::Query,
            opcode: Opcode::Query,
            rd: true,
            ad: true,

            ..Default::default()
        };

        req.add_question(domain, qtype, QClass::Internet);

        let req_buf = req.as_vec().expect("failed to encode message");

        output.push(TestCase {
            name: "Request ".to_owned() + test,
            string: format!("{}", req),    // dig formatted
            binary: hex::encode(&req_buf), // binary encoded
        });

        // Send the request, and always expect a response.
        socket
            .send_to(&req_buf, "8.8.8.8:53")
            .expect("could not send data");

        let mut resp_buf = [0; 1500];
        let (amt, _) = socket
            .recv_from(&mut resp_buf)
            .expect("received no response");

        let resp = Message::from_slice(&resp_buf[0..amt]).expect("invalid response from server");

        output.push(TestCase {
            name: "Response ".to_owned() + test,
            string: format!("{}", resp),            // dig formatted
            binary: hex::encode(&resp_buf[0..amt]), // binary encoded
        });
    }

    println!("Writing new test data to {}", TEST_DATA_FILENAME);

    match serde_yaml::to_string(&output) {
        Err(e) => eprintln!("Failed to serialise test results: {:?}", e),
        Ok(s) => fs::write(TEST_DATA_FILENAME, s)?,
    }

    Ok(())
}
