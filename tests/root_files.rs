// Integration tests validating zone parser handling of canonical IANA root files:
// - named.root (Root Hints)
// - root.zone (Authoritative Root Zone)
//
// If fixture files are not available locally, tests gracefully skip with instructions
// on how to download them via scripts/fetch_root_fixtures.sh.

#![cfg(feature = "zones")]

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

fn get_fixture_path(filename: &str, env_var: &str) -> Option<PathBuf> {
    if let Ok(val) = std::env::var(env_var) {
        let path = PathBuf::from(val);
        if path.is_file() {
            return Some(path);
        } else {
            return None;
        }
    }

    let default_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(filename);

    if default_path.is_file() {
        Some(default_path)
    } else {
        None
    }
}

#[test]
fn test_parse_root_hints() {
    let hints_path = match get_fixture_path("named.root", "ROOT_HINTS_PATH") {
        Some(path) => path,
        None => {
            eprintln!(
                "SKIPPED: tests/fixtures/named.root not found. Run ./scripts/fetch_root_fixtures.sh to download."
            );
            return;
        }
    };

    let contents = fs::read_to_string(&hints_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", hints_path.display(), e));

    assert!(!contents.is_empty(), "named.root fixture must not be empty");

    let zone_file = rustdns::zones::File::from_str(&contents)
        .unwrap_or_else(|e| panic!("failed to parse named.root zone file: {}", e));

    let records = zone_file
        .try_into_records()
        .unwrap_or_else(|e| panic!("failed to process named.root records: {}", e));

    // named.root has:
    // 13 root NS records (. NS [a-m].root-servers.net.)
    // 13 A records (one per [a-m].root-servers.net.)
    // 13 AAAA records (one per [a-m].root-servers.net.)
    // Total = 39 records.
    assert_eq!(
        records.len(),
        39,
        "named.root should resolve exactly 39 records (13 NS, 13 A, 13 AAAA)"
    );

    let mut ns_servers = std::collections::BTreeSet::new();
    let mut a_servers = std::collections::BTreeSet::new();
    let mut aaaa_servers = std::collections::BTreeSet::new();

    for r in &records {
        assert_eq!(
            r.class,
            rustdns::Class::Internet,
            "all records should default to Class::IN"
        );
        assert_eq!(
            r.ttl,
            std::time::Duration::from_secs(3600000),
            "root hints TTL should be 3600000s"
        );

        match &r.resource {
            rustdns::Resource::NS(ns) => {
                assert!(
                    r.name.is_empty() || r.name == ".",
                    "NS record domain should be root, got {:?}",
                    r.name
                );
                ns_servers.insert(ns.to_ascii_lowercase());
            }
            rustdns::Resource::A(_) => {
                a_servers.insert(r.name.to_ascii_lowercase());
            }
            rustdns::Resource::AAAA(_) => {
                aaaa_servers.insert(r.name.to_ascii_lowercase());
            }
            other => panic!("unexpected record in named.root: {:?}", other),
        }
    }

    assert_eq!(ns_servers.len(), 13, "expected 13 root NS servers");
    assert_eq!(a_servers.len(), 13, "expected 13 root A glue records");
    assert_eq!(aaaa_servers.len(), 13, "expected 13 root AAAA glue records");

    for letter in b'a'..=b'm' {
        let expected_server = format!("{}.root-servers.net", letter as char);
        assert!(
            ns_servers.contains(&expected_server),
            "missing root NS {}",
            expected_server
        );
        assert!(
            a_servers.contains(&expected_server),
            "missing root A record for {}",
            expected_server
        );
        assert!(
            aaaa_servers.contains(&expected_server),
            "missing root AAAA record for {}",
            expected_server
        );
    }
}

#[test]
fn test_parse_root_zone() {
    let zone_path = match get_fixture_path("root.zone", "ROOT_ZONE_PATH") {
        Some(path) => path,
        None => {
            eprintln!(
                "SKIPPED: tests/fixtures/root.zone not found. Run ./scripts/fetch_root_fixtures.sh to download."
            );
            return;
        }
    };

    let metadata = fs::metadata(&zone_path)
        .unwrap_or_else(|e| panic!("failed to read metadata for {}: {}", zone_path.display(), e));

    assert!(
        metadata.len() > 100_000,
        "root.zone fixture must be larger than 100KB"
    );
    // Full zone parsing validation will run here once DNSSEC types are supported.
}
