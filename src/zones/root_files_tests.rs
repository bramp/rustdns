// Tests validating zone parser handling of canonical IANA root files:
// - named.root (Root Hints)
// - root.zone (Authoritative Root Zone)
//
// If fixture files are not available locally, tests gracefully skip with instructions
// on how to download them via scripts/fetch_root_fixtures.sh.

use crate::zones::File;
use crate::{Class, Resource, Type};
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

    let zone_file = File::from_str(&contents)
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
            Class::Internet,
            "all records should default to Class::IN"
        );
        assert_eq!(
            r.ttl,
            std::time::Duration::from_secs(3600000),
            "root hints TTL should be 3600000s"
        );

        match &r.resource {
            Resource::NS(ns) => {
                assert!(
                    r.name.is_empty() || r.name == ".",
                    "NS record domain should be root, got {:?}",
                    r.name
                );
                ns_servers.insert(ns.to_ascii_lowercase());
            }
            Resource::A(_) => {
                a_servers.insert(r.name.to_ascii_lowercase());
            }
            Resource::AAAA(_) => {
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

    let content = fs::read_to_string(&zone_path).expect("read root.zone");
    let zone_file = File::from_str(&content)
        .expect("File::from_str should parse entire root zone file");
    let records = zone_file
        .try_into_records()
        .expect("try_into_records should resolve zone records");

    let count = records.len();
    let mut type_counts = std::collections::BTreeMap::new();
    let mut found_root_soa = false;
    let mut found_com_ds = false;
    let mut found_com_ns = false;
    let mut dnskeys = Vec::new();

    for record in &records {
        *type_counts.entry(record.resource.r#type()).or_insert(0) += 1;

        if record.name == "." || record.name.is_empty() {
            if let Resource::SOA(ref soa) = record.resource {
                assert!(
                    soa.mname.contains("root-servers.net"),
                    "unexpected root SOA mname: {}",
                    soa.mname
                );
                found_root_soa = true;
            }
            if let Resource::DNSKEY(ref key) = record.resource {
                dnskeys.push(key.clone());
            }
        }
        if record.name == "com." || record.name == "com" {
            if let Resource::DS(_) = record.resource {
                found_com_ds = true;
            }
            if let Resource::NS(_) = record.resource {
                found_com_ns = true;
            }
        }
    }

    assert!(
        count > 20_000,
        "expected over 20,000 records, got {}",
        count
    );
    assert!(found_root_soa, "must find root SOA record");
    assert!(found_com_ds, "must find com. DS record");
    assert!(found_com_ns, "must find com. NS record");
    assert!(dnskeys.len() >= 2, "must find root DNSKEYs (KSK + ZSK)");

    // Test DNSKEY key_tag calculation and trust anchor match
    #[cfg(feature = "dnssec")]
    {
        let trust_store = crate::dnssec::TrustStore::default();
        let root_anchors = trust_store.find_anchors(".");
        assert!(!root_anchors.is_empty(), "must have root trust anchors");

        let mut matched_ksk = false;
        for dnskey in &dnskeys {
            let tag = dnskey.key_tag();
            if tag == 20326 || tag == 38696 {
                // Verify calculated DS matches trust anchor
                let calculated_ds =
                    crate::resource::DS::from_dnskey(".", dnskey, crate::types::DigestType::Sha256)
                        .expect("calculate DS");
                for anchor in &root_anchors {
                    if anchor.key_tag == tag {
                        assert!(
                            anchor.matches_ds(&calculated_ds),
                            "calculated DS must match IANA trust anchor"
                        );
                        matched_ksk = true;
                    }
                }
            }
        }
        assert!(
            matched_ksk,
            "must match at least one root KSK trust anchor in root.zone"
        );
    }

    assert!(
        type_counts.contains_key(&Type::RRSIG),
        "must contain RRSIG records"
    );
    assert!(
        type_counts.contains_key(&Type::NSEC),
        "must contain NSEC records"
    );
    assert!(
        type_counts.contains_key(&Type::ZONEMD),
        "must contain ZONEMD records"
    );

    // Verify RRSIG cryptographic signature over root DNSKEY RRset using root KSK
    #[cfg(feature = "dnssec")]
    {
        let mut root_dnskeys = Vec::new();
        let mut root_dnskey_rrsig: Option<crate::resource::RRSIG> = None;

        for record in &records {
            if record.name == "." || record.name.is_empty() {
                if let Resource::DNSKEY(_) = &record.resource {
                    root_dnskeys.push(record.clone());
                } else if let Resource::RRSIG(rrsig) = &record.resource {
                    if rrsig.type_covered == Type::DNSKEY
                        && (rrsig.key_tag == 20326 || rrsig.key_tag == 38696)
                    {
                        root_dnskey_rrsig = Some(rrsig.clone());
                    }
                }
            }
        }

        if let Some(rrsig) = root_dnskey_rrsig {
            // Find matching KSK
            let ksk = dnskeys
                .iter()
                .find(|k| k.key_tag() == rrsig.key_tag)
                .expect("must find matching KSK in root zone");

            let report = crate::dnssec::validate_rrset(
                ".",
                &root_dnskeys,
                &rrsig,
                ksk,
                rrsig.inception + std::time::Duration::from_secs(10),
            )
            .expect("root DNSKEY RRset signature must be cryptographically valid");

            assert_eq!(report.key_tag, rrsig.key_tag);
            assert_eq!(report.records_count, root_dnskeys.len());
        }
    }
}
