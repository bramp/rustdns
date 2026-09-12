//! Built-in and user-configured DNSSEC trust anchors.
//!
//! Trust anchors form the cryptographic root of the chain of trust ([RFC 4033 §2]).
//! By default, this embeds the official IANA Root Zone Trust Anchors ([RFC 7958]):
//! - KSK 19036 (Key Tag 19036, Algorithm 8, Digest Type 2: SHA-256)
//! - KSK 20326 (Key Tag 20326, Algorithm 8, Digest Type 2: SHA-256)
//! - KSK 38696 (Key Tag 38696, Algorithm 8, Digest Type 2: SHA-256)
//!
//! To download or update the official IANA `root-anchors.xml` fixture for testing, run:
//! ```sh
//! ./scripts/fetch_root_fixtures.sh --anchors-only
//! ```
//!
//! [RFC 4033 §2]: https://datatracker.ietf.org/doc/html/rfc4033#section-2
//! [RFC 7958]: https://datatracker.ietf.org/doc/html/rfc7958

use crate::resource::DS;
use crate::types::{Algorithm, DigestType};

/// Represents a DNSSEC trust anchor configured for a specific domain name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchor {
    /// Domain name this anchor applies to (e.g. `.` for the root zone).
    pub zone: String,

    /// Key tag of the anchored key.
    pub key_tag: u16,

    /// Algorithm of the anchored key.
    pub algorithm: Algorithm,

    /// Digest type (e.g. `DigestType::Sha256`).
    pub digest_type: DigestType,

    /// Digest bytes.
    pub digest: Vec<u8>,
}

impl TrustAnchor {
    /// Checks whether this trust anchor matches a given DS record.
    #[must_use]
    pub fn matches_ds(&self, ds: &DS) -> bool {
        self.key_tag == ds.key_tag
            && self.algorithm == ds.algorithm
            && self.digest_type == ds.digest_type
            && self.digest == ds.digest
    }
}

/// A repository of DNSSEC trust anchors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustStore {
    anchors: Vec<TrustAnchor>,
}

impl Default for TrustStore {
    /// Creates a trust store pre-populated with the official IANA Root Zone Trust Anchors.
    fn default() -> Self {
        Self::with_root_anchors()
    }
}

impl TrustStore {
    /// Creates an empty trust store with no trust anchors.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            anchors: Vec::new(),
        }
    }

    /// Creates a trust store initialized with current IANA root zone KSK anchors.
    #[must_use]
    pub fn with_root_anchors() -> Self {
        let mut store = Self::empty();
        // IANA Root Zone KSK-2010 (Key Tag 19036)
        // . IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5
        store.add_anchor(TrustAnchor {
            zone: ".".to_string(),
            key_tag: 19036,
            algorithm: Algorithm::RSASHA256,
            digest_type: DigestType::Sha256,
            digest: vec![
                0x49, 0xAA, 0xC1, 0x1D, 0x7B, 0x6F, 0x64, 0x46, 0x70, 0x2E, 0x54, 0xA1, 0x60,
                0x73, 0x71, 0x60, 0x7A, 0x1A, 0x41, 0x85, 0x52, 0x00, 0xFD, 0x2C, 0xE1, 0xCD,
                0xDE, 0x32, 0xF2, 0x4E, 0x8F, 0xB5,
            ],
        });

        // IANA Root Zone KSK-2017 (Key Tag 20326)
        // . IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
        store.add_anchor(TrustAnchor {
            zone: ".".to_string(),
            key_tag: 20326,
            algorithm: Algorithm::RSASHA256,
            digest_type: DigestType::Sha256,
            digest: vec![
                0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39, 0xA9, 0x5C, 0x0B, 0x0D, 0x7C,
                0x65, 0xD0, 0x84, 0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34, 0x57, 0x10,
                0x42, 0x37, 0xC7, 0xF8, 0xEC, 0x8D,
            ],
        });

        // IANA Root Zone KSK-2024 (Key Tag 38696)
        // . IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
        store.add_anchor(TrustAnchor {
            zone: ".".to_string(),
            key_tag: 38696,
            algorithm: Algorithm::RSASHA256,
            digest_type: DigestType::Sha256,
            digest: vec![
                0x68, 0x3D, 0x2D, 0x0A, 0xCB, 0x8C, 0x9B, 0x71, 0x2A, 0x19, 0x48, 0xB2, 0x7F,
                0x74, 0x12, 0x19, 0x29, 0x8D, 0x0A, 0x45, 0x0D, 0x61, 0x2C, 0x48, 0x3A, 0xF4,
                0x44, 0xA4, 0xC0, 0xFB, 0x2B, 0x16,
            ],
        });

        store
    }

    /// Adds a trust anchor to the store.
    pub fn add_anchor(&mut self, anchor: TrustAnchor) {
        self.anchors.push(anchor);
    }

    /// Finds all trust anchors applicable to a specific zone.
    #[must_use]
    pub fn find_anchors(&self, zone: &str) -> Vec<&TrustAnchor> {
        let norm = crate::names::canonical_key(zone);
        self.anchors
            .iter()
            .filter(|a| crate::names::canonical_key(&a.zone) == norm)
            .collect()
    }

    /// Returns all registered trust anchors.
    #[must_use]
    pub fn anchors(&self) -> &[TrustAnchor] {
        &self.anchors
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_all_iana_root_anchors_present_in_code() {
        #[derive(Debug, serde::Deserialize)]
        struct TrustAnchorXml {
            #[serde(rename = "Zone")]
            zone: String,
            #[serde(rename = "KeyDigest")]
            key_digests: Vec<KeyDigestXml>,
        }

        #[derive(Debug, serde::Deserialize)]
        struct KeyDigestXml {
            #[serde(rename = "KeyTag")]
            key_tag: u16,
            #[serde(rename = "Algorithm")]
            algorithm: u8,
            #[serde(rename = "DigestType")]
            digest_type: u8,
            #[serde(rename = "Digest")]
            digest: String,
        }

        let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("root-anchors.xml");

        if !fixture_path.exists() {
            eprintln!(
                "SKIPPED: {} not found. Run `./scripts/fetch_root_fixtures.sh --anchors-only` to download it.",
                fixture_path.display()
            );
            return;
        }

        let xml = std::fs::read_to_string(&fixture_path).expect("read root-anchors.xml");
        let parsed: TrustAnchorXml =
            quick_xml::de::from_str(&xml).expect("parse root-anchors.xml with quick-xml");

        assert_eq!(parsed.zone, ".");

        let store = TrustStore::default();
        let root_anchors = store.find_anchors(".");

        let mut xml_tags = Vec::new();
        for kd in &parsed.key_digests {
            let digest = crate::util::hex_decode(&kd.digest).unwrap();
            xml_tags.push(kd.key_tag);

            let matching = root_anchors.iter().find(|a| {
                a.key_tag == kd.key_tag
                    && a.algorithm.code() == kd.algorithm
                    && a.digest_type.code() == kd.digest_type
                    && a.digest == digest
            });
            assert!(
                matching.is_some(),
                "root anchor with KeyTag {} from root-anchors.xml must be present in TrustStore::default()",
                kd.key_tag
            );
        }

        // Verify bidirectional completeness: every anchor in code must also be in root-anchors.xml
        for anchor in &root_anchors {
            assert!(
                xml_tags.contains(&anchor.key_tag),
                "anchor with KeyTag {} in TrustStore is not in root-anchors.xml",
                anchor.key_tag
            );
        }

        assert_eq!(
            xml_tags.len(),
            root_anchors.len(),
            "number of anchors in code must match root-anchors.xml exactly"
        );
        assert!(root_anchors.len() >= 3);
    }
}
