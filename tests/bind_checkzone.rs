//! Acceptance/rejection coverage from a pinned BIND checkzone corpus.
#![cfg(feature = "zones")]

use rustdns::zones::File;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const CONFIG: &str = include_str!("bind_checkzone.yaml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    revision: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    file: String,
    expect: Expect,
    #[serde(default = "default_origin")]
    origin: String,
    reason: Option<String>,
    error_line: Option<usize>,
    failure: Option<Stage>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Stage {
    Parse,
    Process,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Expect {
    Accept,
    Reject,
    Todo,
    Excluded,
}

fn default_origin() -> String {
    "example.".to_owned()
}

fn is_fixture(name: &str) -> bool {
    (name.starts_with("good") || name.starts_with("bad")) && name.ends_with(".db")
}

fn validate(config: &Config, inventory: &BTreeSet<String>) -> Result<(), String> {
    if config.revision.len() != 40 || !config.revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("revision must be a full commit hash".to_owned());
    }
    let configured: BTreeSet<_> = config.cases.iter().map(|case| case.file.clone()).collect();
    if configured.len() != config.cases.len() {
        return Err("duplicate fixture entries".to_owned());
    }
    if &configured != inventory {
        return Err(format!(
            "unconfigured fixtures: {:?}; stale entries: {:?}",
            inventory.difference(&configured).collect::<Vec<_>>(),
            configured.difference(inventory).collect::<Vec<_>>(),
        ));
    }
    if configured.is_empty() {
        return Err("fixture inventory must not be empty".to_owned());
    }
    for case in &config.cases {
        let name = &case.file;
        if !is_fixture(name) || Path::new(name).components().count() != 1 {
            return Err(format!("{name}: expected an exact good/bad .db filename"));
        }
        if !case.origin.ends_with('.') {
            return Err(format!("{name}: origin must be absolute"));
        }
        if case.expect == Expect::Todo && !name.starts_with("good") {
            return Err(format!("{name}: TODO outcomes are only for valid fixtures"));
        }
        if (case.expect == Expect::Todo) != case.failure.is_some() {
            return Err(format!(
                "{name}: only TODO cases must specify a failure stage"
            ));
        }
        if matches!(case.expect, Expect::Todo | Expect::Excluded)
            && case
                .reason
                .as_ref()
                .is_none_or(|reason| reason.trim().is_empty())
        {
            return Err(format!("{name}: exclusions and TODOs require a reason"));
        }
        if case.expect == Expect::Todo
            || case
                .reason
                .as_ref()
                .is_some_and(|reason| reason.contains("TODO"))
        {
            let reason = case.reason.as_deref().unwrap_or_default();
            if !reason.contains("TODO") || !reason.contains("PLAN.md#") {
                return Err(format!(
                    "{name}: TODO must reference a specific PLAN.md anchor"
                ));
            }
            let anchor = reason
                .split("PLAN.md#")
                .nth(1)
                .and_then(|rest| rest.split(')').next())
                .unwrap_or_default();
            let plan = include_str!("../PLAN.md");
            if anchor.is_empty() || !plan.contains(&format!("id=\"{anchor}\"")) {
                return Err(format!("{name}: unknown roadmap anchor {anchor}"));
            }
        }
        if case.expect == Expect::Reject {
            if !name.starts_with("bad") || case.error_line.is_none_or(|line| line == 0) {
                return Err(format!(
                    "{name}: rejection requires a bad fixture and error_line"
                ));
            }
        } else if case.error_line.is_some() {
            return Err(format!(
                "{name}: error_line is only valid for rejection checks"
            ));
        }
    }
    Ok(())
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bind-checkzone")
}

fn check_case(case: &Case, text: &str) -> Result<(), String> {
    let parsed = text.parse::<File>();
    if case.expect == Expect::Reject {
        return match parsed {
            Err(error) => {
                let line = match error.line_col {
                    pest::error::LineColLocation::Pos((line, _))
                    | pest::error::LineColLocation::Span((line, _), _) => line,
                };
                if Some(line) == case.error_line {
                    Ok(())
                } else {
                    Err(format!(
                        "failed on line {line}, expected {:?}: {error}",
                        case.error_line
                    ))
                }
            }
            Ok(_) => Err("expected a syntax/RDATA rejection, but parsing succeeded".to_owned()),
        };
    }
    let processed = parsed
        .map_err(|error| (Stage::Parse, error.to_string()))
        .and_then(|file| {
            File::try_new(Some(case.origin.clone()), file.entries)
                .and_then(File::try_into_records)
                .map_err(|error| (Stage::Process, error.to_string()))
        });
    match (case.expect == Expect::Todo, processed) {
        (false, Err((stage, error))) => Err(format!("{stage:?}: {error}")),
        (true, Ok(_)) => Err(format!(
            "unexpected success; remove TODO: {:?}",
            case.reason
        )),
        (true, Err((stage, _))) if case.failure.as_ref() == Some(&stage) => Ok(()),
        (true, Err((stage, error))) => Err(format!(
            "TODO failure moved to {stage:?}, expected {:?}; update the gap: {error}",
            case.failure,
        )),
        (false, Ok(records)) if records.is_empty() => Err("no records produced".to_owned()),
        (false, Ok(_)) => Ok(()),
    }
}

#[test]
fn configuration_is_valid() {
    let config: Config = yaml_serde::from_str(CONFIG).expect("invalid checkzone configuration");
    validate(
        &config,
        &config.cases.iter().map(|case| case.file.clone()).collect(),
    )
    .unwrap();
}

#[test]
fn inventory_rejects_unlisted_stale_and_duplicate_entries() {
    let mut config: Config = yaml_serde::from_str(CONFIG).unwrap();
    let inventory: BTreeSet<_> = config.cases.iter().map(|case| case.file.clone()).collect();
    let mut added = inventory.clone();
    added.insert("good-new.db".to_owned());
    assert!(
        validate(&config, &added)
            .unwrap_err()
            .contains("unconfigured")
    );
    let mut removed = inventory.clone();
    removed.remove(&config.cases[0].file);
    assert!(validate(&config, &removed).unwrap_err().contains("stale"));
    config.cases[1].file = config.cases[0].file.clone();
    assert!(
        validate(&config, &inventory)
            .unwrap_err()
            .contains("duplicate")
    );
}

#[test]
fn configuration_rejects_invalid_exceptions_and_unknown_fields() {
    for (yaml, expected) in [
        (
            "{file: good-test.db, expect: todo, failure: parse, reason: missing}",
            "TODO must reference",
        ),
        (
            "{file: good-test.db, expect: todo, failure: parse, reason: 'TODO [plan](../PLAN.md#missing)'}",
            "unknown roadmap anchor",
        ),
        (
            "{file: good-test.db, expect: todo, reason: missing}",
            "failure stage",
        ),
        ("{file: good-test.db, expect: excluded}", "require a reason"),
        (
            "{file: good-test.db, expect: accept, origin: relative}",
            "origin must be absolute",
        ),
        (
            "{file: good-test.db, expect: reject, error_line: 1}",
            "rejection requires",
        ),
        ("{file: bad-test.db, expect: reject}", "rejection requires"),
        (
            "{file: bad-test.db, expect: reject, error_line: 0}",
            "rejection requires",
        ),
        (
            "{file: good-test.db, expect: accept, error_line: 1}",
            "only valid for rejection",
        ),
    ] {
        let case: Case = yaml_serde::from_str(yaml).unwrap();
        let inventory = [case.file.clone()].into_iter().collect();
        let config = Config {
            revision: "a".repeat(40),
            cases: vec![case],
        };
        assert!(
            validate(&config, &inventory)
                .unwrap_err()
                .contains(expected),
            "{yaml}"
        );
    }
    assert!(yaml_serde::from_str::<Case>("{file: good.db, expect: accept, typo: true}").is_err());
}

#[test]
fn outcomes_detect_unexpected_success_wrong_rejection_and_stage_changes() {
    let mut case: Case = yaml_serde::from_str("{file: good-test.db, expect: accept}").unwrap();
    let valid = "$TTL 60\n@ A 192.0.2.1";
    assert!(check_case(&case, valid).is_ok());
    assert!(
        check_case(&case, "@ A 192.0.2.1")
            .unwrap_err()
            .contains("Process")
    );
    assert!(
        check_case(&case, "not a record")
            .unwrap_err()
            .contains("Parse")
    );
    case.expect = Expect::Todo;
    case.failure = Some(Stage::Parse);
    assert!(check_case(&case, "not a record").is_ok());
    assert!(
        check_case(&case, valid)
            .unwrap_err()
            .contains("unexpected success")
    );
    assert!(
        check_case(&case, "@ A 192.0.2.1")
            .unwrap_err()
            .contains("failure moved")
    );
    case.failure = Some(Stage::Process);
    assert!(check_case(&case, "@ A 192.0.2.1").is_ok());
    case.expect = Expect::Reject;
    case.failure = None;
    case.error_line = Some(2);
    assert!(check_case(&case, "$TTL 60\nnot a record").is_ok());
    assert!(
        check_case(&case, "not a record")
            .unwrap_err()
            .contains("failed on line")
    );
    assert!(
        check_case(&case, valid)
            .unwrap_err()
            .contains("parsing succeeded")
    );
    assert!(
        check_case(&case, "@ A 192.0.2.1")
            .unwrap_err()
            .contains("parsing succeeded")
    );
}

#[test]
#[ignore = "fetch with scripts/fetch_bind_fixtures.sh, then run with --include-ignored"]
fn bind_checkzone_conformance() {
    let config: Config = yaml_serde::from_str(CONFIG).expect("invalid checkzone configuration");
    let directory = fixture_dir();
    let revision = fs::read_to_string(directory.join("REVISION"))
        .expect("BIND fixtures missing: run ./scripts/fetch_bind_fixtures.sh");
    assert_eq!(
        revision.trim(),
        config.revision,
        "stale BIND fixture revision"
    );
    for name in ["LICENSE", "COPYRIGHT", "tests.sh"] {
        assert!(directory.join(name).is_file(), "missing upstream {name}");
    }
    let zones = directory.join("zones");
    let inventory: BTreeSet<_> = fs::read_dir(&zones)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| is_fixture(name))
        .collect();
    validate(&config, &inventory).unwrap();
    let mut failures = Vec::new();
    let mut counts = [0_usize; 4];
    for case in &config.cases {
        let name = &case.file;
        let index = match case.expect {
            Expect::Accept => 0,
            Expect::Reject => 1,
            Expect::Todo => 2,
            Expect::Excluded => 3,
        };
        counts[index] += 1;
        if case.expect == Expect::Excluded {
            continue;
        }
        let text = fs::read_to_string(zones.join(name)).unwrap();
        if let Err(error) = check_case(case, &text) {
            failures.push(format!("{name}: {error}"));
        }
        if case.expect == Expect::Todo {
            eprintln!("{name}: {}", case.reason.as_deref().unwrap());
        }
    }
    eprintln!(
        "BIND checkzone: {} accepted, {} rejected, {} TODO, {} excluded",
        counts[0], counts[1], counts[2], counts[3]
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
