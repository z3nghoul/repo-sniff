//! Thresholds on real malicious repositories. The samples are never in this
//! repository: `REPO_SNIFF_REAL_SAMPLES` names one or more directories (several
//! separated like `PATH` on the OS) and each directory directly below one of
//! them is scanned as one repository. Without the variable the test does
//! nothing, so CI and a normal `cargo test` never touch a sample.
//!
//! The table is for the public corpus rubenmarcus/malicious-repositories at
//! commit dc82f33 ("collected from LinkedIn scammers"): a folder per lure, each
//! a "take-home test" project. Only folder names are written here, never any
//! content of the corpus. Clone it with a hardened git (empty configuration,
//! no hooks, no checkout of symlinks) and never run anything in it.
//!
//! ```sh
//! REPO_SNIFF_REAL_SAMPLES=/path/to/malicious-repositories cargo test -p repo-sniff-core --test real_samples -- --nocapture
//! ```

use std::env;
use std::fs;
use std::path::Path;

use repo_sniff_core::{Limits, Severity, builtin_rules, scan};

const VARIABLE: &str = "REPO_SNIFF_REAL_SAMPLES";

/// Lures with a JavaScript loader: each must reach at least HIGH.
const LOADER_LURES: &[&str] = &[
    "0xnfteth-horsepowerfi",
    "golden-city",
    "multify_staking",
    "real_estate",
    "real_estate_new",
    "real-estate-rental-platform",
    "sarostech-assessment",
    "trend-dev-preproduction",
    "web3game",
];

/// Known exceptions: folders the scanner does not bring to HIGH, and why. They
/// are scanned (the scan must complete) but no level is required.
const KNOWN_EXCEPTIONS: &[(&str, &str)] = &[
    (
        "challenge-experiment-module",
        "the payload is a dependency name in package.json, no loader code; needs the dependency analysis of milestone 9 (M9)",
    ),
    (
        "coinpool-rental-platform1.0",
        "the payload is a dependency name in package.json, no loader code; needs the dependency analysis of milestone 9 (M9)",
    ),
    (
        "erc20-token-dapp",
        "the payload is a dependency name in package.json, no loader code; needs the dependency analysis of milestone 9 (M9)",
    ),
    (
        "munity-game",
        "the payload is a dependency name in package.json, no loader code; needs the dependency analysis of milestone 9 (M9)",
    ),
    (
        "DEX-staking-project-ultrax",
        "no loader signature found in the folder; only a vendored charting bundle (INFO, minified source). To be reviewed by hand, not counted as a lure with a loader",
    ),
    ("scammer-documents", "documents only, no code"),
];

#[test]
fn real_samples_reach_their_thresholds() {
    let Some(value) = env::var_os(VARIABLE) else {
        eprintln!("{VARIABLE} is not set: real-sample test skipped");
        return;
    };
    let rules = builtin_rules().unwrap();
    let mut checked = 0;
    for root in env::split_paths(&value) {
        let mut folders: Vec<_> = fs::read_dir(&root)
            .unwrap_or_else(|err| panic!("{}: {err}", root.display()))
            .map(|entry| entry.unwrap())
            .filter(|entry| entry.file_type().unwrap().is_dir())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name != ".git")
            .collect();
        folders.sort();
        for name in folders {
            let loader = LOADER_LURES.contains(&name.as_str());
            let exception = KNOWN_EXCEPTIONS.iter().find(|(known, _)| *known == name);
            if !loader && exception.is_none() {
                eprintln!("{name}: not in the table, not checked");
                continue;
            }
            let report = scan(&root.join(&name), &rules, Limits::default());
            let top = report.findings.iter().map(|f| f.severity).max();
            eprintln!(
                "{name}: {} findings, top level {top:?}",
                report.findings.len()
            );
            if loader {
                assert!(
                    top >= Some(Severity::High),
                    "{name}: a lure with a loader reached only {top:?}"
                );
            } else if let Some((_, why)) = exception {
                eprintln!("{name}: known exception: {why}");
            }
            assert!(
                !report.skipped.iter().any(|s| s.path == Path::new("")),
                "{name}: the scan could not start"
            );
            checked += 1;
        }
    }
    assert!(
        checked > 0,
        "{VARIABLE} is set but none of its folders is in the table"
    );
}
