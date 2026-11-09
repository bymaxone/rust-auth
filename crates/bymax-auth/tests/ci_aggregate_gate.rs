//! Every job of `ci.yml` gates a merge only through the `ci-pass` aggregate, the one check a
//! branch protection rule can name. A job missing from its `needs` list runs, and its failure
//! leaves the aggregate green: a gate that gates nothing, with no sign that it does not.
//!
//! The rule is checked on the workflow file as a set, in both directions: a job added without
//! being listed fails here, and so does a listed name no job carries.

use std::collections::BTreeSet;
use std::path::Path;

fn workflow() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/ci.yml");
    std::fs::read_to_string(path).unwrap_or_default()
}

/// The ids of the jobs: the keys written two spaces in, under `jobs:`.
fn jobs(text: &str) -> BTreeSet<String> {
    text.split("\njobs:\n")
        .nth(1)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.strip_prefix("  ")?.strip_suffix(':'))
        .filter(|name| !name.is_empty() && !name.contains(' '))
        .map(str::to_owned)
        .collect()
}

/// The names in the `needs` list of the `ci-pass` job.
fn aggregate_needs(text: &str) -> BTreeSet<String> {
    text.split("\n  ci-pass:\n")
        .nth(1)
        .unwrap_or_default()
        .lines()
        .skip_while(|line| line.trim() != "needs:")
        .skip(1)
        .map_while(|line| line.strip_prefix("      - "))
        .map(|name| name.trim().to_owned())
        .collect()
}

#[test]
fn every_job_is_a_dependency_of_the_aggregate_check() {
    let text = workflow();
    let mut all = jobs(&text);
    assert!(all.remove("ci-pass"), "the workflow did not load: {all:?}");
    assert!(all.len() > 10, "{all:?}");
    assert_eq!(all, aggregate_needs(&text));
}
