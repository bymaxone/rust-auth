//! A facade feature that names an engine flow must reach every adapter that has a feature of the
//! same name, or a consumer who enables both the flow and the adapter compiles the adapter without
//! its half of the flow (no routes, no extractors, no store implementation).
//!
//! The rule is checked on the manifests, as a set: every feature the facade shares with an adapter
//! must forward to it as a weak dependency feature (`adapter?/feature`, which enables nothing when
//! the adapter is not selected). A flow added to both later fails here until it is forwarded.

use std::collections::BTreeMap;
use std::path::Path;

/// The features of a manifest: name to the entries of its list, comments removed. A list may
/// span several lines; it ends at the line holding its closing bracket.
fn features(manifest: &str) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    let mut in_features = false;
    let mut open: Option<(String, String)> = None;
    for raw in manifest.lines() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if let Some((name, body)) = open.as_mut() {
            body.push_str(line);
            if line.contains(']') {
                out.insert(name.clone(), entries(body));
                open = None;
            }
        } else if line.starts_with('[') {
            in_features = line == "[features]";
        } else if let Some((name, body)) = line.split_once('=').filter(|_| in_features) {
            if body.contains(']') {
                out.insert(name.trim().to_owned(), entries(body));
            } else {
                open = Some((name.trim().to_owned(), body.to_owned()));
            }
        }
    }
    out
}

/// The quoted entries of a feature list.
fn entries(body: &str) -> Vec<String> {
    body.split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn every_feature_shared_with_an_adapter_is_forwarded_to_it() {
    let facade = features(&read("Cargo.toml"));
    assert!(
        facade.contains_key("platform"),
        "the facade manifest did not load"
    );

    for adapter in ["axum", "redis"] {
        let crate_name = format!("bymax-auth-{adapter}");
        let theirs = features(&read(&format!("../{crate_name}/Cargo.toml")));
        assert!(!theirs.is_empty(), "the {crate_name} manifest did not load");
        for name in theirs.keys().filter(|n| facade.contains_key(*n)) {
            if matches!(name.as_str(), "default" | "full") {
                continue;
            }
            let forward = format!("{crate_name}?/{name}");
            assert!(
                facade[name].contains(&forward),
                "facade feature `{name}` must forward to `{forward}`"
            );
        }
    }
}

#[test]
fn the_flows_the_adapters_gate_are_among_the_forwarded_ones() {
    // Guards the check above against passing vacuously: these are the features the adapters
    // gate today, so the shared set must contain them.
    let facade = features(&read("Cargo.toml"));
    let axum = features(&read("../bymax-auth-axum/Cargo.toml"));
    for flow in [
        "mfa",
        "sessions",
        "platform",
        "oauth",
        "invitations",
        "api-keys",
    ] {
        assert!(
            facade.contains_key(flow) && axum.contains_key(flow),
            "`{flow}` should be a feature of both the facade and the axum adapter"
        );
    }
}

#[cfg(all(feature = "axum", feature = "platform"))]
#[test]
fn the_facade_exposes_the_platform_extractors_when_both_features_are_on() {
    // Naming the type is the assertion: without the forwarding it does not compile.
    let user: Option<bymax_auth::axum::PlatformUser> = None;
    assert!(user.is_none());
}
