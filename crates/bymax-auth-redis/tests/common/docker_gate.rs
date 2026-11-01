//! What a Docker-backed test does when no container runtime answers (layer: test support).
//!
//! A test that returns early because Docker is missing passes while proving nothing, so a
//! developer machine without Docker and a CI runner whose Docker broke look the same: green.
//! `BYMAX_REQUIRE_DOCKER=1` turns that skip into a failure, and CI sets it. Without it the test
//! still skips, but says so on stderr instead of passing silently.
//!
//! Shared by every crate's container-backed tests through `#[path]`, so the rule is stated once.

use std::fmt::Display;

/// The switch that makes a missing container runtime a test failure.
const REQUIRE_DOCKER: &str = "BYMAX_REQUIRE_DOCKER";

/// The outcome for a container that failed to start: a failure when the switch is on, otherwise a
/// loud skip (`None`, which the caller's `let Some(..) else { return }` turns into an early return).
pub fn docker_unavailable<T>(image: &str, error: impl Display) -> Option<T> {
    let required = std::env::var(REQUIRE_DOCKER).as_deref() == Ok("1");
    decide(required, image, &error.to_string())
}

/// The decision itself, with the switch passed in so it can be exercised without touching the
/// process environment.
pub fn decide<T>(required: bool, image: &str, error: &str) -> Option<T> {
    assert!(
        !required,
        "{REQUIRE_DOCKER}=1 and no container runtime answered for {image}: {error}"
    );
    eprintln!(
        "skipped: no Docker ({image}): {error}; set {REQUIRE_DOCKER}=1 to make this a failure"
    );
    None
}
