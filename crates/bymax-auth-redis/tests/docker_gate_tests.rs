//! The `BYMAX_REQUIRE_DOCKER` switch: with it set a missing container runtime fails the test, and
//! without it the test skips and says so. Needs no Docker; the end-to-end case points a real
//! container start at a daemon that does not exist.

use std::process::Command;

use testcontainers_modules::redis::Redis;
use testcontainers_modules::testcontainers::core::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[path = "common/docker_gate.rs"]
mod docker_gate;

/// A daemon address nothing listens on.
const DEAD_DAEMON: &str = "unix:///nonexistent/bymax-docker.sock";

#[test]
#[should_panic(expected = "BYMAX_REQUIRE_DOCKER=1 and no container runtime answered")]
fn a_required_runtime_that_does_not_answer_fails_the_test() {
    let _: Option<u8> = docker_gate::decide(true, "redis:8", "connection refused");
}

#[test]
fn an_optional_runtime_that_does_not_answer_skips() {
    let outcome: Option<u8> = docker_gate::decide(false, "redis:8", "connection refused");
    assert!(outcome.is_none());
}

/// A real container start judged by the gate. In this process it starts a container like every
/// other container-backed test; the two child-process cases below run it with `DOCKER_HOST`
/// pointing at a daemon that does not exist.
#[tokio::test]
async fn a_container_start_is_judged_by_the_gate() {
    let started = Redis::default().with_tag("8").start().await;
    if let Err(error) = started {
        let skipped: Option<u8> = docker_gate::docker_unavailable("redis:8", error);
        assert!(skipped.is_none());
    }
}

/// Run the probe in a child process against a dead daemon, with the switch on or off.
fn run_probe(require: bool) -> Option<std::process::Output> {
    let mut child = Command::new(std::env::current_exe().unwrap_or_default());
    child
        .args([
            "--exact",
            "a_container_start_is_judged_by_the_gate",
            "--nocapture",
        ])
        .env("DOCKER_HOST", DEAD_DAEMON)
        .env_remove("BYMAX_REQUIRE_DOCKER");
    if require {
        child.env("BYMAX_REQUIRE_DOCKER", "1");
    }
    child.output().ok()
}

#[test]
fn with_the_switch_on_a_real_container_start_that_cannot_reach_a_daemon_fails() {
    let output = run_probe(true);
    assert!(output.is_some(), "the probe could not be spawned");
    let Some(output) = output else { return };
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "the probe passed:\n{stderr}");
    assert!(stderr.contains("BYMAX_REQUIRE_DOCKER=1"), "{stderr}");
}

#[test]
fn with_the_switch_off_the_same_start_skips_loudly_and_passes() {
    let output = run_probe(false);
    assert!(output.is_some(), "the probe could not be spawned");
    let Some(output) = output else { return };
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "the probe failed:\n{stderr}");
    assert!(stderr.contains("skipped: no Docker (redis:8)"), "{stderr}");
}
