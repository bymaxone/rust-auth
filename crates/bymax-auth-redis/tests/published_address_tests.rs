//! The container address lookup: the port lookup is retried a bounded number of times, and a
//! lookup that still fails names the container and the port (layer: test support, tests).

use std::sync::atomic::{AtomicU32, Ordering};

use testcontainers_modules::redis::{REDIS_PORT, Redis};
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::core::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[path = "common/docker_gate.rs"]
mod docker_gate;
#[path = "common/published_address.rs"]
mod published_address;

/// Start a `redis:8` container, or `None` when Docker is not available.
async fn try_start() -> Option<ContainerAsync<Redis>> {
    match Redis::default().with_tag("8").start().await {
        Ok(container) => Some(container),
        Err(error) => docker_gate::docker_unavailable("redis:8", error),
    }
}

/// Runs the retry over a lookup that answers on call `answers_on`, returning the outcome and the
/// number of calls made.
async fn run_lookup_answering_on(answers_on: u32) -> (Result<u32, u32>, u32) {
    let calls = AtomicU32::new(0);
    let outcome = published_address::retried(|| {
        let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
        async move {
            if call < answers_on {
                Err(call)
            } else {
                Ok(call)
            }
        }
    })
    .await;
    (outcome, calls.load(Ordering::SeqCst))
}

#[tokio::test]
async fn a_lookup_that_answers_late_is_retried_until_it_does() {
    assert_eq!(run_lookup_answering_on(1).await, (Ok(1), 1));
    assert_eq!(run_lookup_answering_on(5).await, (Ok(5), 5));
}

#[tokio::test]
async fn a_lookup_that_never_answers_stops_after_five_calls_with_the_last_error() {
    assert_eq!(run_lookup_answering_on(u32::MAX).await, (Err(5), 5));
}

#[tokio::test]
async fn a_published_port_is_found_and_an_unpublished_one_names_the_container_and_port() {
    let Some(container) = try_start().await else { return };

    let (host, port) = published_address::host_and_port(&container, REDIS_PORT).await;
    assert!(!host.is_empty() && port != 0);

    let failed = published_address::lookup(&container, 6380).await;
    let Err(error) = failed else { unreachable!("6380 is not published") };
    assert!(error.contains(container.id()), "{error}");
    assert!(error.contains("for port 6380"), "{error}");
}
