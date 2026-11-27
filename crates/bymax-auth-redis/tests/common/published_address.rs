//! Where a started Redis container's port is published (layer: test support).
//!
//! The runtime can report a container started before it reports the port mapping, so the port
//! lookup is retried a few times. A lookup that still fails fails the test with the runtime's
//! error, the container id and the port: returning early would read as a pass.
//!
//! Shared by container-backed tests through `#[path]`.

use std::future::Future;
use std::time::Duration;

use testcontainers_modules::redis::Redis;
use testcontainers_modules::testcontainers::ContainerAsync;

/// How many times the port lookup runs before its error stands.
const ATTEMPTS: u32 = 5;

/// The pause between two port lookups.
const STEP: Duration = Duration::from_millis(200);

/// The host and the published port of `port`, failing the test when either cannot be read.
pub async fn host_and_port(container: &ContainerAsync<Redis>, port: u16) -> (String, u16) {
    match lookup(container, port).await {
        Ok(address) => address,
        Err(error) => unreachable!("{error}"),
    }
}

/// [`host_and_port`] with the failure handed back, naming the container id and the port.
pub async fn lookup(container: &ContainerAsync<Redis>, port: u16) -> Result<(String, u16), String> {
    let named = |what: &str, error: String| {
        format!(
            "{what} of container {} for port {port}: {error}",
            container.id()
        )
    };
    let host = container
        .get_host()
        .await
        .map_err(|error| named("host lookup", error.to_string()))?;
    let published = retried(|| container.get_host_port_ipv4(port))
        .await
        .map_err(|error| named("published port lookup", error.to_string()))?;
    Ok((host.to_string(), published))
}

/// Runs `attempt` until it succeeds, at most `ATTEMPTS` times, and hands back the last outcome.
pub async fn retried<T, E, F, Fut>(mut attempt: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut outcome = attempt().await;
    for _ in 1..ATTEMPTS {
        if outcome.is_ok() {
            break;
        }
        tokio::time::sleep(STEP).await;
        outcome = attempt().await;
    }
    outcome
}
