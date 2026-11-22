//! Where a freshly started Redis container is, and a wait until it answers (layer: test support).
//!
//! The address: a container's published port is reached by the host name the runtime reports, and
//! that is `localhost`, which resolves to `::1` before `127.0.0.1`. Any other process listening on
//! `[::1]` at the same port number, such as a development server that binds only to `localhost`,
//! answers in place of the container, and the first command fails on bytes that are not Redis.
//! [`redis_url`] addresses the IPv4 loopback instead, which is where the container is published.
//!
//! The wait: a container is also reported started before its published port is guaranteed to take
//! the first connection. This probes with a `PING` and a write round-trip, a bounded number of
//! times, and then fails with the last error: a server that never answers is a failure, never a
//! skip, because a skip would read as a pass.
//!
//! Shared by the container-backed tests of this crate through `#[path]`.

use std::future::Future;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// The URL of a container published on `host` at `port`, with the name `localhost` replaced by the
/// IPv4 loopback so that a listener on `[::1]` cannot answer for it.
pub fn redis_url(host: &str, port: u16) -> String {
    let host = if host == "localhost" {
        "127.0.0.1"
    } else {
        host
    };
    format!("redis://{host}:{port}")
}

/// How many times the probe runs before the wait gives up.
const ATTEMPTS: u32 = 50;

/// The pause between two attempts; `ATTEMPTS` of them bound the wait at about five seconds.
const STEP: Duration = Duration::from_millis(100);

/// Waits until `url` answers a `PING` and a write round-trip, and fails the test with the last
/// error when it does not within the bound.
pub async fn wait_until_ready(url: &str) {
    wait_with(url, ATTEMPTS, STEP).await;
}

/// [`wait_until_ready`] with the bound given, so the failure can be exercised without waiting.
pub async fn wait_with(url: &str, attempts: u32, step: Duration) {
    let outcome = retry_with(attempts, step, || probe_once(url)).await;
    assert!(
        outcome.is_ok(),
        "redis at {url} did not answer a PING and a write round-trip: {}",
        outcome.err().unwrap_or_default()
    );
}

/// Runs `probe` until it succeeds or `attempts` runs have failed, pausing `step` between runs.
/// Answers the number of the attempt that succeeded, or the last error with its attempt number.
pub async fn retry_with<F, Fut>(attempts: u32, step: Duration, mut probe: F) -> Result<u32, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let mut last = "no attempt was made".to_owned();
    for attempt in 1..=attempts {
        match probe().await {
            Ok(()) => return Ok(attempt),
            Err(error) => last = format!("attempt {attempt} of {attempts}: {error}"),
        }
        if attempt < attempts {
            tokio::time::sleep(step).await;
        }
    }
    Err(last)
}

/// How long one probe may take before it counts as a failed attempt, so a listener that accepts
/// and then says nothing cannot stall the wait.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// One probe over a plain connection: a `PING`, then a `SET`, `GET` and `DEL` of a throwaway key, so
/// a test that inspects the keyspace afterwards finds nothing left behind. It speaks the inline
/// protocol itself, which needs no client crate and lets a listener that is not Redis show what it
/// answered in the error.
pub async fn probe_once(url: &str) -> Result<(), String> {
    let address = url.strip_prefix("redis://").unwrap_or(url);
    let work = async {
        let stream = TcpStream::connect(address)
            .await
            .map_err(|error| format!("connect: {error}"))?;
        let mut connection = BufReader::new(stream);
        expect(&mut connection, "PING", "PING", "+PONG").await?;
        expect(&mut connection, "SET", "SET ready-probe 1 EX 10", "+OK").await?;
        expect(&mut connection, "GET", "GET ready-probe", "$1").await?;
        let value = reply_line(&mut connection, "GET").await?;
        if value != "1" {
            return Err(format!("GET answered {value:?}"));
        }
        expect(&mut connection, "DEL", "DEL ready-probe", ":1").await
    };
    match tokio::time::timeout(PROBE_TIMEOUT, work).await {
        Ok(outcome) => outcome,
        Err(_) => Err(format!("no answer within {PROBE_TIMEOUT:?}")),
    }
}

/// Sends one inline command and requires the first line of its reply to be `expected`.
async fn expect(
    connection: &mut BufReader<TcpStream>,
    name: &str,
    command: &str,
    expected: &str,
) -> Result<(), String> {
    connection
        .write_all(format!("{command}\r\n").as_bytes())
        .await
        .map_err(|error| format!("{name}: {error}"))?;
    let line = reply_line(connection, name).await?;
    if line == expected {
        Ok(())
    } else {
        Err(format!("{name} answered {line:?}"))
    }
}

/// One line of a reply, without its line ending.
async fn reply_line(connection: &mut BufReader<TcpStream>, name: &str) -> Result<String, String> {
    let mut line = String::new();
    let read = connection
        .read_line(&mut line)
        .await
        .map_err(|error| format!("{name}: {error}"))?;
    if read == 0 {
        return Err(format!("{name}: the connection closed with no reply"));
    }
    Ok(line.trim_end().to_owned())
}
