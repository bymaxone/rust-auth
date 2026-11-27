//! The wait that stands between a started Redis container and a test's first command: it retries
//! a bounded number of times, hands back the number of attempts that succeeded, and fails with the
//! last error. None of these cases needs Docker; the probe is a closure, and the one case that
//! runs the real probe points it at a port nothing listens on (layer: test support, tests).

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

#[path = "common/redis_ready.rs"]
mod redis_ready;

/// A pause short enough that no case waits for it.
const STEP: Duration = Duration::from_millis(1);

/// An address nothing listens on, so the first connection is refused.
const DEAD_REDIS: &str = "redis://127.0.0.1:1";

#[tokio::test]
async fn a_probe_that_answers_at_once_is_run_once() {
    let calls = AtomicU32::new(0);
    let outcome = redis_ready::retry_with(5, STEP, || {
        calls.fetch_add(1, Ordering::SeqCst);
        async { Ok(()) }
    })
    .await;

    assert_eq!(outcome, Ok(1));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_probe_that_fails_three_times_and_then_answers_succeeds_on_the_fourth_attempt() {
    let calls = AtomicU32::new(0);
    let outcome = redis_ready::retry_with(10, STEP, || {
        let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
        async move {
            if call < 4 {
                Err(format!("not yet {call}"))
            } else {
                Ok(())
            }
        }
    })
    .await;

    assert_eq!(outcome, Ok(4));
    assert_eq!(calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn a_probe_that_never_answers_stops_at_the_bound_and_reports_its_last_error() {
    let calls = AtomicU32::new(0);
    let outcome = redis_ready::retry_with(4, STEP, || {
        let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
        async move { Err(format!("refused {call}")) }
    })
    .await;

    assert_eq!(outcome, Err("attempt 4 of 4: refused 4".to_owned()));
    assert_eq!(calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn no_attempts_means_no_probe_and_an_error_that_says_so() {
    let calls = AtomicU32::new(0);
    let outcome = redis_ready::retry_with(0, STEP, || {
        calls.fetch_add(1, Ordering::SeqCst);
        async { Ok(()) }
    })
    .await;

    assert_eq!(outcome, Err("no attempt was made".to_owned()));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_real_probe_against_a_closed_port_fails_at_the_connection() {
    let outcome = redis_ready::probe_once(DEAD_REDIS).await;

    assert!(
        matches!(&outcome, Err(message) if message.starts_with("connect: ")),
        "{outcome:?}"
    );
}

#[tokio::test]
#[should_panic(
    expected = "did not answer a PING and a write round-trip: attempt 2 of 2: connect: "
)]
async fn waiting_on_a_closed_port_fails_loudly_with_the_last_error_and_never_skips() {
    redis_ready::wait_with(DEAD_REDIS, 2, STEP).await;
}

#[tokio::test]
#[should_panic(expected = "attempt 50 of 50: connect: ")]
async fn the_default_wait_gives_up_after_fifty_attempts() {
    redis_ready::wait_until_ready(DEAD_REDIS).await;
}

#[test]
fn a_container_published_on_localhost_is_addressed_by_the_ipv4_loopback() {
    assert_eq!(
        redis_ready::redis_url("localhost", 6379),
        "redis://127.0.0.1:6379"
    );
}

#[test]
fn any_other_host_is_addressed_as_it_was_reported() {
    assert_eq!(
        redis_ready::redis_url("192.0.2.7", 55000),
        "redis://192.0.2.7:55000"
    );
    assert_eq!(
        redis_ready::redis_url("docker.internal.example", 1),
        "redis://docker.internal.example:1"
    );
}

/// The switch CI sets so that a case which could not run fails instead of passing. It is the one the
/// Docker cases use, so a runner that skips here would skip there.
const REQUIRE_SWITCH: &str = "BYMAX_REQUIRE_DOCKER";

/// What a host with no IPv6 loopback does: where the switch is on it is an error, because a case
/// that stages nothing would pass while asserting nothing; elsewhere the skip is said on stderr.
fn without_ipv6(required: bool) -> Result<(), String> {
    if required {
        return Err(format!(
            "{REQUIRE_SWITCH}=1 and the host has no IPv6 loopback to stage a listener on"
        ));
    }
    eprintln!(
        "skipped: no IPv6 loopback to stage a listener on; set {REQUIRE_SWITCH}=1 to make this a failure"
    );
    Ok(())
}

/// The same port number on `[::1]` and on `127.0.0.1`. `Ok(None)` when the host has no IPv6 loopback
/// and the switch is off; an error when the switch is on and it has none, or when no port number
/// was free on both families.
async fn dual_stack_pair() -> Result<Option<(TcpListener, TcpListener, u16)>, String> {
    for _ in 0..20 {
        let Ok(v6) = TcpListener::bind("[::1]:0").await else {
            let required = std::env::var(REQUIRE_SWITCH).as_deref() == Ok("1");
            return without_ipv6(required).map(|()| None);
        };
        let Ok(port) = v6.local_addr().map(|address| address.port()) else {
            continue;
        };
        if let Ok(v4) = TcpListener::bind(("127.0.0.1", port)).await {
            return Ok(Some((v6, v4, port)));
        }
    }
    Err("no port number was free on both loopback families".to_owned())
}

#[test]
fn a_host_without_ipv6_loopback_fails_the_impostor_case_where_the_switch_is_on() {
    assert_eq!(
        without_ipv6(true),
        Err(
            "BYMAX_REQUIRE_DOCKER=1 and the host has no IPv6 loopback to stage a listener on"
                .to_owned()
        )
    );
}

#[test]
fn a_host_without_ipv6_loopback_skips_the_impostor_case_where_the_switch_is_off() {
    assert_eq!(without_ipv6(false), Ok(()));
}

#[tokio::test]
async fn the_address_built_for_localhost_reaches_the_ipv4_listener_not_the_one_on_ipv6() {
    // Neither connection depends on how `localhost` resolves here: the impostor is reached by its
    // own address, and the container by the address `redis_url` builds for the name `localhost`.
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    let pair = dual_stack_pair().await;
    assert!(pair.is_ok(), "{pair:?}");
    let Ok(Some((v6, v4, port))) = pair else { unreachable!() };
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = v6.accept().await {
            let _ = socket.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        }
    });
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = v4.accept().await {
            let _ = socket.write_all(b"+PONG\r\n").await;
        }
    });

    let first_bytes = |address: String| async move {
        let mut socket = TcpStream::connect(address).await.ok()?;
        let mut buffer = [0_u8; 4];
        socket.read_exact(&mut buffer).await.ok()?;
        Some(buffer)
    };
    let impostor = first_bytes(format!("[::1]:{port}")).await;
    let built = redis_ready::redis_url("localhost", port);
    let container = first_bytes(built["redis://".len()..].to_owned()).await;

    assert_eq!(impostor, Some(*b"HTTP"));
    assert_eq!(container, Some(*b"+PON"));
}

/// A listener that answers one connection line by line with `answers`, in order, and then closes.
/// Its address is returned as a Redis URL.
async fn fake_server(answers: &'static [&'static str]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await;
    assert!(listener.is_ok(), "no loopback listener: {listener:?}");
    let Ok(listener) = listener else { return String::new() };
    let address = listener.local_addr().map(|address| address.to_string());
    assert!(address.is_ok(), "no local address: {address:?}");
    tokio::spawn(async move {
        if let Ok((socket, _)) = listener.accept().await {
            let mut reader = BufReader::new(socket);
            for answer in answers {
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                let _ = reader.get_mut().write_all(answer.as_bytes()).await;
            }
        }
    });
    format!("redis://{}", address.unwrap_or_default())
}

#[tokio::test]
async fn a_server_that_answers_the_four_commands_is_ready() {
    let url = fake_server(&["+PONG\r\n", "+OK\r\n", "$1\r\n1\r\n", ":1\r\n"]).await;

    assert_eq!(redis_ready::probe_once(&url).await, Ok(()));
}

#[tokio::test]
async fn a_listener_that_is_not_redis_is_reported_with_what_it_answered() {
    let url = fake_server(&["HTTP/1.1 400 Bad Request\r\n"]).await;

    assert_eq!(
        redis_ready::probe_once(&url).await,
        Err("PING answered \"HTTP/1.1 400 Bad Request\"".to_owned())
    );
}

#[tokio::test]
async fn a_value_other_than_the_one_written_is_not_ready() {
    let url = fake_server(&["+PONG\r\n", "+OK\r\n", "$1\r\n2\r\n"]).await;

    assert_eq!(
        redis_ready::probe_once(&url).await,
        Err("GET answered \"2\"".to_owned())
    );
}

#[tokio::test]
async fn a_connection_closed_before_the_reply_is_not_ready() {
    // It reads the PING, answers nothing and closes, so the close is always seen as an end of stream.
    let url = fake_server(&[""]).await;

    assert_eq!(
        redis_ready::probe_once(&url).await,
        Err("PING: the connection closed with no reply".to_owned())
    );
}

#[tokio::test]
async fn a_listener_that_accepts_and_never_answers_fails_the_attempt_after_the_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await;
    assert!(listener.is_ok(), "no loopback listener: {listener:?}");
    let Ok(listener) = listener else { unreachable!() };
    let address = listener.local_addr().map(|address| address.to_string());
    assert!(address.is_ok(), "no local address: {address:?}");
    tokio::spawn(async move {
        let held = listener.accept().await;
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(held);
    });
    let url = format!("redis://{}", address.unwrap_or_default());

    let outcome = redis_ready::probe_once(&url).await;

    assert!(
        matches!(&outcome, Err(message) if message.starts_with("no answer within ")),
        "{outcome:?}"
    );
}
