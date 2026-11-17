//! A store failure's error chain never carries the connection string (layer: store, tests).
//!
//! The chain is what the engine logs for operators when the store cannot answer, so it must not
//! be able to hold the URL, its user, its password or its host. Each case builds a pool from a URL
//! whose password is a sentinel, fails on it, and asserts the sentinel is absent from the whole
//! chain, so an error type that starts echoing its input fails here.

use bymax_auth_redis::RedisStoreError;
use bymax_auth_types::AuthError;

/// A password that appears nowhere else.
const SENTINEL: &str = "S3NT1NEL-p4ssw0rd";

/// Every message of `error` and its sources, joined.
fn chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut out = error.to_string();
    let mut source = error.source();
    while let Some(next) = source {
        out.push_str(": ");
        out.push_str(&next.to_string());
        source = next.source();
    }
    out
}

/// The engine-facing chain of the failure a pool built from `url` hits, or `None` when it did not
/// fail.
async fn failure_chain(url: &str) -> Option<String> {
    let config = deadpool_redis::Config::from_url(url);
    let store_error: RedisStoreError =
        match config.create_pool(Some(deadpool_redis::Runtime::Tokio1)) {
            Err(error) => error.into(),
            Ok(pool) => pool.get().await.err()?.into(),
        };
    Some(chain(&AuthError::from(store_error)))
}

#[tokio::test]
async fn a_connection_failure_never_echoes_the_url_user_password_or_host() {
    let urls = [
        format!("redis://operator:{SENTINEL}@127.0.0.1:1/0"),
        format!("redis://operator:{SENTINEL}@no-such-host.invalid:6379/0"),
        format!("rediss://operator:{SENTINEL}@127.0.0.1:1/0"),
    ];
    for url in urls {
        let chain = failure_chain(&url).await.unwrap_or_default();
        assert!(!chain.is_empty(), "{url} unexpectedly connected");
        for secret in [SENTINEL, "operator", "no-such-host", "127.0.0.1"] {
            assert!(
                !chain.contains(secret),
                "the chain carries {secret:?}: {chain}"
            );
        }
    }
}

#[tokio::test]
async fn a_malformed_url_never_echoes_its_password() {
    let url = format!("redis://operator:{SENTINEL}@[::1");
    let chain = failure_chain(&url).await.unwrap_or_default();
    assert!(
        !chain.contains(SENTINEL),
        "the chain carries the password: {chain}"
    );
}
