//! The engine entry point of the adapter's rate limit (layer: engine surface used by the HTTP
//! adapter).
//!
//! The adapter decides which bucket a request belongs to; the engine owns the keyed hash that
//! turns a client address into a store key, so no raw address reaches the shared keyspace.

use bymax_auth_crypto::mac::hmac_sha256;
use bymax_auth_types::AuthError;

use crate::engine::AuthEngine;
use crate::services::to_hex;

impl AuthEngine {
    /// Count one request from `client_bucket` on `route` against a `window_secs` fixed window and
    /// return the new count, or `None` when no shared counter is configured (the adapter then
    /// falls back to its in-process limiter).
    ///
    /// `client_bucket` is the address unit a limit is charged to (the full IPv4 address, the /64
    /// prefix for IPv6), already collapsed by the caller. It is hashed under the engine's keyed
    /// MAC before it reaches the store.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the store fails.
    pub async fn count_rate_limited_request(
        &self,
        route: &str,
        client_bucket: &str,
        window_secs: u64,
    ) -> Result<Option<i64>, AuthError> {
        let Some(store) = self.rate_limit_store() else {
            return Ok(None);
        };
        let bucket_hash = to_hex(&hmac_sha256(
            self.config().hmac_key(),
            client_bucket.as_bytes(),
        ));
        store.hit(route, &bucket_hash, window_secs).await.map(Some)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use crate::config::Environment;
    use crate::engine::AuthEngine;
    use crate::services::auth::test_support::{base_config, harness};
    use crate::testing::{InMemoryStores, InMemoryUserRepository};

    #[tokio::test]
    async fn requests_are_counted_per_route_and_bucket_within_one_window() {
        let Some(h) = harness(base_config(), None) else { return };
        let count = |route: &'static str, bucket: &'static str| {
            h.engine.count_rate_limited_request(route, bucket, 60)
        };

        assert!(matches!(count("login", "203.0.113.7").await, Ok(Some(1))));
        assert!(matches!(count("login", "203.0.113.7").await, Ok(Some(2))));
        // Another route and another bucket each start their own budget.
        assert!(matches!(
            count("register", "203.0.113.7").await,
            Ok(Some(1))
        ));
        assert!(matches!(count("login", "203.0.113.8").await, Ok(Some(1))));
        assert!(matches!(count("login", "203.0.113.7").await, Ok(Some(3))));
    }

    #[tokio::test]
    async fn the_window_opens_at_the_first_request_and_later_ones_do_not_extend_it() {
        // A steady trickle must not keep a counter alive forever: the window is measured from
        // the first request, so the third request lands in a fresh window even though the
        // second arrived less than a window before it.
        let Some(h) = harness(base_config(), None) else { return };
        let hit = || {
            h.engine
                .count_rate_limited_request("login", "198.51.100.1", 1)
        };

        assert!(matches!(hit().await, Ok(Some(1))));
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(matches!(hit().await, Ok(Some(2))));
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(matches!(hit().await, Ok(Some(1))));
    }

    #[tokio::test]
    async fn without_a_shared_counter_the_engine_reports_none() {
        let stores = Arc::new(InMemoryStores::new());
        let built = AuthEngine::builder()
            .config(base_config())
            .environment(Environment::Test)
            .user_repository(Arc::new(InMemoryUserRepository::new()))
            .session_store(stores.clone())
            .otp_store(stores.clone())
            .brute_force_store(stores)
            .build();
        assert!(built.is_ok());
        let Ok(bare) = built else { return };
        assert!(bare.rate_limit_store().is_none());
        assert!(matches!(
            bare.count_rate_limited_request("login", "203.0.113.7", 60)
                .await,
            Ok(None)
        ));
    }
}
