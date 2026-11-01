//! The in-memory [`RateLimitStore`]: a fixed window that opens at the first request and is not
//! extended by later ones, expiring on the wall clock like the Redis key it stands in for.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use bymax_auth_types::AuthError;

use super::{InMemoryStores, lock};
use crate::traits::RateLimitStore;

#[async_trait]
impl RateLimitStore for InMemoryStores {
    async fn hit(
        &self,
        route: &str,
        bucket_hash: &str,
        window_secs: u64,
    ) -> Result<i64, AuthError> {
        let mut counters = lock(&self.rate_limits);
        let now = Instant::now();
        let entry = counters
            .entry((route.to_owned(), bucket_hash.to_owned()))
            .or_insert((0, now));
        if now.duration_since(entry.1) >= Duration::from_secs(window_secs) {
            *entry = (0, now);
        }
        entry.0 += 1;
        Ok(entry.0)
    }
}
