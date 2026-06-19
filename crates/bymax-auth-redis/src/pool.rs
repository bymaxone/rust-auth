//! The pooled Redis handle that backs every store trait.
//!
//! [`RedisStores`] owns a `deadpool-redis` connection pool and the single
//! [`NamespacedRedis`] key builder. One handle satisfies `SessionStore + OtpStore +
//! BruteForceStore + WsTicketStore`, so it wires straight into
//! `AuthEngineBuilder::redis_stores`. The pool mirrors the ioredis single-pool model of
//! nest-auth; connection and command failures surface as [`RedisStoreError`], never panics.

use deadpool_redis::{Config, Connection, Pool, Runtime};

use crate::error::RedisStoreError;
use crate::keys::NamespacedRedis;

/// A pooled, namespaced Redis backend implementing the engine's store traits.
///
/// Cheap to clone semantics are provided by sharing through `Arc` at the call site
/// (`Arc<RedisStores>`); the pool itself is the unit of connection reuse.
pub struct RedisStores {
    pool: Pool,
    namespaced: NamespacedRedis,
}

impl RedisStores {
    /// Build a pool from a Redis URL and a key namespace (default `auth`).
    ///
    /// The pool is created lazily — connections are established on first use — so this does
    /// not perform any network I/O. It returns an error only when the URL is malformed or
    /// the pool cannot be constructed.
    ///
    /// # Errors
    ///
    /// Returns [`RedisStoreError::Build`] when the URL is invalid or the pool cannot be
    /// created from the resolved configuration.
    pub fn connect(url: &str, namespace: impl Into<Box<str>>) -> Result<Self, RedisStoreError> {
        let pool = Config::from_url(url).create_pool(Some(Runtime::Tokio1))?;
        Ok(Self {
            pool,
            namespaced: NamespacedRedis::new(namespace),
        })
    }

    /// The namespace-prefixing key builder — the only component that constructs a
    /// fully-qualified key.
    pub(crate) fn keys(&self) -> &NamespacedRedis {
        &self.namespaced
    }

    /// Check out a pooled connection.
    ///
    /// # Errors
    ///
    /// Returns [`RedisStoreError::Pool`] when the pool cannot hand out a connection
    /// (unreachable server, exhausted pool, or timeout).
    pub(crate) async fn connection(&self) -> Result<Connection, RedisStoreError> {
        Ok(self.pool.get().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_rejects_a_malformed_url() {
        // A URL the Redis client cannot parse fails pool construction (the `Build` arm),
        // surfaced as a typed error rather than a panic.
        let result = RedisStores::connect("http://not-a-redis-url", "auth");
        assert!(matches!(result, Err(RedisStoreError::Build(_))));
    }

    #[test]
    fn connect_accepts_a_well_formed_url_without_touching_the_network() {
        // A syntactically valid URL builds a pool lazily; no connection is opened here, so a
        // server need not exist for construction to succeed.
        let result = RedisStores::connect("redis://127.0.0.1:6379", "auth");
        assert!(matches!(&result, Ok(stores) if stores.keys().namespace() == "auth"));
    }
}
