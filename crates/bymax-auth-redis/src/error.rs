//! The crate's typed error and its projection into the engine's [`AuthError`].
//!
//! Every backend failure — a pool that cannot hand out a connection, a Redis command or
//! Lua script that fails, a stored value that will not deserialize, or a pool that cannot be
//! built — is captured as a [`RedisStoreError`]. Store-trait methods surface it as the
//! opaque [`AuthError::Internal`]; the concrete cause is carried for `tracing` but never
//! serialized to a client, and it never contains a secret.

use bymax_auth_types::AuthError;

/// A failure originating in the Redis backend. Each variant wraps the underlying driver or
/// (de)serialization error so the cause is available for diagnostics while the public
/// surface stays the opaque [`AuthError::Internal`].
#[derive(Debug, thiserror::Error)]
pub enum RedisStoreError {
    /// The connection pool could not hand out a connection (exhausted, closed, or timed out).
    #[error("redis connection pool unavailable")]
    Pool(#[from] deadpool_redis::PoolError),

    /// A Redis command or Lua script returned an error or an unexpected reply shape.
    #[error("redis command failed")]
    Command(#[from] redis::RedisError),

    /// A value read back from Redis could not be deserialized into its expected DTO.
    #[error("stored redis value could not be decoded")]
    Decode(#[from] serde_json::Error),

    /// The connection pool could not be constructed from the supplied configuration.
    #[error("redis connection pool could not be created")]
    Build(#[from] deadpool_redis::CreatePoolError),
}

impl From<RedisStoreError> for AuthError {
    /// Collapse any backend failure into the engine's opaque internal error. The cause is
    /// preserved as the boxed source (logged, never serialized); none of the variants carry
    /// a secret in their `Display` form.
    fn from(error: RedisStoreError) -> Self {
        AuthError::Internal(Box::new(error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_failures_render_a_secret_free_message_and_map_to_internal() {
        // Each backend failure must (a) render a static, secret-free diagnostic and
        // (b) collapse to the opaque internal error at the trait boundary. Constructing the
        // driver-error variants covers the generated `From`/`Display`/`AuthError` impls
        // deterministically, without a live Redis. The `Decode` variant's `From<serde_json>`
        // is exercised by the session store's `interpret_rotate` malformed-payload test, and
        // the `Build` variant by the pool's malformed-URL test.
        let command: RedisStoreError =
            redis::RedisError::from((redis::ErrorKind::Client, "boom")).into();
        let pool: RedisStoreError = deadpool_redis::PoolError::Closed.into();
        for error in [command, pool] {
            let rendered = error.to_string();
            assert!(!rendered.is_empty());
            assert!(matches!(AuthError::from(error), AuthError::Internal(_)));
        }
    }
}
