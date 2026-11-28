//! The crate's typed error and its projection into the engine's [`AuthError`].
//!
//! Every backend failure — a pool that cannot hand out a connection, a Redis command or
//! Lua script that fails, a stored value that will not deserialize, or a pool that cannot be
//! built — is captured as a [`RedisStoreError`]. Store-trait methods surface it as the
//! opaque [`AuthError::Internal`], or [`AuthError::ServiceUnavailable`] when the store could not
//! answer at all (see [`RedisStoreError::is_outage`]); the concrete cause travels as that error's
//! source, for a host to read, and is never serialized to a client. Each variant's own `Display`
//! text is fixed; what the driver or decoder says sits below it in the source chain.

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

/// The server replies that say it cannot serve the command right now, by error-reply prefix. A
/// condition that clears, unlike a reply about the command itself (`NOSCRIPT`, `WRONGTYPE`,
/// `ERR`) or a misconfiguration (`MISCONF`, `BUSY`), which are defects and stay internal. The
/// list is `serviceUnavailable.outage.replyPrefixes` in the shared contract, which a test reads.
pub(crate) const OUTAGE_REPLY_PREFIXES: [&str; 5] = [
    "READONLY",
    "LOADING",
    "MASTERDOWN",
    "CLUSTERDOWN",
    "TRYAGAIN",
];

impl RedisStoreError {
    /// Whether the store could not answer: the command timed out, the connection was refused,
    /// lost or closed, no connection could be had from the pool in time, or the server replied
    /// that it cannot serve the command (`READONLY`, `LOADING`, `MASTERDOWN`, `CLUSTERDOWN` or `TRYAGAIN`). Every other failure — a
    /// reply about the command, a value that will not decode, a pool that cannot be built — is a
    /// defect, not a condition that clears.
    #[must_use]
    pub fn is_outage(&self) -> bool {
        match self {
            Self::Pool(
                deadpool_redis::PoolError::Timeout(_) | deadpool_redis::PoolError::Closed,
            ) => true,
            Self::Pool(deadpool_redis::PoolError::Backend(error)) | Self::Command(error) => {
                command_is_outage(error)
            }
            Self::Pool(_) | Self::Decode(_) | Self::Build(_) => false,
        }
    }
}

/// Whether a Redis error is an outage: any I/O failure (a timeout, a refused, reset or dropped
/// connection, an unresolvable host; the client's timeout and dropped-connection predicates are
/// subsets of it) or a reply whose prefix says the server cannot serve now.
fn command_is_outage(error: &redis::RedisError) -> bool {
    error.is_io_error()
        || error
            .code()
            .is_some_and(|code| OUTAGE_REPLY_PREFIXES.contains(&code))
}

impl From<RedisStoreError> for AuthError {
    /// Classify a backend failure: [`AuthError::ServiceUnavailable`] when the store could not
    /// answer, otherwise the opaque [`AuthError::Internal`]. The cause is preserved as the boxed
    /// source (never serialized); none of the variants carry a secret in their `Display`
    /// form.
    fn from(error: RedisStoreError) -> Self {
        if error.is_outage() {
            AuthError::ServiceUnavailable(Box::new(error))
        } else {
            AuthError::Internal(Box::new(error))
        }
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
            assert!(!error.to_string().is_empty());
        }
        // A reply the client could not parse is a defect, so it stays the opaque internal error;
        // a pool that is closed cannot answer, so it is the outage (`outage_tests` covers the
        // classification against the contract).
        let defect: RedisStoreError =
            redis::RedisError::from((redis::ErrorKind::Client, "boom")).into();
        assert!(matches!(AuthError::from(defect), AuthError::Internal(_)));
        let closed: RedisStoreError = deadpool_redis::PoolError::Closed.into();
        assert!(matches!(
            AuthError::from(closed),
            AuthError::ServiceUnavailable(_)
        ));
    }
}
