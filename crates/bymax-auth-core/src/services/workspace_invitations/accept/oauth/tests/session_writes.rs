//! A session store whose session write takes a while, as one over a network does, and can be
//! refused (layer: service, test double).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bymax_auth_types::AuthError;

use crate::testing::InMemoryStores;
use crate::traits::{
    RotateOutcome, SessionDetail, SessionKind, SessionRecord, SessionRotation, SessionStore,
};

/// Delays `create_session` and refuses it unless `open`; everything else is answered by the
/// store inside.
#[derive(Default)]
pub(super) struct SlowSessions {
    /// The store that answers.
    pub(super) inner: InMemoryStores,
    /// Whether a delayed write is accepted.
    pub(super) open: bool,
    /// Raised once a session has been written.
    pub(super) written: Arc<AtomicBool>,
}

#[async_trait]
impl SessionStore for SlowSessions {
    async fn create_session(
        &self,
        kind: SessionKind,
        subject_hash: &str,
        token_hash: &str,
        detail: &SessionRecord,
        ttl_secs: u64,
    ) -> Result<(), AuthError> {
        // Long enough for a task already spawned to run before the session exists.
        tokio::time::sleep(Duration::from_millis(20)).await;
        if !self.open {
            return Err(AuthError::ServiceUnavailable("no new sessions".into()));
        }
        self.inner
            .create_session(kind, subject_hash, token_hash, detail, ttl_secs)
            .await?;
        self.written.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn rotate(
        &self,
        kind: SessionKind,
        rotation: &SessionRotation,
    ) -> Result<RotateOutcome, AuthError> {
        self.inner.rotate(kind, rotation).await
    }

    async fn find_session(
        &self,
        kind: SessionKind,
        token_hash: &str,
    ) -> Result<Option<SessionRecord>, AuthError> {
        self.inner.find_session(kind, token_hash).await
    }

    async fn list_sessions(
        &self,
        kind: SessionKind,
        subject_hash: &str,
    ) -> Result<Vec<SessionDetail>, AuthError> {
        self.inner.list_sessions(kind, subject_hash).await
    }

    async fn create_recovered_session(
        &self,
        kind: SessionKind,
        subject_hash: &str,
        token_hash: &str,
        detail: &SessionRecord,
        ttl_secs: u64,
    ) -> Result<bool, AuthError> {
        self.inner
            .create_recovered_session(kind, subject_hash, token_hash, detail, ttl_secs)
            .await
    }

    async fn revoke_session(
        &self,
        kind: SessionKind,
        subject_hash: &str,
        session_hash: &str,
    ) -> Result<(), AuthError> {
        self.inner
            .revoke_session(kind, subject_hash, session_hash)
            .await
    }

    async fn delete_grace_pointer(
        &self,
        kind: SessionKind,
        session_hash: &str,
    ) -> Result<(), AuthError> {
        self.inner.delete_grace_pointer(kind, session_hash).await
    }

    async fn sweep_grace_pointers(
        &self,
        kind: SessionKind,
        subject_hash: &str,
    ) -> Result<(), AuthError> {
        self.inner.sweep_grace_pointers(kind, subject_hash).await
    }

    async fn revoke_all(&self, kind: SessionKind, subject_hash: &str) -> Result<(), AuthError> {
        self.inner.revoke_all(kind, subject_hash).await
    }

    async fn find_family_owner(
        &self,
        kind: SessionKind,
        family_id: &str,
    ) -> Result<Option<SessionRecord>, AuthError> {
        self.inner.find_family_owner(kind, family_id).await
    }

    async fn revoke_family(
        &self,
        kind: SessionKind,
        family_id: &str,
        owner_subject_hash: Option<&str>,
    ) -> Result<(), AuthError> {
        self.inner
            .revoke_family(kind, family_id, owner_subject_hash)
            .await
    }

    async fn blacklist_access(
        &self,
        jti_or_hash: &str,
        remaining_ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.inner
            .blacklist_access(jti_or_hash, remaining_ttl_secs)
            .await
    }

    async fn is_blacklisted(&self, jti_or_hash: &str) -> Result<bool, AuthError> {
        self.inner.is_blacklisted(jti_or_hash).await
    }

    async fn current_epoch(&self, kind: SessionKind, subject_hash: &str) -> Result<u64, AuthError> {
        self.inner.current_epoch(kind, subject_hash).await
    }

    async fn bump_epoch(&self, kind: SessionKind, subject_hash: &str) -> Result<u64, AuthError> {
        self.inner.bump_epoch(kind, subject_hash).await
    }

    async fn mark_recent_auth(&self, user_id_hash: &str, ttl: u64) -> Result<(), AuthError> {
        self.inner.mark_recent_auth(user_id_hash, ttl).await
    }

    async fn has_recent_auth(&self, user_id_hash: &str) -> Result<bool, AuthError> {
        self.inner.has_recent_auth(user_id_hash).await
    }
}
