//! A session store that refuses every new session and otherwise behaves as the in-memory one
//! (layer: service, test double).

use async_trait::async_trait;
use bymax_auth_types::AuthError;

use crate::testing::InMemoryStores;
use crate::traits::{
    RotateOutcome, SessionDetail, SessionKind, SessionRecord, SessionRotation, SessionStore,
};

/// Refuses `create_session`; everything else is answered by the store inside.
#[derive(Default)]
pub(super) struct ClosedSessions(InMemoryStores);

#[async_trait]
impl SessionStore for ClosedSessions {
    async fn create_session(
        &self,
        _kind: SessionKind,
        _subject_hash: &str,
        _token_hash: &str,
        _detail: &SessionRecord,
        _ttl_secs: u64,
    ) -> Result<(), AuthError> {
        Err(AuthError::ServiceUnavailable("no new sessions".into()))
    }

    async fn rotate(
        &self,
        kind: SessionKind,
        rotation: &SessionRotation,
    ) -> Result<RotateOutcome, AuthError> {
        self.0.rotate(kind, rotation).await
    }

    async fn find_session(
        &self,
        kind: SessionKind,
        token_hash: &str,
    ) -> Result<Option<SessionRecord>, AuthError> {
        self.0.find_session(kind, token_hash).await
    }

    async fn list_sessions(
        &self,
        kind: SessionKind,
        subject_hash: &str,
    ) -> Result<Vec<SessionDetail>, AuthError> {
        self.0.list_sessions(kind, subject_hash).await
    }

    async fn create_recovered_session(
        &self,
        kind: SessionKind,
        subject_hash: &str,
        token_hash: &str,
        detail: &SessionRecord,
        ttl_secs: u64,
    ) -> Result<bool, AuthError> {
        self.0
            .create_recovered_session(kind, subject_hash, token_hash, detail, ttl_secs)
            .await
    }

    async fn revoke_session(
        &self,
        kind: SessionKind,
        subject_hash: &str,
        session_hash: &str,
    ) -> Result<(), AuthError> {
        self.0
            .revoke_session(kind, subject_hash, session_hash)
            .await
    }

    async fn delete_grace_pointer(
        &self,
        kind: SessionKind,
        session_hash: &str,
    ) -> Result<(), AuthError> {
        self.0.delete_grace_pointer(kind, session_hash).await
    }

    async fn sweep_grace_pointers(
        &self,
        kind: SessionKind,
        subject_hash: &str,
    ) -> Result<(), AuthError> {
        self.0.sweep_grace_pointers(kind, subject_hash).await
    }

    async fn revoke_all(&self, kind: SessionKind, subject_hash: &str) -> Result<(), AuthError> {
        self.0.revoke_all(kind, subject_hash).await
    }

    async fn find_family_owner(
        &self,
        kind: SessionKind,
        family_id: &str,
    ) -> Result<Option<SessionRecord>, AuthError> {
        self.0.find_family_owner(kind, family_id).await
    }

    async fn revoke_family(
        &self,
        kind: SessionKind,
        family_id: &str,
        owner_subject_hash: Option<&str>,
    ) -> Result<(), AuthError> {
        self.0
            .revoke_family(kind, family_id, owner_subject_hash)
            .await
    }

    async fn blacklist_access(
        &self,
        jti_or_hash: &str,
        remaining_ttl_secs: u64,
    ) -> Result<(), AuthError> {
        self.0
            .blacklist_access(jti_or_hash, remaining_ttl_secs)
            .await
    }

    async fn is_blacklisted(&self, jti_or_hash: &str) -> Result<bool, AuthError> {
        self.0.is_blacklisted(jti_or_hash).await
    }

    async fn current_epoch(&self, kind: SessionKind, subject_hash: &str) -> Result<u64, AuthError> {
        self.0.current_epoch(kind, subject_hash).await
    }

    async fn bump_epoch(&self, kind: SessionKind, subject_hash: &str) -> Result<u64, AuthError> {
        self.0.bump_epoch(kind, subject_hash).await
    }

    async fn mark_recent_auth(&self, user_id_hash: &str, ttl: u64) -> Result<(), AuthError> {
        self.0.mark_recent_auth(user_id_hash, ttl).await
    }

    async fn has_recent_auth(&self, user_id_hash: &str) -> Result<bool, AuthError> {
        self.0.has_recent_auth(user_id_hash).await
    }
}
