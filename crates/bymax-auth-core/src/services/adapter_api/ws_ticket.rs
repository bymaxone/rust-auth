//! Redemption of a WebSocket upgrade ticket (§7.3.6), engine surface layer.
//!
//! A socket is authenticated once and not revalidated by this library, so redemption asks again
//! what can have changed since the ticket was minted: the expiry of the minting token, its
//! revocation and the account's status. A refusal consumes the ticket like a success does.

use bymax_auth_types::{AuthError, DashboardClaims, DashboardType};

use super::WS_TICKET_TTL_SECONDS;
use crate::engine::AuthEngine;
use crate::services::{is_refresh_token_shape, new_uuid_v4, now_unix};
use crate::traits::{SessionKind, WsTicketSnapshot};

impl AuthEngine {
    /// Redeem a single-use WebSocket upgrade ticket (§7.3.6): the store atomically `GETDEL`s
    /// `wst:{sha256(ticket)}`, so the first redemption wins and a captured URL cannot be
    /// replayed. On a hit the stored snapshot is reconstructed into [`DashboardClaims`] (an
    /// authorization snapshot for the socket's lifetime — never re-signed, no REST access).
    ///
    /// `expected_tenant_id` is the tenant the connection belongs to. A host that calls this
    /// itself must pass it: with `None` a ticket of any tenant is accepted.
    ///
    /// The claims' `exp` is the expiry of the token that minted the ticket. A record that
    /// carries none is given [`WS_TICKET_TTL_SECONDS`] from redemption.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::TokenInvalid`] for a missing, expired or already-redeemed ticket,
    /// for one whose minting token has expired or been revoked (a logout or an epoch bump), for
    /// a snapshot that names no tenant or another tenant than the expected one, and for an
    /// account that no longer exists; the status-specific error for a blocked account;
    /// [`AuthError::Internal`] when no WS-ticket store is wired or the account read fails; or a
    /// store [`AuthError`].
    pub async fn redeem_ws_ticket(
        &self,
        ticket: &str,
        expected_tenant_id: Option<&str>,
    ) -> Result<DashboardClaims, AuthError> {
        let store = self
            .ws_ticket_store()
            .ok_or_else(|| crate::services::internal_error("ws-ticket store not configured"))?;
        // Shape-check before hashing, the same guard `reissue_tokens` and `logout` apply to a
        // refresh token and `take_state` applies to an OAuth `state`. The ticket arrives in a
        // `?ticket=` query parameter on a route the consumer mounts itself, so it inherits
        // neither the body-size limit nor any rate-limit entry: without this the store hashes
        // whatever the request line carried, which is SHA-256 work proportional to an
        // attacker-chosen length on an unauthenticated path. A value outside the shape could
        // never match a stored ticket anyway.
        if !is_refresh_token_shape(ticket) {
            return Err(AuthError::TokenInvalid);
        }
        let snapshot = store.redeem(ticket).await?.ok_or(AuthError::TokenInvalid)?;
        let tenant = redeemable_tenant(&snapshot, expected_tenant_id)?;
        self.assert_ticket_session_stands(&snapshot, &tenant)
            .await?;
        self.assert_ticket_account_usable(&snapshot.sub, &tenant)
            .await?;
        Ok(redeemed_claims(snapshot, tenant))
    }

    /// Refuses a snapshot whose minting token is revoked: no identifier to read it by, the
    /// `rv:{jti}` blacklist (logout), or an account epoch above the ticket's (a password reset
    /// or sign-out-everywhere). A revoked ticket gets the answer of an unknown one.
    async fn assert_ticket_session_stands(
        &self,
        snapshot: &WsTicketSnapshot,
        tenant: &str,
    ) -> Result<(), AuthError> {
        let mut revoked =
            snapshot.jti.is_empty() || self.session_store().is_blacklisted(&snapshot.jti).await?;
        if !revoked {
            let subject = self.session_subject(SessionKind::Dashboard, Some(tenant), &snapshot.sub);
            let current = self
                .session_store()
                .current_epoch(SessionKind::Dashboard, &subject)
                .await?;
            revoked = current > snapshot.epoch;
        }
        if revoked {
            tracing::warn!(
                event = "RUST_AUTH_WS_TICKET_REFUSED_TOKEN_REVOKED",
                "ws ticket: refused, the token it was minted from is revoked"
            );
            return Err(AuthError::TokenInvalid);
        }
        Ok(())
    }

    /// Refuses a ticket whose account is gone or blocked now. The status is read from the
    /// repository, not from the status cache, scoped by the snapshot's tenant.
    async fn assert_ticket_account_usable(&self, sub: &str, tenant: &str) -> Result<(), AuthError> {
        let user = self
            .user_repository()
            .find_by_id(sub, Some(tenant))
            .await
            .map_err(crate::services::auth::map_repository_error)?;
        let Some(user) = user else {
            tracing::warn!(
                event = "RUST_AUTH_WS_TICKET_REFUSED_ACCOUNT_GONE",
                "ws ticket: refused, the account no longer exists"
            );
            return Err(AuthError::TokenInvalid);
        };
        self.assert_user_not_blocked(&user.status).inspect_err(|_| {
            tracing::warn!(
                event = "RUST_AUTH_WS_TICKET_REFUSED_ACCOUNT_BLOCKED",
                "ws ticket: refused, the account is blocked"
            );
        })
    }
}

/// The tenant a redeemed snapshot may be honoured for: the one it names, provided the minting
/// token has not expired and the caller expects no other. The record's own lifetime ends before
/// the token's does; the expiry is judged for a keyspace writer, or a clock, that did not keep
/// that.
fn redeemable_tenant(
    snapshot: &WsTicketSnapshot,
    expected_tenant_id: Option<&str>,
) -> Result<String, AuthError> {
    let Some(tenant) = snapshot.tenant_id.clone().filter(|t| !t.is_empty()) else {
        tracing::warn!(
            event = "RUST_AUTH_WS_TICKET_REFUSED_NO_TENANT",
            "ws ticket: refused, the snapshot names no tenant"
        );
        return Err(AuthError::TokenInvalid);
    };
    let now = u64::try_from(now_unix()).unwrap_or(0);
    if snapshot.exp.is_some_and(|exp| exp <= now) {
        tracing::warn!(
            event = "RUST_AUTH_WS_TICKET_REFUSED_EXPIRED",
            "ws ticket: refused, the token it was minted from has expired"
        );
        return Err(AuthError::TokenInvalid);
    }
    if expected_tenant_id.is_some_and(|expected| expected != tenant) {
        tracing::warn!(
            event = "RUST_AUTH_WS_TICKET_REFUSED_TENANT_MISMATCH",
            "ws ticket: refused, the snapshot names another tenant than the expected one"
        );
        return Err(AuthError::TokenInvalid);
    }
    Ok(tenant)
}

/// The claims a socket is authorized as. They are never re-signed or re-verified as an access
/// token, so `jti` is fresh and `epoch` carries the inert default.
fn redeemed_claims(snapshot: WsTicketSnapshot, tenant: String) -> DashboardClaims {
    let now = now_unix();
    let ttl = i64::try_from(WS_TICKET_TTL_SECONDS).unwrap_or(i64::MAX);
    let exp = snapshot.exp.map_or_else(
        || now.saturating_add(ttl),
        |exp| i64::try_from(exp).unwrap_or(i64::MAX),
    );
    DashboardClaims {
        iss: None,
        aud: None,
        sub: snapshot.sub,
        jti: new_uuid_v4(),
        tenant_id: tenant,
        role: snapshot.role,
        token_type: DashboardType::Dashboard,
        status: snapshot.status,
        mfa_enabled: snapshot.mfa_enabled,
        mfa_verified: snapshot.mfa_verified,
        iat: now,
        exp,
        epoch: 0,
    }
}
