//! [`WsTicketStore`] over Redis: a single-use, short-TTL WebSocket upgrade ticket. The
//! opaque raw ticket is returned to the client; only `sha256(ticket)` ever becomes a key,
//! and redemption is an atomic `GETDEL` so a ticket is valid exactly once (sections 12.4 /
//! 13.7).

use async_trait::async_trait;
use bymax_auth_core::traits::{WsTicketSnapshot, WsTicketStore};
use bymax_auth_crypto::mac::sha256;
use bymax_auth_crypto::token::generate_secure_token;
use bymax_auth_types::AuthError;

use crate::error::RedisStoreError;
use crate::keys::{Prefix, to_hex};
use crate::pool::RedisStores;

/// Bytes of entropy in a freshly-minted WebSocket ticket (256-bit, like the opaque refresh
/// token).
const WS_TICKET_ENTROPY_BYTES: usize = 32;

impl RedisStores {
    /// The `wst:` key for a raw ticket — `sha256(ticket)` hex, never the raw ticket.
    fn ws_ticket_key(&self, ticket: &str) -> String {
        self.keys()
            .key(Prefix::Wst, &to_hex(&sha256(ticket.as_bytes())))
    }

    /// Mint a single-use ticket holding the verified-claims snapshot, returning the raw
    /// ticket the client presents at the handshake.
    async fn mint_inner(
        &self,
        snapshot: &WsTicketSnapshot,
        ttl_secs: u64,
    ) -> Result<String, RedisStoreError> {
        let ticket = generate_secure_token(WS_TICKET_ENTROPY_BYTES);
        let key = self.ws_ticket_key(&ticket);
        let json = serde_json::to_string(snapshot)?;
        let mut conn = self.connection().await?;
        redis::cmd("SET")
            .arg(&key)
            .arg(&json)
            .arg("EX")
            .arg(ttl_secs)
            .query_async::<()>(&mut conn)
            .await?;
        Ok(ticket)
    }

    /// Redeem and consume a ticket via atomic `GETDEL`, returning its snapshot once.
    async fn redeem_inner(
        &self,
        ticket: &str,
    ) -> Result<Option<WsTicketSnapshot>, RedisStoreError> {
        let key = self.ws_ticket_key(ticket);
        let mut conn = self.connection().await?;
        let raw: Option<String> = redis::cmd("GETDEL")
            .arg(&key)
            .query_async(&mut conn)
            .await?;
        Ok(raw.as_deref().and_then(parse_snapshot))
    }
}

/// Read a stored ticket record, or `None` when it is not a ticket.
///
/// The record was consumed by the `GETDEL` that produced it, so a record that does not carry
/// the whole shape (a missing `jti` or `epoch`, a `jti` that is not a string, an `epoch` that is
/// a string, negative or fractional, or text that is not a JSON object at all) is refused
/// exactly like an unknown ticket instead of surfacing as a backend error: the caller gets the
/// same answer for every ticket it cannot honour, and a ticket written by an older version of
/// the writer fails closed.
fn parse_snapshot(json: &str) -> Option<WsTicketSnapshot> {
    serde_json::from_str(json).ok()
}

#[async_trait]
impl WsTicketStore for RedisStores {
    async fn mint(&self, snapshot: &WsTicketSnapshot, ttl_secs: u64) -> Result<String, AuthError> {
        self.mint_inner(snapshot, ttl_secs)
            .await
            .map_err(AuthError::from)
    }

    async fn redeem(&self, ticket: &str) -> Result<Option<WsTicketSnapshot>, AuthError> {
        self.redeem_inner(ticket).await.map_err(AuthError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::parse_snapshot;

    /// A complete record, with `fields` replacing or adding to it.
    fn record(overrides: &[(&str, serde_json::Value)]) -> String {
        let mut object = serde_json::json!({
            "sub": "u1",
            "tenantId": "t1",
            "role": "USER",
            "status": "ACTIVE",
            "mfaEnabled": true,
            "mfaVerified": true,
            "jti": "a-jti",
            "epoch": 3
        });
        if let Some(map) = object.as_object_mut() {
            for (key, value) in overrides {
                map.insert((*key).to_owned(), value.clone());
            }
        }
        object.to_string()
    }

    /// The complete record without `key`.
    fn without(key: &str) -> String {
        let mut value: serde_json::Value = serde_json::from_str(&record(&[])).unwrap_or_default();
        if let Some(map) = value.as_object_mut() {
            map.remove(key);
        }
        value.to_string()
    }

    #[test]
    fn a_complete_record_is_a_ticket() {
        let parsed = parse_snapshot(&record(&[]));
        assert!(matches!(&parsed, Some(s) if s.jti == "a-jti" && s.epoch == 3));
    }

    #[test]
    fn a_platform_record_has_no_tenant() {
        let parsed = parse_snapshot(&without("tenantId"));
        assert!(matches!(parsed, Some(s) if s.tenant_id.is_none()));
    }

    #[test]
    fn a_record_that_is_not_a_whole_ticket_is_not_a_ticket() {
        // Every one of these was consumed by the GETDEL, and every one reads as an unknown
        // ticket: an old writer's record without the two identifiers, a jti that is not a
        // string, an epoch that is a string, negative or fractional, and text that is not an
        // object at all.
        for bad in [
            without("jti"),
            without("epoch"),
            record(&[("jti", serde_json::json!(7))]),
            record(&[("epoch", serde_json::json!("0"))]),
            record(&[("epoch", serde_json::json!(-1))]),
            record(&[("epoch", serde_json::json!(1.5))]),
            record(&[("mfaVerified", serde_json::json!("true"))]),
            "[]".to_owned(),
            "not json".to_owned(),
            String::new(),
        ] {
            assert!(parse_snapshot(&bad).is_none(), "accepted: {bad}");
        }
    }
}
