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

    /// The fields of a complete record.
    fn complete() -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::from_iter([
            ("sub".to_owned(), serde_json::json!("u1")),
            ("tenantId".to_owned(), serde_json::json!("t1")),
            ("role".to_owned(), serde_json::json!("USER")),
            ("status".to_owned(), serde_json::json!("ACTIVE")),
            ("mfaEnabled".to_owned(), serde_json::json!(true)),
            ("mfaVerified".to_owned(), serde_json::json!(true)),
            ("jti".to_owned(), serde_json::json!("a-jti")),
            ("epoch".to_owned(), serde_json::json!(3)),
        ])
    }

    /// A complete record, with `overrides` replacing or adding to it.
    fn record(overrides: &[(&str, serde_json::Value)]) -> String {
        let mut map = complete();
        map.extend(
            overrides
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone())),
        );
        serde_json::Value::Object(map).to_string()
    }

    /// The complete record without `key`.
    fn without(key: &str) -> String {
        let mut map = complete();
        map.remove(key);
        serde_json::Value::Object(map).to_string()
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
