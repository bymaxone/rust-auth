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
        match raw {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }
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
