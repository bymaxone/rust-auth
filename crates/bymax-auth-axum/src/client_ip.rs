//! Which address the adapter treats as the client's (layer: HTTP adapter).
//!
//! One rule serves the rate limiter and the engine context alike, so the bucket a request is
//! charged to and the address recorded on its session, lockout key and hooks can never disagree.
//! The rule is resolved once per request by [`resolve_client_ip`] and carried as a request
//! extension, [`ResolvedClientIp`].
//!
//! `X-Forwarded-For` is written by whoever sent the request, so it is believed only when the
//! TCP peer itself is a proxy the deployment vouches for. Behind such a proxy each hop appends
//! the address it saw, so the client is the rightmost entry that is not itself a trusted proxy.

use std::net::{IpAddr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind};

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::state::{ClientIpSource, TrustedProxyFn};

/// The client address resolved for this request, stored as a request extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedClientIp(pub IpAddr);

/// How the client address is derived, built once at router assembly.
#[derive(Clone)]
pub(crate) struct ClientIpPolicy {
    source: ClientIpSource,
    is_trusted_proxy: Option<TrustedProxyFn>,
}

impl ClientIpPolicy {
    /// The policy for a source and its optional trust predicate.
    pub(crate) fn new(source: ClientIpSource, is_trusted_proxy: Option<TrustedProxyFn>) -> Self {
        Self {
            source,
            is_trusted_proxy,
        }
    }

    /// The client address for a request from `peer` carrying `forwarded_for`, or `None` when the
    /// transport reported no peer.
    ///
    /// `PeerAddr` is the peer. `TrustedForwardedFor` believes the header only when the peer
    /// satisfies the predicate; otherwise the peer is the client. Past a trusted peer the header is
    /// read from the right: each entry is a hop, and the first that is not a trusted proxy is the
    /// client. A chain made only of trusted proxies gives its leftmost entry, and an entry that is
    /// not an address ends the walk at the last hop that was one. IPv4-mapped IPv6 addresses are
    /// reduced to IPv4 first, so one host is one address whichever way the socket spells it.
    pub(crate) fn resolve(&self, peer: Option<IpAddr>, forwarded_for: &str) -> Option<IpAddr> {
        let peer = peer.map(|ip| ip.to_canonical());
        let (ClientIpSource::TrustedForwardedFor, Some(is_trusted)) =
            (self.source, self.is_trusted_proxy.as_ref())
        else {
            return peer;
        };
        let peer = peer?;
        if !trusts(is_trusted, peer) {
            return Some(peer);
        }
        let mut client = peer;
        for entry in forwarded_for.rsplit(',') {
            let Ok(hop) = entry.trim().parse::<IpAddr>() else {
                break;
            };
            client = hop.to_canonical();
            if !trusts(is_trusted, client) {
                break;
            }
        }
        Some(client)
    }
}

/// Whether the predicate vouches for `ip`. Only an answer of `true` counts: a predicate that
/// panics is not an answer, so it vouches for nobody.
fn trusts(is_trusted: &TrustedProxyFn, ip: IpAddr) -> bool {
    catch_unwind(AssertUnwindSafe(|| is_trusted(ip))).unwrap_or(false)
}

/// Resolve the client address once and store it as [`ResolvedClientIp`] for the limiter and the
/// engine context. Every `X-Forwarded-For` line counts, joined in arrival order: a second header
/// line is the same list continued, not a way around the right-to-left walk.
pub(crate) async fn resolve_client_ip(
    State(policy): State<ClientIpPolicy>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip());
    let forwarded_for = request
        .headers()
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(",");
    if let Some(ip) = policy.resolve(peer, &forwarded_for) {
        request.extensions_mut().insert(ResolvedClientIp(ip));
    }
    next.run(request).await
}

#[cfg(test)]
mod tests;
