//! The client-address rule: when `X-Forwarded-For` is believed, which hop is the client, and what
//! stands in for a missing or untrustworthy answer.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request};
use axum::routing::get;
use http::StatusCode;
use tower::ServiceExt;

use super::{ClientIpPolicy, ResolvedClientIp, resolve_client_ip};
use crate::state::{ClientIpSource, TrustedProxyFn};

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

/// The deployment's proxies: everything in `10.0.0.0/8`.
fn internal_proxies() -> TrustedProxyFn {
    Arc::new(|addr| matches!(addr, IpAddr::V4(v4) if v4.octets()[0] == 10))
}

fn behind_proxies() -> ClientIpPolicy {
    ClientIpPolicy::new(
        ClientIpSource::TrustedForwardedFor,
        Some(internal_proxies()),
    )
}

#[test]
fn a_directly_exposed_service_ignores_the_header() {
    let policy = ClientIpPolicy::new(ClientIpSource::PeerAddr, None);
    assert_eq!(
        policy.resolve(Some(ip("203.0.113.9")), "1.1.1.1"),
        Some(ip("203.0.113.9"))
    );
}

#[test]
fn a_peer_the_deployment_does_not_vouch_for_cannot_choose_its_address() {
    // The hole the predicate closes: a caller that reaches the service directly writes the
    // header itself.
    assert_eq!(
        behind_proxies().resolve(Some(ip("203.0.113.9")), "6.6.6.6"),
        Some(ip("203.0.113.9"))
    );
}

#[test]
fn a_trusted_single_proxy_reports_the_address_it_saw() {
    assert_eq!(
        behind_proxies().resolve(Some(ip("10.0.0.1")), "198.51.100.7"),
        Some(ip("198.51.100.7"))
    );
}

#[test]
fn junk_the_client_wrote_on_the_left_does_not_move_the_answer() {
    // The proxy appends, so the left of the list is whatever the client sent.
    assert_eq!(
        behind_proxies().resolve(Some(ip("10.0.0.1")), "6.6.6.6, 7.7.7.7, 198.51.100.7"),
        Some(ip("198.51.100.7"))
    );
}

#[test]
fn a_two_proxy_chain_skips_the_inner_proxy() {
    assert_eq!(
        behind_proxies().resolve(Some(ip("10.0.0.1")), "6.6.6.6, 198.51.100.7, 10.0.0.2"),
        Some(ip("198.51.100.7"))
    );
}

#[test]
fn a_chain_of_only_trusted_proxies_gives_its_leftmost_entry() {
    assert_eq!(
        behind_proxies().resolve(Some(ip("10.0.0.1")), "10.0.0.5, 10.0.0.4, 10.0.0.2"),
        Some(ip("10.0.0.5"))
    );
}

#[test]
fn a_trusted_peer_with_no_header_is_its_own_client() {
    assert_eq!(
        behind_proxies().resolve(Some(ip("10.0.0.1")), ""),
        Some(ip("10.0.0.1"))
    );
}

#[test]
fn an_entry_that_is_not_an_address_ends_the_walk_at_the_last_hop_that_was_one() {
    assert_eq!(
        behind_proxies().resolve(Some(ip("10.0.0.1")), "198.51.100.7, garbage, 10.0.0.2"),
        Some(ip("10.0.0.2"))
    );
    assert_eq!(
        behind_proxies().resolve(Some(ip("10.0.0.1")), "not-an-ip"),
        Some(ip("10.0.0.1"))
    );
}

#[test]
fn an_ipv4_mapped_peer_is_judged_as_the_ipv4_address_it_is() {
    assert_eq!(
        behind_proxies().resolve(Some(ip("::ffff:10.0.0.1")), "::ffff:198.51.100.7"),
        Some(ip("198.51.100.7"))
    );
    // And a mapped address outside the trusted range stays untrusted, reported unmapped.
    assert_eq!(
        behind_proxies().resolve(Some(ip("::ffff:203.0.113.9")), "6.6.6.6"),
        Some(ip("203.0.113.9"))
    );
}

#[test]
fn a_predicate_that_panics_vouches_for_nobody() {
    let policy = ClientIpPolicy::new(
        ClientIpSource::TrustedForwardedFor,
        // `resume_unwind` unwinds exactly as a panic does, which is what the guard must absorb.
        Some(Arc::new(|_| {
            std::panic::resume_unwind(Box::new("predicate failure"))
        })),
    );
    assert_eq!(
        policy.resolve(Some(ip("10.0.0.1")), "198.51.100.7"),
        Some(ip("10.0.0.1"))
    );
}

#[test]
fn without_a_peer_there_is_no_client_and_the_header_is_not_believed() {
    assert_eq!(behind_proxies().resolve(None, "198.51.100.7"), None);
    let direct = ClientIpPolicy::new(ClientIpSource::PeerAddr, None);
    assert_eq!(direct.resolve(None, "198.51.100.7"), None);
}

#[test]
fn trusting_the_header_without_a_predicate_falls_back_to_the_peer() {
    // The router refuses to build this shape; if it ever got here the safe answer is the peer.
    let policy = ClientIpPolicy::new(ClientIpSource::TrustedForwardedFor, None);
    assert_eq!(
        policy.resolve(Some(ip("203.0.113.9")), "6.6.6.6"),
        Some(ip("203.0.113.9"))
    );
}

/// Send one request through the resolving middleware and return the address it stored.
async fn stored_address(
    policy: ClientIpPolicy,
    peer: &str,
    header_lines: &[&str],
) -> Option<IpAddr> {
    let app = Router::new()
        .route(
            "/",
            get(|request: Request| async move {
                request
                    .extensions()
                    .get::<ResolvedClientIp>()
                    .map_or_else(String::new, |found| found.0.to_string())
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            policy,
            resolve_client_ip,
        ));
    let mut builder = Request::builder().uri("/");
    for line in header_lines {
        builder = builder.header("x-forwarded-for", *line);
    }
    let mut request = builder.body(Body::empty()).ok()?;
    if let Ok(addr) = peer.parse::<SocketAddr>() {
        request.extensions_mut().insert(ConnectInfo(addr));
    }
    let response = app.oneshot(request).await.ok()?;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 64).await.ok()?;
    String::from_utf8(bytes.to_vec()).ok()?.parse().ok()
}

#[tokio::test]
async fn the_middleware_stores_the_resolved_address_for_the_rest_of_the_request() {
    assert_eq!(
        stored_address(behind_proxies(), "10.0.0.1:443", &["198.51.100.7"]).await,
        Some(ip("198.51.100.7"))
    );
    assert_eq!(
        stored_address(behind_proxies(), "203.0.113.9:443", &["6.6.6.6"]).await,
        Some(ip("203.0.113.9"))
    );
}

#[tokio::test]
async fn a_second_header_line_continues_the_list_instead_of_replacing_it() {
    // Two lines are one comma-separated list in arrival order, so the proxy's line is the last.
    assert_eq!(
        stored_address(
            behind_proxies(),
            "10.0.0.1:443",
            &["6.6.6.6", "198.51.100.7"]
        )
        .await,
        Some(ip("198.51.100.7"))
    );
}

#[tokio::test]
async fn a_request_without_a_peer_stores_nothing() {
    assert_eq!(
        stored_address(behind_proxies(), "no-peer", &["1.1.1.1"]).await,
        None
    );
}
