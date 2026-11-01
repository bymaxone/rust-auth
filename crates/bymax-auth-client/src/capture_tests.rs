//! Request-capture tests for the client: a one-shot TCP server hands back the exact request the
//! client wrote, so a test can assert the method, path and body a call put on the wire. Unlike
//! the scripted server in the main test module, the wait is bounded, so a call that sends
//! nothing fails its assertion instead of hanging the suite.

use std::future::Future;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::tests::response;
use super::*;

/// Whether `raw` holds a complete HTTP request: the header block plus `Content-Length`
/// body bytes.
fn request_is_complete(raw: &str) -> bool {
    let Some((head, body)) = raw.split_once("\r\n\r\n") else { return false };
    let declared = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(str::to_owned)
        })
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    body.len() >= declared
}

/// Read from `stream` until a complete HTTP request has arrived or the peer closes, so a
/// request the client writes in several segments is captured whole.
async fn read_request<R>(stream: &mut R) -> Option<String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    while !request_is_complete(&String::from_utf8_lossy(&raw)) {
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
    }
    Some(String::from_utf8_lossy(&raw).into_owned())
}

/// Serve one `reply` and resolve to the full request the client sent, or `None` when no
/// request arrives within a bounded wait. Unlike [`with_server`], the wait is bounded, so
/// a client call that sends nothing fails the assertion instead of hanging the suite.
async fn capture_request<F, Fut>(reply: Vec<u8>, body: F) -> Option<String>
where
    F: FnOnce(AuthClient) -> Fut,
    Fut: Future<Output = ()>,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
    let addr = listener.local_addr().ok()?;
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.ok()?;
        let request = read_request(&mut socket).await?;
        let _ = socket.write_all(&reply).await;
        let _ = socket.flush().await;
        Some(request)
    });
    body(AuthClient::new(format!("http://{addr}"))).await;
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), server).await;
    outcome.ok().and_then(Result::ok).flatten()
}

#[tokio::test]
async fn a_request_written_in_segments_is_read_whole_and_a_closed_peer_ends_the_read() {
    // reqwest may send the header block and the body in separate writes, so the reader has
    // to keep going until the declared `Content-Length` has arrived.
    let (mut client, mut server) = tokio::io::duplex(64);
    let writer = tokio::spawn(async move {
        let _ = client
            .write_all(b"POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nab")
            .await;
        tokio::task::yield_now().await;
        let _ = client.write_all(b"cde").await;
    });
    let whole = read_request(&mut server).await;
    let _ = writer.await;
    assert_eq!(
        whole.as_deref(),
        Some("POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nabcde")
    );

    // A peer that closes before the body is complete ends the read with what arrived.
    let (mut client, mut server) = tokio::io::duplex(64);
    let _ = client
        .write_all(b"POST /x HTTP/1.1\r\nContent-Length: 9\r\n\r\nab")
        .await;
    drop(client);
    let partial = read_request(&mut server).await;
    assert_eq!(
        partial.as_deref(),
        Some("POST /x HTTP/1.1\r\nContent-Length: 9\r\n\r\nab")
    );
}

#[tokio::test]
async fn forgot_password_posts_the_email_and_tenant() {
    // forgot-password must reach the backend: a POST to the route with the JSON body.
    let request = capture_request(response(200, "OK", "{}"), |client| async move {
        assert!(client.forgot_password("u@e.com", "t1").await.is_ok());
    })
    .await
    .unwrap_or_default();
    assert!(request.starts_with("POST /auth/password/forgot-password "));
    assert!(request.contains(r#""email":"u@e.com""#));
    assert!(request.contains(r#""tenantId":"t1""#));
}

#[tokio::test]
async fn reset_password_posts_each_proof_under_its_own_field() {
    // Each proof variant is sent to the route under exactly its own JSON field.
    let proofs = [
        (
            ResetPasswordProof::Token("tok".to_owned()),
            r#""token":"tok""#,
        ),
        (
            ResetPasswordProof::Otp("123456".to_owned()),
            r#""otp":"123456""#,
        ),
        (
            ResetPasswordProof::VerifiedToken("vt".to_owned()),
            r#""verifiedToken":"vt""#,
        ),
    ];
    for (proof, field) in proofs {
        let request = capture_request(response(204, "No Content", ""), |client| async move {
            let input = ResetPasswordRequest {
                email: "u@e.com".to_owned(),
                new_password: "newglidingwalnut42".to_owned(),
                proof,
                tenant_id: "t1".to_owned(),
            };
            assert!(client.reset_password(&input).await.is_ok());
        })
        .await
        .unwrap_or_default();
        assert!(request.starts_with("POST /auth/password/reset-password "));
        assert!(request.contains(field));
        assert!(request.contains(r#""newPassword":"newglidingwalnut42""#));
        assert!(request.contains(r#""tenantId":"t1""#));
    }
}

#[tokio::test]
async fn logout_names_the_stored_refresh_token_so_the_server_session_ends() {
    // The server revokes the session the refresh token names; a logout that sent only the access
    // token cleared the client's copy and left the session redeemable for its whole lifetime.
    let request = capture_request(response(204, "No Content", ""), |client| async move {
        client.store_tokens("acc-token", "ref-token");
        assert!(client.logout().await.is_ok());
        assert!(client.access_token().is_none() && client.refresh_token().is_none());
    })
    .await
    .unwrap_or_default();
    assert!(request.starts_with("POST /auth/logout "));
    assert!(request.contains("authorization: Bearer acc-token"));
    assert!(request.contains(r#""refreshToken":"ref-token""#));
}
