//! A second-factor code of the wrong shape is refused at the edge with a validation error and is
//! never counted as a failed attempt, so a flood of malformed values cannot lock an account out.
//! Shares the fixtures of the parent test file.

use bymax_auth_axum::{AxumAuthConfig, ClientIpSource, RateLimitConfig};

use super::*;

/// Register `email`, enrol MFA, and return the TOTP secret.
async fn enrolled(app: &axum::Router, email: &str) -> String {
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": email, "password": "glidingwalnut42", "name": "Shape", "tenantId": TENANT
        }))
        .send(app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();
    let setup = Req::post("/auth/mfa/setup")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "password": "glidingwalnut42" }))
        .send(app)
        .await;
    let secret = setup.json()["secret"].as_str().unwrap_or("").to_owned();
    let _ = Req::post("/auth/mfa/verify-enable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": common::totp_at_abs(&secret, common::now_unix()) }))
        .send(app)
        .await;
    secret
}

#[tokio::test]
async fn malformed_challenge_codes_do_not_lock_the_account() {
    let Some(h) = build(EngineSpec {
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    // The route's own edge limit (5 per minute) would answer 429 before the account lockout (5
    // failed attempts) could be observed, so it is switched off for this test.
    let app = router_with(
        &h,
        AxumAuthConfig {
            rate_limits: RateLimitConfig {
                mfa_challenge: None,
                ..RateLimitConfig::default()
            },
            ..AxumAuthConfig::new(ClientIpSource::PeerAddr)
        },
    );
    let secret = enrolled(&app, "shape@e.com").await;
    let login = login(&app, "shape@e.com", "glidingwalnut42").await;
    let temp = login.json()["mfaTempToken"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    assert!(!temp.is_empty());

    // Past the lockout threshold of 5, every one a validation error and none an attempt.
    for attempt in 0..12 {
        let refused = Req::post("/auth/mfa/challenge")
            .json(serde_json::json!({ "mfaTempToken": temp, "code": format!("abcde{attempt}") }))
            .send(&app)
            .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "attempt {attempt}");
    }

    // The account is not locked and the token is untouched: the real code still clears it.
    let cleared = Req::post("/auth/mfa/challenge")
        .json(serde_json::json!({
            "mfaTempToken": temp, "code": common::totp_at_abs(&secret, common::now_unix() + 30)
        }))
        .send(&app)
        .await;
    assert_eq!(cleared.status, StatusCode::OK);
}
