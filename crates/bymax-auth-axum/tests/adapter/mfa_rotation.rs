//! The MFA gate across refresh rotations, driven through the assembled router: a session that
//! cleared the MFA challenge (by TOTP or by recovery code) keeps clearing the gate behind
//! `MfaSatisfied` after every rotation. Shares the fixtures of the parent test file.

use super::*;

/// Enrol MFA for a fresh account and return `(secret, first recovery code)`.
async fn enrol_mfa(app: &axum::Router, email: &str) -> (String, String) {
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": email, "password": "glidingwalnut42", "name": "Mfa", "tenantId": TENANT
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
    let recovery = setup.json()["recoveryCodes"][0]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let _ = Req::post("/auth/mfa/verify-enable")
        .cookie("access_token", &access)
        .json(serde_json::json!({ "code": current_totp(&secret) }))
        .send(app)
        .await;
    (secret, recovery)
}

/// Refresh twice from `challenged`, asserting after the challenge and after each rotation that
/// the session still clears the MFA gate (`POST /auth/ws-ticket` sits behind `MfaSatisfied`).
async fn assert_gate_survives_two_rotations(app: &axum::Router, challenged: &Captured) {
    let mut access = challenged.cookie_value("access_token").unwrap_or_default();
    let mut refresh = challenged.cookie_value("refresh_token").unwrap_or_default();
    for round in 0..3 {
        let gated = Req::post("/auth/ws-ticket")
            .cookie("access_token", &access)
            .send(app)
            .await;
        assert_eq!(
            gated.status,
            StatusCode::OK,
            "the MFA gate refused a session that cleared the challenge (rotation {round})"
        );
        if round == 2 {
            break;
        }
        let rotated = Req::post("/auth/refresh")
            .cookie("refresh_token", &refresh)
            .send(app)
            .await;
        assert_eq!(rotated.status, StatusCode::OK);
        access = rotated.cookie_value("access_token").unwrap_or_default();
        refresh = rotated.cookie_value("refresh_token").unwrap_or_default();
    }
}

#[tokio::test]
async fn a_session_that_cleared_the_mfa_challenge_keeps_clearing_the_gate_after_two_rotations() {
    // Both ways of clearing the challenge, because the claim has to survive either: an
    // authenticated session cannot re-acquire `mfaVerified`, so a session that cleared the
    // challenge by TOTP or by recovery code must keep clearing the MFA gate through every
    // refresh rotation.
    let Some(h) = build(EngineSpec {
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);

    for (email, use_recovery_code) in [("gate-totp@e.com", false), ("gate-recovery@e.com", true)] {
        let (secret, recovery) = enrol_mfa(&app, email).await;
        let login = Req::post("/auth/login")
            .json(serde_json::json!({
                "email": email, "password": "glidingwalnut42", "tenantId": TENANT
            }))
            .send(&app)
            .await;
        let temp = login.json()["mfaTempToken"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        // A distinct window from the verify-enable code, so the anti-replay marker is not hit.
        let code = if use_recovery_code {
            recovery
        } else {
            common::totp_at(&secret, 30)
        };
        let challenge = Req::post("/auth/mfa/challenge")
            .json(serde_json::json!({ "mfaTempToken": temp, "code": code }))
            .send(&app)
            .await;
        assert_eq!(challenge.status, StatusCode::OK);
        assert_gate_survives_two_rotations(&app, &challenge).await;
    }
}
