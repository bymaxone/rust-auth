//! An email is trimmed and lowercased before it is validated, so a padded or upper-case address
//! reaches the same account the canonical one does. Shares the fixtures of the parent test file.

use super::*;

#[tokio::test]
async fn a_padded_upper_case_address_logs_in_to_the_same_account() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    seed_user(&h, "case@e.com", "glidingwalnut42", "USER").await;

    let padded = Req::post("/auth/login")
        .json(serde_json::json!({
            "email": "  CASE@E.com  ", "password": "glidingwalnut42", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    assert_eq!(padded.status, StatusCode::OK);
    assert_eq!(padded.json()["user"]["email"], "case@e.com");
    assert!(padded.has_cookie_value("access_token"));
}

#[tokio::test]
async fn a_malformed_address_is_still_a_validation_error_after_normalizing() {
    let Some(h) = build(EngineSpec::default()) else { return };
    let app = router(&h);
    for bad in ["   ", "not-an-email", "  no-at-sign  ", "\u{0085}a@e.com"] {
        let refused = Req::post("/auth/login")
            .json(serde_json::json!({
                "email": bad, "password": "glidingwalnut42", "tenantId": TENANT
            }))
            .send(&app)
            .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{bad:?}");
    }
}

#[tokio::test]
async fn a_whitespace_only_platform_password_is_a_validation_error() {
    let Some(h) = build(EngineSpec {
        platform: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let blank = Req::post("/auth/platform/login")
        .json(serde_json::json!({ "email": "admin@e.com", "password": "   " }))
        .send(&app)
        .await;
    assert_eq!(blank.status, StatusCode::BAD_REQUEST);
}
