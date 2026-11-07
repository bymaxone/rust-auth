//! The platform guard decides the kind of a token before it reads any store: a validly signed
//! token of another kind is refused as such whether or not the revocation store is up, and only
//! a platform token's own revocation read can surface a store failure (as a 500). Shares the
//! fixtures of the parent test file.

use super::*;

const UUID_V4: &str = "6f1d5c2e-8f3a-4b1e-9a57-0c1d2e3f4a5b";

/// A dashboard access token with a well-formed `jti`, signed with the shared test secret.
fn dashboard_token() -> String {
    use bymax_auth_types::{DashboardClaims, DashboardType};
    let claims = DashboardClaims {
        iss: None,
        aud: None,
        sub: "someone".to_owned(),
        jti: UUID_V4.to_owned(),
        tenant_id: common::TENANT.to_owned(),
        role: "USER".to_owned(),
        token_type: DashboardType::Dashboard,
        status: "ACTIVE".to_owned(),
        mfa_enabled: false,
        mfa_verified: false,
        iat: 1_700_000_000,
        exp: 4_700_000_000,
        epoch: 0,
    };
    let key = bymax_auth_jwt::HsKey::from_bytes(common::JWT_SECRET.as_bytes());
    bymax_auth_jwt::sign(&claims, &key).unwrap_or_default()
}

/// An MFA-challenge token for a platform administrator, signed with the shared test secret.
fn challenge_token() -> String {
    use bymax_auth_types::{MfaContext, MfaTempClaims, MfaTempType};
    let claims = MfaTempClaims {
        sub: "admin".to_owned(),
        jti: UUID_V4.to_owned(),
        token_type: MfaTempType::MfaChallenge,
        context: MfaContext::Platform,
        tenant_id: None,
        epoch: 0,
        iat: 1_700_000_000,
        exp: 4_700_000_000,
        iss: None,
        aud: None,
    };
    let key = bymax_auth_jwt::HsKey::from_bytes(common::JWT_SECRET.as_bytes());
    bymax_auth_jwt::sign(&claims, &key).unwrap_or_default()
}

#[tokio::test]
async fn a_token_of_another_kind_is_refused_as_such_while_the_revocation_store_is_down() {
    let Some(h) = common::build_failing_blacklist() else { return };
    let app = router(&h);

    for (kind, token) in [
        ("dashboard", dashboard_token()),
        ("challenge", challenge_token()),
    ] {
        let refused = Req::get("/auth/platform/me")
            .bearer(&token)
            .send(&app)
            .await;
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{kind}");
        assert_eq!(
            refused.json()["error"]["code"],
            "auth.platform_auth_required",
            "{kind}"
        );
    }
}

#[tokio::test]
async fn a_platform_token_still_surfaces_the_store_failure_as_a_500() {
    let Some(h) = common::build_failing_blacklist() else { return };
    let app = router(&h);

    let token = common::mint_platform_token("padmin", "SUPER_ADMIN");
    let outage = Req::get("/auth/platform/me")
        .bearer(&token)
        .send(&app)
        .await;

    assert_eq!(outage.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(outage.json()["error"]["code"], "auth.internal");
}
