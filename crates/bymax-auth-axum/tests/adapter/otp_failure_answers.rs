//! Every way an OTP can fail is answered the same on the wire.
//!
//! An absent record, a wrong code, and an attempt ceiling that has been reached all answer
//! `401 auth.otp_invalid` with the same message and no `Retry-After`. The engine tells them apart
//! internally (`OtpExpired`, `OtpInvalid`, `OtpMaxAttempts`), and `to_wire` is what collapses them:
//! only a record that exists can expire into a wrong code or reach a ceiling, so a distinct
//! answer would tell a caller whether an address has an account. The three routes that verify an
//! OTP are covered. Shares the fixtures of the parent test file.

use super::*;

/// The attempts the store allows before it consumes the record.
const CEILING: usize = 5;

/// The one answer every OTP failure gets: status, code, message, details, `Retry-After`.
type Answer = (
    StatusCode,
    serde_json::Value,
    serde_json::Value,
    serde_json::Value,
    Option<String>,
);

fn answer(response: &Captured) -> Answer {
    let body = response.json();
    (
        response.status,
        body["error"]["code"].clone(),
        body["error"]["message"].clone(),
        body["error"]["details"].clone(),
        response.retry_after(),
    )
}

fn the_answer() -> Answer {
    (
        StatusCode::UNAUTHORIZED,
        serde_json::json!("auth.otp_invalid"),
        serde_json::json!("Invalid OTP code"),
        serde_json::Value::Null,
        None,
    )
}

/// A route that verifies an OTP.
#[derive(Clone, Copy, Debug)]
enum Route {
    VerifyOtp,
    ResetPassword,
    VerifyEmail,
}

const ROUTES: [Route; 3] = [Route::VerifyOtp, Route::ResetPassword, Route::VerifyEmail];

fn request(route: Route, email: &str, code: &str) -> Req {
    match route {
        Route::VerifyOtp => Req::post("/auth/password/verify-otp")
            .json(serde_json::json!({ "email": email, "otp": code, "tenantId": TENANT })),
        Route::ResetPassword => Req::post("/auth/password/reset-password").json(serde_json::json!({
            "email": email, "newPassword": "aquietmorningwalk77", "otp": code, "tenantId": TENANT
        })),
        Route::VerifyEmail => Req::post("/auth/verify-email")
            .json(serde_json::json!({ "email": email, "otp": code, "tenantId": TENANT })),
    }
}

/// The router with the limits out of the way, and the harness behind it.
fn app_with_limits_raised() -> Option<(common::Harness, axum::Router)> {
    let harness = build(EngineSpec {
        verification_required: true,
        ..EngineSpec::default()
    })?;
    let mut config =
        bymax_auth_axum::AxumAuthConfig::new(bymax_auth_axum::ClientIpSource::PeerAddr);
    let generous = Some(bymax_auth_axum::RateLimit::new(100_000, 60));
    for setter in ALL_LIMIT_SETTERS {
        setter(&mut config.rate_limits, generous);
    }
    let app = router_with(&harness, config);
    Some((harness, app))
}

/// Writes the record the route verifies, for an address, and returns the code that was mailed.
/// An account is created for the address the first time, so the record exists.
async fn open_record(h: &common::Harness, app: &axum::Router, route: Route, email: &str) -> String {
    match route {
        Route::VerifyEmail => {
            let register = Req::post("/auth/register")
                .json(serde_json::json!({
                    "email": email, "password": "glidingwalnut42", "name": "Otp", "tenantId": TENANT
                }))
                .send(app)
                .await;
            assert_eq!(register.status, StatusCode::CREATED);
            h.emails.await_verification_code().await.unwrap_or_default()
        }
        Route::VerifyOtp | Route::ResetPassword => {
            seed_user(h, email, "glidingwalnut42", "USER").await;
            let forgot = Req::post("/auth/password/forgot-password")
                .json(serde_json::json!({ "email": email, "tenantId": TENANT }))
                .send(app)
                .await;
            assert_eq!(forgot.status, StatusCode::OK);
            h.emails
                .await_password_reset_code()
                .await
                .unwrap_or_default()
        }
    }
}

#[tokio::test]
async fn an_absent_record_is_refused_with_the_one_answer() {
    let Some((_h, app)) = app_with_limits_raised() else { return };
    for route in ROUTES {
        let response = request(route, "nobody@e.com", "123456").send(&app).await;
        assert_eq!(answer(&response), the_answer(), "{route:?}");
    }
}

#[tokio::test]
async fn a_wrong_code_against_a_live_record_is_refused_with_the_same_answer() {
    let Some((h, app)) = app_with_limits_raised() else { return };
    for (index, route) in ROUTES.into_iter().enumerate() {
        let email = format!("wrong{index}@e.com");
        let code = open_record(&h, &app, route, &email).await;
        assert!(!code.is_empty(), "{route:?} mailed no code");
        let wrong = if code == "000000" { "111111" } else { "000000" };
        let response = request(route, &email, wrong).send(&app).await;
        assert_eq!(answer(&response), the_answer(), "{route:?}");
        // The record is still there: its own code is accepted, which is what makes the answer
        // above a wrong-code answer and not an absent-record one.
        let accepted = request(route, &email, &code).send(&app).await;
        assert!(
            accepted.status.is_success(),
            "{route:?}: {}",
            accepted.json()
        );
    }
}

#[tokio::test]
async fn past_the_attempts_ceiling_the_answer_is_the_same_and_the_record_is_spent() {
    let Some((h, app)) = app_with_limits_raised() else { return };
    for (index, route) in ROUTES.into_iter().enumerate() {
        let email = format!("ceiling{index}@e.com");
        let code = open_record(&h, &app, route, &email).await;
        let wrong = if code == "000000" { "111111" } else { "000000" };
        for attempt in 1..=CEILING + 2 {
            let response = request(route, &email, wrong).send(&app).await;
            assert_eq!(
                answer(&response),
                the_answer(),
                "{route:?} attempt {attempt}"
            );
        }
        // The ceiling is enforced: the record's own code no longer works, and the refusal is
        // still the one answer, with no `Retry-After` and no 429.
        let spent = request(route, &email, &code).send(&app).await;
        assert_eq!(
            answer(&spent),
            the_answer(),
            "{route:?} with the right code"
        );
    }
}
