//! The operator warning for a repository that answers outside the requested tenant.

use super::*;

#[tokio::test]
async fn only_a_cross_tenant_answer_is_reported_as_a_misconfigured_repository() {
    // The refusal itself is pinned by `a_repository_that_ignores_its_tenant_argument_is_refused`;
    // this pins the operator signal. The warning names the repository as the culprit, so it
    // must fire for an account returned from another tenant and stay silent for an ordinary
    // same-tenant login and for a plain wrong password, or it would cry wolf on every request.
    let mut cfg = base_config();
    cfg.email_verification.required = false;
    let Some(h) = harness(cfg, None) else { return };
    let _ = h
        .seed(SeedUser::active("warn@example.com", "s3cret-pass"))
        .await;
    let cross_tenant = || LoginInput {
        email: "warn@example.com".to_owned(),
        password: "s3cret-pass".to_owned(),
        tenant_id: Some("t2".to_owned()),
    };
    let signal = "outside the requested tenant";

    let (events, capture) = crate::log_capture::capture_events();
    let own = h
        .engine
        .login(login_input("warn@example.com", "s3cret-pass"), &ctx())
        .await;
    let wrong = h
        .engine
        .login(login_input("warn@example.com", "wrong-pass"), &ctx())
        .await;
    drop(capture);
    assert!(own.is_ok());
    assert!(matches!(wrong, Err(AuthError::InvalidCredentials)));
    assert!(
        !events.contains(signal),
        "a same-tenant login must not warn"
    );

    h.users.ignore_tenant_on_email();
    let (events, capture) = crate::log_capture::capture_events();
    let refused = h.engine.login(cross_tenant(), &ctx()).await;
    drop(capture);
    assert!(matches!(refused, Err(AuthError::InvalidCredentials)));
    assert!(events.contains_at(tracing::Level::WARN, signal));
}
