//! The rehash-on-verify toggle: a stale stored hash is upgraded only while the toggle is on.

use super::*;

/// Store `password` under a scrypt cost below the harness default and return the account id and
/// the stored (stale) hash.
#[cfg(feature = "scrypt")]
async fn seed_stale_account(h: &Harness, email: &str, password: &str) -> Option<(String, String)> {
    let weak = bymax_auth_crypto::password::PasswordParams {
        active: bymax_auth_crypto::password::PasswordAlgorithm::Scrypt,
        scrypt: bymax_auth_crypto::password::ScryptParams {
            cost_factor: 1 << 14,
            block_size: 8,
            parallelization: 1,
        },
        #[cfg(feature = "argon2")]
        argon2: bymax_auth_crypto::password::Argon2Params::default(),
    };
    let stale = bymax_auth_crypto::password::hash(password.as_bytes(), &weak).ok()?;
    let created = h
        .users
        .create(bymax_auth_types::CreateUserData {
            email: email.to_owned(),
            name: "Stale".to_owned(),
            password_hash: Some(stale.clone()),
            role: None,
            status: Some("ACTIVE".to_owned()),
            tenant_id: "t1".to_owned(),
            email_verified: Some(true),
        })
        .await
        .ok()?;
    Some((created.id, stale))
}

#[cfg(feature = "scrypt")]
#[tokio::test]
async fn a_stale_hash_is_left_alone_while_the_toggle_is_off() {
    // The upgrade needs the toggle AND a stale hash. The stale hash is present here, so the
    // toggle is the only thing standing between the login and a write on the user table; a
    // deployment that turned it off must not see its hashes rewritten.
    let mut cfg = base_config();
    cfg.email_verification.required = false;
    cfg.password.rehash_on_verify = false;
    let Some(h) = harness(cfg, None) else { return };
    let Some((id, stale)) = seed_stale_account(&h, "off@example.com", "pw").await else {
        return;
    };
    assert!(bymax_auth_crypto::password::needs_rehash(
        &stale,
        &crate::services::auth::test_support::crypto_params()
    ));

    let result = h
        .engine
        .login(login_input("off@example.com", "pw"), &ctx())
        .await;
    assert!(matches!(result, Ok(LoginResult::Success(_))));

    // A rehash is one scrypt derivation, so a generous poll catches it if it is going to happen.
    assert!(
        !super::super::super::test_support::await_rehash_within(&h, &id, &stale, 40).await,
        "a stale hash was rewritten although rehash_on_verify is off"
    );
}
