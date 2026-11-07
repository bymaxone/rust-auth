//! MFA secrets under a key retired by a rotation: a challenge drains them onto the current key on
//! both planes, and a write built from a read taken before the transition lock is abandoned when
//! the holder re-enrolled in between but not when a sibling challenge only re-encrypted the same
//! secret. Shares the fixtures of the parent test module.

use std::sync::Arc;

use base64::Engine as _;
use bymax_auth_types::{AuthPlatformUser, MfaContext};
use secrecy::SecretString;
use time::OffsetDateTime;

use super::tests::{
    Harness, admin_password_hash, build_full, build_rotating, login_temp_token, now_secs, raw_code,
    register, service_deps, service_over,
};
use super::{LoginResultMfa, MfaService};
use crate::testing::InMemoryStores;
use crate::traits::{PlatformUserRepository, UserRepository};

#[tokio::test]
async fn a_platform_totp_challenge_rewrites_a_secret_stored_under_a_retired_key() {
    // The platform plane keeps its secrets under the same key as the dashboard, so a rotation
    // drains there too: otherwise every platform administrator's secret stays under the retired
    // key and that key has to stay configured forever.
    let Some((h, retired_bytes)) = retired_platform_harness() else {
        return;
    };
    let Some((raw_secret, _codes, admin)) = retired_key_admin(&h, "p-rot", retired_bytes) else {
        return;
    };
    let stored_under_retired = admin.mfa_secret.clone().unwrap_or_default();
    let Some(temp) = platform_temp_token(&h, "p-rot").await else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };
    let code = raw_code(&raw_secret, now_secs());
    assert!(matches!(
        mfa.challenge(&temp, &code, "1.2.3.4", "ua").await,
        Ok(LoginResultMfa::Platform(_))
    ));

    // The stored record was rewritten: a service holding ONLY the current key now opens it.
    let Ok(Some(after)) = h.platform.find_by_id("p-rot").await else {
        return;
    };
    let rewritten = after.mfa_secret.unwrap_or_default();
    assert_ne!(rewritten, stored_under_retired);
    let strict = service_over(Arc::new(InMemoryStores::new()), h.users.clone());
    assert_eq!(
        strict.decrypt_secret(&rewritten).as_deref(),
        Some(raw_secret.as_slice())
    );
}

#[tokio::test]
async fn a_platform_recovery_challenge_rewrites_a_secret_stored_under_a_retired_key() {
    // The recovery-code path splices the spent digest out of the stored set; the write carries
    // the secret too, and it must carry the one under the current key.
    let Some((h, retired_bytes)) = retired_platform_harness() else {
        return;
    };
    let Some((raw_secret, codes, admin)) = retired_key_admin(&h, "p-rec", retired_bytes) else {
        return;
    };
    let before = admin.mfa_recovery_codes.as_ref().map(Vec::len);
    let stored_under_retired = admin.mfa_secret.clone().unwrap_or_default();
    let Some(temp) = platform_temp_token(&h, "p-rec").await else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };
    let Some(code) = codes.first() else { return };
    assert!(matches!(
        mfa.challenge(&temp, code, "1.2.3.4", "ua").await,
        Ok(LoginResultMfa::Platform(_))
    ));

    let Ok(Some(after)) = h.platform.find_by_id("p-rec").await else {
        return;
    };
    // The spent code is gone and the secret is under the current key.
    assert_eq!(
        after.mfa_recovery_codes.map(|c| c.len()),
        before.map(|n| n - 1)
    );
    let rewritten = after.mfa_secret.unwrap_or_default();
    assert_ne!(rewritten, stored_under_retired);
    let strict = service_over(Arc::new(InMemoryStores::new()), h.users.clone());
    assert_eq!(
        strict.decrypt_secret(&rewritten).as_deref(),
        Some(raw_secret.as_slice())
    );
}

/// A platform-enabled harness that holds a retired MFA key, and the bytes of that key.
fn retired_platform_harness() -> Option<(Harness, [u8; 32])> {
    let retired_bytes = [3u8; 32];
    let retired_b64 = base64::engine::general_purpose::STANDARD.encode(retired_bytes);
    let keys = vec![SecretString::from(retired_b64)];
    build_full(false, true, None, None, keys).map(|h| (h, retired_bytes))
}

/// A platform MFA temp token for `admin_id`, what a platform login hands an MFA-enabled admin.
async fn platform_temp_token(h: &Harness, admin_id: &str) -> Option<String> {
    h.engine
        .tokens()
        .issue_mfa_temp_token(admin_id, MfaContext::Platform, None)
        .await
        .ok()
}

/// A platform admin whose secret is stored under the RETIRED key, with the plain TOTP secret.
fn retired_key_admin(
    h: &Harness,
    id: &str,
    retired_bytes: [u8; 32],
) -> Option<(Vec<u8>, Vec<String>, AuthPlatformUser)> {
    let mfa = h.engine.mfa()?;
    let (raw_secret, codes, data) = mfa.generate_setup_material().ok()?;
    let mut old_deps = service_deps(Arc::new(InMemoryStores::new()), h.users.clone());
    old_deps.encryption_key = zeroize::Zeroizing::new(retired_bytes);
    let stored = MfaService::new(old_deps)
        .reencrypt_secret(&raw_secret)
        .ok()?;
    let admin = AuthPlatformUser {
        id: id.to_owned(),
        email: format!("{id}@example.com"),
        name: "Admin".to_owned(),
        password_hash: admin_password_hash(),
        role: "SUPER_ADMIN".to_owned(),
        status: "ACTIVE".to_owned(),
        mfa_enabled: true,
        mfa_secret: Some(stored.clone()),
        mfa_recovery_codes: Some(data.hashed_codes),
        platform_id: None,
        last_login_at: None,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        created_at: OffsetDateTime::UNIX_EPOCH,
    };
    h.platform.insert(admin.clone());
    Some((raw_secret, codes, admin))
}

#[tokio::test]
async fn a_platform_rewrite_never_puts_back_a_secret_the_holder_replaced_meanwhile() {
    // The challenge reads the admin, verifies the code, and writes under the transition lock.
    // If the holder disables MFA and enrols again with a NEW secret in between, the write built
    // from the earlier read would restore the old secret: the factor they just replaced, and the
    // one an attacker who held it would still pass. The write is abandoned instead.
    let retired_bytes = [3u8; 32];
    let retired_b64 = base64::engine::general_purpose::STANDARD.encode(retired_bytes);
    let Some(h) = build_full(
        false,
        true,
        None,
        None,
        vec![SecretString::from(retired_b64)],
    ) else {
        return;
    };
    let Some((raw_secret, _codes, admin)) = retired_key_admin(&h, "p-race", retired_bytes) else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(temp) = h
        .engine
        .tokens()
        .issue_mfa_temp_token("p-race", MfaContext::Platform, None)
        .await
    else {
        return;
    };
    // Re-enrolment lands when the transition lock is granted: a fresh secret, current key.
    let Ok((_new_raw, _codes, fresh)) = mfa.generate_setup_material() else {
        return;
    };
    let replacement = fresh.encrypted_secret.clone();
    let platform = h.platform.clone();
    h.stores.run_on_next_mfa_lock(move || {
        platform.insert(AuthPlatformUser {
            mfa_secret: Some(fresh.encrypted_secret),
            ..admin
        });
    });
    let code = raw_code(&raw_secret, now_secs());
    assert!(matches!(
        mfa.challenge(&temp, &code, "1.2.3.4", "ua").await,
        Ok(LoginResultMfa::Platform(_))
    ));
    let Ok(Some(after)) = h.platform.find_by_id("p-race").await else {
        return;
    };
    assert_eq!(after.mfa_secret.as_deref(), Some(replacement.as_str()));
}

#[tokio::test]
async fn a_platform_recovery_splice_never_puts_back_a_secret_the_holder_replaced_meanwhile() {
    // The same window on the recovery-code path: the spent code stays spent, and the secret the
    // holder just enrolled is the one that stays stored.
    let retired_bytes = [3u8; 32];
    let retired_b64 = base64::engine::general_purpose::STANDARD.encode(retired_bytes);
    let Some(h) = build_full(
        false,
        true,
        None,
        None,
        vec![SecretString::from(retired_b64)],
    ) else {
        return;
    };
    let Some((_raw, codes, admin)) = retired_key_admin(&h, "p-rec-race", retired_bytes) else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(temp) = h
        .engine
        .tokens()
        .issue_mfa_temp_token("p-rec-race", MfaContext::Platform, None)
        .await
    else {
        return;
    };
    let Ok((_new_raw, _new_codes, fresh)) = mfa.generate_setup_material() else {
        return;
    };
    let replacement = fresh.encrypted_secret.clone();
    let platform = h.platform.clone();
    h.stores.run_on_next_mfa_lock(move || {
        platform.insert(AuthPlatformUser {
            mfa_secret: Some(fresh.encrypted_secret),
            ..admin
        });
    });
    let Some(code) = codes.first() else { return };
    assert!(matches!(
        mfa.challenge(&temp, code, "1.2.3.4", "ua").await,
        Ok(LoginResultMfa::Platform(_))
    ));
    let Ok(Some(after)) = h.platform.find_by_id("p-rec-race").await else {
        return;
    };
    assert_eq!(after.mfa_secret.as_deref(), Some(replacement.as_str()));
}

/// A dashboard account whose secret is stored under the RETIRED key; returns the plain TOTP
/// secret, the plain recovery codes and the user id. The recovery digests come from the engine's
/// own service, since they depend on its keys.
async fn retired_key_user(
    h: &Harness,
    email: &str,
    retired_bytes: [u8; 32],
) -> Option<(Vec<u8>, Vec<String>, String)> {
    let uid = register(&h.engine, email).await?;
    let mfa = h.engine.mfa()?;
    let (raw_secret, codes, data) = mfa.generate_setup_material().ok()?;
    let mut old_deps = service_deps(Arc::new(InMemoryStores::new()), h.users.clone());
    old_deps.encryption_key = zeroize::Zeroizing::new(retired_bytes);
    let stored = MfaService::new(old_deps)
        .reencrypt_secret(&raw_secret)
        .ok()?;
    h.users
        .update_mfa(
            &uid,
            "t1",
            bymax_auth_types::UpdateMfaData {
                mfa_enabled: true,
                mfa_secret: Some(stored),
                mfa_recovery_codes: Some(data.hashed_codes),
            },
        )
        .await
        .ok()?;
    Some((raw_secret, codes, uid))
}

/// A challenge on a dashboard account whose secret is under the retired key, while the holder
/// re-enrols with a new secret as the transition lock is granted. Returns the secret left stored
/// and the one the holder enrolled.
async fn dashboard_challenge_across_a_re_enrolment(use_recovery: bool) -> Option<(String, String)> {
    let retired_bytes = [3u8; 32];
    let retired_b64 = base64::engine::general_purpose::STANDARD.encode(retired_bytes);
    let h = build_rotating(retired_b64)?;
    let (raw_secret, codes, uid) =
        retired_key_user(&h, "dash-race@example.com", retired_bytes).await?;
    let mfa = h.engine.mfa()?;
    let (_new_raw, _new_codes, fresh) = mfa.generate_setup_material().ok()?;
    let replacement = fresh.encrypted_secret;
    let temp = login_temp_token(&h.engine, "dash-race@example.com").await?;
    let (users, secret, user_id) = (h.users.clone(), replacement.clone(), uid.clone());
    h.stores
        .run_on_next_mfa_lock(move || users.replace_mfa_secret(&user_id, &secret));
    let code = if use_recovery {
        codes.first().cloned()?
    } else {
        raw_code(&raw_secret, now_secs())
    };
    let outcome = mfa.challenge(&temp, &code, "1.2.3.4", "ua").await;
    assert!(matches!(outcome, Ok(LoginResultMfa::Dashboard(_))));
    let after = h.users.find_by_id(&uid, None).await.ok()??;
    Some((after.mfa_secret.unwrap_or_default(), replacement))
}

#[tokio::test]
async fn a_sibling_rewrite_of_the_same_secret_does_not_stop_a_platform_splice() {
    // Two challenges can read the same retired-key secret. The first re-encrypts it, which
    // changes the ciphertext and not the enrolled factor; the second is a recovery-code
    // challenge and must still remove its spent digest, or the code comes back once its
    // five-minute claim expires.
    let Some((h, retired_bytes)) = retired_platform_harness() else {
        return;
    };
    let Some((raw_secret, codes, admin)) = retired_key_admin(&h, "p-sib", retired_bytes) else {
        return;
    };
    let before = admin.mfa_recovery_codes.as_ref().map(Vec::len);
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(rewritten) = mfa.reencrypt_secret(&raw_secret) else {
        return;
    };
    let Some(temp) = platform_temp_token(&h, "p-sib").await else {
        return;
    };
    let platform = h.platform.clone();
    h.stores.run_on_next_mfa_lock(move || {
        platform.insert(AuthPlatformUser {
            mfa_secret: Some(rewritten),
            ..admin
        });
    });
    let Some(code) = codes.first() else { return };
    assert!(matches!(
        mfa.challenge(&temp, code, "1.2.3.4", "ua").await,
        Ok(LoginResultMfa::Platform(_))
    ));
    let Ok(Some(after)) = h.platform.find_by_id("p-sib").await else {
        return;
    };
    assert_eq!(
        after.mfa_recovery_codes.map(|c| c.len()),
        before.map(|n| n - 1)
    );
}

#[tokio::test]
async fn a_sibling_rewrite_of_the_same_secret_does_not_stop_a_dashboard_splice() {
    let retired_bytes = [3u8; 32];
    let retired_b64 = base64::engine::general_purpose::STANDARD.encode(retired_bytes);
    let Some(h) = build_rotating(retired_b64) else {
        return;
    };
    let Some((raw_secret, codes, uid)) =
        retired_key_user(&h, "dash-sib@example.com", retired_bytes).await
    else {
        return;
    };
    let Some(mfa) = h.engine.mfa() else { return };
    let Ok(rewritten) = mfa.reencrypt_secret(&raw_secret) else {
        return;
    };
    let Some(temp) = login_temp_token(&h.engine, "dash-sib@example.com").await else {
        return;
    };
    let Ok(Some(before)) = h.users.find_by_id(&uid, None).await else {
        return;
    };
    let count = before.mfa_recovery_codes.map(|c| c.len());
    let (users, user_id) = (h.users.clone(), uid.clone());
    h.stores
        .run_on_next_mfa_lock(move || users.replace_mfa_secret(&user_id, &rewritten));
    let Some(code) = codes.first() else { return };
    assert!(matches!(
        mfa.challenge(&temp, code, "1.2.3.4", "ua").await,
        Ok(LoginResultMfa::Dashboard(_))
    ));
    let Ok(Some(after)) = h.users.find_by_id(&uid, None).await else {
        return;
    };
    assert_eq!(
        after.mfa_recovery_codes.map(|c| c.len()),
        count.map(|n| n - 1)
    );
}

#[tokio::test]
async fn a_dashboard_totp_rewrite_never_puts_back_a_replaced_secret() {
    let Some((stored, replacement)) = dashboard_challenge_across_a_re_enrolment(false).await else {
        return;
    };
    assert_eq!(stored, replacement);
}

#[tokio::test]
async fn a_dashboard_recovery_splice_never_puts_back_a_replaced_secret() {
    let Some((stored, replacement)) = dashboard_challenge_across_a_re_enrolment(true).await else {
        return;
    };
    assert_eq!(stored, replacement);
}
