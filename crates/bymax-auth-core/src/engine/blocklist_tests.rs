//! `password.blocklist` reaches the engine's default password screen, and only when the host did
//! not supply a screen of its own.

use std::sync::Arc;

use bymax_auth_types::AuthError;

use crate::config::Environment;
use crate::engine::AuthEngine;
use crate::error::ConfigError;
use crate::services::auth::test_support::base_config;
use crate::testing::{InMemoryStores, InMemoryUserRepository};
use crate::traits::AllowAllBreachChecker;

const LONG_ENOUGH: &str = "a-strong-passphrase-with-acme";

fn engine(blocklist: &[&str], custom_screen: bool) -> Result<AuthEngine, ConfigError> {
    let mut cfg = base_config();
    // Below the default floor, so the length check does not answer before the screen does.
    cfg.password.min_length = 8;
    cfg.password.blocklist = blocklist.iter().map(|word| (*word).to_owned()).collect();
    let mut builder = AuthEngine::builder()
        .config(cfg)
        .environment(Environment::Test)
        .user_repository(Arc::new(InMemoryUserRepository::new()))
        .redis_stores(Arc::new(InMemoryStores::new()));
    if custom_screen {
        builder = builder.breach_checker(Arc::new(AllowAllBreachChecker));
    }
    builder.build()
}

async fn refused(engine: &AuthEngine, password: &str) -> bool {
    matches!(
        engine
            .passwords()
            .assert_acceptable(password, "password")
            .await,
        Err(AuthError::PasswordCompromised)
    )
}

#[tokio::test]
async fn a_listed_word_is_refused_in_every_form_a_user_would_reach_for() -> Result<(), ConfigError>
{
    let engine = engine(&["Acme"], false)?;

    for password in ["Acme2024!", "@cme12345", "ACME!!!!!"] {
        assert!(refused(&engine, password).await, "{password}");
    }
    // A password that merely contains the word among other material does not reduce to it.
    assert!(!refused(&engine, "Acme2024!-passphrase").await);
    assert!(!refused(&engine, "correct-horse-battery-staple").await);

    Ok(())
}

#[tokio::test]
async fn without_the_list_the_same_word_is_accepted() -> Result<(), ConfigError> {
    let engine = engine(&[], false)?;

    assert!(!refused(&engine, "Acme2024!").await);
    assert!(!refused(&engine, LONG_ENOUGH).await);

    Ok(())
}

#[tokio::test]
async fn a_screen_the_host_supplied_owns_the_decision_and_the_list_is_ignored()
-> Result<(), ConfigError> {
    let engine = engine(&["Acme"], true)?;

    assert!(!refused(&engine, "Acme2024!").await);

    Ok(())
}
