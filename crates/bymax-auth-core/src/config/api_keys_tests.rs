//! Startup validation of the `api_keys` group: nothing is checked while it is off, and once it is
//! on every option that could make a key unverifiable, shared or unreachable is refused.

use std::time::Duration;

use secrecy::SecretString;

use super::{ApiKeyAuditMode, ApiKeysConfig, AuthConfig, Environment, MfaConfig};
use crate::error::ConfigError;
use crate::services::auth::test_support::base_config;

/// 43 base64url characters that also decode to 32 bytes, so the same value is a valid MFA key.
const PEPPER: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

fn enabled() -> AuthConfig {
    let mut cfg = base_config();
    cfg.api_keys.enabled = true;
    cfg.api_keys.pepper = SecretString::from(PEPPER.to_owned());
    cfg.api_keys.scopes = vec!["reports:read".to_owned(), "reports:write".to_owned()];
    cfg
}

fn verdict(cfg: &AuthConfig) -> Result<bool, ConfigError> {
    cfg.validate(Environment::Test)
}

fn secret(value: &str) -> SecretString {
    SecretString::from(value.to_owned())
}

fn mfa(key: SecretString, previous: Vec<SecretString>) -> MfaConfig {
    MfaConfig {
        encryption_key: key,
        previous_encryption_keys: previous,
        issuer: "Acme".to_owned(),
        recovery_code_count: 8,
        totp_window: 1,
    }
}

#[test]
fn the_group_is_off_by_default_and_nothing_is_checked_while_it_is() {
    let mut cfg = base_config();
    assert!(!cfg.api_keys.enabled);
    assert_eq!(cfg.api_keys.header, "x-api-key");
    assert_eq!(cfg.api_keys.prefix, "bak");
    assert_eq!(cfg.api_keys.last_used_flush, Duration::from_secs(60));
    assert_eq!(cfg.api_keys.audit_mode, ApiKeyAuditMode::BestEffort);
    // A weak pepper and an empty vocabulary are not an error until the feature is on.
    cfg.api_keys.pepper = secret("short");
    cfg.api_keys.header = "Authorization".to_owned();
    assert!(verdict(&cfg).is_ok());
}

#[cfg(feature = "api-keys")]
#[test]
fn a_complete_group_is_accepted() {
    assert!(verdict(&enabled()).is_ok());
}

#[cfg(not(feature = "api-keys"))]
#[test]
fn enabling_the_group_without_the_feature_is_refused() {
    assert!(matches!(
        verdict(&enabled()),
        Err(ConfigError::ApiKeysFeatureDisabled)
    ));
}

#[cfg(feature = "api-keys")]
mod rules {
    use super::*;

    #[test]
    fn a_short_or_low_entropy_pepper_is_refused() {
        let mut cfg = enabled();
        cfg.api_keys.pepper = secret("too-short");
        assert!(matches!(
            verdict(&cfg),
            Err(ConfigError::ApiKeysPepperTooShort { len: 9 })
        ));
        cfg.api_keys.pepper = secret(&"a".repeat(40));
        assert!(matches!(
            verdict(&cfg),
            Err(ConfigError::ApiKeysPepperLowEntropy { .. })
        ));
    }

    #[test]
    fn thirty_two_characters_is_the_shortest_pepper() {
        let mut cfg = enabled();
        cfg.api_keys.pepper = secret(&PEPPER[..31]);
        assert!(matches!(
            verdict(&cfg),
            Err(ConfigError::ApiKeysPepperTooShort { len: 31 })
        ));
        cfg.api_keys.pepper = secret(&PEPPER[..32]);
        assert!(verdict(&cfg).is_ok());
    }

    #[test]
    fn the_pepper_equals_no_other_key_the_deployment_holds() {
        let jwt = secret(PEPPER);
        let mut cfg = enabled();
        cfg.jwt.secret = jwt.clone();
        assert!(matches!(
            verdict(&cfg),
            Err(ConfigError::ApiKeysPepperReused {
                reused: "jwt.secret"
            })
        ));

        let mut cfg = enabled();
        cfg.jwt.previous_secrets = vec![secret(PEPPER)];
        assert!(matches!(
            verdict(&cfg),
            Err(ConfigError::ApiKeysPepperReused {
                reused: "a retired jwt secret"
            })
        ));

        let mut cfg = enabled();
        cfg.identifier_key = Some(secret(PEPPER));
        assert!(matches!(
            verdict(&cfg),
            Err(ConfigError::ApiKeysPepperReused {
                reused: "identifier_key"
            })
        ));

        let mut cfg = enabled();
        cfg.mfa = Some(mfa(secret(PEPPER), Vec::new()));
        assert!(matches!(
            verdict(&cfg),
            Err(ConfigError::ApiKeysPepperReused {
                reused: "an MFA encryption key"
            })
        ));

        let mut cfg = enabled();
        cfg.mfa = Some(mfa(
            secret("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"),
            vec![secret(PEPPER)],
        ));
        assert!(matches!(
            verdict(&cfg),
            Err(ConfigError::ApiKeysPepperReused {
                reused: "an MFA encryption key"
            })
        ));
    }

    #[test]
    fn the_vocabulary_is_non_empty_well_formed_and_distinct() {
        let mut cfg = enabled();
        cfg.api_keys.scopes = Vec::new();
        assert!(matches!(
            verdict(&cfg),
            Err(ConfigError::ApiKeysScopes { index: None, .. })
        ));

        for bad in ["", ":lead", "has space", "slash/x", "ünï", &"s".repeat(65)] {
            let mut cfg = enabled();
            cfg.api_keys.scopes = vec!["ok".to_owned(), bad.to_owned()];
            assert!(
                matches!(
                    verdict(&cfg),
                    Err(ConfigError::ApiKeysScopes { index: Some(1), .. })
                ),
                "{bad:?}"
            );
        }
        // 64 characters is the longest accepted.
        let mut cfg = enabled();
        cfg.api_keys.scopes = vec!["s".repeat(64), "a:b.c_d-e".to_owned()];
        assert!(verdict(&cfg).is_ok());

        let mut cfg = enabled();
        cfg.api_keys.scopes = vec!["a".to_owned(), "b".to_owned(), "a".to_owned()];
        assert!(matches!(
            verdict(&cfg),
            Err(ConfigError::ApiKeysScopes { index: Some(2), .. })
        ));
    }

    #[test]
    fn the_header_is_a_lowercase_name_the_library_does_not_read() {
        for bad in [
            "",
            "X-Api-Key",
            "-lead",
            "has space",
            "a_b",
            "authorization",
            "cookie",
            "host",
            "x-forwarded-for",
        ] {
            let mut cfg = enabled();
            cfg.api_keys.header = bad.to_owned();
            assert!(
                matches!(
                    verdict(&cfg),
                    Err(ConfigError::ApiKeysTransport {
                        field: "header",
                        ..
                    })
                ),
                "{bad:?}"
            );
        }
        let mut cfg = enabled();
        cfg.api_keys.header = "x-service-key".to_owned();
        assert!(verdict(&cfg).is_ok());
        cfg.api_keys.header = "k".repeat(65);
        assert!(matches!(
            verdict(&cfg),
            Err(ConfigError::ApiKeysTransport {
                field: "header",
                ..
            })
        ));
    }

    #[test]
    fn the_prefix_is_two_to_sixteen_lowercase_alphanumerics_without_an_underscore() {
        for bad in ["", "a", "Bak", "1ab", "ba_k", "ba-k", &"p".repeat(17)] {
            let mut cfg = enabled();
            cfg.api_keys.prefix = bad.to_owned();
            assert!(
                matches!(
                    verdict(&cfg),
                    Err(ConfigError::ApiKeysTransport {
                        field: "prefix",
                        ..
                    })
                ),
                "{bad:?}"
            );
        }
        for good in ["ab", "bak", "svc2", &"p".repeat(16)] {
            let mut cfg = enabled();
            cfg.api_keys.prefix = good.to_owned();
            assert!(verdict(&cfg).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn the_flush_interval_is_a_whole_number_of_seconds_from_one_to_3600() {
        for good in [1_u64, 60, 3600] {
            let mut cfg = enabled();
            cfg.api_keys.last_used_flush = Duration::from_secs(good);
            assert!(verdict(&cfg).is_ok(), "{good}");
        }
        for bad in [
            Duration::ZERO,
            Duration::from_millis(999),
            Duration::from_millis(1500),
            Duration::from_secs(3601),
        ] {
            let mut cfg = enabled();
            cfg.api_keys.last_used_flush = bad;
            assert!(
                matches!(verdict(&cfg), Err(ConfigError::ApiKeysFlushInterval { .. })),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_messages_never_carry_the_pepper_or_a_scope() {
        let mut cfg = enabled();
        cfg.api_keys.scopes = vec!["secret-scope!".to_owned()];
        let scope_message = verdict(&cfg)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(scope_message.contains("api_keys.scopes[0]"));
        assert!(!scope_message.contains("secret-scope"));

        let mut cfg = enabled();
        cfg.jwt.secret = secret(PEPPER);
        let message = verdict(&cfg)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(!message.contains(PEPPER));
        assert!(!format!("{:?}", cfg.api_keys).contains(PEPPER));
    }

    #[test]
    fn an_empty_scope_list_message_names_the_list_not_an_entry() {
        let mut cfg = enabled();
        cfg.api_keys.scopes = Vec::new();
        let message = verdict(&cfg)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(message.starts_with("api_keys.scopes:"), "{message}");
    }
}

#[test]
fn the_config_can_be_built_from_its_default_and_cloned() {
    let group = ApiKeysConfig {
        prefix: "svc".to_owned(),
        ..ApiKeysConfig::default()
    };
    assert_eq!(group.clone().prefix, "svc");
}
