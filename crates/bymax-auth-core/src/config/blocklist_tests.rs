//! The startup bounds on `password.blocklist`, which nest-auth leaves unbounded: an entry that
//! reduces to nothing would refuse every password, and an unbounded list is an unbounded set
//! built at startup from deployment input.

use super::{AuthConfig, Environment};
use crate::error::ConfigError;
use crate::services::auth::test_support::base_config;

fn with(blocklist: Vec<String>) -> AuthConfig {
    let mut cfg = base_config();
    cfg.password.blocklist = blocklist;
    cfg
}

fn verdict(cfg: &AuthConfig) -> Result<bool, ConfigError> {
    cfg.validate(Environment::Test)
}

#[test]
fn the_default_blocklist_is_empty_and_valid() {
    assert!(base_config().password.blocklist.is_empty());
    assert!(verdict(&base_config()).is_ok());
}

#[test]
fn a_reasonable_list_is_accepted() {
    let cfg = with(vec!["Acme".to_owned(), "acme-corp".to_owned()]);
    assert!(verdict(&cfg).is_ok());
}

#[test]
fn an_entry_that_reduces_to_nothing_is_refused_with_its_position() {
    // Entries are reduced like a candidate: lowercased, leet undone, trailing digits dropped, so
    // "1234" and "   " both reduce to nothing and would refuse every password that reduces so.
    for empty in ["", "   ", "1234", "!@#"] {
        let cfg = with(vec!["Acme".to_owned(), empty.to_owned()]);
        let refused = verdict(&cfg);
        assert!(
            matches!(
                refused,
                Err(ConfigError::PasswordBlocklistEntry { index: 1, .. })
            ),
            "{empty:?}: {refused:?}"
        );
    }
}

#[test]
fn an_entry_longer_than_the_bound_is_refused() {
    let fits = with(vec!["a".repeat(128)]);
    assert!(verdict(&fits).is_ok());
    let too_long = with(vec!["ok".to_owned(), "a".repeat(129)]);
    assert!(matches!(
        verdict(&too_long),
        Err(ConfigError::PasswordBlocklistEntry { index: 1, .. })
    ));
}

#[test]
fn a_list_longer_than_the_bound_is_refused() {
    let words = |count: usize| (0..count).map(|n| format!("word{n}x")).collect::<Vec<_>>();
    assert!(verdict(&with(words(10_000))).is_ok());
    let refused = verdict(&with(words(10_001)));
    assert!(
        matches!(
            refused,
            Err(ConfigError::PasswordBlocklistSize { got: 10_001 })
        ),
        "{refused:?}"
    );
}
