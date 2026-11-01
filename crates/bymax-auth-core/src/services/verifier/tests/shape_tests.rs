//! The claim-shape predicates and the one-time warning, without an engine.

use std::sync::atomic::{AtomicBool, Ordering};

use super::super::{is_bounded_id, is_uuid_v4, warn_unbound_once};

#[test]
fn only_a_canonical_uuid_v4_is_a_jti() {
    assert!(is_uuid_v4("3f0a1c2e-4b5d-4e6f-8a9b-0c1d2e3f4a5b"));
    assert!(is_uuid_v4("3F0A1C2E-4B5D-4E6F-BA9B-0C1D2E3F4A5B"));
    // Wrong version nibble, wrong variant nibble, wrong group widths, non-hex, empty.
    assert!(!is_uuid_v4("3f0a1c2e-4b5d-1e6f-8a9b-0c1d2e3f4a5b"));
    assert!(!is_uuid_v4("3f0a1c2e-4b5d-4e6f-0a9b-0c1d2e3f4a5b"));
    assert!(!is_uuid_v4("3f0a1c2e4b5d4e6f8a9b0c1d2e3f4a5b"));
    assert!(!is_uuid_v4("3f0a1c2e-4b5d-4e6f-8a9b-0c1d2e3f4a5g"));
    assert!(!is_uuid_v4(""));
}

#[test]
fn a_subject_is_bounded_by_characters_and_never_empty() {
    assert!(is_bounded_id("u1"));
    assert!(is_bounded_id(&"a".repeat(256)));
    assert!(!is_bounded_id(&"a".repeat(257)));
    assert!(!is_bounded_id(""));
    // Counted in characters, not bytes: 256 multi-byte characters are within the bound.
    assert!(is_bounded_id(&"é".repeat(256)));
}

#[test]
fn the_unbound_warning_is_logged_on_the_first_call_and_only_then() {
    let flag = AtomicBool::new(false);
    let (events, capture) = crate::log_capture::capture_events();
    let logged = || {
        events
            .iter()
            .iter()
            .filter(|e| e.rendered.contains("tenant binding is not applied"))
            .count()
    };
    warn_unbound_once(&flag);
    // Logged by the call that set the flag, not by a later one.
    assert_eq!(logged(), 1);
    assert!(flag.load(Ordering::Relaxed));
    warn_unbound_once(&flag);
    drop(capture);
    assert_eq!(logged(), 1);
}
