//! What the OAuth callback writes to the log when the provider refuses.
//!
//! The provider chooses `error`, `error_description` and `error_uri`, so each is provider-controlled
//! text: read under the provider's own names, logged, and never allowed to carry a control
//! character into a line-oriented log pipeline. The events are captured by a subscriber local to
//! this file, because an assertion on a log line needs the line.

use std::cell::{Cell, RefCell};
use std::fmt::Debug;
use std::sync::Once;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

use super::*;

thread_local! {
    /// This thread's captured events, one rendered line each.
    static EVENTS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// Whether this thread is capturing, so a test that does not ask records nothing.
    static CAPTURING: Cell<bool> = const { Cell::new(false) };
}

/// Renders an event's fields as `name=value` pairs, the message included.
struct Fields(String);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.0.push_str(&format!("{}={:?}\n", field.name(), value));
    }
}

struct Capture;

impl Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        if CAPTURING.get() {
            let mut fields = Fields(String::new());
            event.record(&mut fields);
            EVENTS.with_borrow_mut(|events| events.push(fields.0));
        }
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

/// Installs the subscriber once for the test binary and starts capturing on this thread.
fn start_capture() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = tracing::subscriber::set_global_default(Capture);
    });
    EVENTS.with_borrow_mut(Vec::clear);
    CAPTURING.set(true);
}

/// The captured event that reports a provider refusal.
fn refusal_event() -> String {
    EVENTS.with_borrow(|events| {
        events
            .iter()
            .find(|line| line.contains("oauth callback carried a provider error"))
            .cloned()
            .unwrap_or_default()
    })
}

/// Sends a callback carrying `query` and returns the refusal event it logged.
async fn refused_callback(query: &str) -> String {
    let Some(h) = build(EngineSpec {
        oauth: true,
        allow_oauth: true,
        ..EngineSpec::default()
    }) else {
        return String::new();
    };
    let app = router(&h);
    start_capture();
    let res = Req::get(&format!("/auth/oauth/google/callback?{query}"))
        .send(&app)
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "for query {query}");
    refusal_event()
}

#[tokio::test]
async fn the_providers_error_fields_are_read_under_their_own_names_and_logged() {
    let event = refused_callback(
        "error=access_denied&error_description=try%20later&error_uri=https%3A%2F%2Fp.example%2Fdocs&state=deadbeef",
    )
    .await;
    assert!(event.contains("error=access_denied"), "{event:?}");
    assert!(event.contains("error_description=try later"), "{event:?}");
    assert!(
        event.contains("error_uri=https://p.example/docs"),
        "{event:?}"
    );
}

#[tokio::test]
async fn provider_text_with_a_control_character_never_reaches_the_log_raw() {
    // A line break forges a record, an escape sequence rewrites the terminal, and a carriage
    // return overwrites the line: each is provider-chosen and arrives in a field that is bounded
    // in length but carries no character rule of its own.
    let event = refused_callback(
        "error=%0AINFO%20forged&error_description=a%1B%5B2Jb&error_uri=u%0D%0Av&state=deadbeef",
    )
    .await;
    assert!(event.contains("error=<malformed>"), "{event:?}");
    assert!(event.contains("error_description=<malformed>"), "{event:?}");
    assert!(event.contains("error_uri=<malformed>"), "{event:?}");
    let control_in_values = event
        .lines()
        .flat_map(|line| line.split_once('=').map(|(_, value)| value))
        .any(|value| value.chars().any(char::is_control));
    assert!(!control_in_values, "{event:?}");
    assert!(!event.contains("INFO forged"), "{event:?}");
}

#[tokio::test]
async fn a_callback_without_the_optional_fields_logs_them_as_absent() {
    let event = refused_callback("state=deadbeef").await;
    assert!(event.contains("error=<absent>"), "{event:?}");
    assert!(event.contains("error_description=<absent>"), "{event:?}");
    assert!(event.contains("error_uri=<absent>"), "{event:?}");
}
