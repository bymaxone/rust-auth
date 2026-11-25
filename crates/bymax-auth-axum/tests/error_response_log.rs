//! What `error_response` logs when it answers an internal failure or an unavailable store.
//!
//! This is the only test in its binary on purpose. A `tracing` callsite caches whether any
//! subscriber wants it, and a scoped subscriber installed on one thread can lose a race with
//! another thread that reaches the same callsite first with no subscriber at all. Inside the
//! library's unit-test binary other tests call `error_response` concurrently, so a capture
//! asserted there is intermittently missing one of the two events. A binary that runs a single
//! test has no second thread to race with.

use bymax_auth_axum::error_response;
use bymax_auth_types::AuthError;

/// A subscriber that keeps every event's fields as text, so the test can read what was logged.
#[derive(Clone, Default)]
struct Captured(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl tracing::field::Visit for Captured {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if let Ok(mut lines) = self.0.lock() {
            lines.push(format!("{}={value:?}", field.name()));
        }
    }
}

impl tracing::Subscriber for Captured {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        event.record(&mut self.clone());
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn a_store_failure_and_an_internal_error_log_a_code_and_never_their_cause() {
    let captured = Captured::default();
    tracing::subscriber::with_default(captured.clone(), || {
        // A span drives the subscriber's span hooks, which the trait requires and events do not.
        let span = tracing::info_span!("answered", total = tracing::field::Empty);
        span.record("total", 3);
        span.follows_from(&span);
        let _entered = span.enter();
        let answered = [
            error_response(&AuthError::Internal("defect cause".into())),
            error_response(&AuthError::ServiceUnavailable("store cause".into())),
            error_response(&AuthError::TokenInvalid),
        ];
        assert_eq!(answered.len(), 3);
    });
    let lines = captured.0.lock().map(|l| l.clone()).unwrap_or_default();
    let has = |needle: &str| lines.iter().any(|l| l.contains(needle));
    // Each failure is named by its code and message; the cause a failure carries can hold a
    // store's own text, so it is never logged.
    assert!(
        has("RUST_AUTH_INTERNAL_ERROR") && has("RUST_AUTH_STORE_UNAVAILABLE"),
        "{lines:?}"
    );
    assert!(
        has("internal auth error") && has("auth store unavailable"),
        "{lines:?}"
    );
    assert!(!has("defect cause") && !has("store cause"), "{lines:?}");
    assert_eq!(lines.iter().filter(|l| l.starts_with("cause=")).count(), 0);
}
