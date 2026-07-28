//! In-process capture of `tracing` events, for tests that assert the library actually reported
//! something.
//!
//! The security events this crate emits — a lockout, a rejected second factor, a replayed refresh
//! token, a cleanup the store refused — are, by construction, the *only* observable effect of
//! their branch: the call they guard is swallowed or the flow returns the same error either way.
//! Without a subscriber installed, `tracing::warn!` evaluates nothing, so those branches are
//! unreachable from a test and any condition inside them is unfalsifiable. That is not a
//! hypothetical: the mutation gate found `!matches!(error, SessionNotFound)` surviving with the
//! `!` deleted, which inverts *which* failures an operator is told about.
//!
//! nest-auth asserts its log lines through Jest spies for the same reason. This is the equivalent
//! seam, written against `tracing`'s own `Subscriber` trait so the crate takes no new dependency
//! — `tracing-subscriber` would be one, and it exists in this workspace only for the examples.
//!
//! # Why one global subscriber and not a per-test thread-local one
//!
//! `tracing` keeps the maximum enabled level as **process-global** state, and the macros consult
//! it before they ever reach a subscriber. A thread-local `set_default` raises that ceiling when
//! it is installed and lowers it again when its guard drops — so two tests capturing on two
//! threads race: one drops its guard while the other is still logging, the ceiling falls back to
//! `OFF`, and the second test's event is discarded before any subscriber sees it. That failure is
//! intermittent and reads exactly like "the code did not log", which is the assertion under test.
//!
//! So the subscriber is installed **once, globally**, and stays for the life of the test binary,
//! which pins the ceiling open. Isolation moves to where it is cheap: each thread gets its own
//! buffer, and capture is off until a test switches it on.

use std::cell::{Cell, RefCell};
use std::fmt::Debug;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

/// One captured event: its level and its rendered fields, message included.
#[derive(Clone, Debug)]
pub(crate) struct CapturedEvent {
    /// The event's level, so a test can distinguish "reported" from "reported as a warning".
    pub(crate) level: Level,
    /// Every field rendered as `name=value`, joined by spaces. The message rides along as
    /// `message=…`, which is how `tracing` models it.
    pub(crate) rendered: String,
}

/// The handle a test reads captured events back through.
///
/// Reads the calling thread's buffer, which only the calling thread writes.
#[derive(Clone, Copy, Default)]
pub(crate) struct CapturedEvents;

thread_local! {
    /// This thread's captured events. Retained after the guard drops, because a test asserts on
    /// the log *after* the code under test has finished running.
    static BUFFER: RefCell<Vec<CapturedEvent>> = const { RefCell::new(Vec::new()) };
    /// Whether this thread is currently capturing. Off until a test asks, so a test that never
    /// captures pays nothing and records nothing.
    static CAPTURING: Cell<bool> = const { Cell::new(false) };
}

impl CapturedEvents {
    /// Whether any captured event contains `needle` in its rendered fields.
    pub(crate) fn contains(&self, needle: &str) -> bool {
        self.iter().iter().any(|e| e.rendered.contains(needle))
    }

    /// Whether any captured event at `level` contains `needle`.
    pub(crate) fn contains_at(&self, level: Level, needle: &str) -> bool {
        self.iter()
            .iter()
            .any(|e| e.level == level && e.rendered.contains(needle))
    }

    /// A snapshot of everything captured on this thread so far.
    pub(crate) fn iter(&self) -> Vec<CapturedEvent> {
        BUFFER.with(|buffer| buffer.borrow().clone())
    }
}

/// Turns capture off for this thread when dropped.
///
/// What was captured is deliberately kept: the assertion comes after the code under test has run,
/// so a guard that also cleared the buffer would hand every test an empty log — indistinguishable
/// from the code never having logged, which is the thing being asserted.
pub(crate) struct CaptureGuard;

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        CAPTURING.with(|capturing| capturing.set(false));
    }
}

/// Begin capturing this thread's `tracing` events, returning the handle and the guard that stops
/// the capture.
///
/// The guard must be held for as long as the code under test runs — dropping it early stops the
/// capture, and the assertion then reads an empty log rather than a missing event. Nested calls
/// on one thread are not supported: the second would clear the first's buffer.
#[must_use]
pub(crate) fn capture_events() -> (CapturedEvents, CaptureGuard) {
    install_global_subscriber();
    // Cleared here rather than on drop, so one test never reads another's events.
    BUFFER.with(|buffer| buffer.borrow_mut().clear());
    CAPTURING.with(|capturing| capturing.set(true));
    (CapturedEvents, CaptureGuard)
}

/// Install the capturing subscriber process-wide, once.
///
/// An `Err` from `set_global_default` means something else claimed the slot first, which for this
/// binary can only be a second call racing this one — the `Once` makes that unreachable, and
/// ignoring it is still correct: the assertion that follows fails loudly rather than silently
/// passing.
fn install_global_subscriber() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let _ = tracing::subscriber::set_global_default(CapturingSubscriber);
    });
}

/// The minimum `Subscriber` that records events and ignores spans.
struct CapturingSubscriber;

impl Subscriber for CapturingSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        // Everything is enabled: a test that installs this wants the whole log, and the level
        // filtering a deployment applies is the deployment's business.
        true
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        // Spans are not captured; every span gets the same id because nothing reads it back.
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        // Rendering is skipped entirely unless this thread asked to capture, so the subscriber
        // being global costs the other tests nothing.
        if !CAPTURING.with(Cell::get) {
            return;
        }
        let mut visitor = FieldRenderer(String::new());
        event.record(&mut visitor);
        BUFFER.with(|buffer| {
            buffer.borrow_mut().push(CapturedEvent {
                level: *event.metadata().level(),
                rendered: visitor.0,
            });
        });
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

/// Renders every field of an event as `name=value`, space-separated.
struct FieldRenderer(String);

impl Visit for FieldRenderer {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        self.0.push_str(field.name());
        self.0.push('=');
        self.0.push_str(&format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        // Strings are rendered unquoted: an assertion reads `"login: account locked"` the way it
        // is written in the source, not with the escaping `Debug` would add.
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        self.0.push_str(field.name());
        self.0.push('=');
        self.0.push_str(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_level_message_and_fields() {
        let (events, guard) = capture_events();
        tracing::warn!(user_id = "u1", "something worth reporting");
        tracing::info!("routine");
        drop(guard);

        assert!(events.contains("something worth reporting"));
        assert!(events.contains("user_id=u1"));
        assert!(events.contains_at(Level::WARN, "something worth reporting"));
        // The level is part of the assertion surface: a warning demoted to a debug line is still
        // "logged" but no longer reaches an operator watching for warnings.
        assert!(!events.contains_at(Level::INFO, "something worth reporting"));
        assert!(events.contains_at(Level::INFO, "routine"));
        assert_eq!(events.iter().len(), 2);
    }

    #[test]
    fn stops_capturing_once_the_guard_is_dropped() {
        let (events, guard) = capture_events();
        tracing::warn!("before the guard drops");
        drop(guard);
        tracing::warn!("after the guard");
        // What was captured stays readable — that is the whole point of asserting after the
        // fact — but nothing new is recorded.
        assert!(events.contains("before the guard drops"));
        assert!(!events.contains("after the guard"));
        assert_eq!(events.iter().len(), 1);
    }

    #[test]
    fn a_second_capture_on_one_thread_starts_empty() {
        let (first, guard) = capture_events();
        tracing::warn!("from the first capture");
        drop(guard);
        assert!(first.contains("from the first capture"));

        let (second, guard) = capture_events();
        drop(guard);
        // Same thread, fresh capture: the earlier test's events must not leak into this one's
        // assertions, or a passing test could be reading someone else's log.
        assert!(!second.contains("from the first capture"));
        assert!(second.iter().is_empty());
    }

    #[test]
    fn spans_are_accepted_and_ignored() {
        // The crate does not instrument spans today, but a subscriber that panicked or mis-handled
        // one would break every test that captures the moment somebody adds `#[instrument]` — and
        // it would break it far from here. Driving the whole `Subscriber` surface keeps that
        // failure at this file instead.
        let (events, guard) = capture_events();
        let span = tracing::info_span!("outer", step = tracing::field::Empty);
        let other = tracing::info_span!("sibling");
        span.record("step", 1);
        span.follows_from(&other);
        {
            let _entered = span.enter();
            tracing::warn!("inside a span");
        }
        drop(guard);

        // The event is captured; the span itself contributes nothing, which is the contract.
        assert!(events.contains("inside a span"));
        assert_eq!(events.iter().len(), 1);
    }

    #[test]
    fn renders_non_string_fields_through_debug() {
        let (events, guard) = capture_events();
        tracing::warn!(count = 3, flag = true, "mixed");
        drop(guard);
        assert!(events.contains("count=3"));
        assert!(events.contains("flag=true"));
    }
}
