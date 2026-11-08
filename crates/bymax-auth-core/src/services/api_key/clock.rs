//! The time source of the API-key features, injectable so expiry, rotation and last-used tests
//! never depend on the wall clock.

use time::OffsetDateTime;

/// The current instant, as the API-key features see it.
pub trait ApiKeyClock: Send + Sync {
    /// The current instant.
    fn now(&self) -> OffsetDateTime;
}

/// The wall clock. The default when the host supplies no clock of its own.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemApiKeyClock;

impl ApiKeyClock for SystemApiKeyClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}
