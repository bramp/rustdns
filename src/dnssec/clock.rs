//! Monotonic clocks used for DNSSEC cache expiry and deadlines.

use std::fmt::Debug;
use std::time::{Duration, Instant};

/// Monotonic time source used for DNSSEC cache expiry and validation deadlines.
pub trait Clock: Debug + Send + Sync + 'static {
    /// Monotonic instant measured by this clock.
    type Instant: Copy + Ord + Debug + Send + Sync + 'static;

    /// Returns the current monotonic instant, or `None` if the clock is unavailable.
    fn now(&self) -> Option<Self::Instant>;

    /// Adds `duration` to `instant`, returning `None` if the result overflows.
    fn checked_add(&self, instant: Self::Instant, duration: Duration) -> Option<Self::Instant>;

    /// Returns the elapsed duration when `later` is at or after `earlier`.
    fn checked_duration_since(
        &self,
        later: Self::Instant,
        earlier: Self::Instant,
    ) -> Option<Duration>;
}

/// Monotonic clock backed by [`std::time::Instant`] where the target supports it.
///
/// On `wasm32-unknown-unknown`, [`Clock::now`] returns `None`; browser callers
/// should provide a clock backed by the browser's monotonic performance timer.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    type Instant = Instant;

    fn now(&self) -> Option<Self::Instant> {
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            None
        }
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            Some(Instant::now())
        }
    }

    fn checked_add(&self, instant: Self::Instant, duration: Duration) -> Option<Self::Instant> {
        instant.checked_add(duration)
    }

    fn checked_duration_since(
        &self,
        later: Self::Instant,
        earlier: Self::Instant,
    ) -> Option<Duration> {
        later.checked_duration_since(earlier)
    }
}
