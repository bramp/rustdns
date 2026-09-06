use rand::RngExt;
use std::time::Duration;

/// Delay strategy applied between retries against the same upstream.
///
/// Combines the delay curve and jitter into one policy rather than layering a
/// generic jitter ratio on top of an arbitrary curve, since named backoff
/// algorithms (see AWS's "Exponential Backoff And Jitter") define both
/// together; [`Backoff::DecorrelatedJitter`] in particular cannot be expressed
/// as a curve plus a separate multiplicative jitter step.
///
/// `attempt` in each variant's formula is the 1-based index of the retry
/// about to be attempted (the first retry, after the initial attempt, is 1).
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum Backoff {
    /// No delay between retries.
    None,

    /// The same delay before every retry.
    Constant(Duration),

    /// `base * attempt`.
    Linear {
        /// Delay added for each retry.
        base: Duration,
    },

    /// `min(max, base * factor.powi(attempt - 1))`.
    Exponential {
        /// Delay before the first retry.
        base: Duration,
        /// Multiplier applied for each subsequent retry.
        factor: f64,
        /// Upper bound on the computed delay.
        max: Duration,
    },

    /// Exponential backoff with "Full Jitter": a uniform random delay between
    /// `0` and `min(max, base * factor.powi(attempt - 1))`.
    ExponentialFullJitter {
        /// Delay before the first retry.
        base: Duration,
        /// Multiplier applied for each subsequent retry.
        factor: f64,
        /// Upper bound on the computed delay.
        max: Duration,
    },

    /// "Decorrelated Jitter": a uniform random delay between `base` and
    /// `min(max, previous * 3)`, where `previous` is the delay returned for
    /// the prior retry against this upstream (or `base` before the first retry).
    DecorrelatedJitter {
        /// Minimum delay, and the lower bound for every retry.
        base: Duration,
        /// Upper bound on the computed delay.
        max: Duration,
    },
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff::ExponentialFullJitter {
            base: Duration::from_millis(200),
            factor: 2.0,
            max: Duration::from_secs(2),
        }
    }
}

impl Backoff {
    /// Returns the delay before retry number `attempt`.
    ///
    /// `previous` is the delay this method returned for the prior retry
    /// against the same upstream, or [`Duration::ZERO`] before the first
    /// retry. Only [`Backoff::DecorrelatedJitter`] uses it.
    pub(crate) fn next_delay(&self, attempt: u32, previous: Duration) -> Duration {
        let attempt = attempt.max(1);
        match *self {
            Backoff::None => Duration::ZERO,
            Backoff::Constant(delay) => delay,
            Backoff::Linear { base } => base.saturating_mul(attempt),
            Backoff::Exponential { base, factor, max } => {
                exponential_delay(base, factor, max, attempt)
            }
            Backoff::ExponentialFullJitter { base, factor, max } => {
                let cap = exponential_delay(base, factor, max, attempt);
                Duration::from_millis(rand::rng().random_range(0..=cap.as_millis() as u64))
            }
            Backoff::DecorrelatedJitter { base, max } => {
                let lower = base.as_millis() as u64;
                let previous_ms = previous.as_millis() as u64;
                let upper = previous_ms
                    .max(lower)
                    .saturating_mul(3)
                    .min(max.as_millis() as u64)
                    .max(lower);
                Duration::from_millis(rand::rng().random_range(lower..=upper))
            }
        }
    }
}

/// `min(max, base * factor.powi(attempt - 1))`.
fn exponential_delay(base: Duration, factor: f64, max: Duration, attempt: u32) -> Duration {
    let scale = factor.max(1.0).powi(attempt.saturating_sub(1) as i32);
    let millis = (base.as_millis() as f64 * scale).min(max.as_millis() as f64);
    Duration::from_millis(millis as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_none_has_no_delay() {
        assert_eq!(Backoff::None.next_delay(1, Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn backoff_constant_ignores_attempt() {
        let backoff = Backoff::Constant(Duration::from_millis(50));
        assert_eq!(backoff.next_delay(1, Duration::ZERO), Duration::from_millis(50));
        assert_eq!(backoff.next_delay(5, Duration::ZERO), Duration::from_millis(50));
    }

    #[test]
    fn backoff_linear_scales_with_attempt() {
        let backoff = Backoff::Linear {
            base: Duration::from_millis(100),
        };
        assert_eq!(backoff.next_delay(1, Duration::ZERO), Duration::from_millis(100));
        assert_eq!(backoff.next_delay(3, Duration::ZERO), Duration::from_millis(300));
    }

    #[test]
    fn backoff_exponential_doubles_and_caps() {
        let backoff = Backoff::Exponential {
            base: Duration::from_millis(100),
            factor: 2.0,
            max: Duration::from_millis(350),
        };
        assert_eq!(backoff.next_delay(1, Duration::ZERO), Duration::from_millis(100));
        assert_eq!(backoff.next_delay(2, Duration::ZERO), Duration::from_millis(200));
        assert_eq!(backoff.next_delay(3, Duration::ZERO), Duration::from_millis(350)); // Would be 400, capped.
    }

    #[test]
    fn backoff_exponential_full_jitter_stays_within_bounds() {
        let backoff = Backoff::ExponentialFullJitter {
            base: Duration::from_millis(100),
            factor: 2.0,
            max: Duration::from_millis(350),
        };
        for _ in 0..100 {
            let delay = backoff.next_delay(3, Duration::ZERO);
            assert!(delay <= Duration::from_millis(350), "{delay:?} exceeded cap");
        }
    }

    #[test]
    fn backoff_decorrelated_jitter_stays_within_bounds() {
        let backoff = Backoff::DecorrelatedJitter {
            base: Duration::from_millis(100),
            max: Duration::from_millis(500),
        };
        let mut previous = Duration::ZERO;
        for attempt in 1..=10 {
            let delay = backoff.next_delay(attempt, previous);
            assert!(delay >= Duration::from_millis(100), "{delay:?} below base");
            assert!(delay <= Duration::from_millis(500), "{delay:?} exceeded cap");
            previous = delay;
        }
    }
}
