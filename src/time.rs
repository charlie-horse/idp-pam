//! Time sources, injectable for tests.

use std::time::{Duration, SystemTime};

/// Wall-clock source. `Send + Sync` because openidconnect's time hooks
/// (`set_time_fn`) require `Send + Sync` closures; test clocks should use
/// atomics or a `Mutex` rather than `Cell`.
pub trait Clock: Send + Sync {
    /// The current time.
    fn now(&self) -> SystemTime;
}

/// Blocking sleep, used between device-token polls.
pub trait Sleeper {
    /// Sleeps for `d` (a test sleeper usually advances its clock instead).
    fn sleep(&self, d: Duration);
}

/// The real clock: [`SystemTime::now`].
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// The real sleeper: [`std::thread::sleep`] on the calling thread (no threads are spawned).
#[derive(Clone, Copy, Debug, Default)]
pub struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

#[cfg(test)]
#[path = "tests/time_tests.rs"]
mod tests;
