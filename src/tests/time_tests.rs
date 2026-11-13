#[allow(unused_imports)]
use super::*;

use std::time::Instant;

#[test]
fn system_clock_reads_the_wall_clock() {
    let before = SystemTime::now();
    let now = SystemClock.now();
    let after = SystemTime::now();
    assert!(before <= now && now <= after);
}

#[test]
fn system_clock_is_usable_as_a_shared_trait_object() {
    fn assert_send_sync<T: Send + Sync + ?Sized>(_: &T) {}
    let clock: &dyn Clock = &SystemClock;
    assert_send_sync(clock);
    assert!(clock.now() > SystemTime::UNIX_EPOCH);
}

#[test]
fn thread_sleeper_sleeps_at_least_the_requested_time() {
    let d = Duration::from_millis(20);
    let start = Instant::now();
    let sleeper: &dyn Sleeper = &ThreadSleeper;
    sleeper.sleep(d);
    assert!(start.elapsed() >= d);
}

#[test]
fn thread_sleeper_zero_returns() {
    ThreadSleeper.sleep(Duration::ZERO);
}
