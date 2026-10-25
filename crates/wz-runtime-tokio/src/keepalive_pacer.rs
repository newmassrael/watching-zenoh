// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A backstop for the session FSM's keepalive worker that keeps KEEPALIVE
//! flowing while the drive loop cannot.
//!
//! The worker itself is the link's `keepalive_armed`, which the FSM's
//! `start_keepalive_worker` sets on `Established` entry and
//! `stop_keepalive_worker` clears on its exit. The drive loop emits while it
//! is set; this pacer is started only while it is set and ends when it is
//! cleared, so neither emitter outlives the duty the machine released.
//!
//! ## Why the loop alone is not enough
//!
//! [`crate::session_glue::drive_session_until_terminal`] emits KEEPALIVE itself,
//! from the deadline arm of its `select!`, and runs the application's callbacks
//! inline from the same task. A callback that blocks therefore stops the thread
//! that would have emitted the frame, and a peer whose lease is shorter than
//! the block drops the session. `park_on_drain` already keeps the emitter alive
//! while the loop waits on a slow consumer; it cannot help while a callback is
//! running, because nothing is polling the loop at all.
//!
//! zenoh-pico does not have this gap: its keep-alive task is a thread of its
//! own (`src/transport/unicast/lease.c`), so a blocked read task costs the
//! application its throughput, never its session. A blocked callback of a C
//! application on the serial drive is the same shape, and
//! `wz-capi-pico/tests/blocking_callback_keeps_session.rs` pins it.
//!
//! ## What this is, and is not
//!
//! The pacer wakes a little after the loop's own keepalive deadline and, if the
//! line is still idle, emits through the same
//! [`wz_session_core::drive::check_keepalive_deadline`] the loop uses. That function needs no engine and
//! takes the idleness from `last_outbound_at`, so the two emitters cannot send
//! twice for one idle window: whichever runs first re-stamps the window. The
//! slack is what makes the loop the normal emitter and this one the backstop; a
//! healthy session sees no frame from here.
//!
//! It does not check the PEER's lease. That check needs the engine, which only
//! the loop owns, and a loop that is blocked is not reading the peer either, so
//! there is nothing to expire until it runs again.
//!
//! ## Lifetime
//!
//! The pacer holds a [`Weak`] handle and never keeps an `Arc` across an await:
//! the writer's channel closes when the last `Arc<SessionLinkActions>` goes, and
//! a timer task that owned one would hold the session open. It belongs to ONE
//! establishment, named by the `established_at` stamp it started under, and
//! ends when the session is no longer that establishment: the machine left
//! `Established` (its exit stopped the keepalive worker), the link was torn
//! down, or the reconnect supervisor re-established it, which starts a pacer of
//! its own.
//!
//! It runs on [`WzRuntime::Control`], the subsystem that carries keepalive
//! timers and nothing else. It used to run on `Tx`, behind the data the link
//! writers were writing, and a router short of CPU woke its pacers seconds late
//! and let its peers' leases lapse (see `runtime_pool`, "The sixth subsystem").

use std::sync::{Arc, Weak};
use std::time::Duration;

use wz_runtime_core::{Runtime, TimeSource};
use wz_session_core::capacity::LatenessWindows;
use wz_session_core::drive::keepalive_wake_deadline;
use wz_session_core::lease::{KeepAliveCheckOutcome, LEASE_EXPIRE_FACTOR};

use crate::emission_cost::check_keepalive_timed;
use crate::runtime_impl::{TokioRuntime, TokioTime};
use crate::runtime_pool::WzRuntime;
use crate::session_glue::SessionLinkActions;

/// The backstop waits this fraction of the keepalive interval past the loop's
/// own deadline. A quarter leaves the peer most of its lease unspent (a 10 s
/// lease emits at 3.3 s, the backstop at 4.2 s) and is long enough that a loop
/// that is merely busy for a moment emits first.
const SLACK_DIVISOR: u64 = 4;

/// Start the backstop for the establishment `actions` is in now. Returns at
/// once; a session whose keepalive worker is not running has nothing to pace.
pub(crate) fn spawn_keepalive_pacer(actions: &Arc<SessionLinkActions>, clock: TokioTime) {
    if !TokioRuntime::with_mutex_mut(&actions.link.keepalive_armed, |armed| *armed) {
        return;
    }
    let Some(generation) = established_at(actions) else {
        return;
    };
    let weak = Arc::downgrade(actions);
    drop(WzRuntime::Control.spawn(pace(weak, clock, generation)));
}

fn established_at(actions: &SessionLinkActions) -> Option<u64> {
    TokioRuntime::with_mutex_mut(&actions.link.established_at, |slot| *slot)
}

/// How long the pacer sleeps next, or `None` when this establishment is over.
/// Emits first when the backstop time has already passed.
fn step(weak: &Weak<SessionLinkActions>, clock: &TokioTime, generation: u64) -> Option<u64> {
    loop {
        let actions = weak.upgrade()?;
        if established_at(&actions) != Some(generation) {
            return None;
        }
        let now = clock.now_monotonic_ms();
        // `None` once the FSM's exit from Established stopped the worker.
        let due = keepalive_wake_deadline(&actions)?;
        let slack = (actions.adopted_lease_ms() / LEASE_EXPIRE_FACTOR / SLACK_DIVISOR).max(1);
        let backstop = due.saturating_add(slack);
        if now < backstop {
            return Some(backstop - now);
        }
        // Past the backstop, so `now >= due` and the check either emits or
        // finds the transport gone; it cannot answer `WithinInterval`.
        if check_keepalive_timed(&actions, now) == KeepAliveCheckOutcome::Inactive {
            return None;
        }
    }
}

/// Whether the session this pacer belongs to still has its keepalive worker running. One whose
/// worker was stopped from outside (a session the node is closing for capacity) has its pacer wake
/// once more at the time it had set, and end; that wake is not a keepalive timer being served, and
/// how late it is says how late the thread was before the session was cut, which the control that
/// reads the lateness would take, an interval after its cut, for the cut not having worked.
fn worker_runs(weak: &Weak<SessionLinkActions>) -> bool {
    weak.upgrade().is_some_and(|actions| {
        TokioRuntime::with_mutex_mut(&actions.link.keepalive_armed, |armed| *armed)
    })
}

async fn pace(weak: Weak<SessionLinkActions>, clock: TokioTime, generation: u64) {
    while let Some(wait_ms) = step(&weak, &clock, generation) {
        let planned = clock.now_monotonic_ms().saturating_add(wait_ms);
        tokio::time::sleep(Duration::from_millis(wait_ms)).await;
        if worker_runs(&weak) {
            note_wake_lateness(clock.now_monotonic_ms().saturating_sub(planned));
        }
    }
}

/// How late the pacers of this process woke, per window of time
/// ([`wz_session_core::capacity::LatenessWindows`]). Behind a lock the pacers take once per wake and a
/// reader takes once per look, which is a few hundred a second on a router and costs nothing next
/// to the emission a wake makes.
static WAKE_LATENESS: std::sync::Mutex<LatenessWindows> =
    std::sync::Mutex::new(LatenessWindows::new());

/// Milliseconds on a clock of this process that every record and every read shares: the sessions'
/// own clocks are theirs, and a window needs one that does not depend on which session woke.
fn lateness_clock_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    u64::try_from(
        START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

/// The longest wake lateness since [`keepalive_timer_lateness_since_last_read`] was last called.
static WAKE_LATENESS_RECENT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The longest a keepalive timer of this process was served late since the last call of this
/// function, in milliseconds, and the reading starts again from nothing.
///
/// For the one reader that closes a loop on it (`crate::capacity_control`): the windows of
/// [`keepalive_timer_lateness`] answer how late the timers were in the last ten seconds or the
/// last minute, and a loop that read them would still see a spike seconds after the cut that
/// ended it. A second reader would take from the first what it had not read.
pub fn keepalive_timer_lateness_since_last_read() -> u64 {
    WAKE_LATENESS_RECENT.swap(0, std::sync::atomic::Ordering::Relaxed)
}

fn note_wake_lateness(late_ms: u64) {
    WAKE_LATENESS_RECENT.fetch_max(late_ms, std::sync::atomic::Ordering::Relaxed);
    let now_ms = lateness_clock_ms();
    // A poisoned lock means a panic while holding two integers; the figures are still integers.
    let mut windows = WAKE_LATENESS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    windows.record(now_ms, late_ms);
}

/// How late the keepalive timers of this process were served, in three readings
/// ([`wz_session_core::capacity::LatenessWindows`]), in milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeepaliveLateness {
    /// The longest in the current ten-second window.
    pub current_ms: u64,
    /// The longest in the last minute, the current window included.
    pub last_minute_ms: u64,
    /// The longest since the process started.
    pub since_start_ms: u64,
}

/// The lateness of the keepalive timers now, per window: the reading a monitor and an admission
/// rule need, where [`keepalive_timer_lateness_max_ms`] can only say what the worst was.
pub fn keepalive_timer_lateness() -> KeepaliveLateness {
    let now_ms = lateness_clock_ms();
    let windows = WAKE_LATENESS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    KeepaliveLateness {
        current_ms: windows.current(now_ms),
        last_minute_ms: windows.last_minute(now_ms),
        since_start_ms: windows.since_start(),
    }
}

/// The longest a keepalive timer of this process was served after its time, in milliseconds,
/// since the process started: the quantity the lease depends on, read where it is made. A
/// session is lost when a keepalive is later than `2T/3`
/// ([`wz_session_core::capacity::keepalive_lateness_limit_ms`]), whatever the share of the CPU
/// the operator declared and however many sessions the node holds, so this is both the
/// assertion of the capacity promise and the monitor that tells an operator the promise no
/// longer holds. The control runtime's timers are served on one thread, so it is the lateness of
/// the thread's own wake, which on a host short of CPU is its wait for a core
/// (`docs/router-data-plane-scaling.md` section 7.4).
pub fn keepalive_timer_lateness_max_ms() -> u64 {
    keepalive_timer_lateness().since_start_ms
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two readings are one meter: what a wake records is what both functions say, and a
    /// window never reads below the maximum it holds.
    #[test]
    fn a_wake_is_read_by_the_windows_and_by_the_process_maximum() {
        let before = keepalive_timer_lateness();
        // Later than anything another test of this process recorded.
        let late = before.since_start_ms + 1_000;
        note_wake_lateness(late);
        let after = keepalive_timer_lateness();
        // Another test of this process may record a longer one meanwhile, never a shorter.
        assert!(after.since_start_ms >= late);
        assert!(keepalive_timer_lateness_max_ms() >= late);
        assert!(after.current_ms >= late || after.last_minute_ms >= late);
        assert!(after.last_minute_ms >= after.current_ms);
        assert!(after.since_start_ms >= after.last_minute_ms);
    }
}
