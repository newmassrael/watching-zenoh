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
//! [`check_keepalive_deadline`] the loop uses. That function needs no engine and
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
//! It runs on [`WzRuntime::Tx`], the subsystem whose threads never run
//! application callbacks.

use std::sync::{Arc, Weak};
use std::time::Duration;

use wz_runtime_core::{Runtime, TimeSource};
use wz_session_core::drive::{check_keepalive_deadline, keepalive_wake_deadline};
use wz_session_core::lease::{KeepAliveCheckOutcome, LEASE_EXPIRE_FACTOR};

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
    drop(WzRuntime::Tx.spawn(pace(weak, clock, generation)));
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
        if check_keepalive_deadline(&actions, now) == KeepAliveCheckOutcome::Inactive {
            return None;
        }
    }
}

async fn pace(weak: Weak<SessionLinkActions>, clock: TokioTime, generation: u64) {
    while let Some(wait_ms) = step(&weak, &clock, generation) {
        tokio::time::sleep(Duration::from_millis(wait_ms)).await;
    }
}
