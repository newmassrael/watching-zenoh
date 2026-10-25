// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The loop a router that declared its CPU share closes on the lateness of its keepalive timers.
//!
//! The router admits sessions up to a bound it derives from a model and from what a keepalive
//! emission has cost it so far ([`wz_session_core::capacity::effective_max_sessions`]), and that
//! bound is an estimate: the cost is only known as it is paid, a host that was quiet when the
//! sessions came costs several times as much once it is loaded, and a share the host does not give
//! makes the number wrong however well the cost is read. What a lease depends on is not the
//! estimate but how late the keepalives are served, and this reads that, once a second, and
//! closes the loop on it ([`wz_session_core::capacity::AdmissionControl`]): a router in distress
//! closes the newest of its sessions, deep and at once, puts a ceiling on admission where it cut
//! so that they do not come straight back, and raises the ceiling again, as long as the
//! keepalives stay in time.
//!
//! ## Where it runs
//!
//! On a thread of its own, and neither in the router's loop nor on the control runtime. The loop
//! of a router that is short of CPU is run every few seconds, and a router whose keepalives are
//! late by most of a second each second does not have that long (the first form of this was a
//! step of the loop's monitor). The control runtime is one thread that serves every keepalive
//! timer, and a task of it waits its turn behind the timers that are late: it measured the same
//! two to three seconds. A thread that sleeps and wakes, and does a few microseconds of work, is
//! scheduled within the scheduler's own latency, which is what lets the reading be taken when it
//! is wanted. It sheds through [`crate::router_forward::ShedRegistry`], which holds no more of a
//! session than the handle that asks it to close.
//!
//! ## The order of a cut
//!
//! The sessions to close are chosen and marked, and their keepalives stop, before anything else is
//! done: that is a lock each, and the keepalives of the sessions being closed are the load the cut
//! is meant to take off. The closes themselves, a write each, are done on a thread of their own, so
//! that the loop goes on reading the node meanwhile (a thousand of them take ten seconds on a host
//! short of CPU, and a loop that waited them out read nothing for that long and then saw, in its
//! next reading, the lateness they had left, and cut again).

use std::sync::Arc;
use std::time::Duration;

use wz_session_core::capacity::{AdmissionControl, AdmissionStep};

use crate::accept_loop::SessionCeiling;
use crate::config::WzConfig;
use crate::keepalive_pacer::keepalive_timer_lateness_since_last_read;
use crate::router_forward::{ShedBatch, ShedRegistry};

/// How often the loop reads the node, in milliseconds. The lateness it reacts to grows by most of a
/// second each second, so it asks as often as is cheap.
pub const STEP_EVERY_MS: u64 = 1_000;

/// One reading of the node: what the loop is given, so that a test names it.
#[derive(Clone, Copy, Debug)]
pub struct Reading {
    /// Milliseconds on a clock that never goes back.
    pub now_ms: u64,
    /// The sessions held that are not on their way out.
    pub held: usize,
    /// The sessions the model admits now.
    pub bound: usize,
    /// The longest keepalive timer lateness since the previous reading, in milliseconds.
    pub recent_lateness_ms: u64,
    /// The lease the node's bounds are computed for, in milliseconds.
    pub lease_ms: u64,
}

/// One reading of the node and what was done about it.
pub fn govern_once(
    control: &mut AdmissionControl,
    reading: Reading,
    registry: &ShedRegistry,
    ceiling: &SessionCeiling,
) -> AdmissionStep {
    let Reading {
        now_ms,
        held,
        bound,
        recent_lateness_ms,
        lease_ms,
    } = reading;
    let step = control.step(now_ms, held, bound, recent_lateness_ms, lease_ms);
    ceiling.set_cap(step.cap);
    if let Some(keep) = step.keep {
        let batch = registry.begin_shed(keep);
        batch.stop_keepalives();
        let closed = batch.len();
        ceiling.note_shed(closed);
        log::warn!(
            "wz-ap-demo router-hat: holding {held} sessions with keepalive timers \
             {recent_lateness_ms} ms late, where the model admits {bound}: closing the newest \
             {closed} to keep {keep}, and admitting no more than that until they are in time \
             ({} closed so far)",
            registry.total()
        );
        close_in_the_background(batch);
    }
    step
}

/// Do the closes of a batch on a thread of their own, or here when no thread can be made, late
/// being better than never.
fn close_in_the_background(batch: ShedBatch) {
    // `spawn` takes the closure and drops it when it cannot make the thread, so the batch is put
    // where either side can take it.
    let slot = Arc::new(std::sync::Mutex::new(Some(batch)));
    let take = |slot: &std::sync::Mutex<Option<ShedBatch>>| {
        slot.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    };
    let handed = {
        let slot = Arc::clone(&slot);
        std::thread::Builder::new()
            .name("wz-capacity-close".into())
            .spawn(move || {
                if let Some(batch) = take(&slot) {
                    batch.close();
                }
            })
    };
    if handed.is_err() {
        if let Some(batch) = take(&slot) {
            batch.close();
        }
    }
}

/// Start the loop, on a thread of its own, for a router whose configuration is `config` (it reads
/// the lease and the model's bound from it, as the ceiling does), whose sessions are those of
/// `registry`, and whose admission `ceiling` is. The thread lives as long as the process.
pub fn spawn_capacity_control(
    config: WzConfig,
    registry: Arc<ShedRegistry>,
    ceiling: SessionCeiling,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("wz-capacity-control".into())
        .spawn(move || {
            let started = std::time::Instant::now();
            let mut control = AdmissionControl::new();
            // What was read before the first session cannot be about one.
            let _ = keepalive_timer_lateness_since_last_read();
            loop {
                std::thread::sleep(Duration::from_millis(STEP_EVERY_MS));
                let reading = Reading {
                    now_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    held: registry.live(),
                    bound: config.effective_max_sessions().limit,
                    recent_lateness_ms: keepalive_timer_lateness_since_last_read(),
                    lease_ms: config.effective_lease_ms(),
                };
                let step = govern_once(&mut control, reading, &registry, &ceiling);
                log::debug!(
                    "wz-capacity-control: t={} held={} bound={} late={} cap={:?} keep={:?}",
                    reading.now_ms,
                    reading.held,
                    reading.bound,
                    reading.recent_lateness_ms,
                    step.cap,
                    step.keep
                );
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEASE_MS: u64 = 10_000;

    /// The step is applied: the ceiling takes the control's cap, the sessions it names are closed
    /// and counted on the handle the capacity report reads, and a node that was out of distress
    /// has its ceiling lifted again.
    #[test]
    fn a_cut_caps_the_ceiling_and_counts_what_it_closed_and_calm_lifts_it() {
        let registry = ShedRegistry::default();
        let ceiling = SessionCeiling::new(|| 1_100);
        let mut control = AdmissionControl::new();
        assert_eq!(ceiling.get(), 1_100);
        let reading = |now_ms, held, recent_lateness_ms| Reading {
            now_ms,
            held,
            bound: 700,
            recent_lateness_ms,
            lease_ms: LEASE_MS,
        };
        // No sessions to close: only the ceiling is put.
        let step = govern_once(&mut control, reading(0, 800, 2_000), &registry, &ceiling);
        assert_eq!(step.keep, Some(100));
        assert_eq!(ceiling.get(), 100, "admission is capped where it cut");
        assert_eq!(ceiling.shed_over_capacity(), 0, "the registry held none");
        // Calm for an interval each: the ceiling doubles to the threshold (half of the 800 held),
        // adds an eighth after it, and is lifted when the model's 700 is the lower.
        for (at, expect) in [
            (3_400, 200),
            (6_800, 400),
            (10_200, 450),
            (13_600, 506),
            (17_000, 569),
            (20_400, 640),
            (23_800, 1_100),
        ] {
            govern_once(&mut control, reading(at, 100, 0), &registry, &ceiling);
            assert_eq!(ceiling.get(), expect, "at {at} ms");
        }
        assert_eq!(
            control.cap(),
            None,
            "past the model's 700 the ceiling is lifted"
        );
    }
}
