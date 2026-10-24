// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What one keepalive emission costs on the host this node runs on, read where it is paid.
//!
//! The capacity bound ([`wz_session_core::capacity::liveness_bound`]) divides the CPU a node was
//! promised by the cost of one emission, and the cost it first used was the one read on the build
//! host ([`wz_session_core::capacity::RECORDED_HOST_MODEL`]). A hosted CI runner serves the same
//! router about four times slower per message, and the sessions admitted at the recorded cost lost
//! their leases there: a constant read on one machine is not a promise about another. This meter
//! is the node's own reading of the figure the bound needs.
//!
//! Every emission of the process, from the session loop or from the pacer, is timed by
//! [`check_keepalive_timed`], which keeps the last [`WINDOW`] durations, and the first sessions
//! of a process make one on purpose ([`calibrate_on_establishment`]) so that the figure exists
//! before the first one falls due. [`keepalive_emission_cost_median_ns`] is their median once
//! [`MIN_SAMPLES`] have been taken, and `None` before, so a node that has emitted nothing yet is
//! bounded by the recorded model alone. The capacity model gives a median the room the recorded
//! cost has over its own median ([`wz_session_core::capacity::MEDIAN_HEADROOM_PERCENT`]) before
//! it compares them, and a window rather than a running mean keeps a burst of preempted emissions
//! from fixing the figure for the process's life.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use wz_session_core::drive::check_keepalive_deadline;
use wz_session_core::lease::KeepAliveCheckOutcome;

use crate::session_glue::SessionLinkActions;

/// How many of the latest emissions the median is taken over.
const WINDOW: usize = 256;

/// The fewest emissions a median is read from. Below it the figure is one session's few emissions,
/// not the host's, and the recorded model stands.
const MIN_SAMPLES: usize = 64;

/// A fixed window of the latest durations, written without a lock by whichever thread emits.
struct Meter {
    ring: [AtomicU64; WINDOW],
    /// Emissions recorded since the process started; the next one lands in slot `written % WINDOW`.
    written: AtomicUsize,
}

impl Meter {
    const fn new() -> Self {
        Self {
            ring: [const { AtomicU64::new(0) }; WINDOW],
            written: AtomicUsize::new(0),
        }
    }

    /// Whether fewer than [`MIN_SAMPLES`] emissions were recorded, so that a median cannot be read.
    fn wants_samples(&self) -> bool {
        self.written.load(Ordering::Relaxed) < MIN_SAMPLES
    }

    fn record(&self, ns: u64) {
        let slot = self.written.fetch_add(1, Ordering::Relaxed) % WINDOW;
        self.ring[slot].store(ns, Ordering::Relaxed);
    }

    /// The median of the window, or `None` while fewer than [`MIN_SAMPLES`] were recorded. A slot
    /// being overwritten while this reads gives either its old or its new duration, and both are
    /// real emissions.
    fn median_ns(&self) -> Option<u64> {
        let held = self.written.load(Ordering::Relaxed).min(WINDOW);
        if held < MIN_SAMPLES {
            return None;
        }
        let mut seen: Vec<u64> = self.ring[..held]
            .iter()
            .map(|slot| slot.load(Ordering::Relaxed))
            .collect();
        seen.sort_unstable();
        seen.get(held / 2).copied()
    }
}

static METER: Meter = Meter::new();

/// The emission a session makes the moment it is established, while the process has not yet timed
/// [`MIN_SAMPLES`] of them: one KeepAlive, timed.
///
/// Without it the first real emission of a session is a third of a lease after it is established
/// (3.3 s at a 10 s lease), and a burst of peers that arrives in that time is admitted on the
/// recorded cost alone, on a host that may charge four times it. A KeepAlive is legal at any time
/// after the open, and costs the peer one small frame; the first [`MIN_SAMPLES`] sessions of a
/// process pay it, and the figure the bound is calibrated with then exists before the burst is
/// over. It is the same call a due emission makes ([`SessionLinkActions::send_keep_alive`]), so
/// the cost it reads is the cost the bound is about.
pub(crate) fn calibrate_on_establishment(actions: &SessionLinkActions) {
    if !METER.wants_samples() {
        return;
    }
    let started = Instant::now();
    actions.send_keep_alive();
    METER.record(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
}

/// [`check_keepalive_deadline`], timing the emission when it emits. The one call every emitter of
/// the runtime makes, so that the loop's emissions and the pacer's are one population.
pub(crate) fn check_keepalive_timed(
    actions: &SessionLinkActions,
    now_ms: u64,
) -> KeepAliveCheckOutcome {
    let started = Instant::now();
    let outcome = check_keepalive_deadline(actions, now_ms);
    if outcome == KeepAliveCheckOutcome::Emitted {
        METER.record(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
    outcome
}

/// The median cost of one keepalive emission of this process, in nanoseconds, over its latest
/// [`WINDOW`] emissions; `None` until [`MIN_SAMPLES`] were taken. Read by the capacity bound
/// ([`crate::config::WzConfig::effective_max_sessions`]) and by an operator who wants to see what
/// the host charges.
pub fn keepalive_emission_cost_median_ns() -> Option<u64> {
    METER.median_ns()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_median_is_read_before_enough_emissions_were_timed() {
        let meter = Meter::new();
        for _ in 0..MIN_SAMPLES - 1 {
            meter.record(40_000);
        }
        assert_eq!(meter.median_ns(), None);
        meter.record(40_000);
        assert_eq!(meter.median_ns(), Some(40_000));
    }

    #[test]
    fn a_meter_wants_samples_until_it_can_read_a_median() {
        let meter = Meter::new();
        for _ in 0..MIN_SAMPLES - 1 {
            assert!(meter.wants_samples());
            meter.record(1);
        }
        assert!(meter.wants_samples());
        meter.record(1);
        assert!(
            !meter.wants_samples(),
            "from here emissions are timed as they fall due"
        );
    }

    #[test]
    fn a_burst_of_preempted_emissions_does_not_move_the_median() {
        let meter = Meter::new();
        for _ in 0..200 {
            meter.record(8_000);
        }
        for _ in 0..40 {
            meter.record(900_000);
        }
        assert_eq!(meter.median_ns(), Some(8_000));
    }

    #[test]
    fn the_window_forgets_what_it_is_older_than() {
        let meter = Meter::new();
        for _ in 0..WINDOW {
            meter.record(8_000);
        }
        for _ in 0..WINDOW {
            meter.record(40_000);
        }
        assert_eq!(
            meter.median_ns(),
            Some(40_000),
            "a host that became slower is read as slower"
        );
    }
}
