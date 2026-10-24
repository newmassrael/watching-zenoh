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
//! [`check_keepalive_timed`], which keeps the last [`WINDOW`] durations, and a host that wants the
//! figure before the first session may seed it with [`calibrate_with_probe`]. A KeepAlive sent
//! at the moment of establishment would seed it too, and is wrong (see the probe's doc).
//! [`keepalive_emission_cost_floor_ns`] is the lower decile of
//! them once [`MIN_SAMPLES`] have been taken, and `None` before, so a node that has emitted
//! nothing yet is bounded by the recorded model alone. It is the lower decile and not the median
//! because a duration also holds how long the thread waited for a core, which the declared share
//! already accounts for: on the build host under 32 hogs the median swings between 4 and 12 us
//! with the load of the moment and the lower decile stays within 3 and 6 after the first seconds.
//! The capacity model gives the floor the room the recorded cost has over its own floor
//! ([`wz_session_core::capacity::FLOOR_HEADROOM_PERCENT`]) before it compares them, and a window
//! rather than a running mean keeps a burst of preempted emissions from fixing the figure for the
//! process's life.

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

    fn record(&self, ns: u64) {
        let slot = self.written.fetch_add(1, Ordering::Relaxed) % WINDOW;
        self.ring[slot].store(ns, Ordering::Relaxed);
    }

    /// The duration `per_mille` thousandths of the way up the sorted window (500 is the median),
    /// or `None` while fewer than [`MIN_SAMPLES`] were recorded. A slot being overwritten while
    /// this reads gives either its old or its new duration, and both are real emissions.
    fn percentile_ns(&self, per_mille: usize) -> Option<u64> {
        let held = self.written.load(Ordering::Relaxed).min(WINDOW);
        if held < MIN_SAMPLES {
            return None;
        }
        let mut seen: Vec<u64> = self.ring[..held]
            .iter()
            .map(|slot| slot.load(Ordering::Relaxed))
            .collect();
        seen.sort_unstable();
        seen.get(held * per_mille / 1000).copied()
    }

    fn median_ns(&self) -> Option<u64> {
        self.percentile_ns(500)
    }

    /// The lower decile: what an emission costs when nothing interrupts it.
    fn floor_ns(&self) -> Option<u64> {
        self.percentile_ns(100)
    }
}

static METER: Meter = Meter::new();

/// How many small frames [`calibrate_with_probe`] writes: more than [`MIN_SAMPLES`], so that the
/// figure it leaves is readable at once, and fewer than [`WINDOW`], so that the node's own
/// emissions replace it as they are timed.
const PROBE_FRAMES: usize = 128;

/// The size of a probe frame: the 2-byte length prefix of the stream framing and the one byte of
/// a KeepAlive, which is what an emission writes.
const PROBE_FRAME: [u8; 3] = [1, 0, 0x04];

/// Time [`PROBE_FRAMES`] KeepAlive-sized writes on a private loopback socket, and keep them as the
/// first samples of the meter, so that the figure the capacity bound is calibrated with exists
/// before the first session does.
///
/// A node that waits for its own emissions has none until a session is a third of a lease old
/// (3.3 s at a 10 s lease), and a burst of peers that arrives in that time is admitted on the
/// recorded cost alone, on a host that may charge four times it. The obvious way to have one at
/// once, a KeepAlive sent the moment a session is established, is wrong and was measured to be: on
/// a lowlatency link the stream length prefix changes width (2 to 4 bytes) after the open returns,
/// so a frame written inside the open is read by the peer as garbage and the link is lost
/// (`lowlatency_e2e`). The probe touches no peer: it writes to its own socket pair, so it cannot
/// be a frame on anyone's wire, and what it times is the dominant cost of an emission, a small
/// write to a stream socket. Called by a host before it accepts sessions; a host that does not
/// call it has the node's own emissions only, which is also correct, only later.
///
/// Returns how many frames were timed; `0` when the socket pair could not be made, in which case
/// the recorded model stands.
// LINK-SOCKET-SEAM-NOT-APPLICABLE: a private loopback pair this function makes and drops, not a
// link: it carries no locator, so no `iface`, `bind`, `dscp` or buffer option has a socket here
// to apply to, and applying one would change what the probe measures.
pub fn calibrate_with_probe() -> usize {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
        return 0;
    };
    let Ok(addr) = listener.local_addr() else {
        return 0;
    };
    let Ok(mut writer) = TcpStream::connect(addr) else {
        return 0;
    };
    let Ok((mut reader, _)) = listener.accept() else {
        return 0;
    };
    // Frames go out as they are written, as an emission's do.
    let _ = writer.set_nodelay(true);
    // Drained as it arrives, so that the writes are never waiting on a full buffer.
    let drain = std::thread::spawn(move || {
        let mut sink = [0u8; 512];
        while matches!(reader.read(&mut sink), Ok(n) if n > 0) {}
    });
    let mut timed = 0;
    for _ in 0..PROBE_FRAMES {
        let started = Instant::now();
        if writer.write_all(&PROBE_FRAME).is_err() {
            break;
        }
        METER.record(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
        timed += 1;
    }
    drop(writer);
    let _ = drain.join();
    timed
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
/// 256 emissions; `None` until 64 were taken. For an operator who wants to see what the host
/// charges; the capacity bound reads [`keepalive_emission_cost_floor_ns`].
pub fn keepalive_emission_cost_median_ns() -> Option<u64> {
    METER.median_ns()
}

/// The lower decile of the same window, in nanoseconds: what one emission costs when nothing
/// interrupts it. Read by the capacity bound
/// ([`crate::config::WzConfig::effective_max_sessions`]).
pub fn keepalive_emission_cost_floor_ns() -> Option<u64> {
    METER.floor_ns()
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

    /// The probe leaves a figure a host can read at once, times what it says it timed, touches no
    /// session (it has none to touch), and what it records is a duration of a write on a socket,
    /// not nothing and not seconds.
    #[test]
    fn the_probe_seeds_the_meter_before_any_session_exists() {
        let timed = calibrate_with_probe();
        assert_eq!(
            timed, PROBE_FRAMES,
            "every probe frame was written and timed"
        );
        let floor = keepalive_emission_cost_floor_ns().expect("a floor after the probe");
        let median = keepalive_emission_cost_median_ns().expect("a median after the probe");
        assert!(floor > 0, "a write takes time");
        assert!(floor <= median, "the lower decile is not above the median");
        assert!(
            median < 50_000_000,
            "a 3-byte write on loopback is not 50 ms: {median} ns"
        );
    }

    /// The probe is a host's call and not an implicit one: a process that never calls it has no
    /// figure from it, and the meter says so as `None` until its own emissions fill it.
    #[test]
    fn a_fresh_meter_has_no_figure_until_it_is_fed() {
        let meter = Meter::new();
        assert_eq!(meter.floor_ns(), None);
        assert_eq!(meter.median_ns(), None);
    }

    #[test]
    fn the_floor_is_the_speed_of_the_host_while_the_median_follows_its_load() {
        let meter = Meter::new();
        // A host that spends most of its emissions waiting for a core: 4 us when nothing
        // interrupts one, 20 us in the majority that something does.
        for _ in 0..60 {
            meter.record(4_000);
        }
        for _ in 0..196 {
            meter.record(20_000);
        }
        assert_eq!(meter.floor_ns(), Some(4_000));
        assert_eq!(meter.median_ns(), Some(20_000));
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
