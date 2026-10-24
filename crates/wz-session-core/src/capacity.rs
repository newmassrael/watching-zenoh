// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! For how many sessions a node's control work fits the CPU it was promised.
//!
//! ## What is promised
//!
//! While the process receives at least the CPU share its operator declared
//! ([`crate::capacity::CapacityContract::share_ppm`]), each session of up to
//! [`crate::capacity::liveness_bound`] keeps its lease.
//! The promise is conditional on the share on purpose: a node cannot promise a lease to a host
//! that takes its CPU away, and a promise that does not name its condition cannot be tested. A
//! node with no declared share promises nothing and is limited by nothing but its configured
//! `max_sessions`, as upstream is.
//!
//! ## Two bounds
//!
//! With `T` the lease, a keepalive every `T / LEASE_EXPIRE_FACTOR`, `N` the sessions, `s` the share
//! of the process in cores, `b` the threads of the process that are runnable together under load,
//! `c_k` the cost of one keepalive emission, `q` the loop's turn quantum in units and `c_u` the cost
//! of one unit:
//!
//! - **Liveness** ([`crate::capacity::liveness_bound`]). The keepalives are written by ONE thread, and the scheduler
//!   divides the process's share among its runnable threads, so that thread has about `s / b`.
//!   All `N` timers can fall due together and serving them takes `N c_k b / s`. An emission late by
//!   less than `2T/3` still leaves a lease interval to spare, so the burst has to finish within
//!   `T / LEASE_EXPIRE_FACTOR`: `N <= s T / (3 b c_k)`.
//! - **Service** ([`crate::capacity::service_bound`]). The session loop runs on all the workers and returns to a
//!   face after `N q c_u / s`, and a frame waits that long in its buffer. It costs no lease (the
//!   loop reads what is waiting before it judges a peer silent) but it is how stale the data a face
//!   is given is, and how late a peer that is really gone is found. For a frame to wait at most `L`:
//!   `N <= s L / (q c_u)`. Bound only when the operator declares an `L`
//!   ([`crate::capacity::CapacityContract::data_wait_ms`]).
//!
//! The form of both bounds is checked against measurement (`docs/router-data-plane-scaling.md`
//! section 7.4); the costs are measured on the host, and [`crate::capacity::RECORDED_HOST_MODEL`] carries them with a
//! margin.
//!
//! ## Arithmetic
//!
//! Integers only (`u64`, parts per million of a core, milliseconds, nanoseconds), so that the module
//! is the same on every profile and an operator can reproduce a number with a pocket calculator.
//! `ppm * ms / ns` is `s T / c` exactly: `s = ppm / 1e6` and `T` in nanoseconds is `ms * 1e6`. Every
//! product saturates, and a cost of zero is "no work", which bounds nothing.

use crate::lease::LEASE_EXPIRE_FACTOR;

/// The units of work a session loop does in one turn before it yields the thread: the `q` of the
/// service bound. ONE value, read by the loop (`wz-runtime-tokio`'s `session_glue`) and by every
/// bound computed here, so that the number the model assumes is the number the loop runs.
pub const LOOP_TURN_UNITS: u32 = 8;

/// What the node's control work costs on the host it runs on, and how many threads share the CPU
/// it is promised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlModel {
    /// One keepalive emission, in nanoseconds.
    pub emission_ns: u64,
    /// One unit of the session loop's turn (an event of one record), in nanoseconds.
    pub loop_unit_ns: u64,
    /// The threads of the process that are runnable at once when it is loaded. The keepalive thread
    /// is one of them and has a `1 / busy_threads` part of the process's share; zero counts as one.
    pub busy_threads: u32,
}

impl ControlModel {
    /// A model of `emission_ns`, `loop_unit_ns` and `busy_threads`.
    pub const fn new(emission_ns: u64, loop_unit_ns: u64, busy_threads: u32) -> Self {
        Self {
            emission_ns,
            loop_unit_ns,
            busy_threads,
        }
    }

    /// This model with its costs times `margin`: what a bound is computed from, so that a host
    /// slower than the one the costs were read on, or a cache that is cold, does not turn a promise
    /// into a guess. The thread count is a count and is not scaled.
    pub const fn with_margin(self, margin: u64) -> Self {
        Self {
            emission_ns: self.emission_ns.saturating_mul(margin),
            loop_unit_ns: self.loop_unit_ns.saturating_mul(margin),
            busy_threads: self.busy_threads,
        }
    }

    /// This model with the keepalive emission cost the node measured on its own host, when that is
    /// dearer than the recorded one. A host slower than the one the costs were read on holds fewer
    /// leases, and only the host knows how much slower; a host faster than it keeps the recorded
    /// cost, because a figure read from a few emissions on a quiet moment is not evidence for a
    /// larger promise. The measurement can therefore only tighten the bound, never loosen it.
    ///
    /// `measured_floor_ns` is the LOWER DECILE of the node's emission durations: what one costs
    /// when nothing interrupts it, which is the speed of the host. The median and the upper
    /// deciles also carry how long the thread waited for a core, and that is the declared share's
    /// business and is already in the bound, so a measurement that carried it would count it
    /// twice (on the build host the median swings between 4 and 12 us with the load of the
    /// moment, the lower decile between 3 and 6 after the first seconds). The recorded cost is not
    /// a floor either: it carries the room the bound keeps under the loss
    /// ([`FLOOR_HEADROOM_PERCENT`]), and the measurement gets the same room before the two are
    /// compared, so that a host four times dearer is bound four times tighter and not to the edge
    /// of the loss.
    pub const fn calibrated(self, measured_floor_ns: Option<u64>) -> Self {
        let emission_ns = match measured_floor_ns {
            Some(floor) => {
                let with_room = floor.saturating_mul(FLOOR_HEADROOM_PERCENT) / 100;
                if with_room > self.emission_ns {
                    with_room
                } else {
                    self.emission_ns
                }
            }
            None => self.emission_ns,
        };
        Self {
            emission_ns,
            loop_unit_ns: self.loop_unit_ns,
            busy_threads: self.busy_threads,
        }
    }
}

/// The model read on the build host for the tokio runtime (`wz-runtime-tokio`), release build:
///
/// - one keepalive emission 10 us: the upper end of the median (6 to 10 us) of one emission with its
///   urgent write on a router starved by 32 hogs. The 4.5 us this module first carried was read once
///   on an unloaded host and the loss measurements refuted the bound it gave;
/// - one loop event of one record 11 us, the upper end of 6.5 to 11 (an event of `k` records costs at
///   most `k` times it, `a + k b <= k (a + b)`);
/// - four busy router threads, the count that makes the service bound reproduce the router's measured
///   silence from its peers.
///
/// No further margin: the bound it gives at 32 hogs, 1100 sessions, sits at 0.72 of the largest
/// population that lost no client in five runs (1536) and 0.54 of the smallest that lost clients in
/// all five (2048), which is the room a margin is for. Read in `docs/router-data-plane-scaling.md`
/// section 7.4.
pub const RECORDED_HOST_MODEL: ControlModel = ControlModel::new(10_000, 11_000, 4);

/// The room [`RECORDED_HOST_MODEL`]'s emission cost has over the lower decile of the emissions it
/// stands for, in percent: 10 us against the 4.5 us that `wz-runtime-tokio`'s emission meter reads
/// on the build host under 32 hogs once the first seconds are over (3.3 to 5.7 us in three runs of
/// the promise test; the first reading of a run, with cold caches and the handshakes in progress,
/// is 5.7 to 8.5), 2.2 times. It is what keeps the bound at 0.72 of the largest population that
/// lost no client; a cost measured on another host is a lower decile too and takes the same room
/// ([`ControlModel::calibrated`]).
pub const FLOOR_HEADROOM_PERCENT: u64 = 220;

/// What an operator declares about the CPU a node may count on, and how stale a frame may get.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityContract {
    share_ppm: u32,
    data_wait_ms: Option<u32>,
}

/// A contract that cannot be a promise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractError {
    /// A share of nothing admits no session; an operator who means "no promise" declares none.
    ZeroShare,
    /// A longest data wait of nothing is a loop that returns before it has worked.
    ZeroDataWait,
}

impl CapacityContract {
    /// A contract for `share_ppm` parts per million of one core (`10_000` is 1%).
    pub const fn new(share_ppm: u32) -> Result<Self, ContractError> {
        if share_ppm == 0 {
            return Err(ContractError::ZeroShare);
        }
        Ok(Self {
            share_ppm,
            data_wait_ms: None,
        })
    }

    /// This contract that also bounds how long a frame may wait for the loop, in milliseconds.
    pub const fn with_data_wait_ms(self, data_wait_ms: u32) -> Result<Self, ContractError> {
        if data_wait_ms == 0 {
            return Err(ContractError::ZeroDataWait);
        }
        Ok(Self {
            share_ppm: self.share_ppm,
            data_wait_ms: Some(data_wait_ms),
        })
    }

    /// The declared share, in parts per million of one core.
    pub const fn share_ppm(&self) -> u32 {
        self.share_ppm
    }

    /// The longest wait of a frame the operator accepts, when one was declared.
    pub const fn data_wait_ms(&self) -> Option<u32> {
        self.data_wait_ms
    }
}

/// Which limit is the smallest, so that an operator sees whether a refusal was theirs or the model's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limiter {
    /// The configured `max_sessions` (or no contract was declared).
    Configured,
    /// The liveness bound: the keepalives of more sessions would not fit the share.
    Liveness,
    /// The service bound: a frame would wait longer than the declared wait.
    Service,
}

impl Limiter {
    /// The name the capacity report carries.
    pub const fn label(self) -> &'static str {
        match self {
            Limiter::Configured => "configured",
            Limiter::Liveness => "liveness",
            Limiter::Service => "service",
        }
    }
}

/// The number of sessions a node admits, and what set it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectiveBound {
    /// The sessions admitted at once.
    pub limit: usize,
    /// The smallest of the limits. A tie names the configured one first, then liveness.
    pub limiter: Limiter,
}

/// `numerator / denominator` over `u64`, where a zero denominator is no work and bounds nothing.
fn quotient(numerator: u64, denominator: u64) -> u64 {
    numerator.checked_div(denominator).unwrap_or(u64::MAX)
}

/// The sessions whose keepalive burst the keepalive thread serves within one keepalive interval at
/// the process share `share_ppm`: `s T / (3 b c_k)`.
pub fn liveness_bound(share_ppm: u32, lease_ms: u64, model: ControlModel) -> u64 {
    quotient(
        u64::from(share_ppm).saturating_mul(lease_ms),
        LEASE_EXPIRE_FACTOR
            .saturating_mul(u64::from(model.busy_threads.max(1)))
            .saturating_mul(model.emission_ns),
    )
}

/// The sessions for which the loop returns to a face within `wait_ms` at the process share
/// `share_ppm`, with a turn of `quantum_units`: `s L / (q c_u)`.
pub fn service_bound(share_ppm: u32, wait_ms: u32, quantum_units: u32, model: ControlModel) -> u64 {
    quotient(
        u64::from(share_ppm).saturating_mul(u64::from(wait_ms)),
        u64::from(quantum_units).saturating_mul(model.loop_unit_ns),
    )
}

/// The latest a keepalive may be served and still leave a peer its lease: `2T/3`. A keepalive is due
/// every `T / LEASE_EXPIRE_FACTOR`, so one that is a further `2T/3` late has spent the interval it
/// was owed and the one before it; the next is the last the peer will wait for.
pub const fn keepalive_lateness_limit_ms(lease_ms: u64) -> u64 {
    lease_ms - lease_ms / LEASE_EXPIRE_FACTOR
}

/// The width of one lateness window, in milliseconds.
pub const LATENESS_WINDOW_MS: u64 = 10_000;

/// How many windows [`LatenessWindows`] keeps: with [`LATENESS_WINDOW_MS`], the last minute.
pub const LATENESS_WINDOWS: usize = 6;

/// The longest a keepalive timer was served late, kept per window of time and not as one maximum
/// for the life of the process.
///
/// A maximum over the whole life can only rise, so it can say that a bad second happened once but
/// neither whether the node is in one now nor whether it has left it, and a control that read it
/// would refuse sessions for ever after a single bad second. Three readings answer the three
/// questions an operator and an admission rule ask: [`Self::current`] (the window the clock is
/// in), [`Self::last_minute`] (the windows of the last minute, the current one included) and
/// [`Self::since_start`] (the old process maximum, kept because it is what the capacity promise
/// was asserted on).
///
/// Pure: the caller names the time of each record and of each read, in milliseconds on one clock
/// that never goes back, and the type holds no lock and reads no clock, so it is the same on every
/// profile. A host wraps it in whatever lock its runtime has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LatenessWindows {
    /// For each slot, the window number it holds plus one (zero is an empty slot) and the longest
    /// lateness recorded in that window.
    slots: [(u64, u64); LATENESS_WINDOWS],
    since_start_ms: u64,
}

impl LatenessWindows {
    /// No lateness recorded.
    pub const fn new() -> Self {
        Self {
            slots: [(0, 0); LATENESS_WINDOWS],
            since_start_ms: 0,
        }
    }

    /// The window `now_ms` falls in, plus one, so that zero stays "empty".
    const fn tag(now_ms: u64) -> u64 {
        now_ms / LATENESS_WINDOW_MS + 1
    }

    /// Record that a timer was served `late_ms` after its time, at `now_ms`.
    pub fn record(&mut self, now_ms: u64, late_ms: u64) {
        self.since_start_ms = self.since_start_ms.max(late_ms);
        let tag = Self::tag(now_ms);
        // `tag % LATENESS_WINDOWS` is below the array's length by construction.
        let slot = &mut self.slots[(tag % LATENESS_WINDOWS as u64) as usize];
        if slot.0 == tag {
            slot.1 = slot.1.max(late_ms);
        } else {
            *slot = (tag, late_ms);
        }
    }

    /// The longest lateness recorded in the window `now_ms` falls in.
    pub fn current(&self, now_ms: u64) -> u64 {
        let tag = Self::tag(now_ms);
        self.slots
            .iter()
            .find(|slot| slot.0 == tag)
            .map_or(0, |slot| slot.1)
    }

    /// The longest lateness recorded in the last [`LATENESS_WINDOWS`] windows, the current one
    /// included. A slot that holds an older window than that is not read, whatever it holds.
    pub fn last_minute(&self, now_ms: u64) -> u64 {
        let tag = Self::tag(now_ms);
        self.slots
            .iter()
            .filter(|slot| slot.0 != 0 && slot.0 <= tag && tag - slot.0 < LATENESS_WINDOWS as u64)
            .map(|slot| slot.1)
            .max()
            .unwrap_or(0)
    }

    /// The longest lateness recorded since the process started: the figure that only rises.
    pub const fn since_start(&self) -> u64 {
        self.since_start_ms
    }
}

impl Default for LatenessWindows {
    fn default() -> Self {
        Self::new()
    }
}

/// The sessions a node admits at once: the configured `max_sessions`, or less when the declared
/// contract says the node cannot keep that many leases (and, when it declared a longest data wait,
/// serve that many faces in it).
///
/// With no contract the configured number is the answer, as upstream's is.
pub fn effective_max_sessions(
    configured: usize,
    contract: Option<&CapacityContract>,
    lease_ms: u64,
    quantum_units: u32,
    model: ControlModel,
) -> EffectiveBound {
    let mut bound = EffectiveBound {
        limit: configured,
        limiter: Limiter::Configured,
    };
    let Some(contract) = contract else {
        return bound;
    };
    let narrow = |bound: &mut EffectiveBound, limit: u64, limiter: Limiter| {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        if limit < bound.limit {
            *bound = EffectiveBound { limit, limiter };
        }
    };
    narrow(
        &mut bound,
        liveness_bound(contract.share_ppm, lease_ms, model),
        Limiter::Liveness,
    );
    if let Some(wait_ms) = contract.data_wait_ms {
        narrow(
            &mut bound,
            service_bound(contract.share_ppm, wait_ms, quantum_units, model),
            Limiter::Service,
        );
    }
    bound
}

/// The version of the capacity report's shape. Moves when a field is removed or changes meaning;
/// a field added at the end does not move it.
pub const CAPACITY_REPORT_SCHEMA_VERSION: u32 = 1;

/// What a node says about its capacity, at one moment: the promise it was given, the limit it
/// derived and who set it, what it holds, what it measured of its own host, how late its keepalive
/// timers were, and why it refused. A plain value, so the same report is the monitor's, the
/// tests' and the endpoint's, and a node that cannot reach a figure says `None` for it and not
/// zero.
///
/// Every field is an integer in the unit its name says, or an absent value. Counters only rise
/// (`refused_*`); every other figure is a gauge, a reading of now. The shape is the report's
/// schema ([`CAPACITY_REPORT_SCHEMA_VERSION`]); `docs/router-data-plane-scaling.md` section 7.4
/// lists the fields and a test fails when it does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityReport {
    /// The lease the bounds are computed for, in milliseconds.
    pub lease_ms: u64,
    /// The declared CPU share in parts per million of one core; `None` when the operator declared
    /// none and the node promises nothing.
    pub share_ppm: Option<u32>,
    /// The declared longest wait of a frame in milliseconds, when one was declared.
    pub data_wait_ms: Option<u32>,
    /// The configured `max_sessions`.
    pub configured_max_sessions: usize,
    /// The sessions admitted at once now, and what set it.
    pub bound: EffectiveBound,
    /// The sessions held now.
    pub sessions_held: usize,
    /// The cost of a keepalive emission the node measured on its own host, lower decile and
    /// median, in nanoseconds; `None` before enough emissions were timed.
    pub emission_floor_ns: Option<u64>,
    /// See `emission_floor_ns`.
    pub emission_median_ns: Option<u64>,
    /// The longest keepalive timer lateness in the current window, in milliseconds.
    pub lateness_current_ms: u64,
    /// The longest in the last minute.
    pub lateness_last_minute_ms: u64,
    /// The longest since the process started.
    pub lateness_since_start_ms: u64,
    /// Sessions refused because `max_sessions` was reached (counter).
    pub refused_over_max_sessions: u64,
    /// Sessions refused because the measured capacity was reached (counter).
    pub refused_over_capacity: u64,
    /// Senders parked now, waiting for room on a lane (a gauge).
    pub parked_senders: usize,
    /// How many senders the node lets park at once: the bulkhead between a stopped reader and the
    /// workers the other faces share.
    pub park_budget: usize,
    /// Senders turned away because the budget was spent, answered congested at once (counter).
    pub park_refused: u64,
}

impl CapacityReport {
    /// The latest a keepalive may be served and still leave a peer its lease, in milliseconds.
    pub const fn lateness_limit_ms(&self) -> u64 {
        keepalive_lateness_limit_ms(self.lease_ms)
    }

    /// Whether a keepalive was served later than a lease allows in the last minute: the
    /// promise, if one was declared, is not being kept now.
    pub const fn lease_at_risk(&self) -> bool {
        self.lateness_last_minute_ms > self.lateness_limit_ms()
    }

    /// Write the report as one JSON object: integers, strings and `null` only, fields in the order
    /// the schema lists them, so that two reports of one state are the same bytes.
    pub fn write_json<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        fn opt<W: core::fmt::Write, T: core::fmt::Display>(
            w: &mut W,
            name: &str,
            v: Option<T>,
        ) -> core::fmt::Result {
            match v {
                Some(v) => write!(w, "\"{name}\":{v},"),
                None => write!(w, "\"{name}\":null,"),
            }
        }
        write!(w, "{{\"schema_version\":{CAPACITY_REPORT_SCHEMA_VERSION},")?;
        write!(w, "\"lease_ms\":{},", self.lease_ms)?;
        opt(w, "share_ppm", self.share_ppm)?;
        opt(w, "data_wait_ms", self.data_wait_ms)?;
        write!(
            w,
            "\"configured_max_sessions\":{},\"limit\":{},\"limiter\":\"{}\",\"sessions_held\":{},",
            self.configured_max_sessions,
            self.bound.limit,
            self.bound.limiter.label(),
            self.sessions_held
        )?;
        opt(w, "emission_floor_ns", self.emission_floor_ns)?;
        opt(w, "emission_median_ns", self.emission_median_ns)?;
        write!(
            w,
            "\"lateness_current_ms\":{},\"lateness_last_minute_ms\":{},\
             \"lateness_since_start_ms\":{},\"lateness_limit_ms\":{},\"lease_at_risk\":{},\
             \"refused_over_max_sessions\":{},\"refused_over_capacity\":{},\
             \"parked_senders\":{},\"park_budget\":{},\"park_refused\":{}}}",
            self.lateness_current_ms,
            self.lateness_last_minute_ms,
            self.lateness_since_start_ms,
            self.lateness_limit_ms(),
            self.lease_at_risk(),
            self.refused_over_max_sessions,
            self.refused_over_capacity,
            self.parked_senders,
            self.park_budget,
            self.park_refused
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The numbers of `docs/router-data-plane-scaling.md` section 7.4.
    const MEASURED: ControlModel = ControlModel::new(10_000, 11_000, 4);
    /// The router's share at 32 hogs in the E7s runs: four threads at nice 10 against hogs at 0.
    const SHARE_32_HOGS: u32 = 13_200;
    /// And at 24 hogs.
    const SHARE_24_HOGS: u32 = 17_600;
    const LEASE_MS: u64 = 10_000;

    #[test]
    fn the_liveness_bound_is_the_documented_worked_example() {
        // 0.0132 * 10 s / (3 * 4 * 10 us) = 1100
        assert_eq!(liveness_bound(SHARE_32_HOGS, LEASE_MS, MEASURED), 1_100);
    }

    #[test]
    fn the_service_bound_is_the_documented_worked_example() {
        // 0.0132 * 5 s / (8 * 11 us) = 750
        assert_eq!(service_bound(SHARE_32_HOGS, 5_000, 8, MEASURED), 750);
    }

    #[test]
    fn a_margin_halves_a_bound_it_doubles_the_costs_of() {
        let margined = MEASURED.with_margin(2);
        assert_eq!(liveness_bound(SHARE_32_HOGS, LEASE_MS, margined), 550);
        assert_eq!(service_bound(SHARE_32_HOGS, 5_000, 8, margined), 375);
        assert_eq!(margined.busy_threads, 4, "a count of threads is not scaled");
    }

    #[test]
    fn the_keepalive_thread_has_a_part_of_the_share_not_all_of_it() {
        let alone = ControlModel::new(MEASURED.emission_ns, MEASURED.loop_unit_ns, 1);
        let four = liveness_bound(SHARE_32_HOGS, LEASE_MS, MEASURED);
        let one = liveness_bound(SHARE_32_HOGS, LEASE_MS, alone);
        assert!(
            one >= 4 * four && one < 4 * four + 4,
            "one thread that has the whole share serves four times the sessions: {one} and {four}"
        );
        let zero = ControlModel::new(MEASURED.emission_ns, MEASURED.loop_unit_ns, 0);
        assert_eq!(
            liveness_bound(SHARE_32_HOGS, LEASE_MS, zero),
            liveness_bound(SHARE_32_HOGS, LEASE_MS, alone),
            "no threads is read as one, not as no work"
        );
    }

    #[test]
    fn a_bound_grows_with_the_share_and_with_the_lease() {
        for share in [1_000u32, 13_000, 100_000, 1_000_000] {
            let at = liveness_bound(share, LEASE_MS, MEASURED);
            let doubled = liveness_bound(share * 2, LEASE_MS, MEASURED);
            // integer division loses at most one session
            assert!(doubled + 1 >= at * 2, "twice the share, twice the sessions");
            assert!(liveness_bound(share, LEASE_MS * 2, MEASURED) + 1 >= at * 2);
        }
    }

    #[test]
    fn a_bound_falls_as_the_work_per_session_grows() {
        let dear = ControlModel::new(MEASURED.emission_ns * 4, MEASURED.loop_unit_ns * 4, 4);
        assert!(
            liveness_bound(SHARE_32_HOGS, LEASE_MS, dear)
                < liveness_bound(SHARE_32_HOGS, LEASE_MS, MEASURED)
        );
        assert!(
            service_bound(SHARE_32_HOGS, 5_000, 8, dear)
                < service_bound(SHARE_32_HOGS, 5_000, 8, MEASURED)
        );
    }

    #[test]
    fn a_dearer_measured_emission_tightens_the_bound_and_a_cheaper_one_does_not_loosen_it() {
        // A host four times dearer than the build host's 4.5 us lower decile holds a quarter of
        // what the recorded model admits there, with the same room under the loss: 18 us measured
        // is 39.6 us bound, and 0.0132 * 10 s / (3 * 4 * 39.6 us) = 277.
        let slow = MEASURED.calibrated(Some(18_000));
        assert_eq!(slow.emission_ns, 39_600);
        assert_eq!(liveness_bound(SHARE_32_HOGS, LEASE_MS, slow), 277);
        // The build host's own floor keeps the recorded cost: its room is already in it.
        assert_eq!(MEASURED.calibrated(Some(4_500)), MEASURED);
        // A quiet moment's cheap emissions are not a reason to promise more.
        assert_eq!(MEASURED.calibrated(Some(4_500)), MEASURED);
        // No measurement yet: the recorded model.
        assert_eq!(MEASURED.calibrated(None), MEASURED);
        // Only the emission cost is measured; the loop unit and the thread count stay.
        assert_eq!(slow.loop_unit_ns, MEASURED.loop_unit_ns);
        assert_eq!(slow.busy_threads, MEASURED.busy_threads);
    }

    #[test]
    fn a_node_with_no_contract_is_limited_by_its_configuration_alone() {
        let bound = effective_max_sessions(1_000, None, LEASE_MS, 8, RECORDED_HOST_MODEL);
        assert_eq!(
            bound,
            EffectiveBound {
                limit: 1_000,
                limiter: Limiter::Configured
            }
        );
    }

    #[test]
    fn the_smaller_of_the_configured_and_the_liveness_bound_is_the_limit() {
        let contract = CapacityContract::new(SHARE_32_HOGS).unwrap();
        // 1100: a larger configuration is cut down to it...
        let cut = effective_max_sessions(10_000, Some(&contract), LEASE_MS, 8, RECORDED_HOST_MODEL);
        assert_eq!(
            cut,
            EffectiveBound {
                limit: 1_100,
                limiter: Limiter::Liveness
            }
        );
        // ...and a smaller one stays, and says it was the configuration's.
        let kept = effective_max_sessions(1_000, Some(&contract), LEASE_MS, 8, RECORDED_HOST_MODEL);
        assert_eq!(
            kept,
            EffectiveBound {
                limit: 1_000,
                limiter: Limiter::Configured
            }
        );
    }

    #[test]
    fn a_declared_data_wait_can_be_the_binding_bound() {
        let contract = CapacityContract::new(SHARE_32_HOGS)
            .unwrap()
            .with_data_wait_ms(5_000)
            .unwrap();
        let bound =
            effective_max_sessions(10_000, Some(&contract), LEASE_MS, 8, RECORDED_HOST_MODEL);
        assert_eq!(
            bound,
            EffectiveBound {
                limit: 750,
                limiter: Limiter::Service
            }
        );
    }

    #[test]
    fn a_keepalive_may_be_two_thirds_of_a_lease_late() {
        assert_eq!(keepalive_lateness_limit_ms(10_000), 6_667);
        assert_eq!(keepalive_lateness_limit_ms(30_000), 20_000);
        assert_eq!(keepalive_lateness_limit_ms(0), 0);
    }

    #[test]
    fn a_window_reads_what_was_recorded_in_it_and_forgets_it_a_minute_later() {
        let mut w = LatenessWindows::new();
        assert_eq!((w.current(0), w.last_minute(0), w.since_start()), (0, 0, 0));
        w.record(1_000, 400);
        w.record(9_999, 900);
        w.record(5_000, 100);
        assert_eq!(
            w.current(9_999),
            900,
            "the maximum of the window, not the last record"
        );
        // The next window has recorded nothing, the last minute still holds the first.
        assert_eq!(w.current(10_000), 0);
        assert_eq!(w.last_minute(10_000), 900);
        // Five windows on it is still the last minute; the sixth after it is not.
        assert_eq!(w.last_minute(59_999), 900);
        assert_eq!(
            w.last_minute(60_000),
            0,
            "a minute later it is out of the last minute"
        );
        // And what only rises still holds it.
        assert_eq!(w.since_start(), 900);
    }

    #[test]
    fn a_slot_reused_by_a_later_window_does_not_keep_the_old_one() {
        let mut w = LatenessWindows::new();
        w.record(0, 5_000);
        // Six windows later the same slot is the current window's.
        w.record(60_000, 300);
        assert_eq!(
            w.current(60_000),
            300,
            "the old window's 5000 is gone from the slot"
        );
        assert_eq!(w.last_minute(60_000), 300);
        assert_eq!(w.since_start(), 5_000);
    }

    #[test]
    fn the_last_minute_is_the_longest_of_its_windows() {
        let mut w = LatenessWindows::new();
        for (at, late) in [(5_000, 100), (15_000, 2_500), (25_000, 700), (55_000, 300)] {
            w.record(at, late);
        }
        assert_eq!(w.last_minute(55_000), 2_500);
        assert_eq!(w.current(55_000), 300);
        // The window of the 2500 leaves the minute after the sixth window past it.
        assert_eq!(w.last_minute(75_000), 700);
        assert_eq!(w.last_minute(85_000), 300);
        assert_eq!(w.last_minute(115_000), 0);
    }

    #[test]
    fn a_read_before_a_record_is_not_confused_by_an_empty_slot() {
        // A window number of zero is a real window, and an empty slot is not it.
        let mut w = LatenessWindows::new();
        assert_eq!(w.current(0), 0);
        w.record(0, 7);
        assert_eq!(w.current(0), 7);
        assert_eq!(w.last_minute(0), 7);
        // A reading earlier than a record (a clock read by two threads) does not underflow.
        assert_eq!(w.last_minute(0), 7);
        let mut late = LatenessWindows::new();
        late.record(30_000, 9);
        assert_eq!(
            late.last_minute(0),
            0,
            "a window from the future is not in the last minute"
        );
    }

    fn a_report() -> CapacityReport {
        CapacityReport {
            lease_ms: 10_000,
            share_ppm: Some(13_200),
            data_wait_ms: None,
            configured_max_sessions: 20_000,
            bound: EffectiveBound {
                limit: 1_100,
                limiter: Limiter::Liveness,
            },
            sessions_held: 1_093,
            emission_floor_ns: Some(4_500),
            emission_median_ns: None,
            lateness_current_ms: 880,
            lateness_last_minute_ms: 1_263,
            lateness_since_start_ms: 1_263,
            refused_over_max_sessions: 0,
            refused_over_capacity: 948,
            parked_senders: 0,
            park_budget: 32,
            park_refused: 0,
        }
    }

    #[test]
    fn the_report_is_one_json_object_in_the_schemas_order() {
        let mut out = std::string::String::new();
        a_report().write_json(&mut out).unwrap();
        assert_eq!(
            out,
            "{\"schema_version\":1,\"lease_ms\":10000,\"share_ppm\":13200,\"data_wait_ms\":null,\
             \"configured_max_sessions\":20000,\"limit\":1100,\"limiter\":\"liveness\",\
             \"sessions_held\":1093,\"emission_floor_ns\":4500,\"emission_median_ns\":null,\
             \"lateness_current_ms\":880,\"lateness_last_minute_ms\":1263,\
             \"lateness_since_start_ms\":1263,\"lateness_limit_ms\":6667,\"lease_at_risk\":false,\
             \"refused_over_max_sessions\":0,\"refused_over_capacity\":948,\
             \"parked_senders\":0,\"park_budget\":32,\"park_refused\":0}"
        );
    }

    #[test]
    fn a_figure_the_node_cannot_reach_is_null_and_not_zero() {
        let mut r = a_report();
        r.share_ppm = None;
        r.emission_floor_ns = None;
        let mut out = std::string::String::new();
        r.write_json(&mut out).unwrap();
        assert!(out.contains("\"share_ppm\":null,"));
        assert!(out.contains("\"emission_floor_ns\":null,"));
        assert!(!out.contains("\"share_ppm\":0"));
    }

    #[test]
    fn the_lease_is_at_risk_when_the_last_minute_passed_two_thirds_of_it() {
        let mut r = a_report();
        r.lateness_last_minute_ms = 6_667;
        assert!(!r.lease_at_risk(), "at the limit is within it");
        r.lateness_last_minute_ms = 6_668;
        assert!(r.lease_at_risk());
        // The since-start figure alone, with a calm last minute, is history and not a risk now.
        r.lateness_last_minute_ms = 500;
        r.lateness_since_start_ms = 20_000;
        assert!(!r.lease_at_risk());
    }

    /// Every field of the schema is listed in the document with its unit, and the document lists
    /// no field the report does not write: read off the JSON the report writes.
    #[test]
    fn the_document_lists_every_field_of_the_report_and_no_other() {
        let doc = scaling_document();
        let mut out = std::string::String::new();
        a_report().write_json(&mut out).unwrap();
        // A string token followed by a colon is a key; one followed by a comma or brace is a value.
        let tokens: std::vec::Vec<&str> = out.split('"').collect();
        let fields: std::vec::Vec<&str> = (1..tokens.len())
            .step_by(2)
            .filter(|&i| tokens.get(i + 1).is_some_and(|t| t.starts_with(':')))
            .map(|i| tokens[i])
            .collect();
        assert_eq!(fields.len(), 20, "the schema has twenty fields: {fields:?}");
        for f in &fields {
            assert!(
                doc.contains(&std::format!("| `{f}` |")),
                "docs/router-data-plane-scaling.md does not list the report field `{f}`"
            );
        }
        let rows = doc
            .lines()
            .filter(|l| l.starts_with("| `") && l.contains("` | report |"))
            .count();
        assert_eq!(
            rows,
            fields.len(),
            "the document lists a field the report does not write"
        );
    }

    /// The document the numbers are explained in, read from the workspace this test runs in.
    fn scaling_document() -> std::string::String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/router-data-plane-scaling.md");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} is read by the capacity tests: {e}", path.display()))
    }

    /// The costs the document states are the costs the code carries: a constant moved without the
    /// text, or the text without the constant, fails here and not in a reader's arithmetic.
    #[test]
    fn the_document_states_the_costs_the_model_carries() {
        let doc = scaling_document();
        let m = RECORDED_HOST_MODEL;
        for stated in [
            std::format!(
                "`c_k` {} us, `c_u` {} us, `b` {}",
                m.emission_ns / 1_000,
                m.loop_unit_ns / 1_000,
                m.busy_threads
            ),
            std::format!("`FLOOR_HEADROOM_PERCENT` =\n{FLOOR_HEADROOM_PERCENT}"),
            std::format!("`TURN_UNIT_BUDGET` ({LOOP_TURN_UNITS})"),
        ] {
            assert!(
                doc.contains(&stated),
                "docs/router-data-plane-scaling.md no longer states: {stated}"
            );
        }
    }

    /// The table of section 7.4 that sets the predicted return time of the loop against the
    /// observed one, re-derived from the model: the share is `4 x 110 / (4 x 110 + hogs x 1024)`
    /// (the scheduler's weights at nice 10 and nice 0) and the return is
    /// `2048 x LOOP_TURN_UNITS x c_u / share`. A row whose prediction the model no longer gives, or
    /// that sits outside what was observed by more than a tenth, fails.
    #[test]
    fn the_documented_return_times_are_the_ones_the_model_gives() {
        let doc = scaling_document();
        let mut rows = 0;
        for line in doc.lines() {
            let cells: std::vec::Vec<&str> = line.split('|').map(str::trim).collect();
            // | hogs | share | predicted R | observed |
            let [_, hogs, share, predicted, observed, _] = cells[..] else {
                continue;
            };
            let (Ok(hogs), Some(share), Some(predicted)) = (
                hogs.parse::<f64>(),
                share.strip_suffix('%').and_then(|s| s.parse::<f64>().ok()),
                predicted
                    .strip_suffix(" s")
                    .and_then(|s| s.parse::<f64>().ok()),
            ) else {
                continue;
            };
            let Some((low, high)) = observed
                .strip_suffix(" s")
                .and_then(|s| s.split_once(" to "))
                .and_then(|(l, h)| Some((l.parse::<f64>().ok()?, h.parse::<f64>().ok()?)))
            else {
                continue;
            };
            let busy = f64::from(RECORDED_HOST_MODEL.busy_threads);
            let ours = busy * 110.0 / (busy * 110.0 + hogs * 1024.0);
            let ret = 2048.0 * f64::from(LOOP_TURN_UNITS) * RECORDED_HOST_MODEL.loop_unit_ns as f64
                / 1e9
                / ours;
            assert!(
                (100.0 * ours - share).abs() < 0.06,
                "{hogs} hogs: the table says a share of {share}%, the weights give {:.2}%",
                100.0 * ours
            );
            assert!(
                (ret - predicted).abs() < 0.06,
                "{hogs} hogs: the table predicts {predicted} s, the model gives {ret:.2} s"
            );
            assert!(
                ret >= 0.9 * low && ret <= 1.1 * high,
                "{hogs} hogs: the model's {ret:.2} s is not within a tenth of the observed {low} to {high} s"
            );
            rows += 1;
        }
        assert_eq!(
            rows, 5,
            "the table has five rows, and every one was checked"
        );
    }

    #[test]
    fn a_contract_of_nothing_is_refused() {
        assert_eq!(CapacityContract::new(0), Err(ContractError::ZeroShare));
        let contract = CapacityContract::new(1).unwrap();
        assert_eq!(
            contract.with_data_wait_ms(0),
            Err(ContractError::ZeroDataWait)
        );
    }

    #[test]
    fn a_cost_of_zero_bounds_nothing_and_extreme_inputs_do_not_overflow() {
        let free = ControlModel::new(0, 0, 4);
        assert_eq!(liveness_bound(1, 1, free), u64::MAX);
        assert_eq!(service_bound(1, 1, 8, free), u64::MAX);
        let huge = ControlModel::new(u64::MAX, u64::MAX, u32::MAX).with_margin(u64::MAX);
        // Both sides saturate: the answer is a number, and not a panic or a wrap to a large one.
        assert!(liveness_bound(u32::MAX, u64::MAX, huge) <= 1);
        assert!(service_bound(u32::MAX, u32::MAX, u32::MAX, huge) <= 1);
        let contract = CapacityContract::new(u32::MAX).unwrap();
        let bound = effective_max_sessions(5, Some(&contract), u64::MAX, 8, free);
        assert_eq!(
            bound.limit, 5,
            "a share that bounds nothing leaves the configuration"
        );
        assert_eq!(bound.limiter, Limiter::Configured);
    }

    /// The model against the loss measured at 32 hogs (section 7.4): no client lost in five runs at
    /// 1536 sessions, clients lost in all five at 2048. The bound has to refuse every population that
    /// lost clients and keep a margin under the largest that lost none: 1100 is 0.72 of 1536.
    #[test]
    fn the_bound_at_32_hogs_sits_under_the_largest_population_that_lost_nothing() {
        const LARGEST_WITHOUT_LOSS: u64 = 1_536;
        const SMALLEST_WITH_LOSS: u64 = 2_048;
        let at_32 = liveness_bound(SHARE_32_HOGS, LEASE_MS, RECORDED_HOST_MODEL);
        assert!(
            at_32 < LARGEST_WITHOUT_LOSS,
            "it must not admit a population at the edge"
        );
        assert!(
            at_32 * 3 > LARGEST_WITHOUT_LOSS * 2,
            "and not so far under it that the model gives the capacity away: {at_32}"
        );
        assert!(at_32 < SMALLEST_WITH_LOSS);
        // At 24 hogs 2048 sessions lost clients in one run of two; the bound refuses that population.
        assert!(liveness_bound(SHARE_24_HOGS, LEASE_MS, RECORDED_HOST_MODEL) < SMALLEST_WITH_LOSS);
    }
}
