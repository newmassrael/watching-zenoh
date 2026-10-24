// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! For how many sessions a node's control work fits the CPU it was promised.
//!
//! ## What is promised
//!
//! While the process receives at least the CPU share its operator declared
//! ([`CapacityContract::share_ppm`]), each session of up to [`liveness_bound`] keeps its lease.
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
//! - **Liveness** ([`liveness_bound`]). The keepalives are written by ONE thread, and the scheduler
//!   divides the process's share among its runnable threads, so that thread has about `s / b`.
//!   All `N` timers can fall due together and serving them takes `N c_k b / s`. An emission late by
//!   less than `2T/3` still leaves a lease interval to spare, so the burst has to finish within
//!   `T / LEASE_EXPIRE_FACTOR`: `N <= s T / (3 b c_k)`.
//! - **Service** ([`service_bound`]). The session loop runs on all the workers and returns to a
//!   face after `N q c_u / s`, and a frame waits that long in its buffer. It costs no lease (the
//!   loop reads what is waiting before it judges a peer silent) but it is how stale the data a face
//!   is given is, and how late a peer that is really gone is found. For a frame to wait at most `L`:
//!   `N <= s L / (q c_u)`. Bound only when the operator declares an `L`
//!   ([`CapacityContract::data_wait_ms`]).
//!
//! The form of both bounds is checked against measurement (`docs/router-data-plane-scaling.md`
//! section 7.4); the costs are measured on the host, and [`RECORDED_HOST_MODEL`] carries them with a
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
