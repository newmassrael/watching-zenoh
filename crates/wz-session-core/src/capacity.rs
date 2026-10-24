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
//! in cores, `c_k` the cost of one keepalive emission, `q` the loop's turn quantum in units and
//! `c_u` the cost of one unit:
//!
//! - **Liveness** ([`liveness_bound`]). All `N` keepalive timers can fall due together, and serving
//!   them takes `N c_k / s`. An emission late by less than `2T/3` still leaves a lease interval to
//!   spare, so the burst has to finish within `T / LEASE_EXPIRE_FACTOR`: `N <= s T / (3 c_k)`.
//! - **Service** ([`service_bound`]). The session loop returns to a face after `N q c_u / s`, and a
//!   frame waits that long in its buffer. It costs no lease (the loop reads what is waiting before
//!   it judges a peer silent) but it is how stale the data a face is given is, and how late a peer
//!   that is really gone is found. For a frame to wait at most `L`: `N <= s L / (q c_u)`. Bound
//!   only when the operator declares an `L` ([`CapacityContract::data_wait_ms`]).
//!
//! The form of the second bound is checked against measurement
//! (`docs/router-data-plane-scaling.md` section 7.4); the costs are measured on the host, and
//! [`RECORDED_HOST_COSTS`] carries them with a margin.
//!
//! ## Arithmetic
//!
//! Integers only (`u64`, parts per million of a core, milliseconds, nanoseconds), so that the module
//! is the same on every profile and an operator can reproduce a number with a pocket calculator.
//! `ppm * ms / ns` is `s T / c` exactly: `s = ppm / 1e6` and `T` in nanoseconds is `ms * 1e6`. Every
//! product saturates, and a cost of zero is "no work", which bounds nothing.

use crate::lease::LEASE_EXPIRE_FACTOR;

/// What one unit of the node's control work costs, in nanoseconds, on the host it runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlCosts {
    /// One keepalive emission.
    pub emission_ns: u64,
    /// One unit of the session loop's turn: an event of one record.
    pub loop_unit_ns: u64,
}

impl ControlCosts {
    /// Costs of `emission_ns` and `loop_unit_ns`.
    pub const fn new(emission_ns: u64, loop_unit_ns: u64) -> Self {
        Self {
            emission_ns,
            loop_unit_ns,
        }
    }

    /// These costs times `margin`: what a bound is computed from, so that a host slower than the one
    /// the costs were read on, or a cache that is cold, does not turn a promise into a guess.
    pub const fn with_margin(self, margin: u64) -> Self {
        Self {
            emission_ns: self.emission_ns.saturating_mul(margin),
            loop_unit_ns: self.loop_unit_ns.saturating_mul(margin),
        }
    }
}

/// The costs measured on the build host for the tokio runtime (`wz-runtime-tokio`), release build:
/// one keepalive emission 4.5 us, one loop event of one record 6.5 to 11 us (the upper end is the
/// figure, an event of `k` records costing at most `k` times it, `a + k b <= k (a + b)`), times a
/// margin of 2. Read in the Layer E7s runs of `docs/router-data-plane-scaling.md` sections 7.2 and
/// 7.3; the lane that re-derives the bound from them is section 7.4's table.
pub const RECORDED_HOST_COSTS: ControlCosts = ControlCosts::new(4_500, 11_000).with_margin(2);

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

/// `numerator / (denominator)` over `u64`, where a zero denominator is no work and bounds nothing.
fn quotient(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        u64::MAX
    } else {
        numerator / denominator
    }
}

/// The sessions whose keepalive burst fits within one keepalive interval at share `share_ppm`:
/// `s T / (3 c_k)`.
pub fn liveness_bound(share_ppm: u32, lease_ms: u64, costs: ControlCosts) -> u64 {
    quotient(
        u64::from(share_ppm).saturating_mul(lease_ms),
        LEASE_EXPIRE_FACTOR.saturating_mul(costs.emission_ns),
    )
}

/// The sessions for which the loop returns to a face within `wait_ms` at share `share_ppm`, with a
/// turn of `quantum_units`: `s L / (q c_u)`.
pub fn service_bound(share_ppm: u32, wait_ms: u32, quantum_units: u32, costs: ControlCosts) -> u64 {
    quotient(
        u64::from(share_ppm).saturating_mul(u64::from(wait_ms)),
        u64::from(quantum_units).saturating_mul(costs.loop_unit_ns),
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
    costs: ControlCosts,
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
        liveness_bound(contract.share_ppm, lease_ms, costs),
        Limiter::Liveness,
    );
    if let Some(wait_ms) = contract.data_wait_ms {
        narrow(
            &mut bound,
            service_bound(contract.share_ppm, wait_ms, quantum_units, costs),
            Limiter::Service,
        );
    }
    bound
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The numbers of `docs/router-data-plane-scaling.md` section 7.4, before the margin.
    const MEASURED: ControlCosts = ControlCosts::new(4_500, 11_000);
    const SHARE_1_3_PERCENT: u32 = 13_000;
    const LEASE_MS: u64 = 10_000;

    #[test]
    fn the_liveness_bound_is_the_documented_worked_example() {
        // 0.013 * 10 s / (3 * 4.5 us) = 9629.6
        assert_eq!(liveness_bound(SHARE_1_3_PERCENT, LEASE_MS, MEASURED), 9_629);
    }

    #[test]
    fn the_service_bound_is_the_documented_worked_example() {
        // 0.013 * 5 s / (8 * 11 us) = 738.6
        assert_eq!(service_bound(SHARE_1_3_PERCENT, 5_000, 8, MEASURED), 738);
    }

    #[test]
    fn a_margin_halves_a_bound_it_doubles_the_costs_of() {
        let margined = MEASURED.with_margin(2);
        assert_eq!(liveness_bound(SHARE_1_3_PERCENT, LEASE_MS, margined), 4_814);
        assert_eq!(service_bound(SHARE_1_3_PERCENT, 5_000, 8, margined), 369);
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
        let dear = ControlCosts::new(MEASURED.emission_ns * 4, MEASURED.loop_unit_ns * 4);
        assert!(
            liveness_bound(SHARE_1_3_PERCENT, LEASE_MS, dear)
                < liveness_bound(SHARE_1_3_PERCENT, LEASE_MS, MEASURED)
        );
        assert!(
            service_bound(SHARE_1_3_PERCENT, 5_000, 8, dear)
                < service_bound(SHARE_1_3_PERCENT, 5_000, 8, MEASURED)
        );
    }

    #[test]
    fn a_node_with_no_contract_is_limited_by_its_configuration_alone() {
        let bound = effective_max_sessions(1_000, None, LEASE_MS, 8, RECORDED_HOST_COSTS);
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
        let contract = CapacityContract::new(SHARE_1_3_PERCENT).unwrap();
        // 4814 with the margin: a larger configuration is cut down to it...
        let cut = effective_max_sessions(10_000, Some(&contract), LEASE_MS, 8, RECORDED_HOST_COSTS);
        assert_eq!(
            cut,
            EffectiveBound {
                limit: 4_814,
                limiter: Limiter::Liveness
            }
        );
        // ...and a smaller one stays, and says it was the configuration's.
        let kept = effective_max_sessions(1_000, Some(&contract), LEASE_MS, 8, RECORDED_HOST_COSTS);
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
        let contract = CapacityContract::new(SHARE_1_3_PERCENT)
            .unwrap()
            .with_data_wait_ms(5_000)
            .unwrap();
        let bound =
            effective_max_sessions(10_000, Some(&contract), LEASE_MS, 8, RECORDED_HOST_COSTS);
        assert_eq!(
            bound,
            EffectiveBound {
                limit: 369,
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
        let free = ControlCosts::new(0, 0);
        assert_eq!(liveness_bound(1, 1, free), u64::MAX);
        assert_eq!(service_bound(1, 1, 8, free), u64::MAX);
        let huge = ControlCosts::new(u64::MAX, u64::MAX).with_margin(u64::MAX);
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

    /// The model against the E7s run it was fitted to: 2048 sessions at 32 hogs leave the router
    /// 1.3% of a core, and the liveness bound (about 9600 before the margin) admits them, which is
    /// the run in which no lease was lost (section 7.3).
    #[test]
    fn the_e7s_population_is_inside_the_liveness_bound_at_the_share_it_ran_at() {
        assert!(liveness_bound(13_200, LEASE_MS, RECORDED_HOST_COSTS) >= 2_048);
    }
}
