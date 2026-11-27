// SCE-GENERATED — DO NOT EDIT
// source-hash: 9d8cdcf586b7f971624bb74b62e069f290f73c9f6b637096a7142cb31b7685b2
// source: capacity_liveness_bound.scxml
// SCE-MAP: capacity_liveness_bound.scxml:19 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

use super::capacity_quotient;

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn capacity_liveness_bound(share_ppm: u32, lease_ms: u64, expire_factor: u64, busy_threads: u32, emission_ns: u64) -> u64 {
    let share: u64 = share_ppm as u64;
    let mut threads: u64 = busy_threads as u64;
    if threads == 0 {
        threads = 1;
    }
    let work: u64 = u64::saturating_mul(share, lease_ms);
    let burst: u64 = u64::saturating_mul(expire_factor, threads);
    let cost: u64 = u64::saturating_mul(burst, emission_ns);
    return capacity_quotient::capacity_quotient(work, cost);
}