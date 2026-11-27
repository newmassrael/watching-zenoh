// SCE-GENERATED — DO NOT EDIT
// source-hash: 140089db361cf78c14b05ad1dcbca6d8bbf87ea3919846c50c88f9e98ef852e5
// source: capacity_service_bound.scxml
// SCE-MAP: capacity_service_bound.scxml:14 :: _forge_body

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
pub fn capacity_service_bound(share_ppm: u32, wait_ms: u32, quantum_units: u32, loop_unit_ns: u64) -> u64 {
    let share: u64 = share_ppm as u64;
    let wait: u64 = wait_ms as u64;
    let quantum: u64 = quantum_units as u64;
    let work: u64 = u64::saturating_mul(share, wait);
    let cost: u64 = u64::saturating_mul(quantum, loop_unit_ns);
    return capacity_quotient::capacity_quotient(work, cost);
}