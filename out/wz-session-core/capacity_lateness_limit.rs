// SCE-GENERATED — DO NOT EDIT
// source-hash: c876e586ed0337c1452d2f85c5b825b6af13a61625fd27c0a160aa6371e67dc4
// source: capacity_lateness_limit.scxml
// SCE-MAP: capacity_lateness_limit.scxml:17 :: _forge_body

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
pub fn capacity_lateness_limit(lease_ms: u64, expire_factor: u64) -> u64 {
    let interval: u64 = capacity_quotient::capacity_quotient(lease_ms, expire_factor);
    return u64::saturating_sub(lease_ms, interval);
}