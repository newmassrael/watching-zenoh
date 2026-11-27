// SCE-GENERATED — DO NOT EDIT
// source-hash: f07e699c13c94768618c82abf44581d013af054f55c70c1a68743fb2a5feebb6
// source: capacity_cost_with_margin.scxml
// SCE-MAP: capacity_cost_with_margin.scxml:12 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn capacity_cost_with_margin(cost_ns: u64, margin: u64) -> u64 {
    return u64::saturating_mul(cost_ns, margin);
}