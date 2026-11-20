// SCE-GENERATED — DO NOT EDIT
// source-hash: 2169650ac71d5eb7a5af536f75aca6c6d03a892b65042d7515a2b318f491badb
// source: e2e_counter_verdict.scxml
// SCE-MAP: e2e_counter_verdict.scxml:15 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn e2e_counter_verdict(step: u64, max_gap: u64) -> u8 {
    if step == 0 {
        return 1;
    }
    if step <= max_gap {
        return 0;
    }
    return 2;
}