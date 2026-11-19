// SCE-GENERATED — DO NOT EDIT
// source-hash: d4be575c838fab38b93b0c7e5652426a7cf552b96f4795b6a81ea11073158f08
// SCE-MAP: tick_until_due.scxml:19 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn tick_until_due(now: u32, last: u32, period: u32) -> u32 {
    return u32::saturating_sub(period, u32::wrapping_sub(now, last));
}