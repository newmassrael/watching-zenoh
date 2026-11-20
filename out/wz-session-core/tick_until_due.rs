// SCE-GENERATED — DO NOT EDIT
// source-hash: 7eee1dc5ce9a4a59e9a90d4758783df5f70933300ddc53ebf1b8ee42f2a68464
// source: tick_until_due.scxml
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