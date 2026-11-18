// SCE-GENERATED — DO NOT EDIT
// source-hash: d5ca35d512d9f7defe2cc01c1d6baaf9e73f5135a637c429d7087637c197929c
// SCE-MAP: tick_elapsed.scxml:19 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn tick_elapsed(now: u32, last: u32, timeout: u32) -> bool {
    return u32::wrapping_sub(now, last) >= timeout;
}