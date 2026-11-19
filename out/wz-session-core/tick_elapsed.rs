// SCE-GENERATED — DO NOT EDIT
// source-hash: efcd880f13db3c398404bf795b7880282d08f0686f520d1f89297a7688ccc60b
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