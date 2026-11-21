// SCE-GENERATED — DO NOT EDIT
// source-hash: 4c02e38e8136e060789db5e30a33c4daee7239975931aa7677ced414570fc240
// source: tick_elapsed.scxml
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