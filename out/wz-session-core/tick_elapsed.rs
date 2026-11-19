// SCE-GENERATED — DO NOT EDIT
// source-hash: 74ceb15933f6fb51f993a6f4ed5c7e10715f96af9d47cdd107837aff17d2bd0c
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