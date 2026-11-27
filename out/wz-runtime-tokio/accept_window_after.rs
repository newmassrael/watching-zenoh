// SCE-GENERATED — DO NOT EDIT
// source-hash: 65d2e12e9e7b01b5857c0cae7bfe6c8ce4797ab955b7ab560a8d8e74ff6af41a
// source: accept_window_after.scxml
// SCE-MAP: accept_window_after.scxml:21 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn accept_window_after(timeout_ms: u64, spent_ms: u64) -> u64 {
    let left: u64 = u64::saturating_sub(timeout_ms, spent_ms);
    if left == 0 {
        return 1;
    }
    return left;
}