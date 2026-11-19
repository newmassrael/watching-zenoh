// SCE-GENERATED — DO NOT EDIT
// source-hash: efe483b8c23efdefdaa54278e5db4cf384518b44642a21e3544dccee9803aa15
// SCE-MAP: declaration_stall_deadline.scxml:20 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn declaration_stall_deadline(reacts: bool, peer_settled: bool, baseline_ms: u64, window_ms: u64) -> Option<u64> {
    if !reacts || window_ms == 0 || peer_settled {
        return None;
    }
    return Some(u64::saturating_add(baseline_ms, window_ms));
}