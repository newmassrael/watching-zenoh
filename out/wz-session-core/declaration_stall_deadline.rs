// SCE-GENERATED — DO NOT EDIT
// source-hash: d4be575c838fab38b93b0c7e5652426a7cf552b96f4795b6a81ea11073158f08
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