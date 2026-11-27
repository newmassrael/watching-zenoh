// SCE-GENERATED — DO NOT EDIT
// source-hash: 0a667fed7bdf3f580023ad76fe1a7627e5909a757b0046946312c6201516d4a1
// source: counter_after.scxml
// SCE-MAP: counter_after.scxml:27 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn counter_after(sent: u64, largest: u64, restarts: bool, restart_at: u64) -> Option<u64> {
    if sent < largest {
        return Some(u64::wrapping_add(sent, 1));
    }
    if restarts {
        return Some(restart_at);
    }
    return None;
}