// SCE-GENERATED — DO NOT EDIT
// source-hash: efe483b8c23efdefdaa54278e5db4cf384518b44642a21e3544dccee9803aa15
// SCE-MAP: replay_reply_admission.scxml:30 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn replay_reply_admission(counter: u64, baseline: u64, mask: u64, depth: u64, same_crc: bool) -> u8 {
    let behind: u64 = u64::wrapping_sub(baseline, counter) & mask;
    if behind == 0 {
        if same_crc {
            return 1;
        }
        return 0;
    }
    if behind < depth {
        return 2;
    }
    return 0;
}