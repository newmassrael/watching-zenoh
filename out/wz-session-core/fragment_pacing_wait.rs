// SCE-GENERATED — DO NOT EDIT
// source-hash: be501a8f75001a53f577608864c2d9351b04e1d57602da0af21fa745fe329f32
// source: fragment_pacing_wait.scxml
// SCE-MAP: fragment_pacing_wait.scxml:25 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

use super::fragment_pacing_step;

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn fragment_pacing_wait(fragment: bool, run: u32, burst: u32, gap_us: u64, written_at_us: u64, now_us: u64) -> fragment_pacing_step::FragmentPacingStepPayload {
    if !fragment {
        let other = fragment_pacing_step::FragmentPacingStepPayload { wait_us: 0, run: 0 };
        return other;
    }
    if run >= burst {
        let held = fragment_pacing_step::FragmentPacingStepPayload { wait_us: u64::saturating_sub(gap_us, u64::saturating_sub(now_us, written_at_us)), run: 1 };
        return held;
    }
    let through = fragment_pacing_step::FragmentPacingStepPayload { wait_us: 0, run: u32::saturating_add(run, 1) };
    return through;
}