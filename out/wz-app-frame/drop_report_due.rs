// SCE-GENERATED — DO NOT EDIT
// source-hash: c2ec2763bf0af88a68a8919d1b0400152d4a4b3ec1e41f533996ba2c4251cbf2
// source: drop_report_due.scxml
// SCE-MAP: drop_report_due.scxml:22 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn drop_report_due(pending: u64, has_last: bool, last_ms: u64, now_ms: u64, interval_ms: u64) -> u8 {
    if pending == 0 {
        return 0;
    }
    if !has_last {
        return 1;
    }
    if now_ms < last_ms {
        return 2;
    }
    if u64::saturating_sub(now_ms, last_ms) >= interval_ms {
        return 1;
    }
    return 0;
}