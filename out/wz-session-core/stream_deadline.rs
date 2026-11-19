// SCE-GENERATED — DO NOT EDIT
// source-hash: efe483b8c23efdefdaa54278e5db4cf384518b44642a21e3544dccee9803aa15
// SCE-MAP: stream_deadline.scxml:21 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn stream_deadline(period: u32, factor: u16) -> Option<u32> {
    let wide_period: u64 = period as u64;
    let wide_factor: u64 = factor as u64;
    let product: u64 = u64::saturating_mul(wide_period, wide_factor);
    if product >= 1 && product <= 2147483646 {
        return Some(product as u32);
    }
    return None;
}