// SCE-GENERATED — DO NOT EDIT
// source-hash: 74ceb15933f6fb51f993a6f4ed5c7e10715f96af9d47cdd107837aff17d2bd0c
// SCE-MAP: keyexpr_range_equal.scxml:11 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = false).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn keyexpr_range_equal(a: &[u8], a_start: u32, a_end: u32, b: &[u8], b_start: u32, b_end: u32) -> bool {
    if a_end > (a).len() as u32 {
        return false;
    }
    if b_end > (b).len() as u32 {
        return false;
    }
    let mut i: u32 = a_start;
    let mut j: u32 = b_start;
    while i < a_end && j < b_end {
        if a[(i) as usize] != b[(j) as usize] {
            return false;
        }
        i = i + 1;
        j = j + 1;
    }
    return i == a_end && j == b_end;
}