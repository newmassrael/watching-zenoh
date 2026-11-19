// SCE-GENERATED — DO NOT EDIT
// source-hash: d4be575c838fab38b93b0c7e5652426a7cf552b96f4795b6a81ea11073158f08
// SCE-MAP: keyexpr_chunk_includes.scxml:16 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = false).

use super::keyexpr_range_equal;
use super::keyexpr_has_dsl;
use super::keyexpr_dsl_matches;

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn keyexpr_chunk_includes(a: &[u8], a_start: u32, a_end: u32, b: &[u8], b_start: u32, b_end: u32, wild_single: bool, wild_dsl: bool) -> bool {
    if a_end > (a).len() as u32 {
        return false;
    }
    if b_end > (b).len() as u32 {
        return false;
    }
    if keyexpr_range_equal::keyexpr_range_equal(a, a_start, a_end, b, b_start, b_end) {
        return true;
    }
    if a_start >= a_end || b_start >= b_end {
        return false;
    }
    if a[(a_start) as usize] == 64 || b[(b_start) as usize] == 64 {
        return false;
    }
    if wild_single {
        let a_next: u32 = a_start + 1;
        let b_next: u32 = b_start + 1;
        if a[(a_start) as usize] == 42 && a_next == a_end {
            return true;
        }
        if b[(b_start) as usize] == 42 && b_next == b_end {
            return false;
        }
    }
    if wild_dsl {
        if keyexpr_has_dsl::keyexpr_has_dsl(a, a_start, a_end) {
            return keyexpr_dsl_matches::keyexpr_dsl_matches(a, a_start, a_end, b, b_start, b_end);
        }
    }
    return false;
}