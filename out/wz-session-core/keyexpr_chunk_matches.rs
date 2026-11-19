// SCE-GENERATED — DO NOT EDIT
// source-hash: d4be575c838fab38b93b0c7e5652426a7cf552b96f4795b6a81ea11073158f08
// SCE-MAP: keyexpr_chunk_matches.scxml:13 :: _forge_body

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
pub fn keyexpr_chunk_matches(p: &[u8], p_start: u32, p_end: u32, t: &[u8], t_start: u32, t_end: u32, wild_dsl: bool) -> bool {
    if p_end > (p).len() as u32 {
        return false;
    }
    if t_end > (t).len() as u32 {
        return false;
    }
    if keyexpr_range_equal::keyexpr_range_equal(p, p_start, p_end, t, t_start, t_end) {
        return true;
    }
    if p_start < p_end {
        if p[(p_start) as usize] == 64 {
            return false;
        }
    }
    if t_start < t_end {
        if t[(t_start) as usize] == 64 {
            return false;
        }
    }
    if wild_dsl {
        if keyexpr_has_dsl::keyexpr_has_dsl(p, p_start, p_end) {
            return keyexpr_dsl_matches::keyexpr_dsl_matches(p, p_start, p_end, t, t_start, t_end);
        }
    }
    return false;
}