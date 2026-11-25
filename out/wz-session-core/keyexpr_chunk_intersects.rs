// SCE-GENERATED — DO NOT EDIT
// source-hash: c99186ca2600b1cfaf38adeff3769ef130a3a3218a5f4e8e13ad06da9059aab6
// source: keyexpr_chunk_intersects.scxml
// SCE-MAP: keyexpr_chunk_intersects.scxml:17 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: sce_forge_runtime
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
pub fn keyexpr_chunk_intersects(a: &[u8], a_start: u32, a_end: u32, b: &[u8], b_start: u32, b_end: u32, wild_single: bool, wild_dsl: bool) -> bool {
    if a_end > a.len() as u32 {
        return false;
    }
    if b_end > b.len() as u32 {
        return false;
    }
    if a_start >= a_end {
        return keyexpr_range_equal::keyexpr_range_equal(a, a_start, a_end, b, b_start, b_end);
    }
    if b_start >= b_end {
        return false;
    }
    if keyexpr_range_equal::keyexpr_range_equal(a, a_start, a_end, b, b_start, b_end) {
        return true;
    }
    if sce_forge_runtime::algorithm::proven::at(&a, a_start) == 64 || sce_forge_runtime::algorithm::proven::at(&b, b_start) == 64 {
        return false;
    }
    if wild_single {
        let a_next: u32 = sce_forge_runtime::algorithm::proven::add::<u32>(a_start, 1);
        let b_next: u32 = sce_forge_runtime::algorithm::proven::add::<u32>(b_start, 1);
        if sce_forge_runtime::algorithm::proven::at(&a, a_start) == 42 && a_next == a_end {
            return true;
        }
        if sce_forge_runtime::algorithm::proven::at(&b, b_start) == 42 && b_next == b_end {
            return true;
        }
    }
    if !wild_dsl {
        return false;
    }
    let a_dsl: bool = keyexpr_has_dsl::keyexpr_has_dsl(a, a_start, a_end);
    let b_dsl: bool = keyexpr_has_dsl::keyexpr_has_dsl(b, b_start, b_end);
    if a_dsl && !b_dsl {
        return keyexpr_dsl_matches::keyexpr_dsl_matches(a, a_start, a_end, b, b_start, b_end);
    }
    if b_dsl && !a_dsl {
        return keyexpr_dsl_matches::keyexpr_dsl_matches(b, b_start, b_end, a, a_start, a_end);
    }
    if !a_dsl {
        return false;
    }
    let mut a_lead_end: u32 = a_end;
    let mut a_trail: u32 = a_start;
    let mut a_seen: bool = false;
    let mut ai: u32 = a_start;
    while ai < a_end {
        let ai1: u32 = sce_forge_runtime::algorithm::proven::add::<u32>(ai, 1);
        let mut a_step: u32 = ai1;
        if ai1 < a_end {
            if sce_forge_runtime::algorithm::proven::at(&a, ai) == 36 && sce_forge_runtime::algorithm::proven::at(&a, ai1) == 42 {
                if !a_seen {
                    a_lead_end = ai;
                    a_seen = true;
                }
                a_trail = sce_forge_runtime::algorithm::proven::add::<u32>(ai1, 1);
                a_step = sce_forge_runtime::algorithm::proven::add::<u32>(ai1, 1);
            }
        }
        ai = a_step;
    }
    let mut b_lead_end: u32 = b_end;
    let mut b_trail: u32 = b_start;
    let mut b_seen: bool = false;
    let mut bi: u32 = b_start;
    while bi < b_end {
        let bi1: u32 = sce_forge_runtime::algorithm::proven::add::<u32>(bi, 1);
        let mut b_step: u32 = bi1;
        if bi1 < b_end {
            if sce_forge_runtime::algorithm::proven::at(&b, bi) == 36 && sce_forge_runtime::algorithm::proven::at(&b, bi1) == 42 {
                if !b_seen {
                    b_lead_end = bi;
                    b_seen = true;
                }
                b_trail = sce_forge_runtime::algorithm::proven::add::<u32>(bi1, 1);
                b_step = sce_forge_runtime::algorithm::proven::add::<u32>(bi1, 1);
            }
        }
        bi = b_step;
    }
    let mut la: u32 = a_start;
    let mut lb: u32 = b_start;
    while la < a_lead_end && lb < b_lead_end {
        if la >= a_end || lb >= b_end {
            return false;
        }
        if sce_forge_runtime::algorithm::proven::at(&a, la) != sce_forge_runtime::algorithm::proven::at(&b, lb) {
            return false;
        }
        la = sce_forge_runtime::algorithm::proven::add::<u32>(la, 1);
        lb = sce_forge_runtime::algorithm::proven::add::<u32>(lb, 1);
    }
    let mut ts_a: u32 = a_trail;
    while ts_a < a_end {
        if keyexpr_range_equal::keyexpr_range_equal(a, ts_a, a_end, b, b_trail, b_end) {
            return true;
        }
        ts_a = sce_forge_runtime::algorithm::proven::add::<u32>(ts_a, 1);
    }
    let mut ts_b: u32 = b_trail;
    while ts_b < b_end {
        if keyexpr_range_equal::keyexpr_range_equal(b, ts_b, b_end, a, a_trail, a_end) {
            return true;
        }
        ts_b = sce_forge_runtime::algorithm::proven::add::<u32>(ts_b, 1);
    }
    return a_trail >= a_end || b_trail >= b_end;
}