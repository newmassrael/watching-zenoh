// SCE-GENERATED — DO NOT EDIT
// source-hash: cc02b4dba071f4fdc21b539ee37b42dc67d2f985b8209cb58f3f55cbe8bcbd24
// SCE-MAP: keyexpr_intersects_dp.scxml:23 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = false).

use super::keyexpr_chunk_end;
use super::keyexpr_chunk_kind;
use super::keyexpr_chunk_intersects;

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn keyexpr_intersects_dp(r: &[u8], c: &[u8], wild_single: bool, wild_dsl: bool) -> bool {
    let rn: u32 = (r).len() as u32;
    let cn: u32 = (c).len() as u32;
    let one: u64 = 1;
    let mut prev: u64 = 1;
    let mut m: u32 = 0;
    let mut cs0: u32 = 0;
    let mut more0: bool = true;
    while more0 {
        let ce0: u32 = keyexpr_chunk_end::keyexpr_chunk_end(c, cs0);
        if m >= 63 {
            return false;
        }
        m = m + 1;
        if keyexpr_chunk_kind::keyexpr_chunk_kind(c, cs0, ce0) == 2 {
            let below0: u32 = m - 1;
            if prev >> below0 as u64 & 1 == 1 {
                prev = prev | one << m as u64;
            }
        }
        if ce0 < cn {
            cs0 = ce0 + 1;
        } else {
            more0 = false;
        }
    }
    let mut rs: u32 = 0;
    let mut rmore: bool = true;
    while rmore {
        let re: u32 = keyexpr_chunk_end::keyexpr_chunk_end(r, rs);
        let rkind: u8 = keyexpr_chunk_kind::keyexpr_chunk_kind(r, rs, re);
        let mut cur: u64 = 0;
        if rkind == 2 && prev & 1 == 1 {
            cur = 1;
        }
        let mut j: u32 = 0;
        let mut cs: u32 = 0;
        let mut cmore: bool = true;
        while cmore && j < 63 {
            let ce: u32 = keyexpr_chunk_end::keyexpr_chunk_end(c, cs);
            let ckind: u8 = keyexpr_chunk_kind::keyexpr_chunk_kind(c, cs, ce);
            let jb: u32 = j + 1;
            let up: bool = prev >> jb as u64 & 1 == 1;
            let left: bool = cur >> j as u64 & 1 == 1;
            let diag: bool = prev >> j as u64 & 1 == 1;
            let mut v: bool = false;
            if rkind == 2 {
                v = up || ckind != 3 && left;
            } else {
                if ckind == 2 {
                    v = left || rkind != 3 && up;
                } else {
                    if diag {
                        v = keyexpr_chunk_intersects::keyexpr_chunk_intersects(r, rs, re, c, cs, ce, wild_single, wild_dsl);
                    }
                }
            }
            if v {
                cur = cur | one << jb as u64;
            }
            j = jb;
            if ce < cn {
                cs = ce + 1;
            } else {
                cmore = false;
            }
        }
        prev = cur;
        if re < rn {
            rs = re + 1;
        } else {
            rmore = false;
        }
    }
    return prev >> m as u64 & 1 == 1;
}