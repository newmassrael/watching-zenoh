// SCE-GENERATED — DO NOT EDIT
// source-hash: fd580feb56346aee457e031610a4f1ed1ac81ad04364e98242eec177d0c0d129
// source: keyexpr_relation_dp.scxml
// SCE-MAP: keyexpr_relation_dp.scxml:36 :: _forge_body

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
use super::keyexpr_chunk_includes;

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn keyexpr_relation_dp(r: &[u8], c: &[u8], row_star: bool, col_star: bool, includes: bool, wild_single: bool, wild_dsl: bool) -> bool {
    let rn: u32 = (r).len() as u32;
    let cn: u32 = (c).len() as u32;
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
        if col_star && keyexpr_chunk_kind::keyexpr_chunk_kind(c, cs0, ce0) == 2 {
            let below0: u32 = m - 1;
            if prev >> below0 & 1 == 1 {
                prev = prev | 1u64 << m;
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
        if row_star && rkind == 2 && prev & 1 == 1 {
            cur = 1;
        }
        let mut j: u32 = 0;
        let mut cs: u32 = 0;
        let mut cmore: bool = true;
        while cmore && j < 63 {
            let ce: u32 = keyexpr_chunk_end::keyexpr_chunk_end(c, cs);
            let ckind: u8 = keyexpr_chunk_kind::keyexpr_chunk_kind(c, cs, ce);
            let jb: u32 = j + 1;
            let up: bool = prev >> jb & 1 == 1;
            let left: bool = cur >> j & 1 == 1;
            let diag: bool = prev >> j & 1 == 1;
            let mut v: bool = false;
            if row_star && rkind == 2 {
                v = up || ckind != 3 && left;
            } else {
                if col_star && ckind == 2 {
                    v = left || rkind != 3 && up;
                } else {
                    if rkind != 2 && ckind != 2 && diag {
                        if includes {
                            if row_star {
                                v = keyexpr_chunk_includes::keyexpr_chunk_includes(r, rs, re, c, cs, ce, wild_single, wild_dsl);
                            } else {
                                v = keyexpr_chunk_includes::keyexpr_chunk_includes(c, cs, ce, r, rs, re, wild_single, wild_dsl);
                            }
                        } else {
                            v = keyexpr_chunk_intersects::keyexpr_chunk_intersects(r, rs, re, c, cs, ce, wild_single, wild_dsl);
                        }
                    }
                }
            }
            if v {
                cur = cur | 1u64 << jb;
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
    return prev >> m & 1 == 1;
}