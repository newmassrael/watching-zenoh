// SCE-GENERATED — DO NOT EDIT
// source-hash: efe483b8c23efdefdaa54278e5db4cf384518b44642a21e3544dccee9803aa15
// SCE-MAP: keyexpr_includes_dp.scxml:26 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = false).

use super::keyexpr_chunk_end;
use super::keyexpr_chunk_kind;
use super::keyexpr_chunk_includes;

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn keyexpr_includes_dp(a: &[u8], b: &[u8], rows_b: bool, wild_single: bool, wild_dsl: bool) -> bool {
    let mut rn: u32 = (a).len() as u32;
    let mut cn: u32 = (b).len() as u32;
    if rows_b {
        rn = (b).len() as u32;
        cn = (a).len() as u32;
    }
    let one: u64 = 1;
    let mut prev: u64 = 1;
    let mut m: u32 = 0;
    let mut cs0: u32 = 0;
    let mut more0: bool = true;
    while more0 {
        let mut ce0: u32 = 0;
        let mut kind0: u8 = 0;
        if rows_b {
            ce0 = keyexpr_chunk_end::keyexpr_chunk_end(a, cs0);
            kind0 = keyexpr_chunk_kind::keyexpr_chunk_kind(a, cs0, ce0);
        } else {
            ce0 = keyexpr_chunk_end::keyexpr_chunk_end(b, cs0);
        }
        if m >= 63 {
            return false;
        }
        m = m + 1;
        if rows_b && kind0 == 2 {
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
        let mut re: u32 = 0;
        let mut rkind: u8 = 0;
        if rows_b {
            re = keyexpr_chunk_end::keyexpr_chunk_end(b, rs);
            rkind = keyexpr_chunk_kind::keyexpr_chunk_kind(b, rs, re);
        } else {
            re = keyexpr_chunk_end::keyexpr_chunk_end(a, rs);
            rkind = keyexpr_chunk_kind::keyexpr_chunk_kind(a, rs, re);
        }
        let mut cur: u64 = 0;
        if !rows_b && rkind == 2 && prev & 1 == 1 {
            cur = 1;
        }
        let mut j: u32 = 0;
        let mut cs: u32 = 0;
        let mut cmore: bool = true;
        while cmore && j < 63 {
            let mut ce: u32 = 0;
            let mut ckind: u8 = 0;
            if rows_b {
                ce = keyexpr_chunk_end::keyexpr_chunk_end(a, cs);
                ckind = keyexpr_chunk_kind::keyexpr_chunk_kind(a, cs, ce);
            } else {
                ce = keyexpr_chunk_end::keyexpr_chunk_end(b, cs);
                ckind = keyexpr_chunk_kind::keyexpr_chunk_kind(b, cs, ce);
            }
            let jb: u32 = j + 1;
            let up: bool = prev >> jb as u64 & 1 == 1;
            let left: bool = cur >> j as u64 & 1 == 1;
            let diag: bool = prev >> j as u64 & 1 == 1;
            let mut akind: u8 = rkind;
            let mut bkind: u8 = ckind;
            if rows_b {
                akind = ckind;
                bkind = rkind;
            }
            let mut v: bool = false;
            if akind == 2 {
                if rows_b {
                    v = left || bkind != 3 && up;
                } else {
                    v = up || bkind != 3 && left;
                }
            } else {
                if bkind != 2 && diag {
                    if rows_b {
                        v = keyexpr_chunk_includes::keyexpr_chunk_includes(a, cs, ce, b, rs, re, wild_single, wild_dsl);
                    } else {
                        v = keyexpr_chunk_includes::keyexpr_chunk_includes(a, rs, re, b, cs, ce, wild_single, wild_dsl);
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