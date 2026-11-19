// SCE-GENERATED — DO NOT EDIT
// source-hash: cc02b4dba071f4fdc21b539ee37b42dc67d2f985b8209cb58f3f55cbe8bcbd24
// SCE-MAP: keyexpr_has_dsl.scxml:10 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = false).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn keyexpr_has_dsl(k: &[u8], s: u32, e: u32) -> bool {
    if e > (k).len() as u32 {
        return false;
    }
    let mut i: u32 = s;
    while i < e {
        if k[(i) as usize] == 36 {
            let i1: u32 = i + 1;
            if i1 < e {
                if k[(i1) as usize] == 42 {
                    return true;
                }
            }
        }
        i = i + 1;
    }
    return false;
}