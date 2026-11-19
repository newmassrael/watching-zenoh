// SCE-GENERATED — DO NOT EDIT
// source-hash: cc02b4dba071f4fdc21b539ee37b42dc67d2f985b8209cb58f3f55cbe8bcbd24
// SCE-MAP: keyexpr_chunk_kind.scxml:12 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = false).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn keyexpr_chunk_kind(k: &[u8], s: u32, e: u32) -> u8 {
    if e > (k).len() as u32 {
        return 0;
    }
    if s >= e {
        return 0;
    }
    if k[(s) as usize] == 64 {
        return 3;
    }
    if k[(s) as usize] != 42 {
        return 0;
    }
    let s1: u32 = s + 1;
    if s1 >= e {
        return 1;
    }
    if k[(s1) as usize] != 42 {
        return 0;
    }
    let s2: u32 = s1 + 1;
    if s2 >= e {
        return 2;
    }
    return 0;
}