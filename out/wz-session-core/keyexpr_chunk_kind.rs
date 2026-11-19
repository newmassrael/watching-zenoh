// SCE-GENERATED — DO NOT EDIT
// source-hash: 74ceb15933f6fb51f993a6f4ed5c7e10715f96af9d47cdd107837aff17d2bd0c
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