// SCE-GENERATED — DO NOT EDIT
// source-hash: 50e978a6d89492f4cb0aebb3f5b2f4bc0fc02f2ce83c18c1e0fb2ff6bf98b4f4
// source: keyexpr_chunk_end.scxml
// SCE-MAP: keyexpr_chunk_end.scxml:10 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = false).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn keyexpr_chunk_end(k: &[u8], s: u32) -> u32 {
    let n: u32 = (k).len() as u32;
    if s > n {
        return n;
    }
    let mut i: u32 = s;
    while i < n && k[(i) as usize] != 47 {
        i = i + 1;
    }
    return i;
}