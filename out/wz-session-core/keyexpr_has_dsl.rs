// SCE-GENERATED — DO NOT EDIT
// source-hash: 473894f67fb739cd03420443d3dc7c445f1759d433ac085bd61ffbe335846e9a
// source: keyexpr_has_dsl.scxml
// SCE-MAP: keyexpr_has_dsl.scxml:10 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: sce_forge_runtime
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = false).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn keyexpr_has_dsl(k: &[u8], s: u32, e: u32) -> bool {
    if e > k.len() as u32 {
        return false;
    }
    let mut i: u32 = s;
    while i < e {
        if sce_forge_runtime::algorithm::proven::at(&k, i) == 36 {
            let i1: u32 = sce_forge_runtime::algorithm::proven::add::<u32>(i, 1);
            if i1 < e {
                if sce_forge_runtime::algorithm::proven::at(&k, i1) == 42 {
                    return true;
                }
            }
        }
        i = sce_forge_runtime::algorithm::proven::add::<u32>(i, 1);
    }
    return false;
}