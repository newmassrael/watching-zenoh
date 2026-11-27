// SCE-GENERATED — DO NOT EDIT
// source-hash: 905c5b3ff70a702e0307b1003447bbf3bcd18581826fea9ac7497e8a6e49077c
// source: capacity_quotient.scxml
// SCE-MAP: capacity_quotient.scxml:16 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: sce_forge_runtime
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn capacity_quotient(numerator: u64, denominator: u64) -> u64 {
    if denominator != 0 {
        return sce_forge_runtime::algorithm::proven::div::<u64>(numerator, denominator);
    }
    return 18446744073709551615;
}