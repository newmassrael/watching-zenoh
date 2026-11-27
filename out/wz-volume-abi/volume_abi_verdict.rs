// SCE-GENERATED — DO NOT EDIT
// source-hash: 24673dfbf2b32b8574ea95ca31a3a986583de0657b917779bda5fea9d3988952
// source: volume_abi_verdict.scxml
// SCE-MAP: volume_abi_verdict.scxml:19 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

use super::abi_gate_verdict;

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn volume_abi_verdict(host_major: u32, volume_major: u32, host_minor: u32, volume_minor: u32, host_vtable_size: u32, volume_vtable_size: u32, host_vtable_align: u32, volume_vtable_align: u32, host_entry_size: u32, volume_entry_size: u32, host_entry_align: u32, volume_entry_align: u32) -> u8 {
    let table: u8 = abi_gate_verdict::abi_gate_verdict(host_major, volume_major, host_minor, volume_minor, host_vtable_size, volume_vtable_size, host_vtable_align, volume_vtable_align);
    if table != 0 {
        return table;
    }
    if volume_entry_size != host_entry_size || volume_entry_align != host_entry_align {
        return 4;
    }
    return 0;
}