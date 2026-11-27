// SCE-GENERATED — DO NOT EDIT
// source-hash: 5e5c219e044d27dc8df0586cc4c7a6a0289321c88de0d5b24f7a443829f5e5e4
// source: abi_gate_verdict.scxml
// SCE-MAP: abi_gate_verdict.scxml:26 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn abi_gate_verdict(host_major: u32, plugin_major: u32, host_minor: u32, plugin_minor: u32, host_size: u32, plugin_size: u32, host_align: u32, plugin_align: u32) -> u8 {
    if plugin_major != host_major {
        return 1;
    }
    if plugin_minor > host_minor {
        return 2;
    }
    if plugin_size != host_size || plugin_align != host_align {
        return 3;
    }
    return 0;
}