// SCE-GENERATED — DO NOT EDIT
// source-hash: b1360944a7b6325d1b5c25dd3bb91f9b2346352f6fe75b0c68116cc6d9f1a96b
// source: timestamping_enabled_for.scxml
// SCE-MAP: timestamping_enabled_for.scxml:19 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn timestamping_enabled_for(role: u8, router: bool, peer: bool, client: bool) -> bool {
    if role == 1 {
        return router;
    }
    if role == 2 {
        return peer;
    }
    if role == 4 {
        return client;
    }
    return false;
}