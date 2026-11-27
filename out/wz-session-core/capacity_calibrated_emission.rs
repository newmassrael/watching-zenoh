// SCE-GENERATED — DO NOT EDIT
// source-hash: d3787f22ace86a3ac3238509c75ab5f658d7cfd60c75c48fbc2ff70612921bc4
// source: capacity_calibrated_emission.scxml
// SCE-MAP: capacity_calibrated_emission.scxml:17 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: sce_forge_runtime
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn capacity_calibrated_emission(recorded_ns: u64, measured_floor_ns: Option<u64>, headroom_percent: u64) -> u64 {
    if measured_floor_ns.is_some() {
        let with_room: u64 = sce_forge_runtime::algorithm::proven::div::<u64>(u64::saturating_mul(sce_forge_runtime::optional::proven(measured_floor_ns), headroom_percent), 100);
        if with_room > recorded_ns {
            return with_room;
        }
    }
    return recorded_ns;
}