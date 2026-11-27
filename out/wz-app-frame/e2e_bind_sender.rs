// SCE-GENERATED — DO NOT EDIT
// source-hash: 40a7f327325a3bdaf8e080700dacc0d261a07cdd9534fb0b7e4a2cec67e222b6
// source: e2e_bind_sender.scxml
// SCE-MAP: e2e_bind_sender.scxml:20 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

use super::put_outcome;

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn e2e_bind_sender<const N0: usize, S0: ::sce_portable_bytes::MapStorage>(slots: &mut ::sce_portable_bytes::BoundedMap<u64, u32, N0, S0>, sender: u64, capacity: u32, largest: u64) -> bool {
    if sender > largest {
        return false;
    }
    if ::sce_portable_bytes::map::holds(&(*slots), &(sender)) {
        return false;
    }
    if ::sce_portable_bytes::map::count(&(*slots)) >= capacity {
        return false;
    }
    let next: u32 = ::sce_portable_bytes::map::count(&(*slots));
    let mut stored: put_outcome::PutOutcome = put_outcome::PutOutcome::Inserted;
    stored = match slots.put(sender, next) { ::sce_portable_bytes::PutOutcome::Inserted => put_outcome::PutOutcome::Inserted, ::sce_portable_bytes::PutOutcome::Replaced => put_outcome::PutOutcome::Replaced, ::sce_portable_bytes::PutOutcome::Full => put_outcome::PutOutcome::Full };
    return stored == put_outcome::PutOutcome::Inserted;
}