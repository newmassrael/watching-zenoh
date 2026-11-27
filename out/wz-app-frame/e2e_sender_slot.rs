// SCE-GENERATED — DO NOT EDIT
// source-hash: 933b484e9cf77cfc61202f340cee25de9ae44d6f2b87ecc0196bb432f0c58d2a
// source: e2e_sender_slot.scxml
// SCE-MAP: e2e_sender_slot.scxml:26 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

use super::e2e_sender_slot_held;
use super::e2e_sender_slot_result;
use super::put_outcome;

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn e2e_sender_slot<const N0: usize, S0: ::sce_portable_bytes::MapStorage>(slots: &mut ::sce_portable_bytes::BoundedMap<u64, u32, N0, S0>, sender: u64, intact: bool, bound: bool, capacity: u32) -> e2e_sender_slot_result::E2eSenderSlotResult {
    if ::sce_portable_bytes::map::holds(&(*slots), &(sender)) {
        let held = e2e_sender_slot_result::E2eSenderSlotResult::Slotted(e2e_sender_slot_held::E2eSenderSlotHeldPayload { slot: ::sce_portable_bytes::map::held_cloned(&(*slots), &(sender)) });
        return held;
    }
    if bound {
        let not_listed = e2e_sender_slot_result::E2eSenderSlotResult::NotListed;
        return not_listed;
    }
    if !intact {
        let no_claim = e2e_sender_slot_result::E2eSenderSlotResult::NoClaim;
        return no_claim;
    }
    let full = e2e_sender_slot_result::E2eSenderSlotResult::Full;
    if ::sce_portable_bytes::map::count(&(*slots)) >= capacity {
        return full;
    }
    let next: u32 = ::sce_portable_bytes::map::count(&(*slots));
    let mut stored: put_outcome::PutOutcome = put_outcome::PutOutcome::Inserted;
    stored = match slots.put(sender, next) { ::sce_portable_bytes::PutOutcome::Inserted => put_outcome::PutOutcome::Inserted, ::sce_portable_bytes::PutOutcome::Replaced => put_outcome::PutOutcome::Replaced, ::sce_portable_bytes::PutOutcome::Full => put_outcome::PutOutcome::Full };
    if stored == put_outcome::PutOutcome::Full {
        return full;
    }
    let taken = e2e_sender_slot_result::E2eSenderSlotResult::Slotted(e2e_sender_slot_held::E2eSenderSlotHeldPayload { slot: next });
    return taken;
}