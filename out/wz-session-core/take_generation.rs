// SCE-GENERATED — DO NOT EDIT
// source-hash: b287ce35d82bf97c72c9a70bce8b512384fbab9d808b9ad8e67b8384c9e2c84e
// source: take_generation.scxml
// SCE-MAP: take_generation.scxml:18 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

use super::reset_peer_schema;
use super::take_generation_duplicate;
use super::take_generation_result;
use super::put_outcome;

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn take_generation<const N0: usize>(resets: &mut ::sce_portable_bytes::BoundedMap<reset_peer_schema::ResetPeerSchemaPayload, u64, N0>, peer: reset_peer_schema::ResetPeerSchemaPayload, generation: u64) -> take_generation_result::TakeGenerationResult {
    if ::sce_portable_bytes::map::holds(&(*resets), &(peer)) && ::sce_portable_bytes::map::held_cloned(&(*resets), &(peer)) >= generation {
        let duplicate = take_generation_result::TakeGenerationResult::Duplicate(take_generation_duplicate::TakeGenerationDuplicatePayload { last: ::sce_portable_bytes::map::held_cloned(&(*resets), &(peer)) });
        return duplicate;
    }
    let mut stored: put_outcome::PutOutcome = put_outcome::PutOutcome::Inserted;
    stored = match resets.put(peer, generation) { ::sce_portable_bytes::PutOutcome::Inserted => put_outcome::PutOutcome::Inserted, ::sce_portable_bytes::PutOutcome::Replaced => put_outcome::PutOutcome::Replaced, ::sce_portable_bytes::PutOutcome::Full => put_outcome::PutOutcome::Full };
    if stored == put_outcome::PutOutcome::Full {
        let no_room = take_generation_result::TakeGenerationResult::NoRoom;
        return no_room;
    }
    let taken = take_generation_result::TakeGenerationResult::Taken;
    return taken;
}