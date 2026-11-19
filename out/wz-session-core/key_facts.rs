// SCE-GENERATED — DO NOT EDIT
// source-hash: 74ceb15933f6fb51f993a6f4ed5c7e10715f96af9d47cdd107837aff17d2bd0c
// SCE-MAP: key_facts.scxml:26 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = false).

use super::key_facts_schema;

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn key_facts(text: &[u8], bounded: bool, chunk_bound: u32) -> key_facts_schema::KeyFactsSchemaPayload {
    let mut wild: bool = false;
    let mut doubled: bool = false;
    let mut slashes: u32 = 0;
    let mut seen: bool = false;
    let mut first: u8 = 0;
    let mut previous: u8 = 0;
    for &b in text.iter() {
        if !seen {
            first = b;
            seen = true;
        }
        if b == 42 {
            wild = true;
        }
        if b == 47 {
            if previous == 47 {
                doubled = true;
            }
            if slashes < chunk_bound {
                slashes = slashes + 1;
            }
        }
        previous = b;
    }
    let facts = key_facts_schema::KeyFactsSchemaPayload { wild: wild, key: seen && first != 47 && previous != 47 && !doubled && (!bounded || slashes < chunk_bound) };
    return facts;
}