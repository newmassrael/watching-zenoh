// SCE-GENERATED — DO NOT EDIT
// source-hash: d4be575c838fab38b93b0c7e5652426a7cf552b96f4795b6a81ea11073158f08
// SCE-MAP: keyexpr_matches.scxml:21 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = false).

use super::keyexpr_shape;
use super::keyexpr_shape_schema;
use super::keyexpr_walk;

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn keyexpr_matches(p: &[u8], t: &[u8], wild_single: bool, wild_double: bool, wild_dsl: bool, bounded: bool, chunk_bound: u32) -> bool {
    if !bounded {
        return keyexpr_walk::keyexpr_walk(p, t, 0, wild_single, wild_double, wild_dsl) == 1;
    }
    let sp: keyexpr_shape_schema::KeyexprShapeSchemaPayload = keyexpr_shape::keyexpr_shape(p);
    let st: keyexpr_shape_schema::KeyexprShapeSchemaPayload = keyexpr_shape::keyexpr_shape(t);
    if sp.chunks == 0 || st.chunks == 0 {
        return false;
    }
    if bounded && (sp.chunks > chunk_bound || st.chunks > chunk_bound) {
        return false;
    }
    return keyexpr_walk::keyexpr_walk(p, t, 0, wild_single, wild_double, wild_dsl && sp.dollar) == 1;
}