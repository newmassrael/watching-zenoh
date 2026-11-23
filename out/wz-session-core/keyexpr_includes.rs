// SCE-GENERATED — DO NOT EDIT
// source-hash: 74d8b0ae0fde75e18e0cd70046341ae9977d35a52c7f2c2cf010e61504590b70
// source: keyexpr_includes.scxml
// SCE-MAP: keyexpr_includes.scxml:27 :: _forge_body

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
use super::keyexpr_relation_dp;

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn keyexpr_includes(a: &[u8], b: &[u8], wild_single: bool, wild_double: bool, wild_dsl: bool, bounded: bool, chunk_bound: u32) -> bool {
    if !bounded {
        let quick: u8 = keyexpr_walk::keyexpr_walk(a, b, 2, wild_single, wild_double, wild_dsl);
        if quick != 2 {
            return quick == 1;
        }
    }
    let sa: keyexpr_shape_schema::KeyexprShapeSchemaPayload = keyexpr_shape::keyexpr_shape(a);
    let sb: keyexpr_shape_schema::KeyexprShapeSchemaPayload = keyexpr_shape::keyexpr_shape(b);
    let dsl: bool = wild_dsl && (sa.dollar || sb.dollar);
    if sa.chunks == 0 || sb.chunks == 0 {
        return false;
    }
    if bounded && (sa.chunks > chunk_bound || sb.chunks > chunk_bound) {
        return false;
    }
    let da: bool = wild_double && sa.double_star;
    let db: bool = wild_double && sb.double_star;
    if db {
        if !da {
            return false;
        }
        if sb.chunks <= 63 {
            return keyexpr_relation_dp::keyexpr_relation_dp(a, b, true, false, true, wild_single, dsl);
        }
        if sa.chunks <= 63 {
            return keyexpr_relation_dp::keyexpr_relation_dp(b, a, false, true, true, wild_single, dsl);
        }
        return false;
    }
    return keyexpr_walk::keyexpr_walk(a, b, 2, wild_single, wild_double, dsl) == 1;
}