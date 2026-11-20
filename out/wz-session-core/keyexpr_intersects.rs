// SCE-GENERATED — DO NOT EDIT
// source-hash: 340580b0c199e1888f810cbfa6b39b8a0ce86539fbd4279c75cc206a02538683
// source: keyexpr_intersects.scxml
// SCE-MAP: keyexpr_intersects.scxml:25 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = false).

use super::keyexpr_shape;
use super::keyexpr_shape_schema;
use super::keyexpr_range_equal;
use super::keyexpr_walk;
use super::keyexpr_intersects_dp;

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn keyexpr_intersects(a: &[u8], b: &[u8], wild_single: bool, wild_double: bool, wild_dsl: bool, bounded: bool, chunk_bound: u32) -> bool {
    if !bounded {
        let quick: u8 = keyexpr_walk::keyexpr_walk(a, b, 1, wild_single, wild_double, wild_dsl);
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
    if !sa.star && !sb.star {
        return keyexpr_range_equal::keyexpr_range_equal(a, 0, (a).len() as u32, b, 0, (b).len() as u32);
    }
    let da: bool = wild_double && sa.double_star;
    let db: bool = wild_double && sb.double_star;
    if da && db {
        if sb.chunks <= 63 {
            return keyexpr_intersects_dp::keyexpr_intersects_dp(a, b, wild_single, dsl);
        }
        if sa.chunks <= 63 {
            return keyexpr_intersects_dp::keyexpr_intersects_dp(b, a, wild_single, dsl);
        }
        return false;
    }
    if db {
        return keyexpr_walk::keyexpr_walk(b, a, 1, wild_single, wild_double, dsl) == 1;
    }
    return keyexpr_walk::keyexpr_walk(a, b, 1, wild_single, wild_double, dsl) == 1;
}