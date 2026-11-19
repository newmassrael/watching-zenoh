// SCE-GENERATED — DO NOT EDIT
// source-hash: efe483b8c23efdefdaa54278e5db4cf384518b44642a21e3544dccee9803aa15
// SCE-MAP: keyexpr_shape.scxml:12 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = false).

use super::keyexpr_shape_schema;

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn keyexpr_shape(k: &[u8]) -> keyexpr_shape_schema::KeyexprShapeSchemaPayload {
    let n: u32 = (k).len() as u32;
    let mut chunks: u32 = 1;
    let mut empty: bool = n == 0;
    let mut star: bool = false;
    let mut double_star: bool = false;
    let mut dollar: bool = false;
    let mut run: u8 = 0;
    let mut stars: u8 = 0;
    for &byte in k.iter() {
        if byte == 47 {
            if run == 0 {
                empty = true;
            }
            if run == 2 && stars == 2 {
                double_star = true;
            }
            if chunks < n {
                chunks = chunks + 1;
            }
            run = 0;
            stars = 0;
        } else {
            if byte == 36 {
                dollar = true;
            }
            if byte == 42 {
                star = true;
                if stars < 3 {
                    stars = stars + 1;
                }
            }
            if run < 3 {
                run = run + 1;
            }
        }
    }
    if run == 0 {
        empty = true;
    }
    if run == 2 && stars == 2 {
        double_star = true;
    }
    let shape = keyexpr_shape_schema::KeyexprShapeSchemaPayload { chunks: if empty { 0 } else { chunks }, star: star, double_star: double_star, dollar: dollar };
    return shape;
}