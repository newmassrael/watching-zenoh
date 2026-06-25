// SCE-MAP: cobs_decode:53

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = false).

use sce_portable_bytes::{SceBytes, CapacityExceeded};

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn cobs_decode(data: &[u8]) -> Result<SceBytes<1507>, CapacityExceeded> {
    let n: u16 = (data).len() as u16;
    let mut out: SceBytes<1507> = SceBytes::new();
    let mut i: u16 = 0;
    let mut prev: u16 = 255;
    let mut done: bool = false;
    while i < n && done == false {
        let code: u16 = data[(i) as usize] as u16;
        i = i + 1;
        if code == 0 {
            done = true;
        } else {
            if prev != 255 {
                let z: u8 = 0;
                out.push(z)?;
            }
            let mut j: u16 = 1;
            while j < code {
                out.push(data[(i) as usize])?;
                i = i + 1;
                j = j + 1;
            }
            prev = code;
        }
    }
    return Ok(out);
}