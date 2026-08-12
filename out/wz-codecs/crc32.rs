// SCE-MAP: crc32:49 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = false).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &b in data.iter() {
        let bb: u32 = b as u32;
        crc = crc ^ bb;
        let mut i: u8 = 0;
        while i < 8 {
            if crc & 1 != 0 {
                crc = crc >> 1 ^ 0x04C11DB7;
            } else {
                crc = crc >> 1;
            }
            i = i + 1;
        }
    }
    return crc ^ 0xFFFFFFFF;
}