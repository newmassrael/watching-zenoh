// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The configuration sequence of the LAN8650/1 configuration application note
//! (AN1760, DS60001760G, June 2024).
//!
//! The data sheet leaves the startup configuration to this note (DS60001734F
//! 4.1.2: "the latest recommended startup configuration can be found in" AN1760),
//! and the note says its accesses "must be written immediately following a power
//! cycle or reset of the device and should be performed in the sequence provided".
//! It gives ONE sequence for product revisions B0 and B1, and for newer parts
//! until a newer revision of the note supersedes it. If the note is revised, this
//! module is what to re-read it against.
//!
//! Out of scope, on purpose: the optional SQI table (AN1760 Table 2), which only a
//! host that reads signal quality needs.

use crate::regs::{INDIRECT_ADDRESS, INDIRECT_CONTROL, INDIRECT_DATA};
use wz_oa_tc6::proto::Reg;
use wz_oa_tc6::{Error, Tc6};
use wz_runtime_core::SpiTransfer;

/// The number of register writes in AN1760 Table 1.
pub(crate) const TABLE1_LEN: usize = 20;

/// The device parameters the note has the host read before it writes anything:
/// the signed offsets found at indirect addresses 0x04 and 0x08.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Offsets {
    pub offset1: i8,
    pub offset2: i8,
}

/// The note's `indirect_read(addr, mask)`: write the address, write 2 to start
/// the read, read the result and mask it. "Proprietary access mechanism"; not the
/// clause 22 indirect access to clause 45 registers.
fn indirect_read<S: SpiTransfer>(
    tc6: &mut Tc6<S>,
    addr: u8,
    mask: u8,
) -> Result<u8, Error<S::Error>> {
    tc6.reg_write(INDIRECT_ADDRESS, u32::from(addr))?;
    tc6.reg_write(INDIRECT_CONTROL, 0x2)?;
    let value = tc6.reg_read(INDIRECT_DATA)?;
    Ok((value & u32::from(mask)) as u8)
}

/// A value the note stores as a signed 5-bit quantity: bit 4 is the sign, and a
/// set sign bit means the value minus 0x20. `raw` is at most 0x1F, which the mask
/// on the indirect read guarantees; the note does not mask it a second time.
pub(crate) const fn signed5(raw: u8) -> i8 {
    debug_assert!(raw <= 0x1F);
    if raw & 0x10 != 0 {
        raw as i8 - 0x20
    } else {
        raw as i8
    }
}

/// Read both offsets (AN1760, "Calculation of configuration parameters"):
/// `value1` at indirect address 0x04 and `value2` at 0x08, each masked to five bits.
pub(crate) fn read_offsets<S: SpiTransfer>(tc6: &mut Tc6<S>) -> Result<Offsets, Error<S::Error>> {
    let value1 = indirect_read(tc6, 0x04, 0x1F)?;
    let value2 = indirect_read(tc6, 0x08, 0x1F)?;
    Ok(Offsets {
        offset1: signed5(value1),
        offset2: signed5(value2),
    })
}

/// `(base + offset) & 0x3F`: the note masks to six bits, which for a negative sum
/// keeps its two's complement low bits.
const fn field6(base: i16, offset: i8) -> u16 {
    ((base + offset as i16) & 0x3F) as u16
}

/// `cfgparam1 = ((9 + offset1) & 0x3F) << 10 | ((14 + offset1) & 0x3F) << 4 | 0x03`.
pub(crate) const fn cfgparam1(offset1: i8) -> u16 {
    (field6(9, offset1) << 10) | (field6(14, offset1) << 4) | 0x03
}

/// `cfgparam2 = ((40 + offset2) & 0x3F) << 10`.
pub(crate) const fn cfgparam2(offset2: i8) -> u16 {
    field6(40, offset2) << 10
}

/// AN1760 Table 1, "Configuration register writes", in the document's order: "a
/// series of parameters that must be configured with the given values and in the
/// order listed". Every entry is a write. The values for 0x0084 and 0x008A are the
/// two computed parameters; the entry at MMS 1, 0x0077 is the MAC timer increment
/// (40 ns, a 25 MHz timer clock), which DS60001734F 6.4.9 confirms as 0x28.
pub(crate) const fn table1(cfgparam1: u16, cfgparam2: u16) -> [(Reg, u16); TABLE1_LEN] {
    [
        (Reg::new(4, 0x00D0), 0x3F31),
        (Reg::new(4, 0x00E0), 0xC000),
        (Reg::new(4, 0x0084), cfgparam1),
        (Reg::new(4, 0x008A), cfgparam2),
        (Reg::new(4, 0x00E9), 0x9E50),
        (Reg::new(4, 0x00F5), 0x1CF8),
        (Reg::new(4, 0x00F4), 0xC020),
        (Reg::new(4, 0x00F8), 0xB900),
        (Reg::new(4, 0x00F9), 0x4E53),
        (Reg::new(4, 0x0081), 0x0080),
        (Reg::new(4, 0x0091), 0x9660),
        (Reg::new(1, 0x0077), 0x0028),
        (Reg::new(4, 0x0043), 0x00FF),
        (Reg::new(4, 0x0044), 0xFFFF),
        (Reg::new(4, 0x0045), 0x0000),
        (Reg::new(4, 0x0053), 0x00FF),
        (Reg::new(4, 0x0054), 0xFFFF),
        (Reg::new(4, 0x0055), 0x0000),
        (Reg::new(4, 0x0040), 0x0002),
        (Reg::new(4, 0x0050), 0x0002),
    ]
}

/// Run the whole note: the two indirect reads, then Table 1.
pub(crate) fn apply<S: SpiTransfer>(tc6: &mut Tc6<S>) -> Result<(), Error<S::Error>> {
    let offsets = read_offsets(tc6)?;
    let writes = table1(cfgparam1(offsets.offset1), cfgparam2(offsets.offset2));
    for (reg, value) in writes {
        tc6.reg_write(reg, u32::from(value))?;
    }
    Ok(())
}
