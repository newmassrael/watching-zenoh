// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The LAN8650/1 registers this crate touches, by memory map selector (MMS) and
//! address, with the document each one comes from.
//!
//! "DS" is the data sheet DS60001734F and "AN1760" the configuration application
//! note DS60001760G. The registers AN1760 reaches by address alone (the
//! configuration table and the indirect-read handshake) are not described in the
//! data sheet, which points to the application note for them; they are written
//! as the note gives them and carry no names here.

use wz_oa_tc6::proto::Reg;

// ---- identity (MMS 10) ------------------------------------------------------

/// Device Identification, DS 11.6.6; its address and MMS are also the work-around
/// of errata item s1 (DS80001075F 1.1). `MODEL` is bits 19:4 and `REV` bits 3:0.
pub const DEVID: Reg = Reg::new(10, 0x0094);

// ---- MAC (MMS 1, DS 11.2) ---------------------------------------------------

/// MAC Network Control Register.
pub const MAC_NCR: Reg = Reg::new(1, 0x0000);
/// MAC Network Configuration Register. Its reset value is `0x0008_0000`: bit 19 is
/// not a named field and "reserved fields must be written with their default
/// value" (DS 11.2.2), so it is modified, not overwritten.
pub const MAC_NCFGR: Reg = Reg::new(1, 0x0001);
/// MAC Hash Register Bottom (hash index 31:0).
pub const MAC_HRB: Reg = Reg::new(1, 0x0020);
/// MAC Hash Register Top (hash index 63:32).
pub const MAC_HRT: Reg = Reg::new(1, 0x0021);
/// MAC Specific Address 1 Bottom: address bytes 0..=3, byte 0 in bits 7:0. Writing
/// it deactivates the address (DS 11.2.5).
pub const MAC_SAB1: Reg = Reg::new(1, 0x0022);
/// MAC Specific Address 1 Top: address bytes 4 and 5, byte 4 in bits 7:0. Writing
/// it activates the address (DS 11.2.6).
pub const MAC_SAT1: Reg = Reg::new(1, 0x0023);

/// `MAC_NCR.TXEN`: the transmitter is enabled.
pub const NCR_TXEN: u32 = 1 << 3;
/// `MAC_NCR.RXEN`: the receiver is enabled.
pub const NCR_RXEN: u32 = 1 << 2;
/// `MAC_NCFGR.RFCS`: received frames are handed to the host without their FCS.
pub const NCFGR_RFCS: u32 = 1 << 17;
/// `MAC_NCFGR.MTIHEN`: multicast frames are accepted when the hash register
/// selects them.
pub const NCFGR_MTIHEN: u32 = 1 << 6;

// ---- PHY vendor specific (MMS 4, DS 11.5) -----------------------------------

/// Status 1, DS 11.5.2. Its flags (bits 12:0) are read-to-clear.
pub const STS1: Reg = Reg::new(4, 0x0018);
/// Collision Detector Control 0, DS 11.5.51. Reset value `0x80C3`: only
/// `CDEN` is this crate's, so it is read-modified-written.
pub const CDCTL0: Reg = Reg::new(4, 0x0087);
/// PLCA Control 0, DS 11.5.58.
pub const PLCA_CTRL0: Reg = Reg::new(4, 0xCA01);
/// PLCA Control 1, DS 11.5.59: `NCNT` in bits 15:8, `ID` in bits 7:0.
pub const PLCA_CTRL1: Reg = Reg::new(4, 0xCA02);
/// PLCA Status, DS 11.5.60.
pub const PLCA_STS: Reg = Reg::new(4, 0xCA03);

/// `CDCTL0.CDEN`: collision detection is enabled (the reset state).
pub const CDCTL0_CDEN: u32 = 1 << 15;
/// `PLCA_CTRL0.EN`: PLCA is enabled.
pub const PLCA_CTRL0_EN: u32 = 1 << 15;
/// `PLCA_STS.PST`: PLCA is active, a BEACON is regularly sent or received.
pub const PLCA_STS_PST: u32 = 1 << 15;

/// The bits of the Status 1 register that matter to a node on a PLCA segment.
pub mod sts1 {
    /// PLCA Status Changed: `PLCA_STS.PST` changed since the register was last read.
    pub const PSTC: u16 = 1 << 11;
    /// Receive in Transmit Opportunity: another node transmitted in this node's
    /// slot, which can mean two nodes share a PLCA node ID (DS 7.2).
    pub const RXINTO: u16 = 1 << 6;
    /// Unexpected BEACON Received: a coordinator heard a BEACON it did not send, so
    /// another coordinator is on the segment. Errata item s5 (DS80001075F 1.5)
    /// leaves the work-around to the station management: reconfigure the node as a
    /// follower.
    pub const UNEXPB: u16 = 1 << 5;
    /// BEACON Received Before Transmit Opportunity: the PLCA bus cycle is too short
    /// for this follower's ID (DS 7.2).
    pub const BCNBFTO: u16 = 1 << 4;
}

// ---- the configuration application note (AN1760), MMS 4 --------------------

/// The indirect-read handshake's address register (AN1760, "Indirect Read").
pub(crate) const INDIRECT_ADDRESS: Reg = Reg::new(4, 0x00D8);
/// The indirect-read handshake's data register.
pub(crate) const INDIRECT_DATA: Reg = Reg::new(4, 0x00D9);
/// The indirect-read handshake's control register; writing 2 starts the read.
pub(crate) const INDIRECT_CONTROL: Reg = Reg::new(4, 0x00DA);
