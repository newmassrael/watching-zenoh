// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the board asks of the chip, and the checks that run before the bus is
//! touched.

/// How the node takes part in the multidrop segment's collision avoidance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plca {
    /// PLCA off: the node runs CSMA/CD, as the chip does after a reset
    /// (`PLCA_CTRL1.ID` resets to 0xFF, `PLCA_CTRL0.EN` to 0 and `CDCTL0.CDEN` to
    /// 1; DS60001734F 11.5.59, 11.5.58, 11.5.51), so nothing is written for it.
    ///
    /// This is also how to ask for what an ID of `0xFF` means: that value disables
    /// PLCA (DS60001734F 11.5.59), and it is refused as a node ID so the intent is
    /// stated once, here.
    Off,
    /// PLCA on, as the node with this ID. ID 0 is the coordinator, which sends
    /// the periodic BEACON; IDs 1 to 0xFE are followers (AN1760, "Enabling
    /// PLCA"). The ID must be unique on the segment (DS60001734F 11.5.59).
    ///
    /// `count` is the number of transmit opportunities in a bus cycle, "the
    /// maximum Node_ID used in the mixing segment plus 1" (AN1760), and it must
    /// exceed every follower's ID for that follower to get a turn (DS60001734F
    /// 7.2). Only a coordinator has it: a follower ignores the field, AN1760 writes
    /// a follower's ID alone, and so `count` is not written for one.
    Node { id: u8, count: u8 },
}

/// The board's choices for one chip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// The station address. It is written to the MAC's first specific-address
    /// register, and the low 32 bits of it also seed the CSMA/CD back-off, so it
    /// should be unique on the segment (DS60001734F 6.4.2).
    pub mac_address: [u8; 6],
    pub plca: Plca,
    /// Also accept multicast frames whatever their address: the hash registers are
    /// set to all ones and multicast hashing is enabled (DS60001734F 6.4.6). Off,
    /// only frames to the station address and broadcast frames are accepted, which
    /// excludes the multicast groups a discovery protocol listens on.
    pub accept_all_multicast: bool,
    /// Drive a part whose `DEVID.REV` is above the revisions the documents grade
    /// (see [`Revision::Newer`](crate::Revision::Newer)). AN1760 says its sequence
    /// applies to newer versions "until superseded by a newer version of the
    /// Configuration Application Note", and this crate cannot know whether one has
    /// superseded it, so by default it refuses what no document grades. Turn this
    /// on only after reading the current revision of the note against this crate's
    /// copy of its sequence (the `an1760` module).
    pub accept_newer_revisions: bool,
}

/// Why a [`Config`] is refused. Raised before any bus traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// The station address has the group bit set (multicast, and so broadcast
    /// too); a station is addressed by a unicast address.
    MacAddressIsGroup,
    /// The station address is all zeros.
    MacAddressIsZero,
    /// A PLCA node ID of `0xFF`, which the chip reads as "PLCA disabled". Ask for
    /// that with [`Plca::Off`].
    PlcaIdDisablesPlca,
    /// A coordinator (ID 0) with no transmit opportunities in its bus cycle.
    PlcaCoordinatorNeedsCount,
}

impl Config {
    /// Check the config. [`open`](crate::open) does this before it touches the bus;
    /// a caller that wants to know sooner (and to keep the SPI master `open`
    /// consumes) can call it first.
    pub const fn validate(&self) -> Result<(), ConfigError> {
        if self.mac_address[0] & 1 != 0 {
            return Err(ConfigError::MacAddressIsGroup);
        }
        let zero = self.mac_address[0] == 0
            && self.mac_address[1] == 0
            && self.mac_address[2] == 0
            && self.mac_address[3] == 0
            && self.mac_address[4] == 0
            && self.mac_address[5] == 0;
        if zero {
            return Err(ConfigError::MacAddressIsZero);
        }
        match self.plca {
            Plca::Off => {}
            Plca::Node { id: 0xFF, .. } => return Err(ConfigError::PlcaIdDisablesPlca),
            Plca::Node { id: 0, count: 0 } => return Err(ConfigError::PlcaCoordinatorNeedsCount),
            Plca::Node { .. } => {}
        }
        Ok(())
    }
}

/// The two words of `MAC_SAB1` and `MAC_SAT1` for a station address: bytes 0 to 3
/// little-endian in the first and bytes 4 and 5 in the low half of the second.
/// DS60001734F 6.4.4 works the example 21:43:65:87:A9:CB into
/// `0x8765_4321` and `0x0000_CBA9`; the upper half of `MAC_SAT1` is read-only
/// except `FLTTYP`, which 0 leaves as a destination-address filter.
pub(crate) const fn address_words(mac: [u8; 6]) -> (u32, u32) {
    let bottom = (mac[0] as u32)
        | ((mac[1] as u32) << 8)
        | ((mac[2] as u32) << 16)
        | ((mac[3] as u32) << 24);
    let top = (mac[4] as u32) | ((mac[5] as u32) << 8);
    (bottom, top)
}

/// The value AN1760 writes to `PLCA_CTRL1` (`plcaparam1`): the coordinator's
/// count in bits 15:8, a follower's ID alone. `None` for [`Plca::Off`].
pub(crate) const fn plca_ctrl1(plca: Plca) -> Option<u16> {
    match plca {
        Plca::Off => None,
        Plca::Node { id: 0, count } => Some((count as u16) << 8),
        Plca::Node { id, .. } => Some(id as u16),
    }
}
