// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A version-bearing message of ANOTHER protocol version, read as far as the
//! layout this reader shares with it.
//!
//! # Why another version can be read at all
//!
//! An observer refuses an Init, a Join, a Scout or a Hello whose version is not
//! [`wz_codecs::wire_const::PROTOCOL_VERSION`] (`InboundParseError::ForeignVersion`):
//! it folds nothing and names nobody, because this reader does not implement
//! that version. That refusal says nothing about WHAT the bytes were, and a
//! field engineer looking at a zenoh 0.x deployment (version 0x08: a DDS bridge
//! of an older release, a router never upgraded) needs to be told it is zenoh
//! of a version out of this reader's range, not traffic that is not zenoh.
//!
//! The messages that carry the version have the same layout in 0x08 as in
//! 0x09: the body of an InitSyn is written field for field the same, and only
//! the extensions a release adds differ. That was read by comparing the
//! zenoh-codec crate of release 0.11.0, whose protocol version is 0x08, with the
//! pinned one (`commons/zenoh-codec/src/transport/init.rs` @ `impl<W> WCodec<&InitSyn, &mut W> for Zenoh080`);
//! the Open, Join, Scout and Hello bodies compare the same. An extension states
//! its own length, so a message of 0x08 reads under this reader's layout to its
//! end. What it is read for is ONE fact, which this type carries: the message
//! took the whole framing unit it came in. Nothing of its body is folded.
//!
//! # Why a message alone is not a verdict
//!
//! One header byte and a version byte open many things that are not zenoh (a
//! DNS id of `0x0108` reads as a Scout of version 8). A message that fills its
//! unit exactly is rarer, and the verdict this feeds asks for more still: an
//! answer from the other side, or the same sender twice. See the capture's
//! `foreign_zenoh` plane.

use alloc::vec::Vec;

/// Which version-bearing message it was. The closed set the documents write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VersionBearing {
    /// An Init without the A flag: the opener's offer.
    InitSyn,
    /// An Init with the A flag: the acceptor's answer.
    InitAck,
    /// A multicast Join.
    Join,
    /// A scouting Scout.
    Scout,
    /// A scouting Hello.
    Hello,
}

impl VersionBearing {
    /// The word this message is written as.
    pub const fn name(self) -> &'static str {
        match self {
            VersionBearing::InitSyn => "init_syn",
            VersionBearing::InitAck => "init_ack",
            VersionBearing::Join => "join",
            VersionBearing::Scout => "scout",
            VersionBearing::Hello => "hello",
        }
    }

    /// Every kind, from an exhaustive match.
    pub fn all() -> [VersionBearing; 5] {
        let one = |k: VersionBearing| match k {
            VersionBearing::InitSyn => VersionBearing::InitSyn,
            VersionBearing::InitAck => VersionBearing::InitAck,
            VersionBearing::Join => VersionBearing::Join,
            VersionBearing::Scout => VersionBearing::Scout,
            VersionBearing::Hello => VersionBearing::Hello,
        };
        [
            one(VersionBearing::InitSyn),
            one(VersionBearing::InitAck),
            one(VersionBearing::Join),
            one(VersionBearing::Scout),
            one(VersionBearing::Hello),
        ]
    }

    /// Every word, sorted.
    pub fn names() -> Vec<&'static str> {
        let mut words: Vec<&'static str> = Self::all().iter().map(|k| k.name()).collect();
        words.sort_unstable();
        words
    }
}

/// One message of another version, as far as this reader read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignVersionMessage {
    /// The version it announced; never [`wz_codecs::wire_const::PROTOCOL_VERSION`].
    pub version: u8,
    /// Which message it was.
    pub kind: VersionBearing,
    /// The zid it named: an Init's, a Join's, a Hello's, and a Scout's when the
    /// Scout names its asker; `None` for a Scout that names nobody.
    pub zid: Option<Vec<u8>>,
    /// The message took its whole framing unit: it is the unit's only message,
    /// and its last byte is the unit's last.
    pub whole: bool,
}
