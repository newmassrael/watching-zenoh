// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! WHETHER A FLOW IS ZENOH OF A VERSION THIS READER DOES NOT READ: a zenoh 0.x
//! deployment (protocol version 0x08) is zenoh, out of this reader's range, and
//! a field engineer needs it told apart from traffic that is not zenoh at all.
//!
//! # Why this is not a word of the `zenoh` verdict
//!
//! The flow's `zenoh` verdict is a sequential test whose zenoh hypothesis is
//! THIS wire, version 0x09, frozen with its weights before a validation corpus
//! was read (`docs/flow-zenoh-verdict.md`, section 6.12). A flow of another
//! version is a separate question, which that note leaves to a cell of its own:
//! this one. The verdict is left exactly as it was.
//!
//! # The rule
//!
//! Every input is a version-bearing message of another version that took its
//! whole framing unit alone ([`wz_session_core::foreign_version`]), or a Close
//! read from a unit read whole. One such message is not enough: a header byte
//! and a version byte open many things that are not zenoh. The flow is
//! recognised when its messages form one of four exchanges, the first one met
//! latching:
//!
//! * `answered` -- an InitSyn of version V in one direction, then an InitAck
//!   of V in the other: a session of V opening;
//! * `refused` -- an InitSyn of V in one direction, then a Close in the other:
//!   an acceptor refusing it, as zenoh's does an offer of a version not its own
//!   (`io/zenoh-transport/src/unicast/establishment/accept.rs` @ `if init_syn.version != input.mine_version {`);
//! * `answered_scout` -- a Hello of V on a flow addressed to an endpoint the
//!   capture saw send a Scout, which is the only way a unicast Hello is read as
//!   scouting at all;
//! * `repeated` -- a Join, or a Scout that names its asker, of V from the same
//!   zid twice, in the same direction: a multicast member announcing itself
//!   again, or an asker scouting again.
//!
//! Three of them rest on two messages that each fill their unit, and two of
//! those on a message from each side; random bytes that happen to read as one
//! rarely read as the other. `answered_scout` rests on one message of this flow
//! and on the other flow's Scout, whose sender this datagram was addressed to;
//! that pairing is what routed the datagram here, and the Scout's direction is
//! a word of the other flow, so it is not written among this flow's witnesses.
//! The InitSyn of `refused` is a message of another version answered by a
//! refusal, and the Close says nothing about the version of the side that sent
//! it.
//!
//! # Counted at ingest
//!
//! The messages are the oldest of a flow and the first a retention ceiling
//! discards, so the recognition is made where they arrive and kept.

use alloc::vec::Vec;

use wz_session_core::foreign_version::{ForeignVersionMessage, VersionBearing};
use wz_session_core::passive::Direction;

/// How many distinct `(kind, direction, version, zid)` first sightings a flow
/// keeps while it waits for a second: a flow of arbitrary bytes produces few
/// messages that fill a unit, and a bound keeps it from producing many.
const SIGHTINGS_HELD: usize = 8;

/// Which exchange recognised the flow. The closed set the documents write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecognizedBy {
    /// An InitSyn answered by an InitAck of the same version.
    Answered,
    /// An InitSyn answered by a Close.
    Refused,
    /// A Hello sent to an endpoint that scouted.
    AnsweredScout,
    /// A Join, or a Scout naming its asker, twice from the same zid.
    Repeated,
}

impl RecognizedBy {
    /// The word this exchange is written as.
    pub const fn name(self) -> &'static str {
        match self {
            RecognizedBy::Answered => "answered",
            RecognizedBy::Refused => "refused",
            RecognizedBy::AnsweredScout => "answered_scout",
            RecognizedBy::Repeated => "repeated",
        }
    }

    /// Every exchange, from an exhaustive match.
    pub fn all() -> [RecognizedBy; 4] {
        let one = |r: RecognizedBy| match r {
            RecognizedBy::Answered => RecognizedBy::Answered,
            RecognizedBy::Refused => RecognizedBy::Refused,
            RecognizedBy::AnsweredScout => RecognizedBy::AnsweredScout,
            RecognizedBy::Repeated => RecognizedBy::Repeated,
        };
        [
            one(RecognizedBy::Answered),
            one(RecognizedBy::Refused),
            one(RecognizedBy::AnsweredScout),
            one(RecognizedBy::Repeated),
        ]
    }

    /// Every word, sorted.
    pub fn names() -> Vec<&'static str> {
        let mut words: Vec<&'static str> = Self::all().iter().map(|r| r.name()).collect();
        words.sort_unstable();
        words
    }
}

/// Which message a witness is: a version-bearing message, or the Close that
/// refused one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessKind {
    /// A version-bearing message of the flow's version.
    Message(VersionBearing),
    /// A Close.
    Close,
}

impl WitnessKind {
    /// The word this witness is written as.
    pub const fn name(self) -> &'static str {
        match self {
            WitnessKind::Message(kind) => kind.name(),
            WitnessKind::Close => "close",
        }
    }

    /// Every word, sorted.
    pub fn names() -> Vec<&'static str> {
        let mut words = VersionBearing::names();
        words.push(WitnessKind::Close.name());
        words.sort_unstable();
        words
    }
}

/// One message the recognition rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Witness {
    /// Which message.
    pub kind: WitnessKind,
    /// The direction it travelled.
    pub direction: Direction,
    /// The capture-global index of its packet, the axis of a record's `packet`.
    pub packet: u64,
}

/// A flow recognised as zenoh of another version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recognition {
    /// The version its messages announced.
    pub version: u8,
    /// The exchange that recognised it.
    pub recognized_by: RecognizedBy,
    /// The messages of that exchange on this flow, in the order they arrived:
    /// two, and the Hello alone for [`RecognizedBy::AnsweredScout`].
    pub witnesses: Vec<Witness>,
}

/// A first sighting, waiting for the message that would complete an exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sighting {
    kind: VersionBearing,
    direction: Direction,
    version: u8,
    zid: Option<Vec<u8>>,
    packet: u64,
}

/// What one flow's messages of another version came to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ForeignZenoh {
    /// The first sightings held, oldest first.
    sightings: Vec<Sighting>,
    /// The recognition, once an exchange is met; it latches.
    recognition: Option<Recognition>,
}

impl ForeignZenoh {
    /// The recognition, `None` while no exchange has been met.
    pub fn recognition(&self) -> Option<&Recognition> {
        self.recognition.as_ref()
    }

    /// A transport message refused as another version, read at `packet`.
    pub fn observe(&mut self, message: &ForeignVersionMessage, direction: Direction, packet: u64) {
        self.observe_message(message, direction, packet, false);
    }

    /// A scouting message refused as another version, read at `packet`.
    /// `answers_a_scout` is whether its datagram was addressed to an endpoint
    /// the capture saw send a Scout.
    pub fn observe_scouting(
        &mut self,
        message: &ForeignVersionMessage,
        direction: Direction,
        packet: u64,
        answers_a_scout: bool,
    ) {
        self.observe_message(message, direction, packet, answers_a_scout);
    }

    /// A Close read from a unit read whole, travelling `direction` at `packet`.
    pub fn observe_close(&mut self, direction: Direction, packet: u64) {
        if self.recognition.is_some() {
            return;
        }
        let Some(syn) = self
            .sightings
            .iter()
            .find(|s| s.kind == VersionBearing::InitSyn && s.direction != direction)
        else {
            return;
        };
        self.recognition = Some(Recognition {
            version: syn.version,
            recognized_by: RecognizedBy::Refused,
            witnesses: alloc::vec![
                Witness {
                    kind: WitnessKind::Message(VersionBearing::InitSyn),
                    direction: syn.direction,
                    packet: syn.packet,
                },
                Witness {
                    kind: WitnessKind::Close,
                    direction,
                    packet,
                },
            ],
        });
    }

    fn observe_message(
        &mut self,
        message: &ForeignVersionMessage,
        direction: Direction,
        packet: u64,
        answers_a_scout: bool,
    ) {
        if self.recognition.is_some() || !message.whole {
            return;
        }
        let witness = |kind: VersionBearing, direction: Direction, packet: u64| Witness {
            kind: WitnessKind::Message(kind),
            direction,
            packet,
        };
        let this = witness(message.kind, direction, packet);
        let completes = match message.kind {
            VersionBearing::InitAck => self
                .sightings
                .iter()
                .find(|s| {
                    s.kind == VersionBearing::InitSyn
                        && s.direction != direction
                        && s.version == message.version
                })
                .map(|s| {
                    (
                        RecognizedBy::Answered,
                        Some(witness(s.kind, s.direction, s.packet)),
                    )
                }),
            // The Scout it answers is on another flow: see the module doc.
            VersionBearing::Hello if answers_a_scout => Some((RecognizedBy::AnsweredScout, None)),
            VersionBearing::Join | VersionBearing::Scout if message.zid.is_some() => self
                .sightings
                .iter()
                .find(|s| {
                    s.kind == message.kind
                        && s.direction == direction
                        && s.version == message.version
                        && s.zid == message.zid
                        && s.packet != packet
                })
                .map(|s| {
                    (
                        RecognizedBy::Repeated,
                        Some(witness(s.kind, s.direction, s.packet)),
                    )
                }),
            _ => None,
        };
        if let Some((recognized_by, first)) = completes {
            self.recognition = Some(Recognition {
                version: message.version,
                recognized_by,
                witnesses: first.into_iter().chain(Some(this)).collect(),
            });
            return;
        }
        let held = self.sightings.iter().any(|s| {
            s.kind == message.kind
                && s.direction == direction
                && s.version == message.version
                && s.zid == message.zid
        });
        if !held && self.sightings.len() < SIGHTINGS_HELD {
            self.sightings.push(Sighting {
                kind: message.kind,
                direction,
                version: message.version,
                zid: message.zid.clone(),
                packet,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(kind: VersionBearing, zid: Option<&[u8]>, whole: bool) -> ForeignVersionMessage {
        ForeignVersionMessage {
            version: 0x08,
            kind,
            zid: zid.map(<[u8]>::to_vec),
            whole,
        }
    }

    /// A Join repeated by its member is recognised at the second one; the same
    /// Join from another zid, or in the other direction, is not a repetition.
    #[test]
    fn a_join_repeated_by_its_member_is_recognised() {
        let join = |zid: &[u8]| message(VersionBearing::Join, Some(zid), true);
        let mut f = ForeignZenoh::default();
        f.observe(&join(&[1; 4]), Direction::A, 10);
        f.observe(&join(&[2; 4]), Direction::A, 11);
        f.observe(&join(&[1; 4]), Direction::B, 12);
        assert_eq!(f.recognition(), None, "another zid, another direction");
        f.observe(&join(&[1; 4]), Direction::A, 13);
        let r = f.recognition().expect("the member joined again");
        assert_eq!(r.recognized_by, RecognizedBy::Repeated);
        assert_eq!(
            r.witnesses.iter().map(|w| w.packet).collect::<Vec<_>>(),
            alloc::vec![10, 13]
        );
    }

    /// A Scout repeats only when it names its asker: two anonymous Scouts are
    /// two messages that could be anything.
    #[test]
    fn a_scout_repeats_only_when_it_names_its_asker() {
        let mut f = ForeignZenoh::default();
        f.observe_scouting(
            &message(VersionBearing::Scout, None, true),
            Direction::A,
            1,
            false,
        );
        f.observe_scouting(
            &message(VersionBearing::Scout, None, true),
            Direction::A,
            2,
            false,
        );
        assert_eq!(f.recognition(), None);
        let named = message(VersionBearing::Scout, Some(&[7; 8]), true);
        f.observe_scouting(&named, Direction::A, 3, false);
        f.observe_scouting(&named, Direction::A, 4, false);
        assert_eq!(
            f.recognition().map(|r| r.recognized_by),
            Some(RecognizedBy::Repeated)
        );
    }

    /// A Hello is an answer only when its datagram was addressed to an asker,
    /// and then it is its own and only witness on this flow.
    #[test]
    fn a_hello_is_an_answer_only_when_addressed_to_an_asker() {
        let hello = message(VersionBearing::Hello, Some(&[3; 16]), true);
        let mut f = ForeignZenoh::default();
        f.observe_scouting(&hello, Direction::B, 5, false);
        assert_eq!(
            f.recognition(),
            None,
            "a multicast Hello answers nobody here"
        );
        f.observe_scouting(&hello, Direction::B, 6, true);
        let r = f.recognition().expect("an answer to a scout");
        assert_eq!(r.recognized_by, RecognizedBy::AnsweredScout);
        assert_eq!(r.witnesses.len(), 1);
        assert_eq!(r.witnesses[0].packet, 6);
    }

    /// A message that did not fill its unit is no witness, whatever follows.
    #[test]
    fn a_message_that_did_not_fill_its_unit_is_no_witness() {
        let mut f = ForeignZenoh::default();
        f.observe(
            &message(VersionBearing::InitSyn, Some(&[1; 4]), false),
            Direction::A,
            0,
        );
        f.observe(
            &message(VersionBearing::InitAck, Some(&[2; 4]), true),
            Direction::B,
            1,
        );
        f.observe_close(Direction::B, 2);
        assert_eq!(f.recognition(), None);
    }

    /// An answer of ANOTHER version does not answer the offer, and the first
    /// exchange met latches: a Close after an answered offer changes nothing.
    #[test]
    fn the_answer_must_be_of_the_offers_version_and_the_first_exchange_latches() {
        let mut f = ForeignZenoh::default();
        f.observe(
            &message(VersionBearing::InitSyn, Some(&[1; 4]), true),
            Direction::A,
            0,
        );
        let mut other = message(VersionBearing::InitAck, Some(&[2; 4]), true);
        other.version = 0x07;
        f.observe(&other, Direction::B, 1);
        assert_eq!(f.recognition(), None, "0x07 does not answer 0x08");
        f.observe(
            &message(VersionBearing::InitAck, Some(&[2; 4]), true),
            Direction::B,
            2,
        );
        f.observe_close(Direction::B, 3);
        let r = f.recognition().expect("answered");
        assert_eq!(r.recognized_by, RecognizedBy::Answered);
        assert_eq!(r.witnesses[1].packet, 2);
    }

    /// The sightings held are bounded, and a sender that repeats one it holds
    /// takes no second place.
    #[test]
    fn the_sightings_held_are_bounded() {
        let mut f = ForeignZenoh::default();
        for i in 0..20u8 {
            f.observe(
                &message(VersionBearing::Join, Some(&[i; 4]), true),
                Direction::A,
                0,
            );
        }
        assert_eq!(f.sightings.len(), SIGHTINGS_HELD);
        assert_eq!(f.recognition(), None, "the same packet repeats nothing");
    }

    /// The words the documents write are the families revision 73 declares.
    #[test]
    fn the_words_are_the_declared_families() {
        assert_eq!(
            RecognizedBy::names(),
            crate::doc_revision::FOREIGN_ZENOH_RECOGNIZED_BY_R73
        );
        assert_eq!(
            WitnessKind::names(),
            crate::doc_revision::FOREIGN_ZENOH_WITNESS_R73
        );
    }
}
