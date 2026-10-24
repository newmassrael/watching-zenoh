// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The judgement STATE of a capture: one [`Judge`] per SLOT.
//!
//! [`crate::e2e_judge`] judges one stream of frames and leaves open what a
//! stream is. For a capture that is decided here, from what a receiver of the
//! protocol keeps its counters per: the **key expression** a frame was
//! published under (a keyed message has one counter per key INSTANCE), the
//! **sender** (two publishers of one key do not share a counter), and the
//! **message** (the values of the profile's `slot.message` fields, for a key
//! that carries several).
//!
//! # What a slot is NOT
//!
//! Not the sender cell inside the header. A header's sender cell is derived
//! from a local address, and two processes on one machine send the same value;
//! the slot's sender is the zid the capture saw announced on the link, which
//! is the identity the transport gives, and which the profile may turn off
//! (`slot.by_zid`) for a receiver that keeps one counter per message.
//!
//! # An unknown sender is not guessed
//!
//! A capture that began after the handshake never saw the sender's zid. Where
//! the profile separates senders, such a frame has no slot: its CRC is judged
//! (that needs no state), its counter and timeout are NOT, and the outcome says
//! so rather than putting the frame in a slot shared with every other unknown
//! sender and charging one with another's counter. A wrong counter error
//! stated as a fact is worse than an unjudged one.
//!
//! # Order
//!
//! A slot is judged in the order the frames are handed in. The document
//! walks one flow at a time, in capture order within it, so a slot whose frames
//! are spread over two flows (the same sender and key over two connections) is
//! judged flow by flow and not in time order. The clock is the capture's own
//! timestamp, never the host's; a frame whose packet carried none is judged for
//! its counter and not for its timeout ([`Judge::receive_without_clock`]).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use wz_session_core::passive::NANOS_PER_MILLI;
use wz_session_core::zid_hex::canonical_zid;

use crate::e2e_frame::{self, OpenedFrame};
use crate::e2e_judge::{Judge, Judgment};
use crate::e2e_profile::Profile;

/// Why a rule that matched read no frame, when the payload is not one run of
/// bytes this reader holds.
pub const UNREADABLE_PAYLOAD: &str =
    "the payload is not one run of bytes in the capture (shared memory, or several slices)";

/// Why a rule that matched yielded no frame, as a closed set a machine reads:
/// the `unopened_reason` of a capture row's `e2e` block, beside the free `why`
/// a person reads. Two reasons because there are two ways a covered payload is
/// not a frame, and a consumer that has to tell them apart (a payload too short
/// to hold the header is damage; one that is not a run of bytes is a carrier
/// this reader does not follow) must not do it by reading a sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unopened {
    /// The payload is not one run of bytes in the capture.
    PayloadNotContiguous,
    /// The payload is shorter than the profile's header.
    PayloadShorterThanHeader,
}

impl Unopened {
    /// Every reason, so the vocabulary a document declares and a test's walk of
    /// it are one list.
    pub const ALL: [Self; 2] = [Self::PayloadNotContiguous, Self::PayloadShorterThanHeader];

    /// The word a machine reads for this reason. Exhaustive, so a reason added
    /// to the enum cannot reach a consumer without one.
    pub const fn word(self) -> &'static str {
        match self {
            Self::PayloadNotContiguous => "payload_not_contiguous",
            Self::PayloadShorterThanHeader => "payload_shorter_than_header",
        }
    }
}

/// Who a slot's frames are from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SlotSender {
    /// The profile does not separate senders: every sender of the message
    /// shares the slot.
    Pooled,
    /// The zid the capture saw announced on the link, canonical form.
    Zid(Vec<u8>),
    /// The profile separates senders and the capture never named this one.
    Unknown,
}

/// Which counter a frame belongs to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Slot {
    /// The key expression the frame was published under, resolved.
    pub keyexpr: String,
    /// The sender, as far as the profile separates senders.
    pub sender: SlotSender,
    /// The logical value of each `slot.message` field, with its name, in the
    /// profile's order. Empty when a key carries one message.
    pub identity: Vec<(String, u64)>,
}

/// One frame as the ledger is handed it.
#[derive(Debug, Clone, Copy)]
pub struct Reception<'a> {
    /// The profile the matching rule names.
    pub profile: &'a Profile,
    /// The key expression the frame was published under.
    pub keyexpr: &'a str,
    /// The whole payload of the sample: header, then body.
    pub payload: &'a [u8],
    /// The sender's zid, when the capture named it.
    pub sender: Option<&'a [u8]>,
    /// The capture instant of the frame, in nanoseconds, when its packet
    /// carried one.
    pub observed_at_ns: Option<u64>,
}

/// What the ledger made of one frame.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// The rule matched and the payload is not bytes this reader holds in one
    /// piece (a shared-memory descriptor, or several slices).
    Unreadable {
        /// Why, as a sentence.
        why: &'static str,
    },
    /// The payload is shorter than the profile's header: there is no frame.
    TooShort {
        /// How many bytes the payload has.
        payload_bytes: usize,
        /// How many bytes the header needs.
        header_bytes: usize,
    },
    /// The frame was read and judged as far as its slot allowed.
    Opened(Box<Opened>),
}

/// A frame that was read.
#[derive(Debug, Clone)]
pub struct Opened {
    /// The header, the CRC verdict and the length facts.
    pub frame: OpenedFrame,
    /// The slot the frame belongs to.
    pub slot: Slot,
    /// The counter and timeout verdict, or `None` when the slot has an unknown
    /// sender and so no state to judge against.
    pub judgment: Option<Judgment>,
    /// Whether the timeout was judged: false when the packet carried no
    /// timestamp, or when no judgment was made at all.
    pub timed: bool,
    /// The counter this frame was judged against: the last one the slot
    /// ACCEPTED before it, `None` while it has accepted none. A CRC error and a
    /// repetition accept nothing, so after either the same counter is what the
    /// next frame is judged against; a step past the allowed gap IS accepted
    /// (the counter moved and the verdict says by how much it was wrong), so it
    /// becomes the next frame's. `None` as well when there is no slot to judge
    /// against ([`Self::judgment`] is `None`).
    pub previous: Option<u64>,
    /// The step from [`Self::previous`] to this frame's counter, in the counter's
    /// own width, as the judge computes it: `None` when there is nothing to step
    /// from, and when the CRC did not match (the counter of a damaged frame is
    /// not read).
    pub step: Option<u64>,
}

impl Outcome {
    /// Why this outcome is not a frame, or `None` when it is one.
    pub fn unopened(&self) -> Option<Unopened> {
        match self {
            Self::Unreadable { .. } => Some(Unopened::PayloadNotContiguous),
            Self::TooShort { .. } => Some(Unopened::PayloadShorterThanHeader),
            Self::Opened(_) => None,
        }
    }
}

/// The ledger of a run: a judge per slot seen.
///
/// # A ledger that goes on between walks
///
/// A walk that continues from where the last one stopped judges only the frames that
/// arrived since, so the counters it judges them against are the ones the last walk
/// left. That is the same sequence of frames per slot as one walk over everything
/// ONLY while a slot's frames come from one list: a slot whose frames are spread
/// over two lists is judged list by list in one walk and in the order the calls
/// reached them in a continuing one. The ledger therefore remembers which list
/// judged each slot ([`Self::crossed`]), and a caller that sees it say so walks the
/// whole capture again.
///
/// # What it judged, kept by row (open-debt item 924, D9)
///
/// A frame's outcome depends on the frames of its slot before it, so a reader
/// that looks at one row cannot judge it alone. The ledger therefore keeps the
/// outcome of every frame it judged, by the row it came in and its place among
/// the row's judgments, and, per list, how far the walks have judged the list in
/// order ([`Frontier`]). A row behind the frontier is read back from what was
/// kept and moves no counter; a row past it is judged against the counters the
/// frontier left. That is the reference dissector's first pass (a frame's
/// stateful verdicts stored on its first visit), kept per declaration text
/// because the text decides the profiles.
#[derive(Debug, Default)]
pub struct SlotLedger {
    judges: BTreeMap<Slot, Judge>,
    /// The list that judged each slot first.
    owners: BTreeMap<Slot, usize>,
    /// Some slot was judged from two lists.
    crossed: bool,
    /// The outcome of each frame judged, by its list, its row's produced-index
    /// and its place among the judgments of that row. Kept for the field walker,
    /// so built with it.
    #[cfg(feature = "dissect")]
    judged: BTreeMap<(usize, u64, u32), Outcome>,
    /// Per list, how far it has been judged in order.
    #[cfg(feature = "dissect")]
    frontiers: BTreeMap<usize, Frontier>,
}

/// How far one list has been judged in the order a walk over the whole capture
/// judges it: every row before `produced` was judged, and the largest
/// capture-order key among them is `last_key` (`None` for a list judged in its
/// own order, a datagram list).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Frontier {
    /// The produced-index of the first row not judged.
    pub produced: u64,
    /// The largest key judged, for a list judged in capture order.
    pub last_key: Option<(usize, u64)>,
}

impl SlotLedger {
    /// A ledger that has seen nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many slots have a judge.
    pub fn slots(&self) -> usize {
        self.judges.len()
    }

    /// Whether any slot has been judged from two different lists.
    pub fn crossed(&self) -> bool {
        self.crossed
    }
}

/// What the ledger keeps of each row it judged, for the field walker (open-debt
/// item 924, D9; see [`SlotLedger`]).
#[cfg(feature = "dissect")]
impl SlotLedger {
    /// How far the list at `list` has been judged in order.
    pub(crate) fn frontier(&self, list: usize) -> Frontier {
        self.frontiers.get(&list).copied().unwrap_or_default()
    }

    /// The list at `list` has been judged in order up to `frontier`; a frontier
    /// behind the one held moves nothing.
    pub(crate) fn judged_up_to(&mut self, list: usize, frontier: Frontier) {
        let held = self.frontiers.entry(list).or_default();
        if frontier.produced > held.produced {
            *held = frontier;
        }
    }

    /// What was judged of the frame that was judgment `ordinal` of the row at
    /// produced-index `produced` of the list at `list`, when it was.
    pub(crate) fn recall(&self, list: usize, produced: u64, ordinal: u32) -> Option<Outcome> {
        self.judged.get(&(list, produced, ordinal)).cloned()
    }

    /// Keep what was judged of a frame, for [`Self::recall`].
    pub(crate) fn remember(&mut self, list: usize, produced: u64, ordinal: u32, outcome: &Outcome) {
        self.judged
            .insert((list, produced, ordinal), outcome.clone());
    }

    /// Let go of what was judged of the rows of the list at `list` older than
    /// `first_held`, the produced-index of the oldest row it holds: no reader can
    /// ask for them again.
    pub(crate) fn forget_before(&mut self, list: usize, first_held: u64) {
        let gone: Vec<(usize, u64, u32)> = self
            .judged
            .range((list, 0, 0)..(list, first_held, 0))
            .map(|(key, _)| *key)
            .collect();
        for key in gone {
            let _ = self.judged.remove(&key);
        }
    }
}

impl SlotLedger {
    /// Read `reception.payload` under its profile and judge it against its slot.
    pub fn receive(&mut self, reception: &Reception<'_>) -> Outcome {
        self.receive_from(0, reception)
    }

    /// [`Self::receive`], for a frame that came from the list numbered `list`, which
    /// the ledger remembers as the owner of the slot (see the type's note).
    pub fn receive_from(&mut self, list: usize, reception: &Reception<'_>) -> Outcome {
        let profile = reception.profile;
        let frame = match e2e_frame::open(profile, reception.payload) {
            Ok(frame) => frame,
            Err(_) => {
                return Outcome::TooShort {
                    payload_bytes: reception.payload.len(),
                    header_bytes: profile.header_bytes(),
                }
            }
        };
        let spec = profile.slot();
        let sender = if !spec.by_zid {
            SlotSender::Pooled
        } else {
            match reception.sender.map(canonical_zid) {
                Some(zid) if !zid.is_empty() => SlotSender::Zid(zid.to_vec()),
                _ => SlotSender::Unknown,
            }
        };
        let identity = spec
            .message
            .iter()
            .map(|&index| {
                (
                    profile.fields()[index].name.clone(),
                    frame.fields[index].value,
                )
            })
            .collect();
        let slot = Slot {
            keyexpr: String::from(reception.keyexpr),
            sender,
            identity,
        };

        if slot.sender == SlotSender::Unknown {
            return Outcome::Opened(Box::new(Opened {
                frame,
                slot,
                judgment: None,
                timed: false,
                previous: None,
                step: None,
            }));
        }
        match self.owners.get(&slot) {
            Some(&owner) if owner != list => self.crossed = true,
            Some(_) => {}
            None => {
                self.owners.insert(slot.clone(), list);
            }
        }
        let judge = self
            .judges
            .entry(slot.clone())
            .or_insert_with(|| profile.judge());
        let counter = frame.counter(profile);
        // Read BEFORE the judge moves anything: what the frame is judged
        // against, and how far it is from it.
        let previous = judge.baseline();
        let step = if frame.crc_ok {
            judge.step_from_baseline(counter)
        } else {
            None
        };
        let (judged, timed) = match reception.observed_at_ns {
            Some(ns) => (
                judge.receive(frame.crc_ok, counter, ns / NANOS_PER_MILLI),
                true,
            ),
            None => (judge.receive_without_clock(frame.crc_ok, counter), false),
        };
        // The counter is read from the field the judge was configured from, so
        // it fits; the error exists for a caller that mixed two profiles' frames.
        // This ledger is keyed by slot and a slot belongs to one rule, so a
        // profile cannot change under a judge, and the unreachable arm is left
        // as "not judged" rather than a panic in a library a C consumer links.
        let judgment = judged.ok();
        Outcome::Opened(Box::new(Opened {
            frame,
            slot,
            timed: timed && judgment.is_some(),
            judgment,
            previous,
            step,
        }))
    }
}
