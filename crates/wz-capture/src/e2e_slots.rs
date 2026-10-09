// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
}

/// The ledger of a run: a judge per slot seen.
#[derive(Debug, Default)]
pub struct SlotLedger {
    judges: BTreeMap<Slot, Judge>,
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

    /// Read `reception.payload` under its profile and judge it against its slot.
    pub fn receive(&mut self, reception: &Reception<'_>) -> Outcome {
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
            }));
        }
        let judge = self
            .judges
            .entry(slot.clone())
            .or_insert_with(|| profile.judge());
        let counter = frame.counter(profile);
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
        }))
    }
}
