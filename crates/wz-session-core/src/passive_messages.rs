// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y723 (§1.1f) — the one type decoded transport messages are held in.
//!
//! # Where this lives, and why it moved (R311y752, carry N12)
//!
//! It was `wz-capture::messages` until R311y752, one layer above everything it
//! is made of: a [`MessageList`] is a list of [`crate::passive::PassiveFrame`],
//! [`Discarded`] carries one, and every arm of
//! [`DroppedFrameCensus::absorb`] matches a [`crate::inbound::InboundFrame`].
//! Not one line of it named a capture type — the pcap reading, the flow table
//! and the TLS half were never involved — so a consumer that wanted to census
//! decoded messages had to take the capture crate to name the type they come
//! in.
//!
//! The three types moved TOGETHER, and that is the load-bearing part rather
//! than a tidiness: R311y746 (carry N11) closed the discard obligation by
//! putting the receipt's private `take` and the census that consumes it behind
//! ONE privacy boundary. Moving [`MessageList`] alone would have left
//! `discard_oldest` producing a receipt whose only legal consumer was in
//! another crate, which is that boundary deleted. A move that has to keep an
//! invariant intact is a move of everything the invariant spans.
//!
//! Cross-crate references in these docs are PROSE, not intra-doc links: the
//! census planes are in `wz-capture`, which depends on this crate and not the
//! other way round, so a link would name a crate this one must not know.
//!
//! # What this replaces, and why a type rather than a wider check
//!
//! Four census planes walk one enumeration (`Dissection::message_lists` in
//! `wz-capture`,
//! R311y721) and a gate reds when a `Vec<PassiveFrame>` field is outside it
//! (R311y722). Asked what that gate could not see, the honest answer was two
//! things, and the SECOND was the larger: the gate's population was a container
//! SHAPE, so `Vec<(SerialFrame, PassiveFrame)>` — which is exactly what the
//! serial list looked like one round earlier — matched nothing. A producer
//! wrapped in a tuple, an array or a map was invisible to it.
//!
//! Widening the regex would have chased shapes forever. This is the other
//! answer: make the population a NAME. A field that holds decoded messages says
//! `MessageList` somewhere in its declaration whatever it is wrapped in, so the
//! gate stops guessing at syntax and reads a type.
//!
//! # Why the API is shaped the way it is
//!
//! Readers get ROWS, not a slice, through [`Messages`]: the list read with the
//! bytes of the messages it keeps as index entries ([`MessageList::read`]), which
//! hands out [`Row`]s by position or walking, and each row's [`RowHead`] without
//! decoding it. Two rules hold, R311y713's and open-debt item 924's:
//!
//! - Nothing can GROW or SHRINK the list except through a method here: the row
//!   API has no `push`, no `extend` and no `remove`. That makes the accounting
//!   obligation a place in the type system rather than a paragraph a reader has
//!   to follow.
//! - Nothing outside this type learns how the rows are STORED. Until item 924
//!   the list was a slice behind `Deref`, which promised every reader one
//!   contiguous run; a list of hundreds of thousands of rows kept that promise
//!   by doubling one buffer and copying every row into each new one, and held up
//!   to half of it as capacity no row used. The rows sit in chunks (see
//!   `ChunkLog`), and a list whose units can be read again from their bytes keeps
//!   them as index entries and decodes a row when it is read (see `Store`).
//!
//! # The discard receipt
//!
//! [`MessageList::discard_oldest`] returns a `#[must_use]` [`Discarded`] that
//! panics if dropped without being consumed. A bound that drops a message and
//! does not say so is the defect `DissectionDrops` exists to prevent, and this
//! workspace has fixed instances of it four times by hand (R311y612, y649,
//! y650, y656) before R311y713 ended the same shape for flow exits by making it
//! a type. This is that ending, applied to the other list.

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use crate::ascending_map::AscendingMap;
use crate::byte_log::{LogPlace, UnitLog};
use crate::chunk_log::{ChunkLog, Iter};
use crate::inbound::InboundFrame;
#[cfg(feature = "reassembly")]
use crate::passive::FragmentFate;
use crate::passive::{
    redecode_unit, Anchor, Direction, FlowContext, LinkHandshake, MessageFacts, OffsetSpace,
    PassiveFrame, ReadUnit, SnVerdict, StreamResync, UnitFacts, UnitInput,
};
#[cfg(feature = "reassembly")]
use crate::reassembly_dispatch::IngestOutcome;

/// Decoded transport messages, in the order the observer produced them.
///
/// See the module doc: this is a wrapper type so that the population of "things
/// a census plane must be shown" is a NAME rather than a container shape, and
/// so that growth and removal have exactly one door each.
///
/// R2102 (open-debt item 524) — it holds a second field now, and having the one
/// door is what let it: [`MessageList::produced`] is maintained by `push` and
/// `append` and by nothing else, which is a claim only a type whose growth has
/// exactly one door can make.
#[derive(Debug, Default)]
pub struct MessageList {
    /// The rows, in chunks.
    ///
    /// R2109 (open-debt item 528) — taking the oldest is O(1): it was a `Vec`
    /// whose `remove(0)` moved the whole list per message discarded, and a live
    /// tap at its `frames_per_flow` ceiling paid list-length per incoming
    /// message (one 1400-byte packet cost 28.8 ms against 67 us uncapped).
    ///
    /// Open-debt item 924 — and growing is O(1) without copying what is held:
    /// one buffer that doubles copies every row into each new buffer and holds
    /// up to half of it unused, which on a replayed file of a million rows is
    /// hundreds of megabytes. See [`ChunkLog`].
    ///
    /// Open-debt item 924, step 4b — and a row whose unit can be read again
    /// from its bytes keeps no decoded frame at all. See [`Store`].
    rows: Store,
    /// R2102 (open-debt item 524) — messages EVER appended to this list, which
    /// is a different number from `len` the moment a bound bites.
    ///
    /// # Why a monotone total, and why it lives on the list
    ///
    /// A reader that consumes this list INCREMENTALLY — a live tap draining
    /// what has become decodable since it last looked — needs a watermark that
    /// says "I have taken the first N of this list". An INDEX into the held
    /// vector cannot be that watermark: [`MessageList::discard_oldest`] removes
    /// from the FRONT, so every trim silently renumbers every position behind
    /// it, and a consumer holding index 40 would re-deliver messages or skip
    /// them depending on which way the trim went.
    ///
    /// This counter is untouched by removal, so `produced - len` is the
    /// produced-index of the OLDEST message still here. A consumer compares its
    /// own watermark against that number and learns, exactly, how many messages
    /// were discarded out from under it — which is the same obligation
    /// [`Discarded`] states for the census, one consumer over: a bound that
    /// takes something away from a reader and does not say so reports a floor
    /// as a total.
    ///
    /// It also tells a list APART from its successor. A flow evicted and then
    /// reopened under the same 5-tuple gets a fresh list whose `produced` is
    /// zero, and a watermark above zero is how a consumer knows the slot it was
    /// tracking is not the list now standing in it.
    produced: u64,
    /// The chain identities the messages this list has DISCARDED left behind:
    /// the fold [`ChainFold`] describes, run over every message that was
    /// removed from the front, in the order it was removed.
    ///
    /// # Why the list carries it
    ///
    /// A fragment chain's identity is a count of the chains that began before it
    /// in its list. Counted from the first message the list HOLDS, a front trim
    /// that takes the first message of a chain renumbers every chain after it,
    /// and a consumer that was handed an identity cannot keep it. Counted from
    /// the first message the list EVER held, the number is a fact about the
    /// list's history and a trim cannot move it. A trim is the one moment the
    /// message is still in hand, so it is the one place the fold can take it:
    /// a reader that begins its walk later starts from this state instead of
    /// from nothing, and numbers every chain as a reader that never missed a
    /// message would have.
    #[cfg(feature = "reassembly")]
    chain_prefix: ChainFold,
    /// What the chain fold made of each row it moved, decided as the row was
    /// appended (open-debt item 924, D9): a row's chain identity is a count of
    /// the chains that began before it in its list, which no reading of the row
    /// alone can recover, so it is a fact of the row like its SN verdict, kept
    /// for the few rows that have one. A reader that begins anywhere reads it
    /// here instead of folding the rows before.
    #[cfg(feature = "reassembly")]
    chains: ChainFacts,
}

/// The chain fold over every message a list was ever appended, and what it made
/// of each row still held that it moved. See [`MessageList::chain_of`].
#[cfg(feature = "reassembly")]
#[derive(Debug, Default)]
struct ChainFacts {
    /// The fold as the last appended message left it.
    fold: ChainFold,
    /// By produced-index, the outcome and identity of every held row the fold
    /// moved; a row it did not move (no fragment, or no outcome) has none.
    rows: AscendingMap<(IngestOutcome, Option<u64>)>,
}

/// The key a fragment chain is held under: the direction it travelled, whether
/// it is on the reliable channel, and its priority. The router keys a chain by
/// `(peer, reliable, priority)` and an observer holds one router per direction,
/// so this is the same key, read off the same fields.
#[cfg(feature = "reassembly")]
pub type ChainKey = (crate::passive::Direction, bool, crate::qos::Priority);

/// CHAIN IDENTITY, one per list, assigned in message order, and kept across a
/// front trim by the list that holds the messages (see [`MessageList`]).
///
/// # What the identity is, and what it is not
///
/// A number shared by every row that touched ONE chain, unique within its list
/// and counted from 0 in the order chains began. It is an identity for ROWS: it
/// says which fragments belong together, not where in any buffer they were
/// joined.
///
/// # Why it is folded here and cannot drift from the router
///
/// The fold follows the router's OWN outcome rather than re-judging anything:
///
/// * `Begun` opens a new identity. A chain already open on the key was ended by
///   the router without a row (a `First` restart, or a deadline sweep), so
///   minting unconditionally is what keeps the two in step.
/// * `Continued` takes the key's open identity, or none when the chain began
///   before the first message the fold has seen.
/// * `Reassembled` and `Aborted` take it and close it, or mint one for a chain
///   that began and ended on this very fragment.
/// * `Refused` has none: no chain was allocated.
#[cfg(feature = "reassembly")]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ChainFold {
    next: u64,
    open: Vec<(ChainKey, u64)>,
}

#[cfg(feature = "reassembly")]
impl ChainFold {
    /// Advance the fold by one message, and say what the router made of it and
    /// the identity of the chain it touched.
    ///
    /// `None` for a message that is not a fragment, or that carries no router
    /// outcome (a whole lz4 batch no message was read out of): the fold does not
    /// move. The identity is `None` for a continuation of a chain this fold never
    /// saw begin, and for a refusal.
    pub fn observe(&mut self, frame: &PassiveFrame) -> Option<(IngestOutcome, Option<u64>)> {
        use crate::inbound::InboundFrame;
        use crate::passive::Carried;
        use crate::reassembly_dispatch::AbortReason;

        let Ok(InboundFrame::Fragment {
            reliable, priority, ..
        }) = &frame.frame
        else {
            return None;
        };
        let key = (frame.direction, *reliable, *priority);
        let outcome = match &frame.carried {
            Carried::Fragment(outcome) => *outcome,
            // The joiner handed a payload back on this fragment.
            Carried::Reassembled { .. } => IngestOutcome::Reassembled,
            // The router ran on a flow with no SN resolution and ended the chain
            // this fragment continued, because only the ring could have judged
            // the step. The session reports that as a variant of its own, so the
            // outcome is named here rather than carried: it is the one the
            // variant stands for.
            Carried::FragmentWithoutResolution => IngestOutcome::Aborted(AbortReason::Unresolvable),
            // `Undecompressible` is a whole lz4 batch no message was read out of,
            // so no fragment reached the router.
            Carried::Undecompressible | Carried::Nothing | Carried::Batch(_) => return None,
        };
        let identity = match outcome {
            IngestOutcome::Begun => Some(self.begin(key)),
            IngestOutcome::Continued => self.current(key),
            IngestOutcome::Reassembled | IngestOutcome::Aborted(_) => Some(self.close(key)),
            IngestOutcome::Refused(_) => None,
        };
        Some((outcome, identity))
    }

    fn begin(&mut self, key: ChainKey) -> u64 {
        let id = self.next;
        self.next += 1;
        match self.open.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = id,
            None => self.open.push((key, id)),
        }
        id
    }

    fn current(&self, key: ChainKey) -> Option<u64> {
        self.open.iter().find(|(k, _)| *k == key).map(|(_, id)| *id)
    }

    fn close(&mut self, key: ChainKey) -> u64 {
        match self.open.iter().position(|(k, _)| *k == key) {
            Some(i) => self.open.swap_remove(i).1,
            None => {
                let id = self.next;
                self.next += 1;
                id
            }
        }
    }
}

impl MessageList {
    /// An empty list.
    pub fn new() -> Self {
        Self {
            rows: Store::default(),
            produced: 0,
            #[cfg(feature = "reassembly")]
            chain_prefix: ChainFold::default(),
            #[cfg(feature = "reassembly")]
            chains: ChainFacts::default(),
        }
    }

    /// What the chain fold made of the row at produced-index `produced`: the
    /// router's outcome and the identity of the chain it touched, as a walk of
    /// every message the list was ever appended would find them; `None` for a
    /// row that is not a fragment or carries no outcome, and for one not held.
    #[cfg(feature = "reassembly")]
    pub fn chain_of(&self, produced: u64) -> Option<(IngestOutcome, Option<u64>)> {
        self.chains.rows.get(produced).copied()
    }

    /// Move the chain fold by the message about to be appended at `produced`.
    #[cfg_attr(not(feature = "reassembly"), allow(unused_variables))]
    fn note_chain(&mut self, produced: u64, frame: &PassiveFrame) {
        #[cfg(feature = "reassembly")]
        if let Some(fact) = self.chains.fold.observe(frame) {
            self.chains.rows.insert(produced, fact);
        }
    }

    /// The chain fold the messages this list has DISCARDED left behind: the state
    /// a reader that begins at the first message the list holds must start from to
    /// number chains as one that saw every message would. See the field's own doc.
    #[cfg(feature = "reassembly")]
    pub fn chain_prefix(&self) -> &ChainFold {
        &self.chain_prefix
    }

    /// Append one decoded message, kept whole.
    pub fn push(&mut self, frame: PassiveFrame) {
        self.note_chain(self.produced, &frame);
        match &mut self.rows {
            Store::Held(log) => log.push_back(frame),
            Store::Indexed(index) => index.push_held(self.produced, frame),
        }
        self.produced += 1;
    }

    /// Append a decoded batch, which is what a datagram unit yields.
    pub fn append(&mut self, frames: impl IntoIterator<Item = PassiveFrame>) {
        // Counted as they go in rather than from the iterator's size hint, which
        // an `IntoIterator` may report and not deliver.
        for frame in frames {
            self.push(frame);
        }
    }

    /// Append every record of one framing unit, as
    /// `PassiveSession::next_unit_with` hands it out.
    ///
    /// Open-debt item 924, step 4b — a unit read off a byte stream is kept as
    /// index entries: the records are let go here, and read again from the
    /// stream's bytes when a reader asks for them ([`Messages`]). That needs
    /// what the session knew when it read the unit ([`ReadUnit::start`]),
    /// coordinates an entry can carry, and the unit's bytes in `source`, whole:
    /// a holder bounded by a byte ceiling can have released the front of a unit
    /// before its last byte arrived. A unit that lacks any of the three is kept
    /// whole instead, which reads the same.
    pub fn push_unit(&mut self, unit: ReadUnit, source: &dyn UnitBytes) {
        let ReadUnit { start, frames } = unit;
        let readable = start.filter(|_| {
            frames.iter().all(UnitRow::can_hold_streamed)
                && frames.first().is_some_and(|first| {
                    let body = first.stream_offset + first.prefix_width;
                    first.wire_end.is_some_and(|end| {
                        source.stream_bytes(first.direction, body, end).is_some()
                    })
                })
        });
        let Some(start) = readable else {
            self.append(frames);
            return;
        };
        let produced = self.produced;
        for (k, frame) in frames.iter().enumerate() {
            self.note_chain(produced + k as u64, frame);
        }
        self.index()
            .push_unit(produced, start, &frames, Locus::Streamed);
        self.produced += frames.len() as u64;
    }

    /// Append every record of one datagram unit, as
    /// `PassiveSession::next_datagram_unit_on` hands it out, with `bytes` the
    /// unit as it was read and `handshake` the link's.
    ///
    /// Open-debt item 924, step 4c (`docs/dissect-row-index.md`, D8) — the
    /// unit's bytes go into the list's unit log, and its records are read again
    /// from there. `in_container` is where `bytes` sit in the capture container
    /// the list's holder lends, when they do: the log then remembers that place
    /// and keeps no copy, and a reader hands the container in with its source
    /// ([`UnitBytes::container`]). A unit an entry cannot stand for (a record
    /// inadmissible on its link, a coordinate past an entry's fields) is kept
    /// whole, which reads the same, and logs nothing.
    pub fn push_datagram(
        &mut self,
        unit: ReadUnit,
        bytes: &[u8],
        in_container: Option<usize>,
        handshake: LinkHandshake,
    ) {
        let ReadUnit { start, frames } = unit;
        // A unit a layer below framed (a WebSocket message) says where its bytes
        // end in the stream it was carried in, which its own bytes cannot say;
        // every record of it says the same, and the entries keep it once.
        let wire_end = frames.first().and_then(|first| first.wire_end);
        let readable = start.filter(|_| {
            u32::try_from(bytes.len()).is_ok()
                && frames
                    .iter()
                    .all(|frame| UnitRow::can_hold_logged(frame) && frame.wire_end == wire_end)
        });
        let Some(start) = readable else {
            self.append(frames);
            return;
        };
        let produced = self.produced;
        for (k, frame) in frames.iter().enumerate() {
            self.note_chain(produced + k as u64, frame);
        }
        let index = self.index();
        let place = index.log.place(bytes, in_container);
        index.push_unit(
            produced,
            start,
            &frames,
            Locus::Logged {
                place,
                len: bytes.len(),
                handshake,
                wire_end,
            },
        );
        self.produced += frames.len() as u64;
    }

    /// The list's index, made of the rows it keeps whole if it has none yet:
    /// what a list that begins to keep entries turns into, whatever it held.
    fn index(&mut self) -> &mut Index {
        if let Store::Held(log) = &mut self.rows {
            let mut index = Box::<Index>::default();
            let first_produced = self.produced - log.len() as u64;
            for (k, frame) in core::mem::take(log).into_iter().enumerate() {
                index.push_held(first_produced + k as u64, frame);
            }
            self.rows = Store::Indexed(index);
        }
        match &mut self.rows {
            Store::Indexed(index) => index,
            Store::Held(_) => unreachable!("the list was given an index above"),
        }
    }

    /// R2102 (open-debt item 524) — messages ever appended here, never
    /// decremented.
    ///
    /// See the field's own doc for why a position in the list cannot do this
    /// job.
    pub fn produced(&self) -> u64 {
        self.produced
    }

    /// R311y723 — drop the OLDEST message, and hand back a receipt for it.
    ///
    /// The only removal this type offers, and it is deliberately not `remove`:
    /// a bound on a live tap discards the oldest and nothing else, so an index
    /// parameter would be an invitation to write a second policy. See
    /// [`Discarded`] for why the return value cannot be ignored.
    ///
    /// `source` is where the list reads the bytes of a message it keeps as an
    /// index entry (see [`Self::read`]): the receipt carries the decoded
    /// message, so one kept that way is read again to be handed over.
    ///
    /// `None` for an empty list rather than a panic: a bound that cannot be met
    /// must not take the capture down with it, which is the rule the flow caps
    /// already follow.
    #[must_use = "a discarded message must be accounted for -- see `Discarded`"]
    pub fn discard_oldest(&mut self, source: &dyn UnitBytes) -> Option<Discarded> {
        let first_produced = self.produced - self.len() as u64;
        let frame = match &mut self.rows {
            Store::Held(log) => log.pop_front()?,
            Store::Indexed(index) => index.pop_front(first_produced, source)?,
        };
        // The one moment the message is still in hand: fold what a chain's
        // identity needs of it, so the count does not depend on how much of the
        // front a ceiling has taken. See the field's doc.
        #[cfg(feature = "reassembly")]
        let _ = self.chain_prefix.observe(&frame);
        // A row no longer held has no fact to be read.
        #[cfg(feature = "reassembly")]
        self.chains.rows.remove(first_produced);
        Some(Discarded {
            // `produced` deliberately does NOT move here. It counts what was
            // ever appended, and a trim is the one event a consumer's watermark
            // has to be able to see across.
            frame: Some(frame),
        })
    }

    /// Messages held now: what was appended less what a bound discarded.
    #[inline]
    pub fn len(&self) -> usize {
        match &self.rows {
            Store::Held(log) => log.len(),
            Store::Indexed(index) => index.entries.len(),
        }
    }

    /// No message is held.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Restate where the messages from position `from` on stand on the wire:
    /// `restate` is handed each one's direction, anchor offset and end
    /// ([`PassiveFrame::stream_offset`], [`PassiveFrame::wire_end`]) and gives
    /// back the two it stands at instead.
    ///
    /// Open-debt item 924, step 4c — for units a layer below produced in a byte
    /// space of its own, which the report states in the space of the wire that
    /// carried them: a TLS flow's units are framed in the plaintext, and each
    /// stands where the record that carried it does. A message kept as an
    /// index entry is still read from where it was read (its locator does not
    /// move); its anchor takes the new offset, and its end is kept beside the
    /// entries, once per unit (`Index::wire_ends`, which is private). Every row of one unit
    /// must be given the same end, which a restatement by the unit's own
    /// coordinates does.
    pub fn restate_from(
        &mut self,
        from: usize,
        restate: &mut dyn FnMut(Direction, usize, Option<usize>) -> (usize, Option<usize>),
    ) {
        let first_produced = self.produced - self.len() as u64;
        match &mut self.rows {
            Store::Held(log) => {
                for frame in log.iter_mut_from(from) {
                    let (offset, end) =
                        restate(frame.direction, frame.stream_offset, frame.wire_end);
                    frame.stream_offset = offset;
                    frame.wire_end = end;
                }
            }
            Store::Indexed(index) => index.restate_from(first_produced, from, restate),
        }
    }

    /// Where in its source the oldest message of `direction` read from a
    /// byte stream begins being read, looked for among the first `within`
    /// messages held: what a holder that lets the front of that stream go must
    /// keep from. `None` when none of them is such a message of `direction`
    /// (it is kept whole, logged, or further back).
    ///
    /// Open-debt item 924, step 4c — asked of the list and not of a row's
    /// anchor, which a restated message ([`Self::restate_from`]) has moved into
    /// another space.
    pub fn oldest_source_offset(&self, direction: Direction, within: usize) -> Option<usize> {
        let Store::Indexed(index) = &self.rows else {
            return None;
        };
        index
            .entries
            .iter_from(0)
            .take(within)
            .filter_map(|entry| match entry.entry() {
                Entry::Unit(row) if !row.logged() && row.direction() == direction => {
                    Some(row.body().0)
                }
                _ => None,
            })
            .next()
    }

    /// Keep whole every message of `direction` whose unit's bytes begin before
    /// stream offset `offset`, reading each from `source` while it still holds
    /// them.
    ///
    /// What a holder calls BEFORE it releases the bytes of `direction`'s stream
    /// that stand before `offset`: a message kept as an index entry is read
    /// again from those bytes, and one whose bytes are gone could not be. A
    /// message kept whole reads as it did, so every reader's answer is the one
    /// it was before the release. A list that keeps every message whole has
    /// nothing to do.
    pub fn keep_whole_before(
        &mut self,
        direction: Direction,
        offset: usize,
        source: &dyn UnitBytes,
    ) {
        let first_produced = self.produced - self.len() as u64;
        if let Store::Indexed(index) = &mut self.rows {
            index.keep_whole_before(first_produced, direction, offset, source);
        }
    }

    /// The list as a reader reads it, with `source` the bytes of the messages
    /// it keeps as index entries.
    ///
    /// The source is the holder's: a flow's reassembled stream, or [`NoBytes`]
    /// for a list whose messages are all kept whole. A list cannot keep it
    /// itself, because the bytes belong to whatever framed the units and are
    /// released by it.
    #[inline]
    pub fn read<'a>(&'a self, source: &'a dyn UnitBytes) -> Messages<'a> {
        Messages { list: self, source }
    }
}

/// Where a list reads the bytes of the framing units it keeps as index entries.
///
/// Open-debt item 924 (`docs/dissect-row-index.md`, D1): the holder of the
/// bytes answers, by stream coordinate, so a list keeps none of them.
pub trait UnitBytes {
    /// The bytes of `direction`'s stream from offset `from` up to `to`, or
    /// `None` when the source does not hold all of them.
    fn stream_bytes(&self, direction: Direction, from: usize, to: usize) -> Option<Cow<'_, [u8]>>;

    /// The capture container the list's holder lends, which a datagram unit
    /// logged by its place there is read from ([`MessageList::push_datagram`]);
    /// `None` when the holder lends none.
    fn container(&self) -> Option<&[u8]> {
        None
    }
}

/// The source of a list that keeps every message whole, and so reads no bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoBytes;

impl UnitBytes for NoBytes {
    fn stream_bytes(&self, _: Direction, _: usize, _: usize) -> Option<Cow<'_, [u8]>> {
        None
    }
}

/// The source of a list of datagrams: no stream, and the container its holder
/// lends, if any. The list keeps the rest of its units' bytes itself.
#[derive(Debug, Clone, Copy, Default)]
pub struct Datagrams<'a> {
    /// What [`UnitBytes::container`] answers.
    pub container: Option<&'a [u8]>,
}

impl UnitBytes for Datagrams<'_> {
    fn stream_bytes(&self, _: Direction, _: usize, _: usize) -> Option<Cow<'_, [u8]>> {
        None
    }

    fn container(&self) -> Option<&[u8]> {
        self.container
    }
}

/// How a [`MessageList`] keeps its rows.
#[derive(Debug)]
enum Store {
    /// Every row as its decoded frame. A list starts here, and stays here until
    /// a unit it is handed can be read again from its bytes; a list whose units
    /// a layer below decrypted (TLS) is never handed one.
    Held(ChunkLog<PassiveFrame>),
    /// Rows as index entries, read again on demand (see [`Index`]). Boxed, so a
    /// list that keeps its frames does not carry the index's size.
    Indexed(Box<Index>),
}

impl Default for Store {
    fn default() -> Self {
        Store::Held(ChunkLog::new())
    }
}

/// The rows of a list that keeps its units as index entries.
///
/// Open-debt item 924, steps 4b and 4c (`docs/dissect-row-index.md`, D2, D3
/// and D8). One entry per row, in row order. An entry says where its unit's
/// bytes lie (a range of its direction's stream, or a place in the unit log) and
/// what the first reading knew that the unit's bytes do not; [`redecode_unit`]
/// makes the row again from those. The few facts most
/// rows do not have (an SN verdict other than continuous, a fragment's fate, a
/// resynchronisation) are kept apart, by produced-index, and the context a unit
/// was read in is kept once per change.
///
/// A row whose unit cannot be read that way is kept whole beside the entries,
/// so one list can hold both, and so is a row whose bytes its source is about
/// to release ([`MessageList::keep_whole_before`]).
#[derive(Debug, Default)]
struct Index {
    /// One per row, oldest first.
    entries: ChunkLog<UnitRow>,
    /// The units whose entries are logged ([`LOGGED`]): a copy of each one's
    /// bytes, in the order they were logged, or its place in the container the
    /// list's holder lends. A unit's copy goes when a discard takes the unit's
    /// last row ([`Self::pop_front`]).
    log: UnitLog,
    /// The frames of the rows kept whole, by produced-index. Few: a list keeps
    /// a row whole only where it cannot read it again.
    held: BTreeMap<u64, PassiveFrame>,
    /// Per direction, the produced-index below which no row of that direction
    /// is an entry any more: where [`Self::keep_whole_before`] resumes, so a
    /// source that releases bytes on every packet does not walk the rows it
    /// already kept whole.
    whole_below: [u64; 2],
    /// The context each unit was read in, each value once, in the order the
    /// units were read; a [`UnitRow`] names one by place. A context changes only
    /// at a handshake message, so this stays a few long.
    contexts: Vec<FlowContext>,
    /// The facts few rows have, by the row's produced-index
    /// ([`AscendingMap`]: the keys arrive in order and leave from the front).
    sparse: AscendingMap<Sparse>,
    /// What each fragment row came to, apart from [`Self::sparse`] because a
    /// completed chain's fate owns a buffer and the others are three bytes.
    #[cfg(feature = "reassembly")]
    fates: Fates,
    /// The facts of the rows of the OLDEST unit a discard has already taken,
    /// while rows of that unit are still held: what reading those rows again
    /// needs and no entry holds any more. Empty otherwise. Only the oldest unit
    /// can be cut, because rows are discarded from the front.
    cut: Vec<MessageFacts>,
    /// The resynchronisation the cut unit's first row carried.
    cut_resync: Option<StreamResync>,
    /// Where each unit whose end is not its bytes' ends on the wire
    /// ([`PassiveFrame::wire_end`] of its records), by [`UnitRow::end_key`]: a
    /// unit a layer below framed (a WebSocket message) or decrypted (a TLS
    /// record's plaintext) ends where the layer's own unit does. Kept once per
    /// unit for the rows flagged [`WIRE_END`], a flagged row with no end here
    /// has none, and the unit's last row lets it go.
    wire_ends: BTreeMap<(u16, u64), u64>,
}

/// What a [`MessageList`] holds on the heap, by structure (open-debt item 924,
/// D7): the memory report the capture layer sums over its lists.
///
/// Only the structures that follow the row count are named, and `small` is the
/// rest of the index (the contexts, the cut unit), which does not. A figure is
/// bytes allocated and not bytes used, because the first is what the process
/// holds. See [`crate::heap_account`] for what is exact and what is a model.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ListMemory {
    /// The rows: 48-byte entries when the list is an index, else each row's
    /// decoded frame as the slot it sits in (what a frame owns beyond its slot is
    /// not counted).
    pub rows: usize,
    /// The units' bytes the list keeps (copies; a unit in a lent container costs
    /// nothing here).
    pub unit_log: usize,
    /// The rows kept whole beside the entries, a model of their map.
    pub whole_rows: usize,
    /// The facts few rows have (a sequence gap's count, a fragment's fate, a
    /// resynchronisation), as the log that holds them allocated them.
    pub sparse: usize,
    /// Where units a layer below framed end, a model of their map.
    pub wire_ends: usize,
    /// The messages that completed a fragment chain, joined: the only copy of those
    /// bytes anywhere, kept so a consumer can read the joined message back. It
    /// follows the chains' content and not the row count, and it is read off every
    /// fact the list keeps for a row, so asking costs the number of those.
    pub joined: usize,
    /// The chain each fragment row belongs to and what became of it, by row (a
    /// model of the map), and the chains still open. Kept by every list that has
    /// seen a fragment, whether it keeps its rows as entries or whole.
    pub chains: usize,
    /// The rest of the index, which does not follow the row count.
    pub small: usize,
}

impl ListMemory {
    /// Every structure's bytes together.
    pub fn total(&self) -> usize {
        self.rows
            + self.unit_log
            + self.whole_rows
            + self.sparse
            + self.wire_ends
            + self.joined
            + self.chains
            + self.small
    }

    /// This report and `other` added field by field, for a holder of many lists.
    pub fn plus(&self, other: &Self) -> Self {
        Self {
            rows: self.rows + other.rows,
            unit_log: self.unit_log + other.unit_log,
            whole_rows: self.whole_rows + other.whole_rows,
            sparse: self.sparse + other.sparse,
            wire_ends: self.wire_ends + other.wire_ends,
            joined: self.joined + other.joined,
            chains: self.chains + other.chains,
            small: self.small + other.small,
        }
    }
}

impl Index {
    /// Bytes the fragment fates hold: the class of each, and the joined messages of
    /// the chains that completed with the slots that hold them.
    #[cfg(feature = "reassembly")]
    fn fate_bytes(&self) -> (usize, usize) {
        self.fates.bytes()
    }

    /// Without reassembly no row has a fate to hold.
    #[cfg(not(feature = "reassembly"))]
    fn fate_bytes(&self) -> (usize, usize) {
        (0, 0)
    }

    /// What the index holds on the heap.
    fn memory(&self) -> ListMemory {
        let (fates, joined) = self.fate_bytes();
        ListMemory {
            rows: self.entries.allocated_bytes(),
            unit_log: self.log.allocated(),
            whole_rows: crate::heap_account::btree_bytes::<u64, PassiveFrame>(self.held.len()),
            sparse: self.sparse.allocated_bytes() + fates,
            wire_ends: crate::heap_account::btree_bytes::<(u16, u64), u64>(self.wire_ends.len()),
            joined,
            // The list's, which owns the chain facts and adds them.
            chains: 0,
            small: crate::heap_account::vec_bytes(&self.contexts)
                + crate::heap_account::vec_bytes(&self.cut),
        }
    }
}

impl MessageList {
    /// What the chain facts of the list hold: the outcome and identity of every
    /// fragment row, and the chains still open and the ones the discarded rows
    /// left counted.
    #[cfg(feature = "reassembly")]
    fn chain_bytes(&self) -> usize {
        self.chains.rows.allocated_bytes()
            + crate::heap_account::vec_bytes(&self.chains.fold.open)
            + crate::heap_account::vec_bytes(&self.chain_prefix.open)
    }

    /// Without reassembly no fragment is read and no chain is counted.
    #[cfg(not(feature = "reassembly"))]
    fn chain_bytes(&self) -> usize {
        0
    }

    /// What the list holds on the heap, by structure.
    pub fn memory(&self) -> ListMemory {
        let held = match &self.rows {
            Store::Held(frames) => ListMemory {
                rows: frames.allocated_bytes(),
                ..ListMemory::default()
            },
            Store::Indexed(index) => index.memory(),
        };
        ListMemory {
            chains: self.chain_bytes(),
            ..held
        }
    }
}

/// One row of an [`Index`], as its [`UnitRow`] says.
#[derive(Debug, Clone, Copy)]
enum Entry {
    /// Kept whole, in [`Index::held`].
    Held,
    /// Read again from its unit's bytes.
    Unit(UnitRow),
}

/// What an [`Index`] keeps of a row: where its unit's bytes lie, where the row
/// sits in the unit, and what the first reading knew that the unit's bytes do
/// not say. 48 bytes, against a decoded frame's 424 and what it owns.
///
/// One layout for every row (open-debt item 924, D8): a row kept whole is the
/// [`HELD`] flag on it rather than an enum around it, whose tag would cost a
/// word on every row, and a row of a datagram unit differs from one of a
/// stream unit only in what its [`Self::locator`] counts ([`LOGGED`]).
#[derive(Debug, Clone, Copy)]
struct UnitRow {
    /// [`PassiveFrame::stream_offset`] of the unit: its length prefix in its
    /// direction's stream, or the index of the packet that carried a datagram.
    anchor: u64,
    /// Where the unit's body is: its first byte in its direction's stream, or,
    /// with [`LOGGED`] set, its place in the unit log ([`LogPlace`]).
    locator: u64,
    /// The capture instant of the row's first byte, when [`TIMED`] is set.
    observed_at_ns: u64,
    /// [`PassiveFrame::unit_len`]: the unit's length as read, which for an lz4
    /// batch is the length decompressed.
    unit_len: u32,
    /// The unit's length on the wire, past its prefix.
    wire_len: u32,
    /// [`PassiveFrame::unit_offset`].
    unit_offset: u32,
    /// [`PassiveFrame::batch_index`].
    batch_index: u32,
    /// The context the unit was read in, by its place in [`Index::contexts`].
    context: u32,
    /// [`PassiveFrame::prefix_width`].
    prefix_width: u8,
    /// [`RowHead::kind`].
    kind: u8,
    /// The flags below.
    flags: u16,
}

/// The row travelled [`Direction::B`].
const SIDE_B: u16 = 1;
/// [`UnitRow::observed_at_ns`] is an instant.
const TIMED: u16 = 1 << 1;
/// [`PassiveFrame::exceeds_negotiated_batch`].
const OVER_BATCH: u16 = 1 << 2;
/// The row carries a resynchronisation ([`Sparse::resync`]).
const AFTER_RESYNC: u16 = 1 << 3;
/// The row was read out of an lz4 batch ([`PassiveFrame::decompressed`]).
const DECOMPRESSED: u16 = 1 << 4;
/// The row is a fragment with a fate, which [`Index`] keeps in its [`Fates`]. (Bit 5
/// was the flag for a `SnVerdict::Continuous` row, which the SN class
/// (`SN_SHIFT`) now holds with every other verdict that carries no number.)
const FRAGMENT: u16 = 1 << 5;
/// [`Index::sparse`] holds facts for this row.
const SPARSE: u16 = 1 << 6;
/// The row is kept whole, in [`Index::held`]; no other field means anything.
const HELD: u16 = 1 << 7;
/// The row's unit is a datagram: its anchor is a packet index and its locator a
/// place in the unit log.
const LOGGED: u16 = 1 << 8;
/// The datagram's link carries no handshake ([`LinkHandshake::Absent`]).
///
/// Kept so a datagram is read again with the input it was first read with. No
/// reachable state makes the two readings of an entry differ today: the walk
/// reads the flag to judge a handshake message inadmissible, and such a row is
/// kept whole, and to look for a batch header, which only an InitAck folded on
/// the link turns on, and a link without a handshake folds none. The redecode
/// gate therefore cannot tell this flag from its absence, and the flag does not
/// depend on that holding.
const NO_HANDSHAKE: u16 = 1 << 9;
/// The row's end on the wire is the index's to say ([`Index::wire_ends`]), not
/// the end of its bytes: a WebSocket message's last frame, the TLS record that
/// carried a unit's last plaintext byte.
const WIRE_END: u16 = 1 << 10;

/// Where the unit of the rows [`Index::push_unit`] is handed lies.
#[derive(Debug, Clone, Copy)]
enum Locus {
    /// In its direction's stream, where its rows' coordinates say.
    Streamed,
    /// In the unit log.
    Logged {
        place: LogPlace,
        /// The unit's length.
        len: usize,
        /// The link's handshake, which a datagram's reading depends on.
        handshake: LinkHandshake,
        /// Where the unit ends in the stream a layer below carried it in, when
        /// one did.
        wire_end: Option<usize>,
    },
}

/// Where in [`UnitRow::flags`] the row's SN verdict class is kept: three bits.
///
/// Open-debt item 924, step 5. A verdict used to be in [`Index::sparse`] unless it
/// was `Continuous`, on the argument that most rows are. A capture that began
/// after the handshake has no ring to measure a step against, so EVERY frame of
/// it is [`SnVerdict::WithoutResolution`] (and a tap that attaches to a running
/// session is exactly that capture), and every row was in the map, at about 90
/// bytes. Five of the six verdicts carry no number, so they are a class here;
/// only a `Gap`, which says how many frames it skipped, is kept in the map.
const SN_SHIFT: u16 = 11;
/// The bits of [`UnitRow::flags`] that hold the SN class.
const SN_MASK: u16 = 0b111 << SN_SHIFT;

/// The class of a frame's SN verdict, and the part of it that does not fit in the
/// class: `None` for the rows with no verdict (a handshake message is not
/// numbered).
fn sn_class(verdict: Option<SnVerdict>) -> (u16, Option<SnVerdict>) {
    match verdict {
        None => (0, None),
        Some(SnVerdict::Continuous) => (1, None),
        Some(SnVerdict::WithoutResolution) => (2, None),
        Some(SnVerdict::Baseline) => (3, None),
        Some(SnVerdict::Duplicate) => (4, None),
        Some(SnVerdict::OutOfWindow) => (5, None),
        Some(gap @ SnVerdict::Gap { .. }) => (6, Some(gap)),
    }
}

/// The verdict a class stands for: `gap` is the map's, read for the one class
/// whose verdict has a number.
fn sn_verdict_of(class: u16, gap: Option<SnVerdict>) -> Option<SnVerdict> {
    match class {
        0 => None,
        1 => Some(SnVerdict::Continuous),
        2 => Some(SnVerdict::WithoutResolution),
        3 => Some(SnVerdict::Baseline),
        4 => Some(SnVerdict::Duplicate),
        5 => Some(SnVerdict::OutOfWindow),
        _ => gap,
    }
}

/// The facts few rows have, and that are small.
///
/// A fragment's fate is not here: it owns a buffer when its chain completed, and a
/// slot that has to hold that costs 88 bytes for every row that has a fate, which
/// was the dearest thing a fragment row cost. See [`Fates`].
#[derive(Debug, Clone, Default)]
struct Sparse {
    /// An SN verdict that has a number to keep: a [`SnVerdict::Gap`].
    sn_verdict: Option<SnVerdict>,
    /// The resynchronisation a unit's first row carried.
    resync: Option<StreamResync>,
}

impl Sparse {
    fn has_any(&self) -> bool {
        self.sn_verdict.is_some() || self.resync.is_some()
    }
}

/// What a fragment row's fate is, without the buffer a completed chain's carries.
#[cfg(feature = "reassembly")]
#[derive(Debug, Clone, Copy)]
enum FateClass {
    /// The chain completed here; the joined message is in [`Fates::joined`].
    Joined,
    /// The flow had no sequence ring, so the chain could not be followed.
    WithoutResolution,
    /// The chain went on, or ended, as the router's outcome says.
    Pending(IngestOutcome),
}

/// What a fragment came to, for the rows that are fragments: a class a row (three
/// bytes and its key), and the joined message of a chain that completed, by row,
/// in a map of its own because only that fate has a buffer.
#[cfg(feature = "reassembly")]
#[derive(Debug, Default)]
struct Fates {
    classes: AscendingMap<FateClass>,
    joined: AscendingMap<Vec<u8>>,
}

#[cfg(feature = "reassembly")]
impl Fates {
    fn insert(&mut self, key: u64, fate: FragmentFate) {
        match fate {
            FragmentFate::Joined(bytes) => {
                self.classes.insert(key, FateClass::Joined);
                self.joined.insert(key, bytes);
            }
            FragmentFate::WithoutResolution => {
                self.classes.insert(key, FateClass::WithoutResolution);
            }
            FragmentFate::Pending(outcome) => {
                self.classes.insert(key, FateClass::Pending(outcome));
            }
        }
    }

    /// The fate of the row at `key`, the joined message copied.
    fn get(&self, key: u64) -> Option<FragmentFate> {
        Some(match *self.classes.get(key)? {
            FateClass::Joined => {
                FragmentFate::Joined(self.joined.get(key).cloned().unwrap_or_default())
            }
            FateClass::WithoutResolution => FragmentFate::WithoutResolution,
            FateClass::Pending(outcome) => FragmentFate::Pending(outcome),
        })
    }

    /// Take the fate of the row at `key` out.
    fn remove(&mut self, key: u64) -> Option<FragmentFate> {
        Some(match self.classes.remove(key)? {
            FateClass::Joined => FragmentFate::Joined(self.joined.remove(key).unwrap_or_default()),
            FateClass::WithoutResolution => FragmentFate::WithoutResolution,
            FateClass::Pending(outcome) => FragmentFate::Pending(outcome),
        })
    }

    /// Bytes of the fates' classes, and of the joined messages with the slots that
    /// hold them.
    fn bytes(&self) -> (usize, usize) {
        (
            self.classes.allocated_bytes(),
            self.joined.allocated_bytes()
                + self
                    .joined
                    .values()
                    .map(|bytes| bytes.capacity())
                    .sum::<usize>(),
        )
    }
}

/// What a fragment came to, as a row's first reading hands it over: the fate when
/// the build reads fragments, and no value when it does not.
#[cfg(feature = "reassembly")]
type Fate = FragmentFate;
#[cfg(not(feature = "reassembly"))]
type Fate = core::convert::Infallible;

impl UnitRow {
    /// The row of a message kept whole.
    const HELD_ROW: Self = Self {
        anchor: 0,
        locator: 0,
        observed_at_ns: 0,
        unit_len: 0,
        wire_len: 0,
        unit_offset: 0,
        batch_index: 0,
        context: 0,
        prefix_width: 0,
        kind: 0,
        flags: HELD,
    };

    /// What the row is.
    fn entry(self) -> Entry {
        if self.flags & HELD != 0 {
            Entry::Held
        } else {
            Entry::Unit(self)
        }
    }

    /// The coordinates every entry's fields must hold, whatever its unit.
    fn fits(frame: &PassiveFrame) -> bool {
        let fits = |n: usize| u32::try_from(n).is_ok();
        !frame.inadmissible_on_link
            && u8::try_from(frame.prefix_width).is_ok()
            && fits(frame.unit_len)
            && fits(frame.unit_offset)
            && fits(frame.batch_index)
    }

    /// Whether `frame` is a row an entry can stand for read off a byte stream
    /// (whose unit can be read again from the stream, on a link that carries a
    /// handshake).
    fn can_hold_streamed(frame: &PassiveFrame) -> bool {
        Self::fits(frame)
            && frame.offset_space == OffsetSpace::StreamBytes
            && frame
                .wire_end
                .and_then(|end| end.checked_sub(frame.stream_offset + frame.prefix_width))
                .is_some_and(|n| u32::try_from(n).is_ok())
    }

    /// Whether `frame` is a row an entry can stand for read out of a datagram:
    /// anchored at a packet, with no prefix, which is what the walk writes for
    /// a datagram and what an entry gives back. An end it has is its unit's,
    /// which the unit's entries keep apart ([`Index::wire_ends`]).
    fn can_hold_logged(frame: &PassiveFrame) -> bool {
        Self::fits(frame)
            && frame.offset_space == OffsetSpace::PacketIndex
            && frame.prefix_width == 0
    }

    /// The entry for `frame`, of a unit lying where `locus` says, read in the
    /// context at `context`, and the facts it keeps apart. `frame` passed the
    /// `can_hold` of its locus.
    fn of(frame: &PassiveFrame, locus: Locus, context: u32) -> (Self, Sparse, Option<Fate>) {
        let narrow = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        let facts = MessageFacts::of(frame);
        let (locator, wire_len, mut flags) = match locus {
            Locus::Streamed => {
                let body = frame.stream_offset + frame.prefix_width;
                (body as u64, frame.wire_end.unwrap_or(body) - body, 0)
            }
            Locus::Logged {
                place,
                len,
                handshake,
                wire_end,
            } => {
                let mut flags = LOGGED;
                if handshake == LinkHandshake::Absent {
                    flags |= NO_HANDSHAKE;
                }
                if wire_end.is_some() {
                    flags |= WIRE_END;
                }
                (place.locator(), len, flags)
            }
        };
        if frame.direction == Direction::B {
            flags |= SIDE_B;
        }
        if frame.observed_at_ns.is_some() {
            flags |= TIMED;
        }
        if frame.exceeds_negotiated_batch {
            flags |= OVER_BATCH;
        }
        if frame.resync.is_some() {
            flags |= AFTER_RESYNC;
        }
        if frame.decompressed.is_some() {
            flags |= DECOMPRESSED;
        }
        #[cfg(feature = "reassembly")]
        let fate: Option<Fate> = facts.fragment;
        #[cfg(not(feature = "reassembly"))]
        let fate: Option<Fate> = None;
        if fate.is_some() {
            flags |= FRAGMENT;
        }
        let mut sparse = Sparse {
            resync: frame.resync,
            ..Sparse::default()
        };
        let (class, gap) = sn_class(facts.sn_verdict);
        flags |= class << SN_SHIFT;
        sparse.sn_verdict = gap;
        if sparse.has_any() {
            flags |= SPARSE;
        }
        let row = Self {
            anchor: frame.stream_offset as u64,
            locator,
            observed_at_ns: frame.observed_at_ns.unwrap_or(0),
            unit_len: narrow(frame.unit_len),
            wire_len: narrow(wire_len),
            unit_offset: narrow(frame.unit_offset),
            batch_index: narrow(frame.batch_index),
            context,
            prefix_width: u8::try_from(frame.prefix_width).unwrap_or(u8::MAX),
            kind: kind_of(frame),
            flags,
        };
        (row, sparse, fate)
    }

    fn direction(&self) -> Direction {
        if self.flags & SIDE_B != 0 {
            Direction::B
        } else {
            Direction::A
        }
    }

    fn observed_at_ns(&self) -> Option<u64> {
        (self.flags & TIMED != 0).then_some(self.observed_at_ns)
    }

    fn logged(&self) -> bool {
        self.flags & LOGGED != 0
    }

    /// The key of the row's unit in [`Index::wire_ends`]: its locator, which
    /// names one unit among the logged ones and one among each direction's
    /// streamed ones.
    fn end_key(&self) -> (u16, u64) {
        (self.flags & (LOGGED | SIDE_B), self.locator)
    }

    /// Where the body of a streamed unit begins and ends, in its direction's
    /// stream.
    fn body(&self) -> (usize, usize) {
        let from = self.locator as usize;
        (from, from + self.wire_len as usize)
    }

    /// Where the unit stands, in the space it was read in.
    fn anchor(&self) -> Anchor {
        if self.logged() {
            Anchor::packet(self.anchor as usize)
        } else {
            Anchor::bytes(self.anchor as usize)
        }
    }

    /// The row's head, which an entry answers without reading the unit.
    fn head(&self) -> RowHead {
        let anchor = self.anchor();
        RowHead {
            direction: self.direction(),
            stream_offset: anchor.offset,
            offset_space: anchor.space,
            batch_index: self.batch_index as usize,
            unit_offset: self.unit_offset as usize,
            unit_len: self.unit_len as usize,
            prefix_width: usize::from(self.prefix_width),
            // A datagram's anchor names a packet and has no end; the end of a
            // unit a layer below framed is the index's to say.
            wire_end: (!self.logged()).then(|| self.body().1),
            observed_at_ns: self.observed_at_ns(),
            kind: self.kind,
            decompressed: self.flags & DECOMPRESSED != 0,
            exceeds_negotiated_batch: self.flags & OVER_BATCH != 0,
            inadmissible_on_link: false,
            after_resync: self.flags & AFTER_RESYNC != 0,
        }
    }

    /// What the walk asks of this row when its unit is read again.
    #[cfg_attr(not(feature = "reassembly"), allow(unused_variables))]
    fn facts(&self, sparse: Option<&Sparse>, fate: Option<Fate>) -> MessageFacts {
        MessageFacts {
            unit_offset: self.unit_offset as usize,
            observed_at_ns: self.observed_at_ns(),
            sn_verdict: sn_verdict_of(
                (self.flags & SN_MASK) >> SN_SHIFT,
                sparse.and_then(|s| s.sn_verdict),
            ),
            #[cfg(feature = "reassembly")]
            fragment: fate,
        }
    }
}

/// One framing unit an [`Index`] read again, and where its rows stand.
struct ReadAgain {
    /// The list position of the unit's first row still held.
    from: usize,
    /// That row's place in the unit: how many of the unit's rows a discard took.
    cut: usize,
    /// The unit's records not taken yet, in order: the record at the front is
    /// the unit's `next`-th.
    frames: VecDeque<PassiveFrame>,
    /// The place in the unit of the record at the front of `frames`.
    next: usize,
}

impl ReadAgain {
    /// Take the record that stands at list position `position`, if it is one
    /// of this unit's and not passed yet. The records before it are let go: a
    /// walk takes a unit's records in order, and a lookup takes one.
    fn take(&mut self, position: usize) -> Option<PassiveFrame> {
        let k = position.checked_sub(self.from)? + self.cut;
        if k < self.next {
            return None;
        }
        self.frames.drain(..(k - self.next).min(self.frames.len()));
        self.next = k + 1;
        self.frames.pop_front()
    }
}

impl Index {
    /// Append a row kept whole; `produced` is its produced-index.
    fn push_held(&mut self, produced: u64, frame: PassiveFrame) {
        self.entries.push_back(UnitRow::HELD_ROW);
        self.held.insert(produced, frame);
    }

    /// Append the rows of one unit, lying where `locus` says, as entries;
    /// `produced` is the produced-index of the first of them.
    fn push_unit(
        &mut self,
        produced: u64,
        start: FlowContext,
        frames: &[PassiveFrame],
        locus: Locus,
    ) {
        if self.contexts.last() != Some(&start) {
            self.contexts.push(start);
        }
        let context = u32::try_from(self.contexts.len() - 1).unwrap_or(u32::MAX);
        for (k, frame) in frames.iter().enumerate() {
            let (row, sparse, fate) = UnitRow::of(frame, locus, context);
            if row.flags & SPARSE != 0 {
                self.sparse.insert(produced + k as u64, sparse);
            }
            #[cfg(feature = "reassembly")]
            if let Some(fate) = fate {
                self.fates.insert(produced + k as u64, fate);
            }
            #[cfg(not(feature = "reassembly"))]
            let _ = fate;
            if let (
                0,
                Locus::Logged {
                    wire_end: Some(end),
                    ..
                },
            ) = (k, locus)
            {
                self.wire_ends.insert(row.end_key(), end as u64);
            }
            self.entries.push_back(row);
        }
    }

    /// What the row at `position` is.
    #[inline]
    fn entry(&self, position: usize) -> Option<Entry> {
        self.entries.get(position).map(|row| row.entry())
    }

    /// The frame of the row kept whole at `position`.
    #[inline]
    fn held(&self, position: usize, first_produced: u64) -> Option<&PassiveFrame> {
        self.held.get(&(first_produced + position as u64))
    }

    /// Keep whole every row of `direction` whose unit's bytes begin before
    /// stream offset `offset`: see [`MessageList::keep_whole_before`].
    ///
    /// A direction's rows are in stream order (its units are read in the order
    /// their bytes arrive, and a unit's rows sit together), so the walk stops at
    /// the first row of the direction whose bytes begin at or past `offset`.
    fn keep_whole_before(
        &mut self,
        first_produced: u64,
        direction: Direction,
        offset: usize,
        source: &dyn UnitBytes,
    ) {
        let seat = usize::from(direction == Direction::B);
        let mut position = usize::try_from(self.whole_below[seat].saturating_sub(first_produced))
            .unwrap_or(usize::MAX);
        while let Some(entry) = self.entry(position) {
            let Entry::Unit(row) = entry else {
                position += 1;
                continue;
            };
            // A logged unit's bytes are the list's own, and no stream releases
            // them.
            if row.logged() || row.direction() != direction {
                position += 1;
                continue;
            }
            if row.body().0 >= offset {
                break;
            }
            // Every row of the unit from here on, read once.
            let mut unit = self.read_unit(position, first_produced, source);
            while let Some(frame) = unit.take(position) {
                let key = first_produced + position as u64;
                if let Some(slot) = self.entries.get_mut(position) {
                    *slot = UnitRow::HELD_ROW;
                }
                self.sparse.remove(key);
                // The frame kept whole carries what the fate says.
                #[cfg(feature = "reassembly")]
                let _ = self.fates.remove(key);
                self.held.insert(key, frame);
                position += 1;
            }
            // The end is in the held frames now.
            if row.flags & WIRE_END != 0 {
                self.wire_ends.remove(&row.end_key());
            }
        }
        self.whole_below[seat] = first_produced + position.min(self.entries.len()) as u64;
    }

    /// [`MessageList::restate_from`] over the rows from `from` on.
    fn restate_from(
        &mut self,
        first_produced: u64,
        from: usize,
        restate: &mut dyn FnMut(Direction, usize, Option<usize>) -> (usize, Option<usize>),
    ) {
        for position in from..self.entries.len() {
            match self.entry(position) {
                Some(Entry::Held) => {
                    if let Some(frame) = self.held.get_mut(&(first_produced + position as u64)) {
                        let (offset, end) =
                            restate(frame.direction, frame.stream_offset, frame.wire_end);
                        frame.stream_offset = offset;
                        frame.wire_end = end;
                    }
                }
                Some(Entry::Unit(row)) => {
                    let head = self.head(position, first_produced).unwrap_or_else(|| {
                        unreachable!("an entry at {position} has a head");
                    });
                    let (offset, end) = restate(head.direction, head.stream_offset, head.wire_end);
                    let key = row.end_key();
                    match end {
                        Some(end) => self.wire_ends.insert(key, end as u64),
                        None => self.wire_ends.remove(&key),
                    };
                    if let Some(slot) = self.entries.get_mut(position) {
                        slot.anchor = offset as u64;
                        slot.flags |= WIRE_END;
                    }
                }
                None => break,
            }
        }
    }

    /// Read again the unit of the row at `position`, which is an
    /// [`Entry::Unit`]; `first_produced` is the produced-index of the oldest
    /// row held.
    ///
    /// # Panics
    ///
    /// When neither the list's log nor `source` holds the unit's bytes, or the
    /// unit does not read again into the records its entries describe. Either
    /// says the list and its source have come apart: a holder releases bytes
    /// only behind the oldest row it still holds, a reader of a list whose
    /// units are in a lent container hands the container in, and the walk that
    /// read the unit is the walk that reads it again. Reading on would hand a
    /// reader a row that is not the one the capture holds.
    fn read_unit(&self, position: usize, first_produced: u64, source: &dyn UnitBytes) -> ReadAgain {
        let Some(Entry::Unit(row)) = self.entry(position) else {
            unreachable!("only an entry is read again, and {position} is not one");
        };
        let batch = row.batch_index as usize;
        // Rows of a unit sit together, so the unit's rows begin `batch` rows
        // before this one, unless a discard took the first of them, which
        // leaves this unit at the front of the list.
        let (from, cut) = match position.checked_sub(batch) {
            Some(from) => (from, 0),
            None => (0, self.cut.len()),
        };
        let mut messages: Vec<MessageFacts> = self.cut[..cut].to_vec();
        let mut resync = if cut > 0 { self.cut_resync } else { None };
        for (at, entry) in self.entries.iter_from(from).enumerate() {
            let Entry::Unit(member) = entry.entry() else {
                break;
            };
            if member.batch_index as usize != messages.len() {
                break;
            }
            let sparse = (member.flags & SPARSE != 0)
                .then(|| self.sparse.get(first_produced + (from + at) as u64))
                .flatten();
            if messages.is_empty() {
                resync = sparse.and_then(|s| s.resync);
            }
            #[cfg(feature = "reassembly")]
            let fate = (member.flags & FRAGMENT != 0)
                .then(|| self.fates.get(first_produced + (from + at) as u64))
                .flatten();
            #[cfg(not(feature = "reassembly"))]
            let fate: Option<Fate> = None;
            messages.push(member.facts(sparse, fate));
        }
        let facts = UnitFacts {
            start: self.contexts[row.context as usize],
            resync,
            unit_instant: messages.first().and_then(|m| m.observed_at_ns),
            messages,
        };
        let direction = row.direction();
        let bytes = self.unit_bytes(&row, source);
        let mut frames = redecode_unit(
            UnitInput {
                direction,
                bytes: &bytes,
                anchor: row.anchor(),
                prefix_width: usize::from(row.prefix_width),
                // A byte stream is a unicast link by construction; a datagram's
                // link said which it was when the unit was logged.
                handshake: if row.flags & NO_HANDSHAKE != 0 {
                    LinkHandshake::Absent
                } else {
                    LinkHandshake::Present
                },
            },
            &facts,
        )
        .unwrap_or_else(|e| panic!("a unit a list holds did not read again as it was read: {e:?}"));
        // The end a layer below gave the unit is no fact of its bytes.
        if let Some(end) = self.stated_end(&row) {
            for frame in &mut frames {
                frame.wire_end = end;
            }
        }
        ReadAgain {
            from,
            cut,
            frames: VecDeque::from(frames),
            next: 0,
        }
    }

    /// The bytes of the unit `row` belongs to, from the list's log or from
    /// `source`; panics where [`Self::read_unit`] says.
    fn unit_bytes<'a>(&'a self, row: &UnitRow, source: &'a dyn UnitBytes) -> Cow<'a, [u8]> {
        match self.held_unit_bytes(row, source) {
            Some(bytes) => bytes,
            None if row.logged() => panic!(
                "the {} bytes of a datagram a list holds are not at {:?}",
                row.wire_len,
                LogPlace::of(row.locator)
            ),
            None => {
                let (body, end) = row.body();
                panic!("the stream no longer holds bytes {body}..{end} of a unit a list holds")
            }
        }
    }

    /// The bytes of the unit `row` belongs to, when the list's log or `source`
    /// still holds them.
    fn held_unit_bytes<'a>(
        &'a self,
        row: &UnitRow,
        source: &'a dyn UnitBytes,
    ) -> Option<Cow<'a, [u8]>> {
        let len = row.wire_len as usize;
        if !row.logged() {
            let (body, end) = row.body();
            return source.stream_bytes(row.direction(), body, end);
        }
        self.log
            .get(LogPlace::of(row.locator), len, source.container())
            .map(Cow::Borrowed)
    }

    /// The row at `position` as a reader is handed it.
    fn row<'a>(
        &'a self,
        position: usize,
        first_produced: u64,
        source: &dyn UnitBytes,
    ) -> Option<Row<'a>> {
        let produced = first_produced + position as u64;
        match self.entry(position)? {
            Entry::Held => self
                .held(position, first_produced)
                .map(|frame| Row::held(frame, produced)),
            Entry::Unit(_) => self
                .read_unit(position, first_produced, source)
                .take(position)
                .map(|frame| Row::read(frame, produced)),
        }
    }

    /// The end on the wire the index states for `row` ([`WIRE_END`]): `None`
    /// for a row whose end is its bytes', `Some(None)` for one that has none.
    fn stated_end(&self, row: &UnitRow) -> Option<Option<usize>> {
        (row.flags & WIRE_END != 0)
            .then(|| self.wire_ends.get(&row.end_key()).map(|&end| end as usize))
    }

    /// The head of the row at `position`.
    #[inline]
    fn head(&self, position: usize, first_produced: u64) -> Option<RowHead> {
        match self.entry(position)? {
            Entry::Held => self.held(position, first_produced).map(RowHead::of),
            Entry::Unit(row) => {
                let mut head = row.head();
                if let Some(end) = self.stated_end(&row) {
                    head.wire_end = end;
                }
                Some(head)
            }
        }
    }

    /// Release the oldest row and hand back its frame. A row that was the last
    /// its unit had held releases the unit's logged bytes with it.
    fn pop_front(&mut self, first_produced: u64, source: &dyn UnitBytes) -> Option<PassiveFrame> {
        match self.entry(0)? {
            Entry::Held => {
                let _ = self.entries.pop_front();
                // A cut unit whose rows were kept whole since needs no facts.
                self.cut.clear();
                self.cut_resync = None;
                self.held.remove(&first_produced)
            }
            Entry::Unit(row) => {
                let frame = self.read_unit(0, first_produced, source).take(0);
                let _ = self.entries.pop_front();
                let sparse = self.sparse.remove(first_produced);
                #[cfg(feature = "reassembly")]
                let fate = self.fates.remove(first_produced);
                #[cfg(not(feature = "reassembly"))]
                let fate: Option<Fate> = None;
                // The rest of the unit is still held: keep what reading it again
                // needs of the row going. Otherwise the cut, if any, ends here.
                let continues = matches!(
                    self.entry(0),
                    Some(Entry::Unit(next)) if next.batch_index == row.batch_index + 1
                );
                if continues {
                    if self.cut.is_empty() {
                        self.cut_resync = sparse.as_ref().and_then(|s| s.resync);
                    }
                    self.cut.push(row.facts(sparse.as_ref(), fate));
                } else {
                    self.cut.clear();
                    self.cut_resync = None;
                    // The unit's last row: nothing reads its bytes any more, and
                    // every unit logged before it went before it.
                    if row.logged() {
                        self.log
                            .release_through(LogPlace::of(row.locator), row.wire_len as usize);
                    }
                    if row.flags & WIRE_END != 0 {
                        self.wire_ends.remove(&row.end_key());
                    }
                }
                frame
            }
        }
    }
}

/// What a row says about itself without being decoded: the coordinates, the
/// instant and the flags a list keeps for every row it holds.
///
/// Open-debt item 924 (`docs/dissect-row-index.md`, D2). A reader that needs
/// only these (draining records, ordering rows by packet) reads them here and
/// costs no decode; the fields are the [`PassiveFrame`] fields of the same name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowHead {
    /// [`PassiveFrame::direction`].
    pub direction: Direction,
    /// [`PassiveFrame::stream_offset`].
    pub stream_offset: usize,
    /// [`PassiveFrame::offset_space`].
    pub offset_space: OffsetSpace,
    /// [`PassiveFrame::batch_index`].
    pub batch_index: usize,
    /// [`PassiveFrame::unit_offset`].
    pub unit_offset: usize,
    /// [`PassiveFrame::unit_len`].
    pub unit_len: usize,
    /// [`PassiveFrame::prefix_width`].
    pub prefix_width: usize,
    /// [`PassiveFrame::wire_end`].
    pub wire_end: Option<usize>,
    /// [`PassiveFrame::observed_at_ns`].
    pub observed_at_ns: Option<u64>,
    /// What the message is: [`InboundFrame::kind_code`] of the decoded
    /// message, and `0`, which that numbering reserves for it, for one that did
    /// not decode.
    pub kind: u8,
    /// [`PassiveFrame::decompressed`] is `Some`: the message was read out of an
    /// lz4 batch, so its coordinates index that batch and not the stream.
    pub decompressed: bool,
    /// [`PassiveFrame::exceeds_negotiated_batch`].
    pub exceeds_negotiated_batch: bool,
    /// [`PassiveFrame::inadmissible_on_link`].
    pub inadmissible_on_link: bool,
    /// [`PassiveFrame::resync`] is `Some`.
    pub after_resync: bool,
}

impl RowHead {
    /// The head of a decoded row.
    pub fn of(frame: &PassiveFrame) -> Self {
        Self {
            direction: frame.direction,
            stream_offset: frame.stream_offset,
            offset_space: frame.offset_space,
            batch_index: frame.batch_index,
            unit_offset: frame.unit_offset,
            unit_len: frame.unit_len,
            prefix_width: frame.prefix_width,
            wire_end: frame.wire_end,
            observed_at_ns: frame.observed_at_ns,
            kind: kind_of(frame),
            decompressed: frame.decompressed.is_some(),
            exceeds_negotiated_batch: frame.exceeds_negotiated_batch,
            inadmissible_on_link: frame.inadmissible_on_link,
            after_resync: frame.resync.is_some(),
        }
    }
}

/// [`RowHead::kind`] of a decoded row.
fn kind_of(frame: &PassiveFrame) -> u8 {
    frame.frame.as_ref().map_or(0, InboundFrame::kind_code)
}

/// A [`MessageList`] as a reader reads it: the list and the bytes of the
/// messages it keeps as index entries ([`MessageList::read`]).
///
/// The one way to read a list's rows. A row is handed out as a [`Row`], which
/// a list that keeps the row as an entry decodes for that reader; a reader that
/// needs only what a row says about itself reads its [`RowHead`] and decodes
/// nothing.
#[derive(Clone, Copy)]
pub struct Messages<'a> {
    list: &'a MessageList,
    source: &'a dyn UnitBytes,
}

impl core::fmt::Debug for Messages<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Messages")
            .field("list", self.list)
            .finish_non_exhaustive()
    }
}

impl<'a> Messages<'a> {
    /// Messages held: [`MessageList::len`].
    #[inline]
    pub fn len(&self) -> usize {
        self.list.len()
    }

    /// No message is held.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// [`MessageList::produced`].
    #[inline]
    pub fn produced(&self) -> u64 {
        self.list.produced
    }

    /// [`MessageList::chain_prefix`].
    #[cfg(feature = "reassembly")]
    pub fn chain_prefix(&self) -> &'a ChainFold {
        &self.list.chain_prefix
    }

    /// The produced-index of the oldest message held.
    fn first_produced(&self) -> u64 {
        self.list.produced - self.list.len() as u64
    }

    /// The message at position `index` among those held, oldest first.
    #[inline]
    pub fn get(&self, index: usize) -> Option<Row<'a>> {
        let list: &'a MessageList = self.list;
        match &list.rows {
            Store::Held(log) => log
                .get(index)
                .map(|frame| Row::held(frame, self.first_produced() + index as u64)),
            Store::Indexed(entries) => entries.row(index, self.first_produced(), self.source),
        }
    }

    /// The bytes of the framing unit the message at `index` was read out of,
    /// as they crossed the wire past any length prefix: what the list reads the
    /// message again from (open-debt item 924, D8). `None` for a message the
    /// list keeps whole, whose unit's bytes it does not keep, for one whose
    /// source no longer holds them, and past the end.
    pub fn unit_bytes(&self, index: usize) -> Option<Cow<'a, [u8]>> {
        let list: &'a MessageList = self.list;
        let source: &'a dyn UnitBytes = self.source;
        match &list.rows {
            Store::Held(_) => None,
            Store::Indexed(entries) => match entries.entry(index)? {
                Entry::Held => None,
                Entry::Unit(row) => entries.held_unit_bytes(&row, source),
            },
        }
    }

    /// The message at `index`; panics past the end, as indexing a slice does.
    ///
    /// A method and not `Index`: indexing hands out a reference into the list,
    /// and a row the list decodes on demand has none to hand out (see [`Row`]).
    #[inline]
    #[track_caller]
    pub fn row(&self, index: usize) -> Row<'a> {
        match self.get(index) {
            Some(row) => row,
            None => out_of_range(index, self.len()),
        }
    }

    /// The messages held, oldest first.
    #[inline]
    pub fn iter(&self) -> RowIter<'a> {
        self.rows_from(0).iter()
    }

    /// The messages from position `from` on, as a view a reader walks: what one
    /// call added, handed on without a copy.
    #[inline]
    pub fn rows_from(&self, from: usize) -> Rows<'a> {
        Rows {
            messages: *self,
            from,
        }
    }

    /// The heads of the messages from position `from` on, oldest first: what
    /// a reader that decodes nothing reads.
    pub fn heads_from(&self, from: usize) -> Heads<'a> {
        let len = self.len();
        Heads {
            messages: *self,
            front: from.min(len),
            back: len,
        }
    }
}

impl<'a> IntoIterator for Messages<'a> {
    type Item = Row<'a>;
    type IntoIter = RowIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// One message of a [`MessageList`], as a reader is handed it.
///
/// Reads as the decoded [`PassiveFrame`] through [`Deref`](core::ops::Deref).
/// A reader holds a `Row` for as long as it reads the message and no longer:
/// a list that keeps the message as an index entry (open-debt item 924,
/// `docs/dissect-row-index.md`) decodes it again for the reader, and the `Row`
/// owns that frame. Code that kept a frame of every row of a capture would
/// decode the whole capture at once.
#[derive(Debug)]
pub struct Row<'a> {
    frame: RowFrame<'a>,
    /// The row's produced-index: [`MessageList::produced`] when it was appended.
    produced: u64,
}

/// Where a [`Row`]'s frame is.
#[derive(Debug)]
enum RowFrame<'a> {
    /// In the list, kept whole.
    Held(&'a PassiveFrame),
    /// Decoded again for this reader. Boxed, so a row is a pointer's size
    /// whichever it is.
    Read(Box<PassiveFrame>),
}

impl<'a> Row<'a> {
    #[inline]
    fn held(frame: &'a PassiveFrame, produced: u64) -> Self {
        Self {
            frame: RowFrame::Held(frame),
            produced,
        }
    }

    fn read(frame: PassiveFrame, produced: u64) -> Self {
        Self {
            frame: RowFrame::Read(Box::new(frame)),
            produced,
        }
    }

    /// The row's produced-index: how many messages its list had been appended
    /// before it. Unique in its list and untouched by a front trim, so it is
    /// what a table that names rows across calls keys them by (open-debt item
    /// 924, D9), where a position moves with every trim.
    #[inline]
    pub fn produced(&self) -> u64 {
        self.produced
    }
}

impl core::ops::Deref for Row<'_> {
    type Target = PassiveFrame;

    #[inline]
    fn deref(&self) -> &PassiveFrame {
        match &self.frame {
            RowFrame::Held(frame) => frame,
            RowFrame::Read(frame) => frame,
        }
    }
}

impl AsRef<PassiveFrame> for Row<'_> {
    #[inline]
    fn as_ref(&self) -> &PassiveFrame {
        self
    }
}

/// The messages of a [`Messages`] (or of a [`Rows`] view), oldest first, as
/// [`Row`]s.
///
/// Walking forward, a unit read again is read once for all of its rows: the
/// records it yields wait here until their positions are reached.
pub struct RowIter<'a> {
    walk: Walk<'a>,
}

/// How a [`RowIter`] walks.
enum Walk<'a> {
    /// The chunks of a list that keeps its frames, as slices, and the
    /// produced-indices of the next row from the front and of the one past the
    /// next from the back.
    Held {
        rows: Iter<'a, PassiveFrame>,
        front: u64,
        back: u64,
    },
    /// The entries of a list that keeps index entries, by position.
    Indexed {
        index: &'a Index,
        first_produced: u64,
        source: &'a dyn UnitBytes,
        front: usize,
        back: usize,
        /// The unit last read walking forward, until its rows are taken.
        ahead: Option<ReadAgain>,
    },
}

impl core::fmt::Debug for RowIter<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RowIter")
            .field("left", &self.len())
            .finish_non_exhaustive()
    }
}

impl Clone for RowIter<'_> {
    fn clone(&self) -> Self {
        let walk = match &self.walk {
            Walk::Held { rows, front, back } => Walk::Held {
                rows: rows.clone(),
                front: *front,
                back: *back,
            },
            // The unit read ahead is not copied: it is a saving, and the copy
            // reads the unit again when it reaches it.
            Walk::Indexed {
                index,
                first_produced,
                source,
                front,
                back,
                ahead: _,
            } => Walk::Indexed {
                index,
                first_produced: *first_produced,
                source: *source,
                front: *front,
                back: *back,
                ahead: None,
            },
        };
        Self { walk }
    }
}

/// The row at `position` of an indexed walk, taken from `ahead` where its unit
/// was read there, and otherwise read with its unit, which `ahead` then keeps.
fn walk_row<'a>(
    index: &'a Index,
    first_produced: u64,
    source: &dyn UnitBytes,
    position: usize,
    ahead: &mut Option<ReadAgain>,
) -> Option<Row<'a>> {
    let produced = first_produced + position as u64;
    match index.entry(position)? {
        Entry::Held => index
            .held(position, first_produced)
            .map(|frame| Row::held(frame, produced)),
        Entry::Unit(_) => {
            if let Some(frame) = ahead.as_mut().and_then(|unit| unit.take(position)) {
                return Some(Row::read(frame, produced));
            }
            let mut unit = index.read_unit(position, first_produced, source);
            let frame = unit.take(position);
            *ahead = Some(unit);
            frame.map(|frame| Row::read(frame, produced))
        }
    }
}

impl<'a> Iterator for RowIter<'a> {
    type Item = Row<'a>;

    #[inline]
    fn next(&mut self) -> Option<Row<'a>> {
        match &mut self.walk {
            Walk::Held { rows, front, .. } => {
                let frame = rows.next()?;
                *front += 1;
                Some(Row::held(frame, *front - 1))
            }
            Walk::Indexed {
                index,
                first_produced,
                source,
                front,
                back,
                ahead,
            } => {
                if *front >= *back {
                    return None;
                }
                let position = *front;
                *front += 1;
                walk_row(index, *first_produced, *source, position, ahead)
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = match &self.walk {
            Walk::Held { rows, .. } => rows.len(),
            Walk::Indexed { front, back, .. } => back - front,
        };
        (left, Some(left))
    }

    fn count(self) -> usize {
        self.len()
    }

    fn last(mut self) -> Option<Row<'a>> {
        self.next_back()
    }

    fn nth(&mut self, n: usize) -> Option<Row<'a>> {
        match &mut self.walk {
            Walk::Held { rows, front, back } => {
                let skipped = (n as u64).min(*back - *front);
                *front += skipped;
                let frame = rows.nth(n)?;
                *front += 1;
                Some(Row::held(frame, *front - 1))
            }
            Walk::Indexed { front, back, .. } => {
                *front = front.saturating_add(n).min(*back);
                self.next()
            }
        }
    }
}

impl DoubleEndedIterator for RowIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match &mut self.walk {
            Walk::Held { rows, back, .. } => {
                let frame = rows.next_back()?;
                *back -= 1;
                Some(Row::held(frame, *back))
            }
            Walk::Indexed {
                index,
                first_produced,
                source,
                front,
                back,
                ..
            } => {
                if *front >= *back {
                    return None;
                }
                *back -= 1;
                index.row(*back, *first_produced, *source)
            }
        }
    }

    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        match &mut self.walk {
            Walk::Held { rows, front, back } => {
                let skipped = (n as u64).min(*back - *front);
                *back -= skipped;
                let frame = rows.nth_back(n)?;
                *back -= 1;
                Some(Row::held(frame, *back))
            }
            Walk::Indexed { front, back, .. } => {
                *back = back.saturating_sub(n).max(*front);
                self.next_back()
            }
        }
    }
}

impl ExactSizeIterator for RowIter<'_> {}

impl core::iter::FusedIterator for RowIter<'_> {}

/// The messages of a list from one position on.
///
/// What a door hands a reader of "the messages this call added": the list
/// itself, borrowed with its bytes, and where they begin, so nothing is copied
/// and nothing about how the list stores its rows leaks into the reader. Walked,
/// and nothing else: that is all a reader of these records does, and an
/// accessor no shipped surface asks is one `accessor_reach_census.py` would have
/// to carry.
#[derive(Debug, Clone, Copy)]
pub struct Rows<'a> {
    messages: Messages<'a>,
    from: usize,
}

impl<'a> Rows<'a> {
    /// The messages of the view, oldest first.
    pub fn iter(&self) -> RowIter<'a> {
        let list: &'a MessageList = self.messages.list;
        let walk = match &list.rows {
            Store::Held(log) => {
                let first = self.messages.first_produced();
                Walk::Held {
                    rows: log.iter_from(self.from),
                    front: first + self.from.min(log.len()) as u64,
                    back: first + log.len() as u64,
                }
            }
            Store::Indexed(index) => {
                let len = index.entries.len();
                Walk::Indexed {
                    index,
                    first_produced: self.messages.first_produced(),
                    source: self.messages.source,
                    front: self.from.min(len),
                    back: len,
                    ahead: None,
                }
            }
        };
        RowIter { walk }
    }
}

impl<'a> IntoIterator for Rows<'a> {
    type Item = Row<'a>;
    type IntoIter = RowIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// The [`RowHead`]s of a list's messages, oldest first
/// ([`Messages::heads_from`]).
#[derive(Debug, Clone)]
pub struct Heads<'a> {
    messages: Messages<'a>,
    front: usize,
    back: usize,
}

impl Heads<'_> {
    #[inline]
    fn at(&self, position: usize) -> Option<RowHead> {
        match &self.messages.list.rows {
            Store::Held(log) => log.get(position).map(RowHead::of),
            Store::Indexed(index) => index.head(position, self.messages.first_produced()),
        }
    }
}

impl Iterator for Heads<'_> {
    type Item = RowHead;

    #[inline]
    fn next(&mut self) -> Option<RowHead> {
        if self.front >= self.back {
            return None;
        }
        let position = self.front;
        self.front += 1;
        self.at(position)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.back - self.front;
        (left, Some(left))
    }

    fn nth(&mut self, n: usize) -> Option<RowHead> {
        self.front = self.front.saturating_add(n).min(self.back);
        self.next()
    }
}

impl DoubleEndedIterator for Heads<'_> {
    fn next_back(&mut self) -> Option<RowHead> {
        if self.front >= self.back {
            return None;
        }
        self.back -= 1;
        self.at(self.back)
    }
}

impl ExactSizeIterator for Heads<'_> {}

/// R311y723 — one message a bound removed, and the obligation to account for it.
///
/// # Why this is a type and not a comment
///
/// The rule is that a dissection which drops something to stay inside its
/// budget must SAY SO. Written as prose it was missed four times (R311y612,
/// y649, y650, y656 each fixed one instance and restated the rule), and
/// R311y713 ended the same shape for flow exits by making the obligation a
/// `#[must_use]` type that panics when dropped unconsumed. This is that, for
/// the message lists.
///
/// R311y746 (debt-carry-N11) — the receipt is consumable ONLY by
/// [`DroppedFrameCensus::absorb`], which is why that type lives in this module.
///
/// R311y723 left `take` public, and the obligation it discharged was only
/// "somebody holds this frame" — a caller could take the frame and drop it, and
/// the census would read a floor as a total while every guard here stayed
/// silent. That is the same silence one step later, which is what the register
/// carried as N11.
///
/// So the frame no longer has a public exit. `take` is private to this module
/// and its single caller is the census, exactly as R311y713's `exit::Exiting`
/// is constructible only by a flow table and consumable only by `ExitCarry`
/// (named in prose rather than linked: that module is private, and a public doc
/// linking into it is what `rustdoc::private_intra_doc_links` reds on). The
/// counters and the receipt share one privacy boundary, so "removed" and
/// "counted" cannot come apart.
#[must_use = "the discarded message must be counted"]
#[derive(Debug)]
pub struct Discarded {
    /// `Some` until taken. The destructor reads exactly this: an untaken
    /// receipt still holds its frame, which is what makes the obligation
    /// observable without a second flag to keep in step.
    frame: Option<PassiveFrame>,
}

impl Discarded {
    /// Take the discarded message, discharging the obligation to account for
    /// it.
    ///
    /// PRIVATE to this module (R311y746): the census below is the only caller,
    /// so there is no way to get the frame out without the count moving.
    fn take(mut self) -> PassiveFrame {
        // Emptying the option IS the discharge: `self` drops at the end of this
        // call and its destructor then sees a receipt with nothing left to
        // account for. No second flag, and no `mem::forget` -- a receipt that
        // skipped its own destructor could not assert anything.
        self.frame
            .take()
            .expect("a receipt holds its frame until it is taken, once")
    }
}

/// R311y713 (§B10) — what the transport messages a BOUND discarded had said.
///
/// `DissectionDrops::frames` (`wz-capture`) counts them and nothing named them, so a
/// dissection that trimmed a busy flow could not answer the one question the
/// trim raises: was that a hundred keepalives, or the `Close` that explains why
/// the session ended. The count says a bound bit; this says what it bit.
///
/// TRANSPORT messages only. A scouting datagram discarded by the same limit is
/// counted in `DissectionDrops::scouting` (`wz-capture`) and is not censused here,
/// because it is a different message space (`ScoutingFrame`) and folding the
/// two would produce a total that belongs to neither.
///
/// R311y746 (debt-carry-N11) — LIVES HERE, beside [`Discarded`], and its
/// buckets are PRIVATE. Both directions are closed by that one move: a receipt
/// cannot reach a frame except through [`Self::absorb`], and a bucket cannot be
/// moved except by a receipt. It sat in `lib.rs` with public fields and a
/// private `add`, which closed neither.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DroppedFrameCensus {
    init: usize,
    open: usize,
    close: usize,
    keep_alive: usize,
    frame: usize,
    fragment: usize,
    join: usize,
    oam: usize,
    network: usize,
    unknown: usize,
    undecodable: usize,
}

impl DroppedFrameCensus {
    /// R311y746 — retire one discarded message: the receipt goes in, the count
    /// comes out, and there is no other door onto either.
    pub fn absorb(&mut self, receipt: Discarded) {
        let f = receipt.take();
        match &f.frame {
            Ok(crate::inbound::InboundFrame::Init { .. }) => self.init += 1,
            Ok(crate::inbound::InboundFrame::Open { .. }) => self.open += 1,
            Ok(crate::inbound::InboundFrame::Close { .. }) => self.close += 1,
            // R311y752 — GATED ON THE VARIANT'S OWN FEATURE, exactly as
            // `Fragment` below has been since R311y655, and newly necessary
            // rather than newly correct: in `wz-capture` this module was always
            // compiled with a dependency that turned `codec-keep-alive` and
            // `codec-join` on, so the arms could name variants unconditionally.
            // Here the profile is whatever the consumer chose, and a build
            // without the feature decodes the MID as `Unknown` and counts it
            // there -- the honest reading, and the accessor stays ungated so a
            // reader of this census never has to know which features the binary
            // carries.
            #[cfg(feature = "codec-keep-alive")]
            Ok(crate::inbound::InboundFrame::KeepAlive { .. }) => self.keep_alive += 1,
            Ok(crate::inbound::InboundFrame::Frame { .. }) => self.frame += 1,
            Ok(crate::inbound::InboundFrame::Network { .. }) => self.network += 1,
            // The VARIANT is gated on `reassembly`, and the ACCESSOR below is
            // not: a reader of this census must not have to know which features
            // this binary carries (R311y655). Without the feature a `0x06`
            // decodes as `Unknown { mid: 6 }` and is counted there, which is the
            // honest reading -- this build did not recognise it as a fragment.
            #[cfg(feature = "reassembly")]
            Ok(crate::inbound::InboundFrame::Fragment { .. }) => self.fragment += 1,
            #[cfg(feature = "codec-join")]
            Ok(crate::inbound::InboundFrame::Join { .. }) => self.join += 1,
            // UNGATED, alone among these arms, because the variant is: transport
            // OAM needs no generated body codec, so no feature can take it away
            // and no build counts it as `unknown`.
            Ok(crate::inbound::InboundFrame::Oam { .. }) => self.oam += 1,
            Ok(crate::inbound::InboundFrame::Unknown { .. }) => self.unknown += 1,
            Err(_) => self.undecodable += 1,
        }
    }

    /// Session establishment, both halves.
    pub fn init(&self) -> usize {
        self.init
    }

    /// Session opening, both halves.
    pub fn open(&self) -> usize {
        self.open
    }

    /// Session teardown — the one whose loss changes what a reader concludes.
    pub fn close(&self) -> usize {
        self.close
    }

    /// Keepalives, which is what a long trim is usually made of.
    pub fn keep_alive(&self) -> usize {
        self.keep_alive
    }

    /// Data frames.
    pub fn frame(&self) -> usize {
        self.frame
    }

    /// Fragments of one. Structurally present on a build without `reassembly`,
    /// where it stays zero and the messages are counted as [`Self::unknown`].
    pub fn fragment(&self) -> usize {
        self.fragment
    }

    /// R311y608 — the multicast JOIN, which is how a peer announces itself on a
    /// group and therefore the one whose loss changes what a LATER message on
    /// that group is read as.
    pub fn join(&self) -> usize {
        self.join
    }

    /// Transport OAM — operations and maintenance. Its loss matters for the
    /// same reason a JOIN's does: it is a message a peer sends ABOUT the
    /// session rather than through it, so a bound that drops one drops the
    /// explanation for what the next messages do.
    pub fn oam(&self) -> usize {
        self.oam
    }

    /// Bare network bodies on negotiated lowlatency links, without a Frame.
    pub fn network(&self) -> usize {
        self.network
    }

    /// Messages whose MID this reader does not know. Not an error: an unknown
    /// message is a fact about the wire, and a bound discarding one is worth
    /// telling apart from a bound discarding a keepalive.
    pub fn unknown(&self) -> usize {
        self.unknown
    }

    /// Messages this reader had already failed to decode. Kept apart from the
    /// rest: a bound discarding garbage and a bound discarding a `Close` are
    /// different findings.
    pub fn undecodable(&self) -> usize {
        self.undecodable
    }

    /// Every discarded message this censused — the figure that must equal
    /// `DissectionDrops::frames` (`wz-capture`), and the assertion that keeps the two
    /// from drifting into two different stories about one trim.
    pub fn total(&self) -> usize {
        self.init
            + self.open
            + self.close
            + self.keep_alive
            + self.frame
            + self.fragment
            + self.join
            + self.oam
            + self.network
            + self.unknown
            + self.undecodable
    }
}

impl Drop for Discarded {
    fn drop(&mut self) {
        assert!(
            self.frame.is_none(),
            "R311y723: a message was discarded and never accounted for. Take it \
             with `Discarded::take` and fold it into the drop census -- a bound \
             that discards silently reports a floor as a total."
        );
    }
}

/// The panic of an index past the end, kept off the path that does not take it.
#[cold]
#[inline(never)]
#[track_caller]
fn out_of_range(index: usize, len: usize) -> ! {
    panic!("message {index} of a list holding {len}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Open-debt item 924, step 5 -- EVERY SN VERDICT SURVIVES THE CLASS IT IS KEPT
    /// IN, and the class sits in bits no other flag uses.
    ///
    /// The redecode gate reads the verdicts its captures happen to produce back
    /// through the row, and a capture that never duplicates a frame says nothing of
    /// `Duplicate`. This walks the type: the match below has no wildcard, so a
    /// variant added to [`SnVerdict`] does not compile until it is given a class.
    #[test]
    fn every_sn_verdict_survives_the_class_it_is_kept_in() {
        let every = [
            None,
            Some(SnVerdict::Continuous),
            Some(SnVerdict::WithoutResolution),
            Some(SnVerdict::Baseline),
            Some(SnVerdict::Gap { missing: 7 }),
            Some(SnVerdict::Gap { missing: u64::MAX }),
            Some(SnVerdict::Duplicate),
            Some(SnVerdict::OutOfWindow),
        ];
        for verdict in every {
            if let Some(v) = verdict {
                // Exhaustive on purpose.
                match v {
                    SnVerdict::WithoutResolution
                    | SnVerdict::Baseline
                    | SnVerdict::Continuous
                    | SnVerdict::Gap { .. }
                    | SnVerdict::Duplicate
                    | SnVerdict::OutOfWindow => {}
                }
            }
            let (class, gap) = sn_class(verdict);
            assert_eq!(
                class << SN_SHIFT & !SN_MASK,
                0,
                "{verdict:?}: class {class} does not fit its bits"
            );
            assert_eq!(sn_verdict_of(class, gap), verdict, "{verdict:?}");
            // Only a verdict with a number keeps anything beside the class.
            assert_eq!(
                gap.is_some(),
                matches!(verdict, Some(SnVerdict::Gap { .. })),
                "{verdict:?}"
            );
        }
        // And no other flag is in the class's bits.
        for (name, flag) in [
            ("SIDE_B", SIDE_B),
            ("TIMED", TIMED),
            ("OVER_BATCH", OVER_BATCH),
            ("AFTER_RESYNC", AFTER_RESYNC),
            ("DECOMPRESSED", DECOMPRESSED),
            ("FRAGMENT", FRAGMENT),
            ("SPARSE", SPARSE),
            ("HELD", HELD),
            ("LOGGED", LOGGED),
            ("NO_HANDSHAKE", NO_HANDSHAKE),
            ("WIRE_END", WIRE_END),
        ] {
            assert_eq!(flag & SN_MASK, 0, "{name} is in the SN class's bits");
        }
    }
    use crate::chunk_log::CHUNK_ITEMS;

    /// One decoded message, built through the passive observer's own decoder
    /// rather than by naming every field of `PassiveFrame` here -- a fixture
    /// that hand-built one would break on every field this crate adds and
    /// would prove nothing about the type under test.
    fn frame() -> PassiveFrame {
        // A KeepAlive: MID 0x04 with every flag clear.
        frame_with_mid(0x04)
    }

    /// The same, for whichever MID a test needs to land in a named bucket.
    fn frame_with_mid(mid: u8) -> PassiveFrame {
        let mut session = crate::passive::PassiveSession::new();
        let mut out = session.next_datagram_on(
            crate::passive::Direction::A,
            &[mid],
            7,
            crate::passive::LinkHandshake::Absent,
        );
        assert_eq!(
            out.len(),
            1,
            "the fixture must decode, or it proves nothing"
        );
        out.remove(0)
    }

    /// THE OBLIGATION, as a type: a discarded message that nobody takes panics
    /// at the moment it is dropped.
    ///
    /// This is the assertion that separates this type from a comment. Four
    /// rounds fixed one instance each of "a bound discarded and did not say
    /// so"; the fifth made it impossible.
    #[test]
    #[should_panic(expected = "never accounted for")]
    fn a_discarded_message_nobody_accounts_for_panics() {
        let mut list = MessageList::new();
        list.push(frame());
        let _ = list.discard_oldest(&NoBytes);
    }

    /// R311y746 (debt-carry-N11) — AND THE DISCHARGE IS THE COUNT ITSELF.
    ///
    /// R311y723's discharge was `take`, which handed the frame to the caller
    /// and trusted it to census the frame afterwards — so a caller could take
    /// and drop, leaving every guard here quiet while the census read a floor
    /// as a total. `absorb` is the only door now, and it is the census's, so
    /// "removed from the list" and "counted" are one act rather than two.
    #[test]
    fn absorbing_the_receipt_discharges_the_obligation() {
        let mut list = MessageList::new();
        list.push(frame());
        let mut census = DroppedFrameCensus::default();
        census.absorb(list.discard_oldest(&NoBytes).expect("a message to discard"));
        assert!(list.is_empty(), "the list no longer holds it");
        assert_eq!(census.total(), 1, "and the census does");
        assert_eq!(census.keep_alive(), 1, "in the bucket the message names");
    }

    /// R2102 (open-debt item 524) — THE PRODUCED TOTAL SURVIVES A TRIM, which
    /// is the whole of why it is not `len`.
    ///
    /// # What this discriminates
    ///
    /// The only failure that matters here is a `produced` that moves when a
    /// message LEAVES: an implementation that decremented it, or that returned
    /// `held.len()`, satisfies every other test in this file and destroys the
    /// one property an incremental consumer relies on. So the assertion is not
    /// "produced == 3" on its own — it is the PAIR, `produced` unmoved and
    /// `len` moved, measured across the same trim.
    ///
    /// `produced - len` is asserted by name because that difference is the
    /// arithmetic a consumer performs: it is the produced-index of the oldest
    /// message still here, and therefore how many went past unseen.
    #[test]
    fn the_produced_total_counts_what_a_trim_took_away() {
        let mut list = MessageList::new();
        list.push(frame());
        list.append([frame(), frame()]);
        assert_eq!(list.produced(), 3, "one pushed and two appended");
        assert_eq!(list.len(), 3, "and all three are still held");

        let mut census = DroppedFrameCensus::default();
        census.absorb(list.discard_oldest(&NoBytes).expect("a message to discard"));
        assert_eq!(list.len(), 2, "the trim took one");
        assert_eq!(
            list.produced(),
            3,
            "and the produced total is what it always was -- a counter a trim \
             could move is a counter an incremental reader cannot use"
        );
        assert_eq!(
            list.produced() - list.len() as u64,
            1,
            "so the oldest message still held is produced-index 1, and a \
             consumer whose watermark is 0 knows exactly one went past it"
        );
    }

    /// The other half: the buckets DISCRIMINATE, so a total that moved is not
    /// evidence on its own.
    ///
    /// A census that folded every message into one bucket would satisfy the
    /// test above exactly as well, and would answer the question the census
    /// exists for — was it keepalives, or the `Close` — with a wrong name every
    /// time. Three bytes that must land in three different buckets, asserted as
    /// a SET rather than one at a time.
    ///
    /// The three are chosen for what separates them, and MEASURED rather than
    /// assumed: `0x04` is a whole KeepAlive; `0x1f` is past every MID this
    /// reader knows, so it is `unknown` by construction rather than by a
    /// decoder failing; and a bare `0x03` is a CLOSE whose body is not there,
    /// which this reader reports as `undecodable`. That last one is the pair
    /// the doc on these buckets exists for — a bound discarding garbage and a
    /// bound discarding a `Close` are different findings, and a census that
    /// could not tell them apart would say the wrong one.
    #[test]
    fn the_census_names_what_it_counted_rather_than_only_how_many() {
        let mut list = MessageList::new();
        for mid in [0x03u8, 0x04, 0x1f] {
            list.push(frame_with_mid(mid));
        }
        let mut census = DroppedFrameCensus::default();
        for _ in 0..3 {
            census.absorb(list.discard_oldest(&NoBytes).expect("a message to discard"));
        }
        assert_eq!(
            (
                census.keep_alive(),
                census.unknown(),
                census.undecodable(),
                census.total()
            ),
            (1, 1, 1, 3),
            "three distinct messages must be named apart: {census:?}"
        );
        assert_eq!(
            census.close(),
            0,
            "and a truncated CLOSE must not be reported as a CLOSE that was \
             read: {census:?}"
        );
    }

    /// An empty list answers `None` rather than panicking — a bound that cannot
    /// be met must not take the capture down with it.
    #[test]
    fn discarding_from_an_empty_list_is_answered_not_panicked() {
        let mut list = MessageList::new();
        assert!(list.discard_oldest(&NoBytes).is_none());
    }

    /// The row API reads and rewrites in place and has no way to grow or
    /// shrink the list. Asserted through the operations a consumer actually
    /// performs, since "the API has no push" cannot be written as an assertion.
    #[test]
    fn the_list_reads_by_row_and_can_be_rewritten_in_place() {
        let mut list = MessageList::new();
        list.push(frame());
        list.append([frame(), frame()]);
        assert_eq!(list.len(), 3);
        assert_eq!(
            list.read(&NoBytes).get(0).expect("a frame").stream_offset,
            7
        );
        // A restatement of where the rows stand, which is what a TLS flow's
        // records need and which does not change the length.
        list.restate_from(0, &mut |_, offset, end| (offset + 1, end));
        assert!(list.read(&NoBytes).iter().all(|f| f.stream_offset == 8));
        assert_eq!(list.len(), 3, "a rewrite cannot grow or shrink the list");
    }

    /// R2109 (open-debt item 528) — A TRIMMED LIST STILL READS WHOLE.
    ///
    /// Alternating a discard with a push walks the front of the store along;
    /// with the rows in one ring that was what wrapped it. The count every
    /// consumer reads must stay the list's.
    #[test]
    fn a_list_that_has_wrapped_its_ring_still_hands_back_every_message() {
        let mut list = MessageList::new();
        let mut census = DroppedFrameCensus::default();
        for _ in 0..8 {
            list.push(frame());
        }
        // Enough cycles to carry the head past the end of the buffer several
        // times over, which is the state `remove(0)` could never produce.
        // Every receipt is absorbed: the type's own destructor refuses a
        // discard nobody accounted for, which is how this test first failed.
        for _ in 0..64 {
            census.absorb(
                list.discard_oldest(&NoBytes)
                    .expect("the list is not empty"),
            );
            list.push(frame());
        }
        assert_eq!(census.total(), 64, "every discard was accounted for");
        assert_eq!(list.len(), 8, "a discard and a push leave the length alone");
        assert_eq!(
            list.read(&NoBytes).iter().count(),
            8,
            "and the iterator agrees with it"
        );
        assert_eq!(
            list.produced(),
            8 + 64,
            "a trim never moves `produced`, which is what a watermark reads"
        );
    }

    /// Open-debt item 924 — EVERY POSITION READS THE ROW THE ITERATOR READS,
    /// across chunk boundaries and while the front is being released.
    ///
    /// A position is found by arithmetic over the first chunk's length and the
    /// fixed size of the others ([`ChunkLog`]); an off-by-one there hands back a
    /// neighbour of the row asked for, with no error. So each row carries its own
    /// number, and the list is grown past several chunks, trimmed into the
    /// middle of one, and grown again, with every position, the forward and the
    /// backward iteration compared against the numbers that should be there.
    #[test]
    fn every_position_reads_the_row_the_iterator_reads_across_chunks() {
        fn numbered(n: usize) -> PassiveFrame {
            let mut f = frame();
            f.stream_offset = n;
            f
        }
        fn check(list: &MessageList, want: core::ops::Range<usize>) {
            let list = list.read(&NoBytes);
            let want: Vec<usize> = want.collect();
            assert_eq!(list.len(), want.len());
            let by_position: Vec<usize> = (0..list.len())
                .map(|i| list.get(i).expect("in range").stream_offset)
                .collect();
            assert_eq!(by_position, want, "by position");
            let forward: Vec<usize> = list.iter().map(|f| f.stream_offset).collect();
            assert_eq!(forward, want, "forward");
            let mut backward: Vec<usize> = list.iter().rev().map(|f| f.stream_offset).collect();
            backward.reverse();
            assert_eq!(backward, want, "backward");
            assert_eq!(list.iter().len(), want.len(), "the iterator's exact size");
            assert!(list.get(list.len()).is_none(), "past the end is nothing");
            assert_eq!(list.get(0).map(|f| f.stream_offset), want.first().copied());
            assert_eq!(
                list.iter().next_back().map(|f| f.stream_offset),
                want.last().copied()
            );
            // From a position: the chunk's first row, its last, a row in the
            // middle, the end and past it.
            // Skipping: what `iter().enumerate().skip(n)` relies on, which a
            // slice answers without walking and so must this. Into the first
            // run, across a chunk, into the middle, and into the LAST chunk,
            // where the runs passed on the way must not be read again.
            let ends = [want.len().saturating_sub(1), want.len().saturating_sub(5)];
            for n in [
                0,
                1,
                CHUNK_ITEMS - 1,
                CHUNK_ITEMS,
                CHUNK_ITEMS + 1,
                want.len() / 2,
            ]
            .into_iter()
            .chain(ends)
            {
                assert_eq!(
                    list.iter().nth(n).map(|f| f.stream_offset),
                    want.get(n).copied(),
                    "nth {n}"
                );
                assert_eq!(
                    list.iter().nth_back(n).map(|f| f.stream_offset),
                    want.len().checked_sub(n + 1).map(|i| want[i]),
                    "nth_back {n}"
                );
                let mut it = list.iter();
                let _ = it.nth(n);
                assert_eq!(
                    it.len(),
                    want.len().saturating_sub(n + 1),
                    "left after nth {n}"
                );
                let rest: Vec<usize> = it.map(|f| f.stream_offset).collect();
                assert_eq!(rest, want.get(n + 1..).unwrap_or(&[]), "after nth {n}");
                let mut it = list.iter();
                let _ = it.nth_back(n);
                let kept = want.len().saturating_sub(n + 1);
                assert_eq!(it.len(), kept, "left after nth_back {n}");
                let rest: Vec<usize> = it.map(|f| f.stream_offset).collect();
                assert_eq!(rest, &want[..kept], "after nth_back {n}");
            }
            assert!(list.iter().nth(want.len()).is_none(), "nth past the end");
            for from in [
                0,
                1,
                CHUNK_ITEMS - 1,
                CHUNK_ITEMS,
                want.len() / 2,
                want.len(),
                want.len() + 3,
            ] {
                let tail = want.get(from..).unwrap_or(&[]);
                let read: Vec<usize> = list
                    .rows_from(from)
                    .iter()
                    .map(|f| f.stream_offset)
                    .collect();
                assert_eq!(read, tail, "from {from}");
                let mut back: Vec<usize> = list
                    .rows_from(from)
                    .iter()
                    .rev()
                    .map(|f| f.stream_offset)
                    .collect();
                back.reverse();
                assert_eq!(back, tail, "from {from}, backward");
                assert_eq!(
                    list.rows_from(from).iter().len(),
                    tail.len(),
                    "from {from}, counted"
                );
            }
        }
        let mut list = MessageList::new();
        let mut census = DroppedFrameCensus::default();
        let grown = 3 * CHUNK_ITEMS + 17;
        list.append((0..grown).map(numbered));
        check(&list, 0..grown);
        // Into the middle of the second chunk, so the first chunk is gone and the
        // new first is a partial one.
        let trimmed = CHUNK_ITEMS + 300;
        for _ in 0..trimmed {
            census.absorb(list.discard_oldest(&NoBytes).expect("held"));
        }
        check(&list, trimmed..grown);
        let regrown = grown + 2 * CHUNK_ITEMS;
        list.append((grown..regrown).map(numbered));
        check(&list, trimmed..regrown);
        // And down to nothing, which must leave a list that grows again.
        while let Some(gone) = list.discard_oldest(&NoBytes) {
            census.absorb(gone);
        }
        check(&list, 0..0);
        list.push(numbered(5));
        check(&list, 5..6);
        assert_eq!(census.total(), regrown);
    }

    /// Datagrams of one, two and three keep-alives and one that does not
    /// decode, `n` of them.
    fn datagrams(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|k| match k % 4 {
                0 => alloc::vec![0x04],
                1 => alloc::vec![0x04, 0x04],
                2 => alloc::vec![0x04, 0x04, 0x04],
                _ => alloc::vec![0x1f, 0xff, 0x00],
            })
            .collect()
    }

    /// `units` read by one session into a list that logs them (by their place
    /// in `container` when it is given, which holds them back to back) and by
    /// another into a list that keeps them whole.
    fn logged_and_whole(
        units: &[Vec<u8>],
        handshake: LinkHandshake,
        container: Option<&[u8]>,
    ) -> (MessageList, MessageList) {
        logged_and_whole_ending(units, handshake, container, |_| None)
    }

    /// [`logged_and_whole`], with the records of the unit of packet `k` given
    /// the end `end(k)` says, as a layer below that framed the unit does.
    fn logged_and_whole_ending(
        units: &[Vec<u8>],
        handshake: LinkHandshake,
        container: Option<&[u8]>,
        end: impl Fn(usize) -> Option<usize>,
    ) -> (MessageList, MessageList) {
        let mut logging = crate::passive::PassiveSession::new();
        let mut keeping = crate::passive::PassiveSession::new();
        let (mut logged, mut whole) = (MessageList::new(), MessageList::new());
        let mut place = 0;
        for (packet, unit) in units.iter().enumerate() {
            let direction = if packet % 3 == 0 {
                Direction::B
            } else {
                Direction::A
            };
            let _ = logging.observe_at_nanos(1_000 * packet as u64);
            let _ = keeping.observe_at_nanos(1_000 * packet as u64);
            if let Some(mut read) =
                logging.next_datagram_unit_on(direction, unit, packet, handshake)
            {
                for frame in &mut read.frames {
                    frame.wire_end = end(packet);
                }
                logged.push_datagram(read, unit, container.map(|_| place), handshake);
            }
            let mut kept = keeping.next_datagram_on(direction, unit, packet, handshake);
            for frame in &mut kept {
                frame.wire_end = end(packet);
            }
            whole.append(kept);
            place += unit.len();
        }
        (logged, whole)
    }

    /// Every row and head of `logged`, read with `source`, as `whole` holds it.
    fn assert_reads_as_whole(logged: &MessageList, whole: &MessageList, source: &dyn UnitBytes) {
        let (rows, kept) = (logged.read(source), whole.read(&NoBytes));
        assert_eq!(rows.len(), kept.len());
        assert_eq!(rows.produced(), kept.produced());
        for (k, (row, want)) in rows.iter().zip(kept.iter()).enumerate() {
            assert_eq!(
                alloc::format!("{:?}", *row),
                alloc::format!("{:?}", *want),
                "row {k}"
            );
            assert_eq!(
                rows.heads_from(k).next(),
                Some(RowHead::of(&want)),
                "head {k}"
            );
            assert_eq!(
                alloc::format!("{:?}", *rows.row(k)),
                alloc::format!("{:?}", *want)
            );
        }
    }

    /// The bytes a list's unit log holds allocated.
    fn logged_allocation(list: &MessageList) -> usize {
        match &list.rows {
            Store::Held(_) => 0,
            Store::Indexed(index) => index.log.allocated(),
        }
    }

    /// Open-debt item 924, step 4c — a list of datagrams kept as entries reads
    /// as one kept whole, row for row and head for head, on a link with a
    /// handshake and on one without, logged with a copy and logged by place in a
    /// lent container; and the lent one keeps no copy.
    #[test]
    fn a_datagram_list_kept_as_entries_reads_as_one_kept_whole() {
        let units = datagrams(64);
        let container: Vec<u8> = units.concat();
        for handshake in [LinkHandshake::Present, LinkHandshake::Absent] {
            let (logged, whole) = logged_and_whole(&units, handshake, None);
            assert!(
                matches!(logged.rows, Store::Indexed(_)),
                "the units became entries"
            );
            assert!(
                logged_allocation(&logged) >= container.len(),
                "a copy is logged"
            );
            assert_reads_as_whole(&logged, &whole, &NoBytes);

            let (lent, whole) = logged_and_whole(&units, handshake, Some(&container));
            assert_eq!(logged_allocation(&lent), 0, "a lent unit keeps no copy");
            let source = Datagrams {
                container: Some(&container),
            };
            assert_reads_as_whole(&lent, &whole, &source);
        }
    }

    /// A lent unit is read where the container holds it: a reader that does
    /// not hand the container in has no bytes to read it from.
    #[test]
    #[should_panic(expected = "bytes of a datagram a list holds are not at")]
    fn a_lent_datagram_read_without_its_container_is_refused() {
        let units = datagrams(4);
        let container: Vec<u8> = units.concat();
        let (lent, _) = logged_and_whole(&units, LinkHandshake::Present, Some(&container));
        let _ = lent.read(&NoBytes).row(0);
    }

    /// Discarding a unit's last row releases its logged bytes, and what stays
    /// reads as it did, including a unit a discard cut.
    #[test]
    fn discarding_a_datagram_releases_its_bytes_and_keeps_the_rest_readable() {
        // Enough units that the log is mostly chunks of its largest size: what a
        // release can give back is whole chunks, so the one the front is in stays.
        let units = datagrams(200_000);
        let (mut logged, mut whole) = logged_and_whole(&units, LinkHandshake::Present, None);
        let before = logged_allocation(&logged);
        let mut census = DroppedFrameCensus::default();
        // Most of the 350,000 rows, and an odd count, so the front is left inside
        // a unit of several rows.
        for _ in 0..300_001 {
            census.absorb(logged.discard_oldest(&NoBytes).expect("a row"));
            census.absorb(whole.discard_oldest(&NoBytes).expect("a row"));
        }
        assert!(
            logged_allocation(&logged) < before / 2,
            "the discarded units' bytes went"
        );
        assert_reads_as_whole(&logged, &whole, &NoBytes);
        while let Some(receipt) = logged.discard_oldest(&NoBytes) {
            census.absorb(receipt);
        }
        assert_eq!(logged_allocation(&logged), 0, "an empty list logs nothing");
    }

    /// Every row still held reads as it did after EVERY discard, from the
    /// first to the last: a release that came before a unit's last row went
    /// shows only when the unit cut is the last its chunk holds, which the last
    /// unit of a log always is.
    #[test]
    fn every_discard_leaves_every_row_still_held_readable() {
        // Counts whose last unit is one of three rows, one inside the first
        // chunk and one past it.
        for (count, handshake) in [(95, LinkHandshake::Present), (231, LinkHandshake::Absent)] {
            let units = datagrams(count);
            let (mut logged, mut whole) = logged_and_whole(&units, handshake, None);
            let mut census = DroppedFrameCensus::default();
            while !logged.is_empty() {
                census.absorb(logged.discard_oldest(&NoBytes).expect("a row"));
                census.absorb(whole.discard_oldest(&NoBytes).expect("a row"));
                assert_reads_as_whole(&logged, &whole, &NoBytes);
            }
            assert_eq!(logged_allocation(&logged), 0, "an empty list logs nothing");
        }
    }

    /// The ends of units a layer below framed (a WebSocket message's end in
    /// its TCP stream) read back with every row and head, through every
    /// discard; the last row of a unit lets its end go, and a unit whose
    /// records disagree on their end is kept whole rather than given one.
    #[test]
    fn a_unit_framed_below_keeps_its_end_through_every_discard() {
        let units = datagrams(95);
        let end = |k: usize| (k % 5 != 4).then_some(10_000 + 7 * k);
        let (mut logged, mut whole) =
            logged_and_whole_ending(&units, LinkHandshake::Present, None, end);
        let Store::Indexed(index) = &logged.rows else {
            panic!("the units became entries");
        };
        assert!(index.held.is_empty(), "every unit is an entry");
        assert_eq!(
            index.wire_ends.len(),
            (0..95).filter(|&k| end(k).is_some()).count(),
            "one end per unit that has one"
        );
        let mut census = DroppedFrameCensus::default();
        assert_reads_as_whole(&logged, &whole, &NoBytes);
        while !logged.is_empty() {
            census.absorb(logged.discard_oldest(&NoBytes).expect("a row"));
            census.absorb(whole.discard_oldest(&NoBytes).expect("a row"));
            assert_reads_as_whole(&logged, &whole, &NoBytes);
        }
        let Store::Indexed(index) = &logged.rows else {
            panic!("still an index");
        };
        assert!(index.wire_ends.is_empty(), "an empty list keeps no end");

        // Records of one unit that disagree on their end.
        let mut session = crate::passive::PassiveSession::new();
        let mut list = MessageList::new();
        let mut read = session
            .next_datagram_unit_on(Direction::A, &units[2], 0, LinkHandshake::Present)
            .expect("a unit");
        for (k, frame) in read.frames.iter_mut().enumerate() {
            frame.wire_end = Some(100 + k);
        }
        list.push_datagram(read, &units[2], None, LinkHandshake::Present);
        assert!(
            matches!(&list.rows, Store::Held(rows) if rows.len() == 3),
            "kept whole"
        );
    }

    /// Both directions of a byte stream, as a list's source.
    struct TwoStreams([Vec<u8>; 2]);

    impl UnitBytes for TwoStreams {
        fn stream_bytes(
            &self,
            direction: Direction,
            from: usize,
            to: usize,
        ) -> Option<Cow<'_, [u8]>> {
            self.0[usize::from(direction == Direction::B)]
                .get(from..to)
                .map(Cow::Borrowed)
        }
    }

    /// Open-debt item 924, step 4c — A RESTATED STREAM LIST. Units framed in
    /// one byte space and stated in another (a TLS flow's plaintext and the
    /// records that carried it) read, row for row and head for head, as the
    /// same units kept whole and restated alike, before and through every
    /// discard: an entry is still read from where it was read, stands where
    /// it was restated to, ends where it was restated to end (or nowhere),
    /// and its unit's end goes with the unit's last row. The oldest source
    /// offset is the locator's, not the restated anchor's.
    #[test]
    fn a_restated_stream_list_reads_as_one_kept_whole_and_restated_alike() {
        // Per direction, framed units of one to three keep-alives.
        let stream = |seed: usize| -> Vec<u8> {
            let mut out = Vec::new();
            for k in 0..40 {
                let unit = alloc::vec![0x04u8; (k + seed) % 3 + 1];
                out.extend_from_slice(&(unit.len() as u16).to_le_bytes());
                out.extend_from_slice(&unit);
            }
            out
        };
        let source = TwoStreams([stream(0), stream(1)]);
        let mut session = crate::passive::PassiveSession::new();
        let mut keeping = crate::passive::PassiveSession::new();
        let (mut indexed, mut whole) = (MessageList::new(), MessageList::new());
        for direction in [Direction::A, Direction::B] {
            let bytes = &source.0[usize::from(direction == Direction::B)];
            session.push(direction, bytes);
            keeping.push(direction, bytes);
            while let Ok(unit) = session.next_unit_with(direction, &|_| None) {
                indexed.push_unit(unit, &source);
            }
            while let Ok(unit) = keeping.next_unit_with(direction, &|_| None) {
                whole.append(unit.frames);
            }
        }
        assert!(matches!(indexed.rows, Store::Indexed(_)), "entries");
        assert_eq!(
            indexed.oldest_source_offset(Direction::B, usize::MAX),
            Some(2)
        );
        assert_eq!(
            indexed.oldest_source_offset(Direction::B, 1),
            None,
            "direction A's rows come first"
        );
        // A unit stands at ten thousand past twice its offset, by direction,
        // and ends nowhere when its unrestated end is a multiple of seven.
        let mut restate = |direction: Direction, offset: usize, end: Option<usize>| {
            let lift = if direction == Direction::B {
                50_000
            } else {
                10_000
            };
            (
                lift + 2 * offset,
                end.filter(|end| end % 7 != 0).map(|end| lift + 3 * end),
            )
        };
        indexed.restate_from(0, &mut restate);
        whole.restate_from(0, &mut restate);
        assert!(
            whole.read(&NoBytes).iter().any(|f| f.wire_end.is_none())
                && whole.read(&NoBytes).iter().any(|f| f.wire_end.is_some()),
            "both kinds of end are restated"
        );
        assert_reads_as_whole(&indexed, &whole, &source);
        assert_eq!(
            indexed.oldest_source_offset(Direction::B, usize::MAX),
            Some(2),
            "still read where it was read"
        );
        let mut census = DroppedFrameCensus::default();
        while !indexed.is_empty() {
            census.absorb(indexed.discard_oldest(&source).expect("a row"));
            census.absorb(whole.discard_oldest(&NoBytes).expect("a row"));
            assert_reads_as_whole(&indexed, &whole, &source);
        }
        let Store::Indexed(index) = &indexed.rows else {
            panic!("still an index");
        };
        assert!(index.wire_ends.is_empty(), "an empty list keeps no end");
    }

    /// The row a list keeps for every message it can read again, whatever its
    /// unit. A word more and every list of a capture grows by it.
    #[test]
    fn an_entry_is_forty_eight_bytes() {
        assert_eq!(core::mem::size_of::<UnitRow>(), 48);
    }
}
