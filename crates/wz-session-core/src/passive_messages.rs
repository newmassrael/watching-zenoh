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
//! Readers get ROWS, not a slice: `len`, `get`, `first`, `last`, `iter`,
//! `iter_mut`, indexing, and `&list` in a `for`. Two rules hold, R311y713's and
//! open-debt item 924's:
//!
//! - Nothing can GROW or SHRINK the list except through a method here: the row
//!   API has no `push`, no `extend` and no `remove`. That makes the accounting
//!   obligation a place in the type system rather than a paragraph a reader has
//!   to follow.
//! - Nothing outside this type learns how the rows are STORED. Until item 924
//!   the list was a slice behind `Deref`, which promised every reader one
//!   contiguous run; a list of hundreds of thousands of rows kept that promise
//!   by doubling one buffer and copying every row into each new one, and held up
//!   to half of it as capacity no row used. The rows now sit in chunks (see
//!   `ChunkLog`), and the next steps of `docs/dissect-row-index.md` change what a
//!   row is behind the same API.
//!
//! # The discard receipt
//!
//! [`MessageList::discard_oldest`] returns a `#[must_use]` [`Discarded`] that
//! panics if dropped without being consumed. A bound that drops a message and
//! does not say so is the defect `DissectionDrops` exists to prevent, and this
//! workspace has fixed instances of it four times by hand (R311y612, y649,
//! y650, y656) before R311y713 ended the same shape for flow exits by making it
//! a type. This is that ending, applied to the other list.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::ops::{Index, IndexMut};

use crate::passive::PassiveFrame;
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
    held: ChunkLog<PassiveFrame>,
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
            held: ChunkLog::new(),
            produced: 0,
            #[cfg(feature = "reassembly")]
            chain_prefix: ChainFold::default(),
        }
    }

    /// The chain fold the messages this list has DISCARDED left behind: the state
    /// a reader that begins at the first message the list holds must start from to
    /// number chains as one that saw every message would. See the field's own doc.
    #[cfg(feature = "reassembly")]
    pub fn chain_prefix(&self) -> &ChainFold {
        &self.chain_prefix
    }

    /// Append one decoded message.
    pub fn push(&mut self, frame: PassiveFrame) {
        self.held.push_back(frame);
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
    /// `None` for an empty list rather than a panic: a bound that cannot be met
    /// must not take the capture down with it, which is the rule the flow caps
    /// already follow.
    #[must_use = "a discarded message must be accounted for -- see `Discarded`"]
    pub fn discard_oldest(&mut self) -> Option<Discarded> {
        if self.held.is_empty() {
            return None;
        }
        let frame = self.held.pop_front();
        // The one moment the message is still in hand: fold what a chain's
        // identity needs of it, so the count does not depend on how much of the
        // front a ceiling has taken. See the field's doc.
        #[cfg(feature = "reassembly")]
        if let Some(gone) = &frame {
            let _ = self.chain_prefix.observe(gone);
        }
        Some(Discarded {
            // `produced` deliberately does NOT move here. It counts what was
            // ever appended, and a trim is the one event a consumer's watermark
            // has to be able to see across.
            frame,
        })
    }

    /// Messages held now: what was appended less what a bound discarded.
    #[inline]
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// No message is held.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.held.len() == 0
    }

    /// The message at position `index` among those held, oldest first.
    #[inline]
    pub fn get(&self, index: usize) -> Option<&PassiveFrame> {
        self.held.get(index)
    }

    /// [`Self::get`], for an in-place rewrite of a held message (a remap of its
    /// coordinates). There is no way to add or remove one through it.
    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut PassiveFrame> {
        self.held.get_mut(index)
    }

    /// The oldest message held.
    #[inline]
    pub fn first(&self) -> Option<&PassiveFrame> {
        self.held.get(0)
    }

    /// The newest message held.
    #[inline]
    pub fn last(&self) -> Option<&PassiveFrame> {
        self.held
            .len()
            .checked_sub(1)
            .and_then(|i| self.held.get(i))
    }

    /// The messages held, oldest first.
    #[inline]
    pub fn iter(&self) -> Iter<'_, PassiveFrame> {
        self.held.iter()
    }

    /// The messages held, oldest first, for an in-place rewrite.
    pub fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = &mut PassiveFrame> {
        self.held.iter_mut()
    }

    /// The messages from position `from` on, for an in-place rewrite of what
    /// one call added.
    pub fn iter_mut_from(
        &mut self,
        from: usize,
    ) -> impl DoubleEndedIterator<Item = &mut PassiveFrame> {
        self.held.iter_mut_from(from)
    }

    /// The messages from position `from` on, as a view a reader can count,
    /// index and walk: what one call added, handed on without a copy.
    #[inline]
    pub fn rows_from(&self, from: usize) -> Rows<'_> {
        Rows { list: self, from }
    }
}

/// The messages of a [`MessageList`] from one position on.
///
/// What a door hands a reader of "the messages this call added": the list
/// itself, borrowed, and where they begin, so nothing is copied and nothing about
/// how the list stores its rows leaks into the reader.
#[derive(Debug, Clone, Copy)]
pub struct Rows<'a> {
    list: &'a MessageList,
    from: usize,
}

impl<'a> Rows<'a> {
    /// Messages in the view.
    #[inline]
    pub fn len(&self) -> usize {
        self.list.len().saturating_sub(self.from)
    }

    /// The view holds none.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The message at `index` within the view.
    #[inline]
    pub fn get(&self, index: usize) -> Option<&'a PassiveFrame> {
        self.list.get(self.from.checked_add(index)?)
    }

    /// The messages of the view, oldest first.
    #[inline]
    pub fn iter(&self) -> Iter<'a, PassiveFrame> {
        self.list.held.iter_from(self.from)
    }
}

impl<'a> IntoIterator for Rows<'a> {
    type Item = &'a PassiveFrame;
    type IntoIter = Iter<'a, PassiveFrame>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Rows per chunk of a [`ChunkLog`].
///
/// Large enough that the chunk list itself is negligible (one entry per this
/// many rows), small enough that the unused tail of the last chunk is
/// negligible against any list long enough to have one. A power of two, so the
/// first chunk, which grows the way any buffer does, reaches exactly this
/// capacity and stops.
const CHUNK_ROWS: usize = 1024;

/// An append-only list of rows, read by position and released from the front.
///
/// # Why chunks
///
/// One growable buffer doubles: each growth copies every row into a buffer
/// twice the size, and up to half of what it holds is capacity no row uses.
/// For a list of hundreds of thousands of decoded rows that is hundreds of
/// megabytes of copying while the list grows and up to as much again held
/// empty. Here rows go into chunks of `CHUNK_ROWS` (1024). The first chunk grows
/// like any buffer, so a short list costs what a short list costs; every later
/// chunk is allocated whole, so no row is ever copied again, and the most a
/// long list holds unused is one chunk's tail.
///
/// # Every chunk is one run
///
/// A chunk is a ring, so it could hold its rows as two runs. Only a chunk that
/// is both released from and appended to can wrap, which is the one-chunk list
/// of a live tap at its ceiling, and such a chunk is straightened when it does
/// (at most `CHUNK_ROWS` moves, once per `CHUNK_ROWS` appends). So every
/// chunk reads as ONE slice, and [`Iter`] walks slices and skips whole chunks:
/// `iter().skip(n)` costs the chunks it passes, as a slice's costs nothing,
/// rather than one step per row.
///
/// # The shape that makes a position O(1)
///
/// Every chunk except the first and the last holds exactly `CHUNK_ROWS` rows.
/// Appending fills the last chunk to `CHUNK_ROWS` before starting another, and
/// releasing takes rows from the first chunk only, dropping it when it is empty,
/// so neither can break that. The first chunk's length is the only variable
/// before a position, and dividing the rest by `CHUNK_ROWS` finds the chunk.
///
/// No chunk is ever empty, which is what lets [`Self::len`] of zero mean "no
/// chunks" and the first chunk always be the one rows are released from.
#[derive(Debug)]
pub struct ChunkLog<T> {
    /// A `Vec` and not a deque: a position is found by indexing it, and the
    /// front is dropped once per [`CHUNK_ROWS`] releases, which moves one
    /// pointer per chunk held.
    chunks: Vec<VecDeque<T>>,
    len: usize,
}

impl<T> Default for ChunkLog<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> ChunkLog<T> {
    /// An empty log.
    pub const fn new() -> Self {
        Self {
            chunks: Vec::new(),
            len: 0,
        }
    }

    /// Rows held.
    pub fn len(&self) -> usize {
        self.len
    }

    /// No row is held.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append one row.
    pub fn push_back(&mut self, row: T) {
        let chunks = self.chunks.len();
        match self.chunks.last_mut() {
            Some(last) if last.len() < CHUNK_ROWS => {
                last.push_back(row);
                // Only a chunk that is also released from can wrap, and the
                // last chunk is released from only when it is the first.
                if chunks == 1 {
                    straighten(last);
                }
            }
            _ => {
                // The first chunk grows; any later one is allocated whole.
                let mut chunk = if chunks == 0 {
                    VecDeque::new()
                } else {
                    VecDeque::with_capacity(CHUNK_ROWS)
                };
                chunk.push_back(row);
                self.chunks.push(chunk);
            }
        }
        self.len += 1;
    }

    /// Release the oldest row.
    pub fn pop_front(&mut self) -> Option<T> {
        let first = self.chunks.first_mut()?;
        let row = first.pop_front();
        if first.is_empty() {
            self.chunks.remove(0);
        } else {
            straighten(first);
        }
        if row.is_some() {
            self.len -= 1;
        }
        row
    }

    /// Where the row at `index` sits: its chunk and its place in it.
    fn locate(&self, index: usize) -> Option<(usize, usize)> {
        if index >= self.len {
            return None;
        }
        let first = self.chunks.first()?.len();
        if index < first {
            return Some((0, index));
        }
        let rest = index - first;
        Some((1 + rest / CHUNK_ROWS, rest % CHUNK_ROWS))
    }

    /// The row at `index`, oldest first.
    #[inline]
    pub fn get(&self, index: usize) -> Option<&T> {
        let (chunk, at) = self.locate(index)?;
        run(self.chunks.get(chunk)?).get(at)
    }

    /// [`Self::get`], mutably.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        let (chunk, at) = self.locate(index)?;
        self.chunks.get_mut(chunk)?.as_mut_slices().0.get_mut(at)
    }

    /// The rows, oldest first.
    pub fn iter(&self) -> Iter<'_, T> {
        self.iter_from(0)
    }

    /// The rows from position `from` on, oldest first: what one call added to
    /// the list, read without walking what was there before it.
    pub fn iter_from(&self, from: usize) -> Iter<'_, T> {
        let chunks = self.chunks.len();
        let Some((chunk, at)) = self.locate(from) else {
            return Iter {
                front: <&[T]>::default().iter(),
                middle: self.chunks[chunks..].iter(),
                back: <&[T]>::default().iter(),
            };
        };
        let last = chunks - 1;
        let front = run(&self.chunks[chunk])[at..].iter();
        if chunk == last {
            Iter {
                front,
                middle: self.chunks[chunks..].iter(),
                back: <&[T]>::default().iter(),
            }
        } else {
            // Every chunk strictly between the first read and the last is
            // full, which is what `Iter::left` counts on.
            Iter {
                front,
                middle: self.chunks[chunk + 1..last].iter(),
                back: run(&self.chunks[last]).iter(),
            }
        }
    }

    /// The rows, oldest first, mutably.
    pub fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = &mut T> {
        self.iter_mut_from(0)
    }

    /// The rows from position `from` on, mutably.
    pub fn iter_mut_from(&mut self, from: usize) -> impl DoubleEndedIterator<Item = &mut T> {
        let (chunk, at) = self.locate(from).unwrap_or((self.chunks.len(), 0));
        self.chunks
            .iter_mut()
            .enumerate()
            .skip(chunk)
            .flat_map(move |(i, rows)| rows.range_mut(if i == chunk { at } else { 0 }..))
    }
}

/// Keep a chunk one run: see [`ChunkLog`]. Free while the ring has not
/// wrapped, which is every chunk but a one-chunk list's at a live ceiling.
fn straighten<T>(chunk: &mut VecDeque<T>) {
    if !chunk.as_slices().1.is_empty() {
        chunk.make_contiguous();
    }
}

/// A chunk's rows, as the one run [`straighten`] keeps them in.
fn run<T>(chunk: &VecDeque<T>) -> &[T] {
    let (rows, wrapped) = chunk.as_slices();
    debug_assert!(wrapped.is_empty(), "a chunk holds its rows as one run");
    rows
}

/// The rows of a [`ChunkLog`] (and so of a [`MessageList`]), oldest first.
///
/// Walks the chunks as slices: the run being read from the front, the run being
/// read from the back, and the whole chunks between them. A skip passes whole
/// chunks by their length rather than row by row.
///
/// Every chunk between the two runs is a FULL chunk (only a log's first and
/// last chunk can be short, and those are where the runs begin), so what is
/// left is known from the three without a count kept per row, and the step
/// that reads a row is the slice's own.
#[derive(Debug, Clone)]
pub struct Iter<'a, T> {
    front: core::slice::Iter<'a, T>,
    middle: core::slice::Iter<'a, VecDeque<T>>,
    back: core::slice::Iter<'a, T>,
}

impl<'a, T> Iter<'a, T> {
    /// Rows not yet read.
    fn left(&self) -> usize {
        self.front.len() + self.middle.len() * CHUNK_ROWS + self.back.len()
    }

    /// The iterator, spent.
    fn spend(&mut self) {
        self.front = <&[T]>::default().iter();
        self.middle.by_ref().for_each(drop);
        self.back = <&[T]>::default().iter();
    }

    /// [`Iterator::next`] once the front run is spent.
    #[cold]
    fn next_past_front(&mut self) -> Option<&'a T> {
        match self.middle.next() {
            Some(chunk) => {
                self.front = run(chunk).iter();
                self.front.next()
            }
            None => self.back.next(),
        }
    }

    /// [`DoubleEndedIterator::next_back`] once the back run is spent.
    #[cold]
    fn next_back_past_back(&mut self) -> Option<&'a T> {
        match self.middle.next_back() {
            Some(chunk) => {
                self.back = run(chunk).iter();
                self.back.next_back()
            }
            None => self.front.next_back(),
        }
    }
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    #[inline]
    fn next(&mut self) -> Option<&'a T> {
        match self.front.next() {
            Some(row) => Some(row),
            None => self.next_past_front(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.left();
        (left, Some(left))
    }

    fn count(self) -> usize {
        self.left()
    }

    fn last(mut self) -> Option<&'a T> {
        self.next_back()
    }

    fn nth(&mut self, mut n: usize) -> Option<&'a T> {
        if n >= self.left() {
            // Past the end: the iterator is spent, as a slice's is.
            self.spend();
            return None;
        }
        loop {
            let here = self.front.len();
            if n < here {
                return self.front.nth(n);
            }
            n -= here;
            // The run is passed whole: spent here, so no later step reads it
            // again.
            self.front = <&[T]>::default().iter();
            match self.middle.next() {
                Some(chunk) => self.front = run(chunk).iter(),
                None => return self.back.nth(n),
            }
        }
    }
}

impl<T> DoubleEndedIterator for Iter<'_, T> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        match self.back.next_back() {
            Some(row) => Some(row),
            None => self.next_back_past_back(),
        }
    }

    fn nth_back(&mut self, mut n: usize) -> Option<Self::Item> {
        if n >= self.left() {
            self.spend();
            return None;
        }
        loop {
            let here = self.back.len();
            if n < here {
                return self.back.nth_back(n);
            }
            n -= here;
            self.back = <&[T]>::default().iter();
            match self.middle.next_back() {
                Some(chunk) => self.back = run(chunk).iter(),
                None => return self.front.nth_back(n),
            }
        }
    }
}

impl<T> ExactSizeIterator for Iter<'_, T> {}

impl<T> core::iter::FusedIterator for Iter<'_, T> {}

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

impl Index<usize> for MessageList {
    type Output = PassiveFrame;

    /// The message at `index`; panics past the end, as a slice does.
    #[inline]
    fn index(&self, index: usize) -> &PassiveFrame {
        match self.get(index) {
            Some(frame) => frame,
            None => out_of_range(index, self.len()),
        }
    }
}

impl IndexMut<usize> for MessageList {
    /// An in-place rewrite of one message. See the module doc.
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut PassiveFrame {
        let len = self.len();
        match self.get_mut(index) {
            Some(frame) => frame,
            None => out_of_range(index, len),
        }
    }
}

/// The panic of an index past the end, kept off the path that does not take it.
#[cold]
#[inline(never)]
fn out_of_range(index: usize, len: usize) -> ! {
    panic!("message {index} of a list holding {len}")
}

impl<'a> IntoIterator for &'a MessageList {
    type Item = &'a PassiveFrame;
    type IntoIter = Iter<'a, PassiveFrame>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let _ = list.discard_oldest();
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
        census.absorb(list.discard_oldest().expect("a message to discard"));
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
        census.absorb(list.discard_oldest().expect("a message to discard"));
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
            census.absorb(list.discard_oldest().expect("a message to discard"));
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
        assert!(list.discard_oldest().is_none());
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
        assert_eq!(list.first().expect("a frame").stream_offset, 7);
        // In-place mutation, which is what `remap_decrypted_offsets` needs and
        // which does not change the length.
        for f in list.iter_mut() {
            f.stream_offset += 1;
        }
        assert!(list.iter().all(|f| f.stream_offset == 8));
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
            census.absorb(list.discard_oldest().expect("the list is not empty"));
            list.push(frame());
        }
        assert_eq!(census.total(), 64, "every discard was accounted for");
        assert_eq!(list.len(), 8, "a discard and a push leave the length alone");
        assert_eq!(list.iter().count(), 8, "and the iterator agrees with it");
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
            assert_eq!(list.first().map(|f| f.stream_offset), want.first().copied());
            assert_eq!(list.last().map(|f| f.stream_offset), want.last().copied());
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
                CHUNK_ROWS - 1,
                CHUNK_ROWS,
                CHUNK_ROWS + 1,
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
                CHUNK_ROWS - 1,
                CHUNK_ROWS,
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
                    list.rows_from(from).len(),
                    tail.len(),
                    "from {from}, counted"
                );
                assert_eq!(
                    list.rows_from(from).get(0).map(|f| f.stream_offset),
                    tail.first().copied(),
                    "from {from}, indexed"
                );
            }
        }
        let mut list = MessageList::new();
        let mut census = DroppedFrameCensus::default();
        let grown = 3 * CHUNK_ROWS + 17;
        list.append((0..grown).map(numbered));
        check(&list, 0..grown);
        // Into the middle of the second chunk, so the first chunk is gone and the
        // new first is a partial one.
        let trimmed = CHUNK_ROWS + 300;
        for _ in 0..trimmed {
            census.absorb(list.discard_oldest().expect("held"));
        }
        check(&list, trimmed..grown);
        let regrown = grown + 2 * CHUNK_ROWS;
        list.append((grown..regrown).map(numbered));
        check(&list, trimmed..regrown);
        // And down to nothing, which must leave a list that grows again.
        while let Some(gone) = list.discard_oldest() {
            census.absorb(gone);
        }
        check(&list, 0..0);
        list.push(numbered(5));
        check(&list, 5..6);
        assert_eq!(census.total(), regrown);
    }
}
