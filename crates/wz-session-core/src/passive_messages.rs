// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! [`Deref`] and [`DerefMut`] target a SLICE, never the `Vec`. That is the load
//! -bearing choice and it is R311y713's, one obligation over:
//!
//! - Every READ keeps working — `len`, `iter`, `first`, indexing, `&list` where
//!   `&[PassiveFrame]` is wanted, and `&mut list[..]` for an in-place rewrite
//!   like `remap_decrypted_offsets`. Two hundred call sites did not have to
//!   change, so this type could land without a rewrite that would itself be a
//!   source of defects.
//! - Nothing can GROW or SHRINK the list through the deref, because a slice has
//!   no `push`, no `extend` and no `remove`. Every such call must name a method
//!   here — which is the whole point: it makes the accounting obligation a
//!   place in the type system rather than a paragraph a reader has to follow.
//!
//! # The discard receipt
//!
//! [`MessageList::discard_oldest`] returns a `#[must_use]` [`Discarded`] that
//! panics if dropped without being consumed. A bound that drops a message and
//! does not say so is the defect `DissectionDrops` exists to prevent, and this
//! workspace has fixed instances of it four times by hand (R311y612, y649,
//! y650, y656) before R311y713 ended the same shape for flow exits by making it
//! a type. This is that ending, applied to the other list.

use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use crate::passive::PassiveFrame;

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
    held: Vec<PassiveFrame>,
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
}

impl MessageList {
    /// An empty list.
    pub fn new() -> Self {
        Self {
            held: Vec::new(),
            produced: 0,
        }
    }

    /// Append one decoded message.
    pub fn push(&mut self, frame: PassiveFrame) {
        self.held.push(frame);
        self.produced += 1;
    }

    /// Append a decoded batch, which is what a datagram unit yields.
    pub fn append(&mut self, frames: impl IntoIterator<Item = PassiveFrame>) {
        let before = self.held.len();
        self.held.extend(frames);
        // The DIFFERENCE rather than the iterator's own count: an
        // `IntoIterator` may report a size hint it does not deliver, and the
        // vector's growth is the one measurement that cannot disagree with what
        // is now in the list.
        self.produced += (self.held.len() - before) as u64;
    }

    /// R2102 (open-debt item 524) — messages ever appended here, never
    /// decremented.
    ///
    /// See the field's own doc for why an index into [`MessageList::as_slice`]
    /// cannot do this job.
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
        Some(Discarded {
            // `produced` deliberately does NOT move here. It counts what was
            // ever appended, and a trim is the one event a consumer's watermark
            // has to be able to see across.
            frame: Some(self.held.remove(0)),
        })
    }

    /// The messages, as the slice every consumer wants.
    ///
    /// Named as well as reachable through [`Deref`], because `&list` at a
    /// `&[PassiveFrame]` parameter relies on coercion and a caller building an
    /// iterator chain often cannot.
    pub fn as_slice(&self) -> &[PassiveFrame] {
        &self.held
    }
}

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

impl Deref for MessageList {
    type Target = [PassiveFrame];

    fn deref(&self) -> &Self::Target {
        &self.held
    }
}

impl DerefMut for MessageList {
    /// A SLICE, so an in-place rewrite of a frame's coordinates works and a
    /// growth or removal does not. See the module doc.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.held
    }
}

impl<'a> IntoIterator for &'a MessageList {
    type Item = &'a PassiveFrame;
    type IntoIter = core::slice::Iter<'a, PassiveFrame>;

    fn into_iter(self) -> Self::IntoIter {
        self.held.iter()
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

    /// The deref target is a SLICE, which is what makes growth impossible
    /// outside this type. Asserted through the operations a consumer actually
    /// performs, since "a slice has no push" cannot be written as an assertion.
    #[test]
    fn the_list_reads_as_a_slice_and_can_be_rewritten_in_place() {
        let mut list = MessageList::new();
        list.push(frame());
        list.append([frame(), frame()]);
        assert_eq!(list.len(), 3);
        assert_eq!(list.first().expect("a frame").stream_offset, 7);
        // In-place mutation through `DerefMut`, which is what
        // `remap_decrypted_offsets` needs and which does not change the length.
        for f in list.iter_mut() {
            f.stream_offset += 1;
        }
        assert!(list.iter().all(|f| f.stream_offset == 8));
        assert_eq!(list.len(), 3, "a rewrite cannot grow or shrink the list");
    }
}
