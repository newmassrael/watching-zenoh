// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y723 (§1.1f) — the one type decoded transport messages are held in.
//!
//! # What this replaces, and why a type rather than a wider check
//!
//! Four census planes walk one enumeration ([`crate::Dissection::message_lists`],
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

extern crate alloc;

use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use wz_session_core::passive::PassiveFrame;

/// Decoded transport messages, in the order the observer produced them.
///
/// See the module doc: this is a newtype so that the population of "things a
/// census plane must be shown" is a NAME rather than a container shape, and so
/// that growth and removal have exactly one door each.
#[derive(Debug, Default)]
pub struct MessageList(Vec<PassiveFrame>);

impl MessageList {
    /// An empty list.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Append one decoded message.
    pub fn push(&mut self, frame: PassiveFrame) {
        self.0.push(frame);
    }

    /// Append a decoded batch, which is what a datagram unit yields.
    pub fn append(&mut self, frames: impl IntoIterator<Item = PassiveFrame>) {
        self.0.extend(frames);
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
        if self.0.is_empty() {
            return None;
        }
        Some(Discarded {
            frame: Some(self.0.remove(0)),
        })
    }

    /// The messages, as the slice every consumer wants.
    ///
    /// Named as well as reachable through [`Deref`], because `&list` at a
    /// `&[PassiveFrame]` parameter relies on coercion and a caller building an
    /// iterator chain often cannot.
    pub fn as_slice(&self) -> &[PassiveFrame] {
        &self.0
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
/// A caller takes the frame with [`Self::take`], which is what discharges the
/// obligation; dropping the receipt without doing so is a bug in the caller and
/// says so at the moment it happens rather than as a wrong number in a report.
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
    pub fn take(mut self) -> PassiveFrame {
        // Emptying the option IS the discharge: `self` drops at the end of this
        // call and its destructor then sees a receipt with nothing left to
        // account for. No second flag, and no `mem::forget` -- a receipt that
        // skipped its own destructor could not assert anything.
        self.frame
            .take()
            .expect("a receipt holds its frame until it is taken, once")
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
        &self.0
    }
}

impl DerefMut for MessageList {
    /// A SLICE, so an in-place rewrite of a frame's coordinates works and a
    /// growth or removal does not. See the module doc.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> IntoIterator for &'a MessageList {
    type Item = &'a PassiveFrame;
    type IntoIter = core::slice::Iter<'a, PassiveFrame>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
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
        let mut session = wz_session_core::passive::PassiveSession::new();
        let mut out = session.next_datagram_on(
            wz_session_core::passive::Direction::A,
            // A KeepAlive: MID 0x04 with every flag clear.
            &[0x04],
            7,
            wz_session_core::passive::LinkHandshake::Absent,
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

    /// And the discharge: taking it is what makes the drop legal.
    #[test]
    fn taking_the_receipt_discharges_the_obligation() {
        let mut list = MessageList::new();
        list.push(frame());
        let gone = list.discard_oldest().expect("a message to discard").take();
        assert_eq!(
            gone.stream_offset, 7,
            "the caller gets the frame it must count"
        );
        assert!(list.is_empty(), "and the list no longer holds it");
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
