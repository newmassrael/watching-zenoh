// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A publisher of the client node: a stream of puts on a key, for as long as a session is
//! established, played by the workload's definitions (`wz_workload`, docs/target-build-contract.md
//! 5c) in fixed memory.
//!
//! What is here is what a publisher IS and what is counted of it: the [`Publication`] (a key, an
//! arrival process, a body that is a fixed text or made by a fill), the send-side state of a
//! plane's publications ([`Publishing`]: each one's intended times, its sequence number, the
//! moment the plane started them), the counts of the puts that went out, that were refused and
//! how late the latest was ([`PublishCounts`], one `static` of the image's whose initial value is
//! all zero bytes, so it is `.bss`), and the watch the program's loop says them with
//! ([`PublishWatch`]). The puts themselves are sent by the session's application layer, inside its
//! event (`crate::slot_active::Active`), or offered to the group's pump (`crate::slot_group`):
//! nothing runs on the program's main loop and nothing is left in a mailbox, so the cadence is the
//! plane's.
//!
//! # The times are the plan's
//!
//! A publication's intended times are `wz_workload::arrivals::Arrivals` from the moment the plane
//! started it, in nanoseconds, and a time is due on the clock's millisecond at or after it, so a
//! rate the millisecond does not divide does not drift. A put that cannot be made at its time (a
//! slow loop, a session between transports) is made as soon as it can, and the ones behind it
//! follow, at most [`CATCH_UP`] of one publication in one round, so the offered load is the plan's;
//! how late the latest put was is counted, never hidden by dropping puts (the load generator's rule
//! against coordinated omission). A put the session cannot take now is tried again after
//! [`RETRY_MS`]; one the wire cannot carry moves the publication on. A session that is lost starts
//! over when the next one is established ([`Publishing::disarm`]).
//!
//! A round is one event of the session, or one drain of the group's outbound seam: [`Publishing`]
//! says which publication is to be put next in it ([`Publishing::next`]), is told how that went
//! ([`Publishing::settle`]) and says when the plane is to be woken at ([`Publishing::wake`]); a
//! session layer, which sends as it is asked, takes all three at once ([`Publishing::poll`]).
//!
//! This module does not link `alloc`.

use core::cell::{Cell, RefCell, RefMut};

use wz_workload::arrivals::Arrivals;
use wz_workload::payload::fill_into;

use crate::slot_schedule::{Outcome, RETRY_MS};

// The words a publication is written in, so an image (and the constants a node declaration
// generates for it) names one crate for the whole publisher.
pub use wz_workload::arrivals::Process;
pub use wz_workload::payload::Fill;

/// What a publisher puts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    /// The same text every put.
    Text(&'static str),
    /// `size` bytes made for each put by `fill` from its sequence number, in the layer's buffer.
    Made { size: usize, fill: Fill },
}

impl Body {
    /// How long every put is.
    pub const fn len(&self) -> usize {
        match self {
            Self::Text(text) => text.len(),
            Self::Made { size, .. } => *size,
        }
    }

    /// Whether every put is empty.
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The bytes of the put numbered `sequence`: the text, or the fill written into `buffer`;
    /// `None` when `buffer` is shorter than the body.
    pub fn bytes<'b>(&self, sequence: u64, buffer: &'b mut [u8]) -> Option<&'b [u8]> {
        match *self {
            Self::Text(text) => Some(text.as_bytes()),
            Self::Made { size, fill } => {
                let out = buffer.get_mut(..size)?;
                fill_into(fill, sequence, out);
                Some(out)
            }
        }
    }
}

/// One publisher: the key it puts on, when, and what.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Publication {
    /// The key it puts on, a literal key expression.
    pub key: &'static str,
    /// When its puts are due (`wz_workload`'s arrival process, in nanoseconds).
    pub arrivals: Process,
    /// What it puts.
    pub body: Body,
}

impl Publication {
    /// A publication that puts nothing, to fill an array with.
    pub const NONE: Self = Self {
        key: "",
        arrivals: Process::Periodic {
            gap_nanos: 1_000_000,
        },
        body: Body::Text(""),
    };
}

/// The most puts one publication makes in one round when it is behind its times: the rest follow in
/// the next, which the plane is asked to be woken for at once, so a long stall does not hold a
/// round.
pub const CATCH_UP: u32 = 8;

/// The send-side state of a plane's publications: each one's intended times, its sequence number,
/// the moment a put the session could not take is to be tried again and the puts made of it this
/// round, from the moment the plane started them.
pub struct Publishing<const P: usize> {
    arrivals: [Arrivals; P],
    sequence: [u64; P],
    retry_at: [Option<u64>; P],
    made: [u32; P],
    /// The publication the round's next search starts at: a round takes the publications in turn
    /// from the first, so one far behind its times does not make the others wait for its puts.
    cursor: usize,
    start_ms: u64,
    armed: bool,
}

impl<const P: usize> Publishing<P> {
    /// State that has not started: the first round starts every publication at its first time.
    pub const fn new() -> Self {
        Self {
            arrivals: [Arrivals::new(Process::Periodic { gap_nanos: 1 }); P],
            sequence: [0; P],
            retry_at: [None; P],
            made: [0; P],
            cursor: 0,
            start_ms: 0,
            armed: false,
        }
    }

    /// The plane is not up: the next round starts every publication over.
    pub fn disarm(&mut self) {
        self.armed = false;
    }

    /// Start a round at `now_ms`: every publication may make [`CATCH_UP`] puts again, and a plane
    /// that was not started starts here.
    pub fn begin_round(&mut self, now_ms: u64, items: &[Publication]) {
        if !self.armed {
            for (at, item) in items.iter().take(P).enumerate() {
                self.arrivals[at] = Arrivals::new(item.arrivals);
                self.sequence[at] = 0;
                self.retry_at[at] = None;
            }
            self.start_ms = now_ms;
            self.armed = true;
        }
        self.made = [0; P];
        self.cursor = 0;
    }

    /// When publication `at`'s next put is due on the plane's clock: its intended time, rounded up
    /// to the millisecond.
    fn due_ms(&self, at: usize) -> u64 {
        self.start_ms
            .saturating_add(self.arrivals[at].due().div_ceil(1_000_000))
    }

    /// When publication `at` can next be put: its due time, or the retry of a put the session could
    /// not take, whichever is later.
    fn ready_ms(&self, at: usize) -> u64 {
        let due = self.due_ms(at);
        self.retry_at[at].map_or(due, |retry| retry.max(due))
    }

    /// The publication to put next in this round at `now_ms`, or `None` when the round has none
    /// left: none is due, or each that is has made its [`CATCH_UP`].
    pub fn next(&mut self, now_ms: u64, items: &[Publication]) -> Option<usize> {
        let count = items.len().min(P);
        let found = (0..count)
            .map(|step| (self.cursor + step) % count)
            .find(|&at| self.made[at] < CATCH_UP && self.ready_ms(at) <= now_ms)?;
        self.cursor = (found + 1) % count;
        Some(found)
    }

    /// The sequence number of publication `at`'s next put: what a made body is filled from.
    pub fn sequence(&self, at: usize) -> u64 {
        self.sequence[at]
    }

    /// The put of publication `at` that [`Self::next`] named went as `outcome` at `now_ms`: count
    /// it in `counts`, and move the publication on unless the session is to be asked again.
    pub fn settle(&mut self, at: usize, now_ms: u64, outcome: Outcome, counts: &PublishCounts<P>) {
        match outcome {
            Outcome::Retry => {
                self.retry_at[at] = Some(now_ms + RETRY_MS);
                return;
            }
            Outcome::Sent => {
                counts.record_sent(at);
                counts.record_late(at, now_ms.saturating_sub(self.due_ms(at)));
            }
            Outcome::Refused => counts.record_refused(at),
        }
        self.retry_at[at] = None;
        self.sequence[at] = self.sequence[at].wrapping_add(1);
        self.arrivals[at].advance();
        self.made[at] += 1;
    }

    /// The earliest moment at or after `now_ms` the plane is to be woken at for a publication
    /// (`now_ms` itself for one still behind its times), or `None` when there is none.
    pub fn wake(&self, now_ms: u64, items: &[Publication]) -> Option<u64> {
        (0..items.len().min(P))
            .map(|at| self.ready_ms(at).max(now_ms))
            .min()
    }

    /// One round at `now_ms` of a plane that sends as it is asked: each put due is handed to
    /// `send` with its index, key and bytes (a made body is written into `buffer` first; one longer
    /// than `buffer` is refused unsent) and counted in `counts`. Returns [`Self::wake`].
    pub fn poll(
        &mut self,
        now_ms: u64,
        items: &[Publication],
        buffer: &mut [u8],
        counts: &PublishCounts<P>,
        mut send: impl FnMut(usize, &'static str, &[u8]) -> Outcome,
    ) -> Option<u64> {
        self.begin_round(now_ms, items);
        while let Some(at) = self.next(now_ms, items) {
            let item = &items[at];
            let outcome = match item.body.bytes(self.sequence[at], buffer) {
                Some(bytes) => send(at, item.key, bytes),
                None => Outcome::Refused,
            };
            self.settle(at, now_ms, outcome, counts);
        }
        self.wake(now_ms, items)
    }
}

impl<const P: usize> Default for Publishing<P> {
    fn default() -> Self {
        Self::new()
    }
}

/// The bytes a made body is written into before it is put, in storage the image declares: `B` is
/// the longest made body of its publications, and 0 for a node whose bodies are texts. One `static`
/// whose initial value is all zero bytes, so it is `.bss`, and one for the node and not one per
/// session: a body is made and put within one round, and the rounds of two sessions never overlap
/// (the profile's rule: one thread drives the node), so the sessions share it and a session's task
/// cell does not grow by it.
pub struct MadeBuffer<const B: usize>(RefCell<[u8; B]>);

// SAFETY: the profile's rule: one thread drives the node, and only a session's layer, within one
// round, uses the buffer.
unsafe impl<const B: usize> Sync for MadeBuffer<B> {}

impl<const B: usize> MadeBuffer<B> {
    /// A buffer of zero bytes.
    pub const fn new() -> Self {
        Self(RefCell::new([0; B]))
    }

    /// The buffer for one round, or `None` while another round holds it, which the profile's rule
    /// says does not happen: a layer that is refused it puts no made body in that round and asks to
    /// be woken again, rather than stop the node.
    pub fn take(&self) -> Option<RefMut<'_, [u8; B]>> {
        self.0.try_borrow_mut().ok()
    }
}

impl<const B: usize> Default for MadeBuffer<B> {
    fn default() -> Self {
        Self::new()
    }
}

/// How many puts each publication sent and had refused, and how late its latest put was, in storage
/// the image declares.
pub struct PublishCounts<const P: usize> {
    sent: [Cell<u32>; P],
    refused: [Cell<u32>; P],
    late_max_ms: [Cell<u32>; P],
}

// SAFETY: the profile's rule: one thread drives the node, and both the session's layer (which
// writes) and the program's loop (which reads) run on it, never at the same moment.
unsafe impl<const P: usize> Sync for PublishCounts<P> {}

impl<const P: usize> PublishCounts<P> {
    /// Every count zero; all zero bytes.
    pub const fn new() -> Self {
        Self {
            sent: [const { Cell::new(0) }; P],
            refused: [const { Cell::new(0) }; P],
            late_max_ms: [const { Cell::new(0) }; P],
        }
    }

    fn bump(cells: &[Cell<u32>; P], at: usize) {
        if let Some(cell) = cells.get(at) {
            cell.set(cell.get().wrapping_add(1));
        }
    }

    /// The put of publication `at` went out.
    pub fn record_sent(&self, at: usize) {
        Self::bump(&self.sent, at);
    }

    /// The put of publication `at` was refused.
    pub fn record_refused(&self, at: usize) {
        Self::bump(&self.refused, at);
    }

    /// A put of publication `at` went out `late_ms` after its intended time: the latest so far is
    /// kept.
    pub fn record_late(&self, at: usize, late_ms: u64) {
        if let Some(cell) = self.late_max_ms.get(at) {
            let late = u32::try_from(late_ms).unwrap_or(u32::MAX);
            if late > cell.get() {
                cell.set(late);
            }
        }
    }

    /// Puts of publication `at` that went out.
    pub fn sent(&self, at: usize) -> u32 {
        self.sent.get(at).map_or(0, Cell::get)
    }

    /// Puts of publication `at` that were refused.
    pub fn refused(&self, at: usize) -> u32 {
        self.refused.get(at).map_or(0, Cell::get)
    }

    /// How late, in milliseconds, the latest put of publication `at` was against its intended time.
    pub fn late_max_ms(&self, at: usize) -> u32 {
        self.late_max_ms.get(at).map_or(0, Cell::get)
    }
}

impl<const P: usize> Default for PublishCounts<P> {
    fn default() -> Self {
        Self::new()
    }
}

/// What the program's loop remembers of the counts between two rounds, to say each change once.
///
/// A round that finds a publication's counts moved calls `say` with the counts NOW: puts that went
/// out between two rounds are one report with a count that jumps, so nothing is hidden by it.
pub struct PublishWatch<const P: usize> {
    seen: [(u32, u32, u32); P],
}

impl<const P: usize> PublishWatch<P> {
    /// A watch that has seen nothing.
    pub const fn new() -> Self {
        Self {
            seen: [(0, 0, 0); P],
        }
    }

    /// Call `say(index, sent, refused, late_max_ms)` for each publication whose counts moved since
    /// the last call.
    pub fn poll(&mut self, counts: &PublishCounts<P>, mut say: impl FnMut(usize, u32, u32, u32)) {
        for (at, seen) in self.seen.iter_mut().enumerate() {
            let now = (counts.sent(at), counts.refused(at), counts.late_max_ms(at));
            if now != *seen {
                *seen = now;
                say(at, now.0, now.1, now.2);
            }
        }
    }
}

impl<const P: usize> Default for PublishWatch<P> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn every(ms: u64, body: Body) -> Publication {
        Publication {
            key: "k",
            arrivals: Process::Periodic {
                gap_nanos: ms * 1_000_000,
            },
            body,
        }
    }

    fn counter(size: usize) -> Body {
        Body::Made {
            size,
            fill: Fill::Counter,
        }
    }

    /// One round at `now_ms` answering every put with `outcome`: the (index, bytes) offered and
    /// the wake.
    fn poll<const P: usize>(
        state: &mut Publishing<P>,
        counts: &PublishCounts<P>,
        now_ms: u64,
        items: &[Publication],
        outcome: Outcome,
    ) -> (Vec<(usize, Vec<u8>)>, Option<u64>) {
        let mut offered = Vec::new();
        let mut buffer = [0u8; 16];
        let wake = state.poll(now_ms, items, &mut buffer, counts, |at, _, body| {
            offered.push((at, body.to_vec()));
            outcome
        });
        (offered, wake)
    }

    #[test]
    fn the_first_round_puts_at_once_and_the_next_is_a_period_on() {
        let (mut state, counts) = (Publishing::<2>::new(), PublishCounts::<2>::new());
        let items = [every(100, Body::Text("a")), every(250, Body::Text("b"))];
        let (offered, wake) = poll(&mut state, &counts, 1_000, &items, Outcome::Sent);
        assert_eq!(offered, [(0, b"a".to_vec()), (1, b"b".to_vec())]);
        assert_eq!(wake, Some(1_100));
        let (offered, wake) = poll(&mut state, &counts, 1_050, &items, Outcome::Sent);
        assert!(offered.is_empty());
        assert_eq!(wake, Some(1_100));
    }

    /// The times are the plan's: a rate of three a second is due at 0, 334, 667 and 1000 ms (each
    /// time rounded up to the millisecond, never accumulating the rounding).
    #[test]
    fn a_rate_the_millisecond_does_not_divide_does_not_drift() {
        let (mut state, counts) = (Publishing::<1>::new(), PublishCounts::<1>::new());
        let third = [Publication {
            key: "k",
            arrivals: Process::Periodic {
                gap_nanos: 333_333_333,
            },
            body: Body::Text("x"),
        }];
        let mut times = Vec::new();
        let mut now = 0;
        for _ in 0..4 {
            let (offered, wake) = poll(&mut state, &counts, now, &third, Outcome::Sent);
            assert_eq!(offered.len(), 1);
            times.push(now);
            now = wake.expect("a wake");
        }
        assert_eq!(times, [0, 334, 667, 1_000]);
    }

    /// A plane woken late puts every time it passed (up to the round's budget) and counts how late
    /// it was: the load is the plan's, and the delay is said, not hidden.
    #[test]
    fn a_late_round_catches_up_and_says_how_late() {
        let (mut state, counts) = (Publishing::<1>::new(), PublishCounts::<1>::new());
        let one = [every(100, Body::Text("x"))];
        poll(&mut state, &counts, 0, &one, Outcome::Sent);
        let (offered, wake) = poll(&mut state, &counts, 350, &one, Outcome::Sent);
        assert_eq!(offered.len(), 3, "the puts due at 100, 200 and 300");
        assert_eq!(wake, Some(400));
        assert_eq!((counts.sent(0), counts.late_max_ms(0)), (4, 250));
        // A stall longer than the budget: eight now, the rest in the next round, at once.
        let (offered, wake) = poll(&mut state, &counts, 2_000, &one, Outcome::Sent);
        assert_eq!((offered.len(), wake), (CATCH_UP as usize, Some(2_000)));
    }

    /// A round takes the publications in turn from the first, so one far behind does not make the
    /// others wait for its puts.
    #[test]
    fn a_round_takes_the_publications_in_turn() {
        let (mut state, counts) = (Publishing::<2>::new(), PublishCounts::<2>::new());
        let items = [every(10, Body::Text("a")), every(10, Body::Text("b"))];
        poll(&mut state, &counts, 0, &items, Outcome::Sent);
        let (offered, _) = poll(&mut state, &counts, 20, &items, Outcome::Sent);
        let order: Vec<usize> = offered.iter().map(|(at, _)| *at).collect();
        assert_eq!(order, [0, 1, 0, 1]);
    }

    #[test]
    fn a_made_body_is_the_fill_of_its_sequence_number() {
        let (mut state, counts) = (Publishing::<1>::new(), PublishCounts::<1>::new());
        let made = [every(10, counter(4))];
        let (first, _) = poll(&mut state, &counts, 0, &made, Outcome::Sent);
        let (second, _) = poll(&mut state, &counts, 10, &made, Outcome::Sent);
        assert_eq!(first, [(0, alloc::vec![0, 0, 0, 0])]);
        assert_eq!(second, [(0, alloc::vec![1, 0, 0, 0])]);
        let (mut state, counts) = (Publishing::<1>::new(), PublishCounts::<1>::new());
        let (offered, _) = poll(
            &mut state,
            &counts,
            0,
            &[every(10, counter(32))],
            Outcome::Sent,
        );
        assert!(
            offered.is_empty(),
            "a body longer than the buffer is not put"
        );
        assert_eq!(counts.refused(0), 1);
    }

    #[test]
    fn a_put_the_session_could_not_take_is_tried_again_soon_and_not_moved_on() {
        let (mut state, counts) = (Publishing::<1>::new(), PublishCounts::<1>::new());
        let one = [every(1_000, counter(1))];
        let (_, wake) = poll(&mut state, &counts, 500, &one, Outcome::Retry);
        assert_eq!(wake, Some(500 + RETRY_MS));
        let (offered, wake) = poll(&mut state, &counts, 500 + RETRY_MS, &one, Outcome::Sent);
        assert_eq!(offered, [(0, alloc::vec![0])], "the same put, sequence 0");
        assert_eq!(wake, Some(1_500));
        assert_eq!(
            (counts.sent(0), counts.late_max_ms(0)),
            (1, RETRY_MS as u32)
        );
    }

    #[test]
    fn a_refused_put_moves_the_publication_on() {
        let (mut state, counts) = (Publishing::<1>::new(), PublishCounts::<1>::new());
        let one = [every(100, Body::Text("x"))];
        let (_, wake) = poll(&mut state, &counts, 0, &one, Outcome::Refused);
        assert_eq!(wake, Some(100));
        assert_eq!((counts.sent(0), counts.refused(0)), (0, 1));
    }

    #[test]
    fn a_session_that_was_lost_starts_over_when_the_next_is_established() {
        let (mut state, counts) = (Publishing::<1>::new(), PublishCounts::<1>::new());
        let one = [every(100, counter(1))];
        poll(&mut state, &counts, 0, &one, Outcome::Sent);
        poll(&mut state, &counts, 100, &one, Outcome::Sent);
        state.disarm();
        let (offered, wake) = poll(&mut state, &counts, 40, &one, Outcome::Sent);
        assert_eq!(offered, [(0, alloc::vec![0])], "due at once, sequence 0");
        assert_eq!(wake, Some(140));
    }

    #[test]
    fn a_node_with_no_publication_wants_no_wake() {
        let (mut state, counts) = (Publishing::<0>::new(), PublishCounts::<0>::new());
        let (offered, wake) = poll(&mut state, &counts, 10, &[], Outcome::Sent);
        assert!(offered.is_empty());
        assert_eq!(wake, None);
    }

    #[test]
    fn the_made_buffer_is_lent_to_one_round_at_a_time() {
        let buffer = MadeBuffer::<4>::new();
        let held = buffer.take().expect("a free buffer is lent");
        assert!(
            buffer.take().is_none(),
            "a buffer a round holds is not lent twice"
        );
        drop(held);
        assert!(buffer.take().is_some());
    }

    #[test]
    fn the_counts_are_kept_by_publication_and_an_index_outside_them_is_nothing() {
        let counts = PublishCounts::<2>::new();
        counts.record_sent(1);
        counts.record_sent(1);
        counts.record_refused(0);
        counts.record_sent(7);
        counts.record_late(7, 9);
        assert_eq!(
            (
                counts.sent(0),
                counts.sent(1),
                counts.refused(0),
                counts.refused(1)
            ),
            (0, 2, 1, 0)
        );
        assert_eq!(
            (counts.sent(7), counts.refused(7), counts.late_max_ms(7)),
            (0, 0, 0)
        );
    }

    #[test]
    fn the_watch_says_a_change_once_with_the_counts_of_everything_since() {
        let counts = PublishCounts::<1>::new();
        let mut watch = PublishWatch::<1>::new();
        let mut said = Vec::new();
        let mut say = |at, sent, refused, late| said.push((at, sent, refused, late));
        watch.poll(&counts, &mut say);
        counts.record_sent(0);
        counts.record_sent(0);
        counts.record_refused(0);
        counts.record_late(0, 7);
        counts.record_late(0, 3);
        watch.poll(&counts, &mut say);
        watch.poll(&counts, &mut say);
        assert_eq!(
            said,
            [(0, 2, 1, 7)],
            "one report for five events, said once"
        );
    }
}
