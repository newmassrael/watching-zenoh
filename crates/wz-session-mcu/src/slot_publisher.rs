// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The client node as a PUBLISHER, written once for every platform: it puts a fixed document on a
//! key every period, for as long as a session is established.
//!
//! The session's own application layer does it, inside its event: after the layer has dispatched
//! what the iteration brought, it asks its [`Schedule`] what is due, sends each due put on the
//! session ([`SessionLayer`] [`Publishing`] over `PublishEvents`), and tells the drive loop the
//! moment it needs to be awake next ([`set_app_wake_deadline_ms`]), which the loop budgets its
//! wait by together with the transport's own. Nothing runs on the program's main loop and nothing
//! is left in a mailbox: the cadence is the session's.
//!
//! # When a put goes out
//!
//! The first put of a session goes out on its first event after it is established, and each
//! following one a period after the one before it: a loop that was late does not send the puts it
//! missed, it sends one and starts counting again from there. A put the session cannot take now
//! (it is between transports) is tried again after [`RETRY_MS`] and is not counted; a put the wire
//! cannot carry is counted as refused and the period moves on. A session that is lost starts over
//! when the next one is established.
//!
//! # State
//!
//! The schedule is per session and lives in the session's task cell (a deadline for each
//! publication). What the node counts (puts sent, puts refused) is in [`PublishCounts`], one
//! `static` of the image's whose initial value is all zero bytes, so it is `.bss`, and which the
//! program's loop reads ([`PublishWatch`]) to say what happened.
//!
//! This module does not link `alloc`.
//!
//! [`set_app_wake_deadline_ms`]: wz_session_core::session_actions::SessionLinkActions::set_app_wake_deadline_ms

use core::cell::Cell;

use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::ClockSource;
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::send_wire_error::SendWireError;
use wz_session_core::slot_observer::{ObserverCell, Requesters};

use crate::app_layer::{NoReplies, SessionEvents, SlotDispatch};
use crate::slot_client::DocumentSinks;
use crate::slot_node::SessionLayer;

/// How long after a put the session could not take, in milliseconds, it is tried again.
pub const RETRY_MS: u64 = 10;

/// One publisher: the document it puts on its key, and how often.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Publication {
    /// The key it puts on, a literal key expression.
    pub key: &'static str,
    /// The time between two puts, in milliseconds (at least 1).
    pub period_ms: u32,
    /// What it puts.
    pub body: &'static str,
}

impl Publication {
    /// A publication that puts nothing, to fill an array with.
    pub const NONE: Self = Self {
        key: "",
        period_ms: 1,
        body: "",
    };
}

/// What happened to a put the schedule asked the session to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// It went out.
    Sent,
    /// The session could not take it now; ask again soon.
    Retry,
    /// The wire cannot carry it; the period moves on.
    Refused,
}

/// What a session's publications are due, as deadlines in the session clock's milliseconds. A pure
/// value: the session's layer gives it the time and sends what it says is due.
pub struct Schedule<const P: usize> {
    due: [u64; P],
    armed: bool,
}

impl<const P: usize> Schedule<P> {
    /// A schedule that has not started: its first poll finds every publication due.
    pub const fn new() -> Self {
        Self {
            due: [0; P],
            armed: false,
        }
    }

    /// The session is not established: the next poll starts over, with every publication due.
    pub fn disarm(&mut self) {
        self.armed = false;
    }

    /// Offer each publication that is due at `now_ms` to `send`, and move its deadline by what
    /// `send` answers. Returns the earliest deadline, which the drive loop is to be woken at, or
    /// `None` for a node with no publication.
    pub fn poll(
        &mut self,
        now_ms: u64,
        publications: &[Publication],
        mut send: impl FnMut(usize, &Publication) -> Outcome,
    ) -> Option<u64> {
        let count = publications.len().min(P);
        if !self.armed {
            self.due[..count].fill(now_ms);
            self.armed = true;
        }
        let mut earliest: Option<u64> = None;
        for (at, publication) in publications.iter().take(count).enumerate() {
            if now_ms >= self.due[at] {
                self.due[at] = match send(at, publication) {
                    Outcome::Retry => now_ms + RETRY_MS,
                    Outcome::Sent | Outcome::Refused => {
                        let period = u64::from(publication.period_ms.max(1));
                        let next = self.due[at] + period;
                        // A loop that was late sends once and counts again from here.
                        if next > now_ms {
                            next
                        } else {
                            now_ms + period
                        }
                    }
                };
            }
            earliest = Some(earliest.map_or(self.due[at], |e| e.min(self.due[at])));
        }
        earliest
    }
}

impl<const P: usize> Default for Schedule<P> {
    fn default() -> Self {
        Self::new()
    }
}

/// How many puts each publication sent and had refused, in storage the image declares.
pub struct PublishCounts<const P: usize> {
    sent: [Cell<u32>; P],
    refused: [Cell<u32>; P],
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

    /// Puts of publication `at` that went out.
    pub fn sent(&self, at: usize) -> u32 {
        self.sent.get(at).map_or(0, Cell::get)
    }

    /// Puts of publication `at` that were refused.
    pub fn refused(&self, at: usize) -> u32 {
        self.refused.get(at).map_or(0, Cell::get)
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
    seen: [(u32, u32); P],
}

impl<const P: usize> PublishWatch<P> {
    /// A watch that has seen nothing.
    pub const fn new() -> Self {
        Self { seen: [(0, 0); P] }
    }

    /// Call `say(index, sent, refused)` for each publication whose counts moved since the last call.
    pub fn poll(&mut self, counts: &PublishCounts<P>, mut say: impl FnMut(usize, u32, u32)) {
        for (at, seen) in self.seen.iter_mut().enumerate() {
            let now = (counts.sent(at), counts.refused(at));
            if now != *seen {
                *seen = now;
                say(at, now.0, now.1);
            }
        }
    }
}

impl<const P: usize> Default for PublishWatch<P> {
    fn default() -> Self {
        Self::new()
    }
}

/// The application layer of a session of a node that publishes: what a node that only answers does
/// ([`SlotDispatch`]), and then the puts that are due.
///
/// When the node is built with `query-get` the dispatch states the deadline of the session's
/// pending queries to the drive loop on each event; the layer states its own after it, and a node
/// that publishes asks nothing, so there is nothing to lose by that.
pub struct PublishEvents<C: ClockSource + 'static, const P: usize> {
    inner: SlotDispatch<C, NoReplies, NoReplies, DocumentSinks>,
    handle: SessionHandle<C>,
    publications: [Publication; P],
    counts: &'static PublishCounts<P>,
    schedule: Schedule<P>,
}

impl<C: ClockSource + 'static, const P: usize> SessionEvents for PublishEvents<C, P> {
    fn on_event(&mut self, event: IterationEvent<'_>) {
        self.inner.on_event(event);
        if P == 0 {
            return;
        }
        if !self.handle.is_established() {
            self.schedule.disarm();
            self.handle.set_app_wake_deadline_ms(None);
            return;
        }
        let now_ms = wz_runtime_core::TimeSource::now_monotonic_ms(&self.handle.clock);
        let (handle, counts) = (&self.handle, self.counts);
        let next = self
            .schedule
            .poll(now_ms, &self.publications, |at, publication| {
                match handle.send_push_literal(publication.key, publication.body.as_bytes(), true) {
                    Ok(()) => {
                        counts.record_sent(at);
                        Outcome::Sent
                    }
                    Err(SendWireError::TransportUnavailable) => Outcome::Retry,
                    Err(_) => {
                        counts.record_refused(at);
                        Outcome::Refused
                    }
                }
            });
        self.handle.set_app_wake_deadline_ms(next);
    }
}

/// The layer of a node that publishes `publications`, counting into `counts`.
pub struct Publishing<const P: usize> {
    /// What it puts, and how often.
    pub publications: [Publication; P],
    /// Where it counts.
    pub counts: &'static PublishCounts<P>,
}

impl<C: ClockSource + 'static, const P: usize> SessionLayer<C> for Publishing<P> {
    type Events = PublishEvents<C, P>;

    fn events(
        &mut self,
        observer: &'static ObserverCell<DocumentSinks>,
        handle: &SessionHandle<C>,
    ) -> Self::Events {
        PublishEvents {
            inner: SlotDispatch::new(
                observer,
                handle.clone(),
                Requesters::<NoReplies, NoReplies>::new(),
            ),
            handle: handle.clone(),
            publications: self.publications,
            counts: self.counts,
            schedule: Schedule::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn publication(period_ms: u32) -> Publication {
        Publication {
            key: "demo/beat",
            period_ms,
            body: "x",
        }
    }

    /// Poll `schedule` at `now_ms`, answering each offer with `outcome`; the indexes it was offered
    /// and the deadline it returned.
    fn poll<const P: usize>(
        schedule: &mut Schedule<P>,
        now_ms: u64,
        publications: &[Publication],
        outcome: Outcome,
    ) -> (Vec<usize>, Option<u64>) {
        let mut offered = Vec::new();
        let next = schedule.poll(now_ms, publications, |at, _| {
            offered.push(at);
            outcome
        });
        (offered, next)
    }

    #[test]
    fn the_first_poll_finds_everything_due_and_the_next_is_a_period_on() {
        let mut schedule = Schedule::<2>::new();
        let both = [publication(100), publication(250)];
        let (offered, next) = poll(&mut schedule, 1_000, &both, Outcome::Sent);
        assert_eq!(offered, [0, 1]);
        assert_eq!(next, Some(1_100), "the earliest of the two deadlines");
        let (offered, next) = poll(&mut schedule, 1_050, &both, Outcome::Sent);
        assert!(offered.is_empty(), "nothing is due before its deadline");
        assert_eq!(next, Some(1_100));
        let (offered, next) = poll(&mut schedule, 1_100, &both, Outcome::Sent);
        assert_eq!(offered, [0]);
        assert_eq!(next, Some(1_200));
    }

    #[test]
    fn the_cadence_does_not_drift_by_the_lateness_of_a_wake() {
        let mut schedule = Schedule::<1>::new();
        let one = [publication(100)];
        poll(&mut schedule, 0, &one, Outcome::Sent);
        // Woken 7 ms late: the put goes out, and the next is still on the original grid.
        let (offered, next) = poll(&mut schedule, 107, &one, Outcome::Sent);
        assert_eq!(offered, [0]);
        assert_eq!(next, Some(200));
    }

    #[test]
    fn a_loop_that_missed_periods_sends_one_and_counts_again_from_now() {
        let mut schedule = Schedule::<1>::new();
        let one = [publication(100)];
        poll(&mut schedule, 0, &one, Outcome::Sent);
        let (offered, next) = poll(&mut schedule, 1_000, &one, Outcome::Sent);
        assert_eq!(offered, [0], "one put, not ten");
        assert_eq!(next, Some(1_100));
    }

    #[test]
    fn a_put_the_session_could_not_take_is_tried_again_soon_and_not_a_period_later() {
        let mut schedule = Schedule::<1>::new();
        let one = [publication(1_000)];
        let (_, next) = poll(&mut schedule, 500, &one, Outcome::Retry);
        assert_eq!(next, Some(500 + RETRY_MS));
        let (offered, next) = poll(&mut schedule, 500 + RETRY_MS, &one, Outcome::Sent);
        assert_eq!(offered, [0]);
        assert_eq!(next, Some(500 + RETRY_MS + 1_000));
    }

    #[test]
    fn a_refused_put_moves_the_period_on() {
        let mut schedule = Schedule::<1>::new();
        let one = [publication(100)];
        let (_, next) = poll(&mut schedule, 0, &one, Outcome::Refused);
        assert_eq!(next, Some(100));
    }

    #[test]
    fn a_session_that_was_lost_starts_over_when_the_next_is_established() {
        let mut schedule = Schedule::<1>::new();
        let one = [publication(100)];
        poll(&mut schedule, 0, &one, Outcome::Sent);
        schedule.disarm();
        let (offered, next) = poll(&mut schedule, 40, &one, Outcome::Sent);
        assert_eq!(offered, [0], "due at once, not at 100");
        assert_eq!(next, Some(140));
    }

    #[test]
    fn a_node_with_no_publication_wants_no_wake() {
        let mut schedule = Schedule::<0>::new();
        let (offered, next) = poll(&mut schedule, 10, &[], Outcome::Sent);
        assert!(offered.is_empty());
        assert_eq!(next, None);
    }

    #[test]
    fn a_period_of_zero_is_one_millisecond_and_not_a_spin() {
        let mut schedule = Schedule::<1>::new();
        let one = [publication(0)];
        let (_, next) = poll(&mut schedule, 5, &one, Outcome::Sent);
        assert_eq!(next, Some(6));
    }

    #[test]
    fn the_counts_are_kept_by_publication_and_an_index_outside_them_is_nothing() {
        let counts = PublishCounts::<2>::new();
        counts.record_sent(1);
        counts.record_sent(1);
        counts.record_refused(0);
        counts.record_sent(7);
        assert_eq!(
            (
                counts.sent(0),
                counts.sent(1),
                counts.refused(0),
                counts.refused(1)
            ),
            (0, 2, 1, 0)
        );
        assert_eq!((counts.sent(7), counts.refused(7)), (0, 0));
    }

    #[test]
    fn the_watch_says_a_change_once_with_the_counts_of_everything_since() {
        let counts = PublishCounts::<1>::new();
        let mut watch = PublishWatch::<1>::new();
        let mut said = Vec::new();
        watch.poll(&counts, |at, sent, refused| said.push((at, sent, refused)));
        assert!(said.is_empty(), "nothing happened");
        counts.record_sent(0);
        counts.record_sent(0);
        counts.record_refused(0);
        watch.poll(&counts, |at, sent, refused| said.push((at, sent, refused)));
        watch.poll(&counts, |at, sent, refused| said.push((at, sent, refused)));
        assert_eq!(said, [(0, 2, 1)], "one report for three events, said once");
    }
}
