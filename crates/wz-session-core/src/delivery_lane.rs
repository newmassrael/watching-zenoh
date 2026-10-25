// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The bookkeeping of a bounded lane between the receive path and the task that runs a
//! subscriber's callbacks (`docs/rx-delivery-lane.md`).
//!
//! # What it is
//!
//! The receive path copies a sample into a byte area and goes on; a separate consumer runs the
//! callbacks later, in order. What the lane has to decide is how much may wait, and what happens
//! at the bound. It holds the counts and the places, nothing else: the BYTES are the host's. A
//! host with a heap keeps a `Vec`, one with none keeps a static array, and the lane tells it where
//! in that area a sample goes ([`crate::delivery_lane::Reservation::offset`]) and how long it is.
//! The lane reads no clock, allocates nothing, starts no task and does no I/O, so every host uses
//! the one set of rules.
//!
//! # Three bounds at once
//!
//! A sample is admitted only when all three hold: an event slot is free (`EVENTS`, the const
//! parameter), its bytes fit the byte area, and the callbacks it will make fit the callback budget.
//! The first two are charged when the sample is reserved and the third when it is published,
//! because how many callbacks a sample owes is known only after the host has looked up who
//! subscribes to its key.
//!
//! # The rules it states once
//!
//! * Samples leave in the order they were reserved. A sample that was reserved but not yet
//!   published holds the head of the lane: [`crate::delivery_lane::DeliveryLane::front`] says
//!   [`crate::delivery_lane::Next::Waiting`] and passes nothing behind it.
//! * A refusal at either step returns every charge it took, and a refused sample takes no callback
//!   budget. A refusal after the reservation leaves the slot to be skipped in order; its bytes and
//!   event slot come back when the head reaches it.
//! * A sample that owes more callbacks than the whole budget is admitted only when it is the only
//!   sample in the lane, so a large fan-out is delayed and never starved.
//! * The byte area is a ring. A sample's bytes are contiguous: one that does not fit before the end
//!   of the area is placed at the start, and the tail it skipped is charged to it. The bound counts
//!   the charge, not the length.
//! * Every refusal is counted by reason, saturating. A counter that wrapped would hide the
//!   overload it exists to show.
//! * A lane that is stopping admits nothing; it is stopped when every sample it admitted has been
//!   delivered or skipped.

use crate::reliability::Reliability;

/// Why the lane did not admit a sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Every event slot is taken.
    EventsFull,
    /// The sample's bytes do not fit the byte area, wrap charge included.
    BytesFull,
    /// The callbacks the sample owes do not fit the callback budget.
    CallbacksFull,
    /// The lane is stopping.
    Stopping,
    /// The host has no consumer to run the callbacks. The lane never decides this; the host says
    /// it through [`crate::delivery_lane::DeliveryLane::refuse_no_consumer`] so that it is counted
    /// beside the others.
    NoConsumer,
}

/// What the receive path answers for a sample the lane refused, by how the sample was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overload {
    /// The sample is dropped without a result: it was sent best-effort, and the sender asked for no
    /// more.
    Drop,
    /// The receive path reports a resource-limit result, recorded as a LOCAL delivery failure and
    /// not as the peer's fault: the sample was sent reliably, so losing it silently would break
    /// what the sender was promised.
    LocalResourceLimit,
}

impl Overload {
    /// The answer for a sample sent with `reliability`. One function, so no host chooses it.
    pub const fn of(reliability: Reliability) -> Self {
        match reliability {
            Reliability::BestEffort => Overload::Drop,
            Reliability::Reliable => Overload::LocalResourceLimit,
        }
    }
}

/// A place in the lane that a producer holds between [`DeliveryLane::reserve`] and
/// [`DeliveryLane::publish`] or [`DeliveryLane::cancel`]. It is not `Clone`: the producer gives it
/// back exactly once, and the type says so.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a reservation holds the head of the lane until it is published or cancelled"]
pub struct Reservation {
    index: usize,
    offset: usize,
    bytes: usize,
}

impl Reservation {
    /// Where in the host's byte area the sample's `bytes` go.
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// How many bytes were reserved at [`Self::offset`].
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// The event slot the sample holds, below the lane's `EVENTS`: a host that keeps a record
    /// beside each sample (its kind, its timestamp) keeps it at this index, and the consumer finds
    /// it at [`Delivery::index`].
    pub const fn index(&self) -> usize {
        self.index
    }
}

/// A published sample at the head of the lane, as the consumer reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delivery {
    /// The event slot it holds: [`Reservation::index`] of the reservation it was admitted by.
    pub index: usize,
    /// Where its bytes are in the host's byte area.
    pub offset: usize,
    /// How many bytes it holds.
    pub bytes: usize,
    /// How many callbacks it owes.
    pub callbacks: usize,
}

/// What the head of the lane is, as [`DeliveryLane::front`] answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// Nothing waits.
    Empty,
    /// The head was reserved and is not published yet: the consumer waits for it and passes
    /// nothing behind it.
    Waiting,
    /// A published sample is at the head. It stays there, holding its charges, until the consumer
    /// calls [`DeliveryLane::complete`].
    Ready(Delivery),
}

/// How many samples the lane refused, by reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Refused {
    /// Every reason together.
    pub total: usize,
    /// [`Refusal::EventsFull`].
    pub events_full: usize,
    /// [`Refusal::BytesFull`].
    pub bytes_full: usize,
    /// [`Refusal::CallbacksFull`].
    pub callbacks_full: usize,
    /// [`Refusal::Stopping`].
    pub stopping: usize,
    /// [`Refusal::NoConsumer`].
    pub no_consumer: usize,
}

/// A snapshot of the lane: what waits, against what bound, and what was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Event slots in use, reserved ones included.
    pub queued_events: usize,
    /// Event slots the lane has.
    pub event_capacity: usize,
    /// Of those, the ones reserved and not yet published.
    pub reserved_events: usize,
    /// Callbacks owed by the published samples.
    pub pending_callbacks: usize,
    /// The callback budget.
    pub callback_budget: usize,
    /// Bytes charged, wrap padding included.
    pub pending_bytes: usize,
    /// The byte area's size.
    pub byte_capacity: usize,
    /// Refusals by reason.
    pub refused: Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Free,
    /// Reserved; the producer has not published or cancelled it.
    Reserved,
    /// Published with callbacks owed.
    Ready,
    /// Refused after the reservation, cancelled, or owing nothing: the consumer skips it.
    Void,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    offset: usize,
    bytes: usize,
    /// What the byte area is charged for this entry: its length, and the padding at the end of the
    /// area it skipped to stay contiguous.
    charge: usize,
    callbacks: usize,
    phase: Phase,
}

impl Entry {
    const FREE: Entry = Entry {
        offset: 0,
        bytes: 0,
        charge: 0,
        callbacks: 0,
        phase: Phase::Free,
    };
}

/// `at` moved on by `n` in a ring of `cap`, which `at` is inside of.
const fn advance(at: usize, n: usize, cap: usize) -> usize {
    if n >= cap - at {
        n - (cap - at)
    } else {
        at + n
    }
}

/// The lane. `EVENTS` is how many samples it holds at most.
#[derive(Debug, Clone)]
pub struct DeliveryLane<const EVENTS: usize> {
    entries: [Entry; EVENTS],
    head: usize,
    len: usize,
    byte_capacity: usize,
    byte_head: usize,
    byte_tail: usize,
    byte_used: usize,
    callback_budget: usize,
    pending_callbacks: usize,
    reserved: usize,
    stopping: bool,
    refused: Refused,
}

impl<const EVENTS: usize> DeliveryLane<EVENTS> {
    /// A lane over a byte area of `byte_capacity` bytes that admits callbacks up to
    /// `callback_budget` at once. A bound of zero is a lane nothing can enter, so it is refused
    /// where it is built.
    pub const fn new(byte_capacity: usize, callback_budget: usize) -> Self {
        assert!(EVENTS > 0, "a lane with no event slot admits nothing");
        assert!(byte_capacity > 0, "a lane with no byte area admits nothing");
        assert!(
            callback_budget > 0,
            "a lane with no callback budget admits nothing"
        );
        Self {
            entries: [Entry::FREE; EVENTS],
            head: 0,
            len: 0,
            byte_capacity,
            byte_head: 0,
            byte_tail: 0,
            byte_used: 0,
            callback_budget,
            pending_callbacks: 0,
            reserved: 0,
            stopping: false,
            refused: Refused {
                total: 0,
                events_full: 0,
                bytes_full: 0,
                callbacks_full: 0,
                stopping: 0,
                no_consumer: 0,
            },
        }
    }

    fn count(&mut self, why: Refusal) -> Refusal {
        let by_reason = match why {
            Refusal::EventsFull => &mut self.refused.events_full,
            Refusal::BytesFull => &mut self.refused.bytes_full,
            Refusal::CallbacksFull => &mut self.refused.callbacks_full,
            Refusal::Stopping => &mut self.refused.stopping,
            Refusal::NoConsumer => &mut self.refused.no_consumer,
        };
        *by_reason = by_reason.saturating_add(1);
        self.refused.total = self.refused.total.saturating_add(1);
        why
    }

    /// The host has no consumer for a sample: count it beside the lane's own refusals and return
    /// it, so the host answers it as it answers any other.
    pub fn refuse_no_consumer(&mut self) -> Refusal {
        self.count(Refusal::NoConsumer)
    }

    /// Where a sample of `n` bytes goes, and what the byte area is charged for it; `None` when it
    /// does not fit. A sample is never split: if it does not fit before the end of the area, it
    /// goes to the start, and the end it skipped is part of the charge.
    fn place(&self, n: usize) -> Option<(usize, usize)> {
        let (head, tail, cap) = (self.byte_head, self.byte_tail, self.byte_capacity);
        let free = cap - self.byte_used;
        if n == 0 {
            return Some((tail, 0));
        }
        if tail >= head {
            if n <= cap - tail && n <= free {
                return Some((tail, n));
            }
            let pad = cap - tail;
            if n <= head && pad <= free && n <= free - pad {
                return Some((0, pad + n));
            }
        } else if n <= head - tail && n <= free {
            return Some((tail, n));
        }
        None
    }

    /// Take a slot and room for `bytes` bytes, or say why not. The producer writes the sample at
    /// [`Reservation::offset`] and then calls [`Self::publish`], or [`Self::cancel`] if it cannot.
    /// Until it does, the reservation holds the head of the lane.
    pub fn reserve(&mut self, bytes: usize) -> Result<Reservation, Refusal> {
        if self.stopping {
            return Err(self.count(Refusal::Stopping));
        }
        if self.len == EVENTS {
            return Err(self.count(Refusal::EventsFull));
        }
        let Some((offset, charge)) = self.place(bytes) else {
            return Err(self.count(Refusal::BytesFull));
        };
        let index = advance(self.head, self.len, EVENTS);
        self.entries[index] = Entry {
            offset,
            bytes,
            charge,
            callbacks: 0,
            phase: Phase::Reserved,
        };
        self.byte_tail = advance(offset, bytes, self.byte_capacity);
        self.byte_used += charge;
        self.len += 1;
        self.reserved += 1;
        Ok(Reservation {
            index,
            offset,
            bytes,
        })
    }

    /// The producer wrote the sample and it owes `callbacks` callbacks. Charges them against the
    /// budget, or says why not and leaves the slot to be skipped.
    ///
    /// A sample that owes none is not a refusal: nobody subscribes to its key, so it is skipped
    /// quietly. A sample that owes more than the whole budget is admitted only when it is the only
    /// one in the lane.
    pub fn publish(&mut self, reservation: Reservation, callbacks: usize) -> Result<(), Refusal> {
        let at = reservation.index;
        debug_assert_eq!(self.entries[at].phase, Phase::Reserved);
        self.reserved -= 1;
        if self.stopping {
            self.entries[at].phase = Phase::Void;
            return Err(self.count(Refusal::Stopping));
        }
        if callbacks == 0 {
            self.entries[at].phase = Phase::Void;
            return Ok(());
        }
        let budget = self.callback_budget;
        let pending = self.pending_callbacks;
        let oversized = callbacks > budget;
        let fits = if oversized {
            self.len == 1
        } else {
            pending <= budget && callbacks <= budget - pending
        };
        if !fits {
            self.entries[at].phase = Phase::Void;
            return Err(self.count(Refusal::CallbacksFull));
        }
        self.pending_callbacks += callbacks;
        self.entries[at].callbacks = callbacks;
        self.entries[at].phase = Phase::Ready;
        Ok(())
    }

    /// The producer could not write the sample after all (its own failure, not the lane's): the
    /// slot is skipped in order and nothing is counted as a refusal.
    pub fn cancel(&mut self, reservation: Reservation) {
        debug_assert_eq!(self.entries[reservation.index].phase, Phase::Reserved);
        self.reserved -= 1;
        self.entries[reservation.index].phase = Phase::Void;
    }

    /// Give the head's charges back and move on.
    fn pop(&mut self) {
        let entry = self.entries[self.head];
        self.pending_callbacks -= entry.callbacks;
        self.byte_head = advance(self.byte_head, entry.charge, self.byte_capacity);
        self.byte_used -= entry.charge;
        self.entries[self.head] = Entry::FREE;
        self.head = advance(self.head, 1, EVENTS);
        self.len -= 1;
        if self.len == 0 {
            // Nothing is charged, so the area starts over: a sample is not split by where the
            // last one happened to end.
            self.byte_head = 0;
            self.byte_tail = 0;
            self.byte_used = 0;
        }
    }

    /// What the head of the lane is. Skipped slots at the head are passed over here. The answer
    /// does not change until the consumer calls [`Self::complete`], the producer publishes the head,
    /// or a skipped slot is passed.
    pub fn front(&mut self) -> Next {
        loop {
            if self.len == 0 {
                return Next::Empty;
            }
            let entry = self.entries[self.head];
            match entry.phase {
                Phase::Void => self.pop(),
                Phase::Reserved => return Next::Waiting,
                Phase::Ready => {
                    return Next::Ready(Delivery {
                        index: self.head,
                        offset: entry.offset,
                        bytes: entry.bytes,
                        callbacks: entry.callbacks,
                    })
                }
                Phase::Free => {
                    debug_assert!(false, "a free slot inside the lane");
                    return Next::Empty;
                }
            }
        }
    }

    /// The consumer has run the callbacks of the head sample: its charges come back. Returns
    /// whether there was a published sample at the head to complete.
    pub fn complete(&mut self) -> bool {
        if self.len == 0 || self.entries[self.head].phase != Phase::Ready {
            return false;
        }
        self.pop();
        true
    }

    /// Admit nothing more. What was admitted is still delivered or skipped.
    pub fn stop(&mut self) {
        self.stopping = true;
    }

    /// Whether the lane is stopping or stopped.
    pub const fn is_stopping(&self) -> bool {
        self.stopping
    }

    /// Whether the lane is stopped: it was told to stop and everything it admitted is delivered or
    /// skipped, so a host may take the byte area back.
    pub const fn is_stopped(&self) -> bool {
        self.stopping && self.len == 0
    }

    /// A snapshot of the lane.
    pub const fn stats(&self) -> Stats {
        Stats {
            queued_events: self.len,
            event_capacity: EVENTS,
            reserved_events: self.reserved,
            pending_callbacks: self.pending_callbacks,
            callback_budget: self.callback_budget,
            pending_bytes: self.byte_used,
            byte_capacity: self.byte_capacity,
            refused: self.refused,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lane<const E: usize>(bytes: usize, callbacks: usize) -> DeliveryLane<E> {
        DeliveryLane::new(bytes, callbacks)
    }

    /// Reserve and publish one sample, and say what it took.
    fn admit<const E: usize>(
        lane: &mut DeliveryLane<E>,
        bytes: usize,
        callbacks: usize,
    ) -> Result<Delivery, Refusal> {
        let r = lane.reserve(bytes)?;
        let (index, offset, len) = (r.index(), r.offset(), r.bytes());
        lane.publish(r, callbacks)?;
        Ok(Delivery {
            index,
            offset,
            bytes: len,
            callbacks,
        })
    }

    #[test]
    fn a_full_lane_refuses_by_events_and_takes_the_slot_back_when_one_completes() {
        let mut lane = lane::<2>(100, 10);
        admit(&mut lane, 1, 1).unwrap();
        admit(&mut lane, 1, 1).unwrap();
        assert_eq!(lane.reserve(1).unwrap_err(), Refusal::EventsFull);
        assert_eq!(lane.stats().refused.events_full, 1);
        assert!(matches!(lane.front(), Next::Ready(_)));
        assert!(lane.complete());
        admit(&mut lane, 1, 1).expect("the slot came back");
    }

    #[test]
    fn a_sample_that_does_not_fit_the_byte_area_is_refused_and_takes_nothing() {
        let mut lane = lane::<4>(10, 10);
        admit(&mut lane, 8, 1).unwrap();
        assert_eq!(lane.reserve(3).unwrap_err(), Refusal::BytesFull);
        assert_eq!(lane.stats().refused.bytes_full, 1);
        assert_eq!(
            lane.stats().queued_events,
            1,
            "a refused reserve took no slot"
        );
        assert_eq!(lane.stats().pending_bytes, 8);
        assert_eq!(
            lane.reserve(11).unwrap_err(),
            Refusal::BytesFull,
            "longer than the area"
        );
    }

    #[test]
    fn a_sample_is_not_split_across_the_end_of_the_area_and_the_skipped_tail_is_charged() {
        let mut lane = lane::<4>(10, 10);
        let first = admit(&mut lane, 6, 1).unwrap();
        let second = admit(&mut lane, 3, 1).unwrap();
        assert_eq!((first.offset, second.offset), (0, 6));
        // The first sample is delivered; its six bytes are free at the start of the area.
        assert!(matches!(lane.front(), Next::Ready(d) if d.offset == 0));
        assert!(lane.complete());
        // Five bytes do not fit in the one byte left at the end (offset 9): they go to the start.
        let wrapped = admit(&mut lane, 5, 1).unwrap();
        assert_eq!(wrapped.offset, 0, "placed at the start, whole");
        assert_eq!(
            lane.stats().pending_bytes,
            3 + (1 + 5),
            "the byte left at the end is charged to the sample that skipped it"
        );
    }

    #[test]
    fn an_empty_lane_starts_its_area_over() {
        let mut lane = lane::<4>(10, 10);
        admit(&mut lane, 7, 1).unwrap();
        assert!(matches!(lane.front(), Next::Ready(_)));
        assert!(lane.complete());
        let again = admit(&mut lane, 9, 1).unwrap();
        assert_eq!(again.offset, 0, "nothing is charged, so nothing is skipped");
        assert_eq!(lane.stats().pending_bytes, 9);
    }

    #[test]
    fn a_sample_with_no_bytes_takes_a_slot_and_no_room() {
        let mut lane = lane::<2>(4, 10);
        admit(&mut lane, 4, 1).unwrap();
        let empty = admit(&mut lane, 0, 1).expect("an empty payload needs no room");
        assert_eq!(empty.bytes, 0);
        assert_eq!(lane.stats().pending_bytes, 4);
    }

    #[test]
    fn callbacks_past_the_budget_are_refused_and_the_refused_sample_takes_none() {
        let mut lane = lane::<4>(100, 4);
        admit(&mut lane, 1, 3).unwrap();
        assert_eq!(admit(&mut lane, 1, 2).unwrap_err(), Refusal::CallbacksFull);
        let stats = lane.stats();
        assert_eq!(
            stats.pending_callbacks, 3,
            "the refused sample took no callback budget"
        );
        assert_eq!(stats.refused.callbacks_full, 1);
        assert_eq!(
            stats.queued_events, 2,
            "its slot waits to be skipped in order"
        );
        // The refused slot is skipped, in order, behind the first.
        assert!(matches!(lane.front(), Next::Ready(d) if d.callbacks == 3));
        assert!(lane.complete());
        assert_eq!(
            lane.front(),
            Next::Empty,
            "the refused slot was passed over"
        );
        assert_eq!(lane.stats().pending_bytes, 0, "and its bytes came back");
    }

    #[test]
    fn a_sample_that_owes_more_than_the_budget_is_admitted_only_alone() {
        let mut lane = lane::<4>(100, 2);
        admit(&mut lane, 1, 5).expect("alone, it is admitted");
        assert_eq!(
            lane.stats().pending_callbacks,
            5,
            "the budget is overdrawn by the one sample that needs it"
        );
        assert_eq!(
            admit(&mut lane, 1, 1).unwrap_err(),
            Refusal::CallbacksFull,
            "nothing more is admitted while the budget is overdrawn"
        );
        assert!(lane.complete());
        assert_eq!(lane.front(), Next::Empty);

        admit(&mut lane, 1, 1).unwrap();
        assert_eq!(
            admit(&mut lane, 1, 5).unwrap_err(),
            Refusal::CallbacksFull,
            "not alone, it is refused"
        );
    }

    #[test]
    fn a_sample_that_owes_no_callback_is_skipped_and_is_not_a_refusal() {
        let mut lane = lane::<2>(10, 10);
        admit(&mut lane, 4, 0).expect("nobody subscribes: not refused");
        assert_eq!(lane.stats().refused.total, 0);
        assert_eq!(lane.front(), Next::Empty);
        assert_eq!(lane.stats().pending_bytes, 0);
    }

    #[test]
    fn a_reserved_head_holds_everything_behind_it() {
        let mut lane = lane::<4>(100, 10);
        let head = lane.reserve(2).unwrap();
        let _ = admit(&mut lane, 2, 1).unwrap();
        assert_eq!(lane.front(), Next::Waiting, "the head is not published");
        assert!(
            !lane.complete(),
            "nothing to complete behind a reserved head"
        );
        lane.publish(head, 1).unwrap();
        assert!(matches!(lane.front(), Next::Ready(_)));
        assert!(lane.complete());
        assert!(
            matches!(lane.front(), Next::Ready(_)),
            "then the one behind it"
        );
    }

    #[test]
    fn a_cancelled_reservation_is_skipped_in_order_and_is_not_a_refusal() {
        let mut lane = lane::<4>(100, 10);
        let first = lane.reserve(3).unwrap();
        admit(&mut lane, 2, 1).unwrap();
        lane.cancel(first);
        assert_eq!(lane.stats().refused.total, 0);
        assert!(matches!(lane.front(), Next::Ready(d) if d.bytes == 2));
        assert!(lane.complete());
        assert_eq!(lane.stats().pending_bytes, 0);
        assert_eq!(lane.stats().queued_events, 0);
    }

    #[test]
    fn samples_leave_in_the_order_they_were_reserved() {
        let mut lane = lane::<4>(100, 10);
        for callbacks in 1..=3 {
            admit(&mut lane, 1, callbacks).unwrap();
        }
        let mut seen = [0usize; 3];
        for slot in &mut seen {
            let Next::Ready(delivery) = lane.front() else {
                panic!("a sample is ready")
            };
            *slot = delivery.callbacks;
            assert!(lane.complete());
        }
        assert_eq!(seen, [1, 2, 3]);
    }

    #[test]
    fn a_stopping_lane_admits_nothing_and_is_stopped_when_what_it_admitted_is_gone() {
        let mut lane = lane::<4>(100, 10);
        admit(&mut lane, 1, 1).unwrap();
        let held = lane.reserve(1).unwrap();
        lane.stop();
        assert!(lane.is_stopping());
        assert_eq!(lane.reserve(1).unwrap_err(), Refusal::Stopping);
        assert_eq!(lane.stats().refused.stopping, 1);
        assert!(!lane.is_stopped(), "a sample is still waiting");
        assert!(matches!(lane.front(), Next::Ready(_)));
        assert!(lane.complete());
        assert!(!lane.is_stopped(), "a reservation is still held");
        assert_eq!(
            lane.publish(held, 1).unwrap_err(),
            Refusal::Stopping,
            "a sample published after the stop is not delivered"
        );
        assert_eq!(lane.front(), Next::Empty);
        assert!(lane.is_stopped());
    }

    #[test]
    fn the_host_counts_a_missing_consumer_beside_the_lanes_own_refusals() {
        let mut lane = lane::<1>(10, 10);
        assert_eq!(lane.refuse_no_consumer(), Refusal::NoConsumer);
        let refused = lane.stats().refused;
        assert_eq!((refused.no_consumer, refused.total), (1, 1));
    }

    #[test]
    fn a_counter_saturates_and_does_not_wrap() {
        let mut lane = lane::<1>(10, 10);
        lane.refused.events_full = usize::MAX;
        lane.refused.total = usize::MAX;
        admit(&mut lane, 1, 1).unwrap();
        assert_eq!(lane.reserve(1).unwrap_err(), Refusal::EventsFull);
        assert_eq!(lane.stats().refused.events_full, usize::MAX);
        assert_eq!(lane.stats().refused.total, usize::MAX);
    }

    #[test]
    fn a_refusal_is_answered_by_how_the_sample_was_sent() {
        assert_eq!(Overload::of(Reliability::BestEffort), Overload::Drop);
        assert_eq!(
            Overload::of(Reliability::Reliable),
            Overload::LocalResourceLimit
        );
    }

    /// The lane against a model, over many interleavings of the producer's and the consumer's
    /// steps: whatever the order, the bytes of two live samples never overlap, the charges add up
    /// to what the counters say, and the samples that are delivered are the published ones, in the
    /// order they were reserved.
    #[test]
    fn whatever_the_interleaving_the_lane_keeps_its_bytes_apart_and_its_order() {
        use std::collections::VecDeque;
        use std::vec::Vec;

        const EVENTS: usize = 5;
        const BYTES: usize = 24;
        const BUDGET: usize = 6;

        for seed in 1u32..=400 {
            let mut state = seed.wrapping_mul(2_246_822_519).max(1);
            let mut rng = move || {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state
            };
            let mut lane = DeliveryLane::<EVENTS>::new(BYTES, BUDGET);
            let mut area = [0u8; BYTES];
            // Reservations the producer holds, with the id written into their bytes.
            let mut held: Vec<(Reservation, u8)> = Vec::new();
            // Ids of the samples admitted into the lane, in reservation order, with whether each
            // will be delivered (published with callbacks, not refused).
            let mut order: VecDeque<(u8, Option<usize>)> = VecDeque::new();
            let mut next_id = 1u8;
            let mut stopped_asked = false;

            for _ in 0..200 {
                match rng() % 6 {
                    0 | 1 => {
                        let bytes = (rng() % 9) as usize;
                        if let Ok(r) = lane.reserve(bytes) {
                            let id = next_id;
                            next_id = next_id.wrapping_add(1).max(1);
                            area[r.offset()..r.offset() + r.bytes()].fill(id);
                            order.push_back((id, None));
                            held.push((r, id));
                        }
                    }
                    2 | 3 if !held.is_empty() => {
                        let at = (rng() as usize) % held.len();
                        let (r, id) = held.remove(at);
                        let callbacks = (rng() % (BUDGET as u32 + 3)) as usize;
                        let slot = order.iter_mut().find(|(i, _)| *i == id).unwrap();
                        match lane.publish(r, callbacks) {
                            Ok(()) if callbacks > 0 => slot.1 = Some(callbacks),
                            _ => {}
                        }
                    }
                    4 if !held.is_empty() && rng() % 4 == 0 => {
                        let at = (rng() as usize) % held.len();
                        let (r, _) = held.remove(at);
                        lane.cancel(r);
                    }
                    5 => {
                        // The consumer takes whatever is ready.
                        while let Next::Ready(delivery) = lane.front() {
                            // The head of the model is the oldest admitted sample that is not
                            // skipped, and it is the one delivered.
                            let (id, owed) = loop {
                                let front = order.pop_front().expect("the model has it");
                                if front.1.is_some() {
                                    break front;
                                }
                                assert!(
                                    !held.iter().any(|(_, held_id)| *held_id == front.0),
                                    "a skipped sample is passed only once published or cancelled"
                                );
                            };
                            assert_eq!(Some(delivery.callbacks), owed);
                            assert!(
                                area[delivery.offset..delivery.offset + delivery.bytes]
                                    .iter()
                                    .all(|byte| *byte == id),
                                "seed {seed}: another sample was written over this one"
                            );
                            assert!(lane.complete());
                        }
                    }
                    _ => {}
                }
                if !stopped_asked && rng() % 97 == 0 {
                    lane.stop();
                    stopped_asked = true;
                }
                check(&lane, seed);
            }
        }
    }

    /// What must hold whatever was done to the lane.
    fn check<const E: usize>(lane: &DeliveryLane<E>, seed: u32) {
        let mut charged = 0usize;
        let mut callbacks = 0usize;
        let mut reserved = 0usize;
        let mut live: std::vec::Vec<(usize, usize)> = std::vec::Vec::new();
        for place in 0..lane.len {
            let entry = lane.entries[advance(lane.head, place, E)];
            assert_ne!(
                entry.phase,
                Phase::Free,
                "seed {seed}: a free slot inside the lane"
            );
            charged += entry.charge;
            if entry.phase == Phase::Ready {
                callbacks += entry.callbacks;
            }
            if entry.phase == Phase::Reserved {
                reserved += 1;
            }
            if entry.bytes != 0 {
                assert!(
                    entry.offset + entry.bytes <= lane.byte_capacity,
                    "seed {seed}: a sample runs past the end of the area"
                );
                live.push((entry.offset, entry.offset + entry.bytes));
            }
        }
        assert_eq!(charged, lane.byte_used, "seed {seed}: the charges add up");
        assert!(lane.byte_used <= lane.byte_capacity, "seed {seed}");
        assert_eq!(callbacks, lane.pending_callbacks, "seed {seed}");
        assert_eq!(reserved, lane.reserved, "seed {seed}");
        live.sort_unstable();
        for pair in live.windows(2) {
            assert!(
                pair[0].1 <= pair[1].0,
                "seed {seed}: two live samples overlap"
            );
        }
    }
}
