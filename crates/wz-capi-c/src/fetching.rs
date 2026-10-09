// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The merge a zenoh-ext fetching subscriber makes between the replies of its
//! queries and the live samples that arrive while a query is outstanding.
//!
//! Read off zenoh-ext `querying_subscriber.rs` @ `MergeQueue`, `InnerState`,
//! `RepliesHandler` and `register_handler`, not guessed:
//!
//! - a count of queries in flight (`pending_fetches`) is raised BEFORE the live
//!   subscriber is declared and before each later query is issued, and lowered when
//!   the query's reply handler is dropped, which is when the query has ended;
//! - a live sample with no query in flight goes straight to the callback; with one
//!   in flight it is parked, and a sample with no timestamp is given one first (the
//!   moment it arrived, and this session's id), so it always sorts after any
//!   timestamped reply;
//! - EVERY reply is parked too, none is delivered on arrival;
//! - when the count falls to zero the parked samples are delivered: those without
//!   a timestamp first in the order they came, then the rest by timestamp, and a
//!   timestamp that is already parked is not parked twice (the first sample to
//!   carry it stays).
//!
//! So the callback sees nothing while a query is outstanding, and then each
//! distinct instant once, oldest first. The delivery runs with the lock held, as
//! upstream's does: it is what keeps a live sample that arrives mid-delivery from
//! overtaking the samples being delivered, and it makes a callback that issues
//! another query deadlock in both.

use std::collections::{BTreeMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::abi::z_loaned_sample_t;
use crate::sample::EscapedSample;
use crate::sub::CClosure;
use crate::timestamp::z_timestamp_t;

/// A timestamp as zenoh orders them: by time, then by the id of the node that
/// stamped it, read as the number its little-endian bytes spell.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Instant {
    time: u64,
    id: u128,
}

impl Instant {
    fn of(timestamp: &z_timestamp_t) -> Self {
        Self {
            time: timestamp._time,
            id: u128::from_le_bytes(timestamp._id),
        }
    }
}

/// Parked items in the order they are delivered. A port of zenoh-ext's
/// `MergeQueue`, generic over the item so its ordering is tested without a
/// sample in hand.
pub(crate) struct MergeQueue<T> {
    untimestamped: VecDeque<T>,
    timestamped: BTreeMap<Instant, T>,
}

impl<T> MergeQueue<T> {
    pub(crate) fn new() -> Self {
        Self {
            untimestamped: VecDeque::new(),
            timestamped: BTreeMap::new(),
        }
    }

    /// How many samples are parked. Upstream reads it for a log line; here only the
    /// tests do.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.untimestamped.len() + self.timestamped.len()
    }

    /// Park `item`. An instant that is already parked keeps the item that came
    /// first (`entry(ts).or_insert`), and the later one is dropped.
    pub(crate) fn push(&mut self, instant: Option<Instant>, item: T) {
        match instant {
            Some(at) => {
                self.timestamped.entry(at).or_insert(item);
            }
            None => self.untimestamped.push_back(item),
        }
    }

    /// Everything parked, in delivery order, leaving the queue empty.
    pub(crate) fn drain(&mut self) -> impl Iterator<Item = T> {
        std::mem::take(&mut self.untimestamped)
            .into_iter()
            .chain(std::mem::take(&mut self.timestamped).into_values())
    }
}

struct State {
    pending: u64,
    queue: MergeQueue<EscapedSample>,
}

/// One querying subscriber's merge, shared by its live subscription and by every
/// query it issues.
pub(crate) struct Fetching {
    user: CClosure,
    /// This session's id, the node a parked live sample is stamped as.
    zid: [u8; 16],
    state: Mutex<State>,
}

impl Fetching {
    pub(crate) fn new(user: CClosure, zid: [u8; 16]) -> Self {
        Self {
            user,
            zid,
            state: Mutex::new(State {
                pending: 0,
                queue: MergeQueue::new(),
            }),
        }
    }

    /// A query is about to be issued: from here a live sample waits for it.
    /// `end_fetch` must follow once, however the query ends.
    pub(crate) fn begin_fetch(&self) {
        self.lock().pending += 1;
    }

    /// A query has ended. The last one out delivers what was parked.
    pub(crate) fn end_fetch(&self) {
        let mut state = self.lock();
        state.pending = state.pending.saturating_sub(1);
        if state.pending == 0 {
            for sample in state.queue.drain() {
                self.deliver(sample.as_loaned());
            }
        }
    }

    /// A live sample.
    ///
    /// # Safety
    /// `sample` must be null or a pointer this crate handed to a sample callback.
    pub(crate) unsafe fn live(&self, sample: *const z_loaned_sample_t) {
        let mut state = self.lock();
        if state.pending == 0 {
            self.deliver(sample);
            return;
        }
        // SAFETY: the caller's contract.
        let Some(mut copy) = (unsafe { EscapedSample::copy_of(sample) }) else {
            return;
        };
        if copy.timestamp().is_none() {
            copy.stamp(self.arrival_stamp());
        }
        let instant = copy.timestamp().as_ref().map(Instant::of);
        state.queue.push(instant, copy);
    }

    /// One OK reply's sample. It is parked whatever the count, as upstream parks it.
    ///
    /// # Safety
    /// `sample` must be null or a pointer this crate handed to a sample callback.
    pub(crate) unsafe fn reply(&self, sample: *const z_loaned_sample_t) {
        let mut state = self.lock();
        // SAFETY: the caller's contract.
        let Some(copy) = (unsafe { EscapedSample::copy_of(sample) }) else {
            return;
        };
        let instant = copy.timestamp().as_ref().map(Instant::of);
        state.queue.push(instant, copy);
    }

    fn deliver(&self, sample: *const z_loaned_sample_t) {
        let Some(call) = self.user.call else {
            return;
        };
        let context = self.user.context.0;
        // SAFETY: the C callback owns the call; a panic unwinding across the
        // `extern "C"` boundary is UB, so it is caught as every callback
        // trampoline in this crate does.
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe { call(sample, context) }));
    }

    /// The stamp a live sample without one is parked under: now, as this session.
    fn arrival_stamp(&self) -> z_timestamp_t {
        z_timestamp_t {
            _time: ntp64_now(),
            _id: self.zid,
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic inside the user callback is caught, so a poisoned lock is not a
        // state worth refusing to read.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The wall clock as an NTP64 word, converted as uhlc's `From<Duration>` does:
/// whole seconds in the high half, the nanoseconds scaled into the fraction.
fn ntp64_now() -> u64 {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let fraction = (u64::from(since.subsec_nanos()) * (1 << 32)) / 1_000_000_000;
    (since.as_secs() << 32) + fraction
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(time: u64, id: u128) -> Option<Instant> {
        Some(Instant { time, id })
    }

    fn drained(queue: &mut MergeQueue<&'static str>) -> Vec<&'static str> {
        queue.drain().collect()
    }

    #[test]
    fn delivery_is_by_timestamp_whatever_the_arrival_order() {
        let mut q = MergeQueue::new();
        q.push(at(30, 1), "c");
        q.push(at(10, 1), "a");
        q.push(at(20, 1), "b");
        assert_eq!(q.len(), 3);
        assert_eq!(drained(&mut q), ["a", "b", "c"]);
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn a_sample_without_a_timestamp_goes_first_and_in_arrival_order() {
        let mut q = MergeQueue::new();
        q.push(at(10, 1), "stamped");
        q.push(None, "u1");
        q.push(at(5, 1), "older");
        q.push(None, "u2");
        assert_eq!(drained(&mut q), ["u1", "u2", "older", "stamped"]);
    }

    #[test]
    fn an_instant_already_parked_keeps_its_first_sample() {
        let mut q = MergeQueue::new();
        q.push(at(10, 1), "first");
        q.push(at(10, 1), "second");
        assert_eq!(q.len(), 1);
        assert_eq!(drained(&mut q), ["first"]);
    }

    #[test]
    fn the_same_time_from_two_nodes_is_two_instants_ordered_by_the_id() {
        let mut q = MergeQueue::new();
        q.push(at(10, 9), "from-nine");
        q.push(at(10, 2), "from-two");
        assert_eq!(drained(&mut q), ["from-two", "from-nine"]);
    }

    #[test]
    fn the_id_is_the_number_its_little_endian_bytes_spell() {
        let mut low = [0u8; 16];
        low[0] = 1;
        let mut high = [0u8; 16];
        high[15] = 1;
        let low_ts = z_timestamp_t { _time: 5, _id: low };
        let high_ts = z_timestamp_t {
            _time: 5,
            _id: high,
        };
        // Byte 0 is the least significant, so `high` is the larger number even
        // though it sorts first if the bytes were compared as a string.
        assert!(Instant::of(&low_ts) < Instant::of(&high_ts));
    }

    #[test]
    fn a_drained_queue_takes_new_samples() {
        let mut q = MergeQueue::new();
        q.push(at(1, 1), "a");
        assert_eq!(drained(&mut q), ["a"]);
        q.push(at(1, 1), "again");
        assert_eq!(drained(&mut q), ["again"]);
    }

    #[test]
    fn the_arrival_clock_is_a_plausible_ntp64_word() {
        let word = ntp64_now();
        let secs = word >> 32;
        // After 2020 and before the year 2106 the 32-bit seconds half runs out.
        assert!(secs > 1_577_836_800 && secs < u64::from(u32::MAX), "{secs}");
    }
}
