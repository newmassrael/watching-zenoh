// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A querier of the client node: a query asked on a key every period, for as long as a session is
//! established, whose latest reply the node keeps.
//!
//! What is here is what a querier IS and what is kept of it: the [`Query`] (a key, a period, how long
//! it may stay pending, how many bytes of a reply are kept), the [`QueryState`] the replies are
//! delivered to (the latest reply of each query goes to a cell of the node's
//! [`LatestSlots`], the same cells a subscription keeps its samples in, so a
//! queryable can answer from either; and the counts of what was asked and what came back), and the
//! watch the program's loop says the counts with ([`QueryWatch`]). The queries themselves are asked by
//! the session's application layer, inside its event, on the cadence of
//! [`crate::slot_schedule::Schedule`] (`crate::slot_active::Active`).
//!
//! # What a reply does
//!
//! A reply that carries data replaces the query's cell (its key, its payload cut at the query's size,
//! how long it was, and a count); a reply that is a delete replaces it with a delete; an error reply is
//! counted and keeps nothing. The end of a query is counted as a final, or as a timeout when the
//! deadline passed first.
//!
//! The pending table of a session holds a copy of the sink of each query not yet ended, so the sink
//! is two words (a reference to the state and the query's index) and the state is in a `static` of
//! the image's whose initial value is all zero bytes, so it is `.bss`.
//!
//! This module does not link `alloc`.

use core::cell::Cell;

use wz_session_core::reply_sink::{ReplyKind, ReplySink, ReplyView};
use wz_session_core::sample_kind::SampleKind;

use crate::latest::LatestSlots;
use crate::slot_schedule::Periodic;

/// One querier: the query it asks, how often, and how much of a reply it keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Query {
    /// The key expression it asks.
    pub key: &'static str,
    /// The time between two queries, in milliseconds (at least 1).
    pub period_ms: u32,
    /// How long a query may stay pending, in milliseconds.
    pub timeout_ms: u32,
    /// The bytes of a reply payload it keeps.
    pub reply_bytes: usize,
}

impl Query {
    /// A query that asks nothing, to fill an array with.
    pub const NONE: Self = Self {
        key: "",
        period_ms: 1,
        timeout_ms: 1,
        reply_bytes: 1,
    };
}

impl Periodic for Query {
    fn period_ms(&self) -> u32 {
        self.period_ms
    }
}

/// What came of the queries of one querier, as the loop reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tally {
    /// Queries that went out.
    pub asked: u32,
    /// Replies that carried data (or a delete).
    pub replied: u32,
    /// Error replies.
    pub errors: u32,
    /// Queries that ended with their final.
    pub finals: u32,
    /// Queries that ended at their deadline.
    pub timeouts: u32,
    /// Queries the wire could not carry.
    pub refused: u32,
}

/// Where the replies of a node's queries are delivered, by the index of the query.
pub trait ReplyTarget: Sync {
    /// A reply of query `query` arrived.
    fn reply(&self, query: usize, key: &str, payload: &[u8], kind: ReplyKind);

    /// Query `query` ended: with its final, or at its deadline.
    fn finished(&self, query: usize, timed_out: bool);
}

/// The sink of one query's replies: a reference to the node's [`QueryState`] and which query it is.
#[derive(Clone, Copy)]
pub struct ReplyLatest {
    target: &'static dyn ReplyTarget,
    query: usize,
}

impl ReplyLatest {
    /// The sink of query `query` of `target`.
    pub const fn new(target: &'static dyn ReplyTarget, query: usize) -> Self {
        Self { target, query }
    }
}

impl ReplySink for ReplyLatest {
    fn on_reply(&mut self, reply: &dyn ReplyView) {
        self.target
            .reply(self.query, reply.keyexpr(), reply.payload(), reply.kind());
    }

    fn on_final(&mut self, _rid: u64) {
        self.target.finished(self.query, false);
    }

    /// A deadline is one event here, a timeout, and not an error reply and then a final: a query
    /// that timed out is counted once.
    fn on_timeout(&mut self, _rid: u64) {
        self.target.finished(self.query, true);
    }
}

/// What a node's queries keep and count, for `Q` queries, in one `static`.
///
/// The cells replies are kept in are named once, when the node is set up ([`QueryState::attach`]):
/// the node's [`LatestSlots`] and the index of the first cell of the queries, so that a query's cell
/// is one after the subscriptions' in the same storage. Every initial value is zero, so the `static`
/// is `.bss`.
pub struct QueryState<const Q: usize> {
    cells: Cell<Option<&'static dyn LatestSlots>>,
    first_cell: Cell<usize>,
    capacity: [Cell<usize>; Q],
    asked: [Cell<u32>; Q],
    replied: [Cell<u32>; Q],
    errors: [Cell<u32>; Q],
    finals: [Cell<u32>; Q],
    timeouts: [Cell<u32>; Q],
    refused: [Cell<u32>; Q],
}

// SAFETY: the profile's rule: one thread drives the node, and the session's layer (which writes),
// the reply sinks (which write) and the program's loop (which reads) all run on it, never at the
// same moment.
unsafe impl<const Q: usize> Sync for QueryState<Q> {}

impl<const Q: usize> QueryState<Q> {
    /// Nothing attached, nothing counted; all zero bytes.
    pub const fn new() -> Self {
        Self {
            cells: Cell::new(None),
            first_cell: Cell::new(0),
            capacity: [const { Cell::new(0) }; Q],
            asked: [const { Cell::new(0) }; Q],
            replied: [const { Cell::new(0) }; Q],
            errors: [const { Cell::new(0) }; Q],
            finals: [const { Cell::new(0) }; Q],
            timeouts: [const { Cell::new(0) }; Q],
            refused: [const { Cell::new(0) }; Q],
        }
    }

    /// Name where replies are kept: query `i` keeps its latest reply in cell `first_cell + i` of
    /// `cells`, cut at `queries[i].reply_bytes`.
    pub fn attach(&self, cells: &'static dyn LatestSlots, first_cell: usize, queries: &[Query]) {
        self.cells.set(Some(cells));
        self.first_cell.set(first_cell);
        for (cell, query) in self.capacity.iter().zip(queries) {
            cell.set(query.reply_bytes);
        }
    }

    fn bump(cells: &[Cell<u32>; Q], at: usize) {
        if let Some(cell) = cells.get(at) {
            cell.set(cell.get().wrapping_add(1));
        }
    }

    /// Query `at` went out.
    pub fn record_asked(&self, at: usize) {
        Self::bump(&self.asked, at);
    }

    /// Query `at` could not be carried.
    pub fn record_refused(&self, at: usize) {
        Self::bump(&self.refused, at);
    }

    /// What came of query `at`.
    pub fn tally(&self, at: usize) -> Tally {
        let get = |cells: &[Cell<u32>; Q]| cells.get(at).map_or(0, Cell::get);
        Tally {
            asked: get(&self.asked),
            replied: get(&self.replied),
            errors: get(&self.errors),
            finals: get(&self.finals),
            timeouts: get(&self.timeouts),
            refused: get(&self.refused),
        }
    }
}

impl<const Q: usize> Default for QueryState<Q> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const Q: usize> ReplyTarget for QueryState<Q> {
    fn reply(&self, query: usize, key: &str, payload: &[u8], kind: ReplyKind) {
        let kept = match kind {
            ReplyKind::Put => SampleKind::Put,
            ReplyKind::Del => SampleKind::Del,
            ReplyKind::Err => {
                Self::bump(&self.errors, query);
                return;
            }
        };
        Self::bump(&self.replied, query);
        if let (Some(cells), Some(capacity)) = (self.cells.get(), self.capacity.get(query)) {
            cells.put(
                self.first_cell.get() + query,
                capacity.get(),
                key,
                payload,
                kept,
            );
        }
    }

    fn finished(&self, query: usize, timed_out: bool) {
        Self::bump(
            if timed_out {
                &self.timeouts
            } else {
                &self.finals
            },
            query,
        );
    }
}

/// What the program's loop remembers of the counts between two rounds, to say each change once.
///
/// A round that finds a query's counts moved calls `say` with the counts NOW, so queries that ended
/// between two rounds are one report with counts that jump.
pub struct QueryWatch<const Q: usize> {
    seen: [Tally; Q],
}

impl<const Q: usize> QueryWatch<Q> {
    /// A watch that has seen nothing.
    pub const fn new() -> Self {
        Self {
            seen: [Tally {
                asked: 0,
                replied: 0,
                errors: 0,
                finals: 0,
                timeouts: 0,
                refused: 0,
            }; Q],
        }
    }

    /// Call `say(index, tally)` for each query whose counts moved since the last call.
    pub fn poll(&mut self, state: &QueryState<Q>, mut say: impl FnMut(usize, Tally)) {
        for (at, seen) in self.seen.iter_mut().enumerate() {
            let now = state.tally(at);
            if now != *seen {
                *seen = now;
                say(at, now);
            }
        }
    }
}

impl<const Q: usize> Default for QueryWatch<Q> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::latest::LatestCells;
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use wz_session_core::reply_sink::BorrowedReply;

    fn query(reply_bytes: usize) -> Query {
        Query {
            key: "demo/q",
            period_ms: 100,
            timeout_ms: 500,
            reply_bytes,
        }
    }

    /// A state of two queries over cells whose first two are a subscription's, attached.
    fn state() -> (&'static QueryState<2>, &'static LatestCells<4, 8>) {
        let cells: &'static LatestCells<4, 8> = Box::leak(Box::new(LatestCells::new()));
        let state: &'static QueryState<2> = Box::leak(Box::new(QueryState::new()));
        state.attach(cells, 2, &[query(4), query(8)]);
        (state, cells)
    }

    fn reply<'a>(kind: ReplyKind, key: &'a str, payload: &'a [u8]) -> BorrowedReply<'a> {
        BorrowedReply {
            rid: 1,
            keyexpr: key,
            kind,
            payload,
            err_encoding: None,
            attachment: None,
            put_encoding: None,
        }
    }

    fn read(cells: &dyn LatestSlots, index: usize) -> Option<(Vec<u8>, usize, SampleKind, u32)> {
        let mut out = None;
        cells.with(index, &mut |latest| {
            out = latest.map(|l| (l.payload.to_vec(), l.received_len, l.kind, l.sequence));
        });
        out
    }

    #[test]
    fn a_reply_replaces_the_cell_of_its_query_after_the_subscriptions_and_counts() {
        let (state, cells) = state();
        let mut sink = ReplyLatest::new(state, 1);
        sink.on_reply(&reply(ReplyKind::Put, "demo/a", b"one"));
        sink.on_reply(&reply(ReplyKind::Put, "demo/a", b"two2"));
        assert_eq!(
            read(cells, 3),
            Some((b"two2".to_vec(), 4, SampleKind::Put, 2))
        );
        assert_eq!(read(cells, 2), None, "the other query's cell is untouched");
        assert_eq!(
            read(cells, 1),
            None,
            "a subscription's cell is not a query's"
        );
        assert_eq!(state.tally(1).replied, 2);
    }

    #[test]
    fn a_reply_is_cut_at_the_size_its_query_keeps_and_says_how_long_it_was() {
        let (state, cells) = state();
        ReplyLatest::new(state, 0).on_reply(&reply(ReplyKind::Put, "k", b"abcdefgh"));
        assert_eq!(
            read(cells, 2),
            Some((b"abcd".to_vec(), 8, SampleKind::Put, 1))
        );
    }

    #[test]
    fn an_error_reply_is_counted_and_keeps_nothing() {
        let (state, cells) = state();
        ReplyLatest::new(state, 0).on_reply(&reply(ReplyKind::Err, "k", b"boom"));
        assert_eq!(read(cells, 2), None);
        assert_eq!((state.tally(0).errors, state.tally(0).replied), (1, 0));
    }

    #[test]
    fn a_delete_reply_is_kept_as_a_delete() {
        let (state, cells) = state();
        let mut sink = ReplyLatest::new(state, 0);
        sink.on_reply(&reply(ReplyKind::Put, "k", b"x"));
        sink.on_reply(&reply(ReplyKind::Del, "k", b""));
        assert_eq!(read(cells, 2), Some((Vec::new(), 0, SampleKind::Del, 2)));
    }

    #[test]
    fn the_end_of_a_query_is_one_final_or_one_timeout() {
        let (state, _) = state();
        let mut sink = ReplyLatest::new(state, 0);
        sink.on_final(7);
        sink.on_timeout(8);
        let tally = state.tally(0);
        assert_eq!((tally.finals, tally.timeouts, tally.errors), (1, 1, 0));
    }

    #[test]
    fn the_counts_are_kept_by_query_and_an_index_outside_them_is_nothing() {
        let (state, _) = state();
        state.record_asked(1);
        state.record_asked(1);
        state.record_refused(0);
        state.record_asked(9);
        assert_eq!(state.tally(1).asked, 2);
        assert_eq!(state.tally(0).refused, 1);
        assert_eq!(state.tally(9), Tally::default());
        ReplyLatest::new(state, 9).on_final(1);
        assert_eq!(state.tally(9), Tally::default());
    }

    #[test]
    fn a_reply_to_a_state_nothing_was_attached_to_is_counted_and_kept_nowhere() {
        let state: &'static QueryState<1> = Box::leak(Box::new(QueryState::new()));
        ReplyLatest::new(state, 0).on_reply(&reply(ReplyKind::Put, "k", b"x"));
        assert_eq!(state.tally(0).replied, 1);
    }

    #[test]
    fn the_watch_says_a_change_once_with_the_counts_of_everything_since() {
        let (state, _) = state();
        let mut watch = QueryWatch::<2>::new();
        let mut said = Vec::new();
        watch.poll(state, |at, tally| said.push((at, tally)));
        assert!(said.is_empty(), "nothing happened");
        state.record_asked(1);
        ReplyLatest::new(state, 1).on_reply(&reply(ReplyKind::Put, "k", b"x"));
        ReplyLatest::new(state, 1).on_final(1);
        watch.poll(state, |at, tally| said.push((at, tally)));
        watch.poll(state, |at, tally| said.push((at, tally)));
        assert_eq!(
            said,
            [(
                1,
                Tally {
                    asked: 1,
                    replied: 1,
                    errors: 0,
                    finals: 1,
                    timeouts: 0,
                    refused: 0
                }
            )],
            "three events, one report"
        );
    }

    #[test]
    fn a_query_is_as_periodic_as_its_period() {
        assert_eq!(Periodic::period_ms(&query(1)), 100);
    }
}
