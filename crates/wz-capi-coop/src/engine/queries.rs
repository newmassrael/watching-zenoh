// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The delivery of a peer's query to the session's queryables one at a time, in a session whose
//! read steps its one link itself (`direct`): a Request read where its frame lies.
//!
//! The query is read off its Request under the session's lock into the read's own frame
//! (`PinnedQuery`): its key copied out of the peer's tables, every other part where the frame
//! lies, which the pump holds through the read. The first queryable it reaches is pinned there: a
//! hold taken on its Final and a call begun on its row. The lock is let go of, the query is handed
//! to the callback, whose replies go out on the query's link as it makes them, and the call is
//! ended with no lock held; the next row is pinned under the lock again, from the place after the
//! last, so a callback finds the session free and what the queryables before its own did. With no
//! row left the query owes its Final, which waits for any hold a callback kept. Nothing of the
//! query is held in the round.

use super::*;

use wz_session_core::driver_loop::{InPlaceRecord, IterationEvent, OwedToProjection};
use wz_session_core::query::pinned::PinnedQuery;
use wz_session_core::wireexpr_resolve::KeyexprBuf;

use super::direct::FaceRecords;
use super::query::QueryableCall;

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
    /// Hand the query of the Request `record`, the record `event` of the face `records` reads,
    /// to each queryable it reaches, one call at a time with the session let go of, then owe its
    /// Final. A Request no queryable is handed (no Query, its key unresolved, past the bounds or
    /// the Finals the face holds) sends what its dispatch owes. The session, still held, for a
    /// Request the lent form does not represent, which the caller dispatches as any other record;
    /// nothing otherwise, and in a closed session.
    pub(super) fn hand_lent_query(
        &self,
        records: &FaceRecords<C>,
        record: &InPlaceRecord<'_, '_>,
        event: &IterationEvent<'_, '_>,
    ) -> Option<LiveCore<'_, L, C>> {
        let mut room = KeyexprBuf::new();
        let mut held = self.live()?;
        let pinned = held
            .0
            .session
            .registry
            .pin_lent_query(records.face, record, &mut room);
        if let Err(OwedToProjection) = pinned {
            return Some(held);
        }
        records.note_requests(event);
        match pinned {
            Ok(Some(mut query)) => self.hand_query(held, records, &mut query),
            _ => records.owe_finals(&mut held.0.session.registry),
        }
        None
    }

    /// Hand `query`, read under `held` for the face `records` reads, to each queryable it
    /// reaches, one call at a time with the session let go of: each callback's replies go out as
    /// it makes them and its hold on the Final is let go of after it (`run_queryable`). Then the
    /// query owes its Final, sent at once unless a callback keeps the query.
    fn hand_query(
        &self,
        held: LiveCore<'_, L, C>,
        records: &FaceRecords<C>,
        query: &mut PinnedQuery<'_>,
    ) {
        let generation = records.generation;
        let mut next = self.pin_queryable(&held, query, generation);
        drop(held);
        // A read a callback makes reads nothing, so no record is handed out inside another's call.
        self.deliveries.within(|_| {
            while let Some(call) = next.take() {
                query.hand(|view| self.run_queryable(&call, view, generation));
                #[cfg(test)]
                self.takes.pinned_queries.fetch_add(1, Ordering::Relaxed);
                if call.end() {
                    self.let_go_of_drained(|tables, cursor| {
                        tables
                            .release_drained_queryable(cursor)
                            .map(|row| row.into_callback())
                    });
                }
                next = self
                    .live()
                    .and_then(|held| self.pin_queryable(&held, query, generation));
            }
        });
        // A session closed by a callback sends nothing more.
        if let Some(_held) = self.live() {
            records.owe_final(query.rid(), query.qos());
        }
    }

    /// The next queryable `query` reaches under `held`, with a hold taken on the query's Final
    /// and a call begun on its row (`QueryPlane::admit_call`). A row the query is refused at, for
    /// want of a row for its Final, and one past the most calls its latch counts are passed.
    fn pin_queryable(
        &self,
        held: &LiveCore<'_, L, C>,
        query: &mut PinnedQuery<'_>,
        generation: u64,
    ) -> Option<QueryableCall> {
        let tables = tables(&held.0.session.registry);
        let rid = query.rid();
        while let Some(row) = tables.next_queryable_reached(query) {
            if let Some(call) = self
                .plane
                .admit_call(generation, rid, || QueryableCall::begin(row))
            {
                return Some(call);
            }
        }
        None
    }
}
