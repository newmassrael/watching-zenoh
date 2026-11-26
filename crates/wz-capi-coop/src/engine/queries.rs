// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The delivery of a peer's query to the session's queryables one at a time, in a session whose
//! read steps its one link itself (`direct`): a Request read where its frame lies.
//!
//! The query is read off its Request under the session's lock into the read's own frame
//! (`PinnedQuery`), nothing of it copied: its key is the frame's, the face's peer's literal, or
//! composed in a buffer of this frame where an alias and a suffix join, and every other part lies
//! in the frame, which the pump holds through the read. The peer and its buffer are written only
//! by the dispatch of the face's records, which the read makes one at a time and which waits for
//! this walk; a read from a callback reads nothing; and the face's tables are given back only when
//! the face is taken out, which a session of its dial face alone never does, a close from a
//! callback included. The first queryable it reaches is pinned there: a
//! hold taken on its Final and a call begun on its row. The lock is let go of, the query is handed
//! to the callback, whose replies are held on the query's link until its Final leaves with them,
//! and the call is ended with no lock held; the next row is pinned under the lock again, from the place after the
//! last, so a callback finds the session free and what the queryables before its own did. With no
//! row left the query owes its Final, which waits for any hold a callback kept. Nothing of the
//! query is held in the round.
//!
//! A Request the copying receive decoded is walked the same way, read off the owned record of the
//! frame (`QueryPeer::pin_request`), and so is one the lent form does not represent, read off its
//! owned projection: what the record does not hold itself lies in a room of the walk's frame. No
//! query of the frame then reaches the queries' plane of its dispatch: the walk owes the Final of
//! one no queryable answers as of one some did.

use super::*;

use wz_session_core::driver_loop::{InPlaceRecord, IterationEvent, OwedToProjection};
use wz_session_core::query::pinned::{PinnedQuery, QueryRoom};
use wz_session_core::wireexpr_resolve::KeyexprBuf;

use super::direct::{FaceRecords, RecordActions};
use super::query::QueryableCall;

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
    /// Hand the query of the Request `record`, the record `event` of the face `records` reads,
    /// to each queryable it reaches, one call at a time with the session let go of, then owe its
    /// Final; a Request the lent form does not represent by its owned projection. A Request no
    /// queryable is handed (no Query, its key unresolved, past the bounds or the Finals the face
    /// holds) sends what its dispatch owes. A closed session hands nothing.
    pub(super) fn hand_lent_query<A: RecordActions>(
        &self,
        records: &FaceRecords<A>,
        record: &InPlaceRecord<'_, '_>,
        event: &IterationEvent<'_, '_>,
    ) {
        let mut room = KeyexprBuf::new();
        let Some(mut held) = self.live() else {
            return;
        };
        records.note_requests(event);
        let pinned = held
            .0
            .session
            .registry
            .pin_lent_query(records.face, record, &mut room);
        let mut query = match pinned {
            // SAFETY: what the query borrows outlives the walk, which holds it no longer than this
            // call: the frame is lent by the pump the read holds through it, `room` stays in this
            // frame, and the face's peer and its buffer are neither written nor let go of while it
            // runs (see the module's docs).
            Ok(Some(query)) => unsafe { past_the_lock(query, record) },
            Ok(None) => {
                records.owe_finals(&mut held.0.session.registry);
                return;
            }
            Err(OwedToProjection) => {
                self.hand_projected_query(held, records, record);
                return;
            }
        };
        self.hand_query(held, records, &mut query);
    }

    /// [`Self::hand_lent_query`] for a Request the lent form does not represent: its owned
    /// projection, read under `held`, handed as one the copying receive decoded. Out of line, so
    /// the lent walk's frame does not hold the projection's.
    #[inline(never)]
    fn hand_projected_query<A: RecordActions>(
        &self,
        held: LiveCore<'_, L, C>,
        records: &FaceRecords<A>,
        record: &InPlaceRecord<'_, '_>,
    ) {
        if let Some(request) = wz_session_core::query::pinned::project_request(record) {
            self.hand_owned_query(held, records, &request);
        }
    }

    /// Hand the query of `request`, a Request of the face `records` reads that the copying
    /// receive decoded or the owned projection of a lent one, read under `held`, to each queryable
    /// it reaches, one call at a time with the session let go of, then owe its Final. A Request
    /// no queryable is handed sends what its dispatch owes. Out of line, so the room the query's
    /// parts lie in is in a frame of its own.
    #[inline(never)]
    pub(super) fn hand_owned_query<A: RecordActions>(
        &self,
        mut held: LiveCore<'_, L, C>,
        records: &FaceRecords<A>,
        request: &wz_session_core::wire::RequestOwned,
    ) {
        let mut room = QueryRoom::default();
        let pinned = held
            .0
            .session
            .registry
            .pin_owned_query(records.face, request, &mut room);
        let Some(query) = pinned else {
            records.owe_finals(&mut held.0.session.registry);
            return;
        };
        // SAFETY: what the query borrows outlives the walk, which holds it no longer than this
        // call: `request` is the caller's, `room` stays in this frame, and the face's peer and
        // its buffer are neither written nor let go of while it runs (see the module's docs).
        let mut query = unsafe { past_the_lock(query, request) };
        self.hand_query(held, records, &mut query);
    }

    /// Hand `query`, read under `held` for the face `records` reads, to each queryable it
    /// reaches, one call at a time with the session let go of: each callback's replies are held
    /// in the face's open frame and its hold on the Final is let go of after it (`run_queryable`).
    /// Then the query owes its Final, sent at once unless a callback keeps the query, and what
    /// was held leaves with it.
    fn hand_query<A: RecordActions>(
        &self,
        held: LiveCore<'_, L, C>,
        records: &FaceRecords<A>,
        query: &mut PinnedQuery<'_>,
    ) {
        let generation = records.generation;
        let mut next = self.pin_queryable(&held, query, generation);
        drop(held);
        // The callbacks' replies wait in the face's open frame for the Final, and the two leave
        // in one send once it is owed. No window is open meanwhile: what else is sent, on this
        // thread or another, goes at once.
        let replies =
            wz_session_core::response_sink::ResponseSink::hold_replies(records.actions.sink());
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
        wz_session_core::response_sink::ResponseSink::release_replies(
            records.actions.sink(),
            replies,
        );
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

/// `query`, read under the session's lock, held past it for as long as `_record`, the record it
/// was read off, is lent.
///
/// # Safety
///
/// Nothing the query borrows is written or let go of while the result is held.
unsafe fn past_the_lock<'r, R: ?Sized>(query: PinnedQuery<'_>, _record: &'r R) -> PinnedQuery<'r> {
    // SAFETY: the two types differ in their lifetime alone, so they are laid out alike; what the
    // result borrows is the caller's to keep where it lies.
    unsafe { core::mem::transmute::<PinnedQuery<'_>, PinnedQuery<'r>>(query) }
}
