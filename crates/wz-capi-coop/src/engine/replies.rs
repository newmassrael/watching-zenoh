// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The delivery of a peer's reply to the get it answers, in a session whose read steps its one
//! link itself (`direct`).
//!
//! The Response is read into its reply under the session's lock, where its frame lies (or into its
//! owned projection, for one the lent form does not represent), and handed to the face's pending
//! gets as the face's dispatch hands it, with the get plane capturing the leg it reaches: the
//! leg's callback, with a count of its row, and nothing of the reply in the round. The lock is let
//! go of, the reply is handed to the callback, and the count is given back with no lock held. A
//! get's request id is the session's own, given to no other get, so a reply reaches one leg at
//! most.
//!
//! The reply's key is the frame's, a text of the face's peer, or this walk's own room's. The peer
//! is written only by the dispatch of the face's records, which the read makes one at a time and
//! which waits for this delivery; a read from a callback reads nothing; and the frame is the
//! pump's, which the read holds through the delivery (`pinned`).

use super::*;

#[cfg(feature = "liveliness-get")]
use wz_session_core::declare::liveliness_get::token_reply;
use wz_session_core::driver_loop::{InPlaceRecord, OwedToProjection};
use wz_session_core::reply::{InboundReply, LentReply, ReplyRoom};
use wz_session_core::reply_sink::ReplyView;
#[cfg(feature = "liveliness-get")]
use wz_session_core::wireexpr_resolve::{KeyexprBuf, KeyexprOut};

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
    /// Hand the reply of the Response `record` of face `face` lends to the get it answers, with
    /// the session let go of: the reply over the frame, or, for a Response the lent form does not
    /// represent, its owned projection. A reply the get's consolidation holds, or that reaches no
    /// get, is handed to none here. A closed session hands nothing.
    pub(super) fn hand_lent_reply(&self, face: HeldFace, record: &InPlaceRecord<'_, '_>) {
        let mut room = ReplyRoom::default();
        let lent: LentReply<'_, '_>;
        let owned: InboundReply;
        let Some(mut held) = self.live() else {
            return;
        };
        let read = held.0.session.registry.lend_reply(face, record, &mut room);
        let reply: &dyn ReplyView = match read {
            // SAFETY: what the reply borrows outlives its delivery below: the frame is lent by
            // the pump the read holds through it, `room` stays in this frame, and the face's peer
            // is neither written nor let go of while it runs (see the module's docs).
            Ok(Some(reply)) => {
                lent = unsafe { past_the_lock(reply, record) };
                &lent
            }
            Ok(None) => return,
            Err(OwedToProjection) => match held.0.session.registry.project_reply(face, record) {
                Some(projected) => {
                    owned = projected;
                    &owned
                }
                None => return,
            },
        };
        self.hand_reply(held, face, reply);
    }

    /// Hand `reply`, read under `held` for face `face`, to the get it answers: the pending gets
    /// are handed it under the lock with the get plane capturing the leg it reaches, and the leg's
    /// callback is called once the lock is let go of, its count given back after.
    pub(super) fn hand_reply(
        &self,
        mut held: LiveCore<'_, L, C>,
        face: HeldFace,
        reply: &dyn ReplyView,
    ) {
        self.gets.capture();
        held.0.session.registry.fire_reply(face, reply);
        self.hand_captured(held, reply);
    }

    /// Hand the alive token the Declare `record` of face `face` lends to the liveliness get it
    /// answers, with the session let go of, as a peer's reply is handed (`Self::hand_reply`). The
    /// session, still held, for a record that answers no pending get, which the caller dispatches
    /// as any other; nothing for one handed, and in a closed session.
    #[cfg(feature = "liveliness-get")]
    pub(super) fn hand_lent_token(
        &self,
        face: HeldFace,
        record: &InPlaceRecord<'_, '_>,
    ) -> Option<LiveCore<'_, L, C>> {
        let mut room = KeyexprBuf::new();
        let mut held = self.live()?;
        let Some(interest_id) = held
            .0
            .session
            .registry
            .claim_lent_token(face, record, &mut room)
        else {
            return Some(held);
        };
        self.hand_token(held, face, interest_id, KeyexprOut::as_str(&room));
        None
    }

    /// Hand the alive token at `keyexpr`, claimed under `held` for the pending liveliness get
    /// `interest_id` of face `face`, to that get, as a peer's reply is handed
    /// (`Self::hand_reply`).
    #[cfg(feature = "liveliness-get")]
    pub(super) fn hand_token(
        &self,
        mut held: LiveCore<'_, L, C>,
        face: HeldFace,
        interest_id: u64,
        keyexpr: &str,
    ) {
        self.gets.capture();
        held.0
            .session
            .registry
            .fire_token(face, interest_id, keyexpr);
        self.hand_captured(held, &token_reply(interest_id, keyexpr));
    }

    /// Let go of `held`, then hand `reply` to the callback of the leg the answers fired since
    /// the get plane began capturing reached, its count given back after. A leg none reached is
    /// handed nothing.
    fn hand_captured(&self, held: LiveCore<'_, L, C>, reply: &dyn ReplyView) {
        let reached = self.gets.captured();
        drop(held);
        let Some(leg) = reached else {
            return;
        };
        // A read a callback makes reads nothing, so no record is handed out inside the call.
        self.deliveries.within(|_| self.gets.call(leg, reply));
        drop(self.gets.release(leg));
        #[cfg(test)]
        self.takes.pinned_replies.fetch_add(1, Ordering::Relaxed);
    }
}

/// `reply`, read under the session's lock, held past it for as long as the read lends `_frame`.
///
/// # Safety
///
/// Nothing the reply borrows is written or let go of while the result is held.
unsafe fn past_the_lock<'r, 'f>(
    reply: LentReply<'_, 'f>,
    _frame: &'r InPlaceRecord<'_, 'f>,
) -> LentReply<'r, 'f> {
    // SAFETY: the two types differ in one lifetime alone, so they are laid out alike; what the
    // result borrows is the caller's to keep where it lies.
    unsafe { core::mem::transmute::<LentReply<'_, 'f>, LentReply<'r, 'f>>(reply) }
}
