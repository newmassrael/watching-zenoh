// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The delivery of a peer's reply to the get it answers, in a session whose read steps its one
//! link itself (`direct`).
//!
//! The Response is read into its reply under the session's lock, where its frame lies (or into its
//! owned projection, for one the lent form does not represent); the face's legs find the get its
//! id names in one look, and the tables admit it to that get's row (its standing, its gate, its
//! consolidation), beginning a call of the get's callback for a reply they let through. The lock
//! is let go of, the call is made, and ended with no lock held. A leg's request id names one leg
//! of one face, so a reply reaches one get at most.
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
#[cfg(feature = "liveliness-get")]
use wz_session_core::wireexpr_resolve::{KeyexprOut, KeyexprRow};

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
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
                lent = unsafe { reply_past_the_read(reply, record) };
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

    /// Hand `reply`, read under `held` for face `face`, to the get it answers: admitted to the
    /// get's row under the lock, and handed to its callback by the call that admission began once
    /// the lock is let go of.
    pub(super) fn hand_reply(
        &self,
        mut held: LiveCore<'_, L, C>,
        face: HeldFace,
        reply: &dyn ReplyView,
    ) {
        let call = held.0.session.registry.admit_reply(face, reply);
        drop(held);
        if let Some(call) = call {
            // A read a callback makes reads nothing, so no record is handed out inside the call.
            self.make_get_call(call, reply);
            #[cfg(test)]
            self.takes.pinned_replies.fetch_add(1, Ordering::Relaxed);
        }
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
        // Of the static policy whatever the build's profile: a token claimed after the open takes no
        // heap.
        let mut room = KeyexprRow::new_static();
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
    /// (`Self::hand_reply`): admitted to the snapshot's row under the lock, and handed to its
    /// callback by the call that admission began once the lock is let go of.
    #[cfg(feature = "liveliness-get")]
    pub(super) fn hand_token(
        &self,
        mut held: LiveCore<'_, L, C>,
        face: HeldFace,
        interest_id: u64,
        keyexpr: &str,
    ) {
        let reply = token_reply(interest_id, keyexpr);
        let call = held
            .0
            .session
            .registry
            .admit_token(face, interest_id, &reply);
        drop(held);
        if let Some(call) = call {
            self.make_get_call(call, &reply);
            #[cfg(test)]
            self.takes.pinned_replies.fetch_add(1, Ordering::Relaxed);
        }
    }
}
