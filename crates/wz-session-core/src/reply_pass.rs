// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A reply handed on as its queryable makes it, held to the session's payload bound and to no
//! count: what a queryable answers through when its callback runs with no lock of the session
//! held.
//!
//! A stage ([`crate::reply_stage::ReplyStage`]) is for a dispatch that cannot send while it
//! holds the session's lock: it keeps what the queryables answer until the lock is let go, and
//! its rows (`MAX_PENDING_REPLIES`) bound how many replies one such dispatch can defer. A
//! callback that runs outside the lock has nothing to defer. zenoh-pico sends each reply at the
//! call (`vendor/zenoh-pico/src/net/primitives.c` @
//! `if (_z_send_n_msg(zn, &z_msg, Z_RELIABILITY_RELIABLE, Z_CONGESTION_CONTROL_BLOCK, NULL) != _Z_RES_OK) {`),
//! and a stage there would bound how many replies one query may have by the rows of a memory
//! that keeps none of them past the call: a queryable that answers one query with more replies
//! than the rows (a publisher's cache answering a history query) would be refused the rest.
//!
//! A pass refuses a reply only by its length, by the check a stage makes
//! ([`ReplyError::PayloadTooLarge`], counted), and never as full.

use crate::bounded::Profile;
use crate::query_sink::ReplyError;
use crate::reply_stage::{ReplyBounds, ReplyParts, ReplyRefusals, StagesReplies};

/// Where a responder's replies go when each is to leave as it is made: `pass` is handed every
/// reply the bounds admit, borrowed, at the call that made it, and keeps nothing of it past the
/// call unless it copies it.
pub struct ReplyPass<F> {
    /// The payload bound the session's creator stated (`MAX_REPLY_PAYLOAD_BYTES`); the count of
    /// replies it also carries bounds a stage and is not read here.
    bounds: ReplyBounds,
    refusals: ReplyRefusals,
    pass: F,
}

impl<F: FnMut(ReplyParts<'_>)> ReplyPass<F> {
    /// A pass that hands each reply within `bounds` to `pass`.
    pub fn new(bounds: ReplyBounds, pass: F) -> Self {
        Self {
            bounds,
            refusals: ReplyRefusals::default(),
            pass,
        }
    }

    /// What the pass refused since it was made: replies too long for the payload bound alone,
    /// since it has no rows to be full.
    pub fn refusals(&self) -> ReplyRefusals {
        self.refusals
    }
}

impl<F: FnMut(ReplyParts<'_>)> StagesReplies for ReplyPass<F> {
    fn stage_reply(&mut self, parts: ReplyParts<'_>) -> Result<(), ReplyError> {
        // Held as a stage of this build's profile holds a reply, so a reply is refused by its
        // length alike whichever of the two a responder is lent.
        if let Err(refused) = self.bounds.admit::<Profile>(&parts) {
            self.refusals.payload_too_large = self.refusals.payload_too_large.saturating_add(1);
            return Err(refused);
        }
        (self.pass)(parts);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps;
    use crate::limit_binding::{LimitSpec, Quota};
    use crate::limits::{MaxPendingReplies, MaxReplyPayloadBytes, SessionLimits};
    use crate::reply_stage::{PartsBody, PartsKind, ReplyStage, ReplyStaging};
    use crate::sample::QosLevel;
    use crate::wire_id::RequestId;

    /// A Put of `payload` on `"a/b"` answering `rid`.
    fn put(rid: RequestId, payload: &[u8]) -> ReplyParts<'_> {
        ReplyParts::new(
            rid,
            "a/b",
            None,
            QosLevel::DEFAULT,
            PartsKind::Reply {
                body: PartsBody::Put(payload),
                encoding: None,
                timestamp: None,
                attachment: None,
                source_info: None,
            },
        )
    }

    /// More replies than a stage has rows for, under the bounds of a session that states two rows
    /// where the build lets it: the pass hands on every one, in the order they were made, and
    /// refuses none, where a stage held to the same bounds refuses those past its rows.
    #[test]
    fn a_pass_hands_on_every_reply_however_few_rows_a_stage_holds() {
        let mut limits = SessionLimits::defaults();
        if !MaxPendingReplies::DOMAIN.is_singleton() {
            limits
                .select_max_pending_replies(Quota::at_most(2))
                .expect("two is inside the domain");
        }
        let bounds = ReplyBounds::of(&limits);
        let many = caps::MAX_PENDING_REPLIES + 8;

        let mut handed = 0usize;
        let mut pass = ReplyPass::new(bounds, |parts: ReplyParts<'_>| {
            assert_eq!(
                parts.rid as usize, handed,
                "handed on in the order they were made"
            );
            handed += 1;
        });
        for rid in 0..many as RequestId {
            assert_eq!(pass.stage_reply(put(rid, b"x")), Ok(()));
        }
        assert_eq!(pass.refusals(), ReplyRefusals::default());
        drop(pass);
        assert_eq!(handed, many, "every reply was handed on");

        let mut stage = ReplyStage::held_to(bounds);
        let refused = (0..many as RequestId)
            .filter(|&rid| stage.stage_parts(put(rid, b"x")).is_err())
            .count();
        let a_stage_is_held =
            crate::bounded::ENFORCES_CAPACITY || !limits.max_pending_replies().admits(many);
        assert_eq!(
            refused > 0,
            a_stage_is_held,
            "a stage under the same bounds refuses what its rows cannot hold"
        );
    }

    /// The payload bound holds a pass as it holds a stage: stated as two, a reply of three is
    /// refused to the responder and counted, and never handed on; a reply of two is.
    #[test]
    fn a_pass_refuses_a_payload_past_the_stated_bound_and_hands_none_of_it_on() {
        let mut limits = SessionLimits::defaults();
        let stated = limits.select_max_reply_payload_bytes(Quota::at_most(2));
        if MaxReplyPayloadBytes::DOMAIN.is_singleton() {
            assert!(stated.is_err(), "a build of one value refuses two");
            return;
        }
        stated.expect("two is inside the domain");

        let mut handed = 0usize;
        let mut pass = ReplyPass::new(ReplyBounds::of(&limits), |_parts: ReplyParts<'_>| {
            handed += 1;
        });
        assert_eq!(
            pass.stage_reply(put(1, b"abc")),
            Err(ReplyError::PayloadTooLarge)
        );
        assert_eq!(pass.stage_reply(put(2, b"ab")), Ok(()));
        assert_eq!(
            pass.refusals(),
            ReplyRefusals {
                staging_full: 0,
                payload_too_large: 1,
            }
        );
        drop(pass);
        assert_eq!(handed, 1, "only the reply within the bound was handed on");
    }
}
