// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The tokens of the faces that went before each was retracted to the liveliness subscribers,
//! in the order the faces went: what a session that adds faces beside its dial role's
//! (`listen`, `group`) owes after a face it held is gone, in the two forms its tables take.
//!
//! - Lent at the open (`wz_lent`): each face's token table split off whole as the face goes,
//!   its rows still in the session's token pool, which bounds the tokens the faces hold and owe
//!   together; a row of this table for each row of the pool.
//! - On use (`wz_on_use`): a relation of tokens keyed by face and id
//!   (`wz_session_core::declare::liveliness_subscriber::OwedTokens`), each row one token and its
//!   key, counted for every token the faces that may go can hold together and taken at the first
//!   such face's admission. No pool bounds the faces' tokens there, so a face is admitted only
//!   while the relation's rows left hold the tokens of every face that may go
//!   ([`Owed::admits_face`]).
//!
//! Both are one relation of the session's token rows with the owing face as a column once every
//! peer declaration is such a relation over the face table; the on-use form's row
//! (`FaceToken`) is that relation's row.

use super::FaceId;
#[cfg(wz_on_use)]
use super::{names_face, DIAL_FACE};
#[cfg(wz_round)]
use super::{App, RoundDelivery};
#[cfg(wz_on_use)]
use crate::arena::FacePeers;
use crate::RowPolicy;
use wz_session_core::declare::liveliness_subscriber::PeerTokens;

#[cfg(wz_on_use)]
use crate::arena::MAX_FACE_SETS;
#[cfg(wz_lent)]
use wz_session_core::bounded::{BoundedVec, RowCount, SeqPlace};
#[cfg(wz_on_use)]
use wz_session_core::caps;
#[cfg(wz_on_use)]
use wz_session_core::declare::liveliness_subscriber::OwedTokens;
#[cfg(wz_on_use)]
use wz_session_core::limits::SessionLimits;

/// One face's tokens, as its peer's tables hold them.
type FaceTokens = PeerTokens<RowPolicy>;

/// The most tokens the faces that may go hold together on use: a face's table's bound for each
/// place a face other than the dial role's may take.
#[cfg(wz_on_use)]
const OWED_ROWS: usize = MAX_FACE_SETS.saturating_mul(caps::MAX_REMOTE_DECLS);

/// What the faces that went still owe the liveliness subscribers. See the module documentation.
#[cfg(wz_lent)]
pub(super) struct Owed(
    BoundedVec<FaceTokens, { wz_session_core::caps::SESSION_MAX_REMOTE_DECLS }, RowPolicy>,
);

/// See the lent form.
#[cfg(wz_on_use)]
pub(super) struct Owed(OwedTokens<OWED_ROWS>);

#[cfg(wz_lent)]
impl Owed {
    /// The table before the registry's walk lends it its rows (`RegistryOf::new`): of no row.
    pub(super) fn rowless() -> Self {
        Self(BoundedVec::default())
    }

    /// The line of the registry's description that places the table at `at`: a row for each row
    /// of the session's token pool (`RowCount::OwedTokens`, `FacePeers::owed_tokens`), as a table
    /// owed holds one of them at least, so the faces owing at once are never more; none for a
    /// session of one face, whose one face never goes.
    pub(super) const fn place(at: usize) -> SeqPlace {
        SeqPlace::of::<FaceTokens>(
            at.wrapping_add(core::mem::offset_of!(Self, 0)),
            0,
            wz_session_core::caps::SESSION_MAX_REMOTE_DECLS,
        )
        .counted(RowCount::OwedTokens)
    }

    /// Whether a face may be admitted beside those `holders` names: always, the session's token
    /// pool bounding what the faces hold and owe together.
    #[inline]
    pub(super) fn admits_face(&mut self, _holders: &[FaceId]) -> bool {
        true
    }

    /// Keep apart the tokens of `tokens`, the table of face `_face` as it goes, the table left
    /// empty and taking rows of the session's pool.
    pub(super) fn owe(&mut self, _face: FaceId, tokens: &mut FaceTokens) {
        if let Some(tokens) = tokens.split_off() {
            if tokens.count() > 0 {
                // A table owed holds a row of the session's token pool at least, and the open lent
                // a row of this table for each row of the pool.
                let kept = self.0.push(tokens).is_ok();
                debug_assert!(kept, "the tokens owed fit the rows of the pool they hold");
            }
        }
    }

    /// The next token owed, its row unbound and its `Delete` written into `news`: the faces'
    /// tables in the order they went, each in ascending id, a table let go of, its rows back in
    /// the pool, once its last is taken. Whether there was one.
    #[cfg(not(wz_round))]
    pub(super) fn take_lost(
        &mut self,
        news: &mut wz_session_core::declare::liveliness_subscriber::TokenNews,
    ) -> bool {
        while let Some(tokens) = self.0.first_mut() {
            if tokens.take_lost(news) {
                return true;
            }
            self.0.remove(0);
        }
        false
    }

    /// Retract what is owed to `app`'s liveliness subscribers through `delivery`, a token at a
    /// time while `room` says its `Delete` can be taken, in the order of `Self::take_lost`.
    /// Whether none is owed any more.
    #[cfg(wz_round)]
    pub(super) fn retract_while(
        &mut self,
        app: &mut App,
        delivery: &mut RoundDelivery,
        room: &mut dyn FnMut() -> bool,
    ) -> bool {
        while let Some(tokens) = self.0.first_mut() {
            if !app.flush_tokens_on_link_loss_while(delivery, tokens, room) {
                return false;
            }
            self.0.remove(0);
        }
        true
    }

    /// Whether nothing is owed.
    #[cfg(any(not(wz_round), test))]
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The faces' tables owed.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }

    /// Owe nothing any more, every table let go of.
    pub(super) fn clear(&mut self) {
        self.0.clear();
    }
}

#[cfg(wz_on_use)]
impl Owed {
    /// The relation of a session whose faces' tables `peers` counts, each face's tokens held to
    /// `limits`: a row for each token the faces other than the dial role's may hold together, none
    /// taken until the first of them is admitted.
    pub(super) fn counted(peers: &FacePeers, limits: &SessionLimits) -> Self {
        let per_face = limits
            .max_remote_decls()
            .most()
            .map_or(caps::MAX_REMOTE_DECLS, |most| {
                most.min(caps::MAX_REMOTE_DECLS)
            });
        Self(OwedTokens::counted(
            peers.sets().saturating_sub(1),
            per_face,
        ))
    }

    /// Whether a face may be admitted beside the faces `holders` names: the relation's rows left
    /// hold the tokens of every face held but the dial role's, which never goes, and of the new
    /// one, its rows taken now where they were not. A refusal is answered as a face past the
    /// session's faces is.
    pub(super) fn admits_face(&mut self, holders: &[FaceId]) -> bool {
        let may_go = holders
            .iter()
            .filter(|holder| names_face(**holder) && **holder != DIAL_FACE)
            .count();
        self.0.admits_face(may_go)
    }

    /// Owe the tokens of `tokens`, the table of face `face` as it goes, a row each, the table left
    /// holding none.
    pub(super) fn owe(&mut self, face: FaceId, tokens: &mut FaceTokens) {
        let kept = self.0.owe(face, tokens);
        debug_assert!(
            kept,
            "a face is admitted only while the rows of its tokens are left"
        );
    }

    /// The next token owed, taken out of the relation and its `Delete` written into `news`, in
    /// the order the faces went, each face's in ascending id. Whether there was one.
    #[cfg(not(wz_round))]
    pub(super) fn take_lost(
        &mut self,
        news: &mut wz_session_core::declare::liveliness_subscriber::TokenNews,
    ) -> bool {
        self.0.take_lost(news)
    }

    /// Retract what is owed to `app`'s liveliness subscribers through `delivery`, a token at a
    /// time while `room` says its `Delete` can be taken, in the relation's order. Whether none
    /// is owed any more.
    #[cfg(wz_round)]
    pub(super) fn retract_while(
        &mut self,
        app: &mut App,
        delivery: &mut RoundDelivery,
        room: &mut dyn FnMut() -> bool,
    ) -> bool {
        app.flush_tokens_on_link_loss_while(delivery, &mut self.0, room)
    }

    /// Whether nothing is owed.
    #[cfg(any(not(wz_round), test))]
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The tokens owed.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }

    /// Owe nothing any more, every key's bytes back in the session's budget.
    pub(super) fn clear(&mut self) {
        self.0.clear();
    }
}
