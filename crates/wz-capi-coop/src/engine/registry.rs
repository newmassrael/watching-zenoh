// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the session's application layer holds, in the two parts a session that listens needs
//! apart (`docs/capi-pico-on-coop-engine.md`, section 7).
//!
//! - [`Registry::app`], what the application registered (its subscribers, queryables, local
//!   tokens, the listeners on what a peer declares), once for the session however many peers it
//!   comes to hold;
//! - one [`FaceTables`] for each face, what ONE peer wrote (its key aliases, its subscribers,
//!   queryables and tokens, its interests, the replies and Finals its queries are owed), which is
//!   scoped by that peer's transport session and so cannot be shared, and the session's own gets
//!   pending on that face, whose request ids the face's actions mint.
//!
//! The dial role's face is made with the registry and never removed: a link lost and dialled
//! again is the same face, whose tables were emptied when it was lost. An accepted face is added
//! when its link is, and removed with it. The observer this replaces (`ApplicationLayerObserver`)
//! held the application's part and one peer's together; the dispatch order and the rules are the
//! same, which the heap tests of `slot_observer` hold.

use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::peer_tables::PeerTables;
use wz_session_core::reply_sink::{BoxedReplySink, ConsolidatingSink};
#[cfg(feature = "queryable")]
use wz_session_core::reply_stage::FinalStage;
use wz_session_core::response_sink::{DeclareReplySink, LivelinessGetPrune, ResponseSink};
use wz_session_core::slot_observer::{Requesters, SlotObserver};

#[allow(unused_imports)]
use crate::prelude::*;

/// A face of the session, named for as long as the session holds it.
pub(super) type FaceId = u64;

/// The dial role's face, as `wz-capi-core`'s registry names it: accepted faces take the ids
/// beneath it.
pub(super) const DIAL_FACE: FaceId = 1 << 62;

/// The session's own pending gets on one face: a query's sink consolidates what its leg is
/// handed.
pub(super) type Gets = Requesters<ConsolidatingSink<BoxedReplySink>, BoxedReplySink>;

/// What the session holds for one face: what its peer wrote and what the session asked of it.
pub(super) struct FaceTables {
    pub(super) id: FaceId,
    pub(super) peer: PeerTables,
    pub(super) gets: Gets,
}

impl FaceTables {
    fn new(id: FaceId) -> Self {
        Self {
            id,
            peer: PeerTables::new(),
            gets: Gets::new(),
        }
    }
}

/// The application layer of one session. See the module documentation.
pub(super) struct Registry {
    pub(super) app: SlotObserver,
    /// The dial role's face first, then the accepted ones in the order they came.
    faces: Vec<FaceTables>,
}

impl Registry {
    /// A session that holds nothing and has been told nothing, with its dial face.
    pub(super) fn new() -> Self {
        Self {
            app: SlotObserver::new(),
            faces: vec![FaceTables::new(DIAL_FACE)],
        }
    }

    /// The dial role's face, which the registry holds for its whole life.
    pub(super) fn dial(&self) -> &FaceTables {
        &self.faces[0]
    }

    /// [`Self::dial`], to write.
    pub(super) fn dial_mut(&mut self) -> &mut FaceTables {
        &mut self.faces[0]
    }

    /// The application's part and the dial face's tables, apart so both can be written.
    pub(super) fn app_and_dial(&mut self) -> (&mut SlotObserver, &mut FaceTables) {
        let Self { app, faces } = self;
        (app, &mut faces[0])
    }

    /// The tables of face `id`, while the session holds it.
    pub(super) fn face_mut(&mut self, id: FaceId) -> Option<&mut FaceTables> {
        self.faces.iter_mut().find(|face| face.id == id)
    }

    /// The application's part and the tables of face `id`, apart so both can be written: what
    /// every dispatch and drain takes.
    fn split(&mut self, id: FaceId) -> Option<(&mut SlotObserver, &mut FaceTables)> {
        let Self { app, faces } = self;
        faces
            .iter_mut()
            .find(|face| face.id == id)
            .map(|face| (app, face))
    }

    /// Fan one iteration's event of face `id` into the application layer, against that face's
    /// tables. A face the session no longer holds hears nothing.
    pub(super) fn dispatch_event(&mut self, id: FaceId, event: IterationEvent<'_>) {
        if let Some((app, face)) = self.split(id) {
            app.dispatch_event(&mut face.peer, &mut face.gets, event);
        }
    }

    /// Stage for the peer of face `id` what the application did to its subscriptions since the
    /// peer last looked, so the drain that follows sends it: the future push a subscription
    /// registered after the peer's interest is owed, and the retraction of an aggregate
    /// declaration the last matching subscription stood for. An observer that held the peer's
    /// side beside the table staged both as it was told; the table that serves one peer or many
    /// leaves each peer to read the table's epoch, and nothing else reads it.
    fn reconcile_subscribers(&mut self, id: FaceId) {
        if let Some((app, face)) = self.split(id) {
            face.peer.subscribers.reconcile(&app.subscribers);
        }
    }

    /// Drain what the last [`Self::dispatch_event`] of face `id` staged, EXCEPT the `Final`s the
    /// queries owe: the replies, the answers to the peer's interests and the terminated-get
    /// prunes leave through `actions`. The `Final`s are taken with
    /// [`Self::take_pending_final_rids`].
    #[cfg(feature = "queryable")]
    pub(super) fn flush_pending_replies<S>(&mut self, id: FaceId, actions: &S)
    where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        self.reconcile_subscribers(id);
        if let Some((app, face)) = self.split(id) {
            app.flush_pending_replies(&mut face.peer, &mut face.gets, actions);
        }
    }

    /// The `Final`s the queries of face `id` owe its peer, each with the QoS of its query, taken
    /// so the caller sends them once the last callback that may still answer has.
    #[cfg(feature = "queryable")]
    pub(super) fn take_pending_final_rids(&mut self, id: FaceId) -> FinalStage {
        self.face_mut(id)
            .map(|face| core::mem::take(&mut face.peer.finals))
            .unwrap_or_default()
    }

    /// Fan and drain in one call, the `Final`s with the rest: what a session with no queryable
    /// to wait for does with each event.
    #[cfg(not(feature = "queryable"))]
    pub(super) fn dispatch<S>(&mut self, id: FaceId, event: IterationEvent<'_>, actions: &S)
    where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        self.dispatch_event(id, event);
        self.reconcile_subscribers(id);
        if let Some((app, face)) = self.split(id) {
            app.flush_pending(&mut face.peer, &mut face.gets, actions);
        }
    }

    /// The link of face `id` was lost: every subscriber and queryable its peer declared is gone,
    /// and the matching listeners are told what that makes of them.
    pub(super) fn flush_declarations_on_link_loss(&mut self, id: FaceId) -> usize {
        self.split(id).map_or(0, |(app, face)| {
            app.flush_declarations_on_link_loss(&mut face.peer)
        })
    }

    /// The link of face `id` was lost: every token its peer declared is gone, and the liveliness
    /// subscribers are told each is.
    pub(super) fn flush_liveliness_on_link_loss(&mut self, id: FaceId) -> usize {
        self.split(id).map_or(0, |(app, face)| {
            app.flush_liveliness_on_link_loss(&mut face.peer)
        })
    }
}
