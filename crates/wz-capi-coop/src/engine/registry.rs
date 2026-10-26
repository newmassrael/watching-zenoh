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
//!
//! A matching listener on a publisher matches while ANY face's peer holds a subscriber for it,
//! so the verdicts that one face's dispatch reaches count the other faces' declarations beside
//! its own ([`Others`], `slot_observer::OtherPeers`).

use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::peer_tables::PeerTables;
use wz_session_core::reply_sink::{BoxedReplySink, ConsolidatingSink};
#[cfg(feature = "queryable")]
use wz_session_core::reply_stage::FinalStage;
use wz_session_core::response_sink::{DeclareReplySink, LivelinessGetPrune, ResponseSink};
use wz_session_core::slot_observer::{OtherPeers, Requesters, SlotObserver};

use wz_session_core::declare::matching::BoxedMatchingSink;
use wz_session_core::declare::queryable::QuerierCriterion;
use wz_session_core::declare::subscriber::PublisherCriterion;
#[cfg(feature = "liveliness")]
use wz_session_core::registry_error::RegisterError;

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

/// The faces other than the one a call acts on, which the matching verdicts of that call count.
struct Others<'a> {
    before: &'a [FaceTables],
    after: &'a [FaceTables],
}

impl Others<'_> {
    fn faces(&self) -> impl Iterator<Item = &FaceTables> {
        self.before.iter().chain(self.after.iter())
    }
}

impl OtherPeers for Others<'_> {
    fn subscribes(
        &self,
        criterion: &wz_session_core::declare::subscriber::PublisherCriterion,
    ) -> bool {
        self.faces()
            .any(|face| face.peer.remote_subscribers.has_matching_for(criterion))
    }

    fn answers(&self, criterion: &wz_session_core::declare::queryable::QuerierCriterion) -> bool {
        self.faces()
            .any(|face| face.peer.remote_queryables.has_matching_for(criterion))
    }
}

/// The place of the session's own gets that its own queryables answer, which no face owns: a
/// get's leg to them outlives every link.
#[cfg(feature = "local-queryable")]
pub(super) const LOCAL_FACE: FaceId = u64::MAX;

/// The application layer of one session. See the module documentation.
pub(super) struct Registry {
    pub(super) app: SlotObserver,
    /// The dial role's face first, then the accepted ones in the order they came.
    faces: Vec<FaceTables>,
    /// The session's own gets pending on its own queryables ([`LOCAL_FACE`]).
    #[cfg(feature = "local-queryable")]
    pub(super) local: Gets,
}

/// The application's part, one face's tables and the other faces', apart so each can be used as
/// its call needs.
struct Split<'a> {
    app: &'a mut SlotObserver,
    face: &'a mut FaceTables,
    others: Others<'a>,
}

impl Registry {
    /// A session that holds nothing and has been told nothing, with its dial face.
    pub(super) fn new() -> Self {
        Self {
            app: SlotObserver::new(),
            faces: vec![FaceTables::new(DIAL_FACE)],
            #[cfg(feature = "local-queryable")]
            local: Gets::new(),
        }
    }

    /// The tables of every face, the dial role's first.
    pub(super) fn faces(&self) -> impl Iterator<Item = &FaceTables> {
        self.faces.iter()
    }

    /// The pending gets of every face and, where the session answers its own gets, its own.
    #[cfg(feature = "query")]
    pub(super) fn all_gets(&self) -> impl Iterator<Item = &Gets> {
        let gets = self.faces.iter().map(|face| &face.gets);
        #[cfg(feature = "local-queryable")]
        let gets = gets.chain(core::iter::once(&self.local));
        gets
    }

    /// [`Self::all_gets`], to write.
    #[cfg(feature = "query")]
    pub(super) fn all_gets_mut(&mut self) -> impl Iterator<Item = &mut Gets> {
        let gets = self.faces.iter_mut().map(|face| &mut face.gets);
        #[cfg(feature = "local-queryable")]
        let gets = gets.chain(core::iter::once(&mut self.local));
        gets
    }

    /// The pending gets of the face `id` names, or the session's own for [`LOCAL_FACE`], while it
    /// holds them.
    #[cfg(feature = "query")]
    pub(super) fn gets_mut(&mut self, id: FaceId) -> Option<&mut Gets> {
        #[cfg(feature = "local-queryable")]
        if id == LOCAL_FACE {
            return Some(&mut self.local);
        }
        self.face_mut(id).map(|face| &mut face.gets)
    }

    /// Tables for a face that has come: empty, as its peer has said nothing yet.
    pub(super) fn add_face(&mut self, id: FaceId) {
        self.faces.push(FaceTables::new(id));
    }

    /// The tables of face `id`, gone with the face. The dial role's face is never removed.
    pub(super) fn remove_face(&mut self, id: FaceId) {
        if id != DIAL_FACE {
            self.faces.retain(|face| face.id != id);
        }
    }

    /// The tables of every face but the dial role's, gone with their faces.
    pub(super) fn remove_accepted_faces(&mut self) {
        self.faces.truncate(1);
    }

    /// The tables of face `id`, while the session holds it.
    #[cfg(any(feature = "query", feature = "queryable"))]
    pub(super) fn face_mut(&mut self, id: FaceId) -> Option<&mut FaceTables> {
        self.faces.iter_mut().find(|face| face.id == id)
    }

    /// The application's part, the tables of face `id` and those of the others, apart so each can
    /// be used as its call needs: what every dispatch and drain takes.
    fn split(&mut self, id: FaceId) -> Option<Split<'_>> {
        let Self { app, faces, .. } = self;
        let at = faces.iter().position(|face| face.id == id)?;
        let (before, rest) = faces.split_at_mut(at);
        let (face, after) = rest.split_first_mut()?;
        Some(Split {
            app,
            face,
            others: Others {
                before: &*before,
                after: &*after,
            },
        })
    }

    /// Fan one iteration's event of face `id` into the application layer, against that face's
    /// tables. A face the session no longer holds hears nothing.
    pub(super) fn dispatch_event(&mut self, id: FaceId, event: IterationEvent<'_>) {
        if let Some(Split { app, face, others }) = self.split(id) {
            app.dispatch_event_among(&mut face.peer, &mut face.gets, event, &others);
        }
    }

    /// Stage for the peer of face `id` what the application did to its subscriptions since the
    /// peer last looked, so the drain that follows sends it: the future push a subscription
    /// registered after the peer's interest is owed, and the retraction of an aggregate
    /// declaration the last matching subscription stood for. An observer that held the peer's
    /// side beside the table staged both as it was told; the table that serves one peer or many
    /// leaves each peer to read the table's epoch, and nothing else reads it.
    fn reconcile_subscribers(&mut self, id: FaceId) {
        if let Some(Split { app, face, .. }) = self.split(id) {
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
        if let Some(Split { app, face, .. }) = self.split(id) {
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
        if let Some(Split { app, face, .. }) = self.split(id) {
            app.flush_pending(&mut face.peer, &mut face.gets, actions);
        }
    }

    /// The link of face `id` was lost: every subscriber and queryable its peer declared is gone,
    /// and the matching listeners are told what that makes of them, the other faces' peers
    /// counting as they do.
    pub(super) fn flush_declarations_on_link_loss(&mut self, id: FaceId) -> usize {
        self.split(id).map_or(0, |Split { app, face, others }| {
            app.flush_declarations_on_link_loss_among(&mut face.peer, &others)
        })
    }

    /// The link of face `id` was lost: every token its peer declared is gone, and the liveliness
    /// subscribers are told each is.
    pub(super) fn flush_liveliness_on_link_loss(&mut self, id: FaceId) -> usize {
        self.split(id).map_or(0, |Split { app, face, .. }| {
            app.flush_liveliness_on_link_loss(&mut face.peer)
        })
    }

    /// Declare a matching listener on the publishers' plane: it fires when any face's peer comes
    /// to hold a subscriber `criterion` reaches or the last of them lets go. `local` is the
    /// session's own half of the verdict it starts from.
    pub(super) fn watch_publishers(
        &mut self,
        criterion: PublisherCriterion,
        local: bool,
        sink: BoxedMatchingSink,
    ) -> u64 {
        let Split { app, face, others } = self
            .split(DIAL_FACE)
            .expect("the registry holds the dial face");
        let local = local || others.subscribes(&criterion);
        app.remote_subscribers.declare_matching_listener_seeded(
            &face.peer.remote_subscribers,
            criterion,
            local,
            sink,
        )
    }

    /// Declare a matching listener on the queriers' plane; see [`Self::watch_publishers`].
    pub(super) fn watch_queriers(
        &mut self,
        criterion: QuerierCriterion,
        local: bool,
        sink: BoxedMatchingSink,
    ) -> u64 {
        let Split { app, face, others } = self
            .split(DIAL_FACE)
            .expect("the registry holds the dial face");
        let local = local || others.answers(&criterion);
        app.remote_queryables.declare_matching_listener_seeded(
            &face.peer.remote_queryables,
            criterion,
            local,
            sink,
        )
    }

    /// Tell every matching listener on the publishers' plane that counts the session's own
    /// subscribers whether it now matches, after one was declared or retracted here.
    #[cfg(feature = "local-subscriber")]
    pub(super) fn reevaluate_publisher_watches(&mut self) {
        let Split { app, face, others } = self
            .split(DIAL_FACE)
            .expect("the registry holds the dial face");
        let subscribers = &app.subscribers;
        app.remote_subscribers
            .reevaluate_matching(&face.peer.remote_subscribers, &|criterion| {
                (criterion.locality.allows_local()
                    && subscribers.has_local_matching(&criterion.keyexpr))
                    || others.subscribes(criterion)
            });
    }

    /// The queriers' plane's counterpart of [`Self::reevaluate_publisher_watches`].
    #[cfg(feature = "local-queryable")]
    pub(super) fn reevaluate_querier_watches(&mut self) {
        let Split { app, face, others } = self
            .split(DIAL_FACE)
            .expect("the registry holds the dial face");
        let queryables = &app.queryables;
        app.remote_queryables
            .reevaluate_matching(&face.peer.remote_queryables, &|criterion| {
                (criterion.locality.allows_local()
                    && queryables
                        .has_local_matching(&criterion.keyexpr, criterion.complete_required))
                    || others.answers(criterion)
            });
    }

    /// Register a liveliness subscriber, which with `history` is handed the tokens every face's
    /// peer already holds, before the peers answer with the rest.
    #[cfg(feature = "liveliness")]
    pub(super) fn register_liveliness_subscriber(
        &mut self,
        id: u64,
        keyexpr: &str,
        history: bool,
        sink: wz_session_core::declare::liveliness_sample::BoxedLivelinessSampleSink,
    ) -> Result<bool, RegisterError> {
        let Self { app, faces, .. } = self;
        let registered = app.liveliness_subscribers.register(
            &faces[0].peer.tokens,
            id,
            keyexpr,
            history,
            sink,
        )?;
        if registered && history {
            for face in &faces[1..] {
                app.liveliness_subscribers
                    .replay_known_tokens(&face.peer.tokens, id);
            }
        }
        Ok(registered)
    }
}
