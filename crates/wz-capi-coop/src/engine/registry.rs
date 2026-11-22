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
//!   pending on that face, whose request ids the face's actions mint. Both are lent from the
//!   session's arena at its open, one set for each face it may hold at once, a face taking a set
//!   when it comes and giving it back, emptied, when it goes.
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

#[cfg(feature = "queryable")]
use wz_session_core::bounded::Static;
use wz_session_core::bounded::{Arena, LendRefused, Lent};
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::limits::SessionLimits;
use wz_session_core::peer_tables::{PeerRows, PeerTables};
use wz_session_core::reply_sink::{BoxedReplySink, ConsolidatingSink};
#[cfg(feature = "queryable")]
use wz_session_core::reply_stage::FinalStage;
use wz_session_core::response_sink::{DeclareReplySink, LivelinessGetPrune, ResponseSink};
use wz_session_core::slot_observer::{
    HeapSinks, ObserverRows, OtherPeers, Requesters, SlotObserverOf,
};
use wz_session_core::wireexpr_resolve::SharedOwnMappingSpace;

use crate::arena::{FacePeers, GetTables};
use wz_capi_port::FilterPlane;
use wz_session_core::locality::Locality;
use wz_session_core::slot_observer::RequesterRows;

use wz_session_core::declare::matching::BoxedMatchingSink;
use wz_session_core::declare::queryable::QuerierCriterion;
use wz_session_core::declare::subscriber::PublisherCriterion;
#[cfg(feature = "liveliness")]
use wz_session_core::registry_error::RegisterError;

#[allow(unused_imports)]
use crate::prelude::*;

#[cfg(any(
    feature = "remote-declaration-watch",
    feature = "declarations-synced-event"
))]
use super::decl_watch::DeclWatches;

/// A face of the session, named for as long as the session holds it.
pub(super) type FaceId = u64;

/// The dial role's face, as `wz-capi-core`'s registry names it: accepted faces take the ids
/// beneath it.
pub(super) const DIAL_FACE: FaceId = 1 << 62;

/// The session's own pending gets on one face: a query's sink consolidates what its leg is
/// handed. The rows are lent from the session's arena at its open, one table for each face the
/// session may hold at once (`crate::arena::GetTables`).
pub(super) type Gets = Requesters<ConsolidatingSink<BoxedReplySink>, BoxedReplySink, Lent>;

/// What a face's peer writes and is owed. The rows are lent from the session's arena at its open,
/// one set for each face the session may hold at once (`crate::arena::FacePeers`).
pub(super) type Peer = PeerTables<Lent>;

/// The tables one face is lent: the session's gets pending on it and what its peer writes.
struct FaceRows {
    gets: Gets,
    peer: Peer,
}

impl FaceRows {
    /// Both tables, `gets` and `peer` rows of them lent from `arena` and held to `limits`.
    fn lent(
        arena: &mut Arena,
        gets: RequesterRows,
        peer: PeerRows,
        limits: &SessionLimits,
    ) -> Result<Self, LendRefused> {
        Ok(Self {
            gets: Gets::lent(arena, gets, limits)?,
            peer: Peer::lent(arena, peer, limits)?,
        })
    }

    /// Tables of no rows, each refusing what is asked of it before anything is put in it: those of
    /// a face that came when every set the arena lent was held.
    fn rowless(limits: &SessionLimits) -> Self {
        Self {
            gets: Gets::default(),
            // An arena of no bytes lends every table its no rows, so nothing refuses the lend.
            peer: Peer::lent(&mut Arena::empty(), PeerRows::default(), limits).unwrap_or_default(),
        }
    }
}

/// Where the rows of a face's tables lie.
enum RowsOrigin {
    /// A spare set of the session's arena, which goes back to the spares when the face goes.
    Spare,
    /// Nowhere: every set the arena lent was held, and the tables, of no rows, refuse every get
    /// and everything the peer would have them hold. The arena lends a set for each face the
    /// config admits and a face past those is refused before it comes, so no face is expected
    /// here; the session's memory is the arena alone either way.
    Unlent,
}

/// What the session holds for one face: what its peer wrote and what the session asked of it.
pub(super) struct FaceTables {
    pub(super) id: FaceId,
    pub(super) peer: Peer,
    pub(super) gets: Gets,
    origin: RowsOrigin,
}

impl FaceTables {
    /// The tables of face `id`, empty as its peer has said nothing yet, whose rows lie where
    /// `origin` says.
    fn new(id: FaceId, rows: FaceRows, origin: RowsOrigin) -> Self {
        let FaceRows { gets, peer } = rows;
        Self {
            id,
            peer,
            gets,
            origin,
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

/// What the application registered on the session: its tables' rows lent from the session's
/// arena at its open, each as many as the limit the open resolved.
pub(super) type App = SlotObserverOf<HeapSinks, Lent>;

/// The application layer of one session. See the module documentation.
pub(super) struct Registry {
    pub(super) app: App,
    /// The limits the session's open resolved, which every face's tables are held to: a face
    /// accepted after the open takes them as the dial role's face did.
    limits: SessionLimits,
    /// The dial role's face first, then the accepted ones in the order they came.
    faces: Vec<FaceTables>,
    /// The tables the arena lent for faces the session may still come to hold, each set taken by
    /// a face when it comes and given back, emptied, when it goes.
    spare: Vec<FaceRows>,
    /// The session's own gets pending on its own queryables ([`LOCAL_FACE`]).
    #[cfg(feature = "local-queryable")]
    pub(super) local: Gets,
    /// The program's watches of what the peers declare, which the application layer's observers
    /// stage into while a frame is dispatched (`decl_watch`).
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    pub(super) decl_watches: alloc::sync::Arc<DeclWatches>,
    /// Moves each time a face's peer tables are handed out to be written and each time a face
    /// comes or goes: an answer read off what the peers declared ([`Self::peers_declare`]) holds
    /// for as long as this reads what it read when the answer was taken.
    faces_written: u64,
    /// How often what the peers declared was searched ([`Self::peers_declare`]): what a test of
    /// the cost of a filtered put counts.
    #[cfg(test)]
    peer_looks: core::cell::Cell<usize>,
}

/// The application's part, one face's tables and the other faces', apart so each can be used as
/// its call needs.
struct Split<'a> {
    app: &'a mut App,
    face: &'a mut FaceTables,
    others: Others<'a>,
}

impl Registry {
    /// A session that holds nothing and has been told nothing, with its dial face, its tables
    /// held to the session limits its open resolved, the application's lent from `arena`, `rows`
    /// of each, and the tables of each face `gets` and `peers` count lent from it too: the dial
    /// face's, the session's own gets where it answers its own, and the rest kept for the faces to
    /// come. Refused when the arena has not the rows, which one reserved by the plan that counts
    /// them always has.
    pub(super) fn new(
        limits: &SessionLimits,
        arena: &mut Arena,
        rows: ObserverRows,
        gets: GetTables,
        peers: FacePeers,
    ) -> Result<Self, LendRefused> {
        let app = App::lent(arena, rows, limits)?;
        let dial = FaceRows::lent(arena, gets.rows, peers.rows, limits)?;
        #[cfg(feature = "local-queryable")]
        let local = Gets::lent(arena, gets.rows, limits)?;
        let others = peers.tables.saturating_sub(1);
        let mut spare = Vec::with_capacity(others);
        for _ in 0..others {
            spare.push(FaceRows::lent(arena, gets.rows, peers.rows, limits)?);
        }
        Ok(Self {
            app,
            faces: vec![FaceTables::new(DIAL_FACE, dial, RowsOrigin::Spare)],
            spare,
            limits: *limits,
            #[cfg(feature = "local-queryable")]
            local,
            #[cfg(any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ))]
            decl_watches: alloc::sync::Arc::default(),
            faces_written: 0,
            #[cfg(test)]
            peer_looks: core::cell::Cell::new(0),
        })
    }

    /// The count [`Self::peers_declare`]'s answers are good for: one taken while this read the
    /// same still holds.
    pub(super) fn faces_written(&self) -> u64 {
        self.faces_written
    }

    /// A face's peer tables may be written from here on, or a face came or went.
    fn writing(&mut self) {
        self.faces_written = self.faces_written.wrapping_add(1);
    }

    /// Whether any face's peer declared what `plane` counts on `keyexpr`: a subscriber, or a
    /// queryable (a complete one where the plane requires it).
    pub(super) fn peers_declare(&self, plane: FilterPlane, keyexpr: &str) -> bool {
        #[cfg(test)]
        self.peer_looks.set(self.peer_looks.get() + 1);
        match plane {
            FilterPlane::Subscribers => {
                let subscribers = PublisherCriterion::new(keyexpr, Locality::Remote);
                self.faces()
                    .any(|face| face.peer.remote_subscribers.has_matching_for(&subscribers))
            }
            FilterPlane::Queryables { complete_required } => {
                let queryables =
                    QuerierCriterion::new(keyexpr, Locality::Remote, complete_required);
                self.faces()
                    .any(|face| face.peer.remote_queryables.has_matching_for(&queryables))
            }
        }
    }

    /// How often [`Self::peers_declare`] searched what the peers declared.
    #[cfg(test)]
    pub(super) fn peer_looks(&self) -> usize {
        self.peer_looks.get()
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

    /// Tables for a face that has come: empty, as its peer has said nothing yet, in a spare set
    /// the arena lent, or of no rows when every set is held.
    pub(super) fn add_face(&mut self, id: FaceId) {
        self.writing();
        let (rows, origin) = match self.spare.pop() {
            Some(rows) => (rows, RowsOrigin::Spare),
            None => (FaceRows::rowless(&self.limits), RowsOrigin::Unlent),
        };
        self.faces.push(FaceTables::new(id, rows, origin));
    }

    /// The tables of face `id`, gone with the face. The dial role's face is never removed.
    pub(super) fn remove_face(&mut self, id: FaceId) {
        if id == DIAL_FACE {
            return;
        }
        if let Some(at) = self.faces.iter().position(|face| face.id == id) {
            self.writing();
            let face = self.faces.remove(at);
            self.give_back(face);
        }
    }

    /// The tables of every face but the dial role's, gone with their faces.
    pub(super) fn remove_accepted_faces(&mut self) {
        self.writing();
        while self.faces.len() > 1 {
            if let Some(face) = self.faces.pop() {
                self.give_back(face);
            }
        }
    }

    /// The tables of a face that went: what its peer wrote is dropped and its pending gets end, as
    /// the loss of the face they were asked of ends them, and the tables, emptied, are kept for the
    /// next face when the session's arena lent them.
    fn give_back(&mut self, face: FaceTables) {
        let FaceTables {
            mut peer,
            mut gets,
            origin,
            ..
        } = face;
        gets.clear();
        peer.forget_peer();
        match origin {
            RowsOrigin::Spare => self.spare.push(FaceRows { gets, peer }),
            RowsOrigin::Unlent => {}
        }
    }

    /// The tables of face `id`, while the session holds it.
    #[cfg(any(feature = "query", feature = "queryable"))]
    pub(super) fn face_mut(&mut self, id: FaceId) -> Option<&mut FaceTables> {
        self.writing();
        self.faces.iter_mut().find(|face| face.id == id)
    }

    /// Hand the tables of face `id` the id space of the link now opened to it: the key expressions
    /// this session declared to that link, which its peer may name in what it sends. A peer that
    /// has been told an id prefers it to the literal (zenoh's routers do, for a subscriber they
    /// route to), and an id the tables cannot resolve is a sample that is dropped. The space is
    /// the link's, so each link the face is opened over installs its own, and the dial role's
    /// face, which is opened again after a loss, replaces the lost link's.
    pub(super) fn install_own_mapping_space(&mut self, id: FaceId, space: SharedOwnMappingSpace) {
        self.writing();
        if let Some(face) = self.faces.iter_mut().find(|face| face.id == id) {
            face.peer.subscribers.set_own_mapping_space(space);
        }
    }

    /// Let go of the id space the tables of face `id` hold, the link it was the space of being gone:
    /// until the next link of the face installs its own, the peer's ids of the session's
    /// declarations resolve to nothing, as before the first link.
    pub(super) fn forget_own_mapping_space(&mut self, id: FaceId) {
        self.writing();
        if let Some(face) = self.faces.iter_mut().find(|face| face.id == id) {
            face.peer.subscribers.clear_own_mapping_space();
        }
    }

    /// Hand the tables of face `id` the key ids every node of the deployment shares: an id the
    /// peer never declared, and that no declaration of this session holds, is read in them on
    /// every plane. The dictionary is the session's, so each link the face is opened over
    /// installs the same one again.
    #[cfg(feature = "shared-key-ids")]
    pub(super) fn install_shared_key_ids(
        &mut self,
        id: FaceId,
        ids: wz_session_core::shared_key_ids::SharedKeyIds,
    ) {
        self.writing();
        if let Some(face) = self.faces.iter_mut().find(|face| face.id == id) {
            face.peer.subscribers.set_shared_key_ids(ids);
        }
    }

    /// The application's part, the tables of face `id` and those of the others, apart so each can
    /// be used as its call needs: what every dispatch and drain takes.
    fn split(&mut self, id: FaceId) -> Option<Split<'_>> {
        self.writing();
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
    pub(super) fn dispatch_event(&mut self, id: FaceId, event: IterationEvent<'_, '_>) {
        // What an earlier dispatch staged for the watches and nobody settled is a group's, whose
        // members are not watched.
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        self.decl_watches.drop_staged();
        #[cfg(feature = "declarations-synced-event")]
        let was_final = self.declarations_final(id);
        if let Some(Split { app, face, others }) = self.split(id) {
            app.dispatch_event_among(&mut face.peer, &mut face.gets, event, &others);
        }
        #[cfg(feature = "declarations-synced-event")]
        if !was_final && self.declarations_final(id) {
            self.decl_watches.stage_synced();
        }
    }

    /// Whether the peer of face `id` has ended its initial declarations since its link came up.
    #[cfg(feature = "declarations-synced-event")]
    fn declarations_final(&self, id: FaceId) -> bool {
        self.faces
            .iter()
            .find(|face| face.id == id)
            .is_some_and(|face| face.peer.remote_subscribers.initial_declarations_final())
    }

    /// Owe the watches what the last [`Self::dispatch_event`] staged, as the events of the peer
    /// of the link it dispatched, whose zid `peer` reads: what a link's dispatch does after each
    /// frame, and a group's does not.
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    pub(super) fn settle_decl_events(&self, peer: impl FnOnce() -> Option<Vec<u8>>) {
        self.decl_watches.settle(peer);
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
    pub(super) fn take_pending_final_rids(&mut self, id: FaceId) -> FinalStage<Static> {
        self.face_mut(id)
            .map(|face| face.peer.finals.take_owed())
            .unwrap_or_default()
    }

    /// Fan and drain in one call, the `Final`s with the rest: what a session with no queryable
    /// to wait for does with each event.
    #[cfg(not(feature = "queryable"))]
    pub(super) fn dispatch<S>(&mut self, id: FaceId, event: IterationEvent<'_, '_>, actions: &S)
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

    /// Hand liveliness subscriber `id` the tokens every face's peer holds now, as its
    /// registration with `history` does.
    #[cfg(feature = "liveliness")]
    pub(super) fn replay_liveliness_tokens(&mut self, id: u64) {
        let Self { app, faces, .. } = self;
        for face in faces.iter() {
            app.liveliness_subscribers
                .replay_known_tokens(&face.peer.tokens, id);
        }
    }
}

#[cfg(test)]
mod tests {
    //! Each face's tables are lent from the session's arena: the dial face's at the open, an
    //! accepted face's from the spares the open lent, and past those tables of no rows that refuse
    //! what is asked of them: the session takes no memory but its arena.
    use super::*;
    use crate::arena::{AllocatorMemory, SessionArena};
    use wz_session_core::reply_stage::FinalStaging;
    use wz_session_core::sample::QosLevel;

    /// A registry and the arena its tables were lent from, the registry first so its tables go
    /// before the memory they lie in.
    struct Held {
        registry: Registry,
        _arena: SessionArena,
    }

    /// A registry whose arena lends the tables of `faces` faces, one row of each table.
    fn held(faces: usize) -> Held {
        let mut arena =
            SessionArena::of_bytes(1 << 20, &AllocatorMemory).expect("the host has the memory");
        let gets = GetTables {
            rows: RequesterRows {
                queries: 1,
                liveliness_gets: 0,
            },
            tables: faces + usize::from(cfg!(feature = "local-queryable")),
        };
        let peers = FacePeers {
            rows: PeerRows {
                sub_interests: 1,
                pending_declares: 1,
                replies: 1,
                reply_bytes: 64,
                finals: 1,
            },
            tables: faces,
        };
        let registry = Registry::new(
            &SessionLimits::defaults(),
            arena.arena_mut(),
            ObserverRows::default(),
            gets,
            peers,
        )
        .expect("the arena has the rows");
        Held {
            registry,
            _arena: arena,
        }
    }

    fn face(registry: &mut Registry, id: FaceId) -> &mut FaceTables {
        registry
            .faces
            .iter_mut()
            .find(|face| face.id == id)
            .expect("the registry holds the face")
    }

    /// The face's peer tables hold one `Final`, have no room for a second, and have room again
    /// once what is owed is taken: the rows the arena lent stay with the table.
    fn holds_one_final(face: &mut FaceTables) {
        assert!(face.peer.finals.has_room(), "a row was lent");
        face.peer.finals.owe(1, QosLevel::DEFAULT);
        assert!(!face.peer.finals.has_room(), "the one row holds the Final");
        assert_eq!(face.peer.finals.take_owed().len(), 1);
        assert!(
            face.peer.finals.has_room(),
            "taking what is owed keeps the row"
        );
    }

    /// The dial face's peer tables are lent at the open.
    #[test]
    fn the_dial_face_holds_peer_tables_lent_at_the_open() {
        let mut held = held(1);
        holds_one_final(face(&mut held.registry, DIAL_FACE));
    }

    /// The `Final`s the dial face's peer is owed are taken as a table of their own, and the face's
    /// table keeps its row for the next.
    #[cfg(feature = "queryable")]
    #[test]
    fn the_finals_a_face_owes_are_taken_and_its_row_kept() {
        let mut held = held(1);
        face(&mut held.registry, DIAL_FACE)
            .peer
            .finals
            .owe(4, QosLevel::DEFAULT);
        let owed: Vec<_> = held
            .registry
            .take_pending_final_rids(DIAL_FACE)
            .into_iter()
            .map(|(rid, _)| rid)
            .collect();
        assert_eq!(owed, vec![4]);
        assert!(face(&mut held.registry, DIAL_FACE).peer.finals.has_room());
    }

    /// The liveliness plane's answers to the face's peer are staged in a row the arena lent.
    #[cfg(feature = "liveliness")]
    #[test]
    fn the_dial_face_stages_a_liveliness_answer_in_its_lent_row() {
        use wz_session_core::declare::local_token::DeclResponseItem;

        let mut held = held(1);
        let staging = &mut face(&mut held.registry, DIAL_FACE).peer.pending_declares;
        assert!(staging
            .push(DeclResponseItem::Final { interest_id: 1 })
            .is_ok());
        assert!(staging
            .push(DeclResponseItem::Final { interest_id: 2 })
            .is_err());
    }

    /// An accepted face takes the spare set the open lent, gives it back emptied when it goes, and
    /// the next face takes the same rows.
    #[test]
    fn an_accepted_face_takes_the_spare_tables_and_gives_them_back() {
        let mut held = held(2);
        assert_eq!(held.registry.spare.len(), 1);
        held.registry.add_face(5);
        assert!(held.registry.spare.is_empty());
        let accepted = face(&mut held.registry, 5);
        assert!(matches!(accepted.origin, RowsOrigin::Spare));
        accepted.peer.finals.owe(1, QosLevel::DEFAULT);
        held.registry.remove_face(5);
        assert_eq!(held.registry.spare.len(), 1, "the tables went back");
        assert_eq!(
            held.registry.spare[0].peer.finals.owed(),
            0,
            "emptied for the next face"
        );
        held.registry.add_face(6);
        holds_one_final(face(&mut held.registry, 6));
    }

    /// A face past those the open planned for holds tables of no rows, taking no memory of its
    /// own: the `Final` its peer's query would need has no room, so the query is refused before it
    /// runs, and its going leaves no spare.
    #[test]
    fn a_face_past_the_plan_refuses_before_holding_anything() {
        let mut held = held(1);
        held.registry.add_face(5);
        let accepted = face(&mut held.registry, 5);
        assert!(matches!(accepted.origin, RowsOrigin::Unlent));
        assert!(!accepted.peer.finals.has_room());
        assert!(!accepted.gets.replies.has_room());
        held.registry.remove_face(5);
        assert!(held.registry.spare.is_empty(), "no spare comes of it");
    }
}
