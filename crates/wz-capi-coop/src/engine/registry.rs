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
//!   when it comes and giving it back, emptied, when it goes. A set is built where the registry
//!   keeps it and never moved from there (`FaceTables::rowless_in`).
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
use core::mem::MaybeUninit;
use core::ptr::{self, addr_of_mut};

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

/// Where the rows of a face's tables lie.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowsOrigin {
    /// A set the session's arena lent at its open, which a face takes when it comes and leaves,
    /// emptied, for the next when it goes.
    Spare,
    /// Nowhere: every set the arena lent was held, and the tables, of no rows, refuse every get
    /// and everything the peer would have them hold. The arena lends a set for each face the
    /// config admits and a face past those is refused before it comes, so no face is expected
    /// here; the session's memory is the arena alone either way.
    Unlent,
}

/// The id a set no face holds carries: the session numbers its faces from 1, and its own and the
/// dial role's above them, so no face is 0.
const UNHELD: FaceId = 0;

/// What the session holds for one face: what its peer wrote and what the session asked of it.
///
/// A set is built where the registry keeps it ([`Self::rowless_in`], then [`Self::lend`]) and is
/// never moved from there: a face that comes takes a set where it lies and one that goes empties it
/// there. The peer's tables keyed by its ids are inline at the build's capacity, so a set is tens of
/// kilobytes, and a set moved as a value passes through the frame of each function that moves it.
pub(super) struct FaceTables {
    pub(super) id: FaceId,
    pub(super) peer: Peer,
    pub(super) gets: Gets,
    origin: RowsOrigin,
}

impl FaceTables {
    /// A set for no face yet whose rows lie where `origin` says, written field by field into
    /// `place`, which is overwritten without dropping what it held: tables of no rows, each
    /// refusing what is asked of it until [`Self::lend`] lends it rows, the peer's held to
    /// `limits`. Not inlined: the peer's tables, nearly all of the set, are written where they lie
    /// by `init_in`, and of the set only its gets are a value in this frame.
    #[inline(never)]
    fn rowless_in<'p>(
        place: &'p mut MaybeUninit<Self>,
        origin: RowsOrigin,
        limits: &SessionLimits,
    ) -> &'p mut Self {
        let at = place.as_mut_ptr();
        // SAFETY: `at` is valid for writes of a `Self`, and each field is written once through a
        // pointer to it, the peer's tables by `init_in`, which writes them whole (a
        // `MaybeUninit<T>` has the layout of `T`). `every_field_is_written` names every field, so
        // the set is whole when it is lent.
        let set = unsafe {
            ptr::write(addr_of_mut!((*at).id), UNHELD);
            ptr::write(addr_of_mut!((*at).gets), Gets::default());
            Peer::init_in(&mut *addr_of_mut!((*at).peer).cast::<MaybeUninit<Peer>>());
            ptr::write(addr_of_mut!((*at).origin), origin);
            &mut *at
        };
        set.peer.limit_to(limits);
        set
    }

    /// A field added to [`FaceTables`] and not written by [`Self::rowless_in`] would be read
    /// uninitialised. This destructures the set with no `..`, so adding a field without naming it
    /// here (and so without writing it there) does not compile.
    #[allow(dead_code)]
    fn every_field_is_written(set: Self) {
        let Self {
            id: _,
            peer: _,
            gets: _,
            origin: _,
        } = set;
    }

    /// Lend a set of no rows its rows where it lies: `gets` rows of its gets and `peer` of its
    /// peer's tables, from `arena`, in that order, held to `limits`. Refused when the arena has not
    /// the rows; the set stays whole, with what was lent before the refusal.
    fn lend(
        &mut self,
        arena: &mut Arena,
        gets: RequesterRows,
        peer: PeerRows,
        limits: &SessionLimits,
    ) -> Result<(), LendRefused> {
        self.gets = Gets::lent(arena, gets, limits)?;
        self.peer.lend_rows(arena, peer, limits)
    }

    /// Whether face `id` holds this set.
    fn held_by(&self, id: FaceId) -> bool {
        self.id == id && self.held()
    }

    /// Whether a face holds this set.
    fn held(&self) -> bool {
        self.id != UNHELD
    }

    /// Give the set back where it lies, for the next face: what its peer wrote is dropped and its
    /// pending gets end, as the loss of the face they were asked of ends them, each table keeping
    /// the rows it was lent.
    fn give_back(&mut self) {
        self.gets.clear();
        self.peer.forget_peer();
        self.id = UNHELD;
    }
}

/// The faces other than the one a call acts on, which the matching verdicts of that call count.
struct Others<'a> {
    before: &'a [FaceTables],
    after: &'a [FaceTables],
}

impl Others<'_> {
    fn faces(&self) -> impl Iterator<Item = &FaceTables> {
        self.before
            .iter()
            .chain(self.after.iter())
            .filter(|face| face.held())
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
    /// Every set of face tables, each where it was built and never moved from: the sets the arena
    /// lent at the open, the dial role's face's first and always held by it, then any set of no
    /// rows made for a face that came when every lent set was held. A set no face holds is kept,
    /// emptied, for the next face; the faces are those of the sets a face holds, in this order.
    sets: Vec<FaceTables>,
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
        // The sets are lent in the order the plan counts them: the dial face's, the session's own
        // gets, then the faces to come.
        let mut sets = Vec::with_capacity(peers.tables.max(1));
        lend_set(&mut sets, arena, gets.rows, peers.rows, limits)?;
        sets[0].id = DIAL_FACE;
        #[cfg(feature = "local-queryable")]
        let local = Gets::lent(arena, gets.rows, limits)?;
        for _ in 1..peers.tables {
            lend_set(&mut sets, arena, gets.rows, peers.rows, limits)?;
        }
        Ok(Self {
            app,
            sets,
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
        self.sets.iter().filter(|set| set.held())
    }

    /// The tables of face `id`, while the session holds it, to write.
    fn held_mut(&mut self, id: FaceId) -> Option<&mut FaceTables> {
        self.sets.iter_mut().find(|set| set.held_by(id))
    }

    /// The pending gets of every face and, where the session answers its own gets, its own.
    #[cfg(feature = "query")]
    pub(super) fn all_gets(&self) -> impl Iterator<Item = &Gets> {
        let gets = self.faces().map(|face| &face.gets);
        #[cfg(feature = "local-queryable")]
        let gets = gets.chain(core::iter::once(&self.local));
        gets
    }

    /// [`Self::all_gets`], to write.
    #[cfg(feature = "query")]
    pub(super) fn all_gets_mut(&mut self) -> impl Iterator<Item = &mut Gets> {
        let gets = self
            .sets
            .iter_mut()
            .filter(|set| set.held())
            .map(|face| &mut face.gets);
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

    /// Tables for a face that has come: empty, as its peer has said nothing yet, a set the arena
    /// lent that no face holds where there is one, or else a set of no rows (one a face past the
    /// plan left, or a new one).
    pub(super) fn add_face(&mut self, id: FaceId) {
        self.writing();
        let lent = self
            .sets
            .iter()
            .position(|set| !set.held() && set.origin == RowsOrigin::Spare);
        let free = lent.or_else(|| self.sets.iter().position(|set| !set.held()));
        let at = match free {
            Some(at) => at,
            None => {
                push_rowless(&mut self.sets, RowsOrigin::Unlent, &self.limits);
                self.sets.len() - 1
            }
        };
        self.sets[at].id = id;
    }

    /// The tables of face `id`, gone with the face and left, emptied, where they lie for the next
    /// face. The dial role's face is never removed.
    pub(super) fn remove_face(&mut self, id: FaceId) {
        if id == DIAL_FACE {
            return;
        }
        if let Some(at) = self.sets.iter().position(|set| set.held_by(id)) {
            self.writing();
            self.sets[at].give_back();
        }
    }

    /// The tables of every face but the dial role's, gone with their faces and left, emptied,
    /// where they lie.
    pub(super) fn remove_accepted_faces(&mut self) {
        self.writing();
        for set in &mut self.sets {
            if set.held() && set.id != DIAL_FACE {
                set.give_back();
            }
        }
    }

    /// The tables of face `id`, while the session holds it.
    #[cfg(any(feature = "query", feature = "queryable"))]
    pub(super) fn face_mut(&mut self, id: FaceId) -> Option<&mut FaceTables> {
        self.writing();
        self.held_mut(id)
    }

    /// Hand the tables of face `id` the id space of the link now opened to it: the key expressions
    /// this session declared to that link, which its peer may name in what it sends. A peer that
    /// has been told an id prefers it to the literal (zenoh's routers do, for a subscriber they
    /// route to), and an id the tables cannot resolve is a sample that is dropped. The space is
    /// the link's, so each link the face is opened over installs its own, and the dial role's
    /// face, which is opened again after a loss, replaces the lost link's.
    pub(super) fn install_own_mapping_space(&mut self, id: FaceId, space: SharedOwnMappingSpace) {
        self.writing();
        if let Some(face) = self.held_mut(id) {
            face.peer.subscribers.set_own_mapping_space(space);
        }
    }

    /// Let go of the id space the tables of face `id` hold, the link it was the space of being gone:
    /// until the next link of the face installs its own, the peer's ids of the session's
    /// declarations resolve to nothing, as before the first link.
    pub(super) fn forget_own_mapping_space(&mut self, id: FaceId) {
        self.writing();
        if let Some(face) = self.held_mut(id) {
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
        if let Some(face) = self.held_mut(id) {
            face.peer.subscribers.set_shared_key_ids(ids);
        }
    }

    /// The application's part, the tables of face `id` and those of the others, apart so each can
    /// be used as its call needs: what every dispatch and drain takes.
    fn split(&mut self, id: FaceId) -> Option<Split<'_>> {
        self.writing();
        let Self { app, sets, .. } = self;
        let at = sets.iter().position(|set| set.held_by(id))?;
        let (before, rest) = sets.split_at_mut(at);
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
        self.faces()
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
        let Self { app, sets, .. } = self;
        let registered = app.liveliness_subscribers.register(
            &sets[0].peer.tokens,
            id,
            keyexpr,
            history,
            sink,
        )?;
        if registered && history {
            for face in sets[1..].iter().filter(|set| set.held()) {
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
        let Self { app, sets, .. } = self;
        for face in sets.iter().filter(|set| set.held()) {
            app.liveliness_subscribers
                .replay_known_tokens(&face.peer.tokens, id);
        }
    }
}

/// Write a set of no rows at the end of `sets`, in the storage the vector keeps it in, held to
/// `limits`, and hand it back: a set is never a value of its own in this frame.
fn push_rowless<'s>(
    sets: &'s mut Vec<FaceTables>,
    origin: RowsOrigin,
    limits: &SessionLimits,
) -> &'s mut FaceTables {
    sets.reserve(1);
    let at = sets.len();
    // SAFETY: `reserve` left room for at least one set past the length, which is the first cell of
    // the spare capacity; `rowless_in` writes a whole set there and cannot unwind, so the length may
    // count it.
    unsafe {
        FaceTables::rowless_in(&mut sets.spare_capacity_mut()[0], origin, limits);
        sets.set_len(at + 1);
    }
    &mut sets[at]
}

/// Write a set at the end of `sets` and lend it its rows there, `gets` and `peer` of them from
/// `arena`, held to `limits`. A refused set stays in `sets`, whole, and goes with it.
fn lend_set(
    sets: &mut Vec<FaceTables>,
    arena: &mut Arena,
    gets: RequesterRows,
    peer: PeerRows,
    limits: &SessionLimits,
) -> Result<(), LendRefused> {
    push_rowless(sets, RowsOrigin::Spare, limits).lend(arena, gets, peer, limits)
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
        arena: SessionArena,
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
        Held { registry, arena }
    }

    fn face(registry: &mut Registry, id: FaceId) -> &mut FaceTables {
        registry.held_mut(id).expect("the registry holds the face")
    }

    /// How many sets the open lent that no face holds.
    fn free_lent(registry: &Registry) -> usize {
        registry
            .sets
            .iter()
            .filter(|set| !set.held() && set.origin == RowsOrigin::Spare)
            .count()
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

    /// An accepted face takes the set the open lent where it lies, empties it there when it goes,
    /// and the next face takes the same set at the same address: a set is never moved.
    #[test]
    fn an_accepted_face_takes_a_lent_set_where_it_lies_and_gives_it_back_there() {
        let mut held = held(2);
        assert_eq!(free_lent(&held.registry), 1);
        held.registry.add_face(5);
        assert_eq!(free_lent(&held.registry), 0);
        let accepted = face(&mut held.registry, 5);
        assert_eq!(accepted.origin, RowsOrigin::Spare);
        accepted.peer.finals.owe(1, QosLevel::DEFAULT);
        let lies_at: *const FaceTables = accepted;
        held.registry.remove_face(5);
        assert_eq!(free_lent(&held.registry), 1, "the set went back");
        assert_eq!(held.registry.sets.len(), 2, "and stayed where it lies");
        assert_eq!(
            held.registry.sets[1].peer.finals.owed(),
            0,
            "emptied for the next face"
        );
        assert!(
            held.registry.faces().all(|face| face.id == DIAL_FACE),
            "the face that went is not among the faces"
        );
        held.registry.add_face(6);
        let next = face(&mut held.registry, 6);
        assert!(ptr::eq(&*next, lies_at), "the next face took the same set");
        holds_one_final(next);
    }

    /// The faces' sets given back in place leave the arena's pools as full as before the faces
    /// came: every lent set is free again with every row it was lent, and the arena lent nothing
    /// more.
    #[test]
    fn faces_that_go_leave_the_pools_as_full_as_before() {
        let mut held = held(3);
        let lent = held.arena.arena_mut().high_water();
        assert_eq!(free_lent(&held.registry), 2);
        for id in [5, 6] {
            held.registry.add_face(id);
            let accepted = face(&mut held.registry, id);
            accepted.peer.finals.owe(1, QosLevel::DEFAULT);
            assert!(
                !accepted.peer.finals.has_room(),
                "CONTROL: its one row is held"
            );
        }
        assert_eq!(free_lent(&held.registry), 0);
        held.registry.remove_face(5);
        held.registry.remove_accepted_faces();
        assert_eq!(free_lent(&held.registry), 2, "every lent set is free again");
        assert_eq!(
            held.registry.sets.len(),
            3,
            "and no set was made or dropped"
        );
        assert_eq!(
            held.arena.arena_mut().high_water(),
            lent,
            "the arena lent nothing more"
        );
        for set in &held.registry.sets[1..] {
            assert!(set.peer.finals.has_room(), "each row of each set is free");
            assert!(set.gets.replies.has_room());
        }
        assert!(
            held.registry.faces().all(|face| face.id == DIAL_FACE),
            "the dial role's face stays"
        );
    }

    /// A set built where it lies and lent its rows there is the set the tables lent by value make:
    /// the same bytes of the arena, and the rows that bound it.
    #[test]
    fn a_set_lent_in_place_is_the_set_lent_by_value() {
        let limits = SessionLimits::defaults();
        let gets = RequesterRows {
            queries: 1,
            liveliness_gets: 0,
        };
        let peer = PeerRows {
            sub_interests: 1,
            pending_declares: 1,
            replies: 1,
            reply_bytes: 64,
            finals: 1,
        };
        let mut by_value_arena =
            SessionArena::of_bytes(1 << 16, &AllocatorMemory).expect("the host has the memory");
        let by_value_gets = Gets::lent(by_value_arena.arena_mut(), gets, &limits).expect("rows");
        let mut by_value_peer =
            Peer::lent(by_value_arena.arena_mut(), peer, &limits).expect("rows");
        let mut arena =
            SessionArena::of_bytes(1 << 16, &AllocatorMemory).expect("the host has the memory");
        let mut sets = Vec::new();
        lend_set(&mut sets, arena.arena_mut(), gets, peer, &limits)
            .expect("the arena has the rows");
        assert_eq!(
            arena.arena_mut().high_water(),
            by_value_arena.arena_mut().high_water(),
            "the same tables lent in the same order take the same bytes"
        );
        let set = &mut sets[0];
        assert_eq!((set.id, set.origin), (UNHELD, RowsOrigin::Spare));
        assert_eq!(
            set.gets.replies.has_room(),
            by_value_gets.replies.has_room()
        );
        set.peer.finals.owe(1, QosLevel::DEFAULT);
        by_value_peer.finals.owe(1, QosLevel::DEFAULT);
        assert_eq!(
            (set.peer.finals.has_room(), set.peer.finals.owed()),
            (by_value_peer.finals.has_room(), by_value_peer.finals.owed()),
            "one row of Finals either way"
        );
        assert!(!set.peer.finals.has_room());
    }

    /// A face past those the open planned for holds a set of no rows, taking no memory of the
    /// arena: the `Final` its peer's query would need has no room, so the query is refused before
    /// it runs. Its going leaves the set where it lies, and the next face past the plan takes it.
    #[test]
    fn a_face_past_the_plan_refuses_before_holding_anything() {
        let mut held = held(1);
        let lent = held.arena.arena_mut().high_water();
        held.registry.add_face(5);
        let accepted = face(&mut held.registry, 5);
        assert_eq!(accepted.origin, RowsOrigin::Unlent);
        assert!(!accepted.peer.finals.has_room());
        assert!(!accepted.gets.replies.has_room());
        assert_eq!(
            held.arena.arena_mut().high_water(),
            lent,
            "no rows were lent"
        );
        held.registry.remove_face(5);
        assert_eq!(free_lent(&held.registry), 0, "no lent set comes of it");
        held.registry.add_face(6);
        assert_eq!(
            held.registry.sets.len(),
            2,
            "the set of no rows was taken again"
        );
        assert!(!face(&mut held.registry, 6).peer.finals.has_room());
    }
}
