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
//! What a peer writes by its own choice (its aliases, its declarations and the repeats of them,
//! its interests) is not lent to each set at the bound of one peer: each kind of row lies in one
//! pool of the session's ([`PeerPools`]), lent at the open as the sets are, and a face's tables
//! are lists of the rows its peer holds there. A face keeps the bound of one peer; the pool bounds
//! what the faces hold together, and a face that goes gives back its rows, and only its.
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
use wz_session_core::decl_sink::{BoxedDeclSink, BoxedUndeclSink};
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::key_arena::{KeySpace, LentKeys};
use wz_session_core::limits::SessionLimits;
use wz_session_core::peer_tables::{PeerPools, PeerRows, PeerTables, SHARES_ROWS};
use wz_session_core::query_sink::BoxedQuerySink;
use wz_session_core::reply_sink::{BoxedReplySink, ConsolidatingSink};
#[cfg(feature = "queryable")]
use wz_session_core::reply_stage::FinalStage;
use wz_session_core::response_sink::{DeclareReplySink, LivelinessGetPrune, ResponseSink};
use wz_session_core::slot_observer::{
    ObserverRows, ObserverSinks, OtherPeers, Requesters, SlotObserverOf,
};
use wz_session_core::wireexpr_resolve::SharedOwnMappingSpace;

use super::SubscriberRow;
use crate::arena::{FacePeers, GetTables};
use wz_capi_port::FilterPlane;
use wz_session_core::slot_observer::RequesterRows;

use wz_session_core::declare::matching::BoxedMatchingSink;
#[cfg(any(feature = "query", feature = "queryable"))]
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

/// What the session holds for one face: what its peer wrote and what the session asked of it.
///
/// A set is built where the registry keeps it ([`Self::rowless_in`], then [`Self::lend`]) and is
/// never moved from there: a face that comes takes a set where it lies and one that goes empties it
/// there, its rows of the session's pools going back to them. A set holds a few words for each of
/// its tables, and the session's tables are placed once and not moved.
/// Which face holds a set is the registry's index of held sets, not the set's: a walk over the
/// faces reads no set to learn whether a face holds it.
pub(super) struct FaceTables {
    pub(super) peer: Peer,
    pub(super) gets: Gets,
}

impl FaceTables {
    /// A set for no face yet, written field by field into `place`, which is overwritten without
    /// dropping what it held: tables of no rows, each refusing what is asked of it until
    /// [`Self::lend`] lends it rows, the peer's held to `limits`. Not inlined: the peer's tables,
    /// nearly all of the set, are written where they lie by `init_in`, and of the set only its
    /// gets are a value in this frame.
    #[inline(never)]
    fn rowless_in<'p>(place: &'p mut MaybeUninit<Self>, limits: &SessionLimits) -> &'p mut Self {
        let at = place.as_mut_ptr();
        // SAFETY: `at` is valid for writes of a `Self`, and each field is written once through a
        // pointer to it, the peer's tables by `init_in`, which writes them whole (a
        // `MaybeUninit<T>` has the layout of `T`). `every_field_is_written` names every field, so
        // the set is whole when it is lent.
        let set = unsafe {
            ptr::write(addr_of_mut!((*at).gets), Gets::default());
            Peer::init_in(&mut *addr_of_mut!((*at).peer).cast::<MaybeUninit<Peer>>());
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
        let Self { peer: _, gets: _ } = set;
    }

    /// Lend a set of no rows its rows where it lies: `gets` rows of its gets and `peer` of its
    /// peer's tables, from `arena`, in that order, the peer's keys kept in `keys`, the session's
    /// key arena, held to `limits`. Refused when the arena has not the rows; the set stays whole,
    /// with what was lent before the refusal.
    fn lend(
        &mut self,
        arena: &mut Arena,
        keys: KeySpace,
        pools: &mut PeerPools,
        gets: RequesterRows,
        peer: PeerRows,
        limits: &SessionLimits,
    ) -> Result<(), LendRefused> {
        self.gets = Gets::lent(arena, keys, gets, limits)?;
        self.peer.lend_rows(arena, keys, peer, pools, limits)
    }

    /// Give the set back where it lies, for the next face: what its peer wrote is dropped, its rows
    /// of the session's pools back to them, one step for each, and its pending gets end, as the
    /// loss of the face they were asked of ends them, each table keeping the rows it was lent.
    fn give_back(&mut self) {
        self.gets.clear();
        self.peer.forget_peer();
    }
}

/// A set a face holds: where it lies among the registry's sets, and the face. An entry is two
/// words, so a walk over the faces reads one line of the index for every few faces and then the
/// held sets alone, where a test of each set would read a line of every set the open lent.
#[derive(Clone, Copy, Debug)]
struct HeldSet {
    at: usize,
    id: FaceId,
}

/// The sets faces hold, to write, in set order: each is split off what lies past the one before
/// it, so the walk takes the held sets alone.
#[cfg(feature = "query")]
struct HeldMut<'a> {
    /// The sets past the last one taken.
    rest: &'a mut [FaceTables],
    /// Where `rest` starts among the registry's sets.
    base: usize,
    held: core::slice::Iter<'a, HeldSet>,
}

#[cfg(feature = "query")]
impl<'a> HeldMut<'a> {
    /// The sets of `sets` that `held`, in set order, names.
    fn of(sets: &'a mut [FaceTables], held: &'a [HeldSet]) -> Self {
        Self {
            rest: sets,
            base: 0,
            held: held.iter(),
        }
    }
}

#[cfg(feature = "query")]
impl<'a> Iterator for HeldMut<'a> {
    type Item = &'a mut FaceTables;

    fn next(&mut self) -> Option<Self::Item> {
        let held = self.held.next()?;
        let rest = core::mem::take(&mut self.rest);
        let (_, from) = rest.split_at_mut(held.at - self.base);
        let (set, after) = from.split_first_mut()?;
        self.rest = after;
        self.base = held.at + 1;
        Some(set)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.held.size_hint()
    }
}

/// The faces other than the one a call acts on, which the matching verdicts of that call count:
/// the sets before the call's own and after it, and the entries of the index of held sets that
/// name them.
struct Others<'a> {
    before: &'a [FaceTables],
    after: &'a [FaceTables],
    held_before: &'a [HeldSet],
    held_after: &'a [HeldSet],
    /// Where `after` starts among the registry's sets.
    after_at: usize,
}

impl Others<'_> {
    fn faces(&self) -> impl Iterator<Item = &FaceTables> {
        let (before, after, after_at) = (self.before, self.after, self.after_at);
        self.held_before
            .iter()
            .map(move |held| &before[held.at])
            .chain(
                self.held_after
                    .iter()
                    .map(move |held| &after[held.at - after_at]),
            )
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

    // Without a querier or a queryable the faces hold no queryable a peer declared, and the
    // trait's own answer (none) is this engine's.
    #[cfg(any(feature = "query", feature = "queryable"))]
    fn answers(&self, criterion: &QuerierCriterion) -> bool {
        self.faces()
            .any(|face| face.peer.remote_queryables.has_matching_for(criterion))
    }
}

/// The place of the session's own gets that its own queryables answer, which no face owns: a
/// get's leg to them outlives every link.
#[cfg(feature = "local-queryable")]
pub(super) const LOCAL_FACE: FaceId = u64::MAX;

/// What the application's tables hold on this engine: the heap profile's registrations, but for
/// the session's own subscribers, each of whose rows is the engine's whole record of it
/// ([`SubscriberRow`]), not a closure over the engine's own.
pub(super) struct CoopSinks;

impl ObserverSinks for CoopSinks {
    type Subscriber = SubscriberRow;
    type Tables<P: wz_session_core::bounded::Storage> =
        wz_session_core::pubsub::SubscriberTable<Self::Subscriber, P>;
    type Queryable = BoxedQuerySink;
    type Declared = BoxedDeclSink;
    type Undeclared = BoxedUndeclSink;
}

/// What the application registered on the session: its tables' rows lent from the session's
/// arena at its open, each as many as the limit the open resolved.
pub(super) type App = SlotObserverOf<CoopSinks, Lent>;

/// The application layer of one session. See the module documentation.
pub(super) struct Registry {
    pub(super) app: App,
    /// The limits the session's open resolved, which every face's tables are held to: a face
    /// accepted after the open takes them as the dial role's face did.
    limits: SessionLimits,
    /// The session's key arena, which every face's tables keep the keys of what its peer declares
    /// in: a face past the sets the open lent is handed it as a lent set's is.
    keys: KeySpace,
    /// The session's pools of what its peers write by their own choice, which every face's tables
    /// keep those rows in: a face past the sets the open lent is handed them as a lent set's is.
    pools: PeerPools,
    /// Every set of face tables, each where it was built and never moved from: the sets the arena
    /// lent at the open, the dial role's face's first and always held by it, then any set of no
    /// rows made for a face that came when every lent set was held, which refuses every get and
    /// everything the peer would have it stage, and holds what the peer declares as any set does,
    /// each row in the session's pools and each key in its key arena. The arena lends a set for each
    /// face the config
    /// admits and a face past those is refused before it comes, so no face is expected in a set
    /// of no rows; the session's memory is the arena alone either way. A set no face holds is
    /// kept, emptied, for the next face.
    sets: Vec<FaceTables>,
    /// The sets faces hold, each with its face, in the order of `sets`, which is the order of the
    /// faces: the dial role's face first. Every walk over the faces and every lookup of one reads
    /// this and the held sets alone; the open lends a set for each face the config admits, most of
    /// them free at any time. Its room is reserved at the open for every set the open lent, so a
    /// face coming or going moves entries within it.
    held: Vec<HeldSet>,
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
    /// How many sets the walks over the faces read: what a test of the cost of a walk counts.
    #[cfg(test)]
    set_reads: core::cell::Cell<usize>,
    /// The lent Pushes handed to the subscribers' plane alone ([`Self::dispatch_push`]), the
    /// face lookups their dispatches made with the drains after them, and the lent Pushes that
    /// reached the fan over every plane instead ([`Self::dispatch_event`]): what a test of the
    /// cost of one received sample counts.
    #[cfg(all(test, feature = "std"))]
    pushes: (usize, usize, usize),
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
    /// of each, the pools of what the peers write `peers` counts lent from it next, and the tables
    /// of each face `gets` and `peers` count lent from it too: the dial face's (one of no rows for
    /// a session that dials nothing, `FacePeers::dial`), the session's own gets where it answers
    /// its own, and the rest kept for the faces to come. What the peers
    /// declare keeps its keys in `keys`, the session's key arena, as the session's own
    /// declarations do. Refused when the arena has not the rows, which one reserved by the plan
    /// that counts them always has.
    pub(super) fn new(
        limits: &SessionLimits,
        arena: &mut Arena,
        keys: KeySpace,
        rows: ObserverRows,
        gets: GetTables,
        peers: FacePeers,
    ) -> Result<Self, LendRefused> {
        let app = App::lent(arena, keys, rows, limits)?;
        let mut pools = PeerPools::lent(arena, peers.pools)?;
        // One face's own spans are handed to that face's tables alone, so a plan that lends them
        // lends one set; a build without pools keeps each set's rows inline.
        debug_assert!(!SHARES_ROWS || pools.is_shared() || peers.tables <= 1);
        // The sets are lent in the order the plan counts them: the dial face's, the session's own
        // gets, then the faces to come. A session that dials nothing lent its dial face no set:
        // that face holds one of no rows, first, and every lent set is for the faces to come.
        let dial = usize::from(peers.dial);
        let mut sets = Vec::with_capacity((peers.tables + 1 - dial).max(1));
        let mut held = Vec::with_capacity(sets.capacity());
        if peers.dial {
            lend_set(
                &mut sets, arena, keys, &mut pools, gets.rows, peers.rows, limits,
            )?;
        } else {
            push_unpeered(&mut sets, keys, limits);
        }
        held.push(HeldSet {
            at: 0,
            id: DIAL_FACE,
        });
        #[cfg(feature = "local-queryable")]
        let local = Gets::lent(arena, keys, gets.rows, limits)?;
        for _ in dial..peers.tables {
            lend_set(
                &mut sets, arena, keys, &mut pools, gets.rows, peers.rows, limits,
            )?;
        }
        Ok(Self {
            app,
            sets,
            held,
            limits: *limits,
            keys,
            pools,
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
            #[cfg(test)]
            set_reads: core::cell::Cell::new(0),
            #[cfg(all(test, feature = "std"))]
            pushes: (0, 0, 0),
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
        // Asked from the borrowed key: a poll builds no criterion.
        match plane {
            FilterPlane::Subscribers => self
                .faces()
                .any(|face| face.peer.remote_subscribers.has_matching(keyexpr)),
            #[cfg(any(feature = "query", feature = "queryable"))]
            FilterPlane::Queryables { complete_required } => self.faces().any(|face| {
                face.peer
                    .remote_queryables
                    .answers_query(keyexpr, complete_required)
            }),
            // A build without a querier or a queryable holds no queryable a peer declared.
            #[cfg(not(any(feature = "query", feature = "queryable")))]
            FilterPlane::Queryables { .. } => false,
        }
    }

    /// How often [`Self::peers_declare`] searched what the peers declared.
    #[cfg(all(test, feature = "std"))]
    pub(super) fn peer_looks(&self) -> usize {
        self.peer_looks.get()
    }

    /// The lent Pushes handed to the subscribers' plane alone, the face lookups their dispatches
    /// and drains made, and the lent Pushes the fan over every plane was handed.
    #[cfg(all(test, feature = "std"))]
    pub(super) fn push_dispatches(&self) -> (usize, usize, usize) {
        self.pushes
    }

    /// One more lent Push handed to the subscribers' plane alone, the face lookups since
    /// `written` its own.
    #[cfg(all(test, feature = "std"))]
    fn counted_push(&mut self, written: u64) {
        let lookups =
            usize::try_from(self.faces_written.wrapping_sub(written)).unwrap_or(usize::MAX);
        self.pushes.0 += 1;
        self.pushes.1 += lookups;
    }

    /// The set that lies at `at`, for a walk over the faces.
    fn set(&self, at: usize) -> &FaceTables {
        #[cfg(test)]
        self.set_reads.set(self.set_reads.get() + 1);
        &self.sets[at]
    }

    /// The tables of every face, the dial role's first.
    pub(super) fn faces(&self) -> impl Iterator<Item = &FaceTables> {
        self.held.iter().map(move |held| self.set(held.at))
    }

    /// Where the set face `id` holds lies among the sets, while the session holds the face.
    fn held_at(&self, id: FaceId) -> Option<usize> {
        self.held
            .iter()
            .find(|held| held.id == id)
            .map(|held| held.at)
    }

    /// The tables of face `id`, while the session holds it.
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    pub(super) fn tables_of(&self, id: FaceId) -> Option<&FaceTables> {
        self.held_at(id).map(|at| self.set(at))
    }

    /// The tables of face `id`, while the session holds it, to write.
    fn held_mut(&mut self, id: FaceId) -> Option<&mut FaceTables> {
        let at = self.held_at(id)?;
        Some(&mut self.sets[at])
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
        let gets = HeldMut::of(&mut self.sets, &self.held).map(|face| &mut face.gets);
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
        // The index is in set order with one entry for each held set, so the first entry whose set
        // lies past its own place in the index has a free set at that place, and with none the
        // first free set is the one past the last entry. The lent sets lie first, so the first
        // free set is a lent one while any is free.
        let at = self
            .held
            .iter()
            .enumerate()
            .position(|(place, held)| held.at != place)
            .unwrap_or(self.held.len());
        if at == self.sets.len() {
            // A face past the plan shares the pools of a session of many faces; one face's own
            // spans went to the dial face's tables, so a face past it is handed nothing and holds
            // what its peer writes in nothing.
            push_rowless(&mut self.sets, self.keys, &mut self.pools, &self.limits);
        }
        self.held.insert(at, HeldSet { at, id });
    }

    /// The tables of face `id`, gone with the face and left, emptied, where they lie for the next
    /// face. The dial role's face is never removed.
    pub(super) fn remove_face(&mut self, id: FaceId) {
        if id == DIAL_FACE {
            return;
        }
        if let Some(place) = self.held.iter().position(|held| held.id == id) {
            self.writing();
            let at = self.held.remove(place).at;
            self.sets[at].give_back();
        }
    }

    /// The tables of every face but the dial role's, gone with their faces and left, emptied,
    /// where they lie.
    pub(super) fn remove_accepted_faces(&mut self) {
        self.writing();
        let Self { sets, held, .. } = self;
        held.retain(|face| {
            let accepted = face.id != DIAL_FACE;
            if accepted {
                sets[face.at].give_back();
            }
            !accepted
        });
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

    /// State the answer face `id`'s session gives a query of its peer whose key the face's tables
    /// cannot resolve: the session's policy, held by the face from its link on.
    pub(super) fn set_unanswerable_final(
        &mut self,
        id: FaceId,
        value: wz_session_core::policy::QueryUnanswerableFinal,
    ) {
        if let Some(face) = self.held_mut(id) {
            face.peer.queries.set_unanswerable_final(value);
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
        let Self {
            app, sets, held, ..
        } = self;
        let held = held.as_slice();
        let place = held.iter().position(|face| face.id == id)?;
        let at = held[place].at;
        let (before, rest) = sets.split_at_mut(at);
        let (face, after) = rest.split_first_mut()?;
        Some(Split {
            app,
            face,
            others: Others {
                before: &*before,
                after: &*after,
                held_before: &held[..place],
                held_after: &held[place + 1..],
                after_at: at + 1,
            },
        })
    }

    /// Fan one iteration's event of face `id` into the application layer, against that face's
    /// tables. A face the session no longer holds hears nothing.
    pub(super) fn dispatch_event(&mut self, id: FaceId, event: IterationEvent<'_, '_>) {
        #[cfg(all(test, feature = "std"))]
        if super::lent_push(&event) {
            self.pushes.2 += 1;
        }
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
        self.tables_of(id)
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

    /// A Push of face `id` lent where its frame lies ([`super::lent_push`]), handed to the
    /// subscribers' plane alone, which is the one plane that reads a Push: the fan over every
    /// plane ([`Self::dispatch_event`]) is spared, and so are the watches' staging, which a Push
    /// stages nothing into. What follows the dispatch of every record follows it all the same,
    /// under the one lookup of the face the dispatch made: the subscribers' tables reconciled with
    /// what the application registered since, what anything staged drained through `actions`
    /// ([`Self::flush_pending_replies`]), and the `Final`s owed taken for the caller
    /// ([`Self::take_pending_final_rids`]). A face the session no longer holds hears nothing.
    #[cfg(feature = "queryable")]
    pub(super) fn dispatch_push<S>(
        &mut self,
        id: FaceId,
        event: IterationEvent<'_, '_>,
        actions: &S,
    ) -> FinalStage<Static>
    where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        #[cfg(all(test, feature = "std"))]
        let written = self.faces_written;
        let owed = match self.split(id) {
            Some(Split { app, face, .. }) => {
                app.subscribers
                    .dispatch_iteration_event(&mut face.peer.subscribers, event);
                face.peer.subscribers.reconcile(&app.subscribers);
                app.flush_pending_replies(&mut face.peer, &mut face.gets, actions);
                face.peer.finals.take_owed()
            }
            None => FinalStage::default(),
        };
        #[cfg(all(test, feature = "std"))]
        self.counted_push(written);
        owed
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

    /// [`Self::dispatch`] of a lent Push ([`super::lent_push`]), handed to the subscribers' plane
    /// alone, the one plane that reads a Push, and drained under the one lookup of the face the
    /// dispatch made.
    #[cfg(not(feature = "queryable"))]
    pub(super) fn dispatch_push<S>(
        &mut self,
        id: FaceId,
        event: IterationEvent<'_, '_>,
        actions: &S,
    ) where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        #[cfg(all(test, feature = "std"))]
        let written = self.faces_written;
        if let Some(Split { app, face, .. }) = self.split(id) {
            app.subscribers
                .dispatch_iteration_event(&mut face.peer.subscribers, event);
            face.peer.subscribers.reconcile(&app.subscribers);
            app.flush_pending(&mut face.peer, &mut face.gets, actions);
        }
        #[cfg(all(test, feature = "std"))]
        self.counted_push(written);
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
    #[cfg(any(feature = "query", feature = "queryable"))]
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
        let Self {
            app, sets, held, ..
        } = self;
        let registered = app.liveliness_subscribers.register(
            &sets[0].peer.tokens,
            id,
            keyexpr,
            history,
            sink,
        )?;
        // The dial role's face holds the first set and is the first entry, told above.
        if registered && history {
            for face in &held[1..] {
                app.liveliness_subscribers
                    .replay_known_tokens(&sets[face.at].peer.tokens, id);
            }
        }
        Ok(registered)
    }

    /// Hand liveliness subscriber `id` the tokens every face's peer holds now, as its
    /// registration with `history` does.
    #[cfg(feature = "liveliness")]
    pub(super) fn replay_liveliness_tokens(&mut self, id: u64) {
        let Self {
            app, sets, held, ..
        } = self;
        for face in held.iter() {
            app.liveliness_subscribers
                .replay_known_tokens(&sets[face.at].peer.tokens, id);
        }
    }
}

/// Write a set of no rows at the end of `sets`, in the storage the vector keeps it in, held to
/// `limits`, its peer's keys kept in `keys`, the session's key arena, and what its peer writes in
/// the rows `pools`, the session's, hands it, and hand it back: a set is never a value of its own
/// in this frame. No set is without the key arena, whatever its rows (a lent one, or one of no rows
/// for a face past the plan). A set `pools` hands nothing, a face past a session of one face whose
/// own spans went to the dial face, drops and counts every declaration of its peer.
fn push_rowless<'s>(
    sets: &'s mut Vec<FaceTables>,
    keys: KeySpace,
    pools: &mut PeerPools,
    limits: &SessionLimits,
) -> &'s mut FaceTables {
    let set = push_unpeered(sets, keys, limits);
    set.peer.keep_rows_in(pools);
    set
}

/// Write a set of no rows at the end of `sets` that takes nothing of the session's pools: the dial
/// face's of a session that dials nothing, which never has a peer to write into them. With one
/// face's own spans, taking them here would leave the one face that comes none.
fn push_unpeered<'s>(
    sets: &'s mut Vec<FaceTables>,
    keys: KeySpace,
    limits: &SessionLimits,
) -> &'s mut FaceTables {
    sets.reserve(1);
    let at = sets.len();
    // SAFETY: `reserve` left room for at least one set past the length, which is the first cell of
    // the spare capacity; `rowless_in` writes a whole set there and cannot unwind, so the length may
    // count it.
    unsafe {
        FaceTables::rowless_in(&mut sets.spare_capacity_mut()[0], limits);
        sets.set_len(at + 1);
    }
    let set = &mut sets[at];
    set.peer.keep_keys_in(LentKeys::from(keys));
    set
}

/// Write a set at the end of `sets` and lend it its rows there, `gets` and `peer` of them from
/// `arena`, the peer's keys kept in `keys` and what it writes in `pools`, held to `limits`. A
/// refused set stays in `sets`, whole, and goes with it.
fn lend_set(
    sets: &mut Vec<FaceTables>,
    arena: &mut Arena,
    keys: KeySpace,
    pools: &mut PeerPools,
    gets: RequesterRows,
    peer: PeerRows,
    limits: &SessionLimits,
) -> Result<(), LendRefused> {
    push_rowless(sets, keys, pools, limits).lend(arena, keys, pools, gets, peer, limits)
}

#[cfg(test)]
mod tests {
    //! Each face's tables are lent from the session's arena: the dial face's at the open, an
    //! accepted face's from the spares the open lent, and past those tables of no rows that refuse
    //! what is asked of them: the session takes no memory but its arena.
    use super::*;
    use crate::arena::{AllocatorMemory, SessionArena};
    use wz_session_core::peer_tables::PeerPoolRows;
    use wz_session_core::reply_stage::FinalStaging;
    use wz_session_core::sample::QosLevel;

    /// A registry and the arena its tables were lent from, the registry first so its tables go
    /// before the memory they lie in, and how many sets the open lent rows to.
    struct Held {
        registry: Registry,
        arena: SessionArena,
        lent: usize,
        /// The key arena the registry's tables keep their keys in, lent from `arena`.
        keys: KeySpace,
    }

    /// A registry whose arena lends the tables of `faces` faces, one row of each table, and pools
    /// of sixteen rows of each kind.
    fn held(faces: usize) -> Held {
        held_with(
            faces,
            PeerPoolRows {
                aliases: 16,
                remote_decls: 16,
                interests: 16,
                shared: faces > 1,
            },
        )
    }

    /// A registry whose arena lends the tables of `faces` faces, one row of each table, and the
    /// pools `pools` states, which a registry of more than one face shares.
    fn held_with(faces: usize, pools: PeerPoolRows) -> Held {
        held_as(faces, pools, true)
    }

    /// [`held_with`], the first of the faces' tables the dial face's when `dial`, and with no
    /// dial every one of them kept for the faces to come.
    fn held_as(faces: usize, pools: PeerPoolRows, dial: bool) -> Held {
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
                pending_declares: 1,
                replies: 1,
                reply_bytes: 64,
                finals: 1,
            },
            tables: faces,
            pools,
            dial,
        };
        let keys = arena
            .arena_mut()
            .lend_keys(4096, SessionLimits::defaults().max_keyexpr_bytes_held())
            .expect("the arena holds the key arena");
        let registry = Registry::new(
            &SessionLimits::defaults(),
            arena.arena_mut(),
            keys,
            ObserverRows::default(),
            gets,
            peers,
        )
        .expect("the arena has the rows");
        Held {
            registry,
            arena,
            lent: faces,
            keys,
        }
    }

    fn face(registry: &mut Registry, id: FaceId) -> &mut FaceTables {
        registry.held_mut(id).expect("the registry holds the face")
    }

    /// How many sets the open lent that no face holds: the lent sets lie first.
    fn free_lent(held: &Held) -> usize {
        (0..held.lent)
            .filter(|at| held.registry.held.iter().all(|face| face.at != *at))
            .count()
    }

    /// Whether face `id` holds a set the open lent rows to.
    fn in_a_lent_set(held: &Held, id: FaceId) -> bool {
        held.registry.held_at(id).is_some_and(|at| at < held.lent)
    }

    /// The faces the registry holds, in the order its walks take them.
    fn face_ids(registry: &Registry) -> Vec<FaceId> {
        registry.held.iter().map(|held| held.id).collect()
    }

    /// Where the sets the walk over the faces takes lie.
    fn walked(registry: &Registry) -> Vec<*const FaceTables> {
        registry
            .faces()
            .map(|face| face as *const FaceTables)
            .collect()
    }

    /// Where the sets at `at` lie.
    fn lying_at(registry: &Registry, at: &[usize]) -> Vec<*const FaceTables> {
        at.iter()
            .map(|at| &registry.sets[*at] as *const FaceTables)
            .collect()
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

    /// Every face keeps the keys of what its peer declares in the session's key arena: the dial
    /// face's set, a set the open lent that a face takes as it comes (a group's, which the session
    /// adds as it joins the group, `join_groups`), and a set of no rows for a face past the plan.
    /// A subscriber each face's peer declares is held and matched, its key a block of the one
    /// arena, and nothing is refused.
    #[test]
    fn every_face_keeps_what_its_peer_declares_in_the_sessions_key_arena() {
        use wz_session_core::declare_build::build_declare_subscriber;
        use wz_session_core::key_arena::block_bytes;

        let mut held = held(2);
        held.registry.add_face(5);
        held.registry.add_face(6);
        assert!(
            in_a_lent_set(&held, 5),
            "CONTROL: the second face takes the set the open lent"
        );
        assert!(
            !in_a_lent_set(&held, 6),
            "CONTROL: the third face is past the plan"
        );
        let key = "demo/declared/k";
        let block = block_bytes(key.len()).expect("a short key");
        for (held_before, id) in [DIAL_FACE, 5, 6].into_iter().enumerate() {
            let at = held
                .registry
                .held_at(id)
                .expect("the registry holds the face");
            let Registry { app, sets, .. } = &mut held.registry;
            let set = &mut sets[at];
            let declare = build_declare_subscriber(1, 0, Some(key)).expect("a declaration");
            let peer = &mut set.peer;
            app.remote_subscribers.dispatch_declare(
                &mut peer.remote_subscribers,
                &declare.body,
                peer.subscribers.mapping_spaces(),
            );
            assert!(
                peer.remote_subscribers.has_matching(key),
                "face {id}: its peer's subscriber is held"
            );
            assert_eq!(peer.remote_subscribers.refusals(), 0, "face {id}");
            assert_eq!(
                held.keys.counts().used,
                (held_before + 1) * block,
                "face {id}: its key is a block of the session's key arena"
            );
        }
    }

    /// A session that dials nothing gives its dial face a set of no rows, which takes nothing of the
    /// arena and nothing of the pools: the one set it lent, with one face's own spans, is the first
    /// accepted face's, whose peer's subscriber is held there. The CONTROL is the same plan with
    /// the dial face's set lent, where the first accepted face is past the plan and holds nothing.
    #[test]
    fn a_session_that_dials_nothing_keeps_its_one_set_for_the_face_that_comes() {
        use wz_session_core::declare_build::build_declare_subscriber;

        let own_spans = PeerPoolRows {
            aliases: 16,
            remote_decls: 16,
            interests: 16,
            shared: false,
        };
        let declared = |held: &mut Held, id: FaceId| {
            let key = "demo/declared/one";
            let at = held
                .registry
                .held_at(id)
                .expect("the registry holds the face");
            let Registry { app, sets, .. } = &mut held.registry;
            let peer = &mut sets[at].peer;
            let declare = build_declare_subscriber(1, 0, Some(key)).expect("a declaration");
            app.remote_subscribers.dispatch_declare(
                &mut peer.remote_subscribers,
                &declare.body,
                peer.subscribers.mapping_spaces(),
            );
            (
                peer.remote_subscribers.has_matching(key),
                peer.finals.has_room(),
            )
        };

        let mut dialling = held_as(1, own_spans, true);
        dialling.registry.add_face(5);
        assert_eq!(
            declared(&mut dialling, 5),
            (false, false),
            "CONTROL: the one set is the dial face's, so the face that comes holds nothing"
        );

        let mut listening = held_as(1, own_spans, false);
        let lent = listening.arena.arena_mut().high_water();
        assert_eq!(listening.registry.held_at(DIAL_FACE), Some(0));
        assert!(
            !face(&mut listening.registry, DIAL_FACE)
                .peer
                .finals
                .has_room(),
            "the dial face's set has no rows"
        );
        listening.registry.add_face(5);
        assert_eq!(listening.registry.held_at(5), Some(1));
        assert_eq!(
            declared(&mut listening, 5),
            (true, true),
            "the face that comes takes the lent set and the one face's spans"
        );
        assert_eq!(
            listening.arena.arena_mut().high_water(),
            lent,
            "nothing more is lent as the face comes"
        );
        assert_eq!(listening.registry.sets.len(), 2);
        listening.registry.remove_face(DIAL_FACE);
        assert_eq!(
            face_ids(&listening.registry),
            vec![DIAL_FACE, 5],
            "the dial face stays"
        );
    }

    /// An interest a face's peer asks is kept with its key in the session's key arena, on the
    /// dial face and on a face that takes a lent set as it comes (a group's): the interest's row
    /// holds its key, so the answer staged for it names what it asked. A side whose rows were lent
    /// after it was handed the key arena keeps it.
    #[test]
    fn a_faces_peer_interest_keeps_its_key_in_the_sessions_key_arena() {
        use wz_session_core::key_arena::block_bytes;

        let mut held = held(2);
        held.registry.add_face(5);
        let block = block_bytes("demo/**".len()).expect("a short key");
        for (held_before, id) in [DIAL_FACE, 5].into_iter().enumerate() {
            let at = held
                .registry
                .held_at(id)
                .expect("the registry holds the face");
            let Registry { app, sets, .. } = &mut held.registry;
            let set = &mut sets[at];
            app.subscribers.respond_to_subscriber_interest_borrowed(
                &mut set.peer.subscribers,
                7,
                Some("demo/**"),
                false,
                true,
                false,
            );
            assert_eq!(
                held.keys.counts().used,
                (held_before + 1) * block,
                "face {id}: the interest's key is a block of the session's key arena"
            );
        }
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
        assert_eq!(free_lent(&held), 1);
        held.registry.add_face(5);
        assert_eq!(free_lent(&held), 0);
        assert!(in_a_lent_set(&held, 5));
        let accepted = face(&mut held.registry, 5);
        accepted.peer.finals.owe(1, QosLevel::DEFAULT);
        let lies_at: *const FaceTables = accepted;
        held.registry.remove_face(5);
        assert_eq!(free_lent(&held), 1, "the set went back");
        assert_eq!(held.registry.sets.len(), 2, "and stayed where it lies");
        assert_eq!(
            held.registry.sets[1].peer.finals.owed(),
            0,
            "emptied for the next face"
        );
        assert_eq!(
            face_ids(&held.registry),
            vec![DIAL_FACE],
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
        assert_eq!(free_lent(&held), 2);
        for id in [5, 6] {
            held.registry.add_face(id);
            let accepted = face(&mut held.registry, id);
            accepted.peer.finals.owe(1, QosLevel::DEFAULT);
            assert!(
                !accepted.peer.finals.has_room(),
                "CONTROL: its one row is held"
            );
        }
        assert_eq!(free_lent(&held), 0);
        held.registry.remove_face(5);
        held.registry.remove_accepted_faces();
        assert_eq!(free_lent(&held), 2, "every lent set is free again");
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
        assert_eq!(
            face_ids(&held.registry),
            vec![DIAL_FACE],
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
            pending_declares: 1,
            replies: 1,
            reply_bytes: 64,
            finals: 1,
        };
        // The pools are lent from an arena of their own, so the two arenas compared hold the sets'
        // rows alone.
        // Shared: the set lent by value and the one lent in place both take rows of them.
        let pool_rows = PeerPoolRows {
            aliases: 1,
            remote_decls: 1,
            interests: 1,
            shared: true,
        };
        let mut pool_arena =
            SessionArena::of_bytes(1 << 16, &AllocatorMemory).expect("the host has the memory");
        let mut pools =
            PeerPools::lent(pool_arena.arena_mut(), pool_rows).expect("the arena has the pools");
        let mut by_value_arena =
            SessionArena::of_bytes(1 << 16, &AllocatorMemory).expect("the host has the memory");
        let by_value_keys = by_value_arena
            .arena_mut()
            .lend_keys(256, limits.max_keyexpr_bytes_held())
            .expect("the arena holds the key arena");
        let by_value_gets =
            Gets::lent(by_value_arena.arena_mut(), by_value_keys, gets, &limits).expect("rows");
        let mut by_value_peer = Peer::lent(
            by_value_arena.arena_mut(),
            by_value_keys,
            peer,
            &mut pools,
            &limits,
        )
        .expect("rows");
        let mut arena =
            SessionArena::of_bytes(1 << 16, &AllocatorMemory).expect("the host has the memory");
        let keys = arena
            .arena_mut()
            .lend_keys(256, limits.max_keyexpr_bytes_held())
            .expect("the arena holds the key arena");
        let mut sets = Vec::new();
        lend_set(
            &mut sets,
            arena.arena_mut(),
            keys,
            &mut pools,
            gets,
            peer,
            &limits,
        )
        .expect("the arena has the rows");
        assert_eq!(
            arena.arena_mut().high_water(),
            by_value_arena.arena_mut().high_water(),
            "the same tables lent in the same order take the same bytes"
        );
        let set = &mut sets[0];
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
        assert!(!in_a_lent_set(&held, 5));
        let accepted = face(&mut held.registry, 5);
        assert!(!accepted.peer.finals.has_room());
        assert!(!accepted.gets.replies.has_room());
        assert_eq!(
            held.arena.arena_mut().high_water(),
            lent,
            "no rows were lent"
        );
        held.registry.remove_face(5);
        assert_eq!(free_lent(&held), 0, "no lent set comes of it");
        held.registry.add_face(6);
        assert_eq!(
            held.registry.sets.len(),
            2,
            "the set of no rows was taken again"
        );
        assert!(!face(&mut held.registry, 6).peer.finals.has_room());
    }

    /// The walk over the faces takes exactly the sets faces hold, in set order, as faces come, go
    /// and take a set another left: the next face takes the first free set, in its place among
    /// the others, and a lookup by face finds the set the walk takes for it.
    #[test]
    fn the_walk_takes_the_held_sets_in_set_order() {
        let mut held = held(5);
        for id in [5, 6, 7] {
            held.registry.add_face(id);
        }
        assert_eq!(face_ids(&held.registry), vec![DIAL_FACE, 5, 6, 7]);
        assert_eq!(
            walked(&held.registry),
            lying_at(&held.registry, &[0, 1, 2, 3])
        );
        held.registry.remove_face(6);
        assert_eq!(face_ids(&held.registry), vec![DIAL_FACE, 5, 7]);
        assert_eq!(walked(&held.registry), lying_at(&held.registry, &[0, 1, 3]));
        held.registry.add_face(8);
        assert_eq!(
            face_ids(&held.registry),
            vec![DIAL_FACE, 5, 8, 7],
            "the set the face that went left is taken in its place"
        );
        assert_eq!(
            walked(&held.registry),
            lying_at(&held.registry, &[0, 1, 2, 3])
        );
        let taken = lying_at(&held.registry, &[2])[0];
        assert!(ptr::eq(&*face(&mut held.registry, 8), taken));
        held.registry.remove_face(DIAL_FACE);
        held.registry.remove_accepted_faces();
        assert_eq!(face_ids(&held.registry), vec![DIAL_FACE]);
        assert_eq!(walked(&held.registry), lying_at(&held.registry, &[0]));
        held.registry.add_face(9);
        assert_eq!(face_ids(&held.registry), vec![DIAL_FACE, 9]);
        assert_eq!(walked(&held.registry), lying_at(&held.registry, &[0, 1]));
        assert_eq!(held.registry.sets.len(), 5, "no set was made or dropped");
    }

    /// The faces other than the one a call acts on are the other held sets, in set order, and
    /// none that no face holds.
    #[test]
    fn the_other_faces_are_the_other_held_sets() {
        let mut held = held(6);
        for id in [5, 6, 7, 8] {
            held.registry.add_face(id);
        }
        held.registry.remove_face(5);
        held.registry.remove_face(8);
        let own = lying_at(&held.registry, &[3])[0];
        let others = lying_at(&held.registry, &[0, 2]);
        let Split {
            face, others: seen, ..
        } = held.registry.split(7).expect("the registry holds the face");
        assert!(ptr::eq(&*face, own));
        assert_eq!(seen.faces().size_hint(), (2, Some(2)));
        let seen: Vec<*const FaceTables> =
            seen.faces().map(|face| face as *const FaceTables).collect();
        assert_eq!(seen, others);
    }

    /// Face `id`'s peer declares subscriber `sub` on `key`, dispatched as a link's frame is.
    fn declare_on(registry: &mut Registry, id: FaceId, sub: u64, key: &str) {
        use wz_session_core::declare_build::build_declare_subscriber;

        let at = registry.held_at(id).expect("the registry holds the face");
        let Registry { app, sets, .. } = registry;
        let peer = &mut sets[at].peer;
        let declare = build_declare_subscriber(sub, 0, Some(key)).expect("a declaration");
        app.remote_subscribers.dispatch_declare(
            &mut peer.remote_subscribers,
            &declare.body,
            peer.subscribers.mapping_spaces(),
        );
    }

    /// How many subscribers face `id`'s peer holds, and how many its table refused.
    fn subscribers_of(registry: &Registry, id: FaceId) -> (usize, u32) {
        let at = registry.held_at(id).expect("the registry holds the face");
        let tables = &registry.sets[at].peer.remote_subscribers;
        (tables.declared_count(), tables.refusals())
    }

    /// Eight faces whose peers each declare two subscribers fit the session's pool of sixteen
    /// rows, where the faces' own bounds add up to eight times `MAX_REMOTE_DECLS`; a face past
    /// the plan, in a set of no rows, keeps its peer's in the same pool. The next declaration,
    /// on any face, finds the pool full: it alone is refused, counted by that face's table and by
    /// the pool, and every face keeps what it held.
    #[test]
    fn many_faces_each_declaring_a_few_fit_a_pool_far_smaller_than_their_bounds() {
        if wz_session_core::caps::MAX_REMOTE_DECLS < 3 {
            // A face's table of fewer rows refuses the third declaration by itself.
            return;
        }
        const FACES: u64 = 8;
        let mut held = held_with(
            7,
            PeerPoolRows {
                aliases: 1,
                remote_decls: 16,
                interests: 1,
                shared: true,
            },
        );
        let faces: Vec<FaceId> = core::iter::once(DIAL_FACE)
            .chain(5..5 + FACES - 1)
            .collect();
        for id in &faces[1..] {
            held.registry.add_face(*id);
        }
        assert!(
            !in_a_lent_set(&held, faces[7]),
            "CONTROL: the eighth face is past the plan"
        );
        for id in &faces {
            for sub in 1..=2 {
                declare_on(&mut held.registry, *id, sub, &format!("demo/{id}/{sub}"));
            }
        }
        let pools = held.registry.pools.counts().expect("shared pools");
        assert_eq!((pools.subscribers.used, pools.subscribers.refused), (16, 0));
        for id in &faces {
            assert_eq!(subscribers_of(&held.registry, *id), (2, 0), "face {id}");
        }
        declare_on(&mut held.registry, faces[2], 3, "demo/past");
        assert_eq!(
            subscribers_of(&held.registry, faces[2]),
            (2, 1),
            "the declaration past the pool is refused and counted by its face"
        );
        assert_eq!(
            held.registry
                .pools
                .counts()
                .expect("shared pools")
                .subscribers
                .refused,
            1
        );
        for id in faces.iter().filter(|id| **id != faces[2]) {
            assert_eq!(
                subscribers_of(&held.registry, *id),
                (2, 0),
                "face {id} is untouched"
            );
        }
        assert!(held
            .registry
            .peers_declare(FilterPlane::Subscribers, "demo/5/1"));
        assert!(!held
            .registry
            .peers_declare(FilterPlane::Subscribers, "demo/past"));
    }

    /// A face that goes gives back to the session's pools exactly the rows its peer held, and the
    /// faces that stay keep theirs; the rows it gave back take the next face's declarations, and
    /// the faces past the dial role's all going leaves the dial's alone in the pools.
    #[test]
    fn a_face_that_goes_gives_back_exactly_its_rows() {
        if wz_session_core::caps::MAX_REMOTE_DECLS < 3 {
            // A face's table of fewer rows refuses the third declaration by itself.
            return;
        }
        let mut held = held_with(
            3,
            PeerPoolRows {
                aliases: 1,
                remote_decls: 6,
                interests: 1,
                shared: true,
            },
        );
        held.registry.add_face(5);
        held.registry.add_face(6);
        for (id, count) in [(DIAL_FACE, 1u64), (5, 3), (6, 2)] {
            for sub in 1..=count {
                declare_on(&mut held.registry, id, sub, &format!("demo/{id}/{sub}"));
            }
        }
        assert_eq!(
            held.registry
                .pools
                .counts()
                .expect("shared pools")
                .subscribers
                .used,
            6,
            "CONTROL: the pool is full"
        );
        held.registry.remove_face(5);
        assert_eq!(
            held.registry
                .pools
                .counts()
                .expect("shared pools")
                .subscribers
                .used,
            3,
            "face 5's three rows went back, and only those"
        );
        assert_eq!(subscribers_of(&held.registry, DIAL_FACE), (1, 0));
        assert_eq!(subscribers_of(&held.registry, 6), (2, 0));
        held.registry.add_face(7);
        for sub in 1..=3 {
            declare_on(&mut held.registry, 7, sub, &format!("demo/7/{sub}"));
        }
        assert_eq!(
            subscribers_of(&held.registry, 7),
            (3, 0),
            "the rows given back"
        );
        held.registry.remove_accepted_faces();
        assert_eq!(
            held.registry
                .pools
                .counts()
                .expect("shared pools")
                .subscribers
                .used,
            1,
            "the dial role's row alone is held"
        );
        assert_eq!(
            held.registry
                .pools
                .counts()
                .expect("shared pools")
                .subscribers
                .refused,
            0
        );
    }

    /// A session of one face keeps what its peer writes in spans of its tables' own, which no
    /// pool counts: the dial face's peer is held to its spans' rows, the declaration past them
    /// refused and counted by its table; a face past the plan is handed none of those spans, so
    /// its peer's declaration is refused and counted by its own table and the dial face keeps
    /// every row.
    #[test]
    fn a_session_of_one_face_keeps_its_peers_rows_in_spans_of_its_own() {
        if wz_session_core::caps::MAX_REMOTE_DECLS < 3 {
            // A face's table of fewer rows refuses the third declaration by itself.
            return;
        }
        let mut held = held_with(
            1,
            PeerPoolRows {
                aliases: 1,
                remote_decls: 2,
                interests: 1,
                shared: false,
            },
        );
        assert!(!held.registry.pools.is_shared());
        assert_eq!(held.registry.pools.counts(), None, "no pool to count");
        for sub in 1..=3 {
            declare_on(
                &mut held.registry,
                DIAL_FACE,
                sub,
                &format!("demo/dial/{sub}"),
            );
        }
        assert_eq!(
            subscribers_of(&held.registry, DIAL_FACE),
            (2, 1),
            "the spans' two rows held, the third refused and counted"
        );
        held.registry.add_face(5);
        assert!(!in_a_lent_set(&held, 5), "CONTROL: past the plan");
        declare_on(&mut held.registry, 5, 1, "demo/past/1");
        assert_eq!(subscribers_of(&held.registry, 5), (0, 1));
        assert_eq!(subscribers_of(&held.registry, DIAL_FACE), (2, 1));
        assert!(held
            .registry
            .peers_declare(FilterPlane::Subscribers, "demo/dial/2"));
    }

    /// A walk over the faces reads the sets the faces hold and no other: of the sixteen sets the
    /// open lent, a walk over three faces reads three, and says so before it starts.
    #[test]
    fn a_walk_over_the_faces_reads_the_held_sets_alone() {
        let mut held = held(16);
        held.registry.add_face(5);
        held.registry.add_face(6);
        assert_eq!(
            held.registry.sets.len(),
            16,
            "CONTROL: sixteen sets were lent"
        );
        let before = held.registry.set_reads.get();
        let faces = held.registry.faces();
        assert_eq!(faces.size_hint(), (3, Some(3)));
        assert_eq!(faces.count(), 3);
        assert_eq!(
            held.registry.set_reads.get() - before,
            3,
            "one set read for each face"
        );
        #[cfg(feature = "query")]
        {
            let walked = 3 + usize::from(cfg!(feature = "local-queryable"));
            assert_eq!(held.registry.all_gets().size_hint(), (walked, Some(walked)));
            assert_eq!(
                held.registry.all_gets_mut().size_hint(),
                (walked, Some(walked))
            );
            assert_eq!(held.registry.all_gets_mut().count(), walked);
        }
    }
}
