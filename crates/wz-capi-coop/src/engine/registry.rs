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
use wz_session_core::bounded::{Arena, BoundedVec, LendRefused, Lent};
use wz_session_core::decl_sink::{BoxedDeclSink, BoxedUndeclSink};
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::key_arena::{KeySpace, LentKeys};
use wz_session_core::limits::SessionLimits;
use wz_session_core::peer_tables::{PeerPools, PeerRows, PeerTables, SHARES_ROWS};
use wz_session_core::query_sink::BoxedQuerySink;
use wz_session_core::reply_sink::ConsolidatingSink;
#[cfg(feature = "queryable")]
use wz_session_core::reply_stage::FinalStage;
use wz_session_core::response_sink::{DeclareReplySink, LivelinessGetPrune, ResponseSink};
use wz_session_core::slot_observer::{
    ObserverRows, ObserverSinks, OtherPeers, Requesters, SlotObserverOf,
};
use wz_session_core::wireexpr_resolve::SharedOwnMappingSpace;

use super::{LegSink, SubscriberRow};
use crate::arena::{FacePeers, GetTables, MAX_FACE_SETS};
use wz_capi_port::FilterPlane;
use wz_session_core::locality::Locality;
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

/// The tokens a face that went still owes the liveliness subscribers, held apart from the set it
/// gave back, their rows in the session's pool (`Registry::owed`).
#[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
type OwedTokens = wz_session_core::declare::liveliness_subscriber::PeerTokens<Lent>;

/// The session's own pending gets on one face: a query's sink consolidates what its leg is
/// handed. The rows are lent from the session's arena at its open, one table for each face the
/// session may hold at once (`crate::arena::GetTables`).
pub(super) type Gets = Requesters<ConsolidatingSink<LegSink>, LegSink, Lent>;

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
    /// The face's link was lost and the tokens its peer declared are still to be retracted to the
    /// liveliness subscribers: they stay in `peer` until the round of deliveries has taken each
    /// `Delete` (`Registry::retract_owed`), or until the face goes, when they are kept apart
    /// from the set and the set is given back (`Registry::owe_tokens_of`).
    #[cfg(feature = "liveliness")]
    retracting: bool,
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
            #[cfg(feature = "liveliness")]
            ptr::write(addr_of_mut!((*at).retracting), false);
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
        let Self {
            peer: _,
            gets: _,
            #[cfg(feature = "liveliness")]
                retracting: _,
        } = set;
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
        #[cfg(feature = "liveliness")]
        {
            self.retracting = false;
        }
    }
}

/// The bytes of one set of face tables, a row of the arena's table of them
/// (`crate::arena::ArenaPlan`).
pub(crate) const FACE_SET_BYTES: usize = core::mem::size_of::<FaceTables>();

/// The bytes of one entry of the index of held sets, a row of the arena's table of them.
pub(crate) const HELD_SET_BYTES: usize = core::mem::size_of::<HeldSet>();

#[cfg(any(feature = "listen", feature = "group", test))]
mod adding;

/// A set a face holds: where it lies among the registry's sets, and the face. An entry is two
/// words, so a walk over the faces reads one line of the index for every few faces and then the
/// held sets alone, where a test of each set would read a line of every set the open lent.
#[derive(Clone, Copy, Debug)]
struct HeldSet {
    at: usize,
    id: FaceId,
}

/// Where a liveliness subscriber's history stands ([`Registry::next_history_token`]): the face
/// whose peer's tokens it reads now, by id, and the last token handed from them.
#[cfg(feature = "liveliness")]
#[derive(Clone, Copy, Default)]
pub(super) struct HistoryCursor {
    face: Option<FaceId>,
    after: Option<u64>,
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
    /// The session's pools of what its peers write by their own choice, which every face's tables
    /// keep their rows in from the open on: what a test reads the pools' counts by.
    #[cfg(test)]
    pools: PeerPools,
    /// Every set of face tables, each where it was built and never moved from, in a table the arena
    /// lent at the open with a row for each face the config admits: the dial role's face's first
    /// and always held by it, then the faces to come. A face past them is refused
    /// (`FacesFull`), so the session's memory is the arena alone. A set no face holds is kept,
    /// emptied, for the next face.
    sets: BoundedVec<FaceTables, MAX_FACE_SETS, Lent>,
    /// The sets faces hold, each with its face, in the order of `sets`, which is the order of the
    /// faces: the dial role's face first. Every walk over the faces and every lookup of one reads
    /// this and the held sets alone; the open lends a set for each face the config admits, most of
    /// them free at any time. Its room is reserved at the open for every set the open lent, so a
    /// face coming or going moves entries within it.
    held: BoundedVec<HeldSet, MAX_FACE_SETS, Lent>,
    /// The tokens of faces that went before each was retracted, in the order the faces went: each
    /// the token table the face's set held, its rows still in the session's pool, the set given
    /// back as the face went. Lent at the open, a row for each row of the session's token pool,
    /// as a table owed holds one of them at least (`FacePeers::owed_tokens`); none for a session
    /// of one face, whose one face never goes. A session of no face besides the dial role's (a
    /// build without `listen` and `group`) removes none, and keeps no table of them.
    #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
    owed: BoundedVec<OwedTokens, { wz_session_core::caps::SESSION_MAX_REMOTE_DECLS }, Lent>,
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
    /// of each face `gets` and `peers` count lent from it too: the dial face's, the session's own
    /// gets where it answers its own, and the rest kept for the faces to come. What the peers
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
        #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
        let owed = arena.lend(peers.owed_tokens())?;
        // One face's own spans are handed to that face's tables alone, so a plan that lends them
        // lends one set; a build without pools keeps each set's rows inline.
        debug_assert!(!SHARES_ROWS || pools.is_shared() || peers.tables <= 1);
        // The sets are lent in the order the plan counts them: the dial face's, the session's own
        // gets, then the faces to come.
        let mut sets = arena.lend(peers.tables.max(1))?;
        let mut held: BoundedVec<HeldSet, MAX_FACE_SETS, Lent> = arena.lend(peers.tables.max(1))?;
        lend_set(
            &mut sets, arena, keys, &mut pools, gets.rows, peers.rows, limits,
        )?;
        held.push(HeldSet {
            at: 0,
            id: DIAL_FACE,
        })
        .map_err(|_| LendRefused::OverCeiling {
            rows: 1,
            ceiling: 0,
        })?;
        #[cfg(feature = "local-queryable")]
        let local = Gets::lent(arena, keys, gets.rows, limits)?;
        for _ in 1..peers.tables {
            lend_set(
                &mut sets, arena, keys, &mut pools, gets.rows, peers.rows, limits,
            )?;
        }
        Ok(Self {
            app,
            sets,
            held,
            #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
            owed,
            #[cfg(test)]
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
        match plane {
            FilterPlane::Subscribers => {
                let subscribers = PublisherCriterion::new(keyexpr, Locality::Remote);
                self.faces()
                    .any(|face| face.peer.remote_subscribers.has_matching_for(&subscribers))
            }
            #[cfg(any(feature = "query", feature = "queryable"))]
            FilterPlane::Queryables { complete_required } => {
                let queryables =
                    QuerierCriterion::new(keyexpr, Locality::Remote, complete_required);
                self.faces()
                    .any(|face| face.peer.remote_queryables.has_matching_for(&queryables))
            }
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

    /// The tables of face `id`, gone with the face and left, emptied, where they lie for the next
    /// face. The dial role's face is never removed.
    pub(super) fn remove_face(&mut self, id: FaceId) {
        if id == DIAL_FACE {
            return;
        }
        if let Some(place) = self.held.iter().position(|held| held.id == id) {
            self.writing();
            let gone = self.held.remove(place);
            #[cfg(feature = "liveliness")]
            self.owe_tokens_of(gone.at);
            self.sets[gone.at].give_back();
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
        #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
        self.owed.clear();
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
        let Self {
            app, sets, held, ..
        } = self;
        let held: &[HeldSet] = &held[..];
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
    /// subscribers are to be told each is. The face's set owes them the retractions until
    /// `Self::retract_owed` has handed every one, or the face goes and they are owed apart.
    #[cfg(feature = "liveliness")]
    pub(super) fn lose_tokens(&mut self, id: FaceId) {
        if let Some(face) = self.held_mut(id) {
            face.retracting = true;
        }
    }

    /// Retract the tokens of every face whose link was lost, a token at a time while `room` says
    /// its `Delete` can be taken now: those of the faces held first, then those of the faces that
    /// went, in the order they went, each face's in ascending id. Whether none is owed any more.
    /// The tokens left wait where they are, in order.
    #[cfg(feature = "liveliness")]
    pub(super) fn retract_owed(&mut self, room: &mut dyn FnMut() -> bool) -> bool {
        self.writing();
        let Self {
            app,
            sets,
            held,
            #[cfg(any(feature = "listen", feature = "group"))]
            owed,
            ..
        } = self;
        for face in held.iter() {
            let Some(set) = sets.get_mut(face.at) else {
                continue;
            };
            if set.retracting {
                set.retracting = !app.flush_liveliness_on_link_loss_while(&mut set.peer, room);
                if set.retracting {
                    return false;
                }
            }
        }
        // The faces that went, in the order they went.
        #[cfg(any(feature = "listen", feature = "group"))]
        while let Some(tokens) = owed.first_mut() {
            if !app.flush_tokens_on_link_loss_while(tokens, room) {
                return false;
            }
            owed.remove(0);
        }
        true
    }

    /// Keep apart what the set at `at` still owes the liveliness subscribers as its face goes:
    /// the tokens of a lost link not retracted yet, which [`Self::retract_owed`] hands after those
    /// owed before them. The set is given back all the same, its token table left empty and taking
    /// rows of the session's pool.
    #[cfg(feature = "liveliness")]
    fn owe_tokens_of(&mut self, at: usize) {
        let Some(set) = self.sets.get_mut(at) else {
            return;
        };
        if !core::mem::take(&mut set.retracting) {
            return;
        }
        #[cfg(any(feature = "listen", feature = "group"))]
        if let Some(tokens) = set.peer.tokens.split_off() {
            if tokens.count() > 0 {
                // A table owed holds a row of the session's token pool at least, and the open lent
                // a row of this table for each row of the pool.
                let kept = self.owed.push(tokens).is_ok();
                debug_assert!(kept, "the tokens owed fit the rows of the pool they hold");
            }
        }
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

    /// Register a liveliness subscriber, with `history` marked as one owed the tokens every face's
    /// peer already holds, which its declaration hands it after this, with no lock of the session
    /// held, one at a time ([`Self::next_history_token`]), before the peers are asked for the rest.
    #[cfg(feature = "liveliness")]
    pub(super) fn register_liveliness_subscriber(
        &mut self,
        id: u64,
        keyexpr: &str,
        history: bool,
        sink: wz_session_core::declare::liveliness_sample::BoxedLivelinessSampleSink,
    ) -> Result<bool, RegisterError> {
        self.app
            .liveliness_subscribers
            .register_unreplayed(id, keyexpr, history, sink)
    }

    /// The token liveliness subscriber `id` is owed next by its history, from where `cursor`
    /// stands: the faces in ascending id, and on each the token of the lowest id above the last one
    /// handed that its peer holds and the subscriber's pattern matches. With it, the cursor to ask
    /// for the one after; `None` once every face is read. A face that came up since is read in its
    /// turn, and one that went down is passed over.
    #[cfg(feature = "liveliness")]
    pub(super) fn next_history_token(
        &self,
        id: u64,
        cursor: HistoryCursor,
    ) -> Option<(HistoryCursor, u64, &str)> {
        let mut face = match cursor.face {
            Some(face) => face,
            None => self.held.iter().map(|held| held.id).min()?,
        };
        let mut after = cursor.after;
        loop {
            let tokens = self
                .held
                .iter()
                .find(|held| held.id == face)
                .and_then(|held| self.sets.get(held.at))
                .map(|set| &set.peer.tokens);
            if let Some(tokens) = tokens {
                if let Some((token, key)) = self
                    .app
                    .liveliness_subscribers
                    .next_known_token(tokens, id, after)
                {
                    let next = HistoryCursor {
                        face: Some(face),
                        after: Some(token),
                    };
                    return Some((next, token, key));
                }
            }
            face = self
                .held
                .iter()
                .map(|held| held.id)
                .filter(|held| *held > face)
                .min()?;
            after = None;
        }
    }
}

/// Write a set of no rows in the next row of `sets`, held to `limits`, its peer's keys kept in
/// `keys`, the session's key arena, and what its peer writes in the rows `pools`, the session's,
/// hands it, and hand it back: a set is never a value of its own in this frame. `None` when
/// `sets` holds every row it was lent.
fn push_rowless<'s>(
    sets: &'s mut BoundedVec<FaceTables, MAX_FACE_SETS, Lent>,
    keys: KeySpace,
    pools: &mut PeerPools,
    limits: &SessionLimits,
) -> Option<&'s mut FaceTables> {
    // SAFETY: `rowless_in` writes a whole set into the row it is handed and cannot unwind.
    let set = unsafe {
        sets.push_in_place(|place| {
            FaceTables::rowless_in(place, limits);
        })
    }?;
    set.peer.keep_keys_in(LentKeys::from(keys));
    set.peer.keep_rows_in(pools);
    Some(set)
}

/// Write a set at the end of `sets` and lend it its rows there, `gets` and `peer` of them from
/// `arena`, the peer's keys kept in `keys` and what it writes in `pools`, held to `limits`. A
/// refused set stays in `sets`, whole, and goes with it.
fn lend_set(
    sets: &mut BoundedVec<FaceTables, MAX_FACE_SETS, Lent>,
    arena: &mut Arena,
    keys: KeySpace,
    pools: &mut PeerPools,
    gets: RequesterRows,
    peer: PeerRows,
    limits: &SessionLimits,
) -> Result<(), LendRefused> {
    let at = sets.len();
    let set = push_rowless(sets, keys, pools, limits).ok_or(LendRefused::OverCeiling {
        rows: at.saturating_add(1),
        ceiling: at,
    })?;
    set.lend(arena, keys, pools, gets, peer, limits)
}

#[cfg(test)]
mod tests {
    //! Each face's tables are lent from the session's arena: the dial face's at the open, an
    //! accepted face's from the spares the open lent, and past those tables of no rows that refuse
    //! what is asked of them: the session takes no memory but its arena.
    use super::adding::FacesFull;
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
    /// face's set and the sets the open lent that faces take as they come (a group's, which the
    /// session adds as it joins the group, `join_groups`). A subscriber each face's peer declares
    /// is held and matched, its key a block of the one arena, and nothing is refused.
    #[test]
    fn every_face_keeps_what_its_peer_declares_in_the_sessions_key_arena() {
        use wz_session_core::declare_build::build_declare_subscriber;
        use wz_session_core::key_arena::block_bytes;

        let mut held = held(3);
        held.registry
            .add_face(5)
            .expect("the open lent a set for the face");
        held.registry
            .add_face(6)
            .expect("the open lent a set for the face");
        assert!(
            in_a_lent_set(&held, 5) && in_a_lent_set(&held, 6),
            "CONTROL: each face takes a set the open lent"
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

    /// An interest a face's peer asks is kept with its key in the session's key arena, on the
    /// dial face and on a face that takes a lent set as it comes (a group's): the interest's row
    /// holds its key, so the answer staged for it names what it asked. A side whose rows were lent
    /// after it was handed the key arena keeps it.
    #[test]
    fn a_faces_peer_interest_keeps_its_key_in_the_sessions_key_arena() {
        use wz_session_core::key_arena::block_bytes;

        let mut held = held(2);
        held.registry
            .add_face(5)
            .expect("the open lent a set for the face");
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
        held.registry
            .add_face(5)
            .expect("the open lent a set for the face");
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
        held.registry
            .add_face(6)
            .expect("the open lent a set for the face");
        let next = face(&mut held.registry, 6);
        assert!(ptr::eq(&*next, lies_at), "the next face took the same set");
        holds_one_final(next);
    }

    /// A face that goes owing retractions gives its set back at once, and the next face takes it,
    /// its token table empty; the tokens owed wait apart, their rows kept in the session's pool,
    /// and are retracted in the order the faces went, each face's in ascending id. The CONTROL is
    /// a retraction refused for room, which hands nothing and keeps every token owed.
    #[cfg(all(
        feature = "std",
        feature = "liveliness",
        any(feature = "listen", feature = "group")
    ))]
    #[test]
    fn a_face_that_goes_owing_retractions_gives_its_set_back_at_once() {
        use std::sync::{Arc, Mutex};
        use wz_session_core::declare::liveliness_sample::{
            BoxedLivelinessSampleSink, LivelinessSample, LivelinessSampleKind,
        };
        use wz_session_core::declare_build::build_declare_token;

        let mut held = held(3);
        let heard: Arc<Mutex<Vec<(String, u64)>>> = Arc::default();
        let into = Arc::clone(&heard);
        held.registry
            .register_liveliness_subscriber(
                1,
                "demo/**",
                false,
                BoxedLivelinessSampleSink::new(move |sample: LivelinessSample<'_>| {
                    if sample.kind == LivelinessSampleKind::Delete {
                        into.lock()
                            .unwrap()
                            .push((sample.keyexpr.to_owned(), sample.token_id));
                    }
                }),
            )
            .expect("the subscriber is registered");
        held.registry
            .add_face(5)
            .expect("the open lent a set for the face");
        held.registry
            .add_face(6)
            .expect("the open lent a set for the face");
        for (id, tokens) in [(5, [3_u64, 1]), (6, [4, 2])] {
            let at = held
                .registry
                .held_at(id)
                .expect("the registry holds the face");
            let Registry { app, sets, .. } = &mut held.registry;
            let peer = &mut sets[at].peer;
            for token in tokens {
                let key = std::format!("demo/{id}/{token}");
                let declare = build_declare_token(token, 0, Some(&key)).expect("a declaration");
                app.liveliness_subscribers.dispatch_declare(
                    &mut peer.tokens,
                    &declare.body,
                    peer.subscribers.mapping_spaces(),
                );
            }
            assert_eq!(peer.tokens.count(), 2, "face {id} holds its peer's tokens");
        }
        let lies_at: *const FaceTables = face(&mut held.registry, 5);
        held.registry.lose_tokens(5);
        held.registry.lose_tokens(6);
        held.registry.remove_face(5);
        held.registry.remove_face(6);
        assert_eq!(held.registry.owed.len(), 2, "each face's tokens owed apart");
        let tokens_used = |held: &Held| held.registry.pools.counts().map(|c| c.tokens.used);
        assert_eq!(
            tokens_used(&held),
            Some(4),
            "their rows kept in the session's pool"
        );
        assert!(
            !held.registry.retract_owed(&mut || false),
            "CONTROL: no room, so still owed"
        );
        assert!(heard.lock().unwrap().is_empty(), "CONTROL: nothing handed");
        held.registry
            .add_face(7)
            .expect("the open lent a set for the face");
        let next: *const FaceTables = face(&mut held.registry, 7);
        assert!(
            ptr::eq(next, lies_at),
            "the next face took the set given back"
        );
        assert_eq!(
            face(&mut held.registry, 7).peer.tokens.count(),
            0,
            "its token table empty"
        );
        assert!(
            held.registry.retract_owed(&mut || true),
            "every token retracted"
        );
        assert_eq!(
            *heard.lock().unwrap(),
            [
                ("demo/5/1".to_owned(), 1),
                ("demo/5/3".to_owned(), 3),
                ("demo/6/2".to_owned(), 2),
                ("demo/6/4".to_owned(), 4),
            ],
            "in the order the faces went, each face's in ascending id"
        );
        assert!(held.registry.owed.is_empty());
        assert_eq!(tokens_used(&held), Some(0), "and their rows went back");
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
            held.registry
                .add_face(id)
                .expect("the open lent a set for the face");
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
        // The table of sets lies in an arena of its own, so `arena` counts the set's rows alone.
        let mut sets_arena = SessionArena::of_bytes(
            FACE_SET_BYTES + wz_session_core::bounded::ARENA_ALIGN,
            &AllocatorMemory,
        )
        .expect("the host has the memory");
        let mut sets: BoundedVec<FaceTables, MAX_FACE_SETS, Lent> = sets_arena
            .arena_mut()
            .lend(1)
            .expect("the arena has a row for the set");
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

    /// A face past the sets the open lent is refused and nothing is lent or held for it: the
    /// session refuses it as one past `max_faces`. The CONTROL is the same face once a set is
    /// free again, which takes it.
    #[test]
    fn a_face_past_the_plan_is_refused() {
        let mut held = held(2);
        held.registry
            .add_face(5)
            .expect("the open lent a set for the face");
        let lent = held.arena.arena_mut().high_water();
        assert_eq!(held.registry.add_face(6), Err(FacesFull));
        assert!(held.registry.held_at(6).is_none(), "no set is held for it");
        assert_eq!(
            held.arena.arena_mut().high_water(),
            lent,
            "no rows were lent"
        );
        assert_eq!(held.registry.sets.len(), 2, "the sets are the open's");
        held.registry.remove_face(5);
        assert_eq!(
            held.registry.add_face(6),
            Ok(()),
            "CONTROL: a set is free again"
        );
        assert!(in_a_lent_set(&held, 6));
    }

    /// The walk over the faces takes exactly the sets faces hold, in set order, as faces come, go
    /// and take a set another left: the next face takes the first free set, in its place among
    /// the others, and a lookup by face finds the set the walk takes for it.
    #[test]
    fn the_walk_takes_the_held_sets_in_set_order() {
        let mut held = held(5);
        for id in [5, 6, 7] {
            held.registry
                .add_face(id)
                .expect("the open lent a set for the face");
        }
        assert_eq!(face_ids(&held.registry), vec![DIAL_FACE, 5, 6, 7]);
        assert_eq!(
            walked(&held.registry),
            lying_at(&held.registry, &[0, 1, 2, 3])
        );
        held.registry.remove_face(6);
        assert_eq!(face_ids(&held.registry), vec![DIAL_FACE, 5, 7]);
        assert_eq!(walked(&held.registry), lying_at(&held.registry, &[0, 1, 3]));
        held.registry
            .add_face(8)
            .expect("the open lent a set for the face");
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
        held.registry
            .add_face(9)
            .expect("the open lent a set for the face");
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
            held.registry
                .add_face(id)
                .expect("the open lent a set for the face");
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
    /// rows, where the faces' own bounds add up to eight times `MAX_REMOTE_DECLS`. The next
    /// declaration, on any face, finds the pool full: it alone is refused, counted by that face's
    /// table and by the pool, and every face keeps what it held.
    #[test]
    fn many_faces_each_declaring_a_few_fit_a_pool_far_smaller_than_their_bounds() {
        if wz_session_core::caps::MAX_REMOTE_DECLS < 3 {
            // A face's table of fewer rows refuses the third declaration by itself.
            return;
        }
        const FACES: u64 = 8;
        let mut held = held_with(
            8,
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
            held.registry
                .add_face(*id)
                .expect("the open lent a set for the face");
        }
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
        held.registry
            .add_face(5)
            .expect("the open lent a set for the face");
        held.registry
            .add_face(6)
            .expect("the open lent a set for the face");
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
        held.registry
            .add_face(7)
            .expect("the open lent a set for the face");
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
    /// refused and counted by its table. A face past the plan is refused, and the dial face keeps
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
        assert_eq!(
            held.registry.add_face(5),
            Err(FacesFull),
            "CONTROL: no set past the plan"
        );
        assert_eq!(subscribers_of(&held.registry, DIAL_FACE), (2, 1));
        assert!(held
            .registry
            .peers_declare(FilterPlane::Subscribers, "demo/dial/2"));
    }

    /// A MEASUREMENT of the bytes one set of face tables takes, by table, and of the header of a lent
    /// table and of a key arena's handle, which every table of a set repeats: what a shrink of the
    /// set is read from. It asserts only that the tables printed add up to no more than the set.
    #[cfg(feature = "std")]
    #[test]
    fn a_face_sets_bytes_by_table() {
        use core::mem::{size_of, size_of_val};

        let mut held = held(1);
        let set = face(&mut held.registry, DIAL_FACE);
        let peer = &set.peer;
        let tables = [
            ("peer.subscribers", size_of_val(&peer.subscribers)),
            (
                "peer.remote_subscribers",
                size_of_val(&peer.remote_subscribers),
            ),
            (
                "peer.remote_queryables",
                size_of_val(&peer.remote_queryables),
            ),
            ("peer.tokens", size_of_val(&peer.tokens)),
            ("peer.replies", size_of_val(&peer.replies)),
            ("peer.finals", size_of_val(&peer.finals)),
            ("gets.replies", size_of_val(&set.gets.replies)),
        ];
        std::println!("face set: {} B", size_of_val(&*set));
        for (table, bytes) in tables {
            std::println!("  {table}: {bytes} B");
        }
        std::println!(
            "  a lent table's header: {} B; a key arena's handle: {} B",
            size_of::<BoundedVec<u8, 1, Lent>>(),
            size_of::<LentKeys>()
        );
        let printed: usize = tables.iter().map(|(_, bytes)| bytes).sum();
        assert!(printed <= size_of_val(&*set));
    }

    /// A walk over the faces reads the sets the faces hold and no other: of the sixteen sets the
    /// open lent, a walk over three faces reads three, and says so before it starts.
    #[test]
    fn a_walk_over_the_faces_reads_the_held_sets_alone() {
        let mut held = held(16);
        held.registry
            .add_face(5)
            .expect("the open lent a set for the face");
        held.registry
            .add_face(6)
            .expect("the open lent a set for the face");
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
