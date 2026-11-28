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
//!   session's arena, which the open reserves one set for each face it may hold at once in, a set
//!   built in its place as the first face takes it and a face giving it back, emptied, when it
//!   goes. A set is built where the registry keeps it and never moved from there
//!   (`FaceTables::rowless_in`).
//!
//! What a peer writes by its own choice (its aliases, its declarations and the repeats of them,
//! its interests) is not lent to each set at the bound of one peer: each kind of row lies in one
//! pool of the session's (`PeerPools`), lent at the open as the sets are, and a face's tables
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
//! its own (`held::OtherFaces`, `slot_observer::OtherPeers`).

#[cfg(any(
    feature = "remote-declaration-watch",
    feature = "declarations-synced-event"
))]
use super::decl_watch::WatchObserver;
use wz_session_core::bounded::BoundedVec;
#[cfg(feature = "queryable")]
use wz_session_core::bounded::Static;
#[cfg(wz_lent)]
use wz_session_core::bounded::{Arena, LendRefused, RowCount, TableLender};
#[cfg(any(feature = "query", not(wz_round)))]
use wz_session_core::driver_loop::InPlaceRecord;

use crate::RowPolicy;
use wz_session_core::driver_loop::IterationEvent;
#[cfg(wz_lent)]
use wz_session_core::key_arena::{lend_region, KeySpace, LentKeys};
#[cfg(feature = "multicast-declarations")]
use wz_session_core::limit_binding::Quota;
#[cfg(feature = "multicast-declarations")]
use wz_session_core::limits::MaxPeerKeyexprAliasesHeld;
use wz_session_core::limits::SessionLimits;
#[cfg(wz_lent)]
use wz_session_core::peer_tables::PeerPools;
use wz_session_core::peer_tables::PeerTables;
#[cfg(wz_lent)]
use wz_session_core::peer_tables::{PeerRows, SHARES_ROWS};
#[cfg(not(wz_round))]
use wz_session_core::pubsub::LentPush;
#[cfg(feature = "queryable")]
use wz_session_core::reply_stage::FinalStage;
use wz_session_core::response_sink::{DeclareReplySink, LivelinessGetPrune, ResponseSink};
#[cfg(not(feature = "query"))]
use wz_session_core::slot_observer::NoRequesters;
#[cfg(not(any(
    feature = "remote-declaration-watch",
    feature = "declarations-synced-event"
)))]
use wz_session_core::slot_observer::NoSink;
#[cfg(any(feature = "listen", feature = "group"))]
use wz_session_core::slot_observer::OtherPeers;
use wz_session_core::slot_observer::{ObserverSinks, SlotObserverOf, TakenAhead};

#[cfg(wz_lent)]
use super::CoopTables;
#[cfg(feature = "query")]
use super::GetCall;
use super::{RoundDelivery, SubscriberRow};
use crate::arena::MAX_FACE_SETS;
#[cfg(wz_lent)]
use crate::arena::{FacePeers, GetTables};
#[cfg(feature = "query")]
use wz_session_core::get_legs::GetLegs;
#[cfg(feature = "query")]
use wz_session_core::session_tables::PendingGetHandle;
#[cfg(wz_lent)]
use wz_session_core::slot_observer::RequesterRows;

use wz_session_core::declare::matching::MatchingSink;
use wz_session_core::pending_get::SessionFaces;
use wz_session_core::session_tables::{PeerDeclarations, Plane};

#[allow(unused_imports)]
use crate::prelude::*;
use core::mem::{ManuallyDrop, MaybeUninit};
#[cfg(wz_lent)]
use core::ptr::NonNull;
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

/// The session's own gets as one face holds them: the legs its peer answers, each naming its
/// get's row in the session's tables, and the read of that peer's Responses (`GetLegs`); with
/// `liveliness-get`, the legs of its snapshots, answered under the Interest each asked. What a
/// get is (its gate, consolidation, deadline, callback and the Finals it is owed) is its row's;
/// the engine hands every reply and Final of the face to these legs itself, in both forms, so the
/// observer's fan carries none. The rows are lent from the session's arena at its open, one set
/// for each face the session may hold at once (`crate::arena::GetTables`).
#[cfg(feature = "query")]
#[derive(Default)]
pub(super) struct Gets {
    /// The legs of the session's queries on the face, under their request ids.
    pub(super) legs: GetLegs<PendingGetHandle, RowPolicy>,
    /// The legs of the session's liveliness snapshots on the face, under their Interest ids.
    #[cfg(feature = "liveliness-get")]
    pub(super) snapshots: GetLegs<PendingGetHandle, RowPolicy, SNAPSHOT_LEGS>,
}

/// The most legs of the session's liveliness snapshots one face holds: a snapshot has at most one
/// leg on a face, so no more than the session holds pending.
#[cfg(feature = "liveliness-get")]
const SNAPSHOT_LEGS: usize = wz_session_core::caps::MAX_PENDING_LIVELINESS_GETS;

#[cfg(feature = "query")]
impl Gets {
    /// Forget every leg of `get`, which its row retired: no Final it is still owed is waited on.
    pub(super) fn forget(&mut self, get: PendingGetHandle) {
        self.legs.forget(get);
        #[cfg(feature = "liveliness-get")]
        self.snapshots.forget(get);
    }

    /// The face went: every leg ends, each get handed to `ended` once for each leg it had here,
    /// for the caller to end that leg on the get's row.
    pub(super) fn end_every_leg(&mut self, mut ended: impl FnMut(PendingGetHandle)) {
        self.legs.end_every_leg(&mut ended);
        #[cfg(feature = "liveliness-get")]
        self.snapshots.end_every_leg(&mut ended);
    }

    /// Hold no leg, keeping the rows: the set of a face that went, given back for the next once
    /// its legs were ended on their gets' rows (`Registry::end_legs_of`).
    pub(super) fn clear(&mut self) {
        self.end_every_leg(|_| {});
    }
}

/// Admit `reply` to the get `get` names under its standing, gate and consolidation
/// (`SessionTables::admit_reply`): the call begun on its row for a reply let through, to make once
/// the session is let go of; none for one held back or dropped.
#[cfg(feature = "query")]
fn admit_to(
    tables: &mut super::CoopTables,
    get: PendingGetHandle,
    reply: &dyn wz_session_core::reply_sink::ReplyView,
) -> Option<GetCall> {
    match tables.admit_reply(get, reply) {
        wz_session_core::session_tables::ReplyAdmitted::Passed(call) => call.map(GetCall::new),
        wz_session_core::session_tables::ReplyAdmitted::Held
        | wz_session_core::session_tables::ReplyAdmitted::Dropped => None,
    }
}

/// The legs on one face of the session's gets made by value, each table taking its rows at its
/// first leg.
#[cfg(all(feature = "query", wz_on_use))]
impl Gets {
    /// No leg held, the queries' legs at most `rows.queries` and, with `liveliness-get`, the
    /// snapshots' at most `rows.liveliness_gets`. A leg keeps no key and states no quota (its
    /// get's row does), so `keys` and `limits` hold nothing of it.
    pub(super) fn counted(
        _keys: wz_session_core::on_use::BudgetKeys,
        rows: wz_session_core::slot_observer::RequesterRows,
        _limits: &SessionLimits,
    ) -> Self {
        Self {
            legs: GetLegs::counted(rows.queries),
            #[cfg(feature = "liveliness-get")]
            snapshots: GetLegs::counted(rows.liveliness_gets),
        }
    }
}

/// The interest id of a snapshot's leg as its face's legs key it: the id the Interest carries on
/// the wire.
#[cfg(feature = "liveliness-get")]
pub(super) const fn snapshot_leg(interest_id: u64) -> wz_session_core::wire_id::RequestId {
    wz_session_core::wire_id::interest_id_as_read(interest_id)
}

/// A face's legs to the observer's fan: the engine hands every reply, token and Final its faces
/// read to their legs and the gets' rows itself, in both forms (`Registry::dispatch_event_to`),
/// so the fan hands them none; it only keeps a token that answers a pending snapshot from the
/// liveliness subscribers.
#[cfg(feature = "query")]
impl wz_session_core::slot_observer::RequesterTables for Gets {
    #[cfg(feature = "liveliness-get")]
    fn claims(&self, interest_id: u64) -> bool {
        self.snapshots.get_of(snapshot_leg(interest_id)).is_some()
    }

    fn dispatch_iteration_event<
        T: wz_session_core::bounded::Storage,
        O: wz_session_core::bounded::Storage,
    >(
        &mut self,
        _event: IterationEvent<'_, '_>,
        _peer_table: wz_session_core::wireexpr_resolve::MappingSpaces<'_, T, O>,
    ) {
    }

    fn dispatch_finals_of(&mut self, _event: IterationEvent<'_, '_>) {}

    // A snapshot's end stages no prune: the engine declares again from its own entries, and keeps
    // no cache of the Interests it asked.
    #[cfg(feature = "liveliness-get")]
    fn has_finalized(&self) -> bool {
        false
    }

    #[cfg(feature = "liveliness-get")]
    fn drain_prunes<S: LivelinessGetPrune>(&mut self, _sink: &S) {}
}

/// A session that asks no query has no pending get on any face: its requester side is none, and
/// the observer's fan and drains keep no path for gets.
#[cfg(not(feature = "query"))]
pub(super) type Gets = NoRequesters;

/// What a face's peer writes and is owed. The rows are lent from the session's arena at its open,
/// one set for each face the session may hold at once (`crate::arena::FacePeers`).
pub(super) type Peer = PeerTables<RowPolicy>;

/// What a lent Push's sample borrows beside the frame and the face's peer, held by the walk that
/// hands it out (`pinned`).
#[cfg(not(wz_round))]
pub(super) type PeerRoom = wz_session_core::pubsub::LentRoom<RowPolicy>;

/// What the session holds for one face: what its peer wrote and what the session asked of it.
///
/// A set is built where the registry keeps it (`Self::rowless_in`, or over the region's zero bytes
/// `Self::rowless_over_zero`, then `Self::lend`) and is never moved from there: a face that comes
/// takes a set where it lies and one that goes empties it there, its rows of the session's pools
/// going back to them. A set holds a few words for each of its tables, and the session's tables
/// are placed once and not moved.
/// Which face holds a set is the mark of its place in the registry's table of places, not the
/// set's: a walk over the faces reads no set to learn whether a face holds it.
pub(super) struct FaceTables {
    pub(super) peer: Peer,
    pub(super) gets: Gets,
    /// The face's link was lost and the tokens its peer declared are still to be retracted to the
    /// liveliness subscribers: they stay in `peer` until each `Delete` is taken, by the round of
    /// deliveries (`Registry::retract_owed`) or by a read that hands each itself
    /// (`Registry::take_lost_token`), or until the face goes, when they are kept apart
    /// from the set and the set is given back (`Registry::owe_tokens_of`).
    #[cfg(feature = "liveliness")]
    retracting: bool,
}

impl FaceTables {
    /// Write every field of the set at `at` but its peer's tables, each once, through a pointer to
    /// it: gets of no rows, no deadline, nothing being retracted. What the two ways a set is made
    /// share; each writes or keeps the peer's tables itself.
    ///
    /// # Safety
    /// `at` is valid for writes of a `Self` and aligned for it.
    unsafe fn write_unpeered(at: *mut Self) {
        // A field added to the set and not written here or by its makers would be read
        // uninitialised. This names every field with no `..`, so adding one without naming it here
        // (and so without writing it) does not compile.
        let _every_field_is_written = |set: &Self| {
            let Self {
                peer: _,
                gets: _,
                #[cfg(feature = "liveliness")]
                    retracting: _,
            } = set;
        };
        // SAFETY: the caller's contract; each field is written once through a pointer to it.
        unsafe {
            ptr::write(addr_of_mut!((*at).gets), Gets::default());
            #[cfg(feature = "liveliness")]
            ptr::write(addr_of_mut!((*at).retracting), false);
        }
    }

    /// A set for no face yet, written field by field into `place`, which is overwritten without
    /// dropping what it held: tables of no rows, each refusing what is asked of it until
    /// `Self::lend` lends it rows, or until the on-use form counts them (`counted`), the peer's
    /// held to `limits`. Not inlined: the peer's tables, nearly all of the set, are written where
    /// they lie by `init_in`, and of the set only its gets are a value in this frame.
    #[cfg(any(feature = "runtime-plan", feature = "tables-on-use"))]
    #[inline(never)]
    fn rowless_in<'p>(place: &'p mut MaybeUninit<Self>, limits: &SessionLimits) -> &'p mut Self {
        let at = place.as_mut_ptr();
        // SAFETY: `at` is valid for writes of a `Self`: every field but the peer's tables is
        // written by `write_unpeered`, and the peer's tables by `init_in`, which writes them whole
        // (a `MaybeUninit<T>` has the layout of `T`), so the set is whole when it is lent.
        let set = unsafe {
            Self::write_unpeered(at);
            Peer::init_in(&mut *addr_of_mut!((*at).peer).cast::<MaybeUninit<Peer>>());
            &mut *at
        };
        set.peer.limit_to(limits);
        set
    }

    /// A set for no face yet over the zero bytes of the region's place for it: its peer's tables
    /// are left as those bytes, which are tables of the region policy holding no row, and held to
    /// `limits`; the rest of the set is written as `rowless_in` writes it. The region's walk hands
    /// the tables their rows and their key arena after.
    ///
    /// # Safety
    /// `place` holds all zero bytes, and nothing else reaches it.
    #[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
    #[inline(never)]
    unsafe fn rowless_over_zero<'p>(
        place: &'p mut MaybeUninit<Self>,
        limits: &SessionLimits,
    ) -> &'p mut Self
    where
        // The peer's tables are read as they lie only because zero bytes are a whole empty value
        // of them; a policy whose tables are not is refused here.
        Peer: wz_session_core::bounded::ZeroEmpty,
    {
        let at = place.as_mut_ptr();
        // SAFETY: `at` is valid for writes of a `Self` (a `MaybeUninit<T>` has the layout of
        // `T`): every field but the peer's tables is written by `write_unpeered`, and the peer's
        // tables are the place's zero bytes (the caller's contract), which are tables of no rows
        // (`ZeroEmpty`, held above), so the set is whole when it is read.
        let set = unsafe {
            Self::write_unpeered(at);
            &mut *at
        };
        set.peer.limit_to(limits);
        set
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

/// The mark of a place no face holds: the session numbers its faces up from 1 one at a time
/// (`LinkSupervisor::next_face_id`), so no face is known by it.
const NO_FACE: FaceId = FaceId::MAX;

/// The mark of a place a face that went keeps, its set emptied, while a replaying listener is
/// still owed its departure (`told`): neither a face's nor free.
#[cfg(feature = "connectivity")]
const KEPT: FaceId = FaceId::MAX - 1;

/// A mark of a place at or past this names no face: the free and the kept marks lie at the top of
/// the ids, so whether a mark names a face is one comparison.
const NAMES_NO_FACE: FaceId = FaceId::MAX - 1;

/// Whether `holder`, the mark of a place, names the face that holds it.
fn names_face(holder: FaceId) -> bool {
    holder < NAMES_NO_FACE
}

#[cfg(any(feature = "listen", feature = "group"))]
mod adding;
// The registry's and each set's descriptions, read by the forms that lay their tables out at the
// open: the region's and the plan's.
#[cfg(not(wz_on_use))]
mod described;
// What the arena's plan counts of the registry and of a set, by the part of its report: the lines
// of the same descriptions the open walks.
#[cfg(all(feature = "query", wz_lent))]
pub(crate) use described::set_get_bytes;
#[cfg(wz_lent)]
pub(crate) use described::{registry_bytes, registry_row_bytes, set_peer_bytes};

/// The rows of the table of the places' marks the open lends for `sets` sets
/// (`RowCount::HeldSets`): a mark for each place past the dial role's, whose own is no row. What a
/// plan counts of the table, read off the table's own count.
#[cfg(wz_lent)]
pub(crate) const fn held_rows(sets: usize) -> usize {
    HeldPlaces::rows_of(sets)
}
mod held;
use held::{HeldPlaces, OtherFaces};
// What the faces that went owe the liveliness subscribers, kept by a build that adds faces.
#[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
mod owed;
// The registry made by value, its tables counted at the open, where they take their memory at
// their first row, and the sets of the faces that come counted as each comes.
#[cfg(wz_on_use)]
mod counted;
#[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
pub(crate) mod placed;

/// The sets of face tables a session whose shape the build fixes holds: the dial role's face's
/// alone, a build of that form taking no face beside it (`listen` and `group` each name
/// `runtime-plan`). What its region keeps the sets and a place of each face's room for
/// (`RegistryRegion`, `StatePlaces`).
#[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
pub(in crate::engine) const FACE_SETS: usize = 1;

/// A face as the dispatch of its link or group names it: the place of its set and its id, read
/// once as the dispatch is made ([`Registry::held`]). The set is the face's while its place's
/// mark names the id, so the key of a face that went finds nothing, whichever face holds the set
/// since.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct HeldFace {
    at: usize,
    id: FaceId,
}

impl HeldFace {
    /// The key of face `id` whose set lies at `at`: the place the face keeps in every table of
    /// the session while it is held.
    #[cfg(any(
        feature = "listen",
        feature = "group",
        wz_interest_answer,
        all(test, wz_lent)
    ))]
    pub(super) const fn new(at: usize, id: FaceId) -> Self {
        Self { at, id }
    }

    /// The place of the face's set, which its link and its room keep too.
    #[cfg(any(feature = "listen", feature = "group"))]
    pub(super) const fn at(&self) -> usize {
        self.at
    }

    /// The face's id.
    #[cfg(any(feature = "listen", feature = "group"))]
    pub(super) const fn id(&self) -> FaceId {
        self.id
    }
}

/// Where a liveliness subscriber's history stands ([`Registry::next_history_token`]): the face
/// whose peer's tokens it reads now, by id, and the last token handed from them.
#[cfg(feature = "liveliness")]
#[derive(Clone, Copy, Default)]
pub(super) struct HistoryCursor {
    face: Option<FaceId>,
    after: Option<u64>,
}

/// The faces other than the one a call acts on, which the matching verdicts of that call count:
/// the table's rows but the caller's ([`HeldPlaces::split`]): the dial role's set where the call
/// is another face's, the sets past it before the call's own and after it, and the marks of those
/// places, which name the faces that hold them.
#[cfg(any(feature = "listen", feature = "group"))]
pub(super) struct Others<'a> {
    dial: Option<&'a FaceTables>,
    before: &'a [FaceTables],
    after: &'a [FaceTables],
    held_before: &'a [FaceId],
    held_after: &'a [FaceId],
}

#[cfg(any(feature = "listen", feature = "group"))]
impl Others<'_> {
    fn faces(&self) -> impl Iterator<Item = &FaceTables> {
        let before = self.before.iter().zip(self.held_before);
        let after = self.after.iter().zip(self.held_after);
        let past = before
            .chain(after)
            .filter(|(_, holder)| names_face(**holder))
            .map(|(set, _)| set);
        self.dial.into_iter().chain(past)
    }
}

#[cfg(any(feature = "listen", feature = "group"))]
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
    fn answers(&self, criterion: &wz_session_core::declare::queryable::QuerierCriterion) -> bool {
        self.faces()
            .any(|face| face.peer.remote_queryables.has_matching_for(criterion))
    }
}

/// The place of the session's own gets that its own queryables answer, which no face owns: a
/// get's leg to them outlives every link.
#[cfg(feature = "local-queryable")]
pub(super) const LOCAL_FACE: FaceId = u64::MAX;

/// What the application's tables hold on this engine: the heap profile's registrations, but for
/// the session's own subscribers and queryables, which are rows of the session's one table set,
/// each row's callback the engine's whole record of it ([`SubscriberRow`], the queryable's row),
/// not a closure over the engine's own.
pub(super) struct CoopSinks;

impl ObserverSinks for CoopSinks {
    type Subscriber = SubscriberRow;
    type SubscriberId = wz_session_core::session_tables::SubscriberHandle;
    type QueryableId = wz_session_core::session_tables::QueryableHandle;
    type LivelinessSubscriber =
        <super::CoopRows as wz_session_core::session_tables::RowCallbacks>::LivelinessSubscriber;
    type LivelinessSubscriberId = wz_session_core::session_tables::LivelinessSubscriberHandle;
    type Delivery = RoundDelivery;
    type Tables<P: wz_session_core::bounded::Storage> =
        wz_session_core::session_tables::SessionTables<super::CoopRows, P>;
    type Queryable = <super::CoopRows as wz_session_core::session_tables::RowCallbacks>::Queryable;
    // The program's watches of what the peers declare are the only observers this engine installs
    // (`decl_watch`), each held in its row of an observer list; a build without them holds none,
    // so its observer lists are of a sink that cannot be made and hold nothing to drop or free.
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    type Declared = WatchObserver;
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    type Undeclared = WatchObserver;
    #[cfg(not(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    )))]
    type Declared = NoSink;
    #[cfg(not(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    )))]
    type Undeclared = NoSink;
}

/// The sink of the application layer's own matching watches, which this engine registers none
/// in: its matching listeners are rows of the session's tables, read after the lock's turns
/// (`SessionTables::next_matching_change`), so no value of it is ever made and its watch lists
/// stay empty.
pub(super) enum NoWatch {}

impl MatchingSink for NoWatch {
    fn on_matching_changed(&mut self, _matching: bool) {
        match *self {}
    }

    const WATCHES: bool = false;
}

/// What the application registered on the session: its tables' rows lent from the session's
/// arena at its open, each as many as the limit the open resolved.
pub(super) type App = SlotObserverOf<CoopSinks, RowPolicy, NoWatch>;

/// What a write filter's verdict and a matching listener's are read off: every face's peer's
/// declarations, each search of them counted for the tests ([`Registry::peers_declare`]).
impl PeerDeclarations for Registry {
    fn declares(&self, plane: Plane, key: &str) -> bool {
        self.peers_declare(plane, key)
    }

    fn written(&self) -> u64 {
        self.faces_written
    }
}

/// Whether any of `faces`' peers declared what `plane` counts on `keyexpr`: a subscriber, or a
/// queryable (a complete one where the plane requires it). Asked from the borrowed key: a poll
/// builds no criterion.
fn faces_declare<'a>(
    mut faces: impl Iterator<Item = &'a FaceTables>,
    plane: Plane,
    keyexpr: &str,
) -> bool {
    match plane {
        Plane::Subscribers => faces.any(|face| face.peer.remote_subscribers.has_matching(keyexpr)),
        #[cfg(any(feature = "query", feature = "queryable"))]
        Plane::Queryables { complete_required } => faces.any(|face| {
            face.peer
                .remote_queryables
                .answers_query(keyexpr, complete_required)
        }),
        // A build without a querier or a queryable holds no queryable a peer declared.
        #[cfg(not(any(feature = "query", feature = "queryable")))]
        Plane::Queryables { .. } => false,
    }
}

/// What the read takes of a face's records itself, ahead of the face's dispatch, in a build whose
/// read steps its one link itself: every query of the link, handed to the queryables (`queries`)
/// with queryables, and every peer token, handed to the liveliness subscribers (`tokens`) with
/// liveliness. A build without leaves them to their planes, which hand them through the round.
const READ_TAKES: TakenAhead = TakenAhead {
    queries: cfg!(all(feature = "queryable", not(wz_round))),
    tokens: cfg!(all(feature = "liveliness", not(wz_round))),
    declares: false,
};

/// What the read takes of a copied frame's records itself, ahead of the frame's other planes
/// (`Planes::BesideSubscribers`): what it takes of a lent record, and, with the declaration
/// watches, every Declare, dispatched one message at a time (`Registry::dispatch_declare_message`)
/// so the watches' room is handed out before the next message fills it.
#[cfg(not(wz_round))]
const COPIED_TAKES: TakenAhead = TakenAhead {
    declares: cfg!(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    )),
    ..READ_TAKES
};

/// The planes of the application layer a dispatch of a face's event reaches.
#[derive(Clone, Copy)]
pub(super) enum Planes {
    /// Every plane.
    All,
    /// Every plane but the subscribers' and the pending gets' replies, whose side of each of the
    /// event's records the caller took itself, in their order
    /// (`Registry::take_subscriber_record`, `Registry::take_reply`).
    #[cfg(not(wz_round))]
    BesideSubscribers,
}

/// The application layer of one session. See the module documentation.
pub(super) struct Registry {
    /// Dropped by the registry's own drop (`let_go`), as `sets` is.
    pub(super) app: ManuallyDrop<App>,
    /// Where a sample the application's subscribers match goes: the session's round of
    /// deliveries, handed to each dispatch of the application's tables.
    delivery: RoundDelivery,
    /// What builds the set of each place no face has taken yet: from the span the open reserved for
    /// it, the session's pools of what its peers write by their own choice among it, where the open
    /// lends the tables, or counted as the dial face's set is where they take their memory on use.
    /// A session of its dial role's face alone builds its one set at the open and keeps none.
    #[cfg(any(feature = "listen", feature = "group"))]
    spares: adding::SpareSets,
    /// Every set of face tables built so far, each where it was built and never moved from, in a
    /// table with a row for each face the config admits, lent by the arena at the open or, where the
    /// tables take their memory on use, taking every row at the open with its first set: the dial
    /// role's face's first and always held by it, then a set for each place a face has taken, built
    /// as the first face takes it. A face past them is refused (`FacesFull`), so no face takes
    /// memory for its set as it comes. A set no face holds is kept, emptied, for the next face.
    sets: ManuallyDrop<BoundedVec<FaceTables, MAX_FACE_SETS, RowPolicy>>,
    /// The face that holds each place, by the place, [`NO_FACE`] for a place no face holds, and
    /// `KEPT` for one a departed face's tomb keeps: the dial role's face holds the first for the
    /// table's life. The place is the face's in every table of the session (its set's, its
    /// link's, its room's). Every walk over the faces and every lookup of one reads this and the
    /// held sets alone; the open lends a mark for each place the config admits past the dial
    /// role's, most of them free at any time, and every place past the sets built is free or kept.
    holders: HeldPlaces,
    /// The tokens of faces that went before each was retracted, in the order the faces went, the
    /// set each face held given back as it went (`owed::Owed`). A session of no face besides the
    /// dial role's (a build without `listen` and `group`) removes none, and keeps none of them.
    #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
    owed: owed::Owed,
    /// The aliases one face's peer may hold (`MAX_PEER_KEYEXPR_ALIASES`), which a set a group's face
    /// held, at the group's own quota (`Self::hold_member_aliases`), is held to again when it is
    /// given back for the next face.
    #[cfg(feature = "multicast-declarations")]
    peer_aliases: MaxPeerKeyexprAliasesHeld,
    /// The session's own gets pending on its own queryables ([`LOCAL_FACE`]).
    #[cfg(feature = "local-queryable")]
    pub(super) local: Gets,
    /// The program's watches of what the peers declare, which the application layer's observers
    /// hold events for while a link's frame is dispatched (`decl_watch`).
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    pub(super) decl_watches: DeclWatches,
    /// Moves each time a face's peer tables are handed out to a write that may change what its
    /// peer declared, and each time a face comes or goes: an answer read off what the peers
    /// declared ([`Self::peers_declare`]) holds for as long as this reads what it read when the
    /// answer was taken. A Push and the drains after a run of them write no declaration and move
    /// it not ([`Self::split_unwritten`]), so a stream of samples owes the step no bookkeeping.
    faces_written: u64,
    /// How often a face's tables were looked up to be handed out, written or not: what a test of
    /// the cost of one received sample counts.
    #[cfg(all(test, feature = "std"))]
    face_lookups: u64,
    /// How often what the peers declared was searched ([`Self::peers_declare`]): what a test of
    /// the cost of a filtered put counts.
    #[cfg(test)]
    peer_looks: core::cell::Cell<usize>,
    /// How many sets the walks over the faces read: what a test of the cost of a walk counts.
    #[cfg(test)]
    set_reads: core::cell::Cell<usize>,
    /// The lent Pushes handed to the subscribers' plane alone (`Self::dispatch_push`, or
    /// `Self::lend_push`), the face lookups their dispatches made with the drains after them, and
    /// the lent Pushes that reached the fan over every plane instead ([`Self::dispatch_event_to`]):
    /// what a test of the cost of one received sample counts.
    #[cfg(all(test, feature = "std"))]
    pushes: (usize, usize, usize),
    /// The lent Responses and ResponseFinals handed to the pending gets alone
    /// ([`Self::dispatch_reply`]): what a test of a reply's dispatch counts.
    #[cfg(all(test, feature = "std", feature = "query"))]
    replies_alone: usize,
    /// How often a run of Pushes was drained before a later record of its own frame
    /// ([`Self::count_drain_within_frame`]): what tells a test that a Push and the record after
    /// it came in one frame.
    #[cfg(all(test, feature = "std", feature = "queryable"))]
    drains_within_frames: usize,
}

/// The faces as the session's state reaches them (`SessionState`): what a lost face's peer
/// declared and the gets asked of it let go of, the earliest deadline of the gets pending on them,
/// and the tokens of lost links retracted.
impl SessionFaces for Registry {
    fn lose_face(&mut self, face: FaceId) {
        self.flush_declarations_on_link_loss(face);
        // Its peer can send no Final now: every get asked of it ends, each entry's drop saying its
        // leg's end, and the face's tables keep their rows for the link that comes up next.
        #[cfg(feature = "query")]
        self.end_legs_of(face);
        // Its peer's tokens are retracted as the round of deliveries takes each, the rest owed.
        #[cfg(feature = "liveliness")]
        self.lose_tokens(face);
    }

    fn next_get_deadline_ms(&mut self) -> Option<u64> {
        // The tables keep the earliest deadline of a standing get as gets come and go.
        #[cfg(feature = "query")]
        {
            self.app.tables.next_get_deadline()
        }
        #[cfg(not(feature = "query"))]
        {
            None
        }
    }

    #[cfg(all(feature = "liveliness", wz_round))]
    fn retract_owed(&mut self, room: &mut dyn FnMut() -> bool) -> bool {
        Registry::retract_owed(self, room)
    }
}

/// The application's part, one face's tables and the other faces', apart so each can be used as
/// its call needs. A session of its dial role's face alone counts no other.
struct Split<'a> {
    app: &'a mut App,
    delivery: &'a mut RoundDelivery,
    face: &'a mut FaceTables,
    others: OtherFaces<'a>,
}

impl Registry {
    /// A session that holds nothing and has been told nothing, with its dial face, its tables
    /// held to the session limits its open resolved and lent from `arena`: the pools of what the
    /// peers write, `peers` counting them; the span the sets of the faces to come are built in as
    /// each first comes (`adding::SpareSets`); every table of the registry's own, by one walk of
    /// its description (`described`), the application's of `rows`, the sets' table and its index
    /// of a row for each face the config admits, the tokens owed by the faces that went, and the
    /// session's own gets where it answers its own; then the dial face's set, by the set's own
    /// description (one of no rows for a session that dials nothing, `FacePeers::dial`). What the
    /// peers declare keeps its keys in `keys`, the session's key arena, as the session's own
    /// declarations do. What the application's subscribers match goes to `delivery`. Refused when
    /// the arena has not the rows, which one reserved by the plan that counts them always has, or
    /// when `limits` admit more declaration watchers or watches than the build.
    #[cfg(wz_lent)]
    pub(super) fn new(
        limits: &SessionLimits,
        arena: &mut Arena,
        keys: KeySpace,
        rows: wz_session_core::session_tables::TableRows,
        gets: GetTables,
        peers: FacePeers,
        delivery: RoundDelivery,
    ) -> Result<Self, LendRefused> {
        // The rows each line of the registry's description is lent: the application's tables' and
        // lists', the session's own gets', a set for each set and a mark for each past the dial
        // role's, and a table owed for each row of the session's pool of its peers' tokens.
        let counts = rows
            .counts()
            .and(&App::list_counts(limits)?)
            .and(&gets.rows.counts())
            .with(RowCount::FaceSets, peers.sets())
            .with(RowCount::HeldSets, HeldPlaces::rows_of(peers.sets()))
            .with(RowCount::OwedTokens, peers.owed_tokens());
        // The watches hold what the peers declare in the round the application's deliveries go to,
        // where the links are read by a task or a listener; a read that steps its one link itself
        // hands it after each record from a room of the watches' own.
        #[cfg(all(
            any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ),
            wz_round
        ))]
        let decl_watches = DeclWatches::under(limits, &delivery.round)?;
        #[cfg(all(
            any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ),
            not(wz_round)
        ))]
        let decl_watches = DeclWatches::under(limits)?;
        let pools = PeerPools::lent(arena, keys, peers.pools)?;
        // One face's own spans are handed to that face's tables alone, so a plan that lends them
        // lends one set; a build without pools keeps each set's rows inline.
        debug_assert!(!SHARES_ROWS || pools.is_shared() || peers.tables <= 1);
        // Where faces are added beside the dial role's, the dial face's set is built at the open
        // and the set of each other place when a face first takes it, from a span reserved here and
        // written by nothing until then: on a host the pages of the places no face took stay
        // unresident. Every span an arena lends starts on one alignment, so the order the open
        // lends them in moves none of the bytes the plan counts.
        #[cfg(any(feature = "listen", feature = "group"))]
        let built = usize::from(peers.dial).min(peers.tables);
        #[cfg(not(any(feature = "listen", feature = "group")))]
        let built = peers.tables;
        #[cfg(any(feature = "listen", feature = "group"))]
        let spares = adding::SpareSets::reserved(
            arena,
            keys,
            pools,
            gets.rows,
            peers.rows,
            *limits,
            peers.tables.saturating_sub(built),
        )?;
        let mut registry = Self {
            app: ManuallyDrop::new(App::over(CoopTables::rowless())),
            delivery,
            sets: ManuallyDrop::new(BoundedVec::default()),
            holders: HeldPlaces::rowless(),
            #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
            owed: owed::Owed::rowless(),
            #[cfg(feature = "multicast-declarations")]
            peer_aliases: limits.max_peer_keyexpr_aliases_held(),
            #[cfg(any(feature = "listen", feature = "group"))]
            spares,
            #[cfg(feature = "local-queryable")]
            local: Gets::default(),
            #[cfg(any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ))]
            decl_watches,
            faces_written: 0,
            #[cfg(all(test, feature = "std"))]
            face_lookups: 0,
            #[cfg(test)]
            peer_looks: core::cell::Cell::new(0),
            #[cfg(test)]
            set_reads: core::cell::Cell::new(0),
            #[cfg(all(test, feature = "std"))]
            pushes: (0, 0, 0),
            #[cfg(all(test, feature = "std", feature = "query"))]
            replies_alone: 0,
            #[cfg(all(test, feature = "std", feature = "queryable"))]
            drains_within_frames: 0,
        };
        // Lent whole and given up whole: a refused table leaves the ones after it rowless, and the
        // registry goes at once with what it was lent.
        let mut lend = TableLender::new(arena);
        // SAFETY: the description is this type's own (`Self::places`): each line names a table of
        // the registry, which holds no value (each made of no rows above), and states the bytes of
        // its rows, and each key line a table's handle to the key arena, which holds no key; the
        // registry is reached by nothing else during the call, and `keys` is the session's, which
        // outlives it.
        unsafe {
            lend_region(
                NonNull::from(&mut registry).cast::<u8>(),
                keys,
                &Self::LINES,
                &counts,
                &mut lend,
            );
        }
        lend.finish()?;
        registry.app.tables.limit_to(&rows);
        registry.app.limit_to(limits);
        registry.holders.hold_sets(peers.sets())?;
        // A session that dials nothing lent its dial face no set: that face holds one of no rows,
        // first, and every lent set is for the faces to come. Otherwise the first lent set is the
        // dial face's. Either way every set is built and lent by `lend_set`, at the open or as a
        // face comes, so a set is built in one place; its rows keep what its peer writes in the
        // pools the faces to come keep theirs in, or in the open's own where none comes.
        if !peers.dial {
            push_unpeered(&mut registry.sets, keys, limits).ok_or(LendRefused::OverCeiling {
                rows: 1,
                ceiling: 0,
            })?;
        }
        #[cfg(any(feature = "listen", feature = "group"))]
        let pools = &mut registry.spares.pools;
        #[cfg(not(any(feature = "listen", feature = "group")))]
        let mut own_pools = pools;
        #[cfg(not(any(feature = "listen", feature = "group")))]
        let pools = &mut own_pools;
        for _ in 0..built {
            lend_set(
                &mut registry.sets,
                arena,
                keys,
                pools,
                gets.rows,
                peers.rows,
                limits,
            )?;
        }
        Ok(registry)
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
    pub(super) fn peers_declare(&self, plane: Plane, keyexpr: &str) -> bool {
        #[cfg(test)]
        self.peer_looks.set(self.peer_looks.get() + 1);
        faces_declare(self.faces(), plane, keyexpr)
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

    /// The lent Responses and ResponseFinals handed to the pending gets alone.
    #[cfg(all(test, feature = "std", feature = "query"))]
    pub(super) fn reply_dispatches(&self) -> usize {
        self.replies_alone
    }

    /// One more run of Pushes drained before a later record of its own frame.
    #[cfg(all(test, feature = "std", feature = "queryable"))]
    pub(super) fn count_drain_within_frame(&mut self) {
        self.drains_within_frames += 1;
    }

    /// How often a run of Pushes was drained before a later record of its own frame.
    #[cfg(all(test, feature = "std", feature = "queryable"))]
    pub(super) fn drains_within_frames(&self) -> usize {
        self.drains_within_frames
    }

    /// One more lent Push handed to the subscribers' plane alone, the face lookups since
    /// `looked` its own.
    #[cfg(all(test, feature = "std"))]
    pub(super) fn counted_push(&mut self, looked: u64) {
        let lookups = usize::try_from(self.face_lookups.wrapping_sub(looked)).unwrap_or(usize::MAX);
        self.pushes.0 += 1;
        self.pushes.1 += lookups;
    }

    /// The set that lies at `at`, for a walk over the faces.
    fn set(&self, at: usize) -> Option<&FaceTables> {
        #[cfg(test)]
        self.set_reads.set(self.set_reads.get() + 1);
        self.sets.get(at)
    }

    /// What the in-place receive cost the peers of every face the session holds, summed: among
    /// it each key past the row a face composes keys in, refused where it lay.
    pub(super) fn in_place_fallbacks(&self) -> wz_session_core::pubsub::InPlaceFallbacks {
        self.faces().fold(
            wz_session_core::pubsub::InPlaceFallbacks::default(),
            |sum, face| sum.plus(face.peer.subscribers.in_place_fallbacks()),
        )
    }

    /// The tables of every face, the dial role's first.
    pub(super) fn faces(&self) -> impl Iterator<Item = &FaceTables> {
        self.holders
            .marks()
            .enumerate()
            .filter(|(_, holder)| names_face(*holder))
            .filter_map(|(at, _)| self.set(at))
    }

    /// Where the set face `id` holds lies among the sets, while the session holds the face.
    fn held_at(&self, id: FaceId) -> Option<usize> {
        self.holders.place_of(id)
    }

    /// The faces the session holds, in the order of their sets.
    #[cfg(any(feature = "liveliness", all(test, wz_lent)))]
    fn held_ids(&self) -> impl Iterator<Item = FaceId> + '_ {
        self.holders.marks().filter(|holder| names_face(*holder))
    }

    /// The tables of face `id`, while the session holds it.
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    pub(super) fn tables_of(&self, id: FaceId) -> Option<&FaceTables> {
        self.held_at(id).and_then(|at| self.set(at))
    }

    /// The key face `id` is found by while the session holds it ([`HeldFace`]): one that finds
    /// no set for a face it does not hold.
    pub(super) fn held(&self, id: FaceId) -> HeldFace {
        HeldFace {
            at: self.held_at(id).unwrap_or(usize::MAX),
            id,
        }
    }

    /// Where the set `face` names lies, while its face holds it: read at its place, with no walk.
    fn place(&self, face: HeldFace) -> Option<usize> {
        self.holders.holds(face.at, face.id).then_some(face.at)
    }

    /// The tables of face `id`, while the session holds it, to write.
    fn held_mut(&mut self, id: FaceId) -> Option<&mut FaceTables> {
        let at = self.held_at(id)?;
        self.sets.get_mut(at)
    }

    /// The pending gets of every face and, where the session answers its own gets, its own.
    #[cfg(all(
        feature = "query",
        test,
        wz_lent,
        any(feature = "listen", feature = "group")
    ))]
    pub(super) fn all_gets(&self) -> impl Iterator<Item = &Gets> {
        let gets = self.faces().map(|face| &face.gets);
        #[cfg(feature = "local-queryable")]
        let gets = gets.chain(core::iter::once(&self.local));
        gets
    }

    /// The pending gets of every face the session holds, and the session's own, to write.
    #[cfg(feature = "query")]
    pub(super) fn all_gets_mut(&mut self) -> impl Iterator<Item = &mut Gets> {
        let gets = self
            .sets
            .iter_mut()
            .zip(self.holders.marks())
            .filter(|(_, holder)| names_face(*holder))
            .map(|(face, _)| &mut face.gets);
        #[cfg(feature = "local-queryable")]
        let gets = gets.chain(core::iter::once(&mut self.local));
        gets
    }

    /// Forget the legs of `get` on every face the session holds and on its own queryables: its
    /// row was retired (handed out, cancelled, or closed with the session), so no reply or Final
    /// of a leg of it finds it again.
    #[cfg(feature = "query")]
    pub(super) fn forget_get(&mut self, get: PendingGetHandle) {
        for gets in self.all_gets_mut() {
            gets.forget(get);
        }
    }

    /// The face `id` names was lost and its peer sends no Final now: each leg it held ends on its
    /// get's row (`SessionTables::end_leg`), the last leg of a get ending it answered, which the
    /// delivery after the hold hands out.
    #[cfg(feature = "query")]
    fn end_legs_of(&mut self, id: FaceId) {
        let Some(at) = self.held_at(id) else {
            return;
        };
        let Self { sets, app, .. } = self;
        if let Some(set) = sets.get_mut(at) {
            set.gets.end_every_leg(|get| {
                // A get already ended or retired has no leg to end: nothing to say.
                let _ = app.tables.end_leg(get);
            });
        }
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

    /// How many places the open holds for the faces' sets, each set built when a face first takes
    /// its place: the places of every table of the session's faces.
    pub(super) fn face_places(&self) -> usize {
        self.holders.count()
    }

    /// The tables of `face`, gone with the face and left, emptied, where they lie for the next
    /// face: its place is free. The dial role's face is never removed, and the key of a face that
    /// is not held removes nothing.
    #[cfg(any(feature = "listen", feature = "group", all(test, wz_lent)))]
    pub(super) fn remove_face(&mut self, face: HeldFace) {
        self.let_go(face, NO_FACE);
    }

    /// The tables of `face`, gone with the face as [`Self::remove_face`] takes them, its place
    /// kept for the tomb a replaying listener is still owed the departure of: no face takes it
    /// until [`Self::free_kept`]. Only a face taken besides the dial (`listen`) departs.
    #[cfg(all(feature = "connectivity", feature = "listen"))]
    pub(super) fn depart(&mut self, face: HeldFace) {
        self.let_go(face, KEPT);
    }

    /// A free place kept for a tomb of a face whose place holds another (`told`): where it lies,
    /// `None` when every place is held or kept.
    #[cfg(feature = "connectivity")]
    pub(super) fn keep_place(&mut self) -> Option<usize> {
        let at = self.holders.free()?;
        *self.holders.mark_mut(at)? = KEPT;
        Some(at)
    }

    /// The place at `at` a tomb kept is free again; a place a face holds is left as it is.
    #[cfg(feature = "connectivity")]
    pub(super) fn free_kept(&mut self, at: usize) {
        if let Some(row) = self.holders.mark_mut(at).filter(|row| **row == KEPT) {
            *row = NO_FACE;
        }
    }

    /// Empty the set `face` holds, its row then reading `row`.
    #[cfg(any(feature = "listen", feature = "group", all(test, wz_lent)))]
    fn let_go(&mut self, face: HeldFace, row: FaceId) {
        if face.id == DIAL_FACE {
            return;
        }
        let Some(at) = self.place(face) else {
            return;
        };
        self.writing();
        if let Some(holder) = self.holders.mark_mut(at) {
            *holder = row;
        }
        // Only a build that adds faces removes one, and only its sets keep tokens owed apart.
        #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
        self.owe_tokens_of(at, face.id);
        if let Some(set) = self.sets.get_mut(at) {
            set.give_back();
            #[cfg(feature = "multicast-declarations")]
            set.peer.subscribers.limit_aliases_to(self.peer_aliases);
        }
    }

    /// Hold the aliases of `face`, a group's, to no fewer than its members may declare together:
    /// each member's own keyexprs for every member the group admits (`GROUP_FACE_ALIASES`), which
    /// the open reserved in the session's pool. A face whose quota admits them already, one bound
    /// by the pool alone among them, keeps it, as does a build whose limits keep the build's value
    /// alone; a table whose rows are counted when it is made is counted up to them where it is
    /// counted fewer, whatever its quota admits (`SubscriberPeer::hold_aliases_at_least`).
    #[cfg(feature = "multicast-declarations")]
    pub(super) fn hold_member_aliases(&mut self, face: HeldFace) {
        let Some(set) = self.place(face).and_then(|at| self.sets.get_mut(at)) else {
            return;
        };
        if let Ok(quota) =
            MaxPeerKeyexprAliasesHeld::select(Quota::at_most(crate::arena::GROUP_FACE_ALIASES))
        {
            set.peer.subscribers.hold_aliases_at_least(quota);
        }
    }

    /// The tables of every face but the dial role's, gone with their faces and left, emptied,
    /// where they lie, and every place free but the dial role's, a tomb's among them.
    pub(super) fn remove_accepted_faces(&mut self) {
        self.writing();
        let Self {
            sets,
            holders,
            #[cfg(feature = "multicast-declarations")]
            peer_aliases,
            ..
        } = self;
        #[cfg(feature = "connectivity")]
        let built = sets.len();
        // A session of its dial role's face alone has no row to write, and so no set to give back.
        for (set, holder) in sets
            .iter_mut()
            .skip(1)
            .zip(holders.past_dial_mut().iter_mut())
        {
            if names_face(*holder) {
                set.give_back();
                #[cfg(feature = "multicast-declarations")]
                set.peer.subscribers.limit_aliases_to(*peer_aliases);
            }
            *holder = NO_FACE;
        }
        // A place no set was built at holds no face, though a tomb may keep it (`keep_place`).
        #[cfg(feature = "connectivity")]
        for holder in holders
            .past_dial_mut()
            .iter_mut()
            .skip(built.saturating_sub(1))
        {
            *holder = NO_FACE;
        }
        #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
        self.owed.clear();
    }

    /// The tables of face `id`, while the session holds it.
    #[cfg(feature = "query")]
    pub(super) fn face_mut(&mut self, id: FaceId) -> Option<&mut FaceTables> {
        self.writing();
        self.held_mut(id)
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
    fn split(&mut self, at: Option<usize>) -> Option<Split<'_>> {
        self.writing();
        self.split_unwritten(at)
    }

    /// [`Self::split`] for a call that writes nothing a face's peer declared: a Push read into the
    /// subscribers' plane, and the drains after a run of them, which send what the session staged
    /// and take the `Final`s owed. Not counted as a write, so every answer read off the peers'
    /// declarations stands across a stream of samples.
    fn split_unwritten(&mut self, at: Option<usize>) -> Option<Split<'_>> {
        #[cfg(all(test, feature = "std"))]
        {
            self.face_lookups += 1;
        }
        let at = at?;
        let Self {
            app,
            delivery,
            sets,
            holders,
            ..
        } = self;
        let (face, others) = holders.split(sets, at)?;
        Some(Split {
            app,
            delivery,
            face,
            others,
        })
    }

    /// Fan one iteration's event of face `id` into the application layer, against that face's
    /// tables. A face the session no longer holds hears nothing.
    #[cfg(all(feature = "queryable", wz_round))]
    pub(super) fn dispatch_event(&mut self, face: HeldFace, event: IterationEvent<'_, '_>) {
        self.dispatch_event_to(face, event, Planes::All);
    }

    /// Fan one iteration's event of face `face` into the planes `planes` names, against that
    /// face's tables. A face the session no longer holds hears nothing.
    pub(super) fn dispatch_event_to(
        &mut self,
        face: HeldFace,
        event: IterationEvent<'_, '_>,
        planes: Planes,
    ) {
        #[cfg(all(test, feature = "std"))]
        if super::lent_push(&event) {
            self.pushes.2 += 1;
        }
        #[cfg(feature = "declarations-synced-event")]
        let was_final = self.declarations_final(face);
        if let Some(Split {
            app,
            delivery,
            face: set,
            others,
        }) = self.split(self.place(face))
        {
            match planes {
                #[cfg(wz_round)]
                Planes::All => app.dispatch_event_among(
                    delivery,
                    &mut set.peer,
                    &mut set.gets,
                    event,
                    &others,
                    READ_TAKES,
                ),
                // The read that hands each record out as it is read hands every sample out
                // itself, one subscriber at a time (`pinned`), so the planes hand none to the
                // round.
                #[cfg(not(wz_round))]
                Planes::All => app.dispatch_event_but_samples(
                    delivery,
                    &mut set.peer,
                    &mut set.gets,
                    event,
                    &others,
                    READ_TAKES,
                ),
                #[cfg(not(wz_round))]
                Planes::BesideSubscribers => app.dispatch_event_beside_subscribers(
                    delivery,
                    &mut set.peer,
                    &mut set.gets,
                    event,
                    &others,
                    COPIED_TAKES,
                ),
            }
        }
        // The fan hands the face's legs nothing (`RequesterTables for Gets`): what they take of the
        // event follows it, in its order.
        #[cfg(feature = "query")]
        self.take_answers_of(face, event);
        #[cfg(feature = "declarations-synced-event")]
        if !was_final && self.declarations_final(face) {
            #[cfg(wz_round)]
            // SAFETY: a face's frame is dispatched under the session's lock.
            unsafe {
                self.decl_watches.heard_synced()
            };
            #[cfg(not(wz_round))]
            self.decl_watches.heard_synced();
        }
        // What the observers are told after this frame is a group's until a link's frame says
        // otherwise, so a group's members are never told as a link's peer.
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        self.decl_watches.heard_all();
    }

    /// Hand `sample`, which the session itself published, to each of its subscribers that hears
    /// the session's own messages: how many.
    #[cfg(all(feature = "local-subscriber", wz_round))]
    pub(super) fn local_publish(
        &mut self,
        sample: &dyn wz_session_core::sink::SampleView,
    ) -> usize {
        wz_session_core::pubsub::LocalSubscribers::local_publish(
            &mut self.app.tables,
            &mut self.delivery,
            sample,
        )
    }

    /// Ask the session's own queryables `query`, a get of the session's own on `keyexpr`: each
    /// that matches begins a call and holds the get's Final (`QueryPlane::arrive`), so none
    /// stages a reply into `replies`. How many matched.
    #[cfg(feature = "local-queryable")]
    pub(super) fn ask_own_queryables<S: wz_session_core::bounded::Storage>(
        &mut self,
        envelope: wz_session_core::query::QueryEnvelope,
        keyexpr: &str,
        query: &wz_session_core::wire::parts::QueryOwned,
        replies: &mut wz_session_core::reply_stage::ReplyStage<S>,
    ) -> usize {
        let (_, queryables) = self.app.tables.queries_mut();
        wz_session_core::query::ask_local_queryables(
            queryables,
            &mut self.delivery,
            envelope,
            keyexpr,
            query,
            None,
            replies,
        )
    }

    /// Whether the peer of face `id` has ended its initial declarations since its link came up.
    #[cfg(feature = "declarations-synced-event")]
    fn declarations_final(&self, face: HeldFace) -> bool {
        self.place(face)
            .and_then(|at| self.set(at))
            .is_some_and(|face| face.peer.remote_subscribers.initial_declarations_final())
    }

    /// The next [`Self::dispatch_event_to`] is of a link whose peer's zid `peer` reads: what the
    /// watches are told of it is held as that peer's events (`DeclWatches::hear_link`). A group's
    /// dispatch says nothing, and what it tells is held for no one.
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    pub(super) fn hear_decl_link(
        &self,
        peer: impl FnOnce() -> Option<wz_session_core::session_zid::SessionZid>,
    ) {
        self.decl_watches.hear_link(peer);
    }

    /// Tell the declaration watches what the one `Declare` `message` of a copied frame of face
    /// `face` declares, as that face's peer `peer` reads (`DeclWatches::hear_link`), and that its
    /// peer ended its initial declarations if the message ends them: the frame's own dispatch
    /// leaves its Declares to this (`COPIED_TAKES`). A face the session no longer holds tells
    /// nothing.
    #[cfg(all(
        any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ),
        not(wz_round)
    ))]
    pub(super) fn dispatch_declare_message(
        &mut self,
        face: HeldFace,
        message: &wz_session_core::network_message::NetworkMessage,
        peer: impl FnOnce() -> Option<wz_session_core::session_zid::SessionZid>,
    ) {
        #[cfg(feature = "declarations-synced-event")]
        let was_final = self.declarations_final(face);
        self.decl_watches.hear_link(peer);
        if let Some(Split {
            app,
            face: set,
            others,
            ..
        }) = self.split(self.place(face))
        {
            app.dispatch_declare_message(&mut set.peer, &set.gets, message, &others);
        }
        #[cfg(feature = "declarations-synced-event")]
        if !was_final && self.declarations_final(face) {
            self.decl_watches.heard_synced();
        }
        self.decl_watches.heard_all();
    }

    /// Stage for the peer of face `id` what the application did to its subscriptions since the
    /// peer last looked, so the drain that follows sends it: the future push a subscription
    /// registered after the peer's interest is owed, and the retraction of an aggregate
    /// declaration the last matching subscription stood for. An observer that held the peer's
    /// side beside the table staged both as it was told; the table that serves one peer or many
    /// leaves each peer to read the table's epoch, and nothing else reads it. Only a build that
    /// answers its peers' Interests keeps any to reconcile.
    #[cfg(wz_interest_answer)]
    fn reconcile_subscribers(&mut self, face: HeldFace) {
        // Handed out to be written, as `Self::split` hands a face's tables out.
        self.writing();
        if let Some(set) = self.place(face).and_then(|at| self.sets.get_mut(at)) {
            reconcile_face(&self.app, set);
        }
    }

    /// Drain what the last [`Self::dispatch_event_to`] of face `id` staged, EXCEPT the `Final`s the
    /// queries owe: the replies, the answers to the peer's interests and the terminated-get
    /// prunes leave through `actions`. The `Final`s are taken with
    /// [`Self::take_pending_final_rids`].
    #[cfg(feature = "queryable")]
    pub(super) fn flush_pending_replies<S>(&mut self, face: HeldFace, actions: &S)
    where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        #[cfg(wz_interest_answer)]
        self.reconcile_subscribers(face);
        if let Some(Split { app, face, .. }) = self.split(self.place(face)) {
            app.flush_pending_replies(&mut face.peer, &mut face.gets, actions);
        }
    }

    /// The `Final`s the queries of face `id` owe its peer, each with the QoS of its query, taken
    /// so the caller sends them once the last callback that may still answer has.
    #[cfg(feature = "queryable")]
    pub(super) fn take_pending_final_rids(&mut self, face: HeldFace) -> FinalStage<Static> {
        self.writing();
        self.place(face)
            .and_then(|at| self.sets.get_mut(at))
            .map(|set| set.peer.finals.take_owed())
            .unwrap_or_default()
    }

    /// A Push of face `id` lent where its frame lies ([`super::lent_push`]), handed to the
    /// subscribers' plane alone, which is the one plane that reads a Push: the fan over every
    /// plane ([`Self::dispatch_event_to`]) is spared, and so are the watches' staging, which a Push
    /// stages nothing into. What follows the dispatch of a record is put off to the end of the run
    /// of Pushes it is one of ([`Self::settle`]): a Push stages nothing for it to drain, so
    /// it is done once for the run and not once for each. A face the session no longer holds hears
    /// nothing. A session whose read steps its one link itself hands a lent Push out one
    /// subscriber at a time instead (`Self::lend_push`).
    #[cfg(wz_round)]
    pub(super) fn dispatch_push(&mut self, face: HeldFace, event: IterationEvent<'_, '_>) {
        #[cfg(all(test, feature = "std"))]
        let looked = self.face_lookups;
        if let Some(Split {
            app,
            delivery,
            face,
            ..
        }) = self.split_unwritten(self.place(face))
        {
            face.peer
                .subscribers
                .dispatch_iteration_event(&mut app.tables, delivery, event);
        }
        #[cfg(all(test, feature = "std"))]
        self.counted_push(looked);
    }

    /// A Response or a ResponseFinal of face `face` lent where its frame lies
    /// ([`super::lent_reply`]), handed to the face's pending gets alone, the one plane that reads
    /// a reply, as a Push is handed to the subscribers' plane alone ([`Self::dispatch_push`]):
    /// what follows the dispatch is put off to the end of the run of such records
    /// ([`Self::settle`]). A face the session no longer holds hears nothing.
    #[cfg(feature = "query")]
    pub(super) fn dispatch_reply(&mut self, face: HeldFace, record: &InPlaceRecord<'_, '_>) {
        self.take_lent_answer(face, record);
        // A Response is counted where it is lent (`Self::lend_reply`).
        #[cfg(all(test, feature = "std"))]
        if record.response().is_none() {
            self.replies_alone += 1;
        }
    }

    /// What a face's legs and the gets' rows take of `event`, a record or a frame of face `face`,
    /// after the observer's fan, in the frame's order (`RequesterTables for Gets`): each
    /// ResponseFinal ends its leg at the last its face owes, and then that leg of its get's row,
    /// each DeclFinal a snapshot's alike; in a build that keeps a round, each Response and each
    /// alive token answering a pending snapshot is admitted to its get's row and offered to the
    /// round with the call admission began. The read that hands each record out as it reads it
    /// hands the Responses and tokens to their gets itself (`replies`, `pinned`), so in its build
    /// this takes the Finals alone. A face the session no longer holds hears nothing.
    #[cfg(feature = "query")]
    fn take_answers_of(&mut self, face: HeldFace, event: IterationEvent<'_, '_>) {
        match event {
            IterationEvent::InPlace(ref record) => self.take_lent_answer(face, record),
            IterationEvent::Poll(
                wz_session_core::driver_loop::DriverLoopOutcome::FramePayload { messages, .. },
            ) => {
                for message in
                    wz_session_core::driver_loop::owned_records(messages).unwrap_or_default()
                {
                    self.take_owned_answer(face, message);
                }
            }
            _ => {}
        }
    }

    /// [`Self::take_answers_of`] for one record lent where its frame lies.
    #[cfg(feature = "query")]
    fn take_lent_answer(&mut self, face: HeldFace, record: &InPlaceRecord<'_, '_>) {
        #[cfg(wz_round)]
        self.offer_lent_reply(face, record);
        if let Some(response_final) = record.response_final() {
            self.end_get_leg(face, response_final.request_id);
        }
        #[cfg(feature = "liveliness-get")]
        if let Some(declare) = record.declare() {
            if let Some(interest_id) =
                wz_session_core::declare::liveliness_get::snapshot_final_view(declare)
            {
                self.end_snapshot_leg(face, interest_id);
            }
            #[cfg(wz_round)]
            {
                let mut room = wz_session_core::wireexpr_resolve::KeyexprRow::new_static();
                if let Some(interest_id) = self.claim_lent_token(face, record, &mut room) {
                    let key = wz_session_core::wireexpr_resolve::KeyexprOut::as_str(&room);
                    self.offer_token(face, interest_id, key);
                }
            }
        }
    }

    /// [`Self::take_answers_of`] for one record of a frame the copying receive decoded.
    #[cfg(feature = "query")]
    fn take_owned_answer(
        &mut self,
        face: HeldFace,
        message: &wz_session_core::network_message::NetworkMessage,
    ) {
        use wz_session_core::network_message::NetworkMessage;
        match message {
            #[cfg(wz_round)]
            NetworkMessage::Response(response) => {
                if let Some(reply) = self.take_reply(face, response) {
                    let call = self.admit_reply(face, &reply);
                    self.offer_reply(call, &reply);
                }
            }
            NetworkMessage::ResponseFinal(response_final) => {
                self.end_get_leg(face, response_final.request_id);
            }
            #[cfg(feature = "liveliness-get")]
            NetworkMessage::Declare(declare) => {
                if let Some(interest_id) =
                    wz_session_core::declare::liveliness_get::snapshot_final(declare)
                {
                    self.end_snapshot_leg(face, interest_id);
                }
                #[cfg(wz_round)]
                {
                    let mut room = wz_session_core::wireexpr_resolve::KeyexprRow::new_static();
                    if let Some(interest_id) = self.claim_token(face, declare, &mut room) {
                        let key = wz_session_core::wireexpr_resolve::KeyexprOut::as_str(&room);
                        self.offer_token(face, interest_id, key);
                    }
                }
            }
            _ => {}
        }
    }

    /// A Final of the leg `rid` names on face `face` came: the leg ends at the last its face
    /// owes, and then that leg of its get's row, the last leg ending the get answered, which the
    /// delivery after the hold hands out.
    #[cfg(feature = "query")]
    fn end_get_leg(&mut self, face: HeldFace, rid: wz_session_core::wire_id::RequestId) {
        if let Some(Split { app, face, .. }) = self.split_unwritten(self.place(face)) {
            if let Some(get) = face.gets.legs.end_leg(rid) {
                // A get already ended or retired has no leg left to end: nothing to say.
                let _ = app.tables.end_leg(get);
            }
        }
    }

    /// The DeclFinal of the snapshot `interest_id` names on face `face` came: its leg there ends,
    /// as a query's leg ends at its Final ([`Self::end_get_leg`]).
    #[cfg(feature = "liveliness-get")]
    fn end_snapshot_leg(&mut self, face: HeldFace, interest_id: u64) {
        if let Some(Split { app, face, .. }) = self.split_unwritten(self.place(face)) {
            if let Some(get) = face.gets.snapshots.end_leg(snapshot_leg(interest_id)) {
                // A snapshot already ended or retired has no leg left to end: nothing to say.
                let _ = app.tables.end_leg(get);
            }
        }
    }

    /// The reply of the Response `record` of face `face` lends, read as the read that hands each
    /// record out reads it (`Self::lend_reply`, or its owned projection), admitted to the get its
    /// leg names and offered to the round with the call admission began. A record that is no
    /// Response offers nothing.
    #[cfg(all(feature = "query", wz_round))]
    fn offer_lent_reply(&mut self, face: HeldFace, record: &InPlaceRecord<'_, '_>) {
        let mut room = wz_session_core::reply::ReplyRoom::default();
        let read = self.lend_reply(face, record, &mut room);
        match read {
            Ok(Some(reply)) => {
                // SAFETY: what the reply borrows (the frame, `room`, the face's peer) is neither
                // written nor let go of while it is admitted and offered: the admission writes the
                // tables' row of the get and the face's legs alone.
                let reply = unsafe { super::reply_past_the_read(reply, record) };
                let call = self.admit_reply(face, &reply);
                self.offer_reply(call, &reply);
            }
            Ok(None) => {}
            Err(wz_session_core::driver_loop::OwedToProjection) => {
                if let Some(reply) = self.project_reply(face, record) {
                    let call = self.admit_reply(face, &reply);
                    self.offer_reply(call, &reply);
                }
            }
        }
    }

    /// The alive token at `keyexpr` answering the snapshot `interest_id` names on face `face`,
    /// admitted to the snapshot's row and offered to the round with the call admission began.
    #[cfg(all(feature = "liveliness-get", wz_round))]
    fn offer_token(&mut self, face: HeldFace, interest_id: u64, keyexpr: &str) {
        let reply = wz_session_core::declare::liveliness_get::token_reply(interest_id, keyexpr);
        let call = self.admit_token(face, interest_id, &reply);
        self.offer_reply(call, &reply);
    }

    /// Hold `reply` in the round for the call admission began, under the session's lock: the round
    /// hands it to the get's callback as it is emptied, and ends the call then, or at once when it
    /// refuses the reply.
    #[cfg(all(feature = "query", wz_round))]
    fn offer_reply(
        &self,
        call: Option<GetCall>,
        reply: &dyn wz_session_core::reply_sink::ReplyView,
    ) {
        if let Some(call) = call {
            // SAFETY: the registry is reached under the session's lock alone.
            unsafe { self.delivery.round.offer_reply(call, reply) };
        }
    }

    /// A Push of face `face` lent where its frame lies, read into the sample its subscribers are
    /// handed, over the frame, the face's peer and `room` (`SubscriberPeer::lend_in_place`), for
    /// a walk that hands it to one subscriber at a time with the session let go of (`pinned`).
    /// A face the session no longer holds lends nothing.
    #[cfg(not(wz_round))]
    pub(super) fn lend_push<'s, 'a: 's>(
        &'s mut self,
        face: HeldFace,
        record: &InPlaceRecord<'a, '_>,
        room: &'s mut PeerRoom,
    ) -> LentPush<'s> {
        match self.split_unwritten(self.place(face)) {
            Some(Split { app, face, .. }) => {
                face.peer
                    .subscribers
                    .lend_in_place(&app.tables, record, room)
            }
            None => Ok(None),
        }
    }

    /// The row of the image's allowance the session found for face `face`'s peer
    /// (`SubscriberPeer::class`): what the key gate is asked with of a message that peer sent, as
    /// the face's own dispatch asks it. `None` for a peer the image does not declare, and for a
    /// face the session no longer holds.
    #[cfg(not(wz_round))]
    pub(super) fn peer_class(&self, face: HeldFace) -> Option<wz_session_core::key_gate::ClassId> {
        let at = self.place(face)?;
        self.sets.get(at)?.peer.subscribers.class()
    }

    /// The subscribers' side of `message`, one owned record of a frame of face `face`, taken
    /// ahead of the frame's other planes (`Planes::BesideSubscribers`): a Push's projection, which
    /// the caller hands out one subscriber at a time, and any other record taken as the frame's
    /// dispatch takes it (`SubscriberPeer::take_record`). A face the session no longer holds
    /// takes nothing.
    #[cfg(not(wz_round))]
    pub(super) fn take_subscriber_record(
        &mut self,
        face: HeldFace,
        message: &wz_session_core::network_message::NetworkMessage,
        reliability: wz_session_core::sample::Reliability,
    ) -> Option<wz_session_core::sample::Sample> {
        let Split { app, face, .. } = self.split(self.place(face))?;
        face.peer
            .subscribers
            .take_record(&mut app.tables, message, reliability)
    }

    /// Read the key of `put`, the next plain `Put` of the frame `keys` reads, against the aliases
    /// of face `face`'s peer (`SubscriberPeer::plain_put_key`): whether it names the key read
    /// before it, the key then `keys`' own; `None` for a record that is dropped. A face the
    /// session no longer holds reads none.
    #[cfg(not(wz_round))]
    pub(super) fn plain_put_key(
        &mut self,
        face: HeldFace,
        keys: &mut wz_session_core::pubsub::PlainPutKeys<'_>,
        put: &wz_session_core::plain_push::PlainPut,
    ) -> Option<bool> {
        let Split { app, face, .. } = self.split_unwritten(self.place(face))?;
        face.peer.subscribers.plain_put_key(&app.tables, keys, put)
    }

    /// The owned projection of the Push of face `face` that `record` lends, which the lent form
    /// does not represent (`OwedToProjection`): the sample the copying receive delivers for it.
    /// A face the session no longer holds projects nothing.
    #[cfg(not(wz_round))]
    pub(super) fn project_push(
        &mut self,
        face: HeldFace,
        record: &InPlaceRecord<'_, '_>,
    ) -> Option<wz_session_core::sample::Sample> {
        let Split { app, face, .. } = self.split_unwritten(self.place(face))?;
        face.peer.subscribers.project_in_place(&app.tables, record)
    }

    /// The reply of the Response of face `face` that `record` lends, read over the frame, the
    /// face's peer and `room` as the face's dispatch reads it
    /// (`wz_session_core::reply::lend_response`), for a read that hands it to the get it
    /// answers with the session let go of (`replies`). A record that is no Response, and a face
    /// the session no longer holds, lend nothing.
    #[cfg(feature = "query")]
    pub(super) fn lend_reply<'s, 'a: 's, 'f>(
        &'s mut self,
        face: HeldFace,
        record: &InPlaceRecord<'a, 'f>,
        room: &'s mut wz_session_core::reply::ReplyRoom,
    ) -> wz_session_core::reply::LentResponse<'s, 'f> {
        let Some(response) = record.response() else {
            return Ok(None);
        };
        // Handed to the gets alone, as a ResponseFinal is (`Self::dispatch_reply`).
        #[cfg(all(test, feature = "std"))]
        {
            self.replies_alone += 1;
        }
        match self.split_unwritten(self.place(face)) {
            Some(Split { app, face, .. }) => {
                let own = wz_session_core::pubsub::LocalSubscribers::own_space(&app.tables);
                let spaces = face
                    .peer
                    .subscribers
                    .mapping_spaces_over(own)
                    .from_sender(record.sender());
                wz_session_core::reply::lend_response(response, spaces, room)
            }
            None => Ok(None),
        }
    }

    /// The owned projection of the Response of face `face` that `record` lends, which the lent
    /// form does not represent (`OwedToProjection`): the reply the copying receive delivers
    /// for it. A face the session no longer holds projects nothing.
    #[cfg(feature = "query")]
    pub(super) fn project_reply(
        &mut self,
        face: HeldFace,
        record: &InPlaceRecord<'_, '_>,
    ) -> Option<wz_session_core::reply::InboundReply> {
        let response = record.response()?;
        let Split { app, face, .. } = self.split_unwritten(self.place(face))?;
        let own = wz_session_core::pubsub::LocalSubscribers::own_space(&app.tables);
        let spaces = face
            .peer
            .subscribers
            .mapping_spaces_over(own)
            .from_sender(record.sender());
        face.gets
            .legs
            .receive_mut()
            .project_response(response, spaces)
    }

    /// The reply `response`, a record of a frame of face `face` the copying receive decoded, is
    /// delivered as (`ReplyReceive::take_response`), for a read that hands it to the get it
    /// answers with the session let go of (`replies`), the frame's other planes told the rest of
    /// it after (`Planes::BesideSubscribers`). A face the session no longer holds takes nothing.
    #[cfg(feature = "query")]
    pub(super) fn take_reply(
        &mut self,
        face: HeldFace,
        response: &wz_session_core::wire::ResponseOwned,
    ) -> Option<wz_session_core::reply::InboundReply> {
        let Split { app, face, .. } = self.split_unwritten(self.place(face))?;
        let own = wz_session_core::pubsub::LocalSubscribers::own_space(&app.tables);
        let spaces = face.peer.subscribers.mapping_spaces_over(own);
        face.gets.legs.receive_mut().take_response(response, spaces)
    }

    /// Admit `reply`, read by [`Self::lend_reply`] or projected by [`Self::project_reply`], to
    /// the get its leg on face `face` names (`GetLegs::reply_to`: the face's key gate, then one
    /// look at the row the id carries), under the get's standing, gate and consolidation
    /// (`SessionTables::admit_reply`): the call begun on the get's row for a reply let through,
    /// to make once the session is let go of. A reply held back, dropped, or of a face the session
    /// no longer holds begins none.
    #[cfg(feature = "query")]
    pub(super) fn admit_reply(
        &mut self,
        face: HeldFace,
        reply: &dyn wz_session_core::reply_sink::ReplyView,
    ) -> Option<GetCall> {
        let Split { app, face, .. } = self.split_unwritten(self.place(face))?;
        let get = face.gets.legs.reply_to(reply)?;
        admit_to(&mut app.tables, get, reply)
    }

    /// Admit `reply`, made by one of the session's own queryables, to the get its leg on the
    /// session's own queryables names, as [`Self::admit_reply`] admits a peer's.
    #[cfg(feature = "local-queryable")]
    pub(super) fn admit_local_reply(
        &mut self,
        reply: &dyn wz_session_core::reply_sink::ReplyView,
    ) -> Option<GetCall> {
        let get = self.local.legs.reply_to(reply)?;
        admit_to(&mut self.app.tables, get, reply)
    }

    /// The session's own queryables owe the leg `rid` names no more: it ends, and with it that leg
    /// of its get's row, the last ending the get answered.
    #[cfg(feature = "local-queryable")]
    pub(super) fn end_local_leg(&mut self, rid: wz_session_core::wire_id::RequestId) {
        if let Some(get) = self.local.legs.end_leg(rid) {
            // A get already ended or retired has no leg left to end: nothing to say.
            let _ = self.app.tables.end_leg(get);
        }
    }

    /// The alive token `declare`, a record of a frame of face `face` the copying receive decoded,
    /// answers a pending liveliness get with: its key written into `room` and the interest id it
    /// answers (`LivelinessGetRegistry::claim_token`), for a read that hands it to the get with
    /// the session let go of (`replies`). A declaration that answers no pending get, and a face
    /// the session no longer holds, claim nothing.
    #[cfg(feature = "liveliness-get")]
    pub(super) fn claim_token(
        &mut self,
        face: HeldFace,
        declare: &wz_session_core::transport_profile::owned::DeclareOwned,
        room: &mut dyn wz_session_core::wireexpr_resolve::KeyexprOut,
    ) -> Option<u64> {
        let Split { app, face, .. } = self.split_unwritten(self.place(face))?;
        let own = wz_session_core::pubsub::LocalSubscribers::own_space(&app.tables);
        let spaces = face.peer.subscribers.mapping_spaces_over(own);
        // The engine reads no count of keys past the room; the claim needs one to write to.
        let mut oversize = 0;
        wz_session_core::declare::liveliness_get::claim_answering_token(
            declare,
            |id| face.gets.snapshots.get_of(snapshot_leg(id)).is_some(),
            spaces,
            room,
            &mut oversize,
        )
    }

    /// [`Self::claim_token`] for the Declare `record` lends where its frame lies. A record that is
    /// no Declare claims nothing.
    #[cfg(feature = "liveliness-get")]
    pub(super) fn claim_lent_token(
        &mut self,
        face: HeldFace,
        record: &InPlaceRecord<'_, '_>,
        room: &mut dyn wz_session_core::wireexpr_resolve::KeyexprOut,
    ) -> Option<u64> {
        let declare = record.declare()?;
        let Split { app, face, .. } = self.split_unwritten(self.place(face))?;
        let own = wz_session_core::pubsub::LocalSubscribers::own_space(&app.tables);
        let spaces = face
            .peer
            .subscribers
            .mapping_spaces_over(own)
            .from_sender(record.sender());
        // The engine reads no count of keys past the room; the claim needs one to write to.
        let mut oversize = 0;
        wz_session_core::declare::liveliness_get::claim_answering_token_view(
            declare,
            |id| face.gets.snapshots.get_of(snapshot_leg(id)).is_some(),
            spaces,
            room,
            &mut oversize,
        )
    }

    /// The query the Request `record` of face `face` lends, read for a walk that hands it to each
    /// queryable it reaches with the session let go of (`queries`), its key borrowed where it lies
    /// or composed into `room` (`QueryPeer::pin_request_in_place`): it borrows the face's peer,
    /// as long as the session is held. `None`, with what the Request owes staged in the
    /// face's Finals, for one no queryable is handed, and for a face the session no longer holds;
    /// refused for a Request the lent form does not represent, which the caller dispatches.
    #[cfg(all(feature = "queryable", not(wz_round)))]
    pub(super) fn pin_lent_query<'q, 'r: 'q, 'f: 'r>(
        &'q mut self,
        face: HeldFace,
        record: &InPlaceRecord<'r, 'f>,
        room: &'q mut wz_session_core::wireexpr_resolve::KeyexprBuf,
    ) -> Result<
        Option<wz_session_core::query::pinned::PinnedQuery<'q>>,
        wz_session_core::driver_loop::OwedToProjection,
    > {
        let Some(Split { app, face, .. }) = self.split_unwritten(self.place(face)) else {
            return Ok(None);
        };
        let own = wz_session_core::pubsub::LocalSubscribers::own_space(&app.tables);
        let spaces = face.peer.subscribers.mapping_spaces_over(own);
        face.peer
            .queries
            .pin_request_in_place(record, spaces, room, &mut face.peer.finals)
    }

    /// The query of `request`, a Request of face `face` the copying receive decoded or the owned
    /// projection of one the lent form does not represent, read for a walk that hands it to each
    /// queryable it reaches with the session let go of (`queries`), what the Request does not
    /// hold kept in `room` (`QueryPeer::pin_request`): it borrows the face's peer, as long as
    /// the session is held. `None`, with what the Request owes staged in the face's Finals, for
    /// one no queryable is handed, and for a face the session no longer holds.
    #[cfg(all(feature = "queryable", not(wz_round)))]
    pub(super) fn pin_owned_query<'q>(
        &'q mut self,
        face: HeldFace,
        request: &'q wz_session_core::wire::RequestOwned,
        room: &'q mut wz_session_core::query::pinned::QueryRoom,
    ) -> Option<wz_session_core::query::pinned::PinnedQuery<'q>> {
        let Split { app, face, .. } = self.split_unwritten(self.place(face))?;
        let own = wz_session_core::pubsub::LocalSubscribers::own_space(&app.tables);
        let spaces = face.peer.subscribers.mapping_spaces_over(own);
        face.peer
            .queries
            .pin_request(request, spaces, room, &mut face.peer.finals)
    }

    /// Admit `reply`, the alive token claimed for the snapshot `interest_id` names on face `face`
    /// (`Self::claim_token`), to that snapshot's row, as [`Self::admit_reply`] admits a peer's
    /// reply: the call begun for it, to make once the session is let go of, or to offer the round.
    /// A face the session no longer holds, and a snapshot no leg of it names, begin none.
    #[cfg(feature = "liveliness-get")]
    pub(super) fn admit_token(
        &mut self,
        face: HeldFace,
        interest_id: u64,
        reply: &dyn wz_session_core::reply_sink::ReplyView,
    ) -> Option<GetCall> {
        let Split { app, face, .. } = self.split_unwritten(self.place(face))?;
        let get = face.gets.snapshots.get_of(snapshot_leg(interest_id))?;
        admit_to(&mut app.tables, get, reply)
    }

    /// How often a face's tables were looked up since the open: what a lent Push's count of its
    /// lookups starts from ([`Self::counted_push`]).
    #[cfg(all(test, feature = "std", not(wz_round)))]
    pub(super) fn lookups(&self) -> u64 {
        self.face_lookups
    }

    /// What face `id`'s peer is owed outside the dispatch of a record that drains it, under one
    /// lookup of the face: the subscribers' tables reconciled with what the application registered
    /// since, what anything staged drained through `actions` ([`Self::flush_pending_replies`]).
    /// Settled once after a run of lent Pushes (`Self::dispatch_push`, or `Self::lend_push`), and
    /// after the application declares or undeclares a subscriber, which no record of the peer's
    /// need follow. A face the session no longer holds owes nothing.
    #[cfg(feature = "queryable")]
    pub(super) fn settle<S>(&mut self, face: HeldFace, actions: &S)
    where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        if let Some(Split { app, face, .. }) = self.split_unwritten(self.place(face)) {
            #[cfg(wz_interest_answer)]
            reconcile_face(app, face);
            app.flush_pending_replies(&mut face.peer, &mut face.gets, actions);
            // No `Final` is owed here: only a Request's dispatch owes one
            // (`wz_session_core::query::QueryPeer::dispatch_request_in_place` and
            // `QueryPeer::dispatch_messages_with`), and the dispatch of a record that is not a Push
            // takes every one it owed before the next record is read (`FaceDispatch::event`).
            debug_assert!(face.peer.finals.is_empty(), "a run of Pushes owes no Final");
        }
    }

    /// Fan and drain in one call, the `Final`s with the rest: what a session with no queryable
    /// to wait for does with each event.
    #[cfg(all(not(feature = "queryable"), wz_round))]
    pub(super) fn dispatch<S>(&mut self, face: HeldFace, event: IterationEvent<'_, '_>, actions: &S)
    where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        self.dispatch_to(face, event, Planes::All, actions);
    }

    /// Fan and drain one event of face `face` into the planes `planes` names, the `Final`s with
    /// the rest.
    #[cfg(not(feature = "queryable"))]
    pub(super) fn dispatch_to<S>(
        &mut self,
        face: HeldFace,
        event: IterationEvent<'_, '_>,
        planes: Planes,
        actions: &S,
    ) where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        self.dispatch_event_to(face, event, planes);
        #[cfg(wz_interest_answer)]
        self.reconcile_subscribers(face);
        if let Some(Split { app, face, .. }) = self.split(self.place(face)) {
            app.flush_pending(&mut face.peer, &mut face.gets, actions);
        }
    }

    /// What face `id`'s peer is owed outside the dispatch of a record, drained under one lookup of
    /// the face, as `dispatch_to` drains after every other record: after a run of lent Pushes
    /// (`Self::dispatch_push`, or `Self::lend_push`), and after the application declares or
    /// undeclares a subscriber.
    #[cfg(not(feature = "queryable"))]
    pub(super) fn settle<S>(&mut self, face: HeldFace, actions: &S)
    where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        if let Some(Split { app, face, .. }) = self.split_unwritten(self.place(face)) {
            #[cfg(wz_interest_answer)]
            reconcile_face(app, face);
            app.flush_pending(&mut face.peer, &mut face.gets, actions);
        }
    }

    /// The link of face `id` was lost: every subscriber and queryable its peer declared is gone,
    /// and the matching listeners are told what that makes of them, the other faces' peers
    /// counting as they do.
    pub(super) fn flush_declarations_on_link_loss(&mut self, id: FaceId) -> usize {
        self.split(self.held_at(id)).map_or(
            0,
            |Split {
                 app, face, others, ..
             }| { app.flush_declarations_on_link_loss_among(&mut face.peer, &others) },
        )
    }

    /// The link of face `id` was lost: every token its peer declared is gone, and the liveliness
    /// subscribers are to be told each is. The face's set owes them the retractions until
    /// `Self::retract_owed` or `Self::take_lost_token` has handed every one, or the face goes and
    /// they are owed apart.
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
    #[cfg(all(feature = "liveliness", wz_round))]
    pub(super) fn retract_owed(&mut self, room: &mut dyn FnMut() -> bool) -> bool {
        self.writing();
        let Self {
            app,
            delivery,
            sets,
            #[cfg(any(feature = "listen", feature = "group"))]
            owed,
            ..
        } = self;
        // A set no face holds retracts nothing: giving it back ended its retraction.
        for set in sets.iter_mut() {
            if set.retracting {
                set.retracting =
                    !app.flush_liveliness_on_link_loss_while(delivery, &mut set.peer, room);
                if set.retracting {
                    return false;
                }
            }
        }
        // The faces that went, in the order they went.
        #[cfg(any(feature = "listen", feature = "group"))]
        if !owed.retract_while(app, delivery, room) {
            return false;
        }
        true
    }

    /// Whether a face whose link was lost still owes the liveliness subscribers a token's
    /// retraction (`Self::take_lost_token`): one the session holds, or one that went before its
    /// tokens were all handed, whose tokens wait apart (`Self::owe_tokens_of`).
    #[cfg(all(feature = "liveliness", not(wz_round)))]
    pub(super) fn retracting(&self) -> bool {
        #[cfg(any(feature = "listen", feature = "group"))]
        if !self.owed.is_empty() {
            return true;
        }
        self.sets.iter().any(|set| set.retracting)
    }

    /// The next token a face whose link was lost owes the liveliness subscribers, its row
    /// unbound and its `Delete` written into `news`, for a read that hands it to them one row at
    /// a time with the session let go of: whether there was one. They go in the order
    /// `Self::retract_owed` hands them where the round does: those of the faces held first, then
    /// those of the faces that went, in the order they went, each face's in ascending id. A face
    /// left owing none retracts no more, and the tokens a face that went owed are let go of, their
    /// rows back in the session's pool, once the last is taken.
    #[cfg(all(feature = "liveliness", not(wz_round)))]
    pub(super) fn take_lost_token(
        &mut self,
        news: &mut wz_session_core::declare::liveliness_subscriber::TokenNews,
    ) -> bool {
        let mut taken = false;
        for set in self.sets.iter_mut().filter(|set| set.retracting) {
            taken = set.peer.tokens.take_lost(news);
            if taken {
                break;
            }
            set.retracting = false;
        }
        #[cfg(any(feature = "listen", feature = "group"))]
        if !taken {
            taken = self.owed.take_lost(news);
        }
        if taken {
            self.writing();
        }
        taken
    }

    /// The peer token the Declare `record` of face `face` lends, bound or unbound in the face's
    /// peer table under the session's lock, with what the liveliness subscribers are to be told of
    /// it written into `news` (`PeerTokens::take_token_view`), for a read that hands it to them
    /// one row at a time with the session let go of; the face's dispatch then leaves the token
    /// alone (`READ_TAKES`). Whether there is any: none for a record that is no token, one a
    /// pending liveliness get claims, and a face the session no longer holds.
    #[cfg(all(feature = "liveliness", not(wz_round)))]
    pub(super) fn take_lent_token(
        &mut self,
        face: HeldFace,
        record: &InPlaceRecord<'_, '_>,
        news: &mut wz_session_core::declare::liveliness_subscriber::TokenNews,
    ) -> bool {
        let Some(declare) = record.declare() else {
            return false;
        };
        let Some(Split { app, face, .. }) = self.split(self.place(face)) else {
            return false;
        };
        #[cfg(feature = "liveliness-get")]
        if declare
            .interest_id
            .is_some_and(|id| face.gets.snapshots.get_of(snapshot_leg(id)).is_some())
        {
            return false;
        }
        let own = wz_session_core::pubsub::LocalSubscribers::own_space(&app.tables);
        let spaces = face
            .peer
            .subscribers
            .mapping_spaces_over(own)
            .from_sender(record.sender());
        face.peer
            .tokens
            .take_token_view(&declare.body, spaces, declare.interest_id.is_some(), news)
    }

    /// [`Self::take_lent_token`] for `declare`, a record of a frame of face `face` the copying
    /// receive decoded.
    #[cfg(all(feature = "liveliness", not(wz_round)))]
    pub(super) fn take_owned_token(
        &mut self,
        face: HeldFace,
        declare: &wz_session_core::transport_profile::owned::DeclareOwned,
        news: &mut wz_session_core::declare::liveliness_subscriber::TokenNews,
    ) -> bool {
        let Some(Split { app, face, .. }) = self.split(self.place(face)) else {
            return false;
        };
        #[cfg(feature = "liveliness-get")]
        if declare
            .interest_id
            .is_some_and(|id| face.gets.snapshots.get_of(snapshot_leg(id)).is_some())
        {
            return false;
        }
        let own = wz_session_core::pubsub::LocalSubscribers::own_space(&app.tables);
        let spaces = face.peer.subscribers.mapping_spaces_over(own);
        face.peer
            .tokens
            .take_token(&declare.body, spaces, declare.interest_id.is_some(), news)
    }

    /// Keep apart what the set at `at` still owes the liveliness subscribers as its face `face`
    /// goes: the tokens of a lost link not retracted yet, which [`Self::retract_owed`] hands after
    /// those owed before them. The set is given back all the same, its token table left empty.
    #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
    fn owe_tokens_of(&mut self, at: usize, face: FaceId) {
        let Some(set) = self.sets.get_mut(at) else {
            return;
        };
        if !core::mem::take(&mut set.retracting) {
            return;
        }
        self.owed.owe(face, &mut set.peer.tokens);
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
            None => self.held_ids().min()?,
        };
        let mut after = cursor.after;
        loop {
            let tokens = self
                .held_at(face)
                .and_then(|at| self.sets.get(at))
                .map(|set| &set.peer.tokens);
            if let Some(tokens) = tokens {
                if let Some((token, key)) =
                    tokens.next_known_token(self.app.tables.liveliness_subscribers(), id, after)
                {
                    let next = HistoryCursor {
                        face: Some(face),
                        after: Some(token),
                    };
                    return Some((next, token, key));
                }
            }
            face = self.held_ids().filter(|held| *held > face).min()?;
            after = None;
        }
    }
}

/// Stage for `face`'s peer what the application did to its subscriptions since the peer last looked
/// ([`Registry::reconcile_subscribers`]): one body for every caller, not one for each that inlines
/// it. Only a build that answers its peers' Interests keeps any to reconcile.
#[cfg(wz_interest_answer)]
#[inline(never)]
fn reconcile_face(app: &App, face: &mut FaceTables) {
    face.peer.subscribers.reconcile(&app.tables);
}

/// Write a set of no rows in the next row of `sets`, held to `limits`, its peer's keys kept in
/// `keys`, the session's key arena, and what its peer writes in the rows `pools`, the session's,
/// hands it, and hand it back: a set is never a value of its own in this frame. `None` when
/// `sets` holds every row it was lent.
#[cfg(wz_lent)]
fn push_rowless<'s>(
    sets: &'s mut BoundedVec<FaceTables, MAX_FACE_SETS, RowPolicy>,
    keys: KeySpace,
    pools: &mut PeerPools,
    limits: &SessionLimits,
) -> Option<&'s mut FaceTables> {
    let set = push_unpeered(sets, keys, limits)?;
    set.peer.keep_rows_in(pools);
    Some(set)
}

/// Write a set of no rows in the next row of `sets` that takes nothing of the session's pools: the
/// dial face's of a session that dials nothing, which never has a peer to write into them. With one
/// face's own spans, taking them here would leave the one face that comes none. `None` when
/// `sets` holds every row it was lent.
#[cfg(wz_lent)]
fn push_unpeered<'s>(
    sets: &'s mut BoundedVec<FaceTables, MAX_FACE_SETS, RowPolicy>,
    keys: KeySpace,
    limits: &SessionLimits,
) -> Option<&'s mut FaceTables> {
    // SAFETY: `rowless_in` writes a whole set into the row it is handed and cannot unwind.
    let set = unsafe {
        sets.push_in_place(|place| {
            FaceTables::rowless_in(place, limits);
        })
    }?;
    set.peer.keep_keys_in(LentKeys::from(keys));
    Some(set)
}

/// Write a set at the end of `sets` and lend it its rows there, `gets` and `peer` of them from
/// `arena`, the peer's keys kept in `keys` and what it writes in `pools`, held to `limits`. A
/// refused set stays in `sets`, whole, and goes with it.
///
/// Never inlined: the open calls it in a loop, and a loop whose first turn the compiler peels
/// would carry the set's writing and lending twice.
#[cfg(wz_lent)]
#[inline(never)]
fn lend_set(
    sets: &mut BoundedVec<FaceTables, MAX_FACE_SETS, RowPolicy>,
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
    set.lend(arena, keys, gets, peer)
}

/// The engine is generic over its links, so the crate that names them drops the registry, and a
/// type's drop glue is instantiated anew in every crate that drops it: the application's tables
/// and the faces' sets, the most of that glue, are dropped by one body of this crate instead
/// (`let_go`). A `Drop` of the registry alone would not do it: the glue of its fields would
/// still follow it in the dropping crate, so the two are held in `ManuallyDrop`.
///
/// They go first, the tables before the sets as their fields lie, and the registry's other fields
/// after them in their order: what lay between the two (the round's handles, a test's handles of
/// the pools) has nothing to drop. The registry lies in the session's state, which is dropped
/// before the session's arena, so every row either part was lent is let go of while the memory it
/// lies in is still the session's.
impl Drop for Registry {
    fn drop(&mut self) {
        // SAFETY: the registry is being dropped: neither part is read again, and this is the one
        // place either is dropped.
        unsafe { let_go(&mut self.app, &mut self.sets) };
    }
}

/// Drop the application's tables, then the faces' sets: the one body every drop of a registry
/// runs, whichever crate drops it (see the `Drop` of `Registry`), so never inlined.
///
/// # Safety
///
/// Neither part is used, or dropped, again.
#[inline(never)]
unsafe fn let_go(
    app: &mut ManuallyDrop<App>,
    sets: &mut ManuallyDrop<BoundedVec<FaceTables, MAX_FACE_SETS, RowPolicy>>,
) {
    // SAFETY: the caller's contract.
    unsafe {
        ManuallyDrop::drop(app);
        ManuallyDrop::drop(sets);
    }
}

// The registry's own tests build it from an arena, as a build that lays its arena out at the open
// does; a build of the region's form is held by the region's tests (`crate::tests::region`). Each
// test builds the registry of the build under test, so those of faces beside the dial role's are
// built where the build takes such faces (`listen`, `group`): a build of the dial role's face
// alone is tested in the form it ships, whose plan lays out no mark past that face.
#[cfg(all(test, wz_lent))]
mod tests {
    //! Each face's tables are lent from the session's arena: the dial face's at the open, an
    //! accepted face's from the spares the open lent, and past those tables of no rows that refuse
    //! what is asked of them: the session takes no memory but its arena.
    #[cfg(any(feature = "listen", feature = "group"))]
    use super::adding::FacesFull;
    use super::*;
    use crate::arena::{AllocatorMemory, SessionArena};
    #[cfg(any(feature = "listen", feature = "group"))]
    use wz_session_core::bounded::seq_bytes;
    use wz_session_core::bounded::{seq_rows, RowCounts, SeqPlace};
    use wz_session_core::peer_tables::PeerPoolRows;
    #[cfg(any(feature = "listen", feature = "group"))]
    use wz_session_core::pubsub::SubscriberPeer;
    use wz_session_core::reply_stage::FinalStaging;
    use wz_session_core::sample::QosLevel;

    /// Without the declaration watches the observers this engine may hold are none: the lists'
    /// sink has no value, so a list holds nothing to drop and frees nothing. Turned red by boxed
    /// sinks chosen for a build that installs none.
    #[cfg(not(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    )))]
    #[test]
    fn without_the_watches_an_observer_list_holds_nothing_to_drop() {
        assert!(!core::mem::needs_drop::<
            <CoopSinks as ObserverSinks>::Declared,
        >());
        assert!(!core::mem::needs_drop::<
            <CoopSinks as ObserverSinks>::Undeclared,
        >());
    }

    /// A build that asks no query keeps no table of pending gets on a face: its requester side is
    /// of no size and holds nothing to drop. Turned red by a table of gets chosen for such a build.
    #[cfg(not(feature = "query"))]
    #[test]
    fn without_query_a_face_keeps_no_table_of_gets() {
        assert_eq!(core::mem::size_of::<Gets>(), 0);
        assert!(!core::mem::needs_drop::<Gets>());
    }

    /// A registry and the arena its tables were lent from, the registry first so its tables go
    /// before the memory they lie in, and how many sets the open lent rows to.
    struct Held {
        registry: Registry,
        arena: SessionArena,
        /// How many sets the open lent rows to, which the tests of faces beside the dial role's
        /// read.
        #[cfg(any(feature = "listen", feature = "group"))]
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
        try_held_as(faces, pools, dial, observer_rows()).expect("the arena has the rows")
    }

    /// The registry [`held_as`] opens, the application's tables and lists lent `rows`, or why
    /// the open refused it.
    fn try_held_as(
        faces: usize,
        pools: PeerPoolRows,
        dial: bool,
        rows: wz_session_core::session_tables::TableRows,
    ) -> Result<Held, LendRefused> {
        let mut arena =
            SessionArena::of_bytes(1 << 20, &AllocatorMemory).expect("the host has the memory");
        let keys = arena
            .arena_mut()
            .lend_keys(4096, SessionLimits::defaults().max_keyexpr_bytes_held())
            .expect("the arena holds the key arena");
        let delivery = RoundDelivery {
            #[cfg(wz_round)]
            round: crate::round::leaked(4),
            #[cfg(feature = "queryable")]
            plane: wz_session_core::placed::PlacedRef::of_static(alloc::boxed::Box::leak(
                super::super::query::leaked_plane(1),
            )),
        };
        let registry = Registry::new(
            &SessionLimits::defaults(),
            arena.arena_mut(),
            keys,
            rows,
            test_gets(faces),
            test_peers(faces, pools, dial),
            delivery,
        )?;
        Ok(Held {
            registry,
            arena,
            #[cfg(any(feature = "listen", feature = "group"))]
            lent: faces,
            keys,
        })
    }

    /// The application's rows a test's registry is lent: a row for a liveliness subscriber, which
    /// the tests of retractions declare.
    fn observer_rows() -> wz_session_core::session_tables::TableRows {
        wz_session_core::session_tables::TableRows {
            liveliness_subscribers: 1,
            ..Default::default()
        }
    }

    /// The tables of gets a test's registry of `faces` faces is lent: one row each.
    fn test_gets(faces: usize) -> GetTables {
        GetTables {
            rows: RequesterRows {
                queries: 1,
                liveliness_gets: 0,
            },
            tables: faces + usize::from(cfg!(feature = "local-queryable")),
        }
    }

    /// The rows of the tables of each of `faces` faces a test's registry is lent, and its pools:
    /// one of each table, and no reply staged, as the engine's plan lends none
    /// (`arena::peer_rows`).
    fn test_peers(faces: usize, pools: PeerPoolRows, dial: bool) -> FacePeers {
        FacePeers {
            rows: PeerRows {
                pending_declares: 1,
                replies: 0,
                reply_bytes: 0,
                finals: 1,
            },
            tables: faces,
            pools,
            dial,
        }
    }

    /// The counts the registry's own lines are lent for a test's registry of `faces` faces.
    fn registry_counts(faces: usize, pools: PeerPoolRows) -> RowCounts {
        let rows = observer_rows();
        let peers = test_peers(faces, pools, true);
        rows.counts()
            .and(&App::list_counts(&SessionLimits::defaults()).expect("the build's watchers"))
            .and(&test_gets(faces).rows.counts())
            .with(RowCount::FaceSets, peers.sets())
            .with(RowCount::HeldSets, HeldPlaces::rows_of(peers.sets()))
            .with(RowCount::OwedTokens, peers.owed_tokens())
    }

    /// Hold what a walk lent through `lines` at `base`, a value of `size` bytes, to the lines:
    /// each sequence lies inside the value and no two share a place, each table holds its line's
    /// count, its rows lie at the offset the count of the lines before it says from the first
    /// table's, and no two tables' rows meet. Answers where the first table's rows lie, none where
    /// the build describes no table, and the bytes every line took.
    fn laid_as_described(
        base: *const u8,
        size: usize,
        lines: &[SeqPlace],
        counts: &RowCounts,
    ) -> (Option<usize>, usize) {
        let seq = core::mem::size_of::<BoundedVec<u8, 1, RowPolicy>>();
        let base = NonNull::new(base.cast_mut()).expect("a value lies somewhere");
        let mut first = None;
        let mut offset = 0;
        let mut spans: Vec<(core::ops::Range<usize>, core::ops::Range<usize>)> = Vec::new();
        for line in lines {
            // SAFETY: each line names a sequence of the value at `base` that a walk lent its rows,
            // and nothing writes the value during the call.
            let (at, room) = unsafe { seq_rows(base, line) };
            let at = at.expect("a lent table has rows").as_ptr() as usize;
            let start = *first.get_or_insert(at);
            assert_eq!(
                at - start,
                offset,
                "the rows lie where the count of the lines before says"
            );
            assert_eq!(room as usize, counts.of(line), "the table holds its count");
            let span = Arena::stride_bytes(counts.of(line), line.stride as usize).expect("small");
            let place = line.seq as usize..line.seq as usize + seq;
            assert!(place.end <= size, "a sequence lies in what is described");
            for (other_place, other_rows) in &spans {
                assert!(
                    place.end <= other_place.start || other_place.end <= place.start,
                    "no two lines name one sequence"
                );
                assert!(
                    at + span <= other_rows.start || other_rows.end <= at,
                    "no two tables' rows meet"
                );
            }
            spans.push((place, at..at + span));
            offset += span;
        }
        (first, offset)
    }

    fn face(registry: &mut Registry, id: FaceId) -> &mut FaceTables {
        registry.held_mut(id).expect("the registry holds the face")
    }

    #[cfg(any(feature = "listen", feature = "group"))]
    /// How many sets the open lent that no face holds: the lent sets lie first.
    fn free_lent(held: &Held) -> usize {
        marks(&held.registry)
            .iter()
            .take(held.lent)
            .filter(|holder| **holder == NO_FACE)
            .count()
    }

    /// The mark of each place of the registry's table of them, the dial role's first.
    fn marks(registry: &Registry) -> Vec<FaceId> {
        registry.holders.marks().collect()
    }

    #[cfg(any(feature = "listen", feature = "group"))]
    /// Whether face `id` holds a set the open lent rows to.
    fn in_a_lent_set(held: &Held, id: FaceId) -> bool {
        held.registry.held_at(id).is_some_and(|at| at < held.lent)
    }

    #[cfg(any(feature = "listen", feature = "group"))]
    /// The faces the registry holds, in the order its walks take them.
    fn face_ids(registry: &Registry) -> Vec<FaceId> {
        registry.held_ids().collect()
    }

    #[cfg(any(feature = "listen", feature = "group"))]
    /// Remove face `id` by the key its link or its group holds.
    fn remove(registry: &mut Registry, id: FaceId) {
        let face = registry.held(id);
        registry.remove_face(face);
    }

    #[cfg(any(feature = "listen", feature = "group"))]
    /// Where the sets the walk over the faces takes lie.
    fn walked(registry: &Registry) -> Vec<*const FaceTables> {
        registry
            .faces()
            .map(|face| face as *const FaceTables)
            .collect()
    }

    #[cfg(any(feature = "listen", feature = "group"))]
    /// Where the sets at `at` lie.
    fn lying_at(registry: &Registry, at: &[usize]) -> Vec<*const FaceTables> {
        at.iter()
            .map(|at| &registry.sets[*at] as *const FaceTables)
            .collect()
    }

    /// Whether a face's set is lent a row of `Final`s: a build that answers no query owes its
    /// peers none (`Registry::pin_lent_query`), so a set's description has no line of them
    /// (`described`) and their stage has no room. A test that marks a set as a face's holds it by
    /// what the face's peer declares, which every build keeps.
    const OWES_FINALS: bool = cfg!(feature = "queryable");

    /// The face's peer tables hold one `Final`, have no room for a second, and have room again
    /// once what is owed is taken: the rows the arena lent stay with the table. A build that
    /// answers no query describes no `Final` of a face's (`described`), whose stage then has no
    /// room.
    fn holds_one_final(face: &mut FaceTables) {
        if !OWES_FINALS {
            assert!(
                !face.peer.finals.has_room(),
                "no Final is owed where nothing answers a query"
            );
            return;
        }
        assert!(face.peer.finals.has_room(), "a row was lent");
        face.peer.finals.owe(1, QosLevel::DEFAULT);
        assert!(!face.peer.finals.has_room(), "the one row holds the Final");
        assert_eq!(face.peer.finals.take_owed().len(), 1);
        assert!(
            face.peer.finals.has_room(),
            "taking what is owed keeps the row"
        );
    }

    /// A group's face holds its members' aliases together, what the open reserved for it, and the
    /// set it held, given back, holds the next face's peer to one peer's again.
    #[cfg(feature = "multicast-declarations")]
    #[test]
    fn a_groups_face_holds_its_members_aliases_until_its_set_is_given_back() {
        let group = Quota::at_most(crate::arena::GROUP_FACE_ALIASES);
        if MaxPeerKeyexprAliasesHeld::select(group).is_err() {
            // A build whose limits keep the build's value alone states no quota of a face.
            return;
        }
        let fewer = MaxPeerKeyexprAliasesHeld::select(Quota::at_most(2))
            .expect("two is inside the domain where a group's quota is");
        let mut held = held(2);
        let face = held
            .registry
            .add_face(5)
            .expect("the open lent a set for the face");
        let quota = |registry: &Registry| {
            registry.sets[face.at()]
                .peer
                .subscribers
                .alias_quota()
                .get()
        };
        let one_peer = quota(&held.registry);
        // A face held below what the group's members may declare together.
        held.registry.sets[face.at()]
            .peer
            .subscribers
            .limit_aliases_to(fewer);
        assert_eq!(quota(&held.registry), Quota::at_most(2), "CONTROL");
        held.registry.hold_member_aliases(face);
        assert_eq!(
            quota(&held.registry),
            group,
            "the group's face holds every member's"
        );
        held.registry.remove_face(face);
        assert_eq!(
            quota(&held.registry),
            one_peer,
            "the set given back holds the next face to one peer's"
        );
    }

    /// Every face keeps the keys of what its peer declares in the session's key arena: the dial
    /// face's set and the sets the open lent that faces take as they come (a group's, which the
    /// session adds as it joins the group, `join_groups`). A subscriber each face's peer declares
    /// is held and matched, its key a block of the one arena, and nothing is refused.
    #[cfg(any(feature = "listen", feature = "group"))]
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

    /// A session that dials nothing gives its dial face a set of no rows, which takes nothing of the
    /// arena and nothing of the pools: the one set it lent, with one face's own spans, is the first
    /// accepted face's, whose peer's subscriber is held there. The CONTROL is the same plan with
    /// the dial face's set lent, where the first accepted face is past the plan and holds nothing.
    #[cfg(any(feature = "listen", feature = "group"))]
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
        assert!(
            dialling.registry.add_face(5).is_err(),
            "CONTROL: the one set is the dial face's: none is left for the face that comes"
        );
        assert_eq!(
            dialling.registry.held_at(5),
            None,
            "CONTROL: the face that comes holds no set"
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
        listening
            .registry
            .add_face(5)
            .expect("the open lent a set for the face");
        assert_eq!(listening.registry.held_at(5), Some(1));
        assert_eq!(
            declared(&mut listening, 5),
            (true, OWES_FINALS),
            "the face that comes takes the lent set and the one face's spans"
        );
        assert_eq!(
            listening.arena.arena_mut().high_water(),
            lent,
            "nothing more is lent as the face comes"
        );
        assert_eq!(listening.registry.sets.len(), 2);
        remove(&mut listening.registry, DIAL_FACE);
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
    #[cfg(all(wz_interest_answer, any(feature = "listen", feature = "group")))]
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
            set.peer.subscribers.answer_subscriber_interest(
                &mut app.tables,
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
        let dial = held.registry.held(DIAL_FACE);
        let owed: Vec<_> = held
            .registry
            .take_pending_final_rids(dial)
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
        use wz_session_core::declare::local_token::LocalTokenRegistry;

        let mut held = held(1);
        let none = LocalTokenRegistry::new();
        let staging = &mut face(&mut held.registry, DIAL_FACE).peer.token_answers;
        assert!(staging.stage(&none, None, 1).is_ok());
        assert!(staging.stage(&none, None, 2).is_err());
    }

    /// An accepted face takes the set the open lent where it lies, empties it there when it goes,
    /// and the next face takes the same set at the same address: a set is never moved.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[test]
    fn an_accepted_face_takes_a_lent_set_where_it_lies_and_gives_it_back_there() {
        let mut held = held(2);
        assert_eq!(free_lent(&held), 1);
        held.registry
            .add_face(5)
            .expect("the open lent a set for the face");
        assert_eq!(free_lent(&held), 0);
        assert!(in_a_lent_set(&held, 5));
        declare_on(&mut held.registry, 5, 1, "demo/accepted/one");
        assert_eq!(
            subscribers_of(&held.registry, 5).0,
            1,
            "CONTROL: the face's peer holds what it declared"
        );
        let lies_at: *const FaceTables = face(&mut held.registry, 5);
        remove(&mut held.registry, 5);
        assert_eq!(free_lent(&held), 1, "the set went back");
        assert_eq!(held.registry.sets.len(), 2, "and stayed where it lies");
        assert_eq!(
            held.registry.sets[1]
                .peer
                .remote_subscribers
                .declared_count(),
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
    /// and are retracted in the order the faces went, each face's in ascending id. Where the round
    /// is kept they are handed through it, and the CONTROL is a retraction refused for room, which
    /// hands nothing and keeps every token owed. Where the read hands each token itself it takes
    /// them one at a time (`Registry::take_lost_token`), and the CONTROL is that the session still
    /// owes them once both faces went, so the read is told to take them.
    #[cfg(all(
        feature = "std",
        feature = "liveliness",
        any(feature = "listen", feature = "group")
    ))]
    #[test]
    fn a_face_that_goes_owing_retractions_gives_its_set_back_at_once() {
        use std::sync::{Arc, Mutex};
        use wz_capi_port::{LivelinessSink, WireKey};
        use wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleKind};
        use wz_session_core::declare_build::build_declare_token;
        use wz_session_core::session_tables::KeyForm;

        let mut held = held(3);
        let heard: Arc<Mutex<Vec<(String, u64)>>> = Arc::default();
        let into = Arc::clone(&heard);
        held.registry
            .app
            .tables
            .declare_liveliness_subscriber(
                "demo/**",
                false,
                KeyForm::default(),
                super::super::LivelinessRow::new(
                    WireKey::literal().into_anchor(),
                    LivelinessSink::shared(move |sample: LivelinessSample<'_>| {
                        if sample.kind == LivelinessSampleKind::Delete {
                            into.lock()
                                .unwrap()
                                .push((sample.keyexpr.to_owned(), sample.token_id));
                        }
                    }),
                ),
            )
            .map_err(|refused| refused.why)
            .expect("the subscriber is declared");
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
            let Registry {
                app,
                delivery,
                sets,
                ..
            } = &mut held.registry;
            let peer = &mut sets[at].peer;
            for token in tokens {
                let key = std::format!("demo/{id}/{token}");
                let declare = build_declare_token(token, 0, Some(&key)).expect("a declaration");
                let (_, subscribers) = app.tables.liveliness_mut();
                peer.tokens.dispatch_declare_historical(
                    subscribers,
                    delivery,
                    &declare.body,
                    peer.subscribers.mapping_spaces(),
                    false,
                );
            }
            assert_eq!(peer.tokens.count(), 2, "face {id} holds its peer's tokens");
        }
        // The appearances are handed out, so the round has room for the retractions.
        #[cfg(wz_round)]
        {
            // SAFETY: this thread is the round's one writer.
            unsafe { held.registry.delivery.round.seal() };
            assert!(held.registry.delivery.round.deliver(), "the appearances");
        }
        let lies_at: *const FaceTables = face(&mut held.registry, 5);
        held.registry.lose_tokens(5);
        held.registry.lose_tokens(6);
        remove(&mut held.registry, 5);
        remove(&mut held.registry, 6);
        assert_eq!(held.registry.owed.len(), 2, "each face's tokens owed apart");
        let tokens_used = |held: &Held| held.registry.spares.pools.counts().map(|c| c.tokens.used);
        assert_eq!(
            tokens_used(&held),
            Some(4),
            "their rows kept in the session's pool"
        );
        #[cfg(wz_round)]
        assert!(
            !held.registry.retract_owed(&mut || false),
            "CONTROL: no room, so still owed"
        );
        #[cfg(not(wz_round))]
        assert!(
            held.registry.retracting(),
            "CONTROL: the faces that went still owe their tokens"
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
        #[cfg(wz_round)]
        {
            assert!(
                held.registry.retract_owed(&mut || true),
                "every token retracted"
            );
            // SAFETY: this thread is the round's one writer.
            unsafe { held.registry.delivery.round.seal() };
            assert!(held.registry.delivery.round.deliver(), "the retractions");
        }
        // The read hands each token it takes to the subscribers itself (`hand_lost_tokens`); here
        // the test is that read, and the subscriber's sink is told nothing.
        #[cfg(not(wz_round))]
        {
            let mut news = wz_session_core::declare::liveliness_subscriber::TokenNews::default();
            while held.registry.take_lost_token(&mut news) {
                let sample = news.sample();
                assert!(
                    sample.kind == LivelinessSampleKind::Delete,
                    "a lost token is retracted"
                );
                heard
                    .lock()
                    .unwrap()
                    .push((sample.keyexpr.to_owned(), sample.token_id));
            }
            assert!(!held.registry.retracting(), "every token retracted");
        }
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
    #[cfg(any(feature = "listen", feature = "group"))]
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
            if OWES_FINALS {
                accepted.peer.finals.owe(1, QosLevel::DEFAULT);
                assert!(
                    !accepted.peer.finals.has_room(),
                    "CONTROL: its one row is held"
                );
            }
        }
        assert_eq!(free_lent(&held), 0);
        remove(&mut held.registry, 5);
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
            assert_eq!(
                set.peer.finals.has_room(),
                OWES_FINALS,
                "each row of each set is free"
            );
            #[cfg(feature = "query")]
            assert!(set.gets.legs.has_room());
        }
        assert_eq!(
            face_ids(&held.registry),
            vec![DIAL_FACE],
            "the dial role's face stays"
        );
    }

    /// Every table of the registry lies where the registry's description counts it, lent by one
    /// walk: the application's lists and tables, the sets' table and the index of their holders
    /// with a row for each set, the tokens owed and the session's own gets where the build keeps
    /// them; no two tables meet, and the plan's count of the lines is what the walk took. The dial
    /// face's set lies as its own description counts it from the first byte past the registry's
    /// rows, the reserve the sets to come are built in lies right before those, and a set built
    /// there when a face comes lies as the same description counts it. Turned red by a line of the
    /// registry's or a set's description at another offset or count than the table it names (the
    /// sets' line counted as another table's, the index's line left out), by a walk that lends in
    /// another order than its description, or by a span lent between the walks.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[test]
    fn every_table_of_the_registry_lies_where_its_description_counts_it() {
        let pools = PeerPoolRows {
            aliases: 16,
            remote_decls: 16,
            interests: 16,
            shared: true,
        };
        let mut held = held_with(3, pools);
        let counts = registry_counts(3, pools);
        let lines = Registry::LINES;
        let (registry_rows, registry_bytes) = laid_as_described(
            (&held.registry as *const Registry).cast::<u8>(),
            core::mem::size_of::<Registry>(),
            lines.seq_lines(),
            &counts,
        );
        let registry_rows = registry_rows.expect("the registry describes its table of sets");
        assert_eq!(
            seq_bytes(lines.seq_lines(), &counts),
            Some(registry_bytes),
            "the count of the lines is what the walk took"
        );
        let peers = test_peers(3, pools, true);
        assert!(
            held.registry
                .holders
                .marks()
                .eq([DIAL_FACE, NO_FACE, NO_FACE]),
            "a mark for each place, the dial role's face first"
        );
        let gets = test_gets(3).rows;
        let set_counts = FaceTables::counts(gets, peers.rows);
        let (set_rows, set_bytes) = laid_as_described(
            (&held.registry.sets[0] as *const FaceTables).cast::<u8>(),
            core::mem::size_of::<FaceTables>(),
            FaceTables::LINES.seq_lines(),
            &set_counts,
        );
        // A build whose sets keep no row of their own (no query asked or answered, no staging of
        // the answers to a peer's interests) describes no line of a set.
        if let Some(set_rows) = set_rows {
            assert_eq!(
                set_rows,
                registry_rows + registry_bytes,
                "the dial face's set follows the registry's rows"
            );
        }
        assert_eq!(
            FaceTables::arena_bytes(gets, peers.rows),
            SubscriberPeer::<RowPolicy>::compose_bytes().map(|compose| set_bytes + compose),
            "a set takes its lines and the row its peer's side composes keys in"
        );
        holds_one_final(face(&mut held.registry, DIAL_FACE));
        held.registry
            .add_face(5)
            .expect("the open reserved a place for the face");
        let (built_rows, built_bytes) = laid_as_described(
            (&held.registry.sets[1] as *const FaceTables).cast::<u8>(),
            core::mem::size_of::<FaceTables>(),
            FaceTables::LINES.seq_lines(),
            &set_counts,
        );
        assert_eq!(
            built_bytes, set_bytes,
            "every set is lent by one description"
        );
        if let Some(built_rows) = built_rows {
            assert_eq!(
                built_rows + held.registry.spares.arena.bytes(),
                registry_rows,
                "the reserve lies right before the registry's rows"
            );
        }
        holds_one_final(face(&mut held.registry, 5));
    }

    /// What the arena's plan reports of the build's registry is the registry's description read by
    /// part: each part the lines of the counts it names, every other line lent none under them,
    /// each what its table's own description counts, and together what the open's walk lends; a
    /// set's gets and its peer's tables the set's lines of their counts, together the set. Turned
    /// red by a part read off other lines than the ones the open walks, by the index's line lent by
    /// the sets' count (the held faces' row then found nowhere, the parts short of the walk), or by
    /// a peer's part without the row its side composes keys in.
    #[test]
    fn the_plans_parts_of_the_registry_are_the_lines_of_their_counts() {
        // The build's own registry: of one face where the build takes none beside its dial role's.
        let takes_faces = cfg!(any(feature = "listen", feature = "group"));
        let faces = if takes_faces { 3 } else { 1 };
        let pools = PeerPoolRows {
            aliases: 16,
            remote_decls: 16,
            interests: 16,
            shared: faces > 1,
        };
        let held = held_as(faces, pools, true);
        let counts = registry_counts(faces, pools);
        let (_, walked) = laid_as_described(
            (&held.registry as *const Registry).cast::<u8>(),
            core::mem::size_of::<Registry>(),
            Registry::LINES.seq_lines(),
            &counts,
        );

        let watchers =
            App::decl_watcher_rows(&SessionLimits::defaults()).expect("the build's watchers");
        let lists = registry_bytes(&RowCounts::NONE.with(RowCount::DeclWatchers, watchers));
        assert_eq!(
            lists,
            App::arena_bytes(watchers),
            "the lists are the engine's own observer's"
        );
        let tables_rows = observer_rows();
        let tables = registry_bytes(&tables_rows.counts());
        assert_eq!(
            tables,
            CoopTables::arena_bytes(&tables_rows),
            "the tables are the session's one table set"
        );
        assert_eq!(
            registry_row_bytes(RowCount::FaceSets),
            Some(core::mem::size_of::<FaceTables>()),
            "a row of the sets' table is a set"
        );
        #[cfg(any(feature = "listen", feature = "group"))]
        assert_eq!(
            registry_row_bytes(RowCount::HeldSets),
            Some(core::mem::size_of::<FaceId>()),
            "a row of the table of marks names a face"
        );
        // A build of the dial role's face alone keeps no mark past it, so no line of them.
        #[cfg(not(any(feature = "listen", feature = "group")))]
        assert_eq!(registry_row_bytes(RowCount::HeldSets), None);
        #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
        assert_eq!(
            registry_row_bytes(RowCount::OwedTokens),
            Some(core::mem::size_of::<
                wz_session_core::declare::liveliness_subscriber::PeerTokens<RowPolicy>,
            >())
        );
        #[cfg(not(all(feature = "liveliness", any(feature = "listen", feature = "group"))))]
        assert_eq!(registry_row_bytes(RowCount::OwedTokens), None);
        let gets = test_gets(faces).rows;
        let own = registry_bytes(&gets.counts()).expect("small");
        #[cfg(feature = "local-queryable")]
        assert_eq!(
            Some(own),
            set_get_bytes(gets),
            "the session's own gets are described as a set's"
        );
        #[cfg(not(feature = "local-queryable"))]
        assert_eq!(
            own, 0,
            "no gets beside the sets' where the session answers none"
        );

        let peers = test_peers(faces, pools, true);
        let table = |count, rows| {
            registry_row_bytes(count).map_or(0, |stride| {
                Arena::stride_bytes(rows, stride).expect("small")
            })
        };
        let parts = [
            lists.expect("small"),
            tables.expect("small"),
            table(RowCount::FaceSets, peers.sets()),
            table(RowCount::HeldSets, HeldPlaces::rows_of(peers.sets())),
            table(RowCount::OwedTokens, peers.owed_tokens()),
            own,
        ];
        assert_eq!(
            parts.iter().sum::<usize>(),
            walked,
            "the parts add up to what the open's walk lent"
        );

        assert_eq!(
            set_peer_bytes(peers.rows),
            Peer::arena_bytes(PeerRows {
                finals: if cfg!(feature = "queryable") {
                    peers.rows.finals
                } else {
                    0
                },
                ..peers.rows
            }),
            "a face's peer tables are the set's lines of the peer's counts and its compose row"
        );
        #[cfg(feature = "query")]
        let set_gets = {
            let legs = GetLegs::<PendingGetHandle, RowPolicy>::arena_bytes(gets.queries);
            #[cfg(feature = "liveliness-get")]
            let legs = legs
                .zip(
                    GetLegs::<PendingGetHandle, RowPolicy, SNAPSHOT_LEGS>::arena_bytes(
                        gets.liveliness_gets,
                    ),
                )
                .and_then(|(queries, snapshots)| queries.checked_add(snapshots));
            assert_eq!(
                set_get_bytes(gets),
                legs,
                "a face's gets are the set's lines of its legs' counts"
            );
            set_get_bytes(gets).expect("small")
        };
        #[cfg(not(feature = "query"))]
        let set_gets = 0;
        assert_eq!(
            set_peer_bytes(peers.rows).map(|peer| peer + set_gets),
            FaceTables::arena_bytes(gets, peers.rows),
            "a set's two parts are the set"
        );
    }

    /// A session of its dial role's face alone is lent no mark: the dial role's mark is no row, so
    /// the registry's line of the marks is lent none, and its tables and its one set lie as its
    /// description counts them. Turned red by a mark lent for the dial role's place
    /// (`HeldPlaces::rows_of` counting it), which would lend a row nothing reads, or by a set lent
    /// apart from the registry.
    #[test]
    fn a_registry_of_one_face_lies_where_its_description_counts_it() {
        let pools = PeerPoolRows {
            aliases: 1,
            remote_decls: 2,
            interests: 1,
            shared: false,
        };
        let held = held_as(1, pools, true);
        assert_eq!(HeldPlaces::rows_of(1), 0, "the dial role's mark is no row");
        let (registry_rows, registry_bytes) = laid_as_described(
            (&held.registry as *const Registry).cast::<u8>(),
            core::mem::size_of::<Registry>(),
            Registry::LINES.seq_lines(),
            &registry_counts(1, pools),
        );
        let registry_rows = registry_rows.expect("the registry describes its table of sets");
        let peers = test_peers(1, pools, true);
        let (set_rows, _) = laid_as_described(
            (&held.registry.sets[0] as *const FaceTables).cast::<u8>(),
            core::mem::size_of::<FaceTables>(),
            FaceTables::LINES.seq_lines(),
            &FaceTables::counts(test_gets(1).rows, peers.rows),
        );
        if let Some(set_rows) = set_rows {
            assert_eq!(set_rows, registry_rows + registry_bytes);
        }
        assert!(held.registry.holders.marks().eq([DIAL_FACE]));
    }

    /// The walk refuses a count past a line's room as a table past its bound: an open that counts
    /// one subscription past the build's bound of the application's subscriptions table is refused
    /// before any face is lent. The CONTROL is the same open counting the table's own rows. Turned
    /// red by a subscriptions' line of another room, or by a walk that lends a line past its room.
    #[test]
    fn a_count_past_a_lines_room_refuses_the_open() {
        let pools = PeerPoolRows {
            aliases: 16,
            remote_decls: 16,
            interests: 16,
            shared: false,
        };
        let past = wz_session_core::caps::MAX_SUBSCRIPTIONS + 1;
        let rows = wz_session_core::session_tables::TableRows {
            subscribers: past,
            ..observer_rows()
        };
        assert!(matches!(
            try_held_as(1, pools, true, rows),
            Err(LendRefused::OverCeiling { rows, ceiling })
                if rows == past && ceiling == wz_session_core::caps::MAX_SUBSCRIPTIONS
        ));
        assert!(
            try_held_as(1, pools, true, observer_rows()).is_ok(),
            "CONTROL: an open that counts none"
        );
    }

    /// A face past the sets the open lent is refused and nothing is lent or held for it: the
    /// session refuses it as one past `max_faces`. The CONTROL is the same face once a set is
    /// free again, which takes it.
    #[cfg(any(feature = "listen", feature = "group"))]
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
        assert_eq!(
            held.registry.sets.len(),
            2,
            "no set is built for the face refused"
        );
        remove(&mut held.registry, 5);
        assert_eq!(
            held.registry.add_face(6).map(|face| face.at()),
            Ok(1),
            "CONTROL: a set is free again, at the place the face left"
        );
        assert!(in_a_lent_set(&held, 6));
    }

    /// The open builds the dial role's set alone and reserves the rows of the other places unlent:
    /// a face that comes builds the set of its place from that reserve, a face after it that takes
    /// the same place builds nothing, and nothing more is lent from the session's arena. Turned red
    /// by an open that builds every set (`built` in `Registry::new`), by a reserve that is not the
    /// sets' rows, or by a face that builds a set where one lies.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[test]
    fn a_set_is_built_when_a_face_first_takes_its_place() {
        let mut held = held(3);
        let lent = held.arena.arena_mut().high_water();
        assert_eq!(
            (held.registry.sets.len(), held.registry.face_places()),
            (1, 3),
            "the dial role's set alone is built at the open"
        );
        let reserved = held.registry.spares.arena.bytes();
        assert_eq!(
            held.registry.spares.arena.high_water(),
            0,
            "no spare is lent"
        );
        held.registry
            .add_face(5)
            .expect("the open reserved a place for the face");
        assert_eq!(held.registry.sets.len(), 2);
        let one = held.registry.spares.arena.high_water();
        assert!(one > 0, "the set's rows come from the reserve");
        assert_eq!(2 * one, reserved, "the reserve is two sets' rows");
        holds_one_final(face(&mut held.registry, 5));
        remove(&mut held.registry, 5);
        held.registry
            .add_face(6)
            .expect("the set the face left is free");
        assert_eq!(held.registry.sets.len(), 2, "the set built is taken again");
        assert_eq!(
            held.registry.spares.arena.high_water(),
            one,
            "and nothing more is lent from the reserve"
        );
        assert_eq!(
            held.arena.arena_mut().high_water(),
            lent,
            "nor from the session's arena"
        );
    }

    /// A tomb keeps the first free place whether or not a set lies there: kept where none was
    /// built, it is freed with the accepted faces; a face that comes past it builds the set of the
    /// kept place on the way to its own, and once the tomb is freed the next face takes that set,
    /// rows and all. Turned red by a removal of the accepted faces that leaves a kept place past
    /// the sets built, or by a face that takes a place past the sets built without building them.
    #[cfg(all(feature = "connectivity", any(feature = "listen", feature = "group")))]
    #[test]
    fn a_place_kept_where_no_set_lies_is_freed_and_passed() {
        let mut held = held(3);
        assert_eq!(held.registry.keep_place(), Some(1), "the first free place");
        assert_eq!(held.registry.sets.len(), 1, "a kept place builds no set");
        held.registry.remove_accepted_faces();
        assert_eq!(
            marks(&held.registry),
            &[DIAL_FACE, NO_FACE, NO_FACE],
            "the kept place is free again"
        );
        assert_eq!(held.registry.keep_place(), Some(1));
        let taken = held
            .registry
            .add_face(5)
            .expect("a place is free past the kept one");
        assert_eq!(taken.at(), 2);
        assert_eq!(
            held.registry.sets.len(),
            3,
            "the kept place's set is built on the way"
        );
        held.registry.free_kept(1);
        held.registry
            .add_face(6)
            .expect("the kept place is free again");
        assert_eq!(held.registry.held_at(6), Some(1));
        holds_one_final(face(&mut held.registry, 6));
    }

    /// A free place's mark names no face: a lookup of the id it reads
    /// finds no set while sets are free, and one removed by it removes none. Turned red by a
    /// lookup that matches a free set's row.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[test]
    fn a_free_sets_row_names_no_face() {
        let mut held = held(3);
        held.registry
            .add_face(5)
            .expect("the open lent a set for the face");
        assert_eq!(marks(&held.registry), &[DIAL_FACE, 5, NO_FACE]);
        assert_eq!(held.registry.held_at(NO_FACE), None);
        assert_eq!(
            held.registry.place(held.registry.held(NO_FACE)),
            None,
            "no key of it finds a set"
        );
        remove(&mut held.registry, NO_FACE);
        assert_eq!(
            marks(&held.registry),
            &[DIAL_FACE, 5, NO_FACE],
            "nothing was removed"
        );
        assert_eq!(
            held.registry.held_at(5),
            Some(1),
            "CONTROL: a face is found"
        );
    }

    /// A place a tomb keeps is taken by no face that comes and named by no walk until it is freed,
    /// and a face that departs keeps its place the same way. Turned red by a kept row read as
    /// free (the face that comes takes the kept place) or as a face's (the walk names it).
    #[cfg(all(feature = "connectivity", feature = "listen"))]
    #[test]
    fn a_kept_place_is_taken_by_no_face_until_it_is_freed() {
        let mut held = held(4);
        let five = held
            .registry
            .add_face(5)
            .expect("the open lent a set for the face");
        assert_eq!(five.at(), 1);
        held.registry.depart(five);
        assert_eq!(marks(&held.registry), &[DIAL_FACE, KEPT, NO_FACE, NO_FACE]);
        assert_eq!(
            held.registry.keep_place(),
            Some(2),
            "a tomb apart takes the first free place"
        );
        assert_eq!(
            face_ids(&held.registry),
            vec![DIAL_FACE],
            "no walk names a kept place"
        );
        assert_eq!(held.registry.held_at(KEPT), None);
        let six = held.registry.add_face(6).expect("one place is free");
        assert_eq!(six.at(), 3, "the kept places are passed over");
        assert_eq!(held.registry.add_face(7), Err(FacesFull));
        held.registry.free_kept(1);
        held.registry.free_kept(3);
        assert_eq!(
            marks(&held.registry)[3],
            6,
            "a face's place is not freed as a kept one"
        );
        assert_eq!(
            held.registry.add_face(7).map(|face| face.at()),
            Ok(1),
            "CONTROL: the freed place"
        );
        held.registry.remove_accepted_faces();
        assert_eq!(
            marks(&held.registry),
            &[DIAL_FACE, NO_FACE, NO_FACE, NO_FACE],
            "a tomb's place goes with the faces'"
        );
    }

    /// A face's key finds its set by its place while the face holds it, and nothing once the face
    /// went, though another face took the set since; the key of a face the session does not hold
    /// finds nothing. Turned red by a key read off the place alone, without the id.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[test]
    fn a_faces_key_finds_its_set_until_the_face_goes() {
        let mut held = held(3);
        held.registry
            .add_face(5)
            .expect("the open lent a set for the face");
        let key = held.registry.held(5);
        assert_eq!(held.registry.place(key), Some(1));
        assert_eq!(
            held.registry.place(held.registry.held(DIAL_FACE)),
            Some(0),
            "CONTROL: the dial role's face"
        );
        remove(&mut held.registry, 5);
        held.registry
            .add_face(6)
            .expect("the set the face left is free");
        assert_eq!(
            held.registry.held_at(6),
            Some(1),
            "CONTROL: the next face took the set"
        );
        assert_eq!(held.registry.place(key), None, "the face that went");
        assert_eq!(held.registry.place(held.registry.held(9)), None);
    }

    /// The walk over the faces takes exactly the sets faces hold, in set order, as faces come, go
    /// and take a set another left: the next face takes the first free set, in its place among
    /// the others, and a lookup by face finds the set the walk takes for it.
    #[cfg(any(feature = "listen", feature = "group"))]
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
        remove(&mut held.registry, 6);
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
        remove(&mut held.registry, DIAL_FACE);
        held.registry.remove_accepted_faces();
        assert_eq!(face_ids(&held.registry), vec![DIAL_FACE]);
        assert_eq!(walked(&held.registry), lying_at(&held.registry, &[0]));
        held.registry
            .add_face(9)
            .expect("the open lent a set for the face");
        assert_eq!(face_ids(&held.registry), vec![DIAL_FACE, 9]);
        assert_eq!(walked(&held.registry), lying_at(&held.registry, &[0, 1]));
        assert_eq!(
            (held.registry.sets.len(), held.registry.face_places()),
            (4, 5),
            "a set for each place a face took, none made or dropped as faces went"
        );
    }

    /// The faces other than the one a call acts on are the table's rows but the caller's that a
    /// face holds, in place order: the dial role's among them where the caller is another face,
    /// and each face past it where the caller is the dial role's; none that no face holds. Turned
    /// red by others that leave out the dial role's set (`HeldPlaces::split`), or that count the
    /// caller's set or a free one.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[test]
    fn the_other_faces_are_the_other_held_sets() {
        let mut held = held(6);
        for id in [5, 6, 7, 8] {
            held.registry
                .add_face(id)
                .expect("the open lent a set for the face");
        }
        remove(&mut held.registry, 5);
        remove(&mut held.registry, 8);
        let own = lying_at(&held.registry, &[3])[0];
        let others = lying_at(&held.registry, &[0, 2]);
        let Split {
            face, others: seen, ..
        } = held
            .registry
            .split(held.registry.held_at(7))
            .expect("the registry holds the face");
        assert!(ptr::eq(&*face, own));
        let seen: Vec<*const FaceTables> =
            seen.faces().map(|face| face as *const FaceTables).collect();
        assert_eq!(seen, others);
        let of_dial: Vec<*const FaceTables> = held
            .registry
            .split(Some(0))
            .expect("the dial role's face holds the first place")
            .others
            .faces()
            .map(|face| face as *const FaceTables)
            .collect();
        assert_eq!(
            of_dial,
            lying_at(&held.registry, &[2, 3]),
            "the dial role's call counts each face past it"
        );
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
    #[cfg(any(feature = "listen", feature = "group"))]
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
        let pools = held.registry.spares.pools.counts().expect("shared pools");
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
                .spares
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
        assert!(held.registry.peers_declare(Plane::Subscribers, "demo/5/1"));
        assert!(!held.registry.peers_declare(Plane::Subscribers, "demo/past"));
    }

    /// A face that goes gives back to the session's pools exactly the rows its peer held, and the
    /// faces that stay keep theirs; the rows it gave back take the next face's declarations, and
    /// the faces past the dial role's all going leaves the dial's alone in the pools.
    #[cfg(any(feature = "listen", feature = "group"))]
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
                .spares
                .pools
                .counts()
                .expect("shared pools")
                .subscribers
                .used,
            6,
            "CONTROL: the pool is full"
        );
        remove(&mut held.registry, 5);
        assert_eq!(
            held.registry
                .spares
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
                .spares
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
                .spares
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
    #[cfg(any(feature = "listen", feature = "group"))]
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
        assert!(!held.registry.spares.pools.is_shared());
        assert_eq!(
            held.registry.spares.pools.counts(),
            None,
            "no pool to count"
        );
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
            .peers_declare(Plane::Subscribers, "demo/dial/2"));
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
            ("gets", size_of_val(&set.gets)),
        ];
        std::println!("face set: {} B", size_of_val(&*set));
        for (table, bytes) in tables {
            std::println!("  {table}: {bytes} B");
        }
        std::println!(
            "  a lent table's header: {} B; a key arena's handle: {} B",
            size_of::<BoundedVec<u8, 1, RowPolicy>>(),
            size_of::<LentKeys>()
        );
        let printed: usize = tables.iter().map(|(_, bytes)| bytes).sum();
        assert!(printed <= size_of_val(&*set));
    }

    /// A walk over the faces reads the sets the faces hold and no other: of the sixteen sets the
    /// open lent, a walk over three faces reads three.
    #[cfg(any(feature = "listen", feature = "group"))]
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
            (held.registry.face_places(), held.registry.sets.len()),
            (16, 3),
            "CONTROL: sixteen places were reserved, a set built at each a face took"
        );
        let before = held.registry.set_reads.get();
        assert_eq!(held.registry.faces().count(), 3);
        assert_eq!(
            held.registry.set_reads.get() - before,
            3,
            "one set read for each face"
        );
        #[cfg(feature = "query")]
        {
            let walked = 3 + usize::from(cfg!(feature = "local-queryable"));
            assert_eq!(held.registry.all_gets().count(), walked);
            assert_eq!(held.registry.all_gets_mut().count(), walked);
        }
    }
    /// A session of its dial role's face alone holds that face in the first set and no other, its
    /// table of places one row: a face that is not the dial role's finds no set, no call counts
    /// another face, and neither removing the dial role's face nor every accepted face empties its
    /// set. Turned red by a table of one row that names a second face, counts the caller among the
    /// others, or lets the dial role's set go.
    #[test]
    fn a_session_of_one_face_holds_its_dial_role_s_face_alone() {
        let pools = PeerPoolRows {
            aliases: 16,
            remote_decls: 16,
            interests: 16,
            shared: false,
        };
        let mut held = held_as(1, pools, true);
        let registry = &mut held.registry;
        assert_eq!(marks(registry), [DIAL_FACE], "the table of one row");
        assert_eq!(registry.held_ids().collect::<Vec<_>>(), [DIAL_FACE]);
        assert_eq!(registry.held_at(DIAL_FACE), Some(0));
        assert_eq!(
            registry.held_at(5),
            None,
            "no face but the dial role's is held"
        );
        assert_eq!(registry.held_at(NO_FACE), None);
        assert_eq!(registry.place(registry.held(5)), None);
        assert_eq!(registry.place(HeldFace::new(1, DIAL_FACE)), None);
        assert_eq!(registry.faces().count(), 1);
        #[cfg(any(feature = "listen", feature = "group"))]
        assert_eq!(
            registry
                .split(Some(0))
                .map(|split| split.others.faces().count()),
            Some(0),
            "the call of the one face counts no other"
        );
        // A build of the dial role's face alone counts no other face by its type (`NoOtherPeers`).
        #[cfg(not(any(feature = "listen", feature = "group")))]
        assert!(registry.split(Some(0)).is_some());
        assert!(
            registry.split(Some(1)).is_none(),
            "one set lies at the first place"
        );
        #[cfg(feature = "connectivity")]
        assert_eq!(registry.keep_place(), None, "no place is free to keep");
        declare_on(registry, DIAL_FACE, 1, "demo/dial/one");
        let dial = registry.held(DIAL_FACE);
        registry.remove_face(dial);
        registry.remove_accepted_faces();
        assert_eq!(
            registry.held_at(DIAL_FACE),
            Some(0),
            "the dial role's face stays"
        );
        assert_eq!(
            subscribers_of(registry, DIAL_FACE).0,
            1,
            "and its set was not given back"
        );
    }

    /// The dial role's face holds the first place for the table's life, its mark no row of the
    /// arena: a session that adds faces is lent a mark for each place past it, every one free, and
    /// a session of one face is lent none, its table of one row. Turned red by a table that lends a
    /// row for the dial role's place too (`HeldPlaces::rows_of`), or that names a face at a place no
    /// face took.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[test]
    fn the_dial_roles_place_is_marked_for_the_tables_life_and_lent_no_row() {
        let many = held(3);
        assert_eq!(marks(&many.registry), [DIAL_FACE, NO_FACE, NO_FACE]);
        assert_eq!(many.registry.face_places(), 3);
        let one = held_as(
            1,
            PeerPoolRows {
                aliases: 16,
                remote_decls: 16,
                interests: 16,
                shared: false,
            },
            true,
        );
        assert_eq!(marks(&one.registry), [DIAL_FACE]);
        assert_eq!(one.registry.face_places(), 1);
        assert_eq!(one.registry.sets.len(), 1);
    }

    /// A registry dropped gives back the key of every row its faces' peers wrote, while the arena
    /// it was lent from is still the session's: the faces' sets are dropped by the registry's own
    /// drop (`let_go`), and not by their fields' glue. The CONTROL is the key the face's
    /// subscriber holds before the drop. Turned red by a drop that leaves the sets.
    #[test]
    fn a_dropped_registry_gives_back_the_keys_of_its_faces() {
        let mut held = held(1);
        declare_on(&mut held.registry, DIAL_FACE, 1, "demo/dropped/face");
        assert!(
            held.keys.counts().used > 0,
            "CONTROL: the face's subscriber keeps its key in the session's key arena"
        );
        let Held {
            registry,
            arena,
            keys,
            ..
        } = held;
        drop(registry);
        assert_eq!(
            keys.counts().used,
            0,
            "the face's key went with the registry"
        );
        drop(arena);
    }

    /// As `a_dropped_registry_gives_back_the_keys_of_its_faces`, for the application's tables:
    /// the key of the session's own liveliness subscriber goes with the registry. Turned red by a
    /// drop that leaves the application's tables.
    #[cfg(all(feature = "std", feature = "liveliness"))]
    #[test]
    fn a_dropped_registry_gives_back_the_keys_of_its_application() {
        use wz_capi_port::{LivelinessSink, WireKey};
        use wz_session_core::declare::liveliness_sample::LivelinessSample;
        use wz_session_core::session_tables::KeyForm;

        let mut held = held(1);
        held.registry
            .app
            .tables
            .declare_liveliness_subscriber(
                "demo/dropped/**",
                false,
                KeyForm::default(),
                super::super::LivelinessRow::new(
                    WireKey::literal().into_anchor(),
                    LivelinessSink::shared(|_: LivelinessSample<'_>| {}),
                ),
            )
            .map_err(|refused| refused.why)
            .expect("the subscriber is declared");
        assert!(
            held.keys.counts().used > 0,
            "CONTROL: the subscriber keeps its key in the session's key arena"
        );
        let Held {
            registry,
            arena,
            keys,
            ..
        } = held;
        drop(registry);
        assert_eq!(
            keys.counts().used,
            0,
            "the subscriber's key went with the registry"
        );
        drop(arena);
    }
}
