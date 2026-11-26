// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the session's application layer holds, in the two parts a session that listens needs
//! apart (`docs/capi-pico-on-coop-engine.md`, section 7).
//!
//! - [`RegistryOf::app`], what the application registered (its subscribers, queryables, local
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
//! its own ([`Others`], `slot_observer::OtherPeers`).

#[cfg(any(
    feature = "remote-declaration-watch",
    feature = "declarations-synced-event"
))]
use super::decl_watch::WatchObserver;
use wz_session_core::bounded::BoundedVec;
#[cfg(feature = "queryable")]
use wz_session_core::bounded::Static;
#[cfg(feature = "runtime-plan")]
use wz_session_core::bounded::{Arena, LendRefused};
#[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
use wz_session_core::driver_loop::InPlaceRecord;

use crate::RowPolicy;
use wz_session_core::driver_loop::IterationEvent;
#[cfg(feature = "runtime-plan")]
use wz_session_core::key_arena::{KeySpace, LentKeys};
#[cfg(feature = "multicast-declarations")]
use wz_session_core::limit_binding::Quota;
#[cfg(feature = "multicast-declarations")]
use wz_session_core::limits::MaxPeerKeyexprAliasesHeld;
use wz_session_core::limits::SessionLimits;
#[cfg(feature = "runtime-plan")]
use wz_session_core::peer_tables::PeerPools;
use wz_session_core::peer_tables::PeerTables;
#[cfg(feature = "runtime-plan")]
use wz_session_core::peer_tables::{PeerRows, SHARES_ROWS};
#[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
use wz_session_core::pubsub::LentPush;
#[cfg(feature = "query")]
use wz_session_core::reply_sink::ConsolidatingSink;
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
#[cfg(feature = "runtime-plan")]
use wz_session_core::slot_observer::ObserverRows;
#[cfg(any(
    feature = "listen",
    feature = "group",
    all(test, feature = "runtime-plan")
))]
use wz_session_core::slot_observer::OtherPeers;
#[cfg(feature = "query")]
use wz_session_core::slot_observer::Requesters;
use wz_session_core::slot_observer::{ObserverSinks, SlotObserverOf, TakenAhead};

#[cfg(feature = "query")]
use super::{LegHold, LegSink};
use super::{RoundDelivery, SubscriberRow};
use crate::arena::MAX_FACE_SETS;
#[cfg(feature = "runtime-plan")]
use crate::arena::{FacePeers, GetTables};
#[cfg(feature = "runtime-plan")]
use wz_session_core::slot_observer::RequesterRows;

use wz_session_core::declare::matching::MatchingSink;
#[cfg(feature = "query")]
use wz_session_core::pending_get::{DueIndex, DueRow, LegTables};
use wz_session_core::pending_get::{GetKind, SessionFaces};
use wz_session_core::session_tables::{PeerDeclarations, Plane};

#[allow(unused_imports)]
use crate::prelude::*;
use core::mem::{ManuallyDrop, MaybeUninit};
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
type OwedTokens = wz_session_core::declare::liveliness_subscriber::PeerTokens<RowPolicy>;

/// The session's own pending gets on one face: a query's sink consolidates what its leg is
/// handed. The rows are lent from the session's arena at its open, one table for each face the
/// session may hold at once (`crate::arena::GetTables`).
#[cfg(feature = "query")]
pub(super) type Gets = Requesters<ConsolidatingSink<LegSink, LegHold>, LegSink, RowPolicy>;
/// A session that asks no query has no pending get on any face: its requester side is none, and
/// the observer's fan and drains keep no path for gets.
#[cfg(not(feature = "query"))]
pub(super) type Gets = NoRequesters;

/// What a face's peer writes and is owed. The rows are lent from the session's arena at its open,
/// one set for each face the session may hold at once (`crate::arena::FacePeers`).
pub(super) type Peer = PeerTables<RowPolicy>;

/// What a lent Push's sample borrows beside the frame and the face's peer, held by the walk that
/// hands it out (`pinned`).
#[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
pub(super) type PeerRoom = wz_session_core::pubsub::LentRoom<RowPolicy>;

/// What the session holds for one face: what its peer wrote and what the session asked of it.
///
/// A set is built where the registry keeps it ([`Self::rowless_in`], then `Self::lend`) and is
/// never moved from there: a face that comes takes a set where it lies and one that goes empties it
/// there, its rows of the session's pools going back to them. A set holds a few words for each of
/// its tables, and the session's tables are placed once and not moved.
/// Which face holds a set is the registry's index of held sets, not the set's: a walk over the
/// faces reads no set to learn whether a face holds it.
pub(super) struct FaceTables {
    pub(super) peer: Peer,
    pub(super) gets: Gets,
    /// The set's row of the index of the earliest deadline of the session's gets
    /// (`RegistryOf::dues`): the index keeps a leaf for each set, free or held, so its rows are
    /// lent with the sets and none is added or removed as faces come and go.
    #[cfg(feature = "query")]
    due: DueRow,
    /// The face's link was lost and the tokens its peer declared are still to be retracted to the
    /// liveliness subscribers: they stay in `peer` until each `Delete` is taken, by the round of
    /// deliveries (`Registry::retract_owed`) or by a read that hands each itself
    /// (`Registry::take_lost_token`), or until the face goes, when they are kept apart
    /// from the set and the set is given back (`Registry::owe_tokens_of`).
    #[cfg(feature = "liveliness")]
    retracting: bool,
}

impl FaceTables {
    /// A set for no face yet, written field by field into `place`, which is overwritten without
    /// dropping what it held: tables of no rows, each refusing what is asked of it until
    /// `Self::lend` lends it rows, the peer's held to `limits`. Not inlined: the peer's tables,
    /// nearly all of the set, are written where they lie by `init_in`, and of the set only its
    /// gets are a value in this frame.
    #[inline(never)]
    fn rowless_in<'p>(place: &'p mut MaybeUninit<Self>, limits: &SessionLimits) -> &'p mut Self {
        let at = place.as_mut_ptr();
        // A field added to the set and not written below would be read uninitialised. This names
        // every field with no `..`, so adding one without naming it here (and so without writing
        // it below) does not compile.
        let _every_field_is_written = |set: &Self| {
            let Self {
                peer: _,
                gets: _,
                #[cfg(feature = "query")]
                    due: _,
                #[cfg(feature = "liveliness")]
                    retracting: _,
            } = set;
        };
        // SAFETY: `at` is valid for writes of a `Self`, and each field is written once through a
        // pointer to it, the peer's tables by `init_in`, which writes them whole (a
        // `MaybeUninit<T>` has the layout of `T`). The list above names every field, so the set is
        // whole when it is lent.
        let set = unsafe {
            ptr::write(addr_of_mut!((*at).gets), Gets::default());
            #[cfg(feature = "query")]
            ptr::write(addr_of_mut!((*at).due), DueRow::NEVER);
            #[cfg(feature = "liveliness")]
            ptr::write(addr_of_mut!((*at).retracting), false);
            Peer::init_in(&mut *addr_of_mut!((*at).peer).cast::<MaybeUninit<Peer>>());
            &mut *at
        };
        set.peer.limit_to(limits);
        set
    }

    /// Lend a set of no rows its rows where it lies: `gets` rows of its gets and `peer` of its
    /// peer's tables, from `arena`, in that order, the peer's keys kept in `keys`, the session's
    /// key arena, held to `limits`. Refused when the arena has not the rows; the set stays whole,
    /// with what was lent before the refusal.
    #[cfg(feature = "runtime-plan")]
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
/// (`crate::arena::ArenaPlan`), where the arena lends them (`runtime-plan`).
#[cfg(feature = "runtime-plan")]
pub(crate) const FACE_SET_BYTES: usize = core::mem::size_of::<FaceTables>();

/// The bytes of one entry of the index of held sets, a row of the arena's table of them: kept by a
/// build that adds faces beside its dial role's alone (`held::ManyHolders`).
#[cfg(any(feature = "listen", feature = "group"))]
pub(crate) const HELD_SET_BYTES: usize = core::mem::size_of::<FaceId>();

/// What the index of held sets reads for a free set: the session numbers its faces up from 1
/// one at a time (`LinkSupervisor::next_face_id`), so no face is known by it.
const NO_FACE: FaceId = FaceId::MAX;

/// What the index of held sets reads for a set whose place a face that went keeps, emptied, while
/// a replaying listener is still owed its departure (`told`): neither a face's nor free.
#[cfg(feature = "connectivity")]
const KEPT: FaceId = FaceId::MAX - 1;

/// A row of the index of held sets at or past this names no face: the free and the kept rows lie
/// at the top of the ids, so whether a row names a face is one comparison.
const NAMES_NO_FACE: FaceId = FaceId::MAX - 1;

/// Whether `holder`, a row of the index of held sets, names the face that holds its set.
fn names_face(holder: FaceId) -> bool {
    holder < NAMES_NO_FACE
}

#[cfg(any(
    feature = "listen",
    feature = "group",
    all(test, feature = "runtime-plan")
))]
mod adding;
mod held;
use held::Holders;
#[cfg(not(feature = "runtime-plan"))]
pub(crate) mod placed;

/// Where the set face `id` holds lies, `holders` naming the face of each set by the set's
/// place: never a free set, whose row names no face.
fn place_of(holders: &[FaceId], id: FaceId) -> Option<usize> {
    holders
        .iter()
        .position(|holder| *holder == id)
        .filter(|_| names_face(id))
}

/// A face as the dispatch of its link or group names it: the place of its set and its id, read
/// once as the dispatch is made ([`RegistryOf::held`]). The set is the face's while its row of the
/// index of held sets names the id, so the key of a face that went finds nothing, whichever face
/// holds the set since.
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
        feature = "interest-answer",
        all(test, feature = "runtime-plan")
    ))]
    pub(super) const fn new(at: usize, id: FaceId) -> Self {
        Self { at, id }
    }

    /// The place of the face's set, which its link and its room keep too.
    #[cfg(any(
        feature = "listen",
        feature = "group",
        all(test, feature = "runtime-plan")
    ))]
    pub(super) const fn at(&self) -> usize {
        self.at
    }

    /// The face's id.
    #[cfg(any(feature = "listen", feature = "group"))]
    pub(super) const fn id(&self) -> FaceId {
        self.id
    }
}

/// Where a liveliness subscriber's history stands ([`RegistryOf::next_history_token`]): the face
/// whose peer's tokens it reads now, by id, and the last token handed from them.
#[cfg(feature = "liveliness")]
#[derive(Clone, Copy, Default)]
pub(super) struct HistoryCursor {
    face: Option<FaceId>,
    after: Option<u64>,
}

/// The faces other than the one a call acts on, which the matching verdicts of that call count:
/// the sets before the call's own and after it, and the rows of the index of held sets that
/// name their faces.
#[cfg(any(
    feature = "listen",
    feature = "group",
    all(test, feature = "runtime-plan")
))]
pub(super) struct Others<'a> {
    before: &'a [FaceTables],
    after: &'a [FaceTables],
    held_before: &'a [FaceId],
    held_after: &'a [FaceId],
}

#[cfg(any(
    feature = "listen",
    feature = "group",
    all(test, feature = "runtime-plan")
))]
impl Others<'_> {
    fn faces(&self) -> impl Iterator<Item = &FaceTables> {
        let before = self.before.iter().zip(self.held_before);
        let after = self.after.iter().zip(self.held_after);
        before
            .chain(after)
            .filter(|(_, holder)| names_face(**holder))
            .map(|(set, _)| set)
    }
}

#[cfg(any(
    feature = "listen",
    feature = "group",
    all(test, feature = "runtime-plan")
))]
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
/// declarations, each search of them counted for the tests ([`RegistryOf::peers_declare`]).
impl<H: Holders> PeerDeclarations for RegistryOf<H> {
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

/// The index of held sets the build keeps: a build that adds faces beside its dial role's
/// (`listen`, `group`) lends one from its arena, and one of that face alone knows it.
#[cfg(any(feature = "listen", feature = "group"))]
type BuildHolders = held::ManyHolders;
/// See the form of a build that adds faces.
#[cfg(not(any(feature = "listen", feature = "group")))]
type BuildHolders = held::OneHolder;

/// The application layer of one session, as the build holds its faces.
pub(super) type Registry = RegistryOf<BuildHolders>;

/// What the read takes of a face's records itself, ahead of the face's dispatch, in a build whose
/// read steps its one link itself: every query of the link, handed to the queryables (`queries`)
/// with queryables, and every peer token, handed to the liveliness subscribers (`tokens`) with
/// liveliness. A build without leaves them to their planes, which hand them through the round.
const READ_TAKES: TakenAhead = TakenAhead {
    queries: cfg!(all(
        feature = "queryable",
        not(any(
            feature = "threads",
            feature = "listen",
            feature = "group"
        ))
    )),
    tokens: cfg!(all(
        feature = "liveliness",
        not(any(
            feature = "threads",
            feature = "listen",
            feature = "group"
        ))
    )),
    declares: false,
};

/// What the read takes of a copied frame's records itself, ahead of the frame's other planes
/// (`Planes::BesideSubscribers`): what it takes of a lent record, and, with the declaration
/// watches, every Declare, dispatched one message at a time (`RegistryOf::dispatch_declare_message`)
/// so the watches' room is handed out before the next message fills it.
#[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
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
    /// (`RegistryOf::take_subscriber_record`, `RegistryOf::take_reply`).
    #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
    BesideSubscribers,
}

/// The application layer of one session, its faces held as `H` holds them. See the module
/// documentation.
pub(super) struct RegistryOf<H: Holders> {
    /// Dropped by the registry's own drop (`let_go`), as `sets` is.
    pub(super) app: ManuallyDrop<App>,
    /// Where a sample the application's subscribers match goes: the session's round of
    /// deliveries, handed to each dispatch of the application's tables.
    delivery: RoundDelivery,
    /// The session's pools of what its peers write by their own choice, which every face's tables
    /// keep their rows in from the open on: what a test reads the pools' counts by.
    #[cfg(all(test, feature = "runtime-plan"))]
    pools: PeerPools,
    /// Every set of face tables, each where it was built and never moved from, in a table the arena
    /// lent at the open with a row for each face the config admits: the dial role's face's first
    /// and always held by it, then the faces to come. A face past them is refused
    /// (`FacesFull`), so the session's memory is the arena alone. A set no face holds is kept,
    /// emptied, for the next face.
    sets: ManuallyDrop<BoundedVec<FaceTables, MAX_FACE_SETS, RowPolicy>>,
    /// The face that holds each set, by the set's place among `sets`, [`NO_FACE`] for a set no
    /// face holds, and `KEPT` for one a departed face's tomb keeps: the dial role's face holds
    /// the first. The place is the face's in every table of the session (its link's, its room's).
    /// Every walk over the faces and every lookup of one reads this and the held sets alone; the
    /// open lends a set for each face the config admits, most of them free at any time.
    holders: H,
    /// The tokens of faces that went before each was retracted, in the order the faces went: each
    /// the token table the face's set held, its rows still in the session's pool, the set given
    /// back as the face went. Lent at the open, a row for each row of the session's token pool,
    /// as a table owed holds one of them at least (`FacePeers::owed_tokens`); none for a session
    /// of one face, whose one face never goes. A session of no face besides the dial role's (a
    /// build without `listen` and `group`) removes none, and keeps no table of them.
    #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
    owed: BoundedVec<OwedTokens, { wz_session_core::caps::SESSION_MAX_REMOTE_DECLS }, RowPolicy>,
    /// The aliases one face's peer may hold (`MAX_PEER_KEYEXPR_ALIASES`), which a set a group's face
    /// held, at the group's own quota (`Self::hold_member_aliases`), is held to again when it is
    /// given back for the next face.
    #[cfg(feature = "multicast-declarations")]
    peer_aliases: MaxPeerKeyexprAliasesHeld,
    /// The session's own gets pending on its own queryables ([`LOCAL_FACE`]).
    #[cfg(feature = "local-queryable")]
    pub(super) local: Gets,
    /// The row of the session's own gets in the index of the gets' deadlines, its leaf the one
    /// after the sets' (`Self::dues`).
    #[cfg(feature = "local-queryable")]
    local_due: DueRow,
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

/// The faces as the session's state reaches them (`SessionState`): a
/// leg's entry ended in its face's tables, what a lost face's peer declared let go of, the
/// earliest deadline of the gets pending on them, and the tokens of lost links retracted.
impl<H: Holders> SessionFaces for RegistryOf<H> {
    fn end_leg(&mut self, face: FaceId, kind: GetKind) {
        #[cfg(feature = "query")]
        if let Some(gets) = self.gets_mut(face) {
            gets.end_leg(kind);
        }
        #[cfg(not(feature = "query"))]
        let _ = (face, kind);
    }

    fn lose_face(&mut self, face: FaceId) {
        self.flush_declarations_on_link_loss(face);
        // Its peer's tokens are retracted as the round of deliveries takes each, the rest owed.
        #[cfg(feature = "liveliness")]
        self.lose_tokens(face);
    }

    fn next_get_deadline_ms(&mut self) -> Option<u64> {
        #[cfg(feature = "query")]
        {
            self.dues().earliest()
        }
        #[cfg(not(feature = "query"))]
        {
            None
        }
    }

    #[cfg(all(
        feature = "liveliness",
        any(feature = "threads", feature = "listen", feature = "group")
    ))]
    fn retract_owed(&mut self, room: &mut dyn FnMut() -> bool) -> bool {
        RegistryOf::retract_owed(self, room)
    }
}

/// The index of the earliest deadline of the session's gets over the rows the sets and the
/// session's own gets keep: a leaf for each set, in the order of the sets, then the session's own
/// gets'. Each table keeps its earliest deadline as its entries come and go, so a leaf's table is
/// read with no walk of its entries.
#[cfg(feature = "query")]
struct Dues<'a> {
    sets: &'a mut [FaceTables],
    #[cfg(feature = "local-queryable")]
    local: (&'a mut DueRow, &'a mut Gets),
}

#[cfg(feature = "query")]
impl Dues<'_> {
    /// The gets of leaf `leaf`, to write.
    fn gets_mut(&mut self, leaf: usize) -> Option<&mut Gets> {
        let sets = self.sets.len();
        if leaf < sets {
            return self.sets.get_mut(leaf).map(|set| &mut set.gets);
        }
        #[cfg(feature = "local-queryable")]
        if leaf == sets {
            return Some(&mut *self.local.1);
        }
        None
    }
}

#[cfg(feature = "query")]
impl DueIndex for Dues<'_> {
    fn leaves(&self) -> usize {
        self.sets
            .len()
            .wrapping_add(usize::from(cfg!(feature = "local-queryable")))
    }

    fn row(&self, at: usize) -> Option<&DueRow> {
        let sets = self.sets.len();
        if at < sets {
            return self.sets.get(at).map(|set| &set.due);
        }
        #[cfg(feature = "local-queryable")]
        if at == sets {
            return Some(&*self.local.0);
        }
        None
    }

    fn row_mut(&mut self, at: usize) -> Option<&mut DueRow> {
        let sets = self.sets.len();
        if at < sets {
            return self.sets.get_mut(at).map(|set| &mut set.due);
        }
        #[cfg(feature = "local-queryable")]
        if at == sets {
            return Some(&mut *self.local.0);
        }
        None
    }

    fn due(&self, leaf: usize) -> u64 {
        let sets = self.sets.len();
        let gets = if leaf < sets {
            self.sets.get(leaf).map(|set| &set.gets)
        } else {
            #[cfg(feature = "local-queryable")]
            {
                (leaf == sets).then_some(&*self.local.1)
            }
            #[cfg(not(feature = "local-queryable"))]
            {
                None
            }
        };
        gets.and_then(LegTables::next_deadline_ms)
            .unwrap_or(u64::MAX)
    }
}

/// The application's part, one face's tables and the other faces', apart so each can be used as
/// its call needs. A session of its dial role's face alone counts no other.
struct Split<'a, H: Holders + 'a> {
    app: &'a mut App,
    delivery: &'a mut RoundDelivery,
    face: &'a mut FaceTables,
    others: H::Others<'a>,
}

impl<H: Holders> RegistryOf<H> {
    /// A session that holds nothing and has been told nothing, with its dial face, its tables
    /// held to the session limits its open resolved, the application's lent from `arena`, `rows`
    /// of each, the pools of what the peers write `peers` counts lent from it next, and the tables
    /// of each face `gets` and `peers` count lent from it too: the dial face's (one of no rows for
    /// a session that dials nothing, `FacePeers::dial`), the rest kept for the faces to come, and
    /// the session's own gets where it answers its own. What the peers
    /// declare keeps its keys in `keys`, the session's key arena, as the session's own
    /// declarations do. What the application's subscribers match goes to `delivery`. Refused when
    /// the arena has not the rows, which one reserved by the plan that counts them always has.
    #[cfg(feature = "runtime-plan")]
    pub(super) fn new(
        limits: &SessionLimits,
        arena: &mut Arena,
        keys: KeySpace,
        rows: ObserverRows<wz_session_core::session_tables::TableRows>,
        gets: GetTables,
        peers: FacePeers,
        delivery: RoundDelivery,
    ) -> Result<Self, LendRefused> {
        let app = App::lent(arena, keys, rows, limits)?;
        let mut pools = PeerPools::lent(arena, keys, peers.pools)?;
        #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
        let owed = arena.lend(peers.owed_tokens())?;
        // One face's own spans are handed to that face's tables alone, so a plan that lends them
        // lends one set; a build without pools keeps each set's rows inline.
        debug_assert!(!SHARES_ROWS || pools.is_shared() || peers.tables <= 1);
        // A session that dials nothing lent its dial face no set: that face holds one of no rows,
        // first, and every lent set is for the faces to come. Otherwise the first lent set is the
        // dial face's. Either way every set the plan counts is lent by the one call below, so the
        // open builds and lends a set in one place.
        let mut sets = arena.lend(peers.sets())?;
        let holders = H::lent(arena, peers.sets())?;
        if !peers.dial {
            push_unpeered(&mut sets, keys, limits).ok_or(LendRefused::OverCeiling {
                rows: 1,
                ceiling: 0,
            })?;
        }
        for _ in 0..peers.tables {
            lend_set(
                &mut sets, arena, keys, &mut pools, gets.rows, peers.rows, limits,
            )?;
        }
        // Every span an arena lends starts on one alignment, so lending the session's own gets
        // after the faces' takes the bytes the plan counts for them wherever it lends them.
        #[cfg(feature = "local-queryable")]
        let local = Gets::lent(arena, keys, gets.rows, limits)?;
        // The watches hold what the peers declare in the round the application's deliveries go to,
        // where the links are read by a task or a listener; a read that steps its one link itself
        // hands it after each record from a room of the watches' own.
        #[cfg(all(
            any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ),
            any(feature = "threads", feature = "listen", feature = "group")
        ))]
        let decl_watches = DeclWatches::under(limits, &delivery.round)?;
        #[cfg(all(
            any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ),
            not(any(feature = "threads", feature = "listen", feature = "group"))
        ))]
        let decl_watches = DeclWatches::under(limits)?;
        let mut registry = Self {
            app: ManuallyDrop::new(app),
            delivery,
            sets: ManuallyDrop::new(sets),
            holders,
            #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
            owed,
            #[cfg(feature = "multicast-declarations")]
            peer_aliases: limits.max_peer_keyexpr_aliases_held(),
            #[cfg(all(test, feature = "runtime-plan"))]
            pools,
            #[cfg(feature = "local-queryable")]
            local,
            #[cfg(feature = "local-queryable")]
            local_due: DueRow::NEVER,
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
        registry.index_dues();
        Ok(registry)
    }

    /// Index the gets of every set and the session's own as an open finds them, none holding a
    /// deadline: what a registry is made with, whichever form holds it.
    fn index_dues(&mut self) {
        #[cfg(feature = "query")]
        self.dues().reset();
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
            .rows()
            .iter()
            .enumerate()
            .filter(|(_, holder)| names_face(**holder))
            .filter_map(|(at, _)| self.set(at))
    }

    /// Where the set face `id` holds lies among the sets, while the session holds the face.
    fn held_at(&self, id: FaceId) -> Option<usize> {
        place_of(self.holders.rows(), id)
    }

    /// The faces the session holds, in the order of their sets.
    #[cfg(any(feature = "liveliness", all(test, feature = "runtime-plan")))]
    fn held_ids(&self) -> impl Iterator<Item = FaceId> + '_ {
        self.holders
            .rows()
            .iter()
            .copied()
            .filter(|holder| names_face(*holder))
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
        (self.holders.rows().get(face.at) == Some(&face.id)).then_some(face.at)
    }

    /// The tables of face `id`, while the session holds it, to write.
    fn held_mut(&mut self, id: FaceId) -> Option<&mut FaceTables> {
        let at = self.held_at(id)?;
        self.sets.get_mut(at)
    }

    /// The pending gets of every face and, where the session answers its own gets, its own.
    #[cfg(all(feature = "query", any(feature = "liveliness-get", test)))]
    pub(super) fn all_gets(&self) -> impl Iterator<Item = &Gets> {
        let gets = self.faces().map(|face| &face.gets);
        #[cfg(feature = "local-queryable")]
        let gets = gets.chain(core::iter::once(&self.local));
        gets
    }

    /// [`Self::all_gets`], to write.
    #[cfg(all(feature = "query", any(feature = "liveliness-get", test)))]
    pub(super) fn all_gets_mut(&mut self) -> impl Iterator<Item = &mut Gets> {
        let gets = self
            .sets
            .iter_mut()
            .zip(self.holders.rows().iter())
            .filter(|(_, holder)| names_face(**holder))
            .map(|(face, _)| &mut face.gets);
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

    /// The index of the earliest deadline of the session's gets, over the rows the sets and the
    /// session's own gets keep.
    #[cfg(feature = "query")]
    fn dues(&mut self) -> Dues<'_> {
        let Self {
            sets,
            #[cfg(feature = "local-queryable")]
            local,
            #[cfg(feature = "local-queryable")]
            local_due,
            ..
        } = self;
        Dues {
            sets,
            #[cfg(feature = "local-queryable")]
            local: (local_due, local),
        }
    }

    /// The leaf of the index of the gets' deadlines that the gets of face `id` are, or the
    /// session's own for [`LOCAL_FACE`], while the session holds them.
    #[cfg(feature = "query")]
    fn gets_leaf(&self, id: FaceId) -> Option<usize> {
        #[cfg(feature = "local-queryable")]
        if id == LOCAL_FACE {
            return Some(self.sets.len());
        }
        self.held_at(id)
    }

    /// Write the pending gets of face `id`, or the session's own for [`LOCAL_FACE`], by `write`,
    /// while the session holds them: a deadline `write` adds lowers their leaf of the index of the
    /// gets' deadlines at once, so no get is due before the index says. Every get is held through
    /// here; an end needs no telling, as it only moves a table's deadline later.
    #[cfg(feature = "query")]
    pub(super) fn write_gets<R>(
        &mut self,
        id: FaceId,
        write: impl FnOnce(&mut Gets) -> R,
    ) -> Option<R> {
        let leaf = self.gets_leaf(id)?;
        if leaf < self.sets.len() {
            // As every hand-out of a face's tables to write is counted (`Self::face_mut`).
            self.writing();
        }
        let mut dues = self.dues();
        let wrote = write(dues.gets_mut(leaf)?);
        dues.lower(leaf);
        Some(wrote)
    }

    /// End the gets whose deadline passed by `now_ms`, each with its timeout: the index names the
    /// tables one is due in, so a table without one is not visited. A table swept holds no
    /// deadline at or before `now_ms` and is not named again, so each is swept once at most.
    #[cfg(feature = "query")]
    pub(super) fn sweep_due_gets(&mut self, now_ms: u64) {
        let mut dues = self.dues();
        for _ in 0..dues.leaves() {
            let Some(leaf) = dues.due_by(now_ms) else {
                break;
            };
            let Some(gets) = dues.gets_mut(leaf) else {
                break;
            };
            if now_ms >= gets.replies.due_ms() {
                gets.replies.sweep_timed_out(now_ms);
            }
            // Its terminated ids are staged for a reconnect cache, which the caller drains.
            #[cfg(feature = "liveliness-get")]
            if now_ms >= gets.liveliness_gets.due_ms() {
                gets.liveliness_gets.sweep_timed_out(now_ms);
            }
        }
    }

    /// How many places the open lent a set for: the places of every table of the session's faces.
    pub(super) fn places(&self) -> usize {
        self.sets.len()
    }

    /// The tables of `face`, gone with the face and left, emptied, where they lie for the next
    /// face: its place is free. The dial role's face is never removed, and the key of a face that
    /// is not held removes nothing.
    #[cfg(any(
        feature = "listen",
        feature = "group",
        all(test, feature = "runtime-plan")
    ))]
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
        let at = self
            .holders
            .rows()
            .iter()
            .position(|holder| *holder == NO_FACE)?;
        let row = self.holders.rows_mut().get_mut(at)?;
        *row = KEPT;
        Some(at)
    }

    /// The place at `at` a tomb kept is free again; a place a face holds is left as it is.
    #[cfg(feature = "connectivity")]
    pub(super) fn free_kept(&mut self, at: usize) {
        if let Some(row) = self
            .holders
            .rows_mut()
            .get_mut(at)
            .filter(|row| **row == KEPT)
        {
            *row = NO_FACE;
        }
    }

    /// Empty the set `face` holds, its row then reading `row`.
    #[cfg(any(
        feature = "listen",
        feature = "group",
        all(test, feature = "runtime-plan")
    ))]
    fn let_go(&mut self, face: HeldFace, row: FaceId) {
        if face.id == DIAL_FACE {
            return;
        }
        let Some(at) = self.place(face) else {
            return;
        };
        self.writing();
        if let Some(holder) = self.holders.rows_mut().get_mut(at) {
            *holder = row;
        }
        // Only a build that adds faces removes one, and only its sets keep tokens owed apart.
        #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
        self.owe_tokens_of(at);
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
    /// alone.
    #[cfg(feature = "multicast-declarations")]
    pub(super) fn hold_member_aliases(&mut self, face: HeldFace) {
        let Some(set) = self.place(face).and_then(|at| self.sets.get_mut(at)) else {
            return;
        };
        let aliases = &mut set.peer.subscribers;
        if aliases
            .alias_quota()
            .get()
            .admits(crate::arena::GROUP_FACE_ALIASES)
        {
            return;
        }
        if let Ok(quota) =
            MaxPeerKeyexprAliasesHeld::select(Quota::at_most(crate::arena::GROUP_FACE_ALIASES))
        {
            aliases.limit_aliases_to(quota);
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
        // A session of its dial role's face alone has no row to write, and so no set to give back.
        for (set, holder) in sets.iter_mut().zip(holders.rows_mut().iter_mut()) {
            if *holder == DIAL_FACE {
                continue;
            }
            if names_face(*holder) {
                set.give_back();
                #[cfg(feature = "multicast-declarations")]
                set.peer.subscribers.limit_aliases_to(*peer_aliases);
            }
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
    fn split(&mut self, at: Option<usize>) -> Option<Split<'_, H>> {
        self.writing();
        self.split_unwritten(at)
    }

    /// [`Self::split`] for a call that writes nothing a face's peer declared: a Push read into the
    /// subscribers' plane, and the drains after a run of them, which send what the session staged
    /// and take the `Final`s owed. Not counted as a write, so every answer read off the peers'
    /// declarations stands across a stream of samples.
    fn split_unwritten(&mut self, at: Option<usize>) -> Option<Split<'_, H>> {
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
    #[cfg(all(
        feature = "queryable",
        any(feature = "threads", feature = "listen", feature = "group")
    ))]
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
                #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
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
                #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
                Planes::All => app.dispatch_event_but_samples(
                    delivery,
                    &mut set.peer,
                    &mut set.gets,
                    event,
                    &others,
                    READ_TAKES,
                ),
                #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
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
        #[cfg(feature = "declarations-synced-event")]
        if !was_final && self.declarations_final(face) {
            #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
            // SAFETY: a face's frame is dispatched under the session's lock.
            unsafe {
                self.decl_watches.heard_synced()
            };
            #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
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
    #[cfg(all(
        feature = "local-subscriber",
        any(feature = "threads", feature = "listen", feature = "group")
    ))]
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
        not(any(feature = "threads", feature = "listen", feature = "group"))
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
    #[cfg(feature = "interest-answer")]
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
        #[cfg(feature = "interest-answer")]
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
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
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
    #[cfg(all(
        feature = "query",
        any(feature = "threads", feature = "listen", feature = "group")
    ))]
    pub(super) fn dispatch_reply(&mut self, face: HeldFace, event: IterationEvent<'_, '_>) {
        if let Some(Split { app, face, .. }) = self.split(self.place(face)) {
            app.dispatch_reply(&face.peer, &mut face.gets, event);
        }
        #[cfg(all(test, feature = "std"))]
        {
            self.replies_alone += 1;
        }
    }

    /// A Push of face `face` lent where its frame lies, read into the sample its subscribers are
    /// handed, over the frame, the face's peer and `room` (`SubscriberPeer::lend_in_place`), for
    /// a walk that hands it to one subscriber at a time with the session let go of (`pinned`).
    /// A face the session no longer holds lends nothing.
    #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
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
    #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
    pub(super) fn peer_class(&self, face: HeldFace) -> Option<wz_session_core::key_gate::ClassId> {
        let at = self.place(face)?;
        self.sets.get(at)?.peer.subscribers.class()
    }

    /// The subscribers' side of `message`, one owned record of a frame of face `face`, taken
    /// ahead of the frame's other planes (`Planes::BesideSubscribers`): a Push's projection, which
    /// the caller hands out one subscriber at a time, and any other record taken as the frame's
    /// dispatch takes it (`SubscriberPeer::take_record`). A face the session no longer holds
    /// takes nothing.
    #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
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
    #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
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
    #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
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
    #[cfg(all(
        feature = "query",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
    pub(super) fn lend_reply<'s, 'a: 's, 'f>(
        &'s mut self,
        face: HeldFace,
        record: &InPlaceRecord<'a, 'f>,
        room: &'s mut wz_session_core::reply::ReplyRoom,
    ) -> wz_session_core::reply::LentResponse<'s, 'f> {
        let Some(response) = record.response() else {
            return Ok(None);
        };
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
    #[cfg(all(
        feature = "query",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
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
        face.gets.replies.project_response(response, spaces)
    }

    /// The reply `response`, a record of a frame of face `face` the copying receive decoded, is
    /// delivered as (`ReplyRegistry::take_response`), for a read that hands it to the get it
    /// answers with the session let go of (`replies`), the frame's other planes told the rest of
    /// it after (`Planes::BesideSubscribers`). A face the session no longer holds takes nothing.
    #[cfg(all(
        feature = "query",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
    pub(super) fn take_reply(
        &mut self,
        face: HeldFace,
        response: &wz_session_core::wire::ResponseOwned,
    ) -> Option<wz_session_core::reply::InboundReply> {
        let Split { app, face, .. } = self.split_unwritten(self.place(face))?;
        let own = wz_session_core::pubsub::LocalSubscribers::own_space(&app.tables);
        let spaces = face.peer.subscribers.mapping_spaces_over(own);
        face.gets.replies.take_response(response, spaces)
    }

    /// Hand `reply`, read by [`Self::lend_reply`] or projected by [`Self::project_reply`], to
    /// the pending gets of face `face` it answers, as the face's dispatch hands a Response to
    /// them. A face the session no longer holds hands it to none.
    #[cfg(all(
        feature = "query",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
    pub(super) fn fire_reply(
        &mut self,
        face: HeldFace,
        reply: &dyn wz_session_core::reply_sink::ReplyView,
    ) {
        if let Some(Split { face, .. }) = self.split_unwritten(self.place(face)) {
            face.gets.replies.dispatch_borrowed(reply);
        }
    }

    /// The alive token `declare`, a record of a frame of face `face` the copying receive decoded,
    /// answers a pending liveliness get with: its key written into `room` and the interest id it
    /// answers (`LivelinessGetRegistry::claim_token`), for a read that hands it to the get with
    /// the session let go of (`replies`). A declaration that answers no pending get, and a face
    /// the session no longer holds, claim nothing.
    #[cfg(all(
        feature = "liveliness-get",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
    pub(super) fn claim_token(
        &mut self,
        face: HeldFace,
        declare: &wz_session_core::transport_profile::owned::DeclareOwned,
        room: &mut wz_session_core::wireexpr_resolve::KeyexprBuf,
    ) -> Option<u64> {
        let Split { app, face, .. } = self.split_unwritten(self.place(face))?;
        let own = wz_session_core::pubsub::LocalSubscribers::own_space(&app.tables);
        let spaces = face.peer.subscribers.mapping_spaces_over(own);
        face.gets.liveliness_gets.claim_token(declare, spaces, room)
    }

    /// [`Self::claim_token`] for the Declare `record` lends where its frame lies. A record that is
    /// no Declare claims nothing.
    #[cfg(all(
        feature = "liveliness-get",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
    pub(super) fn claim_lent_token(
        &mut self,
        face: HeldFace,
        record: &InPlaceRecord<'_, '_>,
        room: &mut wz_session_core::wireexpr_resolve::KeyexprBuf,
    ) -> Option<u64> {
        let declare = record.declare()?;
        let Split { app, face, .. } = self.split_unwritten(self.place(face))?;
        let own = wz_session_core::pubsub::LocalSubscribers::own_space(&app.tables);
        let spaces = face
            .peer
            .subscribers
            .mapping_spaces_over(own)
            .from_sender(record.sender());
        face.gets
            .liveliness_gets
            .claim_token_view(declare, spaces, room)
    }

    /// The query the Request `record` of face `face` lends, read for a walk that hands it to each
    /// queryable it reaches with the session let go of (`queries`), its key borrowed where it lies
    /// or composed into `room` (`QueryPeer::pin_request_in_place`): it borrows the face's peer,
    /// as long as the session is held. `None`, with what the Request owes staged in the
    /// face's Finals, for one no queryable is handed, and for a face the session no longer holds;
    /// refused for a Request the lent form does not represent, which the caller dispatches.
    #[cfg(all(
        feature = "queryable",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
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
    #[cfg(all(
        feature = "queryable",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
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

    /// Hand the alive token at `keyexpr` to the pending liveliness get `interest_id` of face
    /// `face` (`Self::claim_token`), as the face's dispatch hands it. A face the session no longer
    /// holds hands it to none.
    #[cfg(all(
        feature = "liveliness-get",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
    pub(super) fn fire_token(&mut self, face: HeldFace, interest_id: u64, keyexpr: &str) {
        if let Some(Split { face, .. }) = self.split_unwritten(self.place(face)) {
            face.gets
                .liveliness_gets
                .dispatch_reply_borrowed(interest_id, keyexpr);
        }
    }

    /// How often a face's tables were looked up since the open: what a lent Push's count of its
    /// lookups starts from ([`Self::counted_push`]).
    #[cfg(all(
        test,
        feature = "std",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
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
            #[cfg(feature = "interest-answer")]
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
    #[cfg(all(
        not(feature = "queryable"),
        any(feature = "threads", feature = "listen", feature = "group")
    ))]
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
        #[cfg(feature = "interest-answer")]
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
            #[cfg(feature = "interest-answer")]
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
    #[cfg(all(
        feature = "liveliness",
        any(feature = "threads", feature = "listen", feature = "group")
    ))]
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
        while let Some(tokens) = owed.first_mut() {
            if !app.flush_tokens_on_link_loss_while(delivery, tokens, room) {
                return false;
            }
            owed.remove(0);
        }
        true
    }

    /// Whether the face whose link was lost still owes the liveliness subscribers a token's
    /// retraction (`Self::take_lost_token`).
    #[cfg(all(
        feature = "liveliness",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
    pub(super) fn retracting(&self) -> bool {
        self.sets.iter().any(|set| set.retracting)
    }

    /// The next token the face whose link was lost owes the liveliness subscribers, its row
    /// unbound and its `Delete` written into `news`, in ascending id, for a read that hands it to
    /// them one row at a time with the session let go of: whether there was one. A face left
    /// owing none retracts no more.
    #[cfg(all(
        feature = "liveliness",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
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
    #[cfg(all(
        feature = "liveliness",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
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
            .is_some_and(|id| face.gets.liveliness_gets.has_pending(id))
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
    #[cfg(all(
        feature = "liveliness",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
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
            .is_some_and(|id| face.gets.liveliness_gets.has_pending(id))
        {
            return false;
        }
        let own = wz_session_core::pubsub::LocalSubscribers::own_space(&app.tables);
        let spaces = face.peer.subscribers.mapping_spaces_over(own);
        face.peer
            .tokens
            .take_token(&declare.body, spaces, declare.interest_id.is_some(), news)
    }

    /// Keep apart what the set at `at` still owes the liveliness subscribers as its face goes:
    /// the tokens of a lost link not retracted yet, which [`Self::retract_owed`] hands after those
    /// owed before them. The set is given back all the same, its token table left empty and taking
    /// rows of the session's pool.
    #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
    fn owe_tokens_of(&mut self, at: usize) {
        let Some(set) = self.sets.get_mut(at) else {
            return;
        };
        if !core::mem::take(&mut set.retracting) {
            return;
        }
        if let Some(tokens) = set.peer.tokens.split_off() {
            if tokens.count() > 0 {
                // A table owed holds a row of the session's token pool at least, and the open lent
                // a row of this table for each row of the pool.
                let kept = self.owed.push(tokens).is_ok();
                debug_assert!(kept, "the tokens owed fit the rows of the pool they hold");
            }
        }
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
/// ([`RegistryOf::reconcile_subscribers`]): one body for every caller, not one for each that inlines
/// it. Only a build that answers its peers' Interests keeps any to reconcile.
#[cfg(feature = "interest-answer")]
#[inline(never)]
fn reconcile_face(app: &App, face: &mut FaceTables) {
    face.peer.subscribers.reconcile(&app.tables);
}

/// Write a set of no rows in the next row of `sets`, held to `limits`, its peer's keys kept in
/// `keys`, the session's key arena, and what its peer writes in the rows `pools`, the session's,
/// hands it, and hand it back: a set is never a value of its own in this frame. `None` when
/// `sets` holds every row it was lent.
#[cfg(feature = "runtime-plan")]
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
#[cfg(feature = "runtime-plan")]
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
#[cfg(feature = "runtime-plan")]
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
    set.lend(arena, keys, pools, gets, peer, limits)
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
impl<H: Holders> Drop for RegistryOf<H> {
    fn drop(&mut self) {
        // SAFETY: the registry is being dropped: neither part is read again, and this is the one
        // place either is dropped.
        unsafe { let_go(&mut self.app, &mut self.sets) };
    }
}

/// Drop the application's tables, then the faces' sets: the one body every drop of a registry
/// runs, whichever crate drops it (see the `Drop` of `RegistryOf`), so never inlined.
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
// does; a build of the region's form is held by the region's tests (`crate::tests::region`).
#[cfg(all(test, feature = "runtime-plan"))]
mod tests {
    //! Each face's tables are lent from the session's arena: the dial face's at the open, an
    //! accepted face's from the spares the open lent, and past those tables of no rows that refuse
    //! what is asked of them: the session takes no memory but its arena.
    use super::adding::FacesFull;
    use super::held::{Holders, ManyHolders, OneHolder};
    use super::*;
    use crate::arena::{AllocatorMemory, SessionArena};
    use wz_session_core::peer_tables::PeerPoolRows;
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

    /// The registry of a session that adds faces beside its dial role's, which most of these tests
    /// hold several of, whatever the build.
    type Registry = RegistryOf<ManyHolders>;

    /// A registry and the arena its tables were lent from, the registry first so its tables go
    /// before the memory they lie in, and how many sets the open lent rows to.
    struct Held<H: Holders = ManyHolders> {
        registry: RegistryOf<H>,
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
        held_of::<ManyHolders>(faces, pools, dial)
    }

    /// [`held_as`], its faces held as `H` holds them.
    fn held_of<H: Holders>(faces: usize, pools: PeerPoolRows, dial: bool) -> Held<H> {
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
        let delivery = RoundDelivery {
            #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
            round: crate::round::leaked(4),
            #[cfg(feature = "queryable")]
            plane: wz_session_core::placed::PlacedRef::of_static(alloc::boxed::Box::leak(
                super::super::query::leaked_plane(1),
            )),
        };
        let registry = RegistryOf::<H>::new(
            &SessionLimits::defaults(),
            arena.arena_mut(),
            keys,
            // A row for a liveliness subscriber, which the tests of retractions declare.
            ObserverRows {
                tables: wz_session_core::session_tables::TableRows {
                    liveliness_subscribers: 1,
                    ..Default::default()
                },
                ..ObserverRows::default()
            },
            gets,
            peers,
            delivery,
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
            .filter(|at| held.registry.holders.rows()[*at] == NO_FACE)
            .count()
    }

    /// Whether face `id` holds a set the open lent rows to.
    fn in_a_lent_set(held: &Held, id: FaceId) -> bool {
        held.registry.held_at(id).is_some_and(|at| at < held.lent)
    }

    /// The faces the registry holds, in the order its walks take them.
    fn face_ids(registry: &Registry) -> Vec<FaceId> {
        registry.held_ids().collect()
    }

    /// Remove face `id` by the key its link or its group holds.
    fn remove(registry: &mut Registry, id: FaceId) {
        let face = registry.held(id);
        registry.remove_face(face);
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
            (true, true),
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
    #[cfg(feature = "interest-answer")]
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
        remove(&mut held.registry, 5);
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
        // SAFETY: this thread is the round's one writer.
        unsafe { held.registry.delivery.round.seal() };
        assert!(held.registry.delivery.round.deliver(), "the appearances");
        let lies_at: *const FaceTables = face(&mut held.registry, 5);
        held.registry.lose_tokens(5);
        held.registry.lose_tokens(6);
        remove(&mut held.registry, 5);
        remove(&mut held.registry, 6);
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
        // SAFETY: this thread is the round's one writer.
        unsafe { held.registry.delivery.round.seal() };
        assert!(held.registry.delivery.round.deliver(), "the retractions");
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
            assert!(set.peer.finals.has_room(), "each row of each set is free");
            #[cfg(feature = "query")]
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
        // rows alone. Shared, as a session of many faces lends them.
        let pool_rows = PeerPoolRows {
            aliases: 1,
            remote_decls: 1,
            interests: 1,
            shared: true,
        };
        let mut by_value_arena =
            SessionArena::of_bytes(1 << 16, &AllocatorMemory).expect("the host has the memory");
        let by_value_keys = by_value_arena
            .arena_mut()
            .lend_keys(256, limits.max_keyexpr_bytes_held())
            .expect("the arena holds the key arena");
        let mut arena =
            SessionArena::of_bytes(1 << 16, &AllocatorMemory).expect("the host has the memory");
        let keys = arena
            .arena_mut()
            .lend_keys(256, limits.max_keyexpr_bytes_held())
            .expect("the arena holds the key arena");
        // A set's tables reach the rows of their pools through the key arena they keep their keys
        // in, which names the pools lent with it: pools of their own for each key arena.
        let mut pool_arena =
            SessionArena::of_bytes(1 << 16, &AllocatorMemory).expect("the host has the memory");
        let mut by_value_pools = PeerPools::lent(pool_arena.arena_mut(), by_value_keys, pool_rows)
            .expect("the arena has the pools");
        let mut pools = PeerPools::lent(pool_arena.arena_mut(), keys, pool_rows)
            .expect("the arena has the pools");
        let by_value_gets =
            Gets::lent(by_value_arena.arena_mut(), by_value_keys, gets, &limits).expect("rows");
        let mut by_value_peer = Peer::lent(
            by_value_arena.arena_mut(),
            by_value_keys,
            peer,
            &mut by_value_pools,
            &limits,
        )
        .expect("rows");
        // The table of sets lies in an arena of its own, so `arena` counts the set's rows alone.
        let mut sets_arena = SessionArena::of_bytes(
            FACE_SET_BYTES + wz_session_core::bounded::ARENA_ALIGN,
            &AllocatorMemory,
        )
        .expect("the host has the memory");
        let mut sets: BoundedVec<FaceTables, MAX_FACE_SETS, RowPolicy> = sets_arena
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
        #[cfg(feature = "query")]
        assert_eq!(
            set.gets.replies.has_room(),
            by_value_gets.replies.has_room()
        );
        #[cfg(not(feature = "query"))]
        assert_eq!(
            set.gets, by_value_gets,
            "a build that asks no query lends neither a table of gets"
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
        remove(&mut held.registry, 5);
        assert_eq!(
            held.registry.add_face(6).map(|face| face.at()),
            Ok(1),
            "CONTROL: a set is free again, at the place the face left"
        );
        assert!(in_a_lent_set(&held, 6));
    }

    /// A free set's row of the index of held sets names no face: a lookup of the id it reads
    /// finds no set while sets are free, and one removed by it removes none. Turned red by a
    /// lookup that matches a free set's row.
    #[test]
    fn a_free_sets_row_names_no_face() {
        let mut held = held(3);
        held.registry
            .add_face(5)
            .expect("the open lent a set for the face");
        assert_eq!(held.registry.holders.rows(), &[DIAL_FACE, 5, NO_FACE]);
        assert_eq!(held.registry.held_at(NO_FACE), None);
        assert_eq!(
            held.registry.place(held.registry.held(NO_FACE)),
            None,
            "no key of it finds a set"
        );
        remove(&mut held.registry, NO_FACE);
        assert_eq!(
            held.registry.holders.rows(),
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
        assert_eq!(
            held.registry.holders.rows(),
            &[DIAL_FACE, KEPT, NO_FACE, NO_FACE]
        );
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
            held.registry.holders.rows()[3],
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
            held.registry.holders.rows(),
            &[DIAL_FACE, NO_FACE, NO_FACE, NO_FACE],
            "a tomb's place goes with the faces'"
        );
    }

    /// A face's key finds its set by its place while the face holds it, and nothing once the face
    /// went, though another face took the set since; the key of a face the session does not hold
    /// finds nothing. Turned red by a key read off the place alone, without the id.
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
        assert!(held.registry.peers_declare(Plane::Subscribers, "demo/5/1"));
        assert!(!held.registry.peers_declare(Plane::Subscribers, "demo/past"));
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
        remove(&mut held.registry, 5);
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
    /// The index of the gets' deadlines keeps a leaf for each set the open lent, held or free, and
    /// one for the session's own gets after them: a face's gets are its set's leaf, a face not held
    /// has none and is not written, and a registry made with no get pending answers no deadline.
    /// Turned red by an index made a leaf short or over, or by a face's gets found at another
    /// set's leaf.
    #[cfg(feature = "query")]
    #[test]
    fn the_index_of_the_gets_deadlines_keeps_a_leaf_for_each_set() {
        let mut held = held(4);
        held.registry
            .add_face(5)
            .expect("the open lent a set for the face");
        let own = usize::from(cfg!(feature = "local-queryable"));
        assert_eq!(held.registry.dues().leaves(), 4 + own);
        assert_eq!(held.registry.gets_leaf(DIAL_FACE), Some(0));
        let added = held.registry.gets_leaf(5);
        assert_eq!(added, held.registry.held_at(5));
        assert!(added.is_some_and(|leaf| leaf > 0 && leaf < 4), "{added:?}");
        assert_eq!(held.registry.gets_leaf(9), None, "a face not held");
        #[cfg(feature = "local-queryable")]
        assert_eq!(held.registry.gets_leaf(LOCAL_FACE), Some(4));
        let mut written = false;
        assert_eq!(held.registry.write_gets(9, |_| written = true), None);
        assert!(!written, "the gets of a face not held were written");
        assert_eq!(
            SessionFaces::next_get_deadline_ms(&mut held.registry),
            None,
            "CONTROL: no get is pending"
        );
    }

    /// A session of its dial role's face alone holds that face in the first set and no other, and
    /// keeps no index of held sets: a face that is not the dial role's finds no set, no call counts
    /// another face, and neither removing the dial role's face nor every accepted face empties its
    /// set. Turned red by a one-face index that names a second face or lets the dial role's set go.
    #[test]
    fn a_session_of_one_face_holds_its_dial_role_s_face_alone() {
        assert_eq!(core::mem::size_of::<OneHolder>(), 0, "no index is kept");
        let pools = PeerPoolRows {
            aliases: 16,
            remote_decls: 16,
            interests: 16,
            shared: false,
        };
        let mut held = held_of::<OneHolder>(1, pools, true);
        let registry = &mut held.registry;
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
        assert!(registry.split(Some(0)).is_some());
        assert!(
            registry.split(Some(1)).is_none(),
            "one set lies at the first place"
        );
        #[cfg(feature = "connectivity")]
        assert_eq!(registry.keep_place(), None, "no place is free to keep");
        registry
            .held_mut(DIAL_FACE)
            .expect("the dial role's face holds the first set")
            .peer
            .finals
            .owe(1, QosLevel::DEFAULT);
        let dial = registry.held(DIAL_FACE);
        registry.remove_face(dial);
        registry.remove_accepted_faces();
        assert_eq!(
            registry.held_at(DIAL_FACE),
            Some(0),
            "the dial role's face stays"
        );
        assert_eq!(
            registry.sets[0].peer.finals.owed(),
            1,
            "and its set was not given back"
        );
    }

    /// The index of a session that adds faces is lent a row for each set, the dial role's face's
    /// first and every other free, while a session of one face reads its one row off its form.
    /// Turned red by an index that names a face in a set no face took.
    #[test]
    fn each_form_names_the_dial_role_s_face_in_the_first_set() {
        let many = held(3);
        assert_eq!(many.registry.holders.rows(), &[DIAL_FACE, NO_FACE, NO_FACE]);
        let one = held_of::<OneHolder>(
            1,
            PeerPoolRows {
                aliases: 16,
                remote_decls: 16,
                interests: 16,
                shared: false,
            },
            true,
        );
        assert_eq!(one.registry.holders.rows(), &[DIAL_FACE]);
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
