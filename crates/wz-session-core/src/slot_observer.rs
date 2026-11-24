// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The application-layer observer of the session-slot profile: what the
//! APPLICATION registers, and nothing a peer writes (fixed-memory step S9a,
//! decision Q7).
//!
//! [`crate::observer::ApplicationLayerObserver`] is the AP's: one per session,
//! holding every registry including the tables its peer fills. Under
//! `session-slot` a process serves several sessions from one set of application
//! registrations, so the shape splits by who writes the table:
//!
//! - HERE, once per process: the subscriber table, the queryable table, the
//!   local tokens, the switchboard, and the observer lists of the declaration
//!   registries (what the application listens to);
//! - in each session's SLOT ([`crate::peer_tables::PeerTables`], reached through
//!   `SlotRef::peers`): the peer's keyexpr aliases, its declarations, its
//!   interests, the replies and `Final`s its queries owe, the answers to its
//!   liveliness interests. A wire id is scoped by its session, so these cannot
//!   be shared, and a flood of one session's must stay that session's;
//! - beside each session, caller-supplied ([`crate::slot_observer::Requesters`]): the requester-side
//!   pending queries, which the application writes and whose request ids are
//!   minted per session. They are generic over the application's reply sink, so
//!   the owner of the session (the image) types them; a heap-closure sink makes
//!   them the AP's, a closed enum makes them allocation-free.
//!
//! Every dispatch and drain takes the session's tables as an argument, so the one
//! observer serves every slot and never holds a session's state between calls.
//! The order and the rules are the AP observer's, step for step (the subscriber
//! side first so a `DeclKexpr` binds before the planes that resolve through it;
//! a liveliness get's replies claimed before the token planes see them; every
//! Reply drained before the `Final` that terminates it).

// `Requesters` is generic over the application's reply sink and names no heap
// type, and neither is [`SlotObserverOf`]: the sinks it registers are the types an
// [`ObserverSinks`] names. The liveliness planes and the switchboard register heap
// forms, so they, and what only they name, sit behind `alloc`.
use core::mem::MaybeUninit;

use crate::bounded::{Arena, LendRefused, Lent, Profile, Storage};
use crate::caps;
use crate::decl_sink::{DeclSink, UndeclSink};
#[cfg(all(feature = "alloc", feature = "liveliness-token"))]
use crate::declare::liveliness::LivelinessRegistry;
#[cfg(feature = "liveliness-get")]
use crate::declare::liveliness_get::LivelinessGetRegistry;
use crate::declare::liveliness_sample::LivelinessSampleSink;
use crate::declare::liveliness_subscriber::LivelinessDelivered;
#[cfg(feature = "liveliness-subscriber")]
use crate::declare::liveliness_subscriber::{
    LivelinessSubscriberTable, LocalLivelinessSubscribers,
};
#[cfg(all(feature = "alloc", feature = "liveliness-token"))]
use crate::declare::local_token::LocalTokenRegistry;
#[cfg(feature = "declare-queryable")]
use crate::declare::queryable::RemoteQueryableTable;
#[cfg(feature = "declare-subscriber")]
use crate::declare::subscriber::RemoteSubscriberTable;
use crate::declare::{DefaultMatchingReport, MatchingReport};
use crate::driver_loop::IterationEvent;
use crate::key_arena::KeySpace;
use crate::limit_binding::{Quota, UnlentRows};
use crate::peer_tables::PeerTables;
/// The session's own subscribers as the observer's paths read them, from the table of either
/// storage profile or the session's one table set.
pub use crate::pubsub::LocalSubscribers;
use crate::pubsub::{SubscriberTable, SubscriptionId};
#[cfg(feature = "query-queryable")]
use crate::query::{LocalQueryables, QueryDelivered, QueryableRegistry};
use crate::query_sink::QuerySink;
use crate::reply::ReplyRegistry;
use crate::reply_sink::ReplySink;
#[cfg(feature = "query-queryable")]
use crate::reply_stage::{FinalStaging, ReplyStaging};
use crate::response_sink::{DeclareReplySink, LivelinessGetPrune, ResponseSink};
use crate::session_tables::{RowCallbacks, SessionTables, TableRows};
use crate::sink::{SampleDelivery, SampleSink};
#[cfg(all(feature = "alloc", feature = "switchboard"))]
use crate::switchboard::{EventInjector, SwitchboardRegistry};

/// The requester-side registries of ONE session: the pending `z_get`s and, with
/// `liveliness-get`, the pending liveliness snapshots. Written by the
/// application when it asks and completed by the peer's answer, and keyed by
/// request and interest ids this session minted, so two sessions' ids collide in
/// one registry: each session has its own, placed beside its slot by whoever owns
/// the session.
///
/// `P` is the storage of both registries: the build's [`Profile`], or [`Lent`] for the
/// requesters of one face of a session whose rows its arena lent at its open
/// ([`Requesters::lent`]).
pub struct Requesters<R: ReplySink, G: ReplySink, P: Storage = Profile> {
    /// The pending queries (`z_get`), bounded by [`crate::caps::MAX_PENDING_QUERIES`].
    pub replies: ReplyRegistry<R, P>,
    /// The pending liveliness snapshots, bounded by
    /// [`crate::caps::MAX_PENDING_LIVELINESS_GETS`].
    #[cfg(feature = "liveliness-get")]
    pub liveliness_gets: LivelinessGetRegistry<G, P>,
    #[cfg(not(feature = "liveliness-get"))]
    _gets: core::marker::PhantomData<G>,
}

impl<R: ReplySink, G: ReplySink> Requesters<R, G> {
    /// No query pending.
    pub fn new() -> Self {
        Self {
            replies: ReplyRegistry::with_sink_backing(),
            #[cfg(feature = "liveliness-get")]
            liveliness_gets: LivelinessGetRegistry::with_sink_backing(),
            #[cfg(not(feature = "liveliness-get"))]
            _gets: core::marker::PhantomData,
        }
    }

    /// [`Self::new`], each registry held to the limits `limits` states ([`Self::limit_to`]).
    pub fn with_limits(limits: &crate::limits::SessionLimits) -> Self {
        let mut requesters = Self::new();
        requesters.limit_to(limits);
        requesters
    }
}

/// How many rows each registry of [`Requesters`] of the lent policy is lent
/// ([`Requesters::lent`]): the values of their limits the session's open resolved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequesterRows {
    /// The pending queries (`MAX_PENDING_QUERIES`).
    pub queries: usize,
    /// The pending liveliness snapshots (`MAX_PENDING_LIVELINESS_GETS`); lent none in a build
    /// without `liveliness-get`.
    pub liveliness_gets: usize,
}

impl<R: ReplySink, G: ReplySink> Requesters<R, G, Lent> {
    /// No query pending, each registry's rows lent from `arena` as `rows` states, the keyexpr
    /// each query was asked under kept in `keys`, the session's key arena, and held to `limits`
    /// as [`Requesters::with_limits`] holds one. Refused when the arena has not the room, the rows
    /// lent so far going back with the arena.
    pub fn lent(
        arena: &mut Arena,
        keys: KeySpace,
        rows: RequesterRows,
        limits: &crate::limits::SessionLimits,
    ) -> Result<Self, LendRefused> {
        let mut requesters = Self {
            replies: ReplyRegistry::lent(arena, keys, rows.queries)?,
            #[cfg(feature = "liveliness-get")]
            liveliness_gets: LivelinessGetRegistry::lent(arena, rows.liveliness_gets)?,
            #[cfg(not(feature = "liveliness-get"))]
            _gets: core::marker::PhantomData,
        };
        requesters.limit_to(limits);
        Ok(requesters)
    }

    /// The bytes of an arena [`Self::lent`] takes for `rows`: each registry's spans. `None` past
    /// the address space.
    pub const fn arena_bytes(rows: RequesterRows) -> Option<usize> {
        // A build without `liveliness-get` lends the snapshots no rows.
        #[cfg(feature = "liveliness-get")]
        let gets = LivelinessGetRegistry::<G, Lent>::arena_bytes(rows.liveliness_gets);
        #[cfg(not(feature = "liveliness-get"))]
        let gets = Some(0);
        match (ReplyRegistry::<R, Lent>::arena_bytes(rows.queries), gets) {
            (Some(queries), Some(gets)) => queries.checked_add(gets),
            _ => None,
        }
    }
}

impl<R: ReplySink, G: ReplySink, P: Storage> Requesters<R, G, P> {
    /// Hold each registry to the limits `limits` states: what the creator of the session resolved
    /// for it. What each registry holds is kept, and what it is asked for next is held to the new
    /// quota.
    pub fn limit_to(&mut self, limits: &crate::limits::SessionLimits) {
        self.replies.limit_to(limits.max_pending_queries_held());
        self.replies.limit_keys_to(limits.max_keyexpr_bytes_held());
        #[cfg(feature = "liveliness-get")]
        self.liveliness_gets
            .limit_to(limits.max_pending_liveliness_gets_held());
    }

    /// Drop every pending get of both registries without firing anything, keeping their rows: the
    /// requesters of a face that went, emptied for the next.
    pub fn clear(&mut self) {
        self.replies.clear();
        #[cfg(feature = "liveliness-get")]
        self.liveliness_gets.clear();
    }
}

impl<R: ReplySink, G: ReplySink, P: Storage> Default for Requesters<R, G, P> {
    /// No query pending. Of the lent policy, a requester lent no rows, which refuses every get.
    fn default() -> Self {
        Self {
            replies: ReplyRegistry::default(),
            #[cfg(feature = "liveliness-get")]
            liveliness_gets: LivelinessGetRegistry::default(),
            #[cfg(not(feature = "liveliness-get"))]
            _gets: core::marker::PhantomData,
        }
    }
}

/// The requester side of one session as the observer's fan and drains read it: the pending gets
/// and liveliness snapshots of [`Requesters`], or none at all ([`NoRequesters`]) in a build that
/// asks nothing, whose fan and drains then carry no requester path. Who holds the session's
/// requesters chooses which by the type it passes.
pub trait RequesterTables {
    /// Whether the liveliness token answering `interest_id` belongs to one of this session's
    /// pending liveliness snapshots, and so to no liveliness subscriber.
    #[cfg(feature = "liveliness-get")]
    fn claims(&self, interest_id: u64) -> bool;

    /// Fan `event` into the pending snapshots, then the pending gets, resolving the peer's keys
    /// through `peer_table`.
    #[cfg(any(
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-get"
    ))]
    fn dispatch_iteration_event(
        &mut self,
        event: IterationEvent<'_, '_>,
        peer_table: crate::wireexpr_resolve::MappingSpaces<'_>,
    );

    /// Whether a snapshot terminated since the last drain, its prune still to run.
    #[cfg(feature = "liveliness-get")]
    fn has_finalized(&self) -> bool;

    /// Hand the interest of every snapshot that terminated to `sink` to prune.
    #[cfg(feature = "liveliness-get")]
    fn drain_prunes<S: LivelinessGetPrune>(&mut self, sink: &S);
}

impl<R: ReplySink, G: ReplySink, P: Storage> RequesterTables for Requesters<R, G, P> {
    #[cfg(feature = "liveliness-get")]
    fn claims(&self, interest_id: u64) -> bool {
        self.liveliness_gets.has_pending(interest_id)
    }

    #[cfg(any(
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-get"
    ))]
    fn dispatch_iteration_event(
        &mut self,
        event: IterationEvent<'_, '_>,
        peer_table: crate::wireexpr_resolve::MappingSpaces<'_>,
    ) {
        #[cfg(feature = "liveliness-get")]
        self.liveliness_gets
            .dispatch_iteration_event(event, peer_table);
        #[cfg(any(feature = "codec-response", feature = "codec-response-final"))]
        self.replies.dispatch_iteration_event(event, peer_table);
    }

    #[cfg(feature = "liveliness-get")]
    fn has_finalized(&self) -> bool {
        self.liveliness_gets.has_finalized()
    }

    #[cfg(feature = "liveliness-get")]
    fn drain_prunes<S: LivelinessGetPrune>(&mut self, sink: &S) {
        for interest_id in self.liveliness_gets.take_finalized() {
            sink.prune_liveliness_get_interest(interest_id);
        }
    }
}

/// The requester side of a session that asks nothing: no get and no liveliness snapshot is ever
/// pending, so the observer's fan hands it nothing and its drains find nothing in it. Of no size
/// and with nothing to drop: a session that holds it holds no table of pending gets.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NoRequesters;

impl RequesterTables for NoRequesters {
    #[cfg(feature = "liveliness-get")]
    fn claims(&self, _interest_id: u64) -> bool {
        false
    }

    #[cfg(any(
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-get"
    ))]
    fn dispatch_iteration_event(
        &mut self,
        _event: IterationEvent<'_, '_>,
        _peer_table: crate::wireexpr_resolve::MappingSpaces<'_>,
    ) {
    }

    #[cfg(feature = "liveliness-get")]
    fn has_finalized(&self) -> bool {
        false
    }

    #[cfg(feature = "liveliness-get")]
    fn drain_prunes<S: LivelinessGetPrune>(&mut self, _sink: &S) {}
}

/// What the OTHER faces of a session declare, which the matching verdicts of one face's dispatch
/// count beside that face's own and the application's: a matching listener on a publisher
/// matches while ANY face's peer holds a subscriber for it, so a peer that undeclares one
/// leaves the listener matching while another still holds its own. A session with one face has
/// no other ([`NoOtherPeers`]).
pub trait OtherPeers {
    /// Whether another face's peer declared a subscriber the publisher `criterion` reaches.
    #[cfg(feature = "declare-subscriber")]
    fn subscribes(&self, criterion: &crate::declare::subscriber::PublisherCriterion) -> bool;

    /// Whether another face's peer declared a queryable the querier `criterion` reaches. `false`
    /// unless the faces say otherwise: a session whose engine reads no queryable a peer declares
    /// (an engine built without a querier or a queryable, in a build that has the plane for another
    /// crate's sake) has no other face that answers.
    #[cfg(feature = "declare-queryable")]
    fn answers(&self, criterion: &crate::declare::queryable::QuerierCriterion) -> bool {
        let _ = criterion;
        false
    }
}

/// The session has no face but the one dispatched.
pub struct NoOtherPeers;

impl OtherPeers for NoOtherPeers {
    #[cfg(feature = "declare-subscriber")]
    fn subscribes(&self, _criterion: &crate::declare::subscriber::PublisherCriterion) -> bool {
        false
    }

    #[cfg(feature = "declare-queryable")]
    fn answers(&self, _criterion: &crate::declare::queryable::QuerierCriterion) -> bool {
        false
    }
}

/// What the application registered, shared by every session of the process. See
/// the module documentation. The sinks it registers are the types `K` names
/// ([`ObserverSinks`]): [`SlotObserver`] is the heap profile's, with boxed closures.
///
/// `P` is the storage of the tables the application writes (its subscriptions,
/// queryables, tokens and liveliness subscribers): the build's [`Profile`], or
/// [`Lent`] for an observer whose rows a session's arena lent at its open
/// ([`SlotObserverOf::lent`]), the declaration watchers' lists among them. What a peer
/// writes is in the [`PeerTables`] each call is handed, of their own policy.
///
/// `M` is what a matching listener's flips are handed to ([`MatchingReport`]): a boxed closure
/// unless the holder names a sink of its own.
pub struct SlotObserverOf<
    K: ObserverSinks = DefaultSinks,
    P: Storage = Profile,
    M: MatchingReport = DefaultMatchingReport,
> {
    /// The application's tables `K` keeps (`ObserverSinks::Tables`): the local subscriptions and
    /// queryables, in the registries of the storage policies ([`RegistryTables`]) or the
    /// session's one table set. One registration serves every session.
    pub tables: K::Tables<P>,
    /// The statechart switchboard (the keyexpr -> event table).
    #[cfg(feature = "switchboard")]
    pub switchboard: SwitchboardRegistry,
    /// The application's listeners on the subscribers a peer declares.
    #[cfg(feature = "declare-subscriber")]
    pub remote_subscribers: RemoteSubscriberTable<K::Declared, K::Undeclared, P, M>,
    /// The application's listeners on the queryables a peer declares.
    #[cfg(feature = "declare-queryable")]
    pub remote_queryables: RemoteQueryableTable<K::Declared, K::Undeclared, P, M>,
    /// The matching sink type of a build that holds neither remote table, and so no listener.
    #[cfg(not(any(feature = "declare-subscriber", feature = "declare-queryable")))]
    matching: core::marker::PhantomData<M>,
    /// The application's listeners on the tokens a peer declares.
    #[cfg(feature = "liveliness-token")]
    pub liveliness:
        LivelinessRegistry<crate::decl_sink::BoxedDeclSink, crate::decl_sink::BoxedUndeclSink, P>,
    /// The tokens wz itself holds, answered to a peer's interest.
    #[cfg(feature = "liveliness-token")]
    pub local_tokens: LocalTokenRegistry<P>,
}

/// How many rows each application table of an observer of the lent policy is lent
/// ([`SlotObserverOf::lent`]): the values of their limits the session's open resolved.
///
/// `S` is what the application's tables are lent by ([`LentTables::Rows`]): each registry's
/// rows ([`RegistryRows`]), or every table's rows for the session's one table set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObserverRows<S = RegistryRows> {
    /// The rows of the application's tables ([`ObserverSinks::Tables`]): each registry's
    /// ([`RegistryRows`]), or each table's of the session's one table set ([`TableRows`]).
    pub tables: S,
    /// The tokens the session holds (`MAX_LOCAL_TOKENS`).
    pub local_tokens: usize,
}

/// The sink types a node registers on its [`SlotObserverOf`]: one type for each kind of
/// registration, which is what lets the observer name no heap type. The heap profile's
/// ([`HeapSinks`]) are the boxed closures; a node with no allocator names closed types
/// of its own (a function pointer and a `&'static` context, an enum over the few
/// registrations it makes).
pub trait ObserverSinks {
    /// What a local subscription's row keeps of its subscriber, delivered through
    /// [`Self::Delivery`].
    type Subscriber;
    /// The id the tables give a subscription's row, which a delivery names it by.
    type SubscriberId: Copy;
    /// The id the tables give a queryable's row, which a delivery names it by.
    type QueryableId: Copy;
    /// The id the tables give a liveliness subscriber's row, which a delivery names it by.
    type LivelinessSubscriberId: Copy;
    /// The context a matched row is delivered through, handed to the dispatch
    /// ([`SlotObserverOf::dispatch_event`]) so a row holds no reference to the state its samples,
    /// its queries and its tokens go to. `()` for rows that deliver themselves ([`SampleSink`],
    /// [`crate::query::ResponderSink`], [`LivelinessSampleSink`]). How each kind's rows are told
    /// through it is the rows' own: [`Self::Queryable`], [`Self::LivelinessSubscriber`].
    type Delivery: SampleDelivery<Self::Subscriber, Self::SubscriberId>;
    /// The application's tables, of storage `P`, as one bundle: the registries of the storage
    /// policies ([`RegistryTables`]), or the session's one table set, whose rows are the session's
    /// only record of each entity. One type for every kind the bundle holds, so a kind that moves
    /// into it adds no type here (`docs/c-abi-architecture.md`, P1).
    type Tables<P: Storage>: ObserverTables<Sink = Self::Subscriber, RowId = Self::SubscriberId>
        + QueryTables<Self::Queryable, Self::QueryableId>
        + LivelinessTables<Self::LivelinessSubscriber, Self::LivelinessSubscriberId>;
    /// What a local queryable's row keeps of its queryable, asked through [`Self::Delivery`]: a
    /// row that answers itself is asked by `()` with the view and the responder of the wire
    /// dispatch as their own types, so a closed sink is called with no vtable.
    #[cfg(feature = "query-queryable")]
    type Queryable: QueryDelivered<Self::Delivery, Self::QueryableId>;
    /// What a local queryable's row keeps of its queryable; a build that asks none reads nothing
    /// of it.
    #[cfg(not(feature = "query-queryable"))]
    type Queryable;
    /// What a local liveliness subscriber's row keeps of its subscriber, told through
    /// [`Self::Delivery`].
    type LivelinessSubscriber: LivelinessDelivered<Self::Delivery, Self::LivelinessSubscriberId>;
    /// What a peer's declaration is announced to.
    type Declared: DeclSink;
    /// What a peer's undeclaration is announced to.
    type Undeclared: UndeclSink;
}

/// The heap profile's registrations: boxed closures.
#[cfg(feature = "alloc")]
pub struct HeapSinks;

#[cfg(feature = "alloc")]
impl ObserverSinks for HeapSinks {
    type Subscriber = crate::sink::BoxedSink;
    type SubscriberId = SubscriptionId;
    type QueryableId = crate::query::QueryableId;
    type LivelinessSubscriberId = u64;
    type Delivery = ();
    type Tables<P: Storage> =
        RegistryTables<Self::Subscriber, Self::Queryable, Self::LivelinessSubscriber, P>;
    type Queryable = crate::query_sink::BoxedQuerySink;
    type LivelinessSubscriber = crate::declare::liveliness_sample::BoxedLivelinessSampleSink;
    type Declared = crate::decl_sink::BoxedDeclSink;
    type Undeclared = crate::decl_sink::BoxedUndeclSink;
}

/// A registration that cannot exist: a type with no values, for the kinds of
/// registration a node makes none of. It stands in for them in [`NoSinks`], so a build
/// with no allocator has a default observer type to name that registers nothing.
#[derive(Debug, Clone, Copy)]
pub enum NoSink {}

impl SampleSink for NoSink {
    fn deliver(&mut self, _sample: &dyn crate::sink::SampleView) {
        match *self {}
    }
}

impl QuerySink for NoSink {
    fn handle(
        &mut self,
        _query: &dyn crate::query_sink::QueryView,
        _out: &mut dyn crate::query_sink::ReplyOut,
    ) {
        match *self {}
    }
}

impl DeclSink for NoSink {
    fn on_declared(&mut self, _decl: &dyn crate::decl_sink::DeclView) {
        match *self {}
    }
}

impl UndeclSink for NoSink {
    fn on_undeclared(&mut self, _id: u64) {
        match *self {}
    }
}

impl LivelinessSampleSink for NoSink {
    fn on_sample(&mut self, _sample: crate::declare::liveliness_sample::LivelinessSample<'_>) {
        match *self {}
    }
}

/// What the observer asks of the application's tables ([`ObserverSinks::Tables`]) beyond what
/// its paths read of the subscriptions ([`LocalSubscribers`]): to be made empty and to be held to
/// the session's limits.
pub trait ObserverTables: LocalSubscribers + Sized {
    /// Tables of no entity. Of the lent policy they were lent no rows, and refuse every
    /// registration; [`LentTables::lend`] makes the ones a session holds.
    fn empty() -> Self;

    /// Hold the tables to the limits `limits` states, what the creator of the session resolved for
    /// them. What they hold is kept, and what they are asked for next is held to the new bound.
    fn hold_to(&mut self, limits: &crate::limits::SessionLimits);
}

/// The table of the application's tables the session's own queryables are kept in and asked
/// through, whose rows keep a `Sink` named by an `Id`. Without `query-queryable` the build keeps
/// none, and every bundle meets this with nothing.
pub trait QueryTables<Sink, Id> {
    /// The queryables' table.
    #[cfg(feature = "query-queryable")]
    type Queryables: LocalQueryables<Sink = Sink, RowId = Id>;

    /// The queryables, to read.
    #[cfg(feature = "query-queryable")]
    fn queryables(&self) -> &Self::Queryables;

    /// The queryables to ask, with our own id space beside them where the tables hold the key
    /// expressions the session declared: a peer's query names its key through the one while the
    /// other is asked, so the two are borrowed apart.
    #[cfg(feature = "query-queryable")]
    fn queries_mut(
        &mut self,
    ) -> (
        Option<crate::wireexpr_resolve::OwnSpace<'_>>,
        &mut Self::Queryables,
    );
}

/// The table of the application's tables the session's own liveliness subscribers are kept in and
/// told a peer's tokens through, whose rows keep a `Sink` named by an `Id`. Without
/// `liveliness-subscriber` the build keeps none, and every bundle meets this with nothing.
pub trait LivelinessTables<Sink, Id> {
    /// The liveliness subscribers' table.
    #[cfg(feature = "liveliness-subscriber")]
    type LivelinessSubscribers: LocalLivelinessSubscribers<Sink = Sink, RowId = Id>;

    /// The liveliness subscribers, to read.
    #[cfg(feature = "liveliness-subscriber")]
    fn liveliness_subscribers(&self) -> &Self::LivelinessSubscribers;

    /// The liveliness subscribers to tell, with our own id space beside them where the tables
    /// hold the key expressions the session declared: a peer's token names its key through the
    /// one while the other is told, so the two are borrowed apart.
    #[cfg(feature = "liveliness-subscriber")]
    fn liveliness_mut(
        &mut self,
    ) -> (
        Option<crate::wireexpr_resolve::OwnSpace<'_>>,
        &mut Self::LivelinessSubscribers,
    );
}

/// An [`ObserverTables`] whose rows a session's arena lends at its open
/// ([`SlotObserverOf::lent`]).
pub trait LentTables: ObserverTables {
    /// What the tables are lent by: how many rows of each kind.
    type Rows;

    /// Tables of no entity, their rows lent from `arena` as `rows` states, their keys kept in
    /// `keys`, the session's key arena. Refused, the rows lent so far going back with the arena,
    /// when the arena has not the room or `rows` is past the build's bound.
    fn lend(arena: &mut Arena, keys: KeySpace, rows: Self::Rows) -> Result<Self, LendRefused>;
}

/// The application's tables of the storage policies: the subscriber table, the queryable registry
/// and the liveliness subscribers' table, each the record of its kind. `S` is a subscription's
/// sink, `Q` a queryable's, `L` a liveliness subscriber's.
pub struct RegistryTables<S, Q, L: LivelinessSampleSink, P: Storage = Profile> {
    /// The local subscriptions.
    pub subscribers: SubscriberTable<S, P>,
    /// The local queryables.
    #[cfg(feature = "query-queryable")]
    pub queryables: QueryableRegistry<Q, P>,
    #[cfg(not(feature = "query-queryable"))]
    queryables: core::marker::PhantomData<fn() -> Q>,
    /// The local liveliness subscribers.
    #[cfg(feature = "liveliness-subscriber")]
    pub liveliness_subscribers: LivelinessSubscriberTable<L, P>,
    #[cfg(not(feature = "liveliness-subscriber"))]
    liveliness_subscribers: core::marker::PhantomData<fn() -> L>,
}

/// How many rows each registry of [`RegistryTables`] of the lent policy is lent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RegistryRows {
    /// The subscriptions (`MAX_SUBSCRIPTIONS`).
    pub subscribers: usize,
    /// The queryables (`MAX_QUERYABLES`).
    pub queryables: usize,
    /// The liveliness subscribers (`MAX_LIVELINESS_SUBSCRIPTIONS`).
    pub liveliness_subscribers: usize,
}

/// The subscriptions are the subscriber table's: every read is its own.
impl<S, Q, L: LivelinessSampleSink, P: Storage> LocalSubscribers for RegistryTables<S, Q, L, P> {
    type Sink = S;
    type RowId = SubscriptionId;

    fn epoch(&self) -> u64 {
        LocalSubscribers::epoch(&self.subscribers)
    }

    fn next_subscription_id(&self) -> u64 {
        LocalSubscribers::next_subscription_id(&self.subscribers)
    }

    fn for_each_subscription(&self, f: &mut dyn FnMut(u64, &str, crate::locality::Locality)) {
        LocalSubscribers::for_each_subscription(&self.subscribers, f);
    }

    fn any_subscription(
        &self,
        f: &mut dyn FnMut(u64, &str, crate::locality::Locality) -> bool,
    ) -> bool {
        LocalSubscribers::any_subscription(&self.subscribers, f)
    }

    fn pattern_of(&self, id: u64) -> Option<&str> {
        LocalSubscribers::pattern_of(&self.subscribers, id)
    }

    fn next_entity_id(&self) -> Option<u32> {
        LocalSubscribers::next_entity_id(&self.subscribers)
    }

    fn consume_entity_id(&mut self) {
        LocalSubscribers::consume_entity_id(&mut self.subscribers);
    }

    fn has_local_matching(&self, key: &str) -> bool {
        LocalSubscribers::has_local_matching(&self.subscribers, key)
    }

    fn fire_matching<D: FnMut(SubscriptionId, crate::sink::RowAccess<'_, S>)>(
        &mut self,
        key: &str,
        local: bool,
        repeats_previous: bool,
        deliver: D,
    ) -> usize {
        LocalSubscribers::fire_matching(
            &mut self.subscribers,
            key,
            local,
            repeats_previous,
            deliver,
        )
    }

    fn deliver_from_peer<D: FnMut(SubscriptionId, crate::sink::RowAccess<'_, S>)>(
        &mut self,
        key: &str,
        class: Option<crate::key_gate::ClassId>,
        how: crate::pubsub::PeerDelivery,
        deliver: D,
    ) -> usize {
        LocalSubscribers::deliver_from_peer(&mut self.subscribers, key, class, how, deliver)
    }

    #[cfg(feature = "alloc")]
    fn end_plain_frame<X: SampleDelivery<S, SubscriptionId>>(&mut self, cx: &mut X) {
        LocalSubscribers::end_plain_frame(&mut self.subscribers, cx);
    }
}

impl<S, Q, L: LivelinessSampleSink, P: Storage> ObserverTables for RegistryTables<S, Q, L, P> {
    fn empty() -> Self {
        Self {
            subscribers: SubscriberTable::default(),
            #[cfg(feature = "query-queryable")]
            queryables: QueryableRegistry::default(),
            #[cfg(not(feature = "query-queryable"))]
            queryables: core::marker::PhantomData,
            #[cfg(feature = "liveliness-subscriber")]
            liveliness_subscribers: LivelinessSubscriberTable::default(),
            #[cfg(not(feature = "liveliness-subscriber"))]
            liveliness_subscribers: core::marker::PhantomData,
        }
    }

    fn hold_to(&mut self, limits: &crate::limits::SessionLimits) {
        self.subscribers.limit_to(limits.max_subscriptions_held());
        self.subscribers.limit_memo_to(limits.match_memo_slots());
        self.subscribers
            .limit_keys_to(limits.max_keyexpr_bytes_held());
        #[cfg(feature = "query-queryable")]
        {
            self.queryables.limit_to(limits.max_queryables_held());
            self.queryables
                .limit_keys_to(limits.max_keyexpr_bytes_held());
        }
        #[cfg(feature = "liveliness-subscriber")]
        {
            self.liveliness_subscribers
                .limit_to(limits.max_liveliness_subscriptions_held());
            self.liveliness_subscribers
                .limit_keys_to(limits.max_keyexpr_bytes_held());
        }
    }
}

impl<S, Q, L: LivelinessSampleSink, P: Storage> QueryTables<Q, crate::query::QueryableId>
    for RegistryTables<S, Q, L, P>
{
    #[cfg(feature = "query-queryable")]
    type Queryables = QueryableRegistry<Q, P>;

    #[cfg(feature = "query-queryable")]
    fn queryables(&self) -> &QueryableRegistry<Q, P> {
        &self.queryables
    }

    #[cfg(feature = "query-queryable")]
    fn queries_mut(
        &mut self,
    ) -> (
        Option<crate::wireexpr_resolve::OwnSpace<'_>>,
        &mut QueryableRegistry<Q, P>,
    ) {
        (
            LocalSubscribers::own_space(&self.subscribers),
            &mut self.queryables,
        )
    }
}

/// The liveliness subscribers' slots are named by their Interest's id.
impl<S, Q, L: LivelinessSampleSink, P: Storage> LivelinessTables<L, u64>
    for RegistryTables<S, Q, L, P>
{
    #[cfg(feature = "liveliness-subscriber")]
    type LivelinessSubscribers = LivelinessSubscriberTable<L, P>;

    #[cfg(feature = "liveliness-subscriber")]
    fn liveliness_subscribers(&self) -> &LivelinessSubscriberTable<L, P> {
        &self.liveliness_subscribers
    }

    #[cfg(feature = "liveliness-subscriber")]
    fn liveliness_mut(
        &mut self,
    ) -> (
        Option<crate::wireexpr_resolve::OwnSpace<'_>>,
        &mut LivelinessSubscriberTable<L, P>,
    ) {
        (
            LocalSubscribers::own_space(&self.subscribers),
            &mut self.liveliness_subscribers,
        )
    }
}

impl<S, Q, L: LivelinessSampleSink> LentTables for RegistryTables<S, Q, L, Lent> {
    type Rows = RegistryRows;

    fn lend(arena: &mut Arena, keys: KeySpace, rows: RegistryRows) -> Result<Self, LendRefused> {
        Ok(Self {
            subscribers: SubscriberTable::lent(arena, keys, rows.subscribers)?,
            #[cfg(feature = "query-queryable")]
            queryables: QueryableRegistry::lent(arena, keys, rows.queryables)?,
            #[cfg(not(feature = "query-queryable"))]
            queryables: core::marker::PhantomData,
            #[cfg(feature = "liveliness-subscriber")]
            liveliness_subscribers: LivelinessSubscriberTable::lent(
                arena,
                keys,
                rows.liveliness_subscribers,
            )?,
            #[cfg(not(feature = "liveliness-subscriber"))]
            liveliness_subscribers: core::marker::PhantomData,
        })
    }
}

/// The session's one table set keeps no quota of its own: each table's bound is the rows its
/// creator gave it ([`SessionTables::limit_to`], [`SessionTables::lent`]), and a key it cannot
/// keep is refused by the key arena. Of the session's limits it reads the match cache's size.
impl<F: RowCallbacks, P: Storage> ObserverTables for SessionTables<F, P> {
    fn empty() -> Self {
        Self::new()
    }

    fn hold_to(&mut self, limits: &crate::limits::SessionLimits) {
        self.limit_memo_to(limits.match_memo_slots());
    }
}

impl<F: RowCallbacks, P: Storage> QueryTables<F::Queryable, crate::session_tables::QueryableHandle>
    for SessionTables<F, P>
{
    #[cfg(feature = "query-queryable")]
    type Queryables = crate::session_tables::Queryables<F, P>;

    #[cfg(feature = "query-queryable")]
    fn queryables(&self) -> &Self::Queryables {
        SessionTables::queryables(self)
    }

    #[cfg(feature = "query-queryable")]
    fn queries_mut(
        &mut self,
    ) -> (
        Option<crate::wireexpr_resolve::OwnSpace<'_>>,
        &mut Self::Queryables,
    ) {
        let (own, queryables) = SessionTables::queries_mut(self);
        (Some(own), queryables)
    }
}

impl<F: RowCallbacks, P: Storage>
    LivelinessTables<F::LivelinessSubscriber, crate::session_tables::LivelinessSubscriberHandle>
    for SessionTables<F, P>
{
    #[cfg(feature = "liveliness-subscriber")]
    type LivelinessSubscribers = crate::session_tables::LivelinessSubscribers<F, P>;

    #[cfg(feature = "liveliness-subscriber")]
    fn liveliness_subscribers(&self) -> &Self::LivelinessSubscribers {
        SessionTables::liveliness_subscribers(self)
    }

    #[cfg(feature = "liveliness-subscriber")]
    fn liveliness_mut(
        &mut self,
    ) -> (
        Option<crate::wireexpr_resolve::OwnSpace<'_>>,
        &mut Self::LivelinessSubscribers,
    ) {
        let (own, subscribers) = SessionTables::liveliness_mut(self);
        (Some(own), subscribers)
    }
}

impl<F: RowCallbacks> LentTables for SessionTables<F, Lent> {
    type Rows = TableRows;

    fn lend(arena: &mut Arena, keys: KeySpace, rows: TableRows) -> Result<Self, LendRefused> {
        Self::lent(arena, keys, &rows)
    }
}

/// The observer with no registration of any kind.
pub struct NoSinks;

impl ObserverSinks for NoSinks {
    type Subscriber = NoSink;
    type SubscriberId = SubscriptionId;
    type QueryableId = crate::query::QueryableId;
    type LivelinessSubscriberId = u64;
    type Delivery = ();
    type Tables<P: Storage> =
        RegistryTables<Self::Subscriber, Self::Queryable, Self::LivelinessSubscriber, P>;
    type Queryable = NoSink;
    type LivelinessSubscriber = NoSink;
    type Declared = NoSink;
    type Undeclared = NoSink;
}

/// The sinks an observer is typed with when nothing else is named: the heap profile's
/// where there is a heap, none where there is not.
#[cfg(feature = "alloc")]
pub type DefaultSinks = HeapSinks;
/// See the heap form.
#[cfg(not(feature = "alloc"))]
pub type DefaultSinks = NoSinks;

/// The observer of the heap profile, as it has always been named.
#[cfg(feature = "alloc")]
pub type SlotObserver = SlotObserverOf<HeapSinks>;

impl<K: ObserverSinks> Default for SlotObserverOf<K> {
    fn default() -> Self {
        Self::new()
    }
}

/// Where a cell stands: nothing in it, an observer nobody holds, or one a guard holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CellState {
    Empty,
    Idle,
    Held,
}

/// A second [`ObserverCell::init_with`] on a cell that already holds its observer.
#[derive(Debug, PartialEq, Eq)]
pub struct AlreadyInitialised;

/// The process-wide observer's place, for a `static`: empty until [`Self::init_with`]
/// builds the observer in it, once, and lent through [`Self::borrow_mut`] after that,
/// one holder at a time (the rule `RefCell` keeps, with the same panic on a second).
///
/// It exists for the observer's size. A `RefCell<SlotObserverOf>` can only be filled by
/// value, and the value passes through every call that hands it on: on a 32 KB stack the
/// four copies the install of the Zephyr node made came to 69 KB of the node's main
/// frame, and the node's own loop ran below its stack. Here the observer is written
/// field by field into the cell where it stays, and the callback that registers on it
/// holds a reference to it, never the value.
pub struct ObserverCell<K: ObserverSinks> {
    state: core::cell::Cell<CellState>,
    value: core::cell::UnsafeCell<MaybeUninit<SlotObserverOf<K>>>,
}

impl<K: ObserverSinks> ObserverCell<K> {
    /// An empty cell, for a `static`.
    pub const fn new() -> Self {
        Self {
            state: core::cell::Cell::new(CellState::Empty),
            value: core::cell::UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Build the observer in the cell (nothing registered) and hand it to `register`,
    /// which holds it while it runs. The cell is `Held` meanwhile, so a `borrow_mut`
    /// from inside `register` is the panic it would be on a `RefCell`.
    ///
    /// # Errors
    ///
    /// [`AlreadyInitialised`] if the cell holds its observer already, which is then
    /// left as it was.
    pub fn init_with<R>(
        &self,
        register: impl FnOnce(&mut SlotObserverOf<K>) -> R,
    ) -> Result<R, AlreadyInitialised> {
        if self.state.get() != CellState::Empty {
            return Err(AlreadyInitialised);
        }
        self.state.set(CellState::Held);
        let at = self.value.get().cast::<SlotObserverOf<K>>();
        // SAFETY: the cell is empty, so nothing refers into it and nothing in it needs
        // dropping; `at` is the cell's own storage, aligned for the observer.
        unsafe { SlotObserverOf::init_in_place(at) };
        // SAFETY: just written; the cell is `Held`, so this is the only reference.
        let result = register(unsafe { &mut *at });
        self.state.set(CellState::Idle);
        Ok(result)
    }

    /// Whether the observer has been built.
    pub fn is_initialised(&self) -> bool {
        self.state.get() != CellState::Empty
    }

    /// Lend the observer, or `None` for a cell with no observer yet or one a guard
    /// holds.
    pub fn try_borrow_mut(&self) -> Option<ObserverGuard<'_, K>> {
        if self.state.get() != CellState::Idle {
            return None;
        }
        self.state.set(CellState::Held);
        Some(ObserverGuard { cell: self })
    }

    /// Lend the observer.
    ///
    /// # Panics
    ///
    /// On a cell with no observer yet and on one a guard holds: a dispatch reached
    /// from inside a dispatch, which the profile's one cooperative task never does.
    pub fn borrow_mut(&self) -> ObserverGuard<'_, K> {
        match self.state.get() {
            CellState::Idle => {}
            CellState::Empty => panic!("the observer cell was borrowed before it was built"),
            CellState::Held => panic!("the observer cell is already borrowed"),
        }
        self.state.set(CellState::Held);
        ObserverGuard { cell: self }
    }
}

impl<K: ObserverSinks> Default for ObserverCell<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: ObserverSinks> Drop for ObserverCell<K> {
    fn drop(&mut self) {
        if self.state.get() != CellState::Empty {
            // SAFETY: a cell that is not empty holds an observer `init_with` built, and
            // `&mut self` means no guard is out.
            unsafe { self.value.get_mut().assume_init_drop() };
        }
    }
}

/// The observer, lent by an [`ObserverCell`] until the guard drops.
pub struct ObserverGuard<'a, K: ObserverSinks> {
    cell: &'a ObserverCell<K>,
}

impl<K: ObserverSinks> core::ops::Deref for ObserverGuard<'_, K> {
    type Target = SlotObserverOf<K>;

    fn deref(&self) -> &SlotObserverOf<K> {
        // SAFETY: a guard exists only for a built observer, and holds the cell `Held`.
        unsafe { (*self.cell.value.get()).assume_init_ref() }
    }
}

impl<K: ObserverSinks> core::ops::DerefMut for ObserverGuard<'_, K> {
    fn deref_mut(&mut self) -> &mut SlotObserverOf<K> {
        // SAFETY: as in `deref`, and the cell is `Held`, so this is the one reference.
        unsafe { (*self.cell.value.get()).assume_init_mut() }
    }
}

impl<K: ObserverSinks> Drop for ObserverGuard<'_, K> {
    fn drop(&mut self) {
        self.cell.state.set(CellState::Idle);
    }
}

impl<K: ObserverSinks> SlotObserverOf<K> {
    /// An observer with nothing registered.
    ///
    /// By value, so the whole observer (about 16 KB in the Zephyr node's image) is one
    /// more value on the caller's stack. A node whose stack is a few tens of KB places
    /// it with [`ObserverCell::init_with`] instead, which builds it where it stays.
    pub fn new() -> Self {
        let mut observer = MaybeUninit::<Self>::uninit();
        // SAFETY: `init_in_place` writes every field, which `every_field_is_written`
        // below holds to the field list at compile time.
        unsafe {
            Self::init_in_place(observer.as_mut_ptr());
            observer.assume_init()
        }
    }

    /// [`Self::new`], each registry held to the limits `limits` states ([`Self::limit_to`]).
    pub fn with_limits(limits: &crate::limits::SessionLimits) -> Self {
        let mut observer = Self::new();
        observer.limit_to(limits);
        observer
    }

    /// Write an observer with nothing registered at `at`, one registry at a time, so the
    /// observer is never a value of its own on any stack: the largest value this holds
    /// is one registry. The single list of fields, which [`Self::new`] shares.
    ///
    /// # Safety
    ///
    /// `at` must be aligned and valid for a write of `Self`. What it held is not
    /// dropped.
    // Not inlined: its temporaries (one registry each) would otherwise be part of the
    // frame of whoever calls it, for as long as that frame lives. The Zephyr node's
    // `run` is the node's loop.
    #[inline(never)]
    pub unsafe fn init_in_place(at: *mut Self) {
        use core::ptr::{self, addr_of_mut};
        // Each gated statement opens with the path `ptr::write(`, not with the
        // `addr_of_mut!` macro: the feature-public-surface census reads a gated
        // line that starts with a macro call as a macro that may expand to a public
        // item, and a statement here is not one.
        // SAFETY: the caller's; each field is written once through a pointer to it.
        unsafe {
            ptr::write(addr_of_mut!((*at).tables), ObserverTables::empty());
            #[cfg(feature = "switchboard")]
            ptr::write(addr_of_mut!((*at).switchboard), SwitchboardRegistry::new());
            #[cfg(feature = "declare-subscriber")]
            ptr::write(
                addr_of_mut!((*at).remote_subscribers),
                RemoteSubscriberTable::with_sink_backing(),
            );
            #[cfg(feature = "declare-queryable")]
            ptr::write(
                addr_of_mut!((*at).remote_queryables),
                RemoteQueryableTable::with_sink_backing(),
            );
            #[cfg(not(any(feature = "declare-subscriber", feature = "declare-queryable")))]
            ptr::write(addr_of_mut!((*at).matching), core::marker::PhantomData);
            #[cfg(feature = "liveliness-token")]
            ptr::write(addr_of_mut!((*at).liveliness), LivelinessRegistry::new());
            #[cfg(feature = "liveliness-token")]
            ptr::write(addr_of_mut!((*at).local_tokens), LocalTokenRegistry::new());
        }
    }

    /// A field added to [`SlotObserverOf`] and not written by `init_in_place` would be
    /// read uninitialised. This destructures the struct with no `..`, so adding a field
    /// without naming it here (and so without writing it above) does not compile.
    #[allow(dead_code)]
    fn every_field_is_written(observer: Self) {
        let Self {
            tables: _,
            #[cfg(feature = "switchboard")]
                switchboard: _,
            #[cfg(feature = "declare-subscriber")]
                remote_subscribers: _,
            #[cfg(feature = "declare-queryable")]
                remote_queryables: _,
            #[cfg(not(any(feature = "declare-subscriber", feature = "declare-queryable")))]
                matching: _,
            #[cfg(feature = "liveliness-token")]
                liveliness: _,
            #[cfg(feature = "liveliness-token")]
                local_tokens: _,
        } = observer;
    }
}

impl<K: ObserverSinks, M: MatchingReport> SlotObserverOf<K, Lent, M> {
    /// An observer with nothing registered whose application tables are lent from `arena`, as
    /// many rows each as `rows` states (the subscriptions' table reads its own of them,
    /// [`LentTables::lend`]), their keys kept in `keys`, the session's key arena, and
    /// held to `limits` as [`SlotObserverOf::with_limits`] holds one. The declaration watchers'
    /// lists are lent too, as many rows each as `limits` admits watchers
    /// ([`Self::decl_watcher_rows`]). Refused, the rows lent so far going back with the arena,
    /// when the arena has not the room, or when `limits` admits more watchers than the build.
    pub fn lent(
        arena: &mut Arena,
        keys: KeySpace,
        rows: ObserverRows<<K::Tables<Lent> as LentTables>::Rows>,
        limits: &crate::limits::SessionLimits,
    ) -> Result<Self, LendRefused>
    where
        K::Tables<Lent>: LentTables,
    {
        #[cfg(any(
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "liveliness-token"
        ))]
        let watchers = Self::decl_watcher_rows(limits)?;
        let mut observer = Self {
            tables: LentTables::lend(arena, keys, rows.tables)?,
            #[cfg(feature = "switchboard")]
            switchboard: SwitchboardRegistry::new(),
            #[cfg(feature = "declare-subscriber")]
            remote_subscribers: RemoteSubscriberTable::lent(arena, watchers)?,
            #[cfg(feature = "declare-queryable")]
            remote_queryables: RemoteQueryableTable::lent(arena, watchers)?,
            #[cfg(not(any(feature = "declare-subscriber", feature = "declare-queryable")))]
            matching: core::marker::PhantomData,
            #[cfg(feature = "liveliness-token")]
            liveliness: LivelinessRegistry::lent(arena, watchers)?,
            #[cfg(feature = "liveliness-token")]
            local_tokens: LocalTokenRegistry::lent(arena, keys, rows.local_tokens)?,
        };
        observer.limit_to(limits);
        Ok(observer)
    }

    /// How many rows [`Self::lent`] lends each declaration watcher list under `limits`: the
    /// session's `MAX_DECL_OBSERVERS`, under the build's, as the arena that holds them counts it.
    /// Refused past the build's value. A build that states no value of it lends its lists no row,
    /// as their type holds none.
    pub fn decl_watcher_rows(limits: &crate::limits::SessionLimits) -> Result<usize, LendRefused> {
        Self::watcher_rows_under::<{ caps::MAX_DECL_OBSERVERS }>(limits.max_decl_observers())
    }

    /// The rows `value` lends a declaration watcher list whose type holds `CEILING`, the build's
    /// value of the limit: refused past it, none where the build states no value.
    fn watcher_rows_under<const CEILING: usize>(value: Quota) -> Result<usize, LendRefused> {
        match value.lent_under(Quota::at_most(CEILING)) {
            Ok(rows) => Ok(rows),
            Err(UnlentRows::OverCeiling { value, ceiling }) => Err(LendRefused::OverCeiling {
                rows: value,
                ceiling,
            }),
            Err(UnlentRows::NoCeiling) => Ok(0),
        }
    }

    /// The bytes of an arena the declaration watchers' lists of [`Self::lent`] take, `rows` rows
    /// each: two lists for each plane of the build that has watchers, each a span of its own.
    /// `None` past the address space.
    pub const fn decl_watcher_bytes(rows: usize) -> Option<usize> {
        let bytes = Some(0);
        #[cfg(feature = "declare-subscriber")]
        let bytes = sum_of(
            bytes,
            RemoteSubscriberTable::<K::Declared, K::Undeclared, Lent>::arena_bytes(rows),
        );
        #[cfg(feature = "declare-queryable")]
        let bytes = sum_of(
            bytes,
            RemoteQueryableTable::<K::Declared, K::Undeclared, Lent>::arena_bytes(rows),
        );
        #[cfg(feature = "liveliness-token")]
        let bytes = sum_of(
            bytes,
            LivelinessRegistry::<
                crate::decl_sink::BoxedDeclSink,
                crate::decl_sink::BoxedUndeclSink,
                Lent,
            >::arena_bytes(rows),
        );
        let _ = rows;
        bytes
    }
}

/// `a + b`, `None` when either is or the sum is past the address space.
#[cfg(any(
    feature = "declare-subscriber",
    feature = "declare-queryable",
    feature = "liveliness-token"
))]
const fn sum_of(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (Some(a), Some(b)) => a.checked_add(b),
        _ => None,
    }
}

impl<K: ObserverSinks, P: Storage, M: MatchingReport> SlotObserverOf<K, P, M> {
    /// Hold each registry to the limits `limits` states: what the creator of the session resolved
    /// for it. A table reads its bound here and never from the build. In place, as the observer of a
    /// node is built where it stays ([`ObserverCell::init_with`]) and is never a value; what each
    /// registry holds is kept, and what it is asked for next is held to the new quota, so a node
    /// states its limits before it registers. The tables of each peer, which this observer does not
    /// hold, are held to the same limits by [`PeerTables::limit_to`].
    pub fn limit_to(&mut self, limits: &crate::limits::SessionLimits) {
        self.tables.hold_to(limits);
        // The longest key every table the application registers in stores; the tables each
        // peer fills are held to it by `PeerTables::limit_to`.
        #[cfg(feature = "liveliness-token")]
        self.local_tokens
            .limit_keys_to(limits.max_keyexpr_bytes_held());
        #[cfg(feature = "declare-subscriber")]
        self.remote_subscribers
            .limit_observers_to(limits.max_decl_observers_held());
        #[cfg(feature = "declare-queryable")]
        self.remote_queryables
            .limit_observers_to(limits.max_decl_observers_held());
        #[cfg(feature = "liveliness-token")]
        self.liveliness
            .limit_observers_to(limits.max_decl_observers_held());
        #[cfg(feature = "liveliness-token")]
        self.local_tokens.limit_to(limits.max_local_tokens_held());
        #[cfg(feature = "liveliness-token")]
        self.local_tokens
            .limit_interest_replies_to(limits.max_pending_declares_held());
    }

    /// Fan an [`IterationEvent`] of one session into every registry, against that
    /// session's `peers`. The subscriber side runs first so its alias absorb
    /// binds a `DeclKexpr` BEFORE the planes that resolve keyexprs through it.
    ///
    /// What a queryable stages goes to `peers.replies` / `peers.finals`, and a
    /// `Request` whose `Final` the table cannot hold never reaches one
    /// ([`crate::reply_stage`]). `requesters` is the session's own.
    // Not inlined, for the stack: each plane's fan leaves its temporaries in the frame it runs
    // in, and inlined into the session's `on_event` they are all there for the length of the
    // application layer's call.
    #[inline(never)]
    pub fn dispatch_event<Q: RequesterTables, T: Storage>(
        &mut self,
        cx: &mut K::Delivery,
        peers: &mut PeerTables<T>,
        requesters: &mut Q,
        event: IterationEvent<'_, '_>,
    ) {
        self.dispatch_event_among(cx, peers, requesters, event, &NoOtherPeers);
    }

    /// [`Self::dispatch_event`] for a session that holds other faces: `others` is what their
    /// peers declare, counted by the matching verdicts beside this face's own.
    // Each plane's fan below is a function of its own and not inlined here: inlined, the
    // temporaries of every plane (the views and records each decodes) are laid out in this one
    // frame, which the compiler does not overlap reliably, and the frame is held on every event
    // however few planes the event concerns. Out of line, the stack under this call is this frame
    // and the one plane running.
    #[inline(never)]
    pub fn dispatch_event_among<Q: RequesterTables, O: OtherPeers, T: Storage>(
        &mut self,
        cx: &mut K::Delivery,
        peers: &mut PeerTables<T>,
        requesters: &mut Q,
        event: IterationEvent<'_, '_>,
        others: &O,
    ) {
        peers
            .subscribers
            .dispatch_iteration_event(&mut self.tables, cx, event);
        // A peer's query is resolved through both id spaces while the queryables are asked, so
        // the tables lend the two apart.
        #[cfg(feature = "query-queryable")]
        {
            let (own, queryables) = self.tables.queries_mut();
            peers.queries.dispatch_iteration_event(
                queryables,
                cx,
                event,
                peers.subscribers.mapping_spaces_over(own),
                &mut peers.replies,
                &mut peers.finals,
            );
        }
        // A peer's token is resolved through both id spaces while the liveliness subscribers are
        // told, so the tables lend the two apart. A `Declare(DeclToken)` whose outer
        // `interest_id` names a pending liveliness GET belongs to that GET and to no subscriber.
        #[cfg(feature = "liveliness-subscriber")]
        {
            #[cfg(feature = "liveliness-get")]
            let claimed = |id: u64| requesters.claims(id);
            #[cfg(not(feature = "liveliness-get"))]
            let claimed = |_: u64| false;
            let (own, subscribers) = self.tables.liveliness_mut();
            peers.tokens.dispatch_iteration_event_unclaimed(
                subscribers,
                cx,
                event,
                peers.subscribers.mapping_spaces_over(own),
                &claimed,
            );
        }
        // The two id spaces this session resolves through, as the subscriber side
        // just refreshed them (R311y739): an `M=0` alias names an id WE declared
        // and is answered out of the right table on every plane.
        #[cfg(any(
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "liveliness-token",
            feature = "liveliness-get",
            feature = "codec-response",
            feature = "codec-response-final",
        ))]
        let peer_table = peers
            .subscribers
            .mapping_spaces_over(self.tables.own_space());
        // R311y788 -- the remote-subscriber fan carries the session-local half of
        // the matching verdict, read from the sibling subscriber table.
        #[cfg(feature = "declare-subscriber")]
        {
            let subscribers = &self.tables;
            self.remote_subscribers.dispatch_iteration_event_with_local(
                &mut peers.remote_subscribers,
                event,
                peer_table,
                &|c| {
                    (c.locality.allows_local()
                        && subscribers.has_local_matching(c.keyexpr.as_str()))
                        || others.subscribes(c)
                },
            );
        }
        #[cfg(all(feature = "declare-queryable", feature = "query-queryable"))]
        {
            let queryables = self.tables.queryables();
            self.remote_queryables.dispatch_iteration_event_with_local(
                &mut peers.remote_queryables,
                event,
                peer_table,
                &|c| {
                    (c.locality.allows_local()
                        && queryables.has_local_queryable(c.keyexpr.as_str(), c.complete_required))
                        || others.answers(c)
                },
            );
        }
        #[cfg(all(feature = "declare-queryable", not(feature = "query-queryable")))]
        self.remote_queryables.dispatch_iteration_event_with_local(
            &mut peers.remote_queryables,
            event,
            peer_table,
            &|c| others.answers(c),
        );
        // A `Declare(DeclToken)` whose outer `interest_id` names a pending
        // liveliness GET belongs to that GET and to no observer plane (zenoh
        // answers the query and returns first): the claim is per id.
        #[cfg(all(feature = "liveliness-token", feature = "liveliness-get"))]
        self.liveliness
            .dispatch_iteration_event_unclaimed(event, peer_table, &|id| requesters.claims(id));
        #[cfg(all(feature = "liveliness-token", not(feature = "liveliness-get")))]
        self.liveliness.dispatch_iteration_event(event, peer_table);
        // R283 -- stage an interest-response for each inbound non-final liveliness
        // Interest, whole chains or none, into THIS session's staging. A build that answers no
        // peer's Interest (`interest-answer` off) stages none, as the subscriber plane does
        // (`SubscriberPeer`'s `ignore_subscriber_interest`).
        #[cfg(all(feature = "liveliness-token", feature = "interest-answer"))]
        {
            let refused = self.local_tokens.dispatch_iteration_event(
                event,
                peer_table,
                &mut peers.pending_declares,
            );
            peers.token_interest_chains_refused = peers
                .token_interest_chains_refused
                .saturating_add(u32::try_from(refused).unwrap_or(u32::MAX));
        }
        #[cfg(any(
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "liveliness-get"
        ))]
        requesters.dispatch_iteration_event(event, peer_table);
        // Consumed only by the arms above, which a build with none of them lacks.
        #[cfg(not(any(
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "liveliness-get"
        )))]
        let _ = &requesters;
        let _ = (&peers, event, others);
    }

    /// Drain what the last [`Self::dispatch_event`] staged for this session
    /// through its send path: the replies, the answers to its interests, the
    /// terminated-get prunes, and last the `Final`s, so every Reply for a request
    /// precedes the `Final` that ends it.
    pub fn flush_pending<S, Q: RequesterTables, T: Storage>(
        &mut self,
        peers: &mut PeerTables<T>,
        requesters: &mut Q,
        actions: &S,
    ) where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        if peers.finals.is_empty() && !stages_replies(peers, requesters) {
            return;
        }
        // One burst: the replies and the `Final` that ends them leave as one frame, where each
        // would be a datagram of its own (see `ResponseSink::begin_burst`).
        let burst = actions.begin_burst();
        self.drain_query_replies(peers, actions);
        #[cfg(all(
            feature = "interest-answer",
            any(feature = "declare-subscriber", feature = "liveliness-token")
        ))]
        self.drain_declare_replies(peers, actions);
        self.drain_get_prunes(requesters, actions);
        self.drain_query_finals(peers, actions);
        actions.end_burst(burst);
    }

    /// [`Self::flush_pending`] without the `Final`s: the replies, the answers to the
    /// session's interests and the terminated-get prunes leave through `actions`, and
    /// what is owed in `peers.finals` stays staged. For a host that holds each `Final`
    /// behind the queries a callback may still answer, takes the owed ones with
    /// [`FinalStage::take_owed`](crate::reply_stage::FinalStage::take_owed), which leaves
    /// `peers.finals` its quota, and sends each when the last of them has, so no `Final`
    /// overtakes a reply. The replies it drains are one burst, as
    /// `flush_pending`'s are.
    pub fn flush_pending_replies<S, Q: RequesterTables, T: Storage>(
        &mut self,
        peers: &mut PeerTables<T>,
        requesters: &mut Q,
        actions: &S,
    ) where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        if !stages_replies(peers, requesters) {
            return;
        }
        let burst = actions.begin_burst();
        self.drain_query_replies(peers, actions);
        #[cfg(all(
            feature = "interest-answer",
            any(feature = "declare-subscriber", feature = "liveliness-token")
        ))]
        self.drain_declare_replies(peers, actions);
        self.drain_get_prunes(requesters, actions);
        actions.end_burst(burst);
    }

    /// Fan and drain in one call: [`Self::dispatch_event`] then
    /// [`Self::flush_pending`], the shape a session's `on_event` takes.
    pub fn dispatch<S, Q: RequesterTables, T: Storage>(
        &mut self,
        cx: &mut K::Delivery,
        peers: &mut PeerTables<T>,
        requesters: &mut Q,
        event: IterationEvent<'_, '_>,
        actions: &S,
    ) where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        self.dispatch_event(cx, peers, requesters, event);
        self.flush_pending(peers, requesters, actions);
    }

    /// Fan an event into the statechart switchboard against the session's alias
    /// table; see [`crate::observer::ApplicationLayerObserver::dispatch_switchboard`].
    #[cfg(feature = "switchboard")]
    pub fn dispatch_switchboard<T: Storage>(
        &self,
        peers: &PeerTables<T>,
        event: IterationEvent<'_, '_>,
        injector: &mut dyn EventInjector,
    ) -> usize {
        self.switchboard.dispatch_iteration_event(
            event,
            peers
                .subscribers
                .mapping_spaces_over(self.tables.own_space()),
            injector,
        )
    }

    /// The link of this session was lost: every token its peer had declared is
    /// flushed, delivering a `Delete` to each matching subscriber. Returns the
    /// count. A no-op without `liveliness-subscriber`.
    pub fn flush_liveliness_on_link_loss<T: Storage>(
        &mut self,
        cx: &mut K::Delivery,
        peers: &mut PeerTables<T>,
    ) -> usize {
        #[cfg(feature = "liveliness-subscriber")]
        {
            let (_, subscribers) = self.tables.liveliness_mut();
            peers
                .tokens
                .flush_on_link_loss_while(subscribers, cx, &mut || true)
                .0
        }
        #[cfg(not(feature = "liveliness-subscriber"))]
        {
            let _ = (cx, peers);
            0
        }
    }

    /// [`Self::flush_liveliness_on_link_loss`] a token at a time while `room` says the next
    /// token's `Delete` can be taken: the tokens left stay with `peers` for a later call. Whether
    /// none is left.
    pub fn flush_liveliness_on_link_loss_while<T: Storage>(
        &mut self,
        cx: &mut K::Delivery,
        peers: &mut PeerTables<T>,
        room: &mut dyn FnMut() -> bool,
    ) -> bool {
        self.flush_tokens_on_link_loss_while(cx, &mut peers.tokens, room)
    }

    /// [`Self::flush_liveliness_on_link_loss_while`] of the tokens of a peer whose tables were let
    /// go of, held apart from them (`PeerTokens::split_off`): what a face that went still owes.
    /// Whether none is left.
    pub fn flush_tokens_on_link_loss_while<T: Storage>(
        &mut self,
        cx: &mut K::Delivery,
        tokens: &mut crate::declare::liveliness_subscriber::PeerTokens<T>,
        room: &mut dyn FnMut() -> bool,
    ) -> bool {
        #[cfg(feature = "liveliness-subscriber")]
        {
            let (_, subscribers) = self.tables.liveliness_mut();
            tokens.flush_on_link_loss_while(subscribers, cx, room).1
        }
        #[cfg(not(feature = "liveliness-subscriber"))]
        {
            let _ = (cx, tokens, room);
            true
        }
    }

    /// The link of this session was lost: every subscriber and queryable its peer
    /// had declared is gone, and the matching watches are re-evaluated against what
    /// remains. Returns the number of declarations dropped.
    pub fn flush_declarations_on_link_loss<T: Storage>(
        &mut self,
        peers: &mut PeerTables<T>,
    ) -> usize {
        self.flush_declarations_on_link_loss_among(peers, &NoOtherPeers)
    }

    /// [`Self::flush_declarations_on_link_loss`] for a session that holds other faces: what their
    /// peers declare is counted by the matching verdicts the flush re-evaluates, so a listener
    /// another face's peer still satisfies keeps matching.
    pub fn flush_declarations_on_link_loss_among<O: OtherPeers, T: Storage>(
        &mut self,
        peers: &mut PeerTables<T>,
        others: &O,
    ) -> usize {
        #[allow(unused_mut)]
        let mut dropped = 0usize;
        #[cfg(all(feature = "declare-subscriber", feature = "codec-declare"))]
        {
            let subscribers = &self.tables;
            dropped += self.remote_subscribers.flush_declarations_on_link_loss(
                &mut peers.remote_subscribers,
                &|c| {
                    (c.locality.allows_local()
                        && subscribers.has_local_matching(c.keyexpr.as_str()))
                        || others.subscribes(c)
                },
            );
        }
        #[cfg(all(
            feature = "declare-queryable",
            feature = "query-queryable",
            feature = "codec-declare"
        ))]
        {
            let queryables = self.tables.queryables();
            dropped += self.remote_queryables.flush_declarations_on_link_loss(
                &mut peers.remote_queryables,
                &|c| {
                    (c.locality.allows_local()
                        && queryables.has_local_queryable(c.keyexpr.as_str(), c.complete_required))
                        || others.answers(c)
                },
            );
        }
        #[cfg(all(
            feature = "declare-queryable",
            not(feature = "query-queryable"),
            feature = "codec-declare"
        ))]
        {
            dropped += self
                .remote_queryables
                .flush_declarations_on_link_loss(&mut peers.remote_queryables, &|c| {
                    others.answers(c)
                });
        }
        let _ = (&peers, others);
        dropped
    }

    /// The staged replies, through `send_reply_parts`: each is read where it lies in
    /// the stage and handed to the sink as borrowed parts, so a sink with no allocator
    /// writes the `Response` from the row and builds no record, and a sink with a heap
    /// builds the owned one it always did. A reply whose bounded field overflows cannot
    /// be wire-encoded and is skipped, as on the AP.
    #[inline(never)]
    pub(crate) fn drain_query_replies<S: ResponseSink, T: Storage>(
        &mut self,
        peers: &mut PeerTables<T>,
        sink: &S,
    ) {
        #[cfg(feature = "query-queryable")]
        peers
            .replies
            .drain_parts(|parts| sink.send_reply_parts(parts));
        #[cfg(not(feature = "query-queryable"))]
        let _ = (peers, sink);
    }

    /// The `Final`s owed, through `send_response_final`.
    #[inline(never)]
    pub(crate) fn drain_query_finals<S: ResponseSink, T: Storage>(
        &mut self,
        peers: &mut PeerTables<T>,
        sink: &S,
    ) {
        #[cfg(all(feature = "query-queryable", feature = "codec-response-final"))]
        for (rid, qos) in peers.finals.drain_owed() {
            sink.send_response_final(rid, qos);
        }
        #[cfg(all(feature = "query-queryable", not(feature = "codec-response-final")))]
        peers.finals.drain_owed().for_each(drop);
        #[cfg(not(all(feature = "query-queryable", feature = "codec-response-final")))]
        let _ = (peers, sink);
    }

    /// The answers to the peer's interests: the subscriber interest chains first,
    /// then the liveliness ones, each batch's items before its terminating `Final`. A build that
    /// answers no Interest stages none and has no drain of them.
    #[cfg(all(
        feature = "interest-answer",
        any(feature = "declare-subscriber", feature = "liveliness-token")
    ))]
    #[inline(never)]
    pub(crate) fn drain_declare_replies<S: DeclareReplySink, T: Storage>(
        &mut self,
        peers: &mut PeerTables<T>,
        sink: &S,
    ) {
        #[cfg(feature = "declare-subscriber")]
        for item in peers.subscribers.take_staged_sub_interest_replies() {
            match &item {
                crate::pubsub::SubInterestReply::Final { interest_id } => {
                    sink.send_declare_final_reply(*interest_id)
                }
                crate::pubsub::SubInterestReply::Aggregate { interest_id }
                | crate::pubsub::SubInterestReply::Concrete { interest_id, .. } => {
                    let interest_id = *interest_id;
                    let mut announced_aggregate = false;
                    if let Some((subscriber_id, keyexpr)) =
                        peers.subscribers.sub_interest_reply(&self.tables, &item)
                    {
                        sink.send_declare_subscriber_reply(subscriber_id, keyexpr, interest_id);
                        announced_aggregate =
                            matches!(item, crate::pubsub::SubInterestReply::Aggregate { .. });
                    }
                    // Recorded AFTER the emit and outside the borrow above, and
                    // only when the reply actually left (R2292).
                    #[cfg(feature = "declare-undeclare")]
                    if announced_aggregate {
                        peers.subscribers.mark_aggregate_announced(interest_id);
                    }
                    let _ = announced_aggregate;
                }
                #[cfg(feature = "declare-undeclare")]
                crate::pubsub::SubInterestReply::AggregateRetract { interest_id } => {
                    if let Some(decl_id) = peers
                        .subscribers
                        .take_aggregate_retract(&self.tables, *interest_id)
                    {
                        sink.send_undeclare_subscriber_reply(decl_id);
                    }
                }
            }
        }
        #[cfg(feature = "liveliness-token")]
        // Drained in place: the rows are the ones the peer's tables were made with, which a table
        // moved out would take with it.
        while !peers.pending_declares.is_empty() {
            let item = peers.pending_declares.remove(0);
            match item {
                crate::declare::local_token::DeclResponseItem::Token {
                    token_id,
                    interest_id,
                } => {
                    // A token unregistered between stage and drain is skipped;
                    // its chain's Final still terminates.
                    if let Some(keyexpr) = self.local_tokens.keyexpr_for(token_id) {
                        sink.send_declare_token_reply(token_id, keyexpr, interest_id);
                    }
                }
                crate::declare::local_token::DeclResponseItem::Final { interest_id } => {
                    sink.send_declare_final_reply(interest_id)
                }
            }
        }
    }

    /// The liveliness gets that terminated, through `prune_liveliness_get_interest`.
    #[inline(never)]
    pub(crate) fn drain_get_prunes<S: LivelinessGetPrune, Q: RequesterTables>(
        &mut self,
        requesters: &mut Q,
        sink: &S,
    ) {
        #[cfg(feature = "liveliness-get")]
        requesters.drain_prunes(sink);
        #[cfg(not(feature = "liveliness-get"))]
        let _ = (requesters, sink);
    }
}

/// Whether a drain of what the dispatches staged has anything to send
/// ([`SlotObserverOf::flush_pending_replies`]): a reply a queryable staged, an answer to one of
/// the peer's interests, a terminated get's prune. Asked first, so a drain with nothing to send
/// opens no burst: closing one takes the lock of every conduit to send what it gathered, which
/// every received Push, drained after as every record is, would pay each time.
fn stages_replies<Q: RequesterTables, T: Storage>(peers: &PeerTables<T>, requesters: &Q) -> bool {
    #[allow(unused_mut)]
    let mut staged = false;
    #[cfg(feature = "query-queryable")]
    {
        staged |= !peers.replies.is_empty();
    }
    #[cfg(all(feature = "declare-subscriber", feature = "interest-answer"))]
    {
        staged |= peers.subscribers.has_staged_sub_interest_replies();
    }
    #[cfg(all(feature = "liveliness-token", feature = "interest-answer"))]
    {
        staged |= !peers.pending_declares.is_empty();
    }
    #[cfg(feature = "liveliness-get")]
    {
        staged |= requesters.has_finalized();
    }
    let _ = (peers, requesters);
    staged
}

#[cfg(all(
    test,
    feature = "codec-push",
    feature = "codec-declare",
    feature = "pubsub-put",
    feature = "declare-subscriber"
))]
mod tests {
    //! The own-space witness of the slot fan (R311y740, carry N37): this fan is
    //! the edge every plane of a session reaches its two id spaces through, so a
    //! fan that handed over the peer table alone would type-check and silently
    //! restore the wrong-space read on every plane at once. The per-registry
    //! witnesses cannot see the edge; these drive it.
    use super::*;
    use crate::decl_sink::{BoxedDeclSink, DeclView};
    use crate::driver_loop::DriverLoopOutcome;
    use crate::locality::Locality;
    use crate::network_message::NetworkMessage;
    use crate::reply_sink::BoxedReplySink;
    use crate::sink::{BoxedSink, SampleView};
    use alloc::boxed::Box;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use alloc::vec::Vec;
    use std::sync::{Arc, Mutex};
    use wz_codecs::lent::{Wireexpr, WireexprNonlocal, WireexprVariant};
    use wz_session_core_test_support as fx;

    type Req = Requesters<BoxedReplySink, BoxedReplySink>;

    fn frame(messages: Vec<NetworkMessage>) -> DriverLoopOutcome {
        DriverLoopOutcome::FramePayload {
            priority: crate::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages,
            has_ext: false,
            extensions: Vec::new(),
        }
    }

    /// A Push naming id `mapping_id` with `M=0`: the id is in OUR space.
    fn push_own_alias(mapping_id: crate::wire_id::ExprId) -> crate::wire::PushOwned {
        use wz_codecs::lent::Push;
        Push {
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                    id: mapping_id,
                    suffix_len: None,
                    suffix: None,
                }),
            },
            ..Push::default()
        }
        .try_into_owned_in::<crate::wire::WireStorage>()
        .unwrap()
    }

    /// One observer with a subscriber on each of the two literals, a listener on
    /// the subscribers a peer declares, and a session whose PEER declared id 7 as
    /// `theirs/x`, absorbed through the ordinary inbound `DeclKexpr` path. The
    /// session's own space holds id 7 as `ours/x` when `own` is set. The
    /// collision is the discriminator: a fan handing over the peer's table alone
    /// would resolve a confident wrong keyexpr, not drop the frame.
    struct Fixture {
        observer: SlotObserver,
        peers: PeerTables,
        requesters: Req,
        ours: Arc<Mutex<Vec<String>>>,
        theirs: Arc<Mutex<Vec<String>>>,
        declared: Arc<Mutex<Vec<String>>>,
    }

    fn fixture(own: bool) -> Fixture {
        let mut observer = SlotObserver::new();
        let mut peers = PeerTables::new();
        let mut requesters = Req::new();
        if own {
            let mut space: hashbrown::HashMap<crate::wire_id::ExprId, String> =
                hashbrown::HashMap::new();
            space.insert(7, "ours/x".to_string());
            peers.subscribers.set_own_mapping_space(Arc::new(space));
        }
        let outcome = frame(vec![NetworkMessage::Declare(Box::new(
            fx::declare_envelope_decl_kexpr(fx::decl_kexpr(7, "theirs/x")),
        ))]);
        crate::driver_loop::deliver_frame(&outcome, |event| {
            observer.dispatch_event(&mut (), &mut peers, &mut requesters, event)
        });

        let mut record = |literal: &str| {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let into = seen.clone();
            observer
                .tables
                .subscribers
                .register_sink(
                    literal,
                    Locality::Any,
                    BoxedSink::new(move |s: &dyn SampleView| {
                        into.lock().unwrap().push(s.keyexpr().to_string());
                    }),
                )
                .expect("register");
            seen
        };
        let ours = record("ours/x");
        let theirs = record("theirs/x");
        let declared = Arc::new(Mutex::new(Vec::new()));
        let into = declared.clone();
        observer
            .remote_subscribers
            .on_subscriber_declared_sink(BoxedDeclSink::new(move |d: &dyn DeclView| {
                into.lock().unwrap().push(d.keyexpr().to_string());
            }))
            .expect("install");
        Fixture {
            observer,
            peers,
            requesters,
            ours,
            theirs,
            declared,
        }
    }

    /// A Push on the literal key `key`.
    fn push_literal(key: &str) -> crate::wire::PushOwned {
        use wz_codecs::lent::{Push, WireexprLocal};
        Push {
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprLocal(WireexprLocal {
                    id: 0,
                    suffix_len: Some(key.len() as u64),
                    suffix: Some(sce_forge_runtime::codec::Bounded::new(key).unwrap()),
                }),
            },
            ..Push::default()
        }
        .try_into_owned_in::<crate::wire::WireStorage>()
        .unwrap()
    }

    /// The slot fan delivers a peer's Push to an observer whose subscriptions are kept in the
    /// session's one table set as it does to a subscriber table: the matching key once, another
    /// key not at all.
    #[test]
    fn the_slot_fan_delivers_a_peers_push_to_a_table_set() {
        use crate::session_tables::KeyForm;
        let mut observer = SlotObserverOf::<super::lent_tests::TableSinks>::new();
        let mut peers = PeerTables::new();
        let mut requesters = Req::new();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let into = seen.clone();
        observer
            .tables
            .declare_subscriber(
                "topic/a",
                Locality::Any,
                KeyForm::default(),
                BoxedSink::new(move |s: &dyn SampleView| {
                    into.lock().unwrap().push(s.keyexpr().to_string());
                }),
            )
            .expect("a table of the build's bound has room");
        let outcome = frame(vec![
            NetworkMessage::Push(Box::new(push_literal("topic/a"))),
            NetworkMessage::Push(Box::new(push_literal("topic/b"))),
        ]);
        crate::driver_loop::deliver_frame(&outcome, |event| {
            observer.dispatch_event(&mut (), &mut peers, &mut requesters, event)
        });
        assert_eq!(*seen.lock().unwrap(), vec!["topic/a".to_string()]);
    }

    /// A session that asks nothing holds its requesters as [`NoRequesters`], of no size, and the
    /// fan delivers a peer's Push beside them as it does beside real ones: the matching key once,
    /// another key not at all. Nothing is then staged for a drain to send.
    #[test]
    fn the_slot_fan_delivers_a_peers_push_beside_no_requesters() {
        use crate::session_tables::KeyForm;
        assert_eq!(core::mem::size_of::<NoRequesters>(), 0);
        let mut observer = SlotObserverOf::<super::lent_tests::TableSinks>::new();
        let mut peers = PeerTables::new();
        let mut requesters = NoRequesters;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let into = seen.clone();
        observer
            .tables
            .declare_subscriber(
                "topic/a",
                Locality::Any,
                KeyForm::default(),
                BoxedSink::new(move |s: &dyn SampleView| {
                    into.lock().unwrap().push(s.keyexpr().to_string());
                }),
            )
            .expect("a table of the build's bound has room");
        let outcome = frame(vec![
            NetworkMessage::Push(Box::new(push_literal("topic/a"))),
            NetworkMessage::Push(Box::new(push_literal("topic/b"))),
        ]);
        crate::driver_loop::deliver_frame(&outcome, |event| {
            observer.dispatch_event(&mut (), &mut peers, &mut requesters, event)
        });
        assert_eq!(*seen.lock().unwrap(), vec!["topic/a".to_string()]);
        assert!(!stages_replies(&peers, &requesters));
    }

    /// A delivery context that records the handle of each row it is handed and calls no row.
    #[derive(Default)]
    struct HandleLog(Vec<crate::session_tables::SubscriberHandle>);

    impl SampleDelivery<BoxedSink, crate::session_tables::SubscriberHandle> for HandleLog {
        fn deliver(
            &mut self,
            id: crate::session_tables::SubscriberHandle,
            _row: crate::sink::RowAccess<'_, BoxedSink>,
            _sample: &dyn SampleView,
        ) {
            self.0.push(id);
        }
    }

    /// The tables of these tests hold no liveliness subscriber: a row of no value is never told.
    impl
        crate::declare::liveliness_subscriber::LivelinessDelivered<
            HandleLog,
            crate::session_tables::LivelinessSubscriberHandle,
        > for NoSink
    {
        fn tell(
            _cx: &mut HandleLog,
            _id: crate::session_tables::LivelinessSubscriberHandle,
            row: crate::sink::RowAccess<'_, NoSink>,
            _sample: crate::declare::liveliness_sample::LivelinessSample<'_>,
        ) {
            match *row.row() {}
        }
    }

    /// The tables of these tests hold no queryable: a row of no value is never asked.
    #[cfg(feature = "query-queryable")]
    impl crate::query::QueryDelivered<HandleLog, crate::session_tables::QueryableHandle> for NoSink {
        fn ask(
            _cx: &mut HandleLog,
            _id: crate::session_tables::QueryableHandle,
            row: crate::sink::RowAccess<'_, NoSink>,
            _query: &crate::query_sink::ProvenQuery<'_>,
            _responder: &mut crate::query::QueryResponder<'_>,
        ) {
            match *row.row() {}
        }
    }

    /// Subscriptions kept in the session's one table set, delivered through a [`HandleLog`].
    struct LoggedTableSinks;

    impl ObserverSinks for LoggedTableSinks {
        type Subscriber = BoxedSink;
        type SubscriberId = crate::session_tables::SubscriberHandle;
        type QueryableId = crate::session_tables::QueryableHandle;
        type LivelinessSubscriberId = crate::session_tables::LivelinessSubscriberHandle;
        type Delivery = HandleLog;
        type Tables<P: Storage> = SessionTables<super::lent_tests::BoxedRows, P>;
        type Queryable = NoSink;
        type LivelinessSubscriber = NoSink;
        type Declared = NoSink;
        type Undeclared = NoSink;
    }

    /// The slot fan delivers a peer's Push through the context it is handed, naming the row it
    /// matched by its handle, and the row's own sink is not called by the fan: the matching key
    /// once, another key not at all.
    #[test]
    fn the_slot_fan_delivers_through_the_context_it_is_handed() {
        use crate::session_tables::KeyForm;
        let mut observer = SlotObserverOf::<LoggedTableSinks>::new();
        let mut peers = PeerTables::new();
        let mut requesters = Req::new();
        let called = Arc::new(Mutex::new(0usize));
        let into = called.clone();
        let reached = observer
            .tables
            .declare_subscriber(
                "topic/a",
                Locality::Any,
                KeyForm::default(),
                BoxedSink::new(move |_s: &dyn SampleView| {
                    *into.lock().unwrap() += 1;
                }),
            )
            .expect("a table of the build's bound has room");
        let outcome = frame(vec![
            NetworkMessage::Push(Box::new(push_literal("topic/a"))),
            NetworkMessage::Push(Box::new(push_literal("topic/b"))),
        ]);
        let mut log = HandleLog::default();
        crate::driver_loop::deliver_frame(&outcome, |event| {
            observer.dispatch_event(&mut log, &mut peers, &mut requesters, event)
        });
        assert_eq!(log.0, vec![reached.handle]);
        assert_eq!(
            *called.lock().unwrap(),
            0,
            "the context delivers, not the row"
        );
    }

    /// The row of a queryable these tests declare: a callback the tables call only while they are
    /// held, which only a context asks.
    #[cfg(all(
        feature = "alloc",
        any(feature = "query-queryable", feature = "liveliness-subscriber")
    ))]
    #[derive(Debug)]
    struct AskedRow;

    #[cfg(all(
        feature = "alloc",
        any(feature = "query-queryable", feature = "liveliness-subscriber")
    ))]
    impl crate::row_callback::RowCallback for AskedRow {
        type Call = core::convert::Infallible;
        const READS_ROW_IN_PLACE: bool = false;
        fn begin(&self) -> Option<core::convert::Infallible> {
            None
        }
        unsafe fn end(call: core::convert::Infallible) -> bool {
            match call {}
        }
        fn retire(&self) -> bool {
            true
        }
    }

    /// The callbacks of a table set whose queryables a context asks: boxed closures for the
    /// subscribers, an [`AskedRow`] for each queryable.
    #[cfg(all(feature = "query-queryable", feature = "alloc"))]
    enum AskedRows {}

    #[cfg(all(feature = "query-queryable", feature = "alloc"))]
    impl RowCallbacks for AskedRows {
        type Subscriber = BoxedSink;
        type Queryable = AskedRow;
        type LivelinessSubscriber = NoSink;
        type Matching = NoSink;
        type Reply = NoSink;
    }

    /// The callbacks of a table set whose queryables hold no callback.
    #[cfg(all(feature = "query-queryable", feature = "alloc"))]
    enum UnitRows {}

    #[cfg(all(feature = "query-queryable", feature = "alloc"))]
    impl RowCallbacks for UnitRows {
        type Subscriber = BoxedSink;
        type Queryable = ();
        type LivelinessSubscriber = NoSink;
        type Matching = NoSink;
        type Reply = NoSink;
    }

    /// A delivery context that records the handle of each queryable row it is asked through and
    /// answers nothing.
    #[cfg(all(feature = "query-queryable", feature = "alloc"))]
    #[derive(Default)]
    struct QueryLog(Vec<crate::session_tables::QueryableHandle>);

    #[cfg(all(feature = "query-queryable", feature = "alloc"))]
    impl SampleDelivery<BoxedSink, crate::session_tables::SubscriberHandle> for QueryLog {
        fn deliver(
            &mut self,
            _id: crate::session_tables::SubscriberHandle,
            _row: crate::sink::RowAccess<'_, BoxedSink>,
            _sample: &dyn SampleView,
        ) {
        }
    }

    #[cfg(all(feature = "query-queryable", feature = "alloc"))]
    impl crate::query::QueryDelivered<QueryLog, crate::session_tables::QueryableHandle> for AskedRow {
        fn ask(
            cx: &mut QueryLog,
            id: crate::session_tables::QueryableHandle,
            _row: crate::sink::RowAccess<'_, AskedRow>,
            _query: &crate::query_sink::ProvenQuery<'_>,
            _responder: &mut crate::query::QueryResponder<'_>,
        ) {
            cx.0.push(id);
        }
    }

    /// The tables of these tests hold no liveliness subscriber: a row of no value is never told.
    #[cfg(all(feature = "query-queryable", feature = "alloc"))]
    impl
        crate::declare::liveliness_subscriber::LivelinessDelivered<
            QueryLog,
            crate::session_tables::LivelinessSubscriberHandle,
        > for NoSink
    {
        fn tell(
            _cx: &mut QueryLog,
            _id: crate::session_tables::LivelinessSubscriberHandle,
            row: crate::sink::RowAccess<'_, NoSink>,
            _sample: crate::declare::liveliness_sample::LivelinessSample<'_>,
        ) {
            match *row.row() {}
        }
    }

    /// Queryables kept in the session's one table set, asked through a [`QueryLog`].
    #[cfg(all(feature = "query-queryable", feature = "alloc"))]
    struct QuerySinks;

    #[cfg(all(feature = "query-queryable", feature = "alloc"))]
    impl ObserverSinks for QuerySinks {
        type Subscriber = BoxedSink;
        type SubscriberId = crate::session_tables::SubscriberHandle;
        type QueryableId = crate::session_tables::QueryableHandle;
        type LivelinessSubscriberId = crate::session_tables::LivelinessSubscriberHandle;
        type Delivery = QueryLog;
        type Tables<P: Storage> = SessionTables<AskedRows, P>;
        type Queryable = AskedRow;
        type LivelinessSubscriber = NoSink;
        type Declared = NoSink;
        type Undeclared = NoSink;
    }

    /// Queryables of no callback kept in the session's one table set, with the same context: the
    /// sink set names them with no delivery of its own for them.
    #[cfg(all(feature = "query-queryable", feature = "alloc"))]
    struct UnitSinks;

    #[cfg(all(feature = "query-queryable", feature = "alloc"))]
    impl ObserverSinks for UnitSinks {
        type Subscriber = BoxedSink;
        type SubscriberId = crate::session_tables::SubscriberHandle;
        type QueryableId = crate::session_tables::QueryableHandle;
        type LivelinessSubscriberId = crate::session_tables::LivelinessSubscriberHandle;
        type Delivery = QueryLog;
        type Tables<P: Storage> = SessionTables<UnitRows, P>;
        type Queryable = ();
        type LivelinessSubscriber = NoSink;
        type Declared = NoSink;
        type Undeclared = NoSink;
    }

    /// A frame of one peer query on `q/a`.
    #[cfg(all(feature = "query-queryable", feature = "alloc"))]
    fn query_frame() -> DriverLoopOutcome {
        let request = crate::request_build::build_request_query(
            1,
            crate::wire_key::WireKey::literal("q/a").expect("a literal key"),
        )
        .expect("the request builds");
        frame(vec![NetworkMessage::Request(Box::new(request))])
    }

    /// The slot fan asks a table set's queryable a peer's query reaches through the context it is
    /// handed, naming the row by its handle, and owes the query its Final: the matching key's row
    /// once, the other row not at all.
    #[cfg(all(feature = "query-queryable", feature = "alloc"))]
    #[test]
    fn the_slot_fan_asks_a_queryable_through_the_context_it_is_handed() {
        use crate::session_tables::KeyForm;
        let mut observer = SlotObserverOf::<QuerySinks>::new();
        let mut peers = PeerTables::new();
        let mut requesters = Req::new();
        let asked = observer
            .tables
            .declare_queryable("q/a", Locality::Any, false, KeyForm::default(), AskedRow)
            .expect("a table of the build's bound has room");
        observer
            .tables
            .declare_queryable(
                "q/other",
                Locality::Any,
                false,
                KeyForm::default(),
                AskedRow,
            )
            .expect("a table of the build's bound has room");
        let mut log = QueryLog::default();
        crate::driver_loop::deliver_frame(&query_frame(), |event| {
            observer.dispatch_event(&mut log, &mut peers, &mut requesters, event)
        });
        assert_eq!(log.0, vec![asked.handle]);
        assert!(
            !peers.finals.is_empty(),
            "the routed query is owed its Final"
        );
    }

    /// A row that holds no queryable is asked nothing, whatever context the sink set names: the
    /// query still reaches it and is owed its Final, and the context records no row.
    #[cfg(all(feature = "query-queryable", feature = "alloc"))]
    #[test]
    fn a_row_of_no_queryable_is_asked_nothing_whatever_the_context() {
        use crate::session_tables::KeyForm;
        let mut observer = SlotObserverOf::<UnitSinks>::new();
        let mut peers = PeerTables::new();
        let mut requesters = Req::new();
        observer
            .tables
            .declare_queryable("q/a", Locality::Any, false, KeyForm::default(), ())
            .expect("a table of the build's bound has room");
        let mut log = QueryLog::default();
        crate::driver_loop::deliver_frame(&query_frame(), |event| {
            observer.dispatch_event(&mut log, &mut peers, &mut requesters, event)
        });
        assert!(log.0.is_empty(), "no row of no queryable is recorded");
        assert!(
            !peers.finals.is_empty(),
            "the routed query is owed its Final"
        );
    }

    /// The callbacks of a table set whose liveliness subscribers a context tells: an [`AskedRow`]
    /// for each.
    #[cfg(all(feature = "liveliness-subscriber", feature = "alloc"))]
    enum TokenRows {}

    #[cfg(all(feature = "liveliness-subscriber", feature = "alloc"))]
    impl RowCallbacks for TokenRows {
        type Subscriber = BoxedSink;
        type Queryable = NoSink;
        type LivelinessSubscriber = AskedRow;
        type Matching = NoSink;
        type Reply = NoSink;
    }

    /// A delivery context that records the handle of each liveliness subscriber's row it is told
    /// through, and what it was told.
    #[cfg(all(feature = "liveliness-subscriber", feature = "alloc"))]
    #[derive(Default)]
    struct TokenLog(
        Vec<(
            crate::session_tables::LivelinessSubscriberHandle,
            crate::declare::liveliness_sample::LivelinessSampleKind,
        )>,
    );

    #[cfg(all(feature = "liveliness-subscriber", feature = "alloc"))]
    impl SampleDelivery<BoxedSink, crate::session_tables::SubscriberHandle> for TokenLog {
        fn deliver(
            &mut self,
            _id: crate::session_tables::SubscriberHandle,
            _row: crate::sink::RowAccess<'_, BoxedSink>,
            _sample: &dyn SampleView,
        ) {
        }
    }

    #[cfg(all(
        feature = "liveliness-subscriber",
        feature = "alloc",
        feature = "query-queryable"
    ))]
    impl crate::query::QueryDelivered<TokenLog, crate::session_tables::QueryableHandle> for NoSink {
        fn ask(
            _cx: &mut TokenLog,
            _id: crate::session_tables::QueryableHandle,
            row: crate::sink::RowAccess<'_, NoSink>,
            _query: &crate::query_sink::ProvenQuery<'_>,
            _responder: &mut crate::query::QueryResponder<'_>,
        ) {
            match *row.row() {}
        }
    }

    #[cfg(all(feature = "liveliness-subscriber", feature = "alloc"))]
    impl
        crate::declare::liveliness_subscriber::LivelinessDelivered<
            TokenLog,
            crate::session_tables::LivelinessSubscriberHandle,
        > for AskedRow
    {
        fn tell(
            cx: &mut TokenLog,
            id: crate::session_tables::LivelinessSubscriberHandle,
            _row: crate::sink::RowAccess<'_, AskedRow>,
            sample: crate::declare::liveliness_sample::LivelinessSample<'_>,
        ) {
            cx.0.push((id, sample.kind));
        }
    }

    /// Liveliness subscribers kept in the session's one table set, told through a [`TokenLog`].
    #[cfg(all(feature = "liveliness-subscriber", feature = "alloc"))]
    struct TokenSinks;

    #[cfg(all(feature = "liveliness-subscriber", feature = "alloc"))]
    impl ObserverSinks for TokenSinks {
        type Subscriber = BoxedSink;
        type SubscriberId = crate::session_tables::SubscriberHandle;
        type QueryableId = crate::session_tables::QueryableHandle;
        type LivelinessSubscriberId = crate::session_tables::LivelinessSubscriberHandle;
        type Delivery = TokenLog;
        type Tables<P: Storage> = SessionTables<TokenRows, P>;
        type Queryable = NoSink;
        type LivelinessSubscriber = AskedRow;
        type Declared = NoSink;
        type Undeclared = NoSink;
    }

    /// The slot fan tells a table set's liveliness subscriber a peer's token reaches through the
    /// context it is handed, naming the row by its handle: the token's `Put` to the subscriber on
    /// its key and to no other, and the link's loss as a `Delete` through the same context.
    #[cfg(all(feature = "liveliness-subscriber", feature = "alloc"))]
    #[test]
    fn the_slot_fan_tells_a_liveliness_subscriber_through_the_context_it_is_handed() {
        use crate::declare::liveliness_sample::LivelinessSampleKind;
        use crate::session_tables::KeyForm;
        let mut observer = SlotObserverOf::<TokenSinks>::new();
        let mut peers = PeerTables::new();
        let mut requesters = Req::new();
        let told = observer
            .tables
            .declare_liveliness_subscriber("t/a", false, KeyForm::default(), AskedRow)
            .expect("a table of the build's bound has room");
        observer
            .tables
            .declare_liveliness_subscriber("t/other", false, KeyForm::default(), AskedRow)
            .expect("a table of the build's bound has room");
        let outcome = frame(vec![NetworkMessage::Declare(Box::new(
            fx::declare_envelope_decl_token(fx::decl_token(5, 0, Some("t/a"))),
        ))]);
        let mut log = TokenLog::default();
        crate::driver_loop::deliver_frame(&outcome, |event| {
            observer.dispatch_event(&mut log, &mut peers, &mut requesters, event)
        });
        assert_eq!(log.0, vec![(told.handle, LivelinessSampleKind::Put)]);
        assert_eq!(
            observer.flush_liveliness_on_link_loss(&mut log, &mut peers),
            1
        );
        assert_eq!(
            log.0,
            vec![
                (told.handle, LivelinessSampleKind::Put),
                (told.handle, LivelinessSampleKind::Delete)
            ]
        );
    }

    /// The same two messages in both tests: a Push and a `DeclareSubscriber`, each
    /// naming id 7 with `M=0`.
    fn own_alias_frame() -> DriverLoopOutcome {
        frame(vec![
            NetworkMessage::Push(Box::new(push_own_alias(7))),
            NetworkMessage::Declare(Box::new(fx::declare_envelope_decl_subscriber(
                fx::decl_subscriber_nonlocal(1, 7, None),
            ))),
        ])
    }

    #[test]
    fn an_own_space_alias_resolves_through_the_slot_fan_on_both_planes() {
        let mut f = fixture(true);
        let outcome = own_alias_frame();
        crate::driver_loop::deliver_frame(&outcome, |event| {
            f.observer
                .dispatch_event(&mut (), &mut f.peers, &mut f.requesters, event)
        });
        assert_eq!(
            *f.ours.lock().unwrap(),
            vec!["ours/x".to_string()],
            "the Push plane resolved id 7 in OUR space"
        );
        assert!(
            f.theirs.lock().unwrap().is_empty(),
            "a fan handing over the peer table alone would have fired this one"
        );
        assert_eq!(
            *f.declared.lock().unwrap(),
            vec!["ours/x".to_string()],
            "the declare-subscriber plane resolved id 7 in OUR space"
        );
    }

    /// The anti-vacuity twin: the same frame against a session with no own space
    /// installed resolves nothing on either plane, so the witness above would not
    /// pass on a peer table that merely happened to be empty.
    #[test]
    fn without_an_own_space_the_slot_fan_refuses_the_same_frame_on_both_planes() {
        let mut f = fixture(false);
        let outcome = own_alias_frame();
        crate::driver_loop::deliver_frame(&outcome, |event| {
            f.observer
                .dispatch_event(&mut (), &mut f.peers, &mut f.requesters, event)
        });
        assert!(
            f.ours.lock().unwrap().is_empty() && f.theirs.lock().unwrap().is_empty(),
            "an M=0 alias must refuse with no own space, never fall back to the peer's table"
        );
        assert!(f.declared.lock().unwrap().is_empty());
    }

    /// A sink that counts the bursts a drain opens and sends nothing.
    #[derive(Default)]
    struct Bursts(core::cell::Cell<usize>);

    impl ResponseSink for Bursts {
        #[cfg(all(feature = "codec-response", feature = "alloc"))]
        fn send_response(&self, _response: crate::wire::ResponseOwned) {}

        #[cfg(all(
            feature = "codec-response",
            feature = "storage-profile",
            not(feature = "alloc")
        ))]
        fn send_reply_parts(&self, _parts: crate::reply_stage::ReplyParts<'_>) {}

        #[cfg(feature = "codec-response-final")]
        fn send_response_final(
            &self,
            _request_id: crate::wire_id::RequestId,
            _qos: crate::sample::QosLevel,
        ) {
        }

        fn begin_burst(&self) -> bool {
            self.0.set(self.0.get() + 1);
            true
        }
    }

    impl DeclareReplySink for Bursts {
        #[cfg(feature = "liveliness-token")]
        fn send_declare_token_reply(&self, _token_id: u64, _keyexpr: &str, _interest_id: u64) {}

        fn send_declare_final_reply(&self, _interest_id: u64) {}

        fn send_declare_subscriber_reply(
            &self,
            _subscriber_id: u64,
            _keyexpr: &str,
            _interest_id: u64,
        ) {
        }

        #[cfg(feature = "declare-undeclare")]
        fn send_undeclare_subscriber_reply(&self, _subscriber_id: u64) {}
    }

    impl LivelinessGetPrune for Bursts {
        #[cfg(feature = "liveliness-get")]
        fn prune_liveliness_get_interest(&self, _interest_id: u64) {}
    }

    /// A drain with nothing staged opens no burst, whose close takes the lock of every conduit to
    /// send what it gathered: what follows every received Push, eight here, each burst-free. The
    /// CONTROL is a drain with an answer to the peer's interest staged, which opens one.
    #[cfg(feature = "interest-answer")]
    #[test]
    fn a_drain_with_nothing_staged_opens_no_burst() {
        let mut f = fixture(false);
        let bursts = Bursts::default();
        for _ in 0..8 {
            f.observer
                .flush_pending_replies(&mut f.peers, &mut f.requesters, &bursts);
            f.observer
                .flush_pending(&mut f.peers, &mut f.requesters, &bursts);
        }
        assert_eq!(bursts.0.get(), 0, "sixteen drains of nothing, no burst");
        let staged = f
            .observer
            .tables
            .subscribers
            .respond_to_subscriber_interest_borrowed(
                &mut f.peers.subscribers,
                9,
                Some("ours/x"),
                false,
                true,
                false,
            );
        assert!(staged > 0, "a subscription answers the interest");
        f.observer
            .flush_pending_replies(&mut f.peers, &mut f.requesters, &bursts);
        assert_eq!(
            bursts.0.get(),
            1,
            "CONTROL: a staged answer opens one burst"
        );
        f.observer
            .flush_pending_replies(&mut f.peers, &mut f.requesters, &bursts);
        assert_eq!(bursts.0.get(), 1, "and the drain took it");
    }
}

#[cfg(all(test, feature = "alloc"))]
mod lent_tests {
    //! An observer whose application tables a session's arena lent: the rows lent are what bound
    //! them, and the tables answer a peer side of another policy.
    use super::*;
    use crate::bounded::ARENA_ALIGN;
    use crate::limits::SessionLimits;
    use crate::locality::Locality;
    use crate::registry_error::RegisterError;
    use crate::reply::ReplyHandle;
    use crate::reply_acceptance::ReplyAcceptance;
    use crate::reply_sink::{BoxedReplySink, ReplyView};
    use crate::sink::{BoxedSink, SampleView};
    use crate::wire_id::RequestId;
    use core::ptr::NonNull;

    /// One block of an arena's memory, aligned as an arena's spans start.
    #[derive(Clone, Copy)]
    #[repr(C, align(16))]
    struct Block([u8; ARENA_ALIGN]);

    /// An arena over `bytes` bytes the test process leaks, so it outlives every table lent from it.
    fn arena(bytes: usize) -> Arena {
        let blocks = bytes.div_ceil(ARENA_ALIGN);
        let region: &'static mut [Block] = std::vec![Block([0; ARENA_ALIGN]); blocks].leak();
        // SAFETY: the region is aligned to `ARENA_ALIGN`, as its blocks are, holds at least
        // `bytes` bytes, and is leaked, so nothing else uses it and it outlives every lent table.
        unsafe { Arena::over(NonNull::from(region).cast::<u8>(), bytes) }
    }

    /// A key arena of `bytes` bytes of blocks, lent from an arena of its own, so an arena tables
    /// are lent from is laid out by their plan alone.
    fn keys(bytes: usize) -> KeySpace {
        arena(KeySpace::span_bytes(bytes).expect("a small key arena"))
            .lend_keys(bytes, SessionLimits::defaults().max_keyexpr_bytes_held())
            .expect("the arena is the key arena's span")
    }

    fn sink() -> BoxedSink {
        BoxedSink::new(|_sample: &dyn SampleView| {})
    }

    /// An observer of `subscribers` lent rows whose patterns are kept in `keys`.
    fn lent_in(subscribers: usize, keys: KeySpace) -> SlotObserverOf<HeapSinks, Lent> {
        let rows = ObserverRows {
            tables: RegistryRows {
                subscribers,
                ..RegistryRows::default()
            },
            ..ObserverRows::default()
        };
        SlotObserverOf::<HeapSinks, Lent>::lent(
            &mut arena(1 << 16),
            keys,
            rows,
            &SessionLimits::defaults(),
        )
        .expect("the arena has the rows")
    }

    fn lent_with(subscribers: usize) -> SlotObserverOf<HeapSinks, Lent> {
        lent_in(subscribers, keys(4096))
    }

    /// The callbacks of the table set an observer keeps its subscriptions in: boxed closures for
    /// the subscribers, none for the kinds these tests declare none of.
    pub(super) enum BoxedRows {}

    impl RowCallbacks for BoxedRows {
        type Subscriber = BoxedSink;
        type Queryable = NoSink;
        type LivelinessSubscriber = NoSink;
        type Matching = NoSink;
        type Reply = NoSink;
    }

    /// An observer whose subscriptions are kept in the session's one table set.
    pub(super) struct TableSinks;

    impl ObserverSinks for TableSinks {
        type Subscriber = BoxedSink;
        type SubscriberId = crate::session_tables::SubscriberHandle;
        type QueryableId = crate::session_tables::QueryableHandle;
        type LivelinessSubscriberId = crate::session_tables::LivelinessSubscriberHandle;
        type Delivery = ();
        type Tables<P: Storage> = SessionTables<BoxedRows, P>;
        type Queryable = NoSink;
        type LivelinessSubscriber = NoSink;
        type Declared = NoSink;
        type Undeclared = NoSink;
    }

    /// An observer of table-set subscriptions lent `subscribers` rows of that set.
    fn table_set_lent(subscribers: usize) -> SlotObserverOf<TableSinks, Lent> {
        let rows = ObserverRows {
            tables: TableRows {
                subscribers,
                ..TableRows::default()
            },
            ..ObserverRows::default()
        };
        SlotObserverOf::<TableSinks, Lent>::lent(
            &mut arena(1 << 16),
            keys(4096),
            rows,
            &SessionLimits::defaults(),
        )
        .expect("the arena has the rows")
    }

    /// A table set holding the observer's subscriptions is lent the rows its `TableRows` state:
    /// one row lent, the second subscription is refused as a full table, and a set lent none
    /// refuses the first.
    #[test]
    fn a_lent_table_set_keeps_the_subscriptions_its_rows_hold() {
        use crate::session_tables::KeyForm;
        let mut observer = table_set_lent(1);
        observer
            .tables
            .declare_subscriber("demo/a", Locality::Any, KeyForm::default(), sink())
            .expect("the one row is free");
        let refused = observer
            .tables
            .declare_subscriber("demo/b", Locality::Any, KeyForm::default(), sink())
            .expect_err("one row was lent");
        assert!(matches!(refused.why, RegisterError::TableFull));
        assert!(observer.tables.has_local_matching("demo/a"));
        assert!(!observer.tables.has_local_matching("demo/b"));

        let mut none = table_set_lent(0);
        let refused = none
            .tables
            .declare_subscriber("demo/a", Locality::Any, KeyForm::default(), sink())
            .expect_err("no row was lent");
        assert!(matches!(refused.why, RegisterError::TableFull));
    }

    /// The own zid a peer's tables hold is inline whatever their policy: a side of the lent policy,
    /// lent no rows at all, keeps it.
    #[test]
    fn a_lent_peer_side_keeps_its_own_zid() {
        let mut side = crate::pubsub::SubscriberPeer::<Lent>::default();
        assert!(side.set_own_zid_bytes(&[1, 2, 3]));
        assert_eq!(side.own_zid(), Some(&[1u8, 2, 3][..]));
    }

    /// The application's tables answer the tables of a peer of any storage policy: a lent observer
    /// dispatches against a peer of the static policy, and a lost link drops what that peer
    /// declared, which is nothing here.
    #[test]
    fn a_lent_observer_dispatches_against_a_peer_of_the_static_policy() {
        let mut observer = lent_with(2);
        let mut peers = PeerTables::<crate::bounded::Static>::new_static();
        let mut requesters = Requesters::<BoxedReplySink, BoxedReplySink>::new();
        observer.dispatch_event(
            &mut (),
            &mut peers,
            &mut requesters,
            IterationEvent::AppWake,
        );
        assert_eq!(observer.flush_declarations_on_link_loss(&mut peers), 0);
    }

    /// Two subscriptions lent, under a quota that admits more: the third is refused as a full
    /// table, and the row an unregistration gives back takes the next.
    #[test]
    fn a_lent_observer_refuses_past_the_rows_it_was_lent() {
        let mut observer = lent_with(2);
        let first = observer
            .tables
            .subscribers
            .register_sink("demo/a", Locality::Any, sink())
            .expect("a row is free");
        observer
            .tables
            .subscribers
            .register_sink("demo/b", Locality::Any, sink())
            .expect("the last row is free");
        assert!(matches!(
            observer
                .tables
                .subscribers
                .register_sink("demo/c", Locality::Any, sink()),
            Err(RegisterError::TableFull)
        ));
        assert!(observer.tables.subscribers.unregister(first));
        assert!(observer
            .tables
            .subscribers
            .register_sink("demo/c", Locality::Any, sink())
            .is_ok());
    }

    /// A wild key is canonized in a working buffer of its own, not one of the table's lent
    /// policy, so the lent tables take it as any other key.
    #[test]
    fn a_lent_observer_takes_a_wild_key() {
        let mut observer = lent_with(1);
        assert!(observer
            .tables
            .subscribers
            .register_sink("demo/**", Locality::Any, sink())
            .is_ok());
    }

    /// The registries of a lent observer are each lent their own rows: one queryable row lent,
    /// the second queryable is refused as a full table, and the subscriber table's row is its own.
    #[cfg(feature = "query-queryable")]
    #[test]
    fn a_lent_observers_registries_are_each_lent_their_own_rows() {
        use crate::query_sink::{BoxedQuerySink, QueryView, ReplyOut};
        let answer = || BoxedQuerySink::new(|_q: &dyn QueryView, _r: &mut dyn ReplyOut| {});
        let rows = ObserverRows {
            tables: RegistryRows {
                subscribers: 1,
                queryables: 1,
            },
            ..ObserverRows::default()
        };
        let mut observer = SlotObserverOf::<HeapSinks, Lent>::lent(
            &mut arena(1 << 16),
            keys(4096),
            rows,
            &SessionLimits::defaults(),
        )
        .expect("the arena has the rows");
        observer
            .tables
            .queryables
            .register_sink("q/a", Locality::Any, false, answer())
            .expect("the one queryable row is free");
        assert!(matches!(
            observer
                .tables
                .queryables
                .register_sink("q/b", Locality::Any, false, answer()),
            Err(RegisterError::TableFull)
        ));
        observer
            .tables
            .subscribers
            .register_sink("demo/a", Locality::Any, sink())
            .expect("the subscriber table's row is its own");
    }

    /// An arena without the room refuses the observer: nothing past what it has is lent. (A build
    /// whose ceiling is under one row refuses it past the ceiling instead; either is a refusal.)
    #[test]
    fn a_lent_observer_the_arena_cannot_hold_is_refused() {
        let rows = ObserverRows {
            tables: RegistryRows {
                subscribers: 1,
                ..RegistryRows::default()
            },
            ..ObserverRows::default()
        };
        let refused = SlotObserverOf::<HeapSinks, Lent>::lent(
            &mut arena(0),
            keys(64),
            rows,
            &SessionLimits::defaults(),
        );
        assert!(refused.is_err());
    }

    /// The requesters of one face, with the heap profile's reply sinks.
    type Lending = Requesters<BoxedReplySink, BoxedReplySink, Lent>;

    /// The requesters of one face, `queries` rows of pending queries and `gets` of liveliness
    /// snapshots lent from an arena of their own.
    fn requesters(queries: usize, gets: usize) -> Lending {
        requesters_in(queries, gets, keys(4096))
    }

    /// [`requesters`] whose pending queries keep their keys in `keys`.
    fn requesters_in(queries: usize, gets: usize, keys: KeySpace) -> Lending {
        Lending::lent(
            &mut arena(1 << 16),
            keys,
            RequesterRows {
                queries,
                liveliness_gets: gets,
            },
            &SessionLimits::defaults(),
        )
        .expect("the arena has the rows")
    }

    fn reply_sink() -> BoxedReplySink {
        BoxedReplySink::new(|_reply: &dyn ReplyView| {}, |_rid: RequestId| {})
    }

    /// Hold query `rid` pending in `requesters`, accepting a reply on any key.
    fn hold(requesters: &mut Lending, rid: RequestId) -> Result<ReplyHandle, RegisterError> {
        requesters
            .replies
            .register_sink(rid, 1, None, ReplyAcceptance::Any, reply_sink())
    }

    /// Two pending queries lent: the third get finds no room and is refused as a full table, and
    /// the row its end gives back holds the next.
    #[test]
    fn lent_requesters_refuse_a_get_past_their_rows() {
        let mut requesters = requesters(2, 1);
        assert!(requesters.replies.has_room());
        hold(&mut requesters, 1).expect("a row is free");
        hold(&mut requesters, 2).expect("the last row is free");
        assert!(!requesters.replies.has_room(), "both rows hold a query");
        assert!(matches!(
            hold(&mut requesters, 3),
            Err(RegisterError::TableFull)
        ));
        assert_eq!(requesters.replies.len(), 2, "the refusal held nothing");
        assert!(requesters.replies.unregister(1));
        assert!(requesters.replies.has_room());
        hold(&mut requesters, 3).expect("the row given back holds the next");
    }

    /// A requester of the lent policy that no arena lent rows to has no room, and refuses a get
    /// before anything is put in it: the fallback of a face no table was planned for.
    #[test]
    fn an_unlent_requester_refuses_every_get_before_holding_it() {
        let mut requesters = Lending::default();
        assert!(!requesters.replies.has_room());
        assert!(matches!(
            hold(&mut requesters, 1),
            Err(RegisterError::TableFull)
        ));
        assert!(requesters.replies.is_empty());
    }

    /// The patterns of a lent observer's subscriptions lie in the key arena it was handed, a block
    /// each as long as the pattern, and match as they did inline: a subscription on `demo/a/x`
    /// matches `demo/a/x` and not `demo/b`. Its unregistration gives the block back, and the next
    /// pattern of that length takes the same bytes.
    #[test]
    fn a_lent_observers_patterns_lie_in_the_key_arena_and_match_as_before() {
        use crate::key_arena::block_bytes;

        let keys = keys(256);
        let mut observer = lent_in(2, keys);
        let id = observer
            .tables
            .subscribers
            .register_sink("demo/a/x", Locality::Any, sink())
            .expect("a row and a block are free");
        assert!(observer.tables.subscribers.has_local_matching("demo/a/x"));
        assert!(!observer.tables.subscribers.has_local_matching("demo/b"));
        assert_eq!(
            keys.counts().used,
            block_bytes("demo/a/x".len()).expect("short"),
            "one block of the pattern's length"
        );
        let peak = keys.counts().peak;
        assert!(observer.tables.subscribers.unregister(id));
        assert_eq!(keys.counts().used, 0, "the block went back");
        observer
            .tables
            .subscribers
            .register_sink("demo/c/y", Locality::Any, sink())
            .expect("the block given back holds the next");
        assert!(observer.tables.subscribers.has_local_matching("demo/c/y"));
        assert_eq!(keys.counts().peak, peak, "the same bytes, taken again");
    }

    /// A subscription whose pattern finds no room in the observer's key arena is refused as a
    /// full table refuses it, with a row still free, and counted by the arena; the block an
    /// unregistration gives back takes it.
    #[test]
    fn a_lent_observer_refuses_a_pattern_its_key_arena_cannot_hold() {
        use crate::key_arena::block_bytes;

        let keys = keys(block_bytes("demo/k/1".len()).expect("short"));
        let mut observer = lent_in(2, keys);
        let first = observer
            .tables
            .subscribers
            .register_sink("demo/k/1", Locality::Any, sink())
            .expect("room for one pattern");
        assert!(matches!(
            observer
                .tables
                .subscribers
                .register_sink("demo/k/2", Locality::Any, sink()),
            Err(RegisterError::TableFull)
        ));
        assert_eq!(
            (observer.tables.subscribers.len(), keys.counts().refused),
            (1, 1),
            "(subscriptions held, keys the arena refused)"
        );
        assert!(observer.tables.subscribers.unregister(first));
        assert!(observer
            .tables
            .subscribers
            .register_sink("demo/k/2", Locality::Any, sink())
            .is_ok());
    }

    /// A pending get gated on its keyexpr keeps that keyexpr in the key arena; one the arena has no
    /// room for is refused as a full table refuses it, while a get that accepts any key takes no
    /// key and is held. Its end gives the block back.
    #[test]
    fn a_lent_get_whose_key_finds_no_room_is_refused_as_a_full_table() {
        use crate::key_arena::block_bytes;

        let keys = keys(block_bytes("demo/q/1".len()).expect("short"));
        let mut requesters = requesters_in(3, 0, keys);
        requesters
            .replies
            .register_sink(
                1,
                1,
                None,
                ReplyAcceptance::Matching("demo/q/1"),
                reply_sink(),
            )
            .expect("room for one key");
        assert!(matches!(
            requesters.replies.register_sink(
                2,
                1,
                None,
                ReplyAcceptance::Matching("demo/q/2"),
                reply_sink()
            ),
            Err(RegisterError::TableFull)
        ));
        hold(&mut requesters, 3).expect("a get on any key takes no key");
        assert_eq!(requesters.replies.len(), 2);
        assert!(requesters.replies.unregister(1));
        assert_eq!(keys.counts().used, 0, "the get's end gave its key back");
        requesters
            .replies
            .register_sink(
                2,
                1,
                None,
                ReplyAcceptance::Matching("demo/q/2"),
                reply_sink(),
            )
            .expect("the block given back holds the next key");
    }

    /// What lending a face's requesters takes from an arena is what their plan states, to the byte.
    #[test]
    fn lent_requesters_take_the_bytes_their_plan_states() {
        let rows = RequesterRows {
            queries: 3,
            liveliness_gets: 2,
        };
        let mut memory = arena(1 << 16);
        let lent = Lending::lent(&mut memory, keys(64), rows, &SessionLimits::defaults())
            .expect("the arena has the rows");
        let planned = Lending::arena_bytes(rows).expect("within the address space");
        assert_eq!(memory.high_water(), planned);
        drop(lent);
    }

    /// An arena short of one face's requesters refuses them.
    #[test]
    fn lent_requesters_the_arena_cannot_hold_are_refused() {
        let rows = RequesterRows {
            queries: 1,
            liveliness_gets: 0,
        };
        let refused = Lending::lent(&mut arena(0), keys(64), rows, &SessionLimits::defaults());
        assert!(refused.is_err());
    }

    /// A liveliness snapshot that ends leaves its marker, and draining the markers keeps the rows
    /// the arena lent: the next snapshot is held in them.
    #[cfg(feature = "liveliness-get")]
    #[test]
    fn lent_liveliness_gets_keep_their_rows_across_a_drain() {
        let mut requesters = requesters(1, 1);
        let gets = &mut requesters.liveliness_gets;
        assert_eq!(gets.register(7, Some(10), reply_sink()), Ok(true));
        assert_eq!(gets.sweep_timed_out(11), 1);
        let drained: std::vec::Vec<u64> = gets.take_finalized().into_iter().collect();
        assert_eq!(drained, std::vec![7]);
        assert!(gets.take_finalized().is_empty());
        assert_eq!(
            gets.register(8, None, reply_sink()),
            Ok(true),
            "the drain kept the rows the arena lent"
        );
    }

    /// A lent table answers a peer side of the build's profile: a subscription registered after
    /// the peer's FUTURE interest is staged for that peer when it reconciles.
    #[cfg(all(feature = "declare-subscriber", feature = "interest-answer"))]
    #[test]
    fn a_lent_table_stages_a_future_push_for_a_peer_of_another_policy() {
        let mut observer = lent_with(2);
        let mut peer: crate::pubsub::SubscriberPeer = crate::pubsub::SubscriberPeer::default();
        let now = observer
            .tables
            .subscribers
            .respond_to_subscriber_interest_borrowed(
                &mut peer,
                7,
                Some("demo/a"),
                false,
                true,
                true,
            );
        assert_eq!(now, 0, "nothing subscribes yet");
        let _ = peer.take_staged_sub_interest_replies();
        let id = observer
            .tables
            .subscribers
            .register_sink("demo/a", Locality::Any, sink())
            .expect("a row is free");
        peer.reconcile(&observer.tables.subscribers);
        let staged = peer.take_staged_sub_interest_replies();
        assert!(staged.iter().any(|item| matches!(
            item,
            crate::pubsub::SubInterestReply::Concrete {
                interest_id: 7,
                subscription_id,
            } if *subscription_id == id.as_u64()
        )));
    }

    /// Faces that say nothing of queryables answer no querier: what an engine that reads no
    /// queryable a peer declares relies on, in a build that has the plane for another crate.
    #[cfg(all(feature = "declare-queryable", feature = "declare-subscriber"))]
    #[test]
    fn faces_that_say_nothing_of_queryables_answer_no_querier() {
        struct SubscribersOnly;
        impl OtherPeers for SubscribersOnly {
            fn subscribes(
                &self,
                _criterion: &crate::declare::subscriber::PublisherCriterion,
            ) -> bool {
                true
            }
        }
        let querier =
            crate::declare::queryable::QuerierCriterion::new("demo/q", Locality::Remote, false);
        assert!(!SubscribersOnly.answers(&querier));
        let publisher =
            crate::declare::subscriber::PublisherCriterion::new("demo/q", Locality::Remote);
        assert!(
            SubscribersOnly.subscribes(&publisher),
            "CONTROL: the method the faces do say is theirs"
        );
    }

    /// The watchers' lists of the observer are lent from its arena, the session's
    /// `MAX_DECL_OBSERVERS` rows each: a session that admits fewer watchers is lent fewer bytes, by
    /// what `decl_watcher_bytes` states for the rows between, and a watcher past the rows is
    /// refused on each plane. Turned red by lists of the build's profile, or lent other rows.
    #[cfg(feature = "declare-subscriber")]
    #[test]
    fn lent_watcher_lists_take_the_sessions_rows_and_refuse_one_more() {
        use crate::decl_sink::BoxedDeclSink;
        type App = SlotObserverOf<HeapSinks, Lent>;
        let mut lowered = SessionLimits::defaults();
        // A build whose value is one, or whose domain holds its value alone, has no lower one.
        if caps::MAX_DECL_OBSERVERS < 2
            || lowered
                .select_max_decl_observers(Quota::at_most(1))
                .is_err()
        {
            return;
        }
        assert_eq!(App::decl_watcher_rows(&lowered), Ok(1));
        assert_eq!(
            App::decl_watcher_rows(&SessionLimits::defaults()),
            Ok(caps::MAX_DECL_OBSERVERS)
        );
        let mut one = arena(1 << 16);
        let mut observer = App::lent(&mut one, keys(64), ObserverRows::default(), &lowered)
            .expect("the arena has the rows");
        let mut built = arena(1 << 16);
        let _built = App::lent(
            &mut built,
            keys(64),
            ObserverRows::default(),
            &SessionLimits::defaults(),
        )
        .expect("the arena has the rows");
        let between = App::decl_watcher_bytes(caps::MAX_DECL_OBSERVERS)
            .zip(App::decl_watcher_bytes(1))
            .map(|(all, least)| all - least);
        assert_eq!(
            Some(built.high_water() - one.high_water()),
            between,
            "the lists are lent the session's rows, from the arena"
        );

        observer
            .remote_subscribers
            .on_subscriber_declared_sink(BoxedDeclSink::new(|_| {}))
            .expect("within the row");
        assert_eq!(
            observer
                .remote_subscribers
                .on_subscriber_declared_sink(BoxedDeclSink::new(|_| {})),
            Err(RegisterError::TableFull)
        );
        #[cfg(feature = "declare-queryable")]
        {
            observer
                .remote_queryables
                .on_queryable_declared_sink(BoxedDeclSink::new(|_| {}))
                .expect("within the row");
            assert_eq!(
                observer
                    .remote_queryables
                    .on_queryable_declared_sink(BoxedDeclSink::new(|_| {})),
                Err(RegisterError::TableFull)
            );
        }
        #[cfg(feature = "liveliness-token")]
        {
            observer
                .liveliness
                .on_token_declared_sink(BoxedDeclSink::new(|_| {}))
                .expect("within the row");
            assert_eq!(
                observer
                    .liveliness
                    .on_token_declared_sink(BoxedDeclSink::new(|_| {})),
                Err(RegisterError::TableFull)
            );
        }
    }
}
