// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session's one table set (L3): every declaration the session makes and every get it waits
//! on, each in exactly one row of one table (`docs/c-abi-l3-tables.md`, `docs/c-abi-architecture.md`
//! P1, P3, P10, P11).
//!
//! # The tables
//!
//! Each table is a [`SlotMap`] of the session's storage policy, bounded by the build's `caps` and,
//! below that, by the value of its limit the session's open resolved ([`TableRows`]): the key
//! expressions the session declares, its subscribers, queryables, liveliness tokens and liveliness
//! subscribers, the Interests it holds open, its publishers' and queriers' write filters, its
//! matching listeners and its pending gets. A row is named by its table's [`Handle`]; the numbers
//! the wire carries (entity ids, key expression ids, request ids) are minted here, once.
//!
//! # Keys
//!
//! A row keeps its key as the policy keeps one (the session's key arena on the lent policy). An
//! entity that names a key expression declaration of the session's holds that declaration's row
//! ([`KeyForm::prefix`]) instead of a copy of its id and suffix: its wire form is read off both
//! ([`SessionTables::wire_of`]), and the declaration is retracted when its last holder goes. A
//! write filter keeps no key: it reads the key of the Interest it holds, which every filter of one
//! kind on one key shares, and a matching listener, declared on a filter, reads its filter's.
//!
//! # Refusals
//!
//! A declaration is refused, as a [`RegisterError`], in this order and with nothing taken: its
//! table is at its bound, then its key is not kept (too long, or no room in the key arena), then
//! the entity ids are spent. A refused declaration hands its callback back ([`Refused`]) so the
//! caller drops it where it holds no lock.
//!
//! # Callbacks
//!
//! A row owns its callback, of the type the build's [`RowCallbacks`] names. A call of it pins the
//! row's latch (`begin_*`, [`RowCallback`]); a row undeclared while a call of it runs leaves every
//! lookup at once and is let go of by the call that ends last (`release_*`), after it (P11).
//!
//! # What a peer declared
//!
//! The faces' own tables (`peer_tables`) keep what each peer declared; these tables ask them
//! through [`PeerDeclarations`] when a write filter or a matching listener is judged.

use core::cell::Cell;
use core::fmt;

use crate::bounded::{
    Arena, CapacityFull, KeyBacking, KeyMaker, KeyUnkept, LendRefused, Lent, Profile, Storage,
};
use crate::caps;
use crate::key_arena::{KeySpace, LentKeys};
use crate::keyexpr_match::{keyexpr_intersects, KeyFacts};
use crate::locality::Locality;
use crate::named_key::{NamedKey, Prefix};
use crate::pubsub::{
    any_local_match, fire_into_memoized, scan_subscribers, MatchMemo, RowRef, SubscriberRows,
};
#[cfg(feature = "storage-profile")]
use crate::query::any_local_queryable;
#[cfg(feature = "alloc")]
use crate::query::stage_queryable_interest;
use crate::query::{fire_queryables, QueryableRef, QueryableRows};
use crate::registry_error::RegisterError;
use crate::row_callback::RowCallback;
use crate::sink::RowAccess;
use crate::slot_map::{Handle, Removal, SlotMap};
use crate::wire_id::{EntityId, ExprId, RequestId};
use crate::wire_key::MappedId;

/// The markers that keep one table's handles from being taken by another.
pub mod kind {
    /// A key expression the session declares.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Keyexpr {}
    /// A subscriber of the session's.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Subscriber {}
    /// A queryable of the session's.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Queryable {}
    /// A liveliness token of the session's.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Token {}
    /// A liveliness subscriber of the session's.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum LivelinessSubscriber {}
    /// An Interest the session holds open.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Interest {}
    /// A write filter of a publisher or a querier.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum WriteFilter {}
    /// A matching listener.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum MatchingListener {}
    /// A get the session waits on.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PendingGet {}
}

/// A key expression declaration's row.
pub type KeyexprHandle = Handle<kind::Keyexpr>;
/// A subscriber's row.
pub type SubscriberHandle = Handle<kind::Subscriber>;
/// A queryable's row.
pub type QueryableHandle = Handle<kind::Queryable>;
/// A liveliness token's row.
pub type TokenHandle = Handle<kind::Token>;
/// A liveliness subscriber's row.
pub type LivelinessSubscriberHandle = Handle<kind::LivelinessSubscriber>;
/// An Interest's row.
pub type InterestHandle = Handle<kind::Interest>;
/// A write filter's row.
pub type WriteFilterHandle = Handle<kind::WriteFilter>;
/// A matching listener's row.
pub type MatchingListenerHandle = Handle<kind::MatchingListener>;
/// A pending get's row.
pub type PendingGetHandle = Handle<kind::PendingGet>;

/// A face of the session, as its engine names it: the link a get was asked on.
pub type FaceId = u64;

/// The build's bound of the write filters: a publisher's and a querier's each.
pub const FILTER_ROWS: usize = caps::MAX_PUBLISHERS.saturating_add(caps::MAX_QUERIERS);

/// The build's bound of the Interests: one for each write filter at most, whose matching listeners
/// read its own.
pub const INTEREST_ROWS: usize = FILTER_ROWS;

/// What a write filter or a matching listener counts: the subscribers, or the queryables, complete
/// ones alone where the querier's target requires them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plane {
    /// The subscribers: a publisher's filter and its listeners.
    Subscribers,
    /// The queryables: a querier's filter and its listeners.
    Queryables {
        /// Whether only a complete queryable whose key includes the querier's counts.
        complete_required: bool,
    },
}

impl Plane {
    /// The kind of the Interest that asks about this plane.
    pub fn interest_kind(self) -> InterestKind {
        match self {
            Self::Subscribers => InterestKind::Subscribers,
            Self::Queryables { .. } => InterestKind::Queryables,
        }
    }
}

/// What an Interest asks a peer about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterestKind {
    /// Its subscribers.
    Subscribers,
    /// Its queryables.
    Queryables,
}

/// The callbacks the rows own, one type for each kind of row that has one, chosen once for a
/// build: a C function, its context and its drop, or a shared Rust closure.
pub trait RowCallbacks {
    /// A subscriber's.
    type Subscriber: RowCallback;
    /// A queryable's.
    type Queryable: RowCallback;
    /// A liveliness subscriber's.
    type LivelinessSubscriber: RowCallback;
    /// A matching listener's.
    type Matching: RowCallback;
    /// A pending get's: what each of its replies is handed to, and its end.
    type Reply: RowCallback;
}

/// What the faces' tables answer about what their peers declared.
pub trait PeerDeclarations {
    /// Whether any face's peer declared an entity `plane` counts on a key that reaches `key`.
    fn declares(&self, plane: Plane, key: &str) -> bool;

    /// A count that moves whenever any face's peer tables change: an answer of [`Self::declares`]
    /// taken while this read the same still holds.
    fn written(&self) -> u64;
}

/// A session with no peer: nothing is declared, and nothing ever changes.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPeers;

impl PeerDeclarations for NoPeers {
    fn declares(&self, _plane: Plane, _key: &str) -> bool {
        false
    }

    fn written(&self) -> u64 {
        0
    }
}

/// How an entity's declaration names its key on the wire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyForm {
    /// The session's key expression declaration the key starts with, named by its id and the rest
    /// of the key. One that names no live declaration, or one the key does not start with, is not
    /// used: the key goes on the wire whole.
    pub prefix: Option<KeyexprHandle>,
    /// Whether the retraction names the key beside the id.
    pub names_key: bool,
}

/// An entity's key, as its row keeps it.
#[derive(Debug)]
pub struct EntityKey<Key> {
    key: Key,
    prefix: Option<KeyexprHandle>,
    names_key: bool,
}

impl<Key: KeyBacking> EntityKey<Key> {
    /// The key.
    pub fn as_str(&self) -> &str {
        self.key.as_str()
    }

    /// The declaration the key is named by on the wire, if any.
    pub fn prefix(&self) -> Option<KeyexprHandle> {
        self.prefix
    }

    /// Whether the retraction names the key beside the id.
    pub fn names_key(&self) -> bool {
        self.names_key
    }
}

/// An entity's key as the wire carries it: a key expression declaration's id, `0` for none, and
/// what follows the declared prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireForm<'a> {
    /// The declaration's id, `0` when the key goes whole.
    pub mapping: ExprId,
    /// The rest of the key.
    pub suffix: &'a str,
}

/// A key expression the session declares.
#[derive(Debug)]
pub struct KeyexprRow<Key> {
    id: ExprId,
    key: Key,
    holds: u16,
}

impl<Key: KeyBacking> KeyexprRow<Key> {
    /// The id the wire names it by.
    pub fn id(&self) -> ExprId {
        self.id
    }

    /// The key.
    pub fn key(&self) -> &str {
        self.key.as_str()
    }

    /// Its holders: the declarations of the program and the entities that name it.
    pub fn holds(&self) -> u16 {
        self.holds
    }
}

/// A subscriber of the session's.
#[derive(Debug)]
pub struct SubscriberRow<Key, Cb> {
    id: EntityId,
    key: EntityKey<Key>,
    /// What [`KeyFacts`] reads of the key, read once at the declaration so that a sample matched
    /// against it does not scan the key again.
    facts: KeyFacts,
    origin: Locality,
    callback: Cb,
}

impl<Key, Cb> SubscriberRow<Key, Cb> {
    /// Its entity id.
    pub fn id(&self) -> EntityId {
        self.id
    }

    /// Its key.
    pub fn key(&self) -> &EntityKey<Key> {
        &self.key
    }

    /// The origins of the samples it hears.
    pub fn origin(&self) -> Locality {
        self.origin
    }

    /// Its callback.
    pub fn callback(&self) -> &Cb {
        &self.callback
    }

    /// Its callback, the row let go of.
    pub fn into_callback(self) -> Cb {
        self.callback
    }
}

/// A queryable of the session's.
#[derive(Debug)]
pub struct QueryableRow<Key, Cb> {
    id: EntityId,
    key: EntityKey<Key>,
    /// What [`KeyFacts`] reads of the key, read once at the declaration so that a query matched
    /// against it does not scan the key again.
    facts: KeyFacts,
    origin: Locality,
    complete: bool,
    callback: Cb,
}

impl<Key, Cb> QueryableRow<Key, Cb> {
    /// Its entity id.
    pub fn id(&self) -> EntityId {
        self.id
    }

    /// Its key.
    pub fn key(&self) -> &EntityKey<Key> {
        &self.key
    }

    /// The origins of the queries it answers.
    pub fn origin(&self) -> Locality {
        self.origin
    }

    /// Whether it answers for its whole key.
    pub fn complete(&self) -> bool {
        self.complete
    }

    /// Its callback.
    pub fn callback(&self) -> &Cb {
        &self.callback
    }

    /// Its callback, the row let go of.
    pub fn into_callback(self) -> Cb {
        self.callback
    }
}

/// A liveliness token of the session's.
#[derive(Debug)]
pub struct TokenRow<Key> {
    id: EntityId,
    key: EntityKey<Key>,
}

impl<Key> TokenRow<Key> {
    /// Its entity id.
    pub fn id(&self) -> EntityId {
        self.id
    }

    /// Its key.
    pub fn key(&self) -> &EntityKey<Key> {
        &self.key
    }
}

/// A liveliness subscriber of the session's: its entity id is its Interest's.
#[derive(Debug)]
pub struct LivelinessSubscriberRow<Key, Cb> {
    id: EntityId,
    key: EntityKey<Key>,
    history: bool,
    callback: Cb,
}

impl<Key, Cb> LivelinessSubscriberRow<Key, Cb> {
    /// Its entity id, which its Interest carries.
    pub fn id(&self) -> EntityId {
        self.id
    }

    /// Its key.
    pub fn key(&self) -> &EntityKey<Key> {
        &self.key
    }

    /// Whether it asked for the tokens alive when it was declared.
    pub fn history(&self) -> bool {
        self.history
    }

    /// Its callback.
    pub fn callback(&self) -> &Cb {
        &self.callback
    }

    /// Its callback, the row let go of.
    pub fn into_callback(self) -> Cb {
        self.callback
    }
}

/// An Interest the session holds open, and how many filters and listeners hold it.
#[derive(Debug)]
pub struct InterestRow<Key> {
    id: EntityId,
    kind: InterestKind,
    key: Key,
    holds: u16,
}

impl<Key: KeyBacking> InterestRow<Key> {
    /// The id the Interest carries.
    pub fn id(&self) -> EntityId {
        self.id
    }

    /// What it asks about.
    pub fn kind(&self) -> InterestKind {
        self.kind
    }

    /// The key it asks about.
    pub fn key(&self) -> &str {
        self.key.as_str()
    }

    /// How many filters and listeners hold it.
    pub fn holds(&self) -> u16 {
        self.holds
    }
}

/// A publisher's or a querier's write filter: whether a put or a get is sent at all.
#[derive(Debug)]
pub struct WriteFilterRow {
    plane: Plane,
    interest: InterestHandle,
    count_local: bool,
    /// What the peers answered, with the count of [`PeerDeclarations::written`] it was read at.
    verdict: Cell<Option<(u64, bool)>>,
}

impl WriteFilterRow {
    /// What it counts.
    pub fn plane(&self) -> Plane {
        self.plane
    }

    /// The Interest it holds, whose key is its key.
    pub fn interest(&self) -> InterestHandle {
        self.interest
    }

    /// Whether the session's own entities count.
    pub fn count_local(&self) -> bool {
        self.count_local
    }
}

/// A matching listener: told when what its publisher or querier reaches starts or stops matching.
/// It is declared on that publisher's or querier's write filter, whose row owns it: it reads the
/// filter's Interest, and goes with the filter ([`SessionTables::undeclare_write_filter`]).
#[derive(Debug)]
pub struct MatchingRow<Cb> {
    filter: WriteFilterHandle,
    plane: Plane,
    interest: InterestHandle,
    count_local: bool,
    last: bool,
    callback: Cb,
}

impl<Cb> MatchingRow<Cb> {
    /// The write filter it is declared on.
    pub fn filter(&self) -> WriteFilterHandle {
        self.filter
    }

    /// What it counts.
    pub fn plane(&self) -> Plane {
        self.plane
    }

    /// The Interest it holds, whose key is its key.
    pub fn interest(&self) -> InterestHandle {
        self.interest
    }

    /// Whether the session's own entities count.
    pub fn count_local(&self) -> bool {
        self.count_local
    }

    /// The verdict it was last told.
    pub fn last(&self) -> bool {
        self.last
    }

    /// Its callback.
    pub fn callback(&self) -> &Cb {
        &self.callback
    }

    /// Its callback, the row let go of.
    pub fn into_callback(self) -> Cb {
        self.callback
    }
}

/// A get the session waits on: the request id its legs carry, the key its replies must
/// intersect, how many legs still owe their Final, and when it ends unanswered.
#[derive(Debug)]
pub struct PendingGetRow<Key, Cb> {
    request: RequestId,
    /// `None` for a get that takes a reply on any key (pico's `_anyke`).
    gate: Option<Key>,
    legs: u16,
    deadline: u64,
    callback: Cb,
}

impl<Key: KeyBacking, Cb> PendingGetRow<Key, Cb> {
    /// The request id its query carries on every leg.
    pub fn request(&self) -> RequestId {
        self.request
    }

    /// The key a reply must intersect, `None` when any key is taken.
    pub fn gate(&self) -> Option<&str> {
        self.gate.as_ref().map(KeyBacking::as_str)
    }

    /// Whether `reply` is one of this get's to hand its callback: an Err always, a Put or a Del
    /// on a key the gate intersects.
    pub fn admits(&self, reply: &dyn crate::reply_sink::ReplyView) -> bool {
        crate::reply_acceptance::admits_reply(self.gate(), reply)
    }

    /// How many legs still owe their Final.
    pub fn legs(&self) -> u16 {
        self.legs
    }

    /// When it ends unanswered, in the driver's clock.
    pub fn deadline(&self) -> u64 {
        self.deadline
    }

    /// Its callback.
    pub fn callback(&self) -> &Cb {
        &self.callback
    }

    /// Its callback, the row let go of.
    pub fn into_callback(self) -> Cb {
        self.callback
    }
}

/// The key expression declarations' table.
pub type Keyexprs<P> =
    SlotMap<kind::Keyexpr, KeyexprRow<<P as Storage>::Key>, { caps::MAX_DECLARED_KEYEXPRS }, P>;
/// A subscriber's row of a build's tables.
pub type Subscriber<F, P> = SubscriberRow<<P as Storage>::Key, <F as RowCallbacks>::Subscriber>;
/// The subscribers' table.
pub type Subscribers<F, P> =
    SlotMap<kind::Subscriber, Subscriber<F, P>, { caps::MAX_SUBSCRIPTIONS }, P>;
/// A queryable's row of a build's tables.
pub type Queryable<F, P> = QueryableRow<<P as Storage>::Key, <F as RowCallbacks>::Queryable>;
/// The queryables' table.
pub type Queryables<F, P> = SlotMap<kind::Queryable, Queryable<F, P>, { caps::MAX_QUERYABLES }, P>;
/// The liveliness tokens' table.
pub type Tokens<P> =
    SlotMap<kind::Token, TokenRow<<P as Storage>::Key>, { caps::MAX_LOCAL_TOKENS }, P>;
/// A liveliness subscriber's row of a build's tables.
pub type LivelinessSubscriber<F, P> =
    LivelinessSubscriberRow<<P as Storage>::Key, <F as RowCallbacks>::LivelinessSubscriber>;
/// The liveliness subscribers' table.
pub type LivelinessSubscribers<F, P> = SlotMap<
    kind::LivelinessSubscriber,
    LivelinessSubscriber<F, P>,
    { caps::MAX_LIVELINESS_SUBSCRIPTIONS },
    P,
>;
/// The Interests' table.
pub type Interests<P> = SlotMap<kind::Interest, InterestRow<<P as Storage>::Key>, INTEREST_ROWS, P>;
/// The write filters' table.
pub type WriteFilters<P> = SlotMap<kind::WriteFilter, WriteFilterRow, FILTER_ROWS, P>;
/// A matching listener's row of a build's tables.
pub type Matching<F> = MatchingRow<<F as RowCallbacks>::Matching>;
/// The matching listeners' table.
pub type MatchingListeners<F, P> =
    SlotMap<kind::MatchingListener, Matching<F>, { caps::MAX_MATCHING_LISTENERS }, P>;
/// A pending get's row of a build's tables.
pub type PendingGet<F, P> = PendingGetRow<<P as Storage>::Key, <F as RowCallbacks>::Reply>;
/// The pending gets' table.
pub type PendingGets<F, P> =
    SlotMap<kind::PendingGet, PendingGet<F, P>, { caps::MAX_PENDING_QUERIES }, P>;

/// How many rows each table holds: the values of the limits the session's open resolved, each
/// under the build's bound.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TableRows {
    /// `MAX_DECLARED_KEYEXPRS`.
    pub keyexprs: usize,
    /// `MAX_SUBSCRIPTIONS`.
    pub subscribers: usize,
    /// `MAX_QUERYABLES`.
    pub queryables: usize,
    /// `MAX_LOCAL_TOKENS`.
    pub tokens: usize,
    /// `MAX_LIVELINESS_SUBSCRIPTIONS`.
    pub liveliness_subscribers: usize,
    /// `MAX_PUBLISHERS` and `MAX_QUERIERS` together.
    pub write_filters: usize,
    /// `MAX_MATCHING_LISTENERS`.
    pub matching_listeners: usize,
    /// `MAX_PENDING_QUERIES`.
    pub pending_gets: usize,
    /// `MAX_PENDING_REPLIES`: the replies the consolidating gets hold back, of all of them.
    pub held_replies: usize,
}

impl TableRows {
    /// The Interests: one for each write filter at most, so a filter the tables have room for
    /// always finds room for its Interest; a matching listener reads its filter's.
    pub fn interests(&self) -> usize {
        self.write_filters
    }
}

/// A declaration made: its row, and the id the wire names it by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Declared<K> {
    /// Its row.
    pub handle: Handle<K>,
    /// Its entity id.
    pub id: EntityId,
}

/// A key expression declared, or found declared already and held once more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyexprDeclared {
    /// Its row.
    pub handle: KeyexprHandle,
    /// The id the wire names it by.
    pub id: ExprId,
    /// Whether it is new, and so to be declared on every link.
    pub new: bool,
}

/// A declaration refused: why, and the callback it was handed, for the caller to drop.
pub struct Refused<C> {
    /// Why.
    pub why: RegisterError,
    /// The callback the declaration was handed.
    pub callback: C,
}

impl<C> fmt::Debug for Refused<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Refused").field("why", &self.why).finish()
    }
}

/// An entity undeclared.
pub struct Undeclared<R> {
    /// The id its retraction names.
    pub id: EntityId,
    /// The row, for the caller to drop where it holds no lock; `None` while a call of its
    /// callback runs, whose last unpin hands it back.
    pub row: Option<R>,
    /// The key expression declaration the entity held last, retracted with it: its id goes on
    /// the wire after the entity's retraction.
    pub keyexpr: Option<ExprId>,
}

/// A write filter or a matching listener declared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watching<K> {
    /// Its row.
    pub handle: Handle<K>,
    /// The id of a new Interest to send, `None` when it shares one already open.
    pub interest: Option<EntityId>,
}

/// A write filter or a matching listener undeclared.
pub struct Unwatched<R> {
    /// The row, as [`Undeclared::row`].
    pub row: Option<R>,
    /// The id of the Interest it held last, whose Final goes on the wire.
    pub interest_final: Option<EntityId>,
}

/// What ending one leg of a get left of it.
#[derive(Debug)]
pub enum LegEnded<R> {
    /// Other legs still owe their Final: how many.
    Owed(u16),
    /// That was the last leg: the get is over, its row as [`SessionTables::end_get`] hands it.
    Over(Removal<R>),
}

/// The bytes the table of held replies takes of an arena for `rows`; none in a build that holds
/// none (no `storage-profile`).
#[cfg(feature = "storage-profile")]
fn held_arena_bytes(rows: usize) -> Option<usize> {
    crate::reply_hold::HeldReplies::<PendingGetHandle, Lent>::arena_bytes(rows)
}

/// See the `storage-profile` form.
#[cfg(not(feature = "storage-profile"))]
fn held_arena_bytes(_rows: usize) -> Option<usize> {
    Some(0)
}

/// A get begun: its row and the request id its query carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetBegun {
    /// Its row.
    pub handle: PendingGetHandle,
    /// The request id.
    pub request: RequestId,
}

/// The session's one table set. See the module.
pub struct SessionTables<F: RowCallbacks, P: Storage = Profile> {
    keys: P::Keys,
    /// The next entity id, `None` once every one has been handed out.
    next_entity: Option<EntityId>,
    next_expr: ExprId,
    next_request: RequestId,
    /// Moves after every subscriber declared or undeclared ([`crate::pubsub::LocalSubscribers::epoch`]).
    subscriber_epoch: u64,
    /// Which subscribers the keys delivered lately reached, valid at one `subscriber_epoch`: the
    /// subscriber table's receive match cache, over these rows' places.
    memo: MatchMemo<P>,
    keyexprs: Keyexprs<P>,
    subscribers: Subscribers<F, P>,
    queryables: Queryables<F, P>,
    tokens: Tokens<P>,
    liveliness_subscribers: LivelinessSubscribers<F, P>,
    interests: Interests<P>,
    write_filters: WriteFilters<P>,
    matching: MatchingListeners<F, P>,
    pending_gets: PendingGets<F, P>,
    /// What the consolidating gets hold back (`consolidate_reply`).
    #[cfg(feature = "storage-profile")]
    held: crate::reply_hold::HeldReplies<PendingGetHandle, P>,
}

/// The text of a key a row keeps.
fn text<Key: KeyBacking>(key: &Key) -> &str {
    key.as_str()
}

/// Whether an entity that hears `origin` hears what came from the session itself (`local`) or
/// from a peer.
fn admits(origin: Locality, local: bool) -> bool {
    if local {
        origin.allows_local()
    } else {
        origin.allows_remote()
    }
}

/// Whether a queryable on `queryable`, `complete` or not, answers a query on `key`: by
/// intersection, or, where only complete ones count, complete and including the key.
fn answers(queryable: &str, complete: bool, key: &str, complete_required: bool) -> bool {
    if complete_required {
        complete && includes(queryable, key)
    } else {
        keyexpr_intersects(queryable, key)
    }
}

#[cfg(feature = "keyexpr-includes")]
fn includes(superset: &str, subset: &str) -> bool {
    crate::keyexpr_match::keyexpr_includes(superset, subset)
}

/// Without the inclusion matcher a key includes only itself: never an inclusion that is not one.
#[cfg(not(feature = "keyexpr-includes"))]
fn includes(superset: &str, subset: &str) -> bool {
    superset == subset
}

/// A key a table refused to keep, as the declaration's refusal.
fn unkept(why: KeyUnkept) -> RegisterError {
    match why {
        KeyUnkept::TooLong => RegisterError::KeyexprTooLong,
        KeyUnkept::NoRoom => RegisterError::TableFull,
    }
}

/// What a declared entity's row says of its declaration.
trait Entity {
    fn entity_id(&self) -> EntityId;
    fn key_prefix(&self) -> Option<KeyexprHandle>;
    /// Retire what the row calls ([`RowCallback::retire`]): `true` when no call of it runs.
    fn retire(&self) -> bool;
}

impl<Key, Cb: RowCallback> Entity for SubscriberRow<Key, Cb> {
    fn entity_id(&self) -> EntityId {
        self.id
    }
    fn key_prefix(&self) -> Option<KeyexprHandle> {
        self.key.prefix
    }
    fn retire(&self) -> bool {
        self.callback.retire()
    }
}

impl<Key, Cb: RowCallback> Entity for QueryableRow<Key, Cb> {
    fn entity_id(&self) -> EntityId {
        self.id
    }
    fn key_prefix(&self) -> Option<KeyexprHandle> {
        self.key.prefix
    }
    fn retire(&self) -> bool {
        self.callback.retire()
    }
}

impl<Key> Entity for TokenRow<Key> {
    fn entity_id(&self) -> EntityId {
        self.id
    }
    fn key_prefix(&self) -> Option<KeyexprHandle> {
        self.key.prefix
    }
    fn retire(&self) -> bool {
        true
    }
}

impl<Key, Cb: RowCallback> Entity for LivelinessSubscriberRow<Key, Cb> {
    fn entity_id(&self) -> EntityId {
        self.id
    }
    fn key_prefix(&self) -> Option<KeyexprHandle> {
        self.key.prefix
    }
    fn retire(&self) -> bool {
        self.callback.retire()
    }
}

/// Take one hold of the declaration `handle` names off it: its id when that was the last, and the
/// declaration is gone.
fn release_keyexpr<P: Storage>(
    keyexprs: &mut Keyexprs<P>,
    handle: KeyexprHandle,
) -> Option<ExprId> {
    let row = keyexprs.get_mut(handle)?;
    row.holds = row.holds.saturating_sub(1);
    if row.holds > 0 {
        return None;
    }
    let id = row.id;
    let _ = keyexprs.remove(handle);
    Some(id)
}

/// Remove the entity `handle` names from `table`, and its hold of the declaration its key names.
fn undeclare_entity<K, R: Entity, P: Storage, const N: usize>(
    table: &mut SlotMap<K, R, N, P>,
    keyexprs: &mut Keyexprs<P>,
    handle: Handle<K>,
) -> Option<Undeclared<R>> {
    let (id, prefix, idle) = table
        .get(handle)
        .map(|row| (row.entity_id(), row.key_prefix(), row.retire()))?;
    // A row a call of which runs is kept, retired, for the call that ends last to let go of
    // (`release_*`).
    if !idle {
        let _held = table.pin(handle)?;
    }
    let removal = table.remove(handle)?;
    let keyexpr = prefix.and_then(|prefix| release_keyexpr(keyexprs, prefix));
    Some(Undeclared {
        id,
        row: removal.taken(),
        keyexpr,
    })
}

/// What a declaration reads and moves besides its own table.
struct Declaring<'a, P: Storage> {
    keys: &'a P::Keys,
    keyexprs: &'a mut Keyexprs<P>,
    next_entity: &'a mut Option<EntityId>,
}

impl<P: Storage> Declaring<'_, P> {
    /// `text` kept as a row keeps it, named on the wire as `form` asks where it can be.
    fn entity_key(&self, text: &str, form: KeyForm) -> Result<EntityKey<P::Key>, RegisterError> {
        let key = KeyMaker::shared(self.keys, text).map_err(unkept)?;
        let prefix = form.prefix.filter(|&prefix| {
            self.keyexprs.get(prefix).is_some_and(|row| {
                row.holds < u16::MAX && text.starts_with(KeyBacking::as_str(&row.key))
            })
        });
        Ok(EntityKey {
            key,
            prefix,
            names_key: form.names_key,
        })
    }

    /// The next entity id.
    fn mint(&mut self) -> Result<EntityId, RegisterError> {
        let id = self.next_entity.ok_or(RegisterError::IdsExhausted)?;
        *self.next_entity = id.checked_add(1);
        Ok(id)
    }

    /// Hold the declaration `prefix` names once more.
    fn hold(&mut self, prefix: Option<KeyexprHandle>) {
        if let Some(row) = prefix.and_then(|prefix| self.keyexprs.get_mut(prefix)) {
            row.holds = row.holds.saturating_add(1);
        }
    }

    /// Declare an entity on `text` into `table`: the row `make` builds of its id, its key and
    /// `callback`, or the refusal with `callback` back (`back` takes it out of a row the table
    /// refused).
    fn declare<K, R, C, const N: usize>(
        mut self,
        table: &mut SlotMap<K, R, N, P>,
        text: &str,
        form: KeyForm,
        callback: C,
        make: impl FnOnce(EntityId, EntityKey<P::Key>, C) -> R,
        back: impl FnOnce(R) -> C,
    ) -> Result<Declared<K>, Refused<C>> {
        if table.is_full() {
            return Err(Refused {
                why: RegisterError::TableFull,
                callback,
            });
        }
        let key = match self.entity_key(text, form) {
            Ok(key) => key,
            Err(why) => return Err(Refused { why, callback }),
        };
        let id = match self.mint() {
            Ok(id) => id,
            Err(why) => return Err(Refused { why, callback }),
        };
        let prefix = key.prefix;
        match table.insert(make(id, key, callback)) {
            Ok(handle) => {
                self.hold(prefix);
                Ok(Declared { handle, id })
            }
            Err(CapacityFull(row)) => Err(Refused {
                why: RegisterError::TableFull,
                callback: back(row),
            }),
        }
    }
}

impl<F: RowCallbacks, P: Storage> SessionTables<F, P> {
    /// Tables of no rows, each holding at most the build's bound. On the lent policy tables made
    /// so were lent no rows and refuse every declaration; [`SessionTables::lent`] makes the ones a
    /// session holds.
    pub fn new() -> Self {
        Self {
            keys: Default::default(),
            next_entity: Some(1),
            next_expr: 1,
            next_request: 0,
            subscriber_epoch: 0,
            memo: MatchMemo::new(
                <crate::limits::MatchMemoSlots as crate::limit_binding::LimitSpec>::DEFAULT,
            ),
            keyexprs: SlotMap::new(),
            subscribers: SlotMap::new(),
            queryables: SlotMap::new(),
            tokens: SlotMap::new(),
            liveliness_subscribers: SlotMap::new(),
            interests: SlotMap::new(),
            write_filters: SlotMap::new(),
            matching: SlotMap::new(),
            pending_gets: SlotMap::new(),
            #[cfg(feature = "storage-profile")]
            held: crate::reply_hold::HeldReplies::default(),
        }
    }

    /// Size the subscribers' receive match cache to the `MATCH_MEMO_SLOTS` the session's open
    /// resolved, `0` leaving it out, as [`crate::pubsub::SubscriberTable::limit_memo_to`] does: the
    /// keys it remembered are forgotten, and a table of the fixed policy keeps the build's
    /// `MATCH_MEMO_FIXED_SLOTS`.
    pub fn limit_memo_to(&mut self, slots: usize) {
        if !P::ENFORCES_CAPACITY {
            self.memo = MatchMemo::new(slots);
        }
    }

    /// How many distinct keys the subscribers' receive match cache remembers at once.
    pub fn memo_slot_count(&self) -> usize {
        self.memo.slot_count()
    }

    /// Hold each table to the rows `rows` gives it, under the build's bound.
    pub fn limit_to(&mut self, rows: &TableRows) {
        self.keyexprs.limit_to(rows.keyexprs);
        self.subscribers.limit_to(rows.subscribers);
        self.queryables.limit_to(rows.queryables);
        self.tokens.limit_to(rows.tokens);
        self.liveliness_subscribers
            .limit_to(rows.liveliness_subscribers);
        self.interests.limit_to(rows.interests());
        self.write_filters.limit_to(rows.write_filters);
        self.matching.limit_to(rows.matching_listeners);
        self.pending_gets.limit_to(rows.pending_gets);
    }

    // ---- key expressions -------------------------------------------------------------------

    /// Declare `key`, or hold the declaration of it the session made already once more.
    pub fn declare_keyexpr(&mut self, key: &str) -> Result<KeyexprDeclared, RegisterError> {
        self.declare_keyexpr_where(key, false, |_| true)
    }

    /// Declare `key` under an id `usable` admits: with `apart` a declaration of its own whatever
    /// the session holds, otherwise the declaration of it the session made already, held once more,
    /// when there is one. Refused with [`RegisterError::IdsExhausted`] when no id is left that is
    /// neither declared nor refused by `usable` (an id a dictionary of shared key ids names).
    pub fn declare_keyexpr_where(
        &mut self,
        key: &str,
        apart: bool,
        usable: impl Fn(ExprId) -> bool,
    ) -> Result<KeyexprDeclared, RegisterError> {
        let found = if apart {
            None
        } else {
            self.keyexprs
                .iter()
                .find(|(_, row)| text(&row.key) == key)
                .map(|(handle, row)| (handle, row.id, row.holds))
        };
        if let Some((handle, id, holds)) = found {
            let holds = holds.checked_add(1).ok_or(RegisterError::TableFull)?;
            if let Some(row) = self.keyexprs.get_mut(handle) {
                row.holds = holds;
            }
            return Ok(KeyexprDeclared {
                handle,
                id,
                new: false,
            });
        }
        if self.keyexprs.is_full() {
            return Err(RegisterError::TableFull);
        }
        let kept = KeyMaker::shared(&self.keys, key).map_err(unkept)?;
        let id = self.mint_expr(usable).ok_or(RegisterError::IdsExhausted)?;
        let handle = self
            .keyexprs
            .insert(KeyexprRow {
                id,
                key: kept,
                holds: 1,
            })
            .map_err(|_| RegisterError::TableFull)?;
        Ok(KeyexprDeclared {
            handle,
            id,
            new: true,
        })
    }

    /// Let go of one hold of the declaration `handle` names: its id when that was the last, for
    /// its retraction to go on the wire.
    pub fn undeclare_keyexpr(&mut self, handle: KeyexprHandle) -> Option<ExprId> {
        release_keyexpr(&mut self.keyexprs, handle)
    }

    /// Take one more hold of the declaration `handle` names, for a holder of it that is copied,
    /// with nothing on the wire: `false`, changing nothing, when it names no row now or the row
    /// holds as many as its count holds.
    pub fn retain_keyexpr(&mut self, handle: KeyexprHandle) -> bool {
        let Some(row) = self.keyexprs.get_mut(handle) else {
            return false;
        };
        match row.holds.checked_add(1) {
            Some(holds) => {
                row.holds = holds;
                true
            }
            None => false,
        }
    }

    /// Retract the declaration `handle` names whatever holds it: its id, for its retraction to go
    /// on the wire. An entity that named its key by it names it whole from here on
    /// ([`Self::wire_of`]).
    pub fn retract_keyexpr(&mut self, handle: KeyexprHandle) -> Option<ExprId> {
        let id = self.keyexprs.get(handle)?.id;
        let _ = self.keyexprs.remove(handle);
        Some(id)
    }

    /// The declaration the wire names by `id`.
    pub fn keyexpr_by_id(&self, id: ExprId) -> Option<KeyexprHandle> {
        self.keyexprs
            .iter()
            .find(|(_, row)| row.id == id)
            .map(|(handle, _)| handle)
    }

    /// The next key expression id: from 1, past any still declared and any `usable` refuses;
    /// `None` when every id is one or the other.
    fn mint_expr(&mut self, usable: impl Fn(ExprId) -> bool) -> Option<ExprId> {
        for _ in 0..=usize::from(ExprId::MAX) {
            let id = self.next_expr.max(1);
            self.next_expr = id.wrapping_add(1);
            if usable(id) && !self.keyexprs.iter().any(|(_, row)| row.id == id) {
                return Some(id);
            }
        }
        None
    }

    // ---- entity ids ------------------------------------------------------------------------

    /// The next entity id, for an entity the session numbers and keeps no row of here (a
    /// publisher, a querier, a get's Interest); `None` once every one has been handed out.
    pub fn take_entity_id(&mut self) -> Option<EntityId> {
        let id = self.next_entity?;
        self.next_entity = id.checked_add(1);
        Some(id)
    }

    /// The entity id the next declaration takes, `None` once every one has been handed out.
    pub fn next_entity_id(&self) -> Option<EntityId> {
        self.next_entity
    }

    /// Hand out entity ids from `next` on, or none with `None`: for a host that carries a
    /// session's numbering over, and for a test that reaches the end of the space.
    pub fn entity_ids_from(&mut self, next: Option<EntityId>) {
        self.next_entity = next;
    }

    /// `key` as the wire carries it: by the declaration its form names where it still stands,
    /// whole otherwise.
    pub fn wire_of<'k>(&self, key: &'k EntityKey<P::Key>) -> WireForm<'k> {
        let whole = text(&key.key);
        let literal = WireForm {
            mapping: 0,
            suffix: whole,
        };
        let Some(row) = key.prefix.and_then(|prefix| self.keyexprs.get(prefix)) else {
            return literal;
        };
        match whole.get(text(&row.key).len()..) {
            Some(suffix) => WireForm {
                mapping: row.id,
                suffix,
            },
            None => literal,
        }
    }

    /// The key `key` names as the session sends it: its whole text, named on the wire by the
    /// declaration its row holds while that declaration stands, and whole otherwise
    /// ([`Self::wire_of`]). `None` for an empty key, which no row keeps.
    pub fn named<'k>(&self, key: &'k EntityKey<P::Key>) -> Option<NamedKey<'k>> {
        let whole = text(&key.key);
        let declared = key
            .prefix
            .and_then(|prefix| self.keyexprs.get(prefix))
            .and_then(|row| Some(Prefix::of(MappedId::new(row.id)?, text(&row.key))));
        match declared {
            Some(prefix) => NamedKey::under(whole, prefix).or_else(|| NamedKey::literal(whole)),
            None => NamedKey::literal(whole),
        }
    }

    /// `key`, which the program names by the declaration the wire calls `id` (`0` for none), as
    /// the session sends it: named by that declaration while it stands and begins the key, and
    /// whole otherwise. `None` for an empty key.
    pub fn named_by<'k>(&self, key: &'k str, id: ExprId) -> Option<NamedKey<'k>> {
        let declared = MappedId::new(id).and_then(|mapped| {
            let handle = self.keyexpr_by_id(id)?;
            let row = self.keyexprs.get(handle)?;
            Some(Prefix::of(mapped, text(&row.key)))
        });
        match declared {
            Some(prefix) => NamedKey::under(key, prefix).or_else(|| NamedKey::literal(key)),
            None => NamedKey::literal(key),
        }
    }

    // ---- entities --------------------------------------------------------------------------

    /// Declare a subscriber on `key`, hearing what `origin` admits.
    pub fn declare_subscriber(
        &mut self,
        key: &str,
        origin: Locality,
        form: KeyForm,
        callback: F::Subscriber,
    ) -> Result<Declared<kind::Subscriber>, Refused<F::Subscriber>> {
        let declared = Declaring {
            keys: &self.keys,
            keyexprs: &mut self.keyexprs,
            next_entity: &mut self.next_entity,
        }
        .declare(
            &mut self.subscribers,
            key,
            form,
            callback,
            |id, key, callback| SubscriberRow {
                facts: KeyFacts::of(key.as_str()),
                id,
                key,
                origin,
                callback,
            },
            SubscriberRow::into_callback,
        )?;
        self.subscriber_epoch = self.subscriber_epoch.wrapping_add(1);
        Ok(declared)
    }

    /// Undeclare the subscriber `handle` names. The row leaves every lookup now and no call of it
    /// begins. When a call of its callback runs ([`Self::begin_subscriber`]) the row is not handed
    /// back here: the call that ends last lets it go ([`Self::release_subscriber`]), so the
    /// undeclaring caller returns only once `subscribers().holds_slot(handle)` is false, after the
    /// last call has returned and the row, with its callback, was dropped (P11). The same holds for
    /// every kind with a callback.
    pub fn undeclare_subscriber(
        &mut self,
        handle: SubscriberHandle,
    ) -> Option<Undeclared<Subscriber<F, P>>> {
        let undeclared = undeclare_entity(&mut self.subscribers, &mut self.keyexprs, handle)?;
        self.subscriber_epoch = self.subscriber_epoch.wrapping_add(1);
        Some(undeclared)
    }

    /// Declare a queryable on `key`, answering what `origin` admits, `complete` or not.
    pub fn declare_queryable(
        &mut self,
        key: &str,
        origin: Locality,
        complete: bool,
        form: KeyForm,
        callback: F::Queryable,
    ) -> Result<Declared<kind::Queryable>, Refused<F::Queryable>> {
        Declaring {
            keys: &self.keys,
            keyexprs: &mut self.keyexprs,
            next_entity: &mut self.next_entity,
        }
        .declare(
            &mut self.queryables,
            key,
            form,
            callback,
            |id, key, callback| QueryableRow {
                facts: KeyFacts::of(key.as_str()),
                id,
                key,
                origin,
                complete,
                callback,
            },
            QueryableRow::into_callback,
        )
    }

    /// Undeclare the queryable `handle` names.
    pub fn undeclare_queryable(
        &mut self,
        handle: QueryableHandle,
    ) -> Option<Undeclared<Queryable<F, P>>> {
        undeclare_entity(&mut self.queryables, &mut self.keyexprs, handle)
    }

    /// Declare a liveliness token on `key`.
    pub fn declare_token(
        &mut self,
        key: &str,
        form: KeyForm,
    ) -> Result<Declared<kind::Token>, RegisterError> {
        Declaring {
            keys: &self.keys,
            keyexprs: &mut self.keyexprs,
            next_entity: &mut self.next_entity,
        }
        .declare(
            &mut self.tokens,
            key,
            form,
            (),
            |id, key, ()| TokenRow { id, key },
            |_| (),
        )
        .map_err(|refused| refused.why)
    }

    /// Undeclare the liveliness token `handle` names.
    pub fn undeclare_token(&mut self, handle: TokenHandle) -> Option<Undeclared<TokenRow<P::Key>>> {
        undeclare_entity(&mut self.tokens, &mut self.keyexprs, handle)
    }

    /// Declare a liveliness subscriber on `key`, asking for the tokens alive now with `history`.
    pub fn declare_liveliness_subscriber(
        &mut self,
        key: &str,
        history: bool,
        form: KeyForm,
        callback: F::LivelinessSubscriber,
    ) -> Result<Declared<kind::LivelinessSubscriber>, Refused<F::LivelinessSubscriber>> {
        Declaring {
            keys: &self.keys,
            keyexprs: &mut self.keyexprs,
            next_entity: &mut self.next_entity,
        }
        .declare(
            &mut self.liveliness_subscribers,
            key,
            form,
            callback,
            |id, key, callback| LivelinessSubscriberRow {
                id,
                key,
                history,
                callback,
            },
            LivelinessSubscriberRow::into_callback,
        )
    }

    /// Undeclare the liveliness subscriber `handle` names: its id is its Interest's, whose Final
    /// goes on the wire.
    pub fn undeclare_liveliness_subscriber(
        &mut self,
        handle: LivelinessSubscriberHandle,
    ) -> Option<Undeclared<LivelinessSubscriber<F, P>>> {
        undeclare_entity(&mut self.liveliness_subscribers, &mut self.keyexprs, handle)
    }

    // ---- Interests, write filters and matching listeners ------------------------------------

    /// Hold an Interest of `kind` on `key`: the one open already, or a new one, whose id is
    /// handed back to be sent.
    fn hold_interest(
        &mut self,
        kind: InterestKind,
        key: &str,
    ) -> Result<(InterestHandle, Option<EntityId>), RegisterError> {
        let found = self
            .interests
            .iter()
            .find(|(_, row)| row.kind == kind && text(&row.key) == key)
            .map(|(handle, row)| (handle, row.holds));
        if let Some((handle, holds)) = found {
            let holds = holds.checked_add(1).ok_or(RegisterError::TableFull)?;
            if let Some(row) = self.interests.get_mut(handle) {
                row.holds = holds;
            }
            return Ok((handle, None));
        }
        if self.interests.is_full() {
            return Err(RegisterError::TableFull);
        }
        let kept = KeyMaker::shared(&self.keys, key).map_err(unkept)?;
        let id = self.next_entity.ok_or(RegisterError::IdsExhausted)?;
        self.next_entity = id.checked_add(1);
        let handle = self
            .interests
            .insert(InterestRow {
                id,
                kind,
                key: kept,
                holds: 1,
            })
            .map_err(|_| RegisterError::TableFull)?;
        Ok((handle, Some(id)))
    }

    /// Let go of one hold of the Interest `handle` names: its id when that was the last, for its
    /// Final to go on the wire.
    fn release_interest(&mut self, handle: InterestHandle) -> Option<EntityId> {
        let row = self.interests.get_mut(handle)?;
        row.holds = row.holds.saturating_sub(1);
        if row.holds > 0 {
            return None;
        }
        let id = row.id;
        let _ = self.interests.remove(handle);
        Some(id)
    }

    /// The key of the Interest `handle` names.
    pub fn interest_key(&self, handle: InterestHandle) -> Option<&str> {
        self.interests.get(handle).map(|row| text(&row.key))
    }

    /// Declare the write filter of a publisher or a querier on `key`.
    pub fn declare_write_filter(
        &mut self,
        plane: Plane,
        key: &str,
        count_local: bool,
    ) -> Result<Watching<kind::WriteFilter>, RegisterError> {
        if self.write_filters.is_full() {
            return Err(RegisterError::TableFull);
        }
        let (interest, asked) = self.hold_interest(plane.interest_kind(), key)?;
        let row = WriteFilterRow {
            plane,
            interest,
            count_local,
            verdict: Cell::new(None),
        };
        match self.write_filters.insert(row) {
            Ok(handle) => Ok(Watching {
                handle,
                interest: asked,
            }),
            Err(_) => {
                let _ = self.release_interest(interest);
                Err(RegisterError::TableFull)
            }
        }
    }

    /// Undeclare the write filter `handle` names, and every matching listener declared on it:
    /// `each` is handed each listener's handle and its removal, the row when no call of it runs,
    /// else [`Removal::AfterCalls`], when the call that ends last lets it go
    /// ([`Self::release_matching_listener`]).
    pub fn undeclare_write_filter(
        &mut self,
        handle: WriteFilterHandle,
        mut each: impl FnMut(MatchingListenerHandle, Removal<Matching<F>>),
    ) -> Option<Unwatched<WriteFilterRow>> {
        let interest = self.write_filters.get(handle)?.interest;
        let mut cursor = 0usize;
        while let Some((listener, owned)) = self
            .matching
            .next_from(&mut cursor)
            .map(|(listener, row)| (listener, row.filter == handle))
        {
            if owned {
                if let Some(removal) = self.retire_matching_listener(listener) {
                    each(listener, removal);
                }
            }
        }
        let removal = self.write_filters.remove(handle)?;
        let interest_final = self.release_interest(interest);
        Some(Unwatched {
            row: removal.taken(),
            interest_final,
        })
    }

    /// Declare a matching listener on the write filter `filter`, whose kind, key and Interest it
    /// reads and with which it goes. It starts as not matching: the first
    /// [`Self::next_matching_change`] tells it otherwise where it matches. Refused with
    /// [`RegisterError::OwnerGone`] when `filter` names no filter, the callback handed back.
    pub fn declare_matching_listener(
        &mut self,
        filter: WriteFilterHandle,
        callback: F::Matching,
    ) -> Result<MatchingListenerHandle, Refused<F::Matching>> {
        let Some(owner) = self.write_filters.get(filter) else {
            return Err(Refused {
                why: RegisterError::OwnerGone,
                callback,
            });
        };
        let row = MatchingRow {
            filter,
            plane: owner.plane,
            interest: owner.interest,
            count_local: owner.count_local,
            last: false,
            callback,
        };
        self.matching
            .insert(row)
            .map_err(|CapacityFull(row)| Refused {
                why: RegisterError::TableFull,
                callback: row.callback,
            })
    }

    /// Undeclare the matching listener `handle` names, its filter staying: its row when no call of
    /// it runs, else [`Removal::AfterCalls`], when the call that ends last lets it go
    /// ([`Self::release_matching_listener`]).
    pub fn undeclare_matching_listener(
        &mut self,
        handle: MatchingListenerHandle,
    ) -> Option<Removal<Matching<F>>> {
        self.retire_matching_listener(handle)
    }

    /// Retire the matching listener `handle` names: it leaves every lookup and no call of it
    /// begins.
    fn retire_matching_listener(
        &mut self,
        handle: MatchingListenerHandle,
    ) -> Option<Removal<Matching<F>>> {
        if !self.matching.get(handle)?.callback.retire() {
            let _held = self.matching.pin(handle)?;
        }
        self.matching.remove(handle)
    }

    /// Whether the session's own entities of `plane` that hear what the session itself sends
    /// reach `key`.
    pub fn local_declares(&self, plane: Plane, key: &str) -> bool {
        match plane {
            Plane::Subscribers => self.subscribers.iter().any(|(_, row)| {
                row.origin.allows_local() && keyexpr_intersects(text(&row.key.key), key)
            }),
            Plane::Queryables { complete_required } => self.queryables.iter().any(|(_, row)| {
                row.origin.allows_local()
                    && answers(text(&row.key.key), row.complete, key, complete_required)
            }),
        }
    }

    /// Whether what `plane` counts on `key` is declared: by a peer, or with `count_local` by
    /// the session itself.
    pub fn matches(
        &self,
        plane: Plane,
        key: &str,
        count_local: bool,
        peers: &impl PeerDeclarations,
    ) -> bool {
        (count_local && self.local_declares(plane, key)) || peers.declares(plane, key)
    }

    /// Whether the write filter `handle` names lets a put or a get through: what the peers
    /// answered is kept until their tables change ([`PeerDeclarations::written`]).
    pub fn write_filter_open(
        &self,
        handle: WriteFilterHandle,
        peers: &impl PeerDeclarations,
    ) -> Option<bool> {
        let row = self.write_filters.get(handle)?;
        let key = self.interest_key(row.interest)?;
        if row.count_local && self.local_declares(row.plane, key) {
            return Some(true);
        }
        let written = peers.written();
        let remote = match row.verdict.get() {
            Some((at, verdict)) if at == written => verdict,
            _ => {
                let verdict = peers.declares(row.plane, key);
                row.verdict.set(Some((written, verdict)));
                verdict
            }
        };
        Some(remote)
    }

    /// The next matching listener at or after `cursor` whose verdict changed, with its new
    /// verdict, now recorded as the one it was told.
    pub fn next_matching_change(
        &mut self,
        cursor: &mut usize,
        peers: &impl PeerDeclarations,
    ) -> Option<(MatchingListenerHandle, bool)> {
        loop {
            let (handle, plane, interest, count_local, last) = {
                let (handle, row) = self.matching.next_from(cursor)?;
                (handle, row.plane, row.interest, row.count_local, row.last)
            };
            let Some(key) = self.interest_key(interest) else {
                continue;
            };
            let now = self.matches(plane, key, count_local, peers);
            if now != last {
                if let Some(row) = self.matching.get_mut(handle) {
                    row.last = now;
                }
                return Some((handle, now));
            }
        }
    }

    // ---- pending gets ----------------------------------------------------------------------

    /// Begin a get whose replies pass `accept`, owed a Final by each of its `legs`, ending
    /// unanswered at `deadline`: its row and the request id every leg's query carries.
    ///
    /// Refused in the order the other declarations are, so a refused get spends no request id
    /// and keeps no key: table room, then the gate's key (`KeyexprTooLong` past what a row
    /// holds, `TableFull` when the key arena has no room), and the callback is handed back.
    pub fn begin_get(
        &mut self,
        accept: crate::reply_acceptance::ReplyAcceptance<'_>,
        legs: u16,
        deadline: u64,
        callback: F::Reply,
    ) -> Result<GetBegun, Refused<F::Reply>> {
        if self.pending_gets.is_full() {
            return Err(Refused {
                why: RegisterError::TableFull,
                callback,
            });
        }
        let gate = match accept {
            crate::reply_acceptance::ReplyAcceptance::Any => None,
            crate::reply_acceptance::ReplyAcceptance::Matching(key) => {
                match KeyMaker::shared(&self.keys, key) {
                    Ok(key) => Some(key),
                    Err(why) => {
                        return Err(Refused {
                            why: unkept(why),
                            callback,
                        })
                    }
                }
            }
        };
        let request = self.mint_request();
        let row = PendingGetRow {
            request,
            gate,
            legs,
            deadline,
            callback,
        };
        match self.pending_gets.insert(row) {
            Ok(handle) => Ok(GetBegun { handle, request }),
            Err(CapacityFull(row)) => Err(Refused {
                why: RegisterError::TableFull,
                callback: row.callback,
            }),
        }
    }

    /// The next request id, past any still pending.
    fn mint_request(&mut self) -> RequestId {
        let mut id = self.next_request;
        for _ in 0..=self.pending_gets.len() {
            id = self.next_request;
            self.next_request = id.wrapping_add(1);
            if !self.pending_gets.iter().any(|(_, row)| row.request == id) {
                return id;
            }
        }
        id
    }

    /// The get whose legs carry `request`.
    pub fn pending_get(&self, request: RequestId) -> Option<(PendingGetHandle, &PendingGet<F, P>)> {
        self.pending_gets
            .iter()
            .find(|(_, row)| row.request == request)
    }

    /// Begin a call of the get `handle` names, with a reply the tables admitted, the tables held:
    /// what the call is made with once they are let go, `None` when no live row is named. See
    /// [`Self::begin_subscriber`].
    pub fn begin_reply(&self, handle: PendingGetHandle) -> Option<<F::Reply as RowCallback>::Call> {
        const {
            assert!(row_may_lie_in::<F::Reply, P>(), "a callback whose calls read its row in place, on another thread, needs its row out of every &mut of the tables: in the arena, on the lent policy");
        }
        self.pending_gets.get(handle)?.callback.begin()
    }

    /// Let go of the get `handle` named, ended while a call of it ran, once that call ended last:
    /// its row, to drop where no lock is held.
    pub fn release_get(&mut self, handle: PendingGetHandle) -> Option<PendingGet<F, P>> {
        self.pending_gets.release(handle)
    }

    /// One leg of the get `handle` names has its Final, or will have none (its face is gone): what
    /// is left of the get. The last leg ends it as [`Self::end_get`] does.
    pub fn end_leg(&mut self, handle: PendingGetHandle) -> Option<LegEnded<PendingGet<F, P>>> {
        let row = self.pending_gets.get_mut(handle)?;
        row.legs = row.legs.saturating_sub(1);
        if row.legs > 0 {
            return Some(LegEnded::Owed(row.legs));
        }
        self.end_get(handle).map(LegEnded::Over)
    }

    /// End the get `handle` names, whatever its legs still owe (its deadline passed, its asker
    /// cancelled it): no call of its callback begins after this. Its row is handed back at once
    /// when no call runs, else the call that ends last lets it go ([`Self::release_get`]).
    pub fn end_get(&mut self, handle: PendingGetHandle) -> Option<Removal<PendingGet<F, P>>> {
        // What it held back goes with it: a get that delivers its held replies takes them out
        // first (`take_held`).
        #[cfg(feature = "storage-profile")]
        self.held.forget(handle);
        if !self.pending_gets.get(handle)?.callback.retire() {
            let _held = self.pending_gets.pin(handle)?;
        }
        self.pending_gets.remove(handle)
    }

    #[cfg(feature = "storage-profile")]
    /// Apply the get's consolidation `mode` to `reply`, one its gate admitted: hold it back, drop
    /// it as stale, or let it through (`Consolidated::Forwarded`), for the caller to hand to the
    /// get's callback once the tables are let go. The rule is [`crate::reply_hold::consolidate`]'s,
    /// the one every consolidating get applies.
    pub fn consolidate_reply(
        &mut self,
        handle: PendingGetHandle,
        mode: crate::query_mode::ConsolidationMode,
        reply: &dyn crate::reply_sink::ReplyView,
    ) -> crate::reply_hold::Consolidated {
        crate::reply_hold::consolidate(mode, &mut self.held.of(handle), reply, &mut |_| {})
    }

    #[cfg(feature = "storage-profile")]
    /// Take out the next reply the get `handle` names held back, for its caller to hand to the
    /// get's callback once the tables are let go: what a `Latest` get delivers at its end, before
    /// [`Self::end_get`] lets go of what is left.
    pub fn take_held(
        &mut self,
        handle: PendingGetHandle,
    ) -> Option<crate::reply_hold::HeldReply<PendingGetHandle, P>> {
        self.held.take(handle)
    }

    /// How many replies the consolidating gets could not hold back, for want of room.
    #[cfg(feature = "storage-profile")]
    pub fn held_refused(&self) -> u32 {
        self.held.refused()
    }

    /// The next get at or after `cursor` whose deadline is at or before `now`.
    pub fn next_expired_get(&self, now: u64, cursor: &mut usize) -> Option<PendingGetHandle> {
        loop {
            let (handle, row) = self.pending_gets.next_from(cursor)?;
            if row.deadline <= now {
                return Some(handle);
            }
        }
    }

    /// The nearest deadline of a pending get: what a driver's wait is cut short to.
    pub fn next_get_deadline(&self) -> Option<u64> {
        self.pending_gets.iter().map(|(_, row)| row.deadline).min()
    }

    // ---- delivery --------------------------------------------------------------------------

    /// The subscribers a sample on `key` reaches, from the session itself when `local`.
    pub fn subscribers_for<'a>(
        &'a self,
        key: &'a str,
        local: bool,
    ) -> impl Iterator<Item = (SubscriberHandle, &'a Subscriber<F, P>)> + 'a {
        self.subscribers.iter().filter(move |(_, row)| {
            admits(row.origin, local) && keyexpr_intersects(text(&row.key.key), key)
        })
    }

    /// The queryables a query on `key` reaches, from the session itself when `local`. Which of
    /// them a query's target asks is the driver's to choose from what each row says.
    pub fn queryables_for<'a>(
        &'a self,
        key: &'a str,
        local: bool,
    ) -> impl Iterator<Item = (QueryableHandle, &'a Queryable<F, P>)> + 'a {
        self.queryables.iter().filter(move |(_, row)| {
            admits(row.origin, local) && keyexpr_intersects(text(&row.key.key), key)
        })
    }

    /// The liveliness subscribers a token on `key` reaches.
    pub fn liveliness_subscribers_for<'a>(
        &'a self,
        key: &'a str,
    ) -> impl Iterator<Item = (LivelinessSubscriberHandle, &'a LivelinessSubscriber<F, P>)> + 'a
    {
        self.liveliness_subscribers
            .iter()
            .filter(move |(_, row)| keyexpr_intersects(text(&row.key.key), key))
    }

    /// The session's tokens on keys that reach `key`: what answers a peer's liveliness Interest
    /// or get.
    pub fn tokens_for<'a>(
        &'a self,
        key: &'a str,
    ) -> impl Iterator<Item = (TokenHandle, &'a TokenRow<P::Key>)> + 'a {
        self.tokens
            .iter()
            .filter(move |(_, row)| keyexpr_intersects(text(&row.key.key), key))
    }

    /// Begin a call of the subscriber `handle` names, with the tables held: what the call is made
    /// with once they are let go, `None` when no live row is named. End it with [`RowCallback::end`];
    /// when that says it was the last call of a row undeclared meanwhile, let the row go with
    /// [`Self::release_subscriber`]. A callback whose call reads the row where it lies is held only by
    /// a table of the lent policy, whose rows lie in the arena (`row_may_lie_in`).
    pub fn begin_subscriber(
        &self,
        handle: SubscriberHandle,
    ) -> Option<<F::Subscriber as RowCallback>::Call> {
        const {
            assert!(row_may_lie_in::<F::Subscriber, P>(), "a callback whose calls read its row in place, on another thread, needs its row out of every &mut of the tables: in the arena, on the lent policy");
        }
        self.subscribers.get(handle)?.callback.begin()
    }

    /// Let go of the subscriber `handle` named, undeclared while a call of it ran, once that call
    /// ended last: its row, to drop where no lock is held.
    pub fn release_subscriber(&mut self, handle: SubscriberHandle) -> Option<Subscriber<F, P>> {
        self.subscribers.release(handle)
    }

    /// Begin a call of the queryable `handle` names, with the tables held: what the call is made
    /// with once they are let go, `None` when no live row is named. See [`Self::begin_subscriber`].
    pub fn begin_queryable(
        &self,
        handle: QueryableHandle,
    ) -> Option<<F::Queryable as RowCallback>::Call> {
        const {
            assert!(row_may_lie_in::<F::Queryable, P>(), "a callback whose calls read its row in place, on another thread, needs its row out of every &mut of the tables: in the arena, on the lent policy");
        }
        self.queryables.get(handle)?.callback.begin()
    }

    /// Let go of the queryable `handle` named, undeclared while a call of it ran, once that call
    /// ended last: its row, to drop where no lock is held.
    pub fn release_queryable(&mut self, handle: QueryableHandle) -> Option<Queryable<F, P>> {
        self.queryables.release(handle)
    }

    /// Begin a call of the liveliness subscriber `handle` names, with the tables held: what the call is made
    /// with once they are let go, `None` when no live row is named. See [`Self::begin_subscriber`].
    pub fn begin_liveliness_subscriber(
        &self,
        handle: LivelinessSubscriberHandle,
    ) -> Option<<F::LivelinessSubscriber as RowCallback>::Call> {
        const {
            assert!(row_may_lie_in::<F::LivelinessSubscriber, P>(), "a callback whose calls read its row in place, on another thread, needs its row out of every &mut of the tables: in the arena, on the lent policy");
        }
        self.liveliness_subscribers.get(handle)?.callback.begin()
    }

    /// Let go of the liveliness subscriber `handle` named, undeclared while a call of it ran, once that call
    /// ended last: its row, to drop where no lock is held.
    pub fn release_liveliness_subscriber(
        &mut self,
        handle: LivelinessSubscriberHandle,
    ) -> Option<LivelinessSubscriber<F, P>> {
        self.liveliness_subscribers.release(handle)
    }

    /// Begin a call of the matching listener `handle` names, with the tables held: what the call is made
    /// with once they are let go, `None` when no live row is named. See [`Self::begin_subscriber`].
    pub fn begin_matching_listener(
        &self,
        handle: MatchingListenerHandle,
    ) -> Option<<F::Matching as RowCallback>::Call> {
        const {
            assert!(row_may_lie_in::<F::Matching, P>(), "a callback whose calls read its row in place, on another thread, needs its row out of every &mut of the tables: in the arena, on the lent policy");
        }
        self.matching.get(handle)?.callback.begin()
    }

    /// Let go of the matching listener `handle` named, undeclared while a call of it ran, once that call
    /// ended last: its row, to drop where no lock is held.
    pub fn release_matching_listener(
        &mut self,
        handle: MatchingListenerHandle,
    ) -> Option<Matching<F>> {
        self.matching.release(handle)
    }

    // ---- the tables, to read ---------------------------------------------------------------

    /// The key expression declarations.
    pub fn keyexprs(&self) -> &Keyexprs<P> {
        &self.keyexprs
    }

    /// The subscribers.
    pub fn subscribers(&self) -> &Subscribers<F, P> {
        &self.subscribers
    }

    /// The queryables.
    pub fn queryables(&self) -> &Queryables<F, P> {
        &self.queryables
    }

    /// The liveliness tokens.
    pub fn tokens(&self) -> &Tokens<P> {
        &self.tokens
    }

    /// The liveliness subscribers.
    pub fn liveliness_subscribers(&self) -> &LivelinessSubscribers<F, P> {
        &self.liveliness_subscribers
    }

    /// The Interests held open.
    pub fn interests(&self) -> &Interests<P> {
        &self.interests
    }

    /// The write filters.
    pub fn write_filters(&self) -> &WriteFilters<P> {
        &self.write_filters
    }

    /// The matching listeners.
    pub fn matching_listeners(&self) -> &MatchingListeners<F, P> {
        &self.matching
    }

    /// The pending gets.
    pub fn pending_gets(&self) -> &PendingGets<F, P> {
        &self.pending_gets
    }
}

impl<F: RowCallbacks, P: Storage> Default for SessionTables<F, P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: RowCallbacks, P: Storage> fmt::Debug for SessionTables<F, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionTables")
            .field("keyexprs", &self.keyexprs)
            .field("subscribers", &self.subscribers)
            .field("queryables", &self.queryables)
            .field("tokens", &self.tokens)
            .field("liveliness_subscribers", &self.liveliness_subscribers)
            .field("interests", &self.interests)
            .field("write_filters", &self.write_filters)
            .field("matching", &self.matching)
            .field("pending_gets", &self.pending_gets)
            .finish()
    }
}

impl<F: RowCallbacks> SessionTables<F, Lent> {
    /// The tables of a session, `rows` of each lent from `arena` in the order of
    /// [`TableRows`], their keys kept in `keys`, the session's key arena. Refused past the
    /// build's bound of a table or past what the arena has left.
    pub fn lent(arena: &mut Arena, keys: KeySpace, rows: &TableRows) -> Result<Self, LendRefused> {
        Ok(Self {
            keys: LentKeys::from(keys),
            next_entity: Some(1),
            next_expr: 1,
            next_request: 0,
            subscriber_epoch: 0,
            // A table whose rows are lent at open remembers no key: each slot of the cache would
            // be rows of its own, which only the arena could give it.
            memo: MatchMemo::new(0),
            keyexprs: SlotMap::lent(arena, rows.keyexprs)?,
            subscribers: SlotMap::lent(arena, rows.subscribers)?,
            queryables: SlotMap::lent(arena, rows.queryables)?,
            tokens: SlotMap::lent(arena, rows.tokens)?,
            liveliness_subscribers: SlotMap::lent(arena, rows.liveliness_subscribers)?,
            interests: SlotMap::lent(arena, rows.interests())?,
            write_filters: SlotMap::lent(arena, rows.write_filters)?,
            matching: SlotMap::lent(arena, rows.matching_listeners)?,
            pending_gets: SlotMap::lent(arena, rows.pending_gets)?,
            #[cfg(feature = "storage-profile")]
            held: crate::reply_hold::HeldReplies::lent(arena, rows.held_replies)?,
        })
    }

    /// The bytes [`Self::lent`] takes of an arena for `rows`. `None` past the address space.
    pub fn arena_bytes(rows: &TableRows) -> Option<usize> {
        let parts = [
            <Keyexprs<Lent>>::arena_bytes(rows.keyexprs),
            <Subscribers<F, Lent>>::arena_bytes(rows.subscribers),
            <Queryables<F, Lent>>::arena_bytes(rows.queryables),
            <Tokens<Lent>>::arena_bytes(rows.tokens),
            <LivelinessSubscribers<F, Lent>>::arena_bytes(rows.liveliness_subscribers),
            <Interests<Lent>>::arena_bytes(rows.interests()),
            <WriteFilters<Lent>>::arena_bytes(rows.write_filters),
            <MatchingListeners<F, Lent>>::arena_bytes(rows.matching_listeners),
            <PendingGets<F, Lent>>::arena_bytes(rows.pending_gets),
            held_arena_bytes(rows.held_replies),
        ];
        parts
            .iter()
            .try_fold(0_usize, |sum, part| sum.checked_add((*part)?))
    }
}

/// Whether a row whose callback is `Cb` may lie in a table of policy `P`: a callback whose calls
/// read its row where it lies ([`RowCallback::READS_ROW_IN_PLACE`]) is read on another thread while
/// the tables are held, so its row lies only where no `&mut` of the tables, nor of what holds them,
/// reaches it: in the arena, behind the pointer a table of the lent policy keeps (P3, P11).
const fn row_may_lie_in<Cb: RowCallback, P: Storage>() -> bool {
    !Cb::READS_ROW_IN_PLACE || P::LENT_AT_OPEN
}

/// A row whose calls read it where it lies ([`RowCallback::READS_ROW_IN_PLACE`]) is read by them
/// on other threads while the tables are held, so the dispatch reaches it only by a shared
/// reference; a row the tables call while held is handed exclusively.
impl<Key: KeyBacking, Cb: RowCallback, P: Storage> SubscriberRows
    for SlotMap<kind::Subscriber, SubscriberRow<Key, Cb>, { caps::MAX_SUBSCRIPTIONS }, P>
{
    type Sink = Cb;
    type RowId = SubscriberHandle;

    fn each_row_mut<F: FnMut(usize, RowRef<'_>, SubscriberHandle, RowAccess<'_, Cb>)>(
        &mut self,
        mut f: F,
    ) {
        if Cb::READS_ROW_IN_PLACE {
            for (place, handle, row) in self.live_handles() {
                let found = RowRef {
                    pattern: text(&row.key.key),
                    facts: row.facts,
                    origin: row.origin,
                };
                f(place, found, handle, RowAccess::InPlace(&row.callback));
            }
        } else {
            // The row's fields are borrowed apart: its key to read, its callback to change.
            for (place, handle, row) in self.live_handles_mut() {
                let found = RowRef {
                    pattern: text(&row.key.key),
                    facts: row.facts,
                    origin: row.origin,
                };
                f(place, found, handle, RowAccess::Held(&mut row.callback));
            }
        }
    }

    fn any_row<F: FnMut(RowRef<'_>) -> bool>(&self, mut f: F) -> bool {
        self.iter().any(|(_, row)| {
            f(RowRef {
                pattern: text(&row.key.key),
                facts: row.facts,
                origin: row.origin,
            })
        })
    }

    fn sink_at(&mut self, position: usize) -> Option<(SubscriberHandle, RowAccess<'_, Cb>)> {
        if Cb::READS_ROW_IN_PLACE {
            self.live_handle_at(position)
                .map(|(handle, row)| (handle, RowAccess::InPlace(&row.callback)))
        } else {
            self.live_handle_at_mut(position)
                .map(|(handle, row)| (handle, RowAccess::Held(&mut row.callback)))
        }
    }
}

impl<F: RowCallbacks, P: Storage> crate::pubsub::LocalSubscribers for SessionTables<F, P> {
    type Sink = F::Subscriber;
    type RowId = SubscriberHandle;

    // The table set holds the key expressions the session declared: a peer's `M=0` key is read
    // from them where they lie.
    #[cfg(feature = "storage-profile")]
    fn own_space(&self) -> Option<crate::wireexpr_resolve::OwnSpace<'_>> {
        Some(P::own_space(&self.keyexprs))
    }

    fn epoch(&self) -> u64 {
        self.subscriber_epoch
    }

    fn next_subscription_id(&self) -> u64 {
        self.next_entity
            .map_or(u64::from(u32::MAX).saturating_add(1), u64::from)
    }

    fn for_each_subscription(&self, f: &mut dyn FnMut(u64, &str, Locality)) {
        for (_, row) in self.subscribers.iter() {
            f(u64::from(row.id), text(&row.key.key), row.origin);
        }
    }

    fn any_subscription(&self, f: &mut dyn FnMut(u64, &str, Locality) -> bool) -> bool {
        self.subscribers
            .iter()
            .any(|(_, row)| f(u64::from(row.id), text(&row.key.key), row.origin))
    }

    fn pattern_of(&self, id: u64) -> Option<&str> {
        self.subscribers
            .iter()
            .find(|(_, row)| u64::from(row.id) == id)
            .map(|(_, row)| text(&row.key.key))
    }

    fn next_entity_id(&self) -> Option<u32> {
        self.next_entity
    }

    fn consume_entity_id(&mut self) {
        let _ = self.take_entity_id();
    }

    fn has_local_matching(&self, key: &str) -> bool {
        any_local_match(&self.subscribers, key)
    }

    fn fire_matching<D: FnMut(Self::RowId, RowAccess<'_, Self::Sink>)>(
        &mut self,
        key: &str,
        local: bool,
        repeats_previous: bool,
        deliver: D,
    ) -> usize {
        fire_into_memoized(
            &mut self.subscribers,
            &mut self.memo,
            self.subscriber_epoch,
            key,
            !local,
            repeats_previous,
            deliver,
        )
    }

    /// The table set holds no key gate yet: a peer's message on any key is matched against
    /// every subscription that hears peers.
    fn deliver_from_peer<D: FnMut(Self::RowId, RowAccess<'_, Self::Sink>)>(
        &mut self,
        key: &str,
        _class: Option<crate::key_gate::ClassId>,
        how: crate::pubsub::PeerDelivery,
        deliver: D,
    ) -> usize {
        if how.no_allocation && !P::ENFORCES_CAPACITY {
            return scan_subscribers(&mut self.subscribers, key, true, deliver, |_| {})
                .unwrap_or(0);
        }
        fire_into_memoized(
            &mut self.subscribers,
            &mut self.memo,
            self.subscriber_epoch,
            key,
            true,
            how.repeats_previous,
            deliver,
        )
    }

    #[cfg(feature = "alloc")]
    fn end_plain_frame<X: crate::sink::SampleDelivery<Self::Sink, Self::RowId>>(
        &mut self,
        cx: &mut X,
    ) {
        if <F::Subscriber as RowCallback>::READS_ROW_IN_PLACE {
            for (handle, row) in self.subscribers.iter() {
                cx.end_plain_frame(handle, RowAccess::InPlace(&row.callback));
            }
        } else {
            for (handle, row) in self.subscribers.iter_mut() {
                cx.end_plain_frame(handle, RowAccess::Held(&mut row.callback));
            }
        }
    }
}

impl<Key: KeyBacking, Cb, P: Storage> QueryableRows
    for SlotMap<kind::Queryable, QueryableRow<Key, Cb>, { caps::MAX_QUERYABLES }, P>
{
    type Sink = Cb;

    fn each_row_mut<F: FnMut(QueryableRef<'_>, &mut Cb)>(&mut self, mut f: F) {
        for (_, row) in self.live_places_mut() {
            let found = QueryableRef {
                #[cfg(feature = "alloc")]
                id: u64::from(row.id),
                pattern: text(&row.key.key),
                facts: row.facts,
                origin: row.origin,
                complete: row.complete,
            };
            f(found, &mut row.callback);
        }
    }

    #[cfg(feature = "storage-profile")]
    fn any_row<F: FnMut(QueryableRef<'_>) -> bool>(&self, mut f: F) -> bool {
        self.iter().any(|(_, row)| {
            f(QueryableRef {
                #[cfg(feature = "alloc")]
                id: u64::from(row.id),
                pattern: text(&row.key.key),
                facts: row.facts,
                origin: row.origin,
                complete: row.complete,
            })
        })
    }
}

impl<F: RowCallbacks, P: Storage> crate::query::LocalQueryables for SessionTables<F, P> {
    type Sink = F::Queryable;

    #[cfg(feature = "storage-profile")]
    fn has_local_queryable(&self, query_keyexpr: &str, require_complete: bool) -> bool {
        any_local_queryable(&self.queryables, query_keyexpr, require_complete)
    }

    #[cfg(feature = "alloc")]
    fn respond_to_queryable_interest(
        &self,
        interest_id: u64,
        pattern: Option<&str>,
        aggregate: bool,
        staged: &mut alloc::vec::Vec<crate::query::QueryableInterestReply>,
    ) -> usize {
        stage_queryable_interest(&self.queryables, interest_id, pattern, aggregate, staged)
    }

    fn fire_matching_queryables<D: FnMut(&mut Self::Sink)>(
        &mut self,
        keyexpr: &str,
        keyexpr_facts: KeyFacts,
        is_remote: bool,
        target: Option<crate::query_mode::QueryTarget>,
        deliver: D,
    ) -> usize {
        fire_queryables(
            &mut self.queryables,
            keyexpr,
            keyexpr_facts,
            is_remote,
            target,
            deliver,
        )
    }
}

#[cfg(test)]
mod tests;
