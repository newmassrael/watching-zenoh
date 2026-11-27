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
//! subscribers, its publishers' and queriers' write filters with the Interests they hold open, its
//! matching listeners and its pending gets. A row is named by its table's [`Handle`]; the numbers
//! the wire carries (entity ids, key expression ids, request ids) are minted here, once.
//!
//! # Keys
//!
//! A row keeps its key as the policy keeps one (the session's key arena on the lent policy). An
//! entity that names a key expression declaration of the session's holds that declaration's row
//! ([`KeyForm::prefix`]) instead of a copy of its id and suffix: its wire form is read off both
//! ([`SessionTables::wire_of`]), and the declaration is retracted when its last holder goes. Each
//! write filter that asks the peers opens an Interest of its own, as zenoh-pico's
//! `_z_write_filter_create` adds one for every filter, and keeps it in its own row: the filter is
//! the Interest's one holder, so no table of Interests stands beside it. A matching listener is a
//! callback of a filter, as zenoh-pico's is of its entity's: one declared on a key brings a filter
//! of its own.
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
//!
//! [`SlotMap`]: crate::slot_map::SlotMap
//! [`TableRows`]: crate::session_tables::TableRows
//! [`Handle`]: crate::slot_map::Handle
//! [`KeyForm::prefix`]: crate::session_tables::KeyForm::prefix
//! [`SessionTables::wire_of`]: crate::session_tables::SessionTables::wire_of
//! [`RegisterError`]: crate::registry_error::RegisterError
//! [`Refused`]: crate::session_tables::Refused
//! [`RowCallbacks`]: crate::session_tables::RowCallbacks
//! [`RowCallback`]: crate::row_callback::RowCallback
//! [`PeerDeclarations`]: crate::session_tables::PeerDeclarations

use core::cell::Cell;
use core::fmt;
// The split the request plane uses: the host profile has the native atomics, the `no_std` profile
// gets the critical-section ones for the cores that have none.
#[cfg(not(feature = "no_std"))]
use core::sync::atomic::AtomicU32;
#[cfg(feature = "no_std")]
use portable_atomic::AtomicU32;

use crate::bounded::{
    Arena, BoundedVec, CapacityFull, KeyBacking, KeyLength, KeyMaker, KeyUnkept, LendRefused, Lent,
    Profile, Region, RegionLines, Static, Storage, TableLender, ZeroEmpty,
};
use crate::caps;
use crate::declare_form::RetractionKey;
use crate::key_arena::{KeyRef, KeySpace, LentKeys};
use crate::key_gate::{ClassId, KeyGate};
use crate::keyexpr_match::{keyexpr_intersects, KeyFacts};
use crate::locality::Locality;
use crate::named_key::{NamedKey, Prefix};
use crate::pubsub::{
    admit_from_peer, any_local_match, fire_into_marked, fire_into_memoized, past_matcher_depth,
    row_reaches, scan_subscribers, Admission, MatchMemo, RowRef, SubscriberRows,
};
#[cfg(feature = "storage-profile")]
use crate::query::any_local_queryable;
#[cfg(feature = "alloc")]
use crate::query::stage_queryable_interest;
use crate::query::{fire_queryables, QueryableRef, QueryableRows};
use crate::registry_error::RegisterError;
use crate::row_callback::RowCallback;
use crate::sink::RowAccess;
use crate::slot_map::{Handle, Removal, SlotMap, SlotRows, Slots};
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
/// A write filter's row.
pub type WriteFilterHandle = Handle<kind::WriteFilter>;
/// A matching listener's row.
pub type MatchingListenerHandle = Handle<kind::MatchingListener>;
/// A pending get's row.
pub type PendingGetHandle = Handle<kind::PendingGet>;

/// The tables of the declarations a session tells its peers, each named apart from its rows'
/// type: what a walk of them in one order reads through [`SessionTables::slots_of`], and what a
/// row of any of them is named by as data ([`DeclaredRow`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredTable {
    /// The key expression declarations.
    Keyexprs,
    /// The subscribers.
    Subscribers,
    /// The write filters, each told as the Interest it holds open; one that holds none has
    /// nothing to tell.
    Interests,
    /// The queryables.
    Queryables,
    /// The liveliness tokens.
    Tokens,
    /// The liveliness subscribers.
    LivelinessSubscribers,
}

/// A kind of row kept in one of the tables of declarations ([`DeclaredTable`]).
pub trait DeclaredKind {
    /// The table its rows are kept in.
    const TABLE: DeclaredTable;
}

impl DeclaredKind for kind::Keyexpr {
    const TABLE: DeclaredTable = DeclaredTable::Keyexprs;
}

impl DeclaredKind for kind::Subscriber {
    const TABLE: DeclaredTable = DeclaredTable::Subscribers;
}

// A filter's row is its Interest's, so the filters' table is the one the Interests are told from.
impl DeclaredKind for kind::WriteFilter {
    const TABLE: DeclaredTable = DeclaredTable::Interests;
}

impl DeclaredKind for kind::Queryable {
    const TABLE: DeclaredTable = DeclaredTable::Queryables;
}

impl DeclaredKind for kind::Token {
    const TABLE: DeclaredTable = DeclaredTable::Tokens;
}

impl DeclaredKind for kind::LivelinessSubscriber {
    const TABLE: DeclaredTable = DeclaredTable::LivelinessSubscribers;
}

/// A row of one of the tables of declarations, named as data: its table and the bits of its
/// handle ([`Handle::to_bits`]). One value for every kind, so a caller that tells a peer of a
/// declaration of any kind is one body that reads the kind, not one body for each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeclaredRow {
    /// The table the row is kept in.
    pub table: DeclaredTable,
    /// The bits of the row's handle.
    pub row: core::num::NonZeroU32,
}

impl DeclaredRow {
    /// The row `handle` names.
    pub fn of<K: DeclaredKind>(handle: Handle<K>) -> Self {
        Self {
            table: K::TABLE,
            row: handle.to_bits(),
        }
    }
}

/// A face of the session, as its engine names it: the link a get was asked on.
pub type FaceId = u64;

/// The build's bound of the write filters: a publisher's and a querier's each, and the one each
/// matching listener declared on a key judges through.
pub const FILTER_ROWS: usize = caps::MAX_PUBLISHERS
    .saturating_add(caps::MAX_QUERIERS)
    .saturating_add(caps::MAX_MATCHING_LISTENERS);

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
    /// Whether the tables keep queryables at all: [`Present`], or [`Absent`] for a session that
    /// answers no query, whose table of them is no value and whose every use is left out.
    type QueryablePresence: Presence;
    /// Whether the tables keep liveliness tokens and liveliness subscribers at all.
    type LivelinessPresence: Presence;
    /// Whether the tables keep write filters, the Interests they hold and their matching
    /// listeners at all.
    type FilterPresence: Presence;
    /// Whether the tables keep pending gets at all.
    type GetPresence: Presence;
}

/// Whether a kind of row has a table in a session's tables. A build that keeps none of a kind
/// names it [`Absent`]: the table is a value of no size and nothing to drop, every read of it finds
/// nothing and every declaration on it is refused, each answered where the compiler sees it, so
/// the code that would walk, lend or drop the table is not in the build.
pub trait Presence: sealed::Presence {
    /// The table of a kind whose table is `T`.
    type Table<T>;

    /// The table of no rows, as `T`'s `Default` makes it where the kind is kept.
    fn empty<T: Default>() -> Self::Table<T>;

    /// The table made at `at`, where it stays: by `make`, handed the place, where the kind is
    /// kept, and of no bytes otherwise. What a table that holds a lock is made by.
    ///
    /// # Safety
    /// `at` is valid for writes of a table and aligned for it, and `make` writes a whole `T` at
    /// the place it is handed.
    unsafe fn init_at<T>(
        at: core::ptr::NonNull<Self::Table<T>>,
        make: impl FnOnce(core::ptr::NonNull<T>),
    );

    /// The table, to read, where the kind is kept.
    fn get<T>(table: &Self::Table<T>) -> Option<&T>;

    /// The table, to write, where the kind is kept.
    fn get_mut<T>(table: &mut Self::Table<T>) -> Option<&mut T>;

    /// The table lent by `lend`, `rows` rows of it, where the kind is kept; nothing is lent where
    /// it is not.
    fn lent_from<T: LentTable>(lend: &mut TableLender<'_>, rows: usize) -> Self::Table<T>;

    /// The table of `rows` rows that takes its memory at its first row ([`CountedTable`]), where
    /// the kind is kept; nothing is made where it is not.
    #[cfg(feature = "alloc")]
    fn counted<T: CountedTable>(rows: usize) -> Self::Table<T>;

    /// Whether the kind is kept.
    const KEPT: bool;

    /// A value of the kind as a variant of an enum holds it: `T` where the kind is kept, and
    /// [`Unkept`] where it is not, a type of no value and no size, so the variant takes no room in
    /// the enum and every arm that reads it is left out of the build.
    type Record<T>;

    /// `value` as a variant holds it, where the kind is kept; `None` where it is not.
    fn record<T>(value: T) -> Option<Self::Record<T>>;

    /// The value `record` holds.
    fn read<T>(record: &Self::Record<T>) -> &T;

    /// The value `record` holds, taken out of it.
    fn take<T>(record: Self::Record<T>) -> T;
}

/// A value of a kind a build keeps none of ([`Presence::Record`]): none is ever made, and it
/// takes no room.
pub enum Unkept<T> {
    /// Never made: its first field has no value.
    #[doc(hidden)]
    Never(
        core::convert::Infallible,
        core::marker::PhantomData<fn() -> T>,
    ),
}

impl<T> Unkept<T> {
    /// Anything at all, as a value that cannot be is read.
    fn absurd<R>(&self) -> R {
        match self {
            Self::Never(never, _) => match *never {},
        }
    }
}

/// A table a session's arena lends at its open, `rows` rows of it ([`Presence::lent_from`]).
pub trait LentTable {
    /// The table of `rows` rows `lend` lends.
    fn lent_from(lend: &mut TableLender<'_>, rows: usize) -> Self;
}

impl<K, T, const N: usize> LentTable for SlotMap<K, T, N, Lent> {
    fn lent_from(lend: &mut TableLender<'_>, rows: usize) -> Self {
        SlotMap::lent_from(lend, rows)
    }
}

/// A table of the on-use policy, made with its count and no memory, which its first row takes
/// ([`Presence::counted`]).
#[cfg(feature = "alloc")]
pub trait CountedTable {
    /// The table of at most `rows` rows, none taken yet.
    fn counted(rows: usize) -> Self;
}

#[cfg(feature = "alloc")]
impl<K, T, const N: usize> CountedTable for SlotMap<K, T, N, crate::bounded::OnUse> {
    fn counted(rows: usize) -> Self {
        SlotMap::<K, T, N, crate::bounded::OnUse>::counted(rows)
    }
}

mod sealed {
    /// The two answers to whether a kind is kept, and no other: what lets tables of the region
    /// policy, and their rows, state that they are empty at all zero bytes whichever a build
    /// gives, a kept table being its own table and an absent one no bytes.
    pub trait Presence {}

    impl Presence for super::Present {}
    impl Presence for super::Absent {}
}

/// A kind the tables keep: its table is the table itself.
#[derive(Debug)]
pub enum Present {}

impl Presence for Present {
    type Table<T> = T;

    fn empty<T: Default>() -> T {
        T::default()
    }

    unsafe fn init_at<T>(at: core::ptr::NonNull<T>, make: impl FnOnce(core::ptr::NonNull<T>)) {
        make(at);
    }

    fn get<T>(table: &T) -> Option<&T> {
        Some(table)
    }

    fn get_mut<T>(table: &mut T) -> Option<&mut T> {
        Some(table)
    }

    fn lent_from<T: LentTable>(lend: &mut TableLender<'_>, rows: usize) -> T {
        T::lent_from(lend, rows)
    }

    #[cfg(feature = "alloc")]
    fn counted<T: CountedTable>(rows: usize) -> T {
        T::counted(rows)
    }

    const KEPT: bool = true;

    type Record<T> = T;

    fn record<T>(value: T) -> Option<T> {
        Some(value)
    }

    fn read<T>(record: &T) -> &T {
        record
    }

    fn take<T>(record: T) -> T {
        record
    }
}

/// A kind the tables keep none of: its table is [`AbsentTable`].
#[derive(Debug)]
pub enum Absent {}

/// The table of a kind the tables keep none of: no row, no byte and nothing to drop.
pub struct AbsentTable<T>(core::marker::PhantomData<fn() -> T>);

impl<T> AbsentTable<T> {
    /// The table of a kind kept by none: what a path that needs a table of the kind is handed
    /// where the tables keep none, so it finds no row in it.
    pub const fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<T> Default for AbsentTable<T> {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: an absent table is a `PhantomData`, no bytes.
unsafe impl<T> ZeroEmpty for AbsentTable<T> {}

impl<T> fmt::Debug for AbsentTable<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AbsentTable")
    }
}

impl Presence for Absent {
    type Table<T> = AbsentTable<T>;

    fn empty<T: Default>() -> AbsentTable<T> {
        AbsentTable::new()
    }

    unsafe fn init_at<T>(
        at: core::ptr::NonNull<AbsentTable<T>>,
        _make: impl FnOnce(core::ptr::NonNull<T>),
    ) {
        // SAFETY: `at` is valid for writes of the table (the caller's contract).
        unsafe { at.as_ptr().write(AbsentTable::new()) }
    }

    fn get<T>(_table: &AbsentTable<T>) -> Option<&T> {
        None
    }

    fn get_mut<T>(_table: &mut AbsentTable<T>) -> Option<&mut T> {
        None
    }

    fn lent_from<T: LentTable>(_lend: &mut TableLender<'_>, _rows: usize) -> AbsentTable<T> {
        AbsentTable::new()
    }

    #[cfg(feature = "alloc")]
    fn counted<T: CountedTable>(_rows: usize) -> AbsentTable<T> {
        AbsentTable::new()
    }

    const KEPT: bool = false;

    type Record<T> = Unkept<T>;

    fn record<T>(_value: T) -> Option<Unkept<T>> {
        None
    }

    fn read<T>(record: &Unkept<T>) -> &T {
        record.absurd()
    }

    fn take<T>(record: Unkept<T>) -> T {
        record.absurd()
    }
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
    /// The declaration of the entity's own key, when the declaring ABI states one besides the one
    /// its key is named by: the row holds it while it stands, as zenoh-pico's subscription keeps
    /// its own declared key. One that names no live declaration is not held.
    pub own: Option<KeyexprHandle>,
    /// What the retraction names beside the id.
    pub retraction: Retraction,
}

impl KeyForm {
    /// This form, its row holding `own`, the declaration of the entity's own key, as well.
    pub fn owning(self, own: Option<KeyexprHandle>) -> Self {
        Self { own, ..self }
    }
}

/// What an entity's retraction names beside its id: the one record of it, read off the entity's
/// row ([`SessionTables::retraction_of`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Retraction {
    /// Nothing: the id alone.
    #[default]
    ById,
    /// The key, named as the entity's announcement names it ([`SessionTables::wire_of`]), read
    /// when the retraction is: the declaration its row holds while that stands, the whole key
    /// otherwise.
    AsAnnounced,
    /// The key, named as the declaring ABI states it: a declaration of the entity's own key that
    /// need not be the one its announcement names, and the rest of the key past it.
    Named(RetractionKey),
}

/// An entity's key, as its row keeps it.
#[derive(Debug)]
pub struct EntityKey<Key> {
    key: Key,
    prefix: Option<KeyexprHandle>,
    /// The declaration of the entity's own key, which the row holds as it holds `prefix`: the one
    /// the form states, or else the one a named retraction names, which the entity's retraction
    /// names after every other holder may have let it go.
    named: Option<KeyexprHandle>,
    retraction: Retraction,
    /// Whether the key passed the wire's pre-emit gate when the row was made: judged once there,
    /// so the key is not walked again at each link it is announced or replayed on
    /// (`NamedKey::check_outbound`).
    proven: bool,
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

    /// What the retraction names beside the id, as the declaration stated it.
    pub fn retraction(&self) -> Retraction {
        self.retraction
    }

    /// The key as the row keeps it: a clone is one more holder of it, for a reader past the row.
    pub fn backing(&self) -> &Key {
        &self.key
    }
}

impl<Key: KeyBacking> EntityKey<Key> {
    /// The key as the row keeps it ([`RowKey`]), lent with the declaration of the entity's own
    /// key when the row holds one, else the one the key is named by.
    pub fn lent(&self) -> RowKey {
        RowKey::of(self.key.as_str(), self.named.or(self.prefix))
    }
}

impl<Key> EntityKey<Key> {
    /// The declaration of the entity's own key the row holds, `None` when it holds none: what a
    /// program asking for the entity's key is lent beside the key's text.
    pub fn named(&self) -> Option<KeyexprHandle> {
        self.named
    }

    /// The declarations the row holds, each once: the one the key is named by, and the one of the
    /// entity's own key when that is another.
    pub fn holds(&self) -> (Option<KeyexprHandle>, Option<KeyexprHandle>) {
        (
            self.prefix,
            self.named.filter(|&named| Some(named) != self.prefix),
        )
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

/// The count of a key expression declaration's holders ([`KeyexprRow::holds`]): a declaration
/// whose count is at its `MAX` takes no further holder.
pub type KeyexprHolds = u16;

/// A key expression the session declares. `Len` is the integer its key's length is kept in
/// ([`Storage::KeyLen`]).
#[derive(Debug)]
pub struct KeyexprRow<Key, Len = caps::KeyLen> {
    key: Key,
    head: KeyexprHead<Len>,
}

impl<Key, Len: crate::bounded::KeyLength> KeyexprRow<Key, Len> {
    /// The id the wire names it by.
    pub fn id(&self) -> ExprId {
        self.head.id()
    }

    /// Its holders: the declarations of the program and the entities that name it.
    pub fn holds(&self) -> KeyexprHolds {
        self.head.holds()
    }

    /// What a holder reads and counts at the row's own address ([`KeyexprHead`]).
    pub fn head(&self) -> &KeyexprHead<Len> {
        &self.head
    }
}

impl<Key: KeyBacking, Len> KeyexprRow<Key, Len> {
    /// The key.
    pub fn key(&self) -> &str {
        self.key.as_str()
    }
}

/// The part of a key expression declaration's row a holder reaches by the row's address, with no
/// lock of the session: the declaration's id, the length of its key, its count of holders and the
/// tables the row lies in. The address stays the row's while the row stands on every policy:
/// a table placed in a region or lent at the open keeps its rows where they are, and a growable
/// one keeps them in chunks that are only ever added ([`Chunked`](crate::slot_map::Chunked)).
///
/// The count is the declaration's one count: the table's own declarations and entities take and
/// give back holds of it under the session's lock, and a holder that keeps the row's address takes
/// and gives back its own at its count ([`KeyexprCount`]), by the row it holds. The last hold is let go of only by the table
/// ([`SessionTables::undeclare_keyexpr`]), which removes the row and has the declaration retracted.
///
/// A holder names the row by its address, so the count's word carries only what tells the row's
/// declarations apart: the generation of the row's slot, which moves each time a row leaves it.
/// A hold kept past a retraction that took the declaration whatever held it is then told from the
/// declaration that took the row next, up to the bound the generation has: a stale hold given back
/// after the slot was taken again a multiple of 65536 times reads as the new one's. The generation
/// is not held at its last value to close that: a slot that stopped being taken would leave a
/// bounded table one row short for good, a refusal every later declaration would meet, against a
/// stale holder outliving that many declarations of one row, which only a program that retracts a
/// key it still holds can make.
#[derive(Debug)]
pub struct KeyexprHead<Len = caps::KeyLen> {
    /// The count of the declaration's holders, the one part of the head a holder that is not the
    /// table touches: the same type whatever `Len` is, so a holder names it alone.
    count: KeyexprCount,
    /// The id the wire names the declaration by.
    id: ExprId,
    /// The length of the declared key, in bytes, in the integer of the table's policy
    /// ([`Storage::KeyLen`]).
    key_len: Len,
    /// The address of the tables the row lies in.
    table: usize,
}

impl<Len: crate::bounded::KeyLength> KeyexprHead<Len> {
    /// The head of a declaration of `id` on a key of `key_len` bytes in the tables at `table`. It
    /// is held by none until the table takes its first hold at the generation of the row it was
    /// put in ([`KeyexprCount::first_hold`]): a hold kept of the row's last declaration takes and
    /// gives back nothing in between.
    fn new(id: ExprId, key_len: Len, table: usize) -> Self {
        Self {
            count: KeyexprCount(AtomicU32::new(0)),
            id,
            key_len,
            table,
        }
    }

    /// The id the wire names the declaration by.
    pub fn id(&self) -> ExprId {
        self.id
    }

    /// Its holders now.
    pub fn holds(&self) -> KeyexprHolds {
        self.count.holds()
    }

    /// How many bytes of a key the declaration covers: the length of its own key, which every key
    /// named by it begins with.
    pub fn key_len(&self) -> usize {
        self.key_len.get()
    }

    /// The count of the declaration's holders, where a holder takes and gives back its hold.
    pub fn count(&self) -> &KeyexprCount {
        &self.count
    }
}

/// A declaration's count of holders at its row's address ([`KeyexprHead`]): the generation of
/// the row's slot in the upper half of one word of the machine's atomic width and the count in
/// the lower, so a hold taken or given back here is of the declaration its holder took it of.
#[derive(Debug)]
pub struct KeyexprCount(AtomicU32);

/// Why a declaration's row took no more hold at its address ([`KeyexprCount::retain`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowHoldRefused {
    /// The count holds as many holders as it can.
    Full,
    /// The row holds no declaration at the generation asked: its last holder let go of it, or a
    /// retraction took it whatever held it, whatever took the row's place since.
    Released,
}

impl KeyexprCount {
    /// The table's first hold of the declaration it put in `row`, at `row`'s generation.
    fn first_hold(&self, row: KeyexprHandle) {
        self.0.store(
            Self::word(Self::generation_of(row), 1),
            core::sync::atomic::Ordering::Release,
        );
    }

    /// No holder of the declaration in `row` from here on, whatever held it: a holder at the
    /// address takes no more hold of it and gives its own back to the table, which finds the row
    /// gone.
    fn retract(&self, row: KeyexprHandle) {
        self.0.store(
            Self::word(Self::generation_of(row), 0),
            core::sync::atomic::Ordering::Release,
        );
    }

    /// The count's word of `holds` holders at `generation`.
    fn word(generation: u16, holds: KeyexprHolds) -> u32 {
        (u32::from(generation) << 16) | u32::from(holds)
    }

    /// The generation `row` was taken at.
    fn generation_of(row: KeyexprHandle) -> u16 {
        (row.to_bits().get() >> 16) as u16
    }

    /// The generation in `word`.
    fn generation_in(word: u32) -> u16 {
        (word >> 16) as u16
    }

    /// The count of holders in `word`.
    fn holds_of(word: u32) -> KeyexprHolds {
        (word & 0xffff) as KeyexprHolds
    }

    /// Its holders now.
    pub fn holds(&self) -> KeyexprHolds {
        Self::holds_of(self.0.load(core::sync::atomic::Ordering::Relaxed))
    }

    /// One more hold of the declaration in `row`, for a holder that already holds one: refused,
    /// taking none, when the count holds as many as it can, and when the row holds no declaration
    /// at `row`'s generation (its last holder let go of it, or a retraction took it, whatever
    /// took the row's place since).
    pub fn retain(&self, row: KeyexprHandle) -> Result<(), RowHoldRefused> {
        let generation = Self::generation_of(row);
        let mut now = self.0.load(core::sync::atomic::Ordering::Relaxed);
        loop {
            let holds = Self::holds_of(now);
            if Self::generation_in(now) != generation || holds == 0 {
                return Err(RowHoldRefused::Released);
            }
            if holds == KeyexprHolds::MAX {
                return Err(RowHoldRefused::Full);
            }
            // Under the bound, so the count does not carry into the generation.
            match self.0.compare_exchange_weak(
                now,
                now.wrapping_add(1),
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(seen) => now = seen,
            }
        }
    }

    /// Let go of one hold of the declaration in `row` when it is not the last: `false`, taking
    /// nothing, when it is the last, or the row holds no declaration at `row`'s generation. The
    /// last is let go of by the table, under the session's lock
    /// ([`SessionTables::undeclare_keyexpr`]), which removes the row: a count that reached none
    /// here would leave a row no one removes.
    pub fn release_shared(&self, row: KeyexprHandle) -> bool {
        let generation = Self::generation_of(row);
        let mut now = self.0.load(core::sync::atomic::Ordering::Relaxed);
        loop {
            if Self::generation_in(now) != generation || Self::holds_of(now) <= 1 {
                return false;
            }
            match self.0.compare_exchange_weak(
                now,
                now.wrapping_sub(1),
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(seen) => now = seen,
            }
        }
    }

    /// Let go of one hold, for the table that holds the row: `true` when it was the last, and the
    /// row is to go. A count of none, which a row the table still holds never has, lets go of
    /// nothing.
    fn release(&self) -> bool {
        let mut now = self.0.load(core::sync::atomic::Ordering::Relaxed);
        loop {
            let holds = Self::holds_of(now);
            if holds == 0 {
                return false;
            }
            match self.0.compare_exchange_weak(
                now,
                now.wrapping_sub(1),
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return holds == 1,
                Err(seen) => now = seen,
            }
        }
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
    /// Set by the responder's `Declare(DeclFinal)` that ends its history. A cell, so the mark is
    /// set through a shared row, which a row whose calls read it in place is only ever reached by.
    history_complete: Cell<bool>,
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

    /// Whether it asked for the tokens alive when it was declared and the responder has ended
    /// that history.
    pub fn history_complete(&self) -> bool {
        self.history && self.history_complete.get()
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

/// The Interest a write filter holds open, kept in the filter's row: the filter is its one holder,
/// as zenoh-pico's filter context keeps its Interest's id, so the Interest's key and kind are the
/// filter's own and the row keeps only what the Interest adds to them.
#[derive(Clone, Copy, Debug)]
struct HeldInterest {
    id: EntityId,
    mapping_id: ExprId,
    aggregate: bool,
    /// Where in the filter's key the rest of the key the Interest names lies, as a start and a
    /// length, so the row keeps no copy of it; `None` for no rest.
    suffix: Option<(u16, u16)>,
}

/// The Interest a write filter holds open, read off its row ([`WriteFilterRow::interest`]): what
/// a link is asked, borrowed from the row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilterInterest<'a> {
    /// The id the Interest carries.
    pub id: EntityId,
    /// What it asks about: what the filter counts.
    pub kind: InterestKind,
    /// The key it asks about: the filter's.
    pub key: &'a str,
    /// The key expression declaration it names its key by, `0` for none.
    pub mapping_id: ExprId,
    /// Whether it asks the peer for aggregated answers.
    pub aggregate: bool,
    /// The rest of the key it names after its declaration: the whole key when it names none.
    pub suffix: Option<&'a str>,
}

/// How an Interest names its key on the wire: a key expression declaration of the session and the
/// rest of the key after it, or the whole key with `mapping_id` `0`, and whether it asks the peer
/// for aggregated answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterestName<'a> {
    /// The declaration, `0` for none.
    pub mapping_id: ExprId,
    /// What follows the declaration's key; the whole key when `mapping_id` is `0`.
    pub suffix: Option<&'a str>,
    /// Ask the peer to answer aggregated.
    pub aggregate: bool,
}

impl<'a> InterestName<'a> {
    /// `key` whole, by no declaration, not aggregated: how a matching listener asks.
    pub fn whole(key: &'a str) -> Self {
        Self {
            mapping_id: 0,
            suffix: Some(key),
            aggregate: false,
        }
    }
}

/// How the row of a write filter on `key` keeps the `name` of its Interest: its declaration, whether it aggregates, and
/// where in `key` its rest lies, read there rather than copied. A rest is the tail of the key it
/// names, so it is found at the end of `key`, else anywhere in it; one found nowhere is named as
/// `key` whole by no declaration, the same key. `None` for a key too long to be told by a range.
fn kept_name(key: &str, name: InterestName<'_>) -> Option<KeptName> {
    let range = |at: usize, len: usize| Some((u16::try_from(at).ok()?, u16::try_from(len).ok()?));
    let kept = |mapping_id, suffix| KeptName {
        mapping_id,
        aggregate: name.aggregate,
        suffix,
    };
    let Some(rest) = name.suffix else {
        return Some(kept(name.mapping_id, None));
    };
    // Searched as bytes: a text search brings the pattern searcher and the panic formatting of a
    // text slice into every image that holds an Interest. A rest is whole UTF-8, so the place it
    // starts at is a character boundary of `key`.
    let (bytes, wanted) = (key.as_bytes(), rest.as_bytes());
    let tail = key
        .len()
        .checked_sub(rest.len())
        .filter(|_| bytes.ends_with(wanted));
    let inside =
        || (0..key.len()).find(|&at| bytes.get(at..).is_some_and(|from| from.starts_with(wanted)));
    match tail.or_else(inside) {
        Some(at) => Some(kept(name.mapping_id, Some(range(at, rest.len())?))),
        None => Some(kept(0, Some(range(0, key.len())?))),
    }
}

/// An [`InterestName`] as the row of its write filter keeps it ([`kept_name`]).
struct KeptName {
    mapping_id: ExprId,
    aggregate: bool,
    /// Where in the key the rest lies, as a start and a length; `None` for no rest.
    suffix: Option<(u16, u16)>,
}

/// A publisher's or a querier's write filter: whether a put or a get is sent at all.
#[derive(Debug)]
pub struct WriteFilterRow<Key> {
    plane: Plane,
    /// The Interest it holds, `None` for a filter that asks the peers nothing.
    interest: Option<HeldInterest>,
    key: Key,
    /// The declaration the entity's key is named by, which the row holds as an entity's row holds
    /// its own ([`EntityKey::named`]), so the entity keeps no hold of its key; `None` for none.
    own: Option<KeyexprHandle>,
    count_local: bool,
    /// Whether a matching listener declared on a key owns it: it counts apart from the publishers'
    /// and the queriers' bounds, and goes with that listener.
    for_listener: bool,
    /// How many matching listeners are declared on it: its status is read for them alone.
    listeners: u16,
    /// Whether it matched when it was last read for its listeners (zenoh-pico's
    /// `ctx->state != WRITE_FILTER_ACTIVE`): each listener told otherwise is owed the change.
    matching: Cell<bool>,
    /// What the peers answered, with the count of [`PeerDeclarations::written`] it was read at.
    verdict: Cell<Option<(u64, bool)>>,
    /// How a write of the filter's entity that brings nothing of its own is sent the plain way,
    /// stated by that entity ([`SessionTables::keep_write_filter_plain`]); `None` sends it the
    /// general way.
    #[cfg(feature = "alloc")]
    plain: Cell<Option<PlainWay>>,
    /// The sender's epoch at which the plain way was found written from its head on every link
    /// ([`Self::keep_plan`]): a put at the same epoch is written from it with nothing asked again.
    #[cfg(all(feature = "alloc", feature = "codec-push"))]
    planned: Cell<Option<u64>>,
}

/// How a write of a write filter's entity that brings nothing of its own is sent the plain way:
/// the facts it is sent from and the head they write. The declaration that names the entity's key
/// is not kept here: the entity names it on every write (its wire key), and the row holds it
/// (`WriteFilterRow::own`).
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug)]
pub struct PlainWay {
    /// The facts the Put is sent from.
    pub params: crate::publish_options::PlainPutParams,
    /// The Put's bytes up to its payload's length, written once here for the declaration that
    /// names the entity's key and the QoS: `None` for a key no declaration names by an id.
    #[cfg(feature = "codec-push")]
    pub head: Option<crate::lent_push::PutHead>,
}

/// A plain put of a write filter's way as its plan holds it ([`WriteFilterRow::planned_put`]):
/// the filter's key named by the head's declaration alone, the head and the facts it is sent from.
/// Made by the row alone, from a plan it checked, so no holder pairs a key with a head of its own.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
#[derive(Clone, Copy, Debug)]
pub struct PlannedPut<'r> {
    key: crate::named_key::NamedKey<'r>,
    head: crate::lent_push::PutHead,
    params: crate::publish_options::PlainPutParams,
}

#[cfg(all(feature = "alloc", feature = "codec-push"))]
impl<'r> PlannedPut<'r> {
    /// The filter's key, named by the declaration the head was written for.
    pub fn key(&self) -> crate::named_key::NamedKey<'r> {
        self.key
    }

    /// The Put's head.
    pub fn head(&self) -> crate::lent_push::PutHead {
        self.head
    }

    /// The facts the Put is sent from.
    pub fn params(&self) -> crate::publish_options::PlainPutParams {
        self.params
    }
}

/// A key expression declaration as its holder names it: the id the wire names it by, `0` for
/// none, and the row of the session's tables the holder found it at, `None` for a holder that
/// knows only the id. A row is read in place while it still holds the id
/// ([`SessionTables::keyexpr_at`]), so a holder that kept one never searches the declarations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyexprRef {
    /// The id the wire names the declaration by.
    pub id: ExprId,
    /// The row the holder found it at.
    pub row: Option<KeyexprHandle>,
}

impl KeyexprRef {
    /// The declaration `id` names, at no row known.
    pub const fn by_id(id: ExprId) -> Self {
        Self { id, row: None }
    }
}

impl<Key: KeyBacking> WriteFilterRow<Key> {
    /// What it counts.
    pub fn plane(&self) -> Plane {
        self.plane
    }

    /// The Interest it holds, `None` when it asks the peers nothing.
    pub fn interest(&self) -> Option<FilterInterest<'_>> {
        let held = self.interest?;
        let key = self.key.as_str();
        Some(FilterInterest {
            id: held.id,
            kind: self.plane.interest_kind(),
            key,
            mapping_id: held.mapping_id,
            aggregate: held.aggregate,
            suffix: held.suffix.and_then(|(at, len)| {
                let at = usize::from(at);
                key.get(at..at.checked_add(usize::from(len))?)
            }),
        })
    }

    /// The key it filters on.
    pub fn key(&self) -> &str {
        self.key.as_str()
    }

    /// The declaration the row holds that its key is named by, `None` when it holds none: what a
    /// program asking for the entity's key is lent beside the key's text.
    pub fn own(&self) -> Option<KeyexprHandle> {
        self.own
    }

    /// How a write that brings nothing of its own is sent the plain way, when its entity said.
    #[cfg(feature = "alloc")]
    pub fn plain(&self) -> Option<PlainWay> {
        self.plain.get()
    }

    /// Whether the session's own entities count.
    pub fn count_local(&self) -> bool {
        self.count_local
    }

    /// Whether it matched when it was last read for its listeners.
    pub fn matching(&self) -> bool {
        self.matching.get()
    }

    /// The put of the plain way as planned at `epoch`, while the plan stands there: `None` for a
    /// row planned at another epoch or never, which the sender plans again.
    #[cfg(all(feature = "alloc", feature = "codec-push"))]
    pub fn planned_put(&self, epoch: u64) -> Option<PlannedPut<'_>> {
        if self.planned.get() != Some(epoch) {
            return None;
        }
        let way = self.plain.get()?;
        let head = way.head?;
        Some(PlannedPut {
            key: crate::named_key::NamedKey::by_head(self.key.as_str(), &head)?,
            head,
            params: way.params,
        })
    }

    /// Plan the plain way at the sender's `epoch`, `named` being the filter's key as the session
    /// names it: kept when that is the way's head's declaration alone, and dropped otherwise.
    /// The sender answers for the rest its epoch stands for (its links, and what the filter's
    /// answer and the put's way are read from). Whether the plan was kept.
    #[cfg(all(feature = "alloc", feature = "codec-push"))]
    pub fn keep_plan(&self, epoch: u64, named: crate::named_key::NamedKey<'_>) -> bool {
        let holds = named.text() == self.key.as_str()
            && self
                .plain
                .get()
                .and_then(|way| way.head)
                .is_some_and(|head| head.names(named.wire()));
        self.planned.set(holds.then_some(epoch));
        holds
    }
}

/// A matching listener: a callback of a write filter, told when what the filter counts starts or
/// stops matching, and gone with it ([`SessionTables::undeclare_write_filter`]). One declared on a
/// key owns the filter it is declared on, which goes with it.
#[derive(Debug)]
pub struct MatchingRow<Cb> {
    filter: WriteFilterHandle,
    owns_filter: bool,
    /// The status its callback was last handed: one apart from its filter's is owed to it
    /// ([`SessionTables::take_owed_matching`]), so a change and the change back before the first
    /// was handed owe it nothing.
    told: Cell<bool>,
    callback: Cb,
}

impl<Cb> MatchingRow<Cb> {
    /// The write filter it is declared on.
    pub fn filter(&self) -> WriteFilterHandle {
        self.filter
    }

    /// Whether it was declared on a key, and owns its filter.
    pub fn owns_filter(&self) -> bool {
        self.owns_filter
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
pub type Keyexprs<P> = SlotMap<
    kind::Keyexpr,
    KeyexprRow<<P as Storage>::Key, <P as Storage>::KeyLen>,
    { caps::MAX_DECLARED_KEYEXPRS },
    P,
>;
/// A subscriber's row of a build's tables.
pub type Subscriber<F, P> = SubscriberRow<<P as Storage>::Key, <F as RowCallbacks>::Subscriber>;
/// The subscribers' table.
pub type Subscribers<F, P> =
    SlotMap<kind::Subscriber, Subscriber<F, P>, { caps::MAX_SUBSCRIPTIONS }, P>;
/// A queryable's row of a build's tables.
pub type Queryable<F, P> = QueryableRow<<P as Storage>::Key, <F as RowCallbacks>::Queryable>;
/// The queryables' table.
pub type Queryables<F, P> = SlotMap<kind::Queryable, Queryable<F, P>, { caps::MAX_QUERYABLES }, P>;
/// The queryables' table where the tables keep one ([`RowCallbacks::QueryablePresence`]): the
/// table itself, or nothing.
pub type QueryablesKept<F, P> =
    <<F as RowCallbacks>::QueryablePresence as Presence>::Table<Queryables<F, P>>;
/// The liveliness tokens' table where the tables keep one.
pub type TokensKept<F, P> = <<F as RowCallbacks>::LivelinessPresence as Presence>::Table<Tokens<P>>;
/// The liveliness subscribers' table where the tables keep one.
pub type LivelinessSubscribersKept<F, P> =
    <<F as RowCallbacks>::LivelinessPresence as Presence>::Table<LivelinessSubscribers<F, P>>;
/// The write filters' table where the tables keep one.
pub type WriteFiltersKept<F, P> =
    <<F as RowCallbacks>::FilterPresence as Presence>::Table<WriteFilters<P>>;
/// The matching listeners' table where the tables keep write filters.
pub type MatchingListenersKept<F, P> =
    <<F as RowCallbacks>::FilterPresence as Presence>::Table<MatchingListeners<F, P>>;
/// The pending gets' table where the tables keep one.
pub type PendingGetsKept<F, P> =
    <<F as RowCallbacks>::GetPresence as Presence>::Table<PendingGets<F, P>>;
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
/// The write filters' table.
pub type WriteFilters<P> =
    SlotMap<kind::WriteFilter, WriteFilterRow<<P as Storage>::Key>, FILTER_ROWS, P>;
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
    /// `MAX_PUBLISHERS`: the publishers' write filters.
    pub publishers: usize,
    /// `MAX_QUERIERS`: the queriers' write filters.
    pub queriers: usize,
    /// `MAX_MATCHING_LISTENERS`.
    pub matching_listeners: usize,
    /// The matching listeners declared on a key, each with a write filter of its own:
    /// `MAX_MATCHING_LISTENERS` where the engine keeps such listeners, none where it does not.
    pub key_listeners: usize,
    /// `MAX_PENDING_QUERIES`.
    pub pending_gets: usize,
    /// `MAX_PENDING_REPLIES`: the replies the consolidating gets hold back, of all of them.
    pub held_replies: usize,
}

impl TableRows {
    /// The write filters' one table: a publisher's and a querier's each, and a key listener's.
    pub const fn write_filters(&self) -> usize {
        self.publishers
            .saturating_add(self.queriers)
            .saturating_add(self.key_listeners)
    }
}

/// The most write filters of each owner the tables hold, in the one table lent for all: a
/// publisher's are held to `MAX_PUBLISHERS`, a querier's to `MAX_QUERIERS` and a key listener's
/// to the key listeners' rows.
// Each bound is kept inverted, as `slot_map`'s limit is, so tables of all zero bytes are bound by
// nothing but each table's own rows until the session's open holds them to its limits.
#[derive(Clone, Copy, Debug)]
struct PlaneBounds {
    inverted_publishers: usize,
    inverted_queriers: usize,
    inverted_listeners: usize,
}

impl PlaneBounds {
    /// No bound but the table's own.
    const UNBOUND: Self = Self {
        inverted_publishers: 0,
        inverted_queriers: 0,
        inverted_listeners: 0,
    };

    /// The bounds `rows` gives.
    fn of(rows: &TableRows) -> Self {
        Self {
            inverted_publishers: !rows.publishers,
            inverted_queriers: !rows.queriers,
            inverted_listeners: !rows.key_listeners,
        }
    }

    /// The bound of a filter of `plane`'s kind, or of a key listener's.
    fn of_filter(self, plane: Plane, for_listener: bool) -> usize {
        match plane {
            _ if for_listener => !self.inverted_listeners,
            Plane::Subscribers => !self.inverted_publishers,
            Plane::Queryables { .. } => !self.inverted_queriers,
        }
    }
}

/// The entity ids a session's tables handed out, counted, so tables of all zero bytes have handed
/// out none and hand out 1 first, and every id is spent once `EntityId::MAX` of them were.
#[derive(Clone, Copy, Debug, Default)]
struct EntityIds {
    given: EntityId,
}

impl EntityIds {
    /// The id the next declaration takes, `None` once every one has been handed out.
    const fn next(self) -> Option<EntityId> {
        self.given.checked_add(1)
    }

    /// The next id, now handed out.
    fn take(&mut self) -> Option<EntityId> {
        let id = self.next()?;
        self.given = id;
        Some(id)
    }

    /// Ids handed out from `next` on, or none with `None`. No session hands out 0, so ids from 0
    /// are ids from 1.
    const fn from_next(next: Option<EntityId>) -> Self {
        Self {
            given: match next {
                Some(next) => next.saturating_sub(1),
                None => EntityId::MAX,
            },
        }
    }
}

/// A declaration made: its row, and the id the wire names it by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Declared<K> {
    /// Its row.
    pub handle: Handle<K>,
    /// Its entity id.
    pub id: EntityId,
    /// Its key as the row keeps it, read where the row was put.
    pub key: RowKey,
}

/// An entity's key as its row keeps it: where its text lies, and the declaration the row holds
/// that the key is lent with, the one of the entity's own key or else the one the key is named by.
/// Read off the row where it is put (`Declared::key`), so a declaration lends its key with no
/// second look at the row. The text stays where it is while the row stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowKey {
    start: *const u8,
    len: usize,
    /// The declaration the key is lent with, `None` for none.
    pub held: Option<KeyexprHandle>,
}

impl RowKey {
    /// `text`, as a row keeps it, lent with `held`.
    pub fn of(text: &str, held: Option<KeyexprHandle>) -> Self {
        Self {
            start: text.as_ptr(),
            len: text.len(),
            held,
        }
    }

    /// The key's text.
    ///
    /// # Safety
    /// The row this was read off stands, so its text is where it was read.
    pub unsafe fn text<'a>(&self) -> &'a str {
        // SAFETY: the caller's: the row stands, and keeps at `start` the `len` bytes of the
        // `str` this was made of.
        unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(self.start, self.len)) }
    }
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
    /// The address of the row's count of holders, read where the hold was taken, so a holder
    /// names its row with no second look at the table ([`Self::count`]).
    count: usize,
}

impl KeyexprDeclared {
    /// The count of holders of the row the hold was taken in, where it lies.
    ///
    /// # Safety
    /// The row stands (a hold of it is not given back) and the tables keep their rows in place
    /// (a region, a lent span, or the growable policy's chunks), so the count is where it was read.
    pub unsafe fn count<'a>(&self) -> &'a KeyexprCount {
        // SAFETY: the caller's: the address is of the count of a row that still stands where it
        // was when the hold was taken.
        unsafe { &*(self.count as *const KeyexprCount) }
    }
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
pub struct Undeclared<T> {
    /// The id its retraction names.
    pub id: EntityId,
    /// What the caller drops where it holds no lock: the callback of a kind that has one, the row
    /// let go of around it, or the row of a kind that has none; `None` while a call of its
    /// callback runs, whose last unpin hands the row back.
    pub taken: Option<T>,
    /// The key expression declaration the entity's key was named by, when the entity held it
    /// last, retracted with it: its id goes on the wire after the entity's retraction.
    pub keyexpr: Option<ExprId>,
    /// The declaration of its own key ([`KeyForm::own`]), when that was another and the entity
    /// held it last: retracted as [`Self::keyexpr`] is, after it.
    pub named: Option<ExprId>,
}

/// A write filter or a matching listener declared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watching<K> {
    /// Its row.
    pub handle: Handle<K>,
    /// The Interest it opened, to send; `None` for a write filter that asks the peers nothing.
    pub interest: Option<OpenedInterest>,
}

/// An Interest a declaration opened, to send: the row of the write filter that holds it, which the
/// sender reads it from, and its id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenedInterest {
    /// The row of the write filter that holds it.
    pub handle: WriteFilterHandle,
    /// The id it carries.
    pub id: EntityId,
}

/// A write filter undeclared ([`SessionTables::undeclare_write_filter`]). Its row is dropped where
/// it lay: it owns no program callback, and its key is one of the key arena's, which is let go of
/// under the lock the tables are held by, so nothing of it is handed to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterUnwatched {
    /// The id of the Interest it held last, whose Final goes on the wire.
    pub interest_final: Option<EntityId>,
    /// The declaration the row held that the entity's key is named by ([`WriteFilterRow::own`]),
    /// `None` for none: the row's hold of it is the caller's from here on, given back as any
    /// holder's is ([`SessionTables::undeclare_keyexpr`]), so a key's last hold is let go of, and
    /// its retraction sent, by one body whoever held it.
    pub held: Option<KeyexprHandle>,
}

/// A matching listener undeclared.
pub struct Unwatched<R> {
    /// The row, for the caller to drop where it holds no lock; `None` while a call of its
    /// callback runs, whose last unpin hands it back.
    pub row: Option<R>,
    /// The id of the Interest it held last, whose Final goes on the wire.
    pub interest_final: Option<EntityId>,
    /// The declaration the row held that the entity's key is named by ([`WriteFilterRow::own`]),
    /// `None` for none: the row's hold of it is the caller's from here on, given back as any
    /// holder's is ([`SessionTables::undeclare_keyexpr`]), so a key's last hold is let go of, and
    /// its retraction sent, by one body whoever held it.
    pub held: Option<KeyexprHandle>,
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
const fn held_arena_bytes(rows: usize) -> Option<usize> {
    crate::reply_hold::HeldReplies::<PendingGetHandle, Lent>::arena_bytes(rows)
}

/// See the `storage-profile` form.
#[cfg(not(feature = "storage-profile"))]
const fn held_arena_bytes(_rows: usize) -> Option<usize> {
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
    /// The entity ids handed out.
    next_entity: EntityIds,
    /// The next key expression id to try: 0 is tried as 1, so tables of all zero bytes mint 1
    /// first.
    next_expr: ExprId,
    next_request: RequestId,
    /// Moves after every subscriber declared or undeclared, and when the key gate is replaced
    /// ([`crate::pubsub::LocalSubscribers::epoch`]).
    subscriber_epoch: u64,
    /// Which subscribers the keys delivered lately reached, valid at one `subscriber_epoch`: the
    /// subscriber table's receive match cache, over these rows' places.
    memo: MatchMemo<P>,
    /// What decides which keys a peer's message may be on, asked before any subscriber is looked
    /// up ([`Self::set_key_gate`]).
    key_gate: KeyGate<'static>,
    keyexprs: Keyexprs<P>,
    subscribers: Subscribers<F, P>,
    queryables: QueryablesKept<F, P>,
    tokens: TokensKept<F, P>,
    liveliness_subscribers: LivelinessSubscribersKept<F, P>,
    write_filters: WriteFiltersKept<F, P>,
    /// What holds a plane's write filters to its own bound in the table the two planes share.
    plane_bounds: PlaneBounds,
    matching: MatchingListenersKept<F, P>,
    pending_gets: PendingGetsKept<F, P>,
    /// What the consolidating gets hold back (`consolidate_reply`).
    #[cfg(feature = "storage-profile")]
    held: crate::reply_hold::HeldReplies<PendingGetHandle, P>,
}

/// The session's own tokens are the rows of its tokens' table, where the tables keep one: what a
/// peer's liveliness Interest is answered from, with no second table of them.
#[cfg(feature = "liveliness-token")]
impl<F: RowCallbacks, P: Storage> crate::declare::local_token::HeldTokens for SessionTables<F, P> {
    fn each_token(&self, each: &mut dyn FnMut(u64, &str)) {
        for (_, row) in self
            .kept_tokens()
            .into_iter()
            .flat_map(|tokens| tokens.iter())
        {
            each(u64::from(row.id), text(&row.key.key));
        }
    }

    fn keyexpr_for(&self, token_id: u64) -> Option<&str> {
        self.kept_tokens()?
            .iter()
            .find(|(_, row)| u64::from(row.id) == token_id)
            .map(|(_, row)| text(&row.key.key))
    }
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
    /// The declarations the row holds ([`EntityKey::holds`]).
    fn key_holds(&self) -> (Option<KeyexprHandle>, Option<KeyexprHandle>);
    /// Retire what the row calls ([`RowCallback::retire`]): `true` when no call of it runs.
    fn retire(&self) -> bool;
    /// Whether the row, retired, has no call left running ([`RowCallback::drained`]).
    fn drained(&self) -> bool;
    /// The key as the row keeps it, lent with its declaration ([`EntityKey::lent`]).
    fn row_key(&self) -> RowKey;
}

impl<Key: KeyBacking, Cb: RowCallback> Entity for SubscriberRow<Key, Cb> {
    fn entity_id(&self) -> EntityId {
        self.id
    }
    fn key_holds(&self) -> (Option<KeyexprHandle>, Option<KeyexprHandle>) {
        self.key.holds()
    }
    fn retire(&self) -> bool {
        self.callback.retire()
    }
    fn drained(&self) -> bool {
        self.callback.drained()
    }
    fn row_key(&self) -> RowKey {
        self.key.lent()
    }
}

impl<Key: KeyBacking, Cb: RowCallback> Entity for QueryableRow<Key, Cb> {
    fn entity_id(&self) -> EntityId {
        self.id
    }
    fn key_holds(&self) -> (Option<KeyexprHandle>, Option<KeyexprHandle>) {
        self.key.holds()
    }
    fn retire(&self) -> bool {
        self.callback.retire()
    }
    fn drained(&self) -> bool {
        self.callback.drained()
    }
    fn row_key(&self) -> RowKey {
        self.key.lent()
    }
}

impl<Key: KeyBacking> Entity for TokenRow<Key> {
    fn entity_id(&self) -> EntityId {
        self.id
    }
    fn key_holds(&self) -> (Option<KeyexprHandle>, Option<KeyexprHandle>) {
        self.key.holds()
    }
    fn retire(&self) -> bool {
        true
    }
    fn drained(&self) -> bool {
        true
    }
    fn row_key(&self) -> RowKey {
        self.key.lent()
    }
}

impl<Key: KeyBacking, Cb: RowCallback> Entity for LivelinessSubscriberRow<Key, Cb> {
    fn entity_id(&self) -> EntityId {
        self.id
    }
    fn key_holds(&self) -> (Option<KeyexprHandle>, Option<KeyexprHandle>) {
        self.key.holds()
    }
    fn retire(&self) -> bool {
        self.callback.retire()
    }
    fn drained(&self) -> bool {
        self.callback.drained()
    }
    fn row_key(&self) -> RowKey {
        self.key.lent()
    }
}

/// Hold the declaration `held` names once more, for a row put in its table after its count was
/// found to have room ([`Declaring::holdable`]). A holder at the row's address that filled the
/// count since is let be, as a count at its bound is.
fn hold_keyexpr<P: Storage>(keyexprs: &Keyexprs<P>, held: Option<KeyexprHandle>) {
    if let Some(held) = held {
        if let Some(row) = keyexprs.get(held) {
            let _ = row.head.count.retain(held);
        }
    }
}

/// Take one hold of the declaration `handle` names off it: its id when that was the last, and the
/// declaration is gone.
fn release_keyexpr<P: Storage>(
    keyexprs: &mut Keyexprs<P>,
    handle: KeyexprHandle,
) -> Option<ExprId> {
    let entry = keyexprs.entry(handle)?;
    let row = entry.get()?;
    if !row.head.count.release() {
        return None;
    }
    let id = row.id();
    let _ = entry.discard();
    Some(id)
}

/// A declaration found with its row: the handle the table knows it by and the row it reads.
type FoundKeyexpr<'a, P> = Option<(
    KeyexprHandle,
    &'a KeyexprRow<<P as Storage>::Key, <P as Storage>::KeyLen>,
)>;

/// The declaration the wire names by `id` and its row: the one search of the declarations by id,
/// which every lookup that knows only the id reads.
#[inline(never)]
fn keyexpr_row_by_id<P: Storage>(keyexprs: &Keyexprs<P>, id: ExprId) -> FoundKeyexpr<'_, P> {
    keyexprs.iter().find(|(_, row)| row.id() == id)
}

/// Remove the entity `handle` names from `table`, and its holds of the declarations it names.
// What the caller drops is taken out of the row here (`hand`), once for every caller, so the
// whole row is moved no further than this.
fn undeclare_entity<K, R: Entity, T, P: Storage, const N: usize>(
    table: &mut SlotMap<K, R, N, P>,
    keyexprs: &mut Keyexprs<P>,
    handle: Handle<K>,
    hand: impl FnOnce(R) -> T,
) -> Option<Undeclared<T>> {
    let mut entry = table.entry(handle)?;
    let (id, (prefix, named), idle) = entry
        .get()
        .map(|row| (row.entity_id(), row.key_holds(), row.retire()))?;
    // A row a call of which runs is kept, retired, for the call that ends last to let go of
    // (`release_*`).
    if !(idle || entry.pin()) {
        return None;
    }
    let removal = entry.remove()?;
    let keyexpr = prefix.and_then(|prefix| release_keyexpr(keyexprs, prefix));
    let named = named.and_then(|named| release_keyexpr(keyexprs, named));
    Some(Undeclared {
        id,
        taken: removal.taken().map(hand),
        keyexpr,
        named,
    })
}

/// Take out of `table` the next row at or after `cursor` that was removed while a call of it ran
/// and whose last call has ended since: its row, for the caller to drop where no lock is held. The
/// row's latch is the one mark that it waits ([`Entity::drained`]), so the rows that wait are
/// found by this walk and no list of them is kept beside the table.
fn release_drained<K, R: Entity, P: Storage, const N: usize>(
    table: &mut SlotMap<K, R, N, P>,
    cursor: &mut usize,
) -> Option<R> {
    let handle = loop {
        let (handle, row) = table.next_retired_from(cursor)?;
        if row.drained() {
            break handle;
        }
    };
    table.release(handle)
}

/// What a declaration reads and moves besides its own table.
struct Declaring<'a, P: Storage> {
    keys: &'a P::Keys,
    keyexprs: &'a mut Keyexprs<P>,
    next_entity: &'a mut EntityIds,
}

impl<P: Storage> Declaring<'_, P> {
    /// `text` kept as a row keeps it, named on the wire as `form` asks where it can be. Refused
    /// with [`RegisterError::KeyexprHoldsFull`], keeping nothing, when a declaration the row would
    /// hold has as many holders as its count holds: a row that named it holding nothing would name
    /// a declaration its last counted holder's going retracts.
    fn entity_key(&self, text: &str, form: KeyForm) -> Result<EntityKey<P::Key>, RegisterError> {
        // Each declaration is looked up once, and its count read off the row that look found.
        let prefix = Self::holdable(form.prefix.and_then(|prefix| {
            self.keyexprs
                .get(prefix)
                .filter(|row| text.starts_with(KeyBacking::as_str(&row.key)))
                .map(|row| (prefix, row.holds()))
        }))?;
        // The declaration of the entity's own key: the one the form states, or else the one a
        // named retraction names, found by its id once, here, and held by handle from here on.
        // One no longer declared is not held, and a retraction that named it names the key whole.
        let stated = form
            .own
            .and_then(|own| Some((own, self.keyexprs.get(own)?.holds())));
        let named = Self::holdable(stated.or_else(|| {
            match form.retraction {
                Retraction::Named(named) if named.mapping_id != 0 => {
                    keyexpr_row_by_id(&*self.keyexprs, named.mapping_id)
                        .map(|(handle, row)| (handle, row.holds()))
                }
                _ => None,
            }
        }))?;
        let key = KeyMaker::shared(self.keys, text).map_err(unkept)?;
        // A key the gate refuses is kept unproven, and each send of it judges it and refuses it
        // as before.
        #[cfg(feature = "storage-profile")]
        let proven = crate::keyexpr_canon::check_outbound_keyexpr_pico_safe(text).is_ok();
        #[cfg(not(feature = "storage-profile"))]
        let proven = false;
        Ok(EntityKey {
            key,
            prefix,
            named,
            retraction: form.retraction,
            proven,
        })
    }

    /// A declaration found standing, with the holders its count has: its handle where the count
    /// has room for one more; `None` where none was found, which is held by nothing; refused
    /// where its count is full.
    fn holdable(
        found: Option<(KeyexprHandle, KeyexprHolds)>,
    ) -> Result<Option<KeyexprHandle>, RegisterError> {
        match found {
            Some((_, holds)) if holds == KeyexprHolds::MAX => Err(RegisterError::KeyexprHoldsFull),
            stands => Ok(stands.map(|(handle, _)| handle)),
        }
    }

    /// The id and the key of an entity declared on `text` as `form` asks, into a table with
    /// room for its row (`room`): the first refusal met when there is none, with nothing kept.
    // Out of line: one body admits every kind of entity, so each kind a build links adds only the
    // insert of its own row (`Self::declare`), not another copy of the key's admission.
    #[inline(never)]
    fn keyed(
        &mut self,
        room: bool,
        text: &str,
        form: KeyForm,
    ) -> Result<(EntityId, EntityKey<P::Key>), RegisterError> {
        if !room {
            return Err(RegisterError::TableFull);
        }
        let key = self.entity_key(text, form)?;
        Ok((self.mint()?, key))
    }

    /// The next entity id.
    fn mint(&mut self) -> Result<EntityId, RegisterError> {
        self.next_entity.take().ok_or(RegisterError::IdsExhausted)
    }

    /// Hold the declaration `prefix` names once more. Its count was found to have room
    /// ([`Self::holdable`]); a holder at the row's address that filled it since is let be, as a
    /// count at its bound is.
    fn hold(&mut self, prefix: Option<KeyexprHandle>) {
        hold_keyexpr(self.keyexprs, prefix);
    }

    /// Declare an entity on `text` into `table`: the row `make` builds of its id, its key and
    /// `callback`, or the refusal with `callback` back.
    // Out of line: the declaration of each kind measured smaller with the row built and placed
    // apart from the caller that hands it its parts.
    #[inline(never)]
    fn declare<K, R: Entity, C, const N: usize>(
        mut self,
        table: &mut SlotMap<K, R, N, P>,
        text: &str,
        form: KeyForm,
        callback: C,
        make: impl FnOnce(EntityId, EntityKey<P::Key>, C) -> R,
    ) -> Result<Declared<K>, Refused<C>> {
        // One refusal hands `callback` back for a full table, a key not kept and the ids run out
        // alike: each of its own would move the callback into the refusal once more.
        let (id, key) = match self.keyed(!table.is_full(), text, form) {
            Ok(keyed) => keyed,
            Err(why) => return Err(Refused { why, callback }),
        };
        let (prefix, named) = key.holds();
        // The row is built only in the slot it is kept in: a table that refuses it after all hands
        // its parts back whole, the key let go of here and the callback with the refusal.
        match table.insert_with_row((id, key, callback), |(id, key, callback)| {
            make(id, key, callback)
        }) {
            Ok((handle, row)) => {
                let key = row.row_key();
                self.hold(prefix);
                self.hold(named);
                Ok(Declared { handle, id, key })
            }
            Err((_, _, callback)) => Err(Refused {
                why: RegisterError::TableFull,
                callback,
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
            next_entity: EntityIds::default(),
            next_expr: 1,
            next_request: 0,
            subscriber_epoch: 0,
            memo: MatchMemo::new(
                <crate::limits::MatchMemoSlots as crate::limit_binding::LimitSpec>::DEFAULT,
            ),
            key_gate: KeyGate::of_build(),
            keyexprs: SlotMap::new(),
            subscribers: SlotMap::new(),
            queryables: <F::QueryablePresence as Presence>::empty::<Queryables<F, P>>(),
            tokens: <F::LivelinessPresence as Presence>::empty::<Tokens<P>>(),
            liveliness_subscribers: <F::LivelinessPresence as Presence>::empty::<
                LivelinessSubscribers<F, P>,
            >(),
            write_filters: <F::FilterPresence as Presence>::empty::<WriteFilters<P>>(),
            plane_bounds: PlaneBounds::UNBOUND,
            matching: <F::FilterPresence as Presence>::empty::<MatchingListeners<F, P>>(),
            pending_gets: <F::GetPresence as Presence>::empty::<PendingGets<F, P>>(),
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

    /// Replace the gate that decides which keys a message from a peer may be on, which starts as
    /// what the build's `key-set` policy states, as
    /// [`crate::pubsub::SubscriberTable::set_key_gate`] does: a closed image hands it the gate over
    /// its generated table. The counts of the gate it replaces are not carried over. The rows hold
    /// no entity of the image's, so a key of the set reaches the rows its pattern meets.
    pub fn set_key_gate(&mut self, gate: KeyGate<'static>) {
        self.key_gate = gate;
        // An answer a peer's side keeps for a key holds what the gate it replaces admitted.
        self.subscriber_epoch = self.subscriber_epoch.wrapping_add(1);
    }

    /// How many messages from a peer the key gate dropped, by reason: all zero for an open gate.
    pub const fn key_gate_refused(&self) -> crate::key_gate::Refused {
        self.key_gate.refused()
    }

    /// Hold each table to the rows `rows` gives it, under the build's bound.
    pub fn limit_to(&mut self, rows: &TableRows) {
        self.plane_bounds = PlaneBounds::of(rows);
        self.keyexprs.limit_to(rows.keyexprs);
        self.subscribers.limit_to(rows.subscribers);
        if let Some(queryables) = self.kept_queryables_mut() {
            queryables.limit_to(rows.queryables);
        }
        if let Some(table) =
            <F::LivelinessPresence as Presence>::get_mut::<Tokens<P>>(&mut self.tokens)
        {
            table.limit_to(rows.tokens);
        }
        if let Some(table) = <F::LivelinessPresence as Presence>::get_mut::<
            LivelinessSubscribers<F, P>,
        >(&mut self.liveliness_subscribers)
        {
            table.limit_to(rows.liveliness_subscribers);
        }
        if let Some(table) =
            <F::FilterPresence as Presence>::get_mut::<WriteFilters<P>>(&mut self.write_filters)
        {
            table.limit_to(rows.write_filters());
        }
        if let Some(table) =
            <F::FilterPresence as Presence>::get_mut::<MatchingListeners<F, P>>(&mut self.matching)
        {
            table.limit_to(rows.matching_listeners);
        }
        if let Some(table) =
            <F::GetPresence as Presence>::get_mut::<PendingGets<F, P>>(&mut self.pending_gets)
        {
            table.limit_to(rows.pending_gets);
        }
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
    // Out of line: the engine's key expression declaration measured smaller with it apart.
    #[inline(never)]
    pub fn declare_keyexpr_where(
        &mut self,
        key: &str,
        apart: bool,
        usable: impl Fn(ExprId) -> bool,
    ) -> Result<KeyexprDeclared, RegisterError> {
        // The row's count is read once, by the hold taken of it: a row stands with a holder, since
        // a holder at its address never lets go of the last hold (`KeyexprCount::release_shared`)
        // and a retraction removes the row it emptied, and a count that holds none even so takes no
        // hold, so the key is declared apart.
        let found = if apart {
            None
        } else {
            self.keyexprs
                .iter()
                .find(|(_, row)| text(&row.key) == key)
                .map(|(handle, row)| (handle, row, row.head.count.retain(handle)))
        };
        match found {
            Some((handle, row, Ok(()))) => {
                return Ok(KeyexprDeclared {
                    handle,
                    id: row.id(),
                    new: false,
                    count: core::ptr::from_ref(&row.head.count) as usize,
                })
            }
            Some((_, _, Err(RowHoldRefused::Full))) => return Err(RegisterError::TableFull),
            Some((_, _, Err(RowHoldRefused::Released))) | None => {}
        }
        if self.keyexprs.is_full() {
            return Err(RegisterError::TableFull);
        }
        // A key longer than its row can state is refused as one longer than a row keeps.
        let key_len =
            <P::KeyLen as KeyLength>::of(key.len()).ok_or(RegisterError::KeyexprTooLong)?;
        let table = self.address();
        let kept = KeyMaker::shared(&self.keys, key).map_err(unkept)?;
        let id = self.mint_expr(usable).ok_or(RegisterError::IdsExhausted)?;
        // The first hold is taken on the row where it is put, with no second look at the table.
        let (handle, row) = self
            .keyexprs
            .insert_with_row(
                KeyexprRow {
                    key: kept,
                    head: KeyexprHead::new(id, key_len, table),
                },
                core::convert::identity,
            )
            .map_err(|_| RegisterError::TableFull)?;
        row.head.count.first_hold(handle);
        Ok(KeyexprDeclared {
            handle,
            id,
            new: true,
            count: core::ptr::from_ref(&row.head.count) as usize,
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
    pub fn retain_keyexpr(&self, handle: KeyexprHandle) -> bool {
        self.keyexprs
            .get(handle)
            .is_some_and(|row| row.head.count.retain(handle).is_ok())
    }

    /// Whether `head` is of a row of these tables: the address its row names as its tables'
    /// ([`KeyexprHead`]), which a row of another session's tables does not name.
    pub fn is_own_row(&self, head: &KeyexprHead<P::KeyLen>) -> bool {
        head.table == self.address()
    }

    /// The address of these tables, which each row of a declaration names as its tables'.
    fn address(&self) -> usize {
        self as *const Self as usize
    }

    /// Retract the declaration `handle` names whatever holds it: its id, for its retraction to go
    /// on the wire. An entity that named its key by it names it whole from here on
    /// ([`Self::wire_of`]).
    pub fn retract_keyexpr(&mut self, handle: KeyexprHandle) -> Option<ExprId> {
        let entry = self.keyexprs.entry(handle)?;
        let row = entry.get()?;
        let id = row.id();
        // Its count goes to none first: a holder at the row's address takes no more hold of it and
        // gives its own back to the table, which finds the row gone.
        row.head.count.retract(handle);
        let _ = entry.discard();
        Some(id)
    }

    /// Retract every declaration's count at the session's close, each row left where it lies: a
    /// holder that copies its hold from here on takes none ([`RowHoldRefused::Released`] at the
    /// row's address), and one that gives its own back finds no count to take it from, so a hold
    /// kept past the close is judged by its row's word alone, with no reach of the session. The
    /// rows are not removed: a holder past the close still reads its count where it was.
    pub fn close_keyexpr_counts(&self) {
        for (handle, row) in self.keyexprs.iter() {
            row.head.count.retract(handle);
        }
    }

    /// The declaration `declared` names: its row while that row still holds its id, and the
    /// declaration the id names otherwise ([`Self::keyexpr_by_id`]), as for a holder that knows no
    /// row. Ids are minted apart from every declared one, so either way finds the same row. `None`
    /// for the id `0`, which names no declaration.
    pub fn keyexpr_at(&self, declared: KeyexprRef) -> Option<KeyexprHandle> {
        self.keyexpr_row_at(declared).map(|(handle, _)| handle)
    }

    /// [`Self::keyexpr_at`] with the row it found: the one lookup of a declaration a holder names,
    /// which a reader of the row's key reads it in, with no second look at the handle.
    #[inline(never)]
    fn keyexpr_row_at(&self, declared: KeyexprRef) -> FoundKeyexpr<'_, P> {
        if declared.id == 0 {
            return None;
        }
        let kept = declared.row.and_then(|row| {
            let kept = self.keyexprs.get(row)?;
            (kept.id() == declared.id).then_some((row, kept))
        });
        kept.or_else(|| keyexpr_row_by_id(&self.keyexprs, declared.id))
    }

    /// The declaration in row `row` when it declares the first bytes of `key`: its id and how many
    /// bytes of `key` it covers. `None` for a row that went and for one that declares another key,
    /// so a holder that names a row of another session's tables, or one whose generation moved on,
    /// names `key` whole. Wire names concatenate, so a row whose key is a prefix of `key` names
    /// `key` with its id and the rest, whoever holds it.
    pub fn declared_prefix(&self, row: KeyexprHandle, key: &str) -> Option<(ExprId, usize)> {
        let kept = self.keyexprs.get(row)?;
        let declared = kept.key();
        key.starts_with(declared)
            .then_some((kept.id(), declared.len()))
    }

    /// The declaration the wire names by `id`: a search of the declarations, which a holder that
    /// keeps the row it found ([`Self::keyexpr_at`]) does not make.
    pub fn keyexpr_by_id(&self, id: ExprId) -> Option<KeyexprHandle> {
        keyexpr_row_by_id(&self.keyexprs, id).map(|(handle, _)| handle)
    }

    /// The form of an entity's key whose wire names the declaration `mapping_id` (`0` for none):
    /// named by that declaration while it stands, which the entity's row then holds, and retracted
    /// naming what `retraction` says beside the id.
    pub fn key_form(&self, mapping_id: ExprId, retraction: Retraction) -> KeyForm {
        self.key_form_at(KeyexprRef::by_id(mapping_id), retraction)
    }

    /// [`Self::key_form`] of a key whose declaration its holder names with its row.
    pub fn key_form_at(&self, declared: KeyexprRef, retraction: Retraction) -> KeyForm {
        KeyForm {
            prefix: self.keyexpr_at(declared),
            own: None,
            retraction,
        }
    }

    /// The next key expression id: from 1, past any still declared and any `usable` refuses;
    /// `None` when every id is one or the other.
    fn mint_expr(&mut self, usable: impl Fn(ExprId) -> bool) -> Option<ExprId> {
        for _ in 0..=usize::from(ExprId::MAX) {
            let id = self.next_expr.max(1);
            self.next_expr = id.wrapping_add(1);
            if usable(id) && !self.keyexprs.iter().any(|(_, row)| row.id() == id) {
                return Some(id);
            }
        }
        None
    }

    // ---- entity ids ------------------------------------------------------------------------

    /// The next entity id, for an entity the session numbers and keeps no row of here (a
    /// publisher, a querier, a get's Interest); `None` once every one has been handed out.
    // Out of line, as the engine's own taking of an id is: measured smaller apart.
    #[inline(never)]
    pub fn take_entity_id(&mut self) -> Option<EntityId> {
        self.next_entity.take()
    }

    /// The entity id the next declaration takes, `None` once every one has been handed out.
    pub fn next_entity_id(&self) -> Option<EntityId> {
        self.next_entity.next()
    }

    /// Hand out entity ids from `next` on, or none with `None`: for a host that carries a
    /// session's numbering over, and for a test that reaches the end of the space. No id is 0, so
    /// ids from 0 are ids from 1.
    pub fn entity_ids_from(&mut self, next: Option<EntityId>) {
        self.next_entity = EntityIds::from_next(next);
    }

    /// Mint key expression ids from `next` on, past the last to 1 as every mint goes on: for a
    /// test that reaches the wrap of the space without spending it.
    pub fn expr_ids_from(&mut self, next: ExprId) {
        self.next_expr = next;
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
                mapping: row.id(),
                suffix,
            },
            None => literal,
        }
    }

    /// What the retraction of the entity whose key is `key` names beside its id, read against
    /// that key ([`RetractionKey::names`]): `None` for the id alone, and for a key retracted as
    /// it is announced, the declaration its row holds while that stands, the whole key otherwise.
    pub fn retraction_of(&self, key: &EntityKey<P::Key>) -> Option<RetractionKey> {
        match key.retraction {
            Retraction::ById => None,
            Retraction::AsAnnounced => {
                let form = self.wire_of(key);
                Some(RetractionKey::declared(form.mapping, form.suffix))
            }
            // The declaration as the row holds it: its id while it stands, the whole key once it
            // was retracted whatever held it.
            Retraction::Named(named) => {
                let (mapping, rest) = named.names(text(&key.key));
                Some(match key.named.and_then(|held| self.keyexprs.get(held)) {
                    Some(row) if mapping == row.id() => RetractionKey::declared(row.id(), rest),
                    _ => RetractionKey::literal(),
                })
            }
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
            .and_then(|row| Some(Prefix::of(MappedId::new(row.id())?, text(&row.key))));
        let named = NamedKey::under_or_whole(whole, declared)?;
        Some(if key.proven { named.proven() } else { named })
    }

    /// `key`, which the program names by the declaration the wire calls `id` (`0` for none), as
    /// the session sends it: named by that declaration while it stands and begins the key, and
    /// whole otherwise. `None` for an empty key.
    pub fn named_by<'k>(&self, key: &'k str, id: ExprId) -> Option<NamedKey<'k>> {
        self.named_at(key, KeyexprRef::by_id(id))
    }

    /// [`Self::named_by`] for a holder that names the declaration with its row: read there while
    /// that row still holds the id ([`Self::keyexpr_at`]).
    pub fn named_at<'k>(&self, key: &'k str, declared: KeyexprRef) -> Option<NamedKey<'k>> {
        let prefix = MappedId::new(declared.id).and_then(|mapped| {
            let (_, row) = self.keyexpr_row_at(declared)?;
            Some(Prefix::of(mapped, text(&row.key)))
        });
        NamedKey::under_or_whole(key, prefix)
    }

    // ---- entities --------------------------------------------------------------------------

    /// Declare a subscriber on `key`, hearing what `origin` admits.
    // Out of line, as `Declaring::declare` is: measured smaller apart from the engine's caller.
    #[inline(never)]
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
        )?;
        self.subscriber_epoch = self.subscriber_epoch.wrapping_add(1);
        Ok(declared)
    }

    /// Undeclare the subscriber `handle` names, its callback handed back. The row leaves every
    /// lookup now and no call of it begins. When a call of its callback runs
    /// ([`Self::begin_subscriber`]) nothing is handed back here: the call that ends last lets the
    /// row go ([`Self::release_subscriber`]), so the undeclaring caller returns only once
    /// `subscribers().holds_slot(handle)` is false, after the last call has returned and the row,
    /// with its callback, was dropped (P11). The same holds for every kind with a callback.
    pub fn undeclare_subscriber(
        &mut self,
        handle: SubscriberHandle,
    ) -> Option<Undeclared<F::Subscriber>> {
        let undeclared = undeclare_entity(
            &mut self.subscribers,
            &mut self.keyexprs,
            handle,
            SubscriberRow::into_callback,
        )?;
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
        // Tables that keep no queryable have no room for one.
        let Some(queryables) =
            <F::QueryablePresence as Presence>::get_mut::<Queryables<F, P>>(&mut self.queryables)
        else {
            return Err(Refused {
                why: RegisterError::TableFull,
                callback,
            });
        };
        Declaring {
            keys: &self.keys,
            keyexprs: &mut self.keyexprs,
            next_entity: &mut self.next_entity,
        }
        .declare(queryables, key, form, callback, |id, key, callback| {
            QueryableRow {
                facts: KeyFacts::of(key.as_str()),
                id,
                key,
                origin,
                complete,
                callback,
            }
        })
    }

    /// Undeclare the queryable `handle` names, its callback handed back.
    pub fn undeclare_queryable(
        &mut self,
        handle: QueryableHandle,
    ) -> Option<Undeclared<F::Queryable>> {
        let queryables =
            <F::QueryablePresence as Presence>::get_mut::<Queryables<F, P>>(&mut self.queryables)?;
        undeclare_entity(
            queryables,
            &mut self.keyexprs,
            handle,
            QueryableRow::into_callback,
        )
    }

    /// Declare a liveliness token on `key`.
    pub fn declare_token(
        &mut self,
        key: &str,
        form: KeyForm,
    ) -> Result<Declared<kind::Token>, RegisterError> {
        // Tables that keep no token have no room for one.
        let tokens = <F::LivelinessPresence as Presence>::get_mut::<Tokens<P>>(&mut self.tokens)
            .ok_or(RegisterError::TableFull)?;
        Declaring {
            keys: &self.keys,
            keyexprs: &mut self.keyexprs,
            next_entity: &mut self.next_entity,
        }
        .declare(tokens, key, form, (), |id, key, ()| TokenRow { id, key })
        .map_err(|refused| refused.why)
    }

    /// Undeclare the liveliness token `handle` names.
    pub fn undeclare_token(&mut self, handle: TokenHandle) -> Option<Undeclared<TokenRow<P::Key>>> {
        let tokens = <F::LivelinessPresence as Presence>::get_mut::<Tokens<P>>(&mut self.tokens)?;
        undeclare_entity(tokens, &mut self.keyexprs, handle, core::convert::identity)
    }

    /// Declare a liveliness subscriber on `key`, asking for the tokens alive now with `history`.
    pub fn declare_liveliness_subscriber(
        &mut self,
        key: &str,
        history: bool,
        form: KeyForm,
        callback: F::LivelinessSubscriber,
    ) -> Result<Declared<kind::LivelinessSubscriber>, Refused<F::LivelinessSubscriber>> {
        // Tables that keep no liveliness subscriber have no room for one.
        let Some(subscribers) = <F::LivelinessPresence as Presence>::get_mut::<
            LivelinessSubscribers<F, P>,
        >(&mut self.liveliness_subscribers) else {
            return Err(Refused {
                why: RegisterError::TableFull,
                callback,
            });
        };
        Declaring {
            keys: &self.keys,
            keyexprs: &mut self.keyexprs,
            next_entity: &mut self.next_entity,
        }
        .declare(subscribers, key, form, callback, |id, key, callback| {
            LivelinessSubscriberRow {
                id,
                key,
                history,
                history_complete: Cell::new(false),
                callback,
            }
        })
    }

    /// Undeclare the liveliness subscriber `handle` names, its callback handed back: its id is its
    /// Interest's, whose Final goes on the wire.
    pub fn undeclare_liveliness_subscriber(
        &mut self,
        handle: LivelinessSubscriberHandle,
    ) -> Option<Undeclared<F::LivelinessSubscriber>> {
        let subscribers = <F::LivelinessPresence as Presence>::get_mut::<
            LivelinessSubscribers<F, P>,
        >(&mut self.liveliness_subscribers)?;
        undeclare_entity(
            subscribers,
            &mut self.keyexprs,
            handle,
            LivelinessSubscriberRow::into_callback,
        )
    }

    // ---- write filters, the Interests they hold, and matching listeners --------------------

    /// The Interest a write filter on `key` holds, named as `name` says and numbered: one for each
    /// filter, as zenoh-pico adds one for each write filter, whatever is open on the same key
    /// already. The filter's row keeps it, with no key of its own.
    fn ask_interest(
        &mut self,
        key: &str,
        name: InterestName<'_>,
    ) -> Result<HeldInterest, RegisterError> {
        let KeptName {
            mapping_id,
            aggregate,
            suffix,
        } = kept_name(key, name).ok_or(RegisterError::KeyexprTooLong)?;
        let id = self.next_entity.take().ok_or(RegisterError::IdsExhausted)?;
        Ok(HeldInterest {
            id,
            mapping_id,
            aggregate,
            suffix,
        })
    }

    /// Declare the write filter of a publisher or a querier on `key`, its Interest naming `key`
    /// whole ([`InterestName::whole`]).
    pub fn declare_write_filter(
        &mut self,
        plane: Plane,
        key: &str,
        count_local: bool,
    ) -> Result<Watching<kind::WriteFilter>, RegisterError> {
        self.declare_write_filter_as(
            plane,
            key,
            count_local,
            Some(InterestName::whole(key)),
            None,
        )
    }

    /// Whether a write filter of `plane`, or a key listener's, finds room under its own bound in
    /// `filters`, the table they all share: the filters of its owner it holds are fewer than the
    /// bound.
    fn plane_has_room(&self, filters: &WriteFilters<P>, plane: Plane, for_listener: bool) -> bool {
        let kind = plane.interest_kind();
        let held = filters
            .iter()
            .filter(|(_, row)| {
                row.for_listener == for_listener
                    && (for_listener || row.plane.interest_kind() == kind)
            })
            .count();
        held < self.plane_bounds.of_filter(plane, for_listener)
    }

    /// Declare the write filter of a publisher or a querier on `key`, holding an Interest named as
    /// `ask` says, or none for a filter that asks the peers nothing, and `own`, the declaration the
    /// entity's key is named by, until it is undeclared. One no longer declared is not held; one
    /// whose count holds as many holders as it can refuses the filter
    /// ([`RegisterError::KeyexprHoldsFull`]), keeping nothing.
    pub fn declare_write_filter_as(
        &mut self,
        plane: Plane,
        key: &str,
        count_local: bool,
        ask: Option<InterestName<'_>>,
        own: Option<KeyexprHandle>,
    ) -> Result<Watching<kind::WriteFilter>, RegisterError> {
        self.declare_filter(plane, key, count_local, ask, own, false)
    }

    /// [`Self::declare_write_filter_as`] for an entity, or for the matching listener declared on
    /// a key (`for_listener`).
    fn declare_filter(
        &mut self,
        plane: Plane,
        key: &str,
        count_local: bool,
        ask: Option<InterestName<'_>>,
        own: Option<KeyexprHandle>,
        for_listener: bool,
    ) -> Result<Watching<kind::WriteFilter>, RegisterError> {
        // Tables that keep no write filter have no room for one, nor has an owner at its own
        // bound, whatever room the table they share has left.
        match self.kept_write_filters() {
            Some(filters)
                if !filters.is_full() && self.plane_has_room(filters, plane, for_listener) => {}
            _ => return Err(RegisterError::TableFull),
        }
        // The declaration the key is named by is looked up once, and a count with no room for the
        // row refuses the filter before anything is kept or asked. It is held once the row is in,
        // as an entity's row holds its key's (`Declaring::hold`), so no refusal gives a hold back.
        let own = Declaring::<P>::holdable(
            own.and_then(|own| Some((own, self.keyexprs.get(own)?.holds()))),
        )?;
        let kept = KeyMaker::shared(&self.keys, key).map_err(unkept)?;
        let interest = match ask {
            Some(name) => Some(self.ask_interest(key, name)?),
            None => None,
        };
        let row = WriteFilterRow {
            plane,
            interest,
            key: kept,
            own,
            count_local,
            for_listener,
            listeners: 0,
            matching: Cell::new(false),
            verdict: Cell::new(None),
            #[cfg(feature = "alloc")]
            plain: Cell::new(None),
            #[cfg(all(feature = "alloc", feature = "codec-push"))]
            planned: Cell::new(None),
        };
        let inserted = self
            .kept_write_filters_mut()
            .and_then(|filters| filters.insert(row).ok());
        let handle = inserted.ok_or(RegisterError::TableFull)?;
        hold_keyexpr(&self.keyexprs, own);
        Ok(Watching {
            handle,
            interest: interest.map(|held| OpenedInterest {
                handle,
                id: held.id,
            }),
        })
    }

    /// Undeclare the write filter `handle` names, and every matching listener declared on it:
    /// `each` is handed each listener's handle and its removal, the row when no call of it runs,
    /// else [`Removal::AfterCalls`], when the call that ends last lets it go
    /// ([`Self::release_matching_listener`]). The row's hold of the declaration its key is named
    /// by goes to the caller ([`FilterUnwatched::held`]); the row itself is dropped where it lies.
    pub fn undeclare_write_filter(
        &mut self,
        handle: WriteFilterHandle,
        mut each: impl FnMut(MatchingListenerHandle, Removal<Matching<F>>),
    ) -> Option<FilterUnwatched> {
        let (interest_final, own) = {
            let row = self.kept_write_filters()?.get(handle)?;
            (row.interest.map(|held| held.id), row.own)
        };
        let mut cursor = 0usize;
        while let Some((listener, owned)) = self
            .kept_matching()
            .and_then(|matching| matching.next_from(&mut cursor))
            .map(|(listener, row)| (listener, row.filter == handle))
        {
            if owned {
                if let Some(removal) = self.retire_matching_listener(listener) {
                    each(listener, removal);
                }
            }
        }
        // Its key is the arena's and its drop no program's, so it goes where it lies, with no copy
        // of the row moved out to be dropped by the caller under the same lock.
        self.kept_write_filters_mut()?.discard(handle)?;
        Some(FilterUnwatched {
            interest_final,
            held: own,
        })
    }

    /// [`Self::undeclare_write_filter`] handing no caller the listeners it lets go of: one body
    /// for every caller that takes none, where each passed a closure of its own and so held a
    /// copy of the walk over the listeners.
    #[inline(never)]
    pub fn undeclare_write_filter_quietly(
        &mut self,
        handle: WriteFilterHandle,
    ) -> Option<FilterUnwatched> {
        self.undeclare_write_filter(handle, |_, _| {})
    }

    /// Declare a matching listener on the write filter `filter`, whose kind, key and Interest it
    /// reads and with which it goes: it asks the peers nothing of its own, as zenoh-pico's
    /// listener is a callback of its entity's filter
    /// (`vendor/zenoh-pico/src/net/filtering.c` @ `_z_write_filter_ctx_add_callback`). It starts
    /// as not matching: the first [`Self::next_matching_change`] tells it otherwise where it
    /// matches. Refused with [`RegisterError::OwnerGone`] when `filter` names no filter, the
    /// callback handed back.
    pub fn declare_matching_listener(
        &mut self,
        filter: WriteFilterHandle,
        callback: F::Matching,
    ) -> Result<MatchingListenerHandle, Refused<F::Matching>> {
        if self
            .kept_write_filters()
            .and_then(|filters| filters.get(filter))
            .is_none()
        {
            return Err(Refused {
                why: RegisterError::OwnerGone,
                callback,
            });
        }
        self.attach_listener(filter, false, callback)
    }

    /// Put a listener of `filter` in the matching listeners' table, counted on the filter's row.
    fn attach_listener(
        &mut self,
        filter: WriteFilterHandle,
        owns_filter: bool,
        callback: F::Matching,
    ) -> Result<MatchingListenerHandle, Refused<F::Matching>> {
        let handle = self.insert_matching_listener(MatchingRow {
            filter,
            owns_filter,
            told: Cell::new(false),
            callback,
        })?;
        if let Some(row) = self
            .kept_write_filters_mut()
            .and_then(|filters| filters.get_mut(filter))
        {
            row.listeners = row.listeners.saturating_add(1);
        }
        Ok(handle)
    }

    /// Declare a matching listener of what `plane` counts on `key`, with no entity's write filter:
    /// it owns a filter of its own, whose Interest names `key` whole ([`InterestName::whole`]),
    /// whatever is open on the same key and kind, and starts as not matching, as one on a filter
    /// does. Refused, the callback handed back and nothing held, when its table or the key
    /// listeners' filters have no room, the key arena none for its key, or no id is left for its
    /// Interest.
    pub fn declare_matching_listener_on(
        &mut self,
        plane: Plane,
        key: &str,
        count_local: bool,
        callback: F::Matching,
    ) -> Result<Watching<kind::MatchingListener>, Refused<F::Matching>> {
        if !self
            .kept_matching()
            .is_some_and(|matching| !matching.is_full())
        {
            return Err(Refused {
                why: RegisterError::TableFull,
                callback,
            });
        }
        let filter = match self.declare_filter(
            plane,
            key,
            count_local,
            Some(InterestName::whole(key)),
            None,
            true,
        ) {
            Ok(filter) => filter,
            Err(why) => return Err(Refused { why, callback }),
        };
        match self.attach_listener(filter.handle, true, callback) {
            Ok(handle) => Ok(Watching {
                handle,
                interest: filter.interest,
            }),
            Err(refused) => {
                let _ = self.undeclare_write_filter_quietly(filter.handle);
                Err(refused)
            }
        }
    }

    /// Put `row` in the matching listeners' table.
    fn insert_matching_listener(
        &mut self,
        row: Matching<F>,
    ) -> Result<MatchingListenerHandle, Refused<F::Matching>> {
        // Tables that keep write filters keep their listeners.
        let Some(matching) =
            <F::FilterPresence as Presence>::get_mut::<MatchingListeners<F, P>>(&mut self.matching)
        else {
            return Err(Refused {
                why: RegisterError::TableFull,
                callback: row.callback,
            });
        };
        matching.insert(row).map_err(|CapacityFull(row)| Refused {
            why: RegisterError::TableFull,
            callback: row.callback,
        })
    }

    /// Undeclare the matching listener `handle` names: its row when no call of it runs, else none,
    /// when the call that ends last lets it go ([`Self::release_matching_listener`]). An entity's
    /// filter stays; the filter one declared on a key owns goes with it, and the id of its
    /// Interest is handed back, whose Final goes on the wire.
    pub fn undeclare_matching_listener(
        &mut self,
        handle: MatchingListenerHandle,
    ) -> Option<Unwatched<Matching<F>>> {
        let (filter, owns_filter) = {
            let row = self.kept_matching()?.get(handle)?;
            (row.filter, row.owns_filter)
        };
        let removal = self.retire_matching_listener(handle)?;
        let interest_final = if owns_filter {
            self.undeclare_write_filter_quietly(filter)
                .and_then(|gone| gone.interest_final)
        } else {
            None
        };
        // A filter declared on a key holds no declaration of it.
        Some(Unwatched {
            row: removal.taken(),
            interest_final,
            held: None,
        })
    }

    /// Retire the matching listener `handle` names: it leaves every lookup and no call of it
    /// begins, and its filter counts it no more.
    fn retire_matching_listener(
        &mut self,
        handle: MatchingListenerHandle,
    ) -> Option<Removal<Matching<F>>> {
        let mut entry = self.kept_matching_mut()?.entry(handle)?;
        let filter = entry.get()?.filter;
        if !(entry.get()?.callback.retire() || entry.pin()) {
            return None;
        }
        let removal = entry.remove()?;
        if let Some(row) = self
            .kept_write_filters_mut()
            .and_then(|filters| filters.get_mut(filter))
        {
            row.listeners = row.listeners.saturating_sub(1);
        }
        Some(removal)
    }

    /// Whether the session's own entities of `plane` that hear what the session itself sends
    /// reach `key`.
    // Out of line: a write filter's answer and the matching listeners' walk both read it, and each
    // would carry a copy of the walks over the subscribers and the queryables.
    #[inline(never)]
    pub fn local_declares(&self, plane: Plane, key: &str) -> bool {
        match plane {
            Plane::Subscribers => self.subscribers.iter().any(|(_, row)| {
                row.origin.allows_local() && keyexpr_intersects(text(&row.key.key), key)
            }),
            Plane::Queryables { complete_required } => {
                self.kept_queryables().is_some_and(|queryables| {
                    queryables.iter().any(|(_, row)| {
                        row.origin.allows_local()
                            && answers(text(&row.key.key), row.complete, key, complete_required)
                    })
                })
            }
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
        let row = self.kept_write_filters()?.get(handle)?;
        Some(self.write_filter_row_open(row, peers))
    }

    /// [`Self::write_filter_open`] of a filter whose row the caller holds already: a write that
    /// reads the row for its plain way too looks it up once.
    pub fn write_filter_row_open(
        &self,
        row: &WriteFilterRow<P::Key>,
        peers: &impl PeerDeclarations,
    ) -> bool {
        let key = text(&row.key);
        if row.count_local && self.local_declares(row.plane, key) {
            return true;
        }
        let written = peers.written();
        match row.verdict.get() {
            Some((at, verdict)) if at == written => verdict,
            _ => {
                let verdict = peers.declares(row.plane, key);
                row.verdict.set(Some((written, verdict)));
                verdict
            }
        }
    }

    /// Keep how a write of write filter `filter`'s entity that brings nothing of its own is sent
    /// the plain way, `None` for the general way: the facts it is sent from, and the head they
    /// write for the declaration naming its key, which only its id is read of. A filter the tables
    /// do not hold keeps nothing.
    #[cfg(feature = "alloc")]
    pub fn keep_write_filter_plain(
        &self,
        filter: WriteFilterHandle,
        plain: Option<(crate::publish_options::PlainPutParams, KeyexprRef)>,
    ) {
        let Some(row) = self
            .kept_write_filters()
            .and_then(|filters| filters.get(filter))
        else {
            return;
        };
        // A way stated again is planned again.
        #[cfg(feature = "codec-push")]
        row.planned.set(None);
        row.plain.set(plain.map(|(params, key)| {
            // A build with no Push codec writes no head, and reads nothing of the declaration.
            #[cfg(not(feature = "codec-push"))]
            let _ = key;
            PlainWay {
                params,
                #[cfg(feature = "codec-push")]
                head: crate::lent_push::PutHead::new(
                    key.id,
                    params.qos.unwrap_or(crate::sample::QosLevel::DEFAULT),
                ),
            }
        }));
    }

    /// The callback of the matching listener `handle` names, for a caller that takes what it calls
    /// out of the row under the tables' lock, calls it with none held and puts it back; `None`
    /// once the listener is undeclared, so a callback put back after its row went is let go of by
    /// the caller instead of landing in the row that took the slot since.
    pub fn matching_listener_callback_mut(
        &mut self,
        handle: MatchingListenerHandle,
    ) -> Option<&mut F::Matching> {
        self.kept_matching_mut()?
            .get_mut(handle)
            .map(|row| &mut row.callback)
    }

    /// The next write filter at or after `cursor` that has a listener and whose status changed,
    /// with its new status, now recorded as the one its listeners are owed: a filter is read once
    /// however many listeners it has, as zenoh-pico's filter updates its state once and calls each
    /// of its callbacks (`vendor/zenoh-pico/src/net/filtering.c` @
    /// `_z_write_filter_ctx_update_state`).
    pub fn next_matching_change(
        &self,
        cursor: &mut usize,
        peers: &impl PeerDeclarations,
    ) -> Option<(WriteFilterHandle, bool)> {
        let filters = self.kept_write_filters()?;
        while let Some((handle, row)) = filters.next_from(cursor) {
            if row.listeners == 0 {
                continue;
            }
            let now = self.matches(row.plane, text(&row.key), row.count_local, peers);
            if now != row.matching.get() {
                row.matching.set(now);
                return Some((handle, now));
            }
        }
        None
    }

    /// The first matching listener at or after `cursor` whose callback is owed its filter's status
    /// (the one [`Self::next_matching_change`] recorded, not handed to the callback yet) and of
    /// whose callback `take` hands something: what it handed, with the listener and the status,
    /// now recorded as handed. A listener `take` hands nothing of (its callback is out for a call)
    /// stays owed, for a later walk to find.
    pub fn take_owed_matching<T>(
        &mut self,
        cursor: &mut usize,
        mut take: impl FnMut(&mut F::Matching) -> Option<T>,
    ) -> Option<(MatchingListenerHandle, bool, T)> {
        let filters = <F::FilterPresence as Presence>::get::<WriteFilters<P>>(&self.write_filters)?;
        let matching = <F::FilterPresence as Presence>::get_mut::<MatchingListeners<F, P>>(
            &mut self.matching,
        )?;
        loop {
            let (handle, owed) = {
                let (handle, row) = matching.next_from(cursor)?;
                let now = filters
                    .get(row.filter)
                    .is_some_and(|filter| filter.matching.get());
                (handle, (row.told.get() != now).then_some(now))
            };
            let Some(verdict) = owed else {
                continue;
            };
            let Some(row) = matching.get_mut(handle) else {
                continue;
            };
            if let Some(taken) = take(&mut row.callback) {
                row.told.set(verdict);
                return Some((handle, verdict, taken));
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
        // Tables that keep no pending get have no room for one.
        match self.kept_pending_gets() {
            Some(gets) if !gets.is_full() => {}
            _ => {
                return Err(Refused {
                    why: RegisterError::TableFull,
                    callback,
                })
            }
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
        let Some(gets) = self.kept_pending_gets_mut() else {
            return Err(Refused {
                why: RegisterError::TableFull,
                callback: row.callback,
            });
        };
        match gets.insert(row) {
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
        let Some(gets) = <F::GetPresence as Presence>::get::<PendingGets<F, P>>(&self.pending_gets)
        else {
            self.next_request = id.wrapping_add(1);
            return id;
        };
        for _ in 0..=gets.len() {
            id = self.next_request;
            self.next_request = id.wrapping_add(1);
            if !gets.iter().any(|(_, row)| row.request == id) {
                return id;
            }
        }
        id
    }

    /// The get whose legs carry `request`.
    pub fn pending_get(&self, request: RequestId) -> Option<(PendingGetHandle, &PendingGet<F, P>)> {
        self.kept_pending_gets()?
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
        self.kept_pending_gets()?.get(handle)?.callback.begin()
    }

    /// Let go of the get `handle` named, ended while a call of it ran, once that call ended last:
    /// its row, to drop where no lock is held.
    pub fn release_get(&mut self, handle: PendingGetHandle) -> Option<PendingGet<F, P>> {
        self.kept_pending_gets_mut()?.release(handle)
    }

    /// One leg of the get `handle` names has its Final, or will have none (its face is gone): what
    /// is left of the get. The last leg ends it as [`Self::end_get`] does.
    pub fn end_leg(&mut self, handle: PendingGetHandle) -> Option<LegEnded<PendingGet<F, P>>> {
        let row = self.kept_pending_gets_mut()?.get_mut(handle)?;
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
        let gets =
            <F::GetPresence as Presence>::get_mut::<PendingGets<F, P>>(&mut self.pending_gets)?;
        let mut entry = gets.entry(handle)?;
        if !(entry.get()?.callback.retire() || entry.pin()) {
            return None;
        }
        entry.remove()
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
            let (handle, row) = self.kept_pending_gets()?.next_from(cursor)?;
            if row.deadline <= now {
                return Some(handle);
            }
        }
    }

    /// The nearest deadline of a pending get: what a driver's wait is cut short to.
    pub fn next_get_deadline(&self) -> Option<u64> {
        self.kept_pending_gets()?
            .iter()
            .map(|(_, row)| row.deadline)
            .min()
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
        self.kept_queryables()
            .into_iter()
            .flat_map(|queryables| queryables.iter())
            .filter(move |(_, row)| {
                admits(row.origin, local) && keyexpr_intersects(text(&row.key.key), key)
            })
    }

    /// The liveliness subscribers a token on `key` reaches.
    pub fn liveliness_subscribers_for<'a>(
        &'a self,
        key: &'a str,
    ) -> impl Iterator<Item = (LivelinessSubscriberHandle, &'a LivelinessSubscriber<F, P>)> + 'a
    {
        self.kept_liveliness_subscribers()
            .into_iter()
            .flat_map(|subscribers| subscribers.iter())
            .filter(move |(_, row)| keyexpr_intersects(text(&row.key.key), key))
    }

    /// The session's tokens on keys that reach `key`: what answers a peer's liveliness Interest
    /// or get.
    pub fn tokens_for<'a>(
        &'a self,
        key: &'a str,
    ) -> impl Iterator<Item = (TokenHandle, &'a TokenRow<P::Key>)> + 'a {
        self.kept_tokens()
            .into_iter()
            .flat_map(|tokens| tokens.iter())
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

    /// The next subscriber `fan` reaches, with a call begun on its row, with the tables held: what
    /// the call is made with once they are let go, `None` when no row at or after `fan`'s place is
    /// reached. A peer's message is first put to the key gate, once, at the walk's first pin, by
    /// the rule [`crate::pubsub::LocalSubscribers::deliver_from_peer`] keeps, and a refused one
    /// reaches no row. The rows are walked in the table's order from the place after the last one
    /// pinned, matched by the rule every walk of the subscribers keeps (`row_reaches`), so a
    /// message is handed to the rows a fan-out from its origin reaches, in its order, one call at a
    /// time; a row undeclared while an earlier call ran is retired and begins no call. End each
    /// call with [`RowCallback::end`]; when it was the last call of a row undeclared meanwhile, let
    /// the row go with [`Self::release_drained_subscriber`].
    pub fn pin_next_subscriber(
        &mut self,
        fan: &mut PinnedFanOut<'_>,
    ) -> Option<<F::Subscriber as RowCallback>::Call> {
        const {
            assert!(row_may_lie_in::<F::Subscriber, P>(), "a callback whose calls read its row in place, on another thread, needs its row out of every &mut of the tables: in the arena, on the lent policy");
        }
        if !self.fan_admitted(fan) {
            return None;
        }
        // Taken up at the place after the last row reached: the rows before it are not read again.
        let mut cursor = fan.next;
        while let Some((_, row)) = self.subscribers.next_from(&mut cursor) {
            if !fan_reaches(fan, row) {
                continue;
            }
            if let Some(call) = row.callback.begin() {
                fan.next = cursor;
                return Some(call);
            }
        }
        None
    }

    /// Every subscriber `fan` reaches from its place on, each with a call begun on its row, in one
    /// hold of the tables: the calls pushed to `calls` in the table's order, matched and gated as
    /// [`Self::pin_next_subscriber`] matches and gates one. Whether the walk reached the table's
    /// end; `false` only when `calls` had no room for a row reached, where `fan` is left so that
    /// the next pin begins with that row. The calls are what the message is handed to once the
    /// tables are let go: a row declared after this pin is not among them, and a row undeclared
    /// after it keeps its slot until its call here has ended. End each call with
    /// [`RowCallback::end`]; when it was the last call of a row undeclared meanwhile, let the row
    /// go with [`Self::release_drained_subscriber`].
    pub fn pin_subscribers<const N: usize>(
        &mut self,
        fan: &mut PinnedFanOut<'_>,
        calls: &mut BoundedVec<<F::Subscriber as RowCallback>::Call, N, Static>,
    ) -> bool {
        const {
            assert!(row_may_lie_in::<F::Subscriber, P>(), "a callback whose calls read its row in place, on another thread, needs its row out of every &mut of the tables: in the arena, on the lent policy");
        }
        if !self.fan_admitted(fan) {
            return true;
        }
        let mut cursor = fan.next;
        loop {
            let place = cursor;
            let Some((_, row)) = self.subscribers.next_from(&mut cursor) else {
                fan.next = cursor;
                return true;
            };
            if !fan_reaches(fan, row) {
                continue;
            }
            if calls.free_slots() == 0 {
                fan.next = place;
                return false;
            }
            if let Some(call) = row.callback.begin() {
                let kept = calls.push(call).is_ok();
                debug_assert!(kept, "room for the call was found before it began");
            }
        }
    }

    /// Put a peer's message `fan` walks to the key gate, once, at its walk's first pin, by the
    /// rule [`crate::pubsub::LocalSubscribers::deliver_from_peer`] keeps: whether the message may
    /// reach a row. A refused one, or one deeper than the matcher's bound, reaches none.
    fn fan_admitted(&mut self, fan: &mut PinnedFanOut<'_>) -> bool {
        if fan.ungated {
            fan.ungated = false;
            if matches!(
                admit_from_peer(&mut self.key_gate, fan.key, fan.class),
                Admission::Refused
            ) {
                fan.reaches_none = true;
            }
        }
        !fan.reaches_none
    }

    /// Let go of the subscriber `handle` named, undeclared while a call of it ran, once that call
    /// ended last: its row, to drop where no lock is held.
    pub fn release_subscriber(&mut self, handle: SubscriberHandle) -> Option<Subscriber<F, P>> {
        self.subscribers.release(handle)
    }

    /// The next subscriber at or after `cursor` in its table that was undeclared while a call of it
    /// ran and whose last call has ended since, taken out of the table: its row, to drop where no
    /// lock is held. A walk from cursor `0` to `None` finds every such row, each once, so a caller
    /// whose calls end with no lock held keeps no list of the rows that wait: the call that ended
    /// last leaves its mark in the row's latch alone ([`RowCallback::drained`]).
    pub fn release_drained_subscriber(&mut self, cursor: &mut usize) -> Option<Subscriber<F, P>> {
        release_drained(&mut self.subscribers, cursor)
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
        self.kept_queryables()?.get(handle)?.callback.begin()
    }

    /// Let go of the queryable `handle` named, undeclared while a call of it ran, once that call
    /// ended last: its row, to drop where no lock is held.
    pub fn release_queryable(&mut self, handle: QueryableHandle) -> Option<Queryable<F, P>> {
        self.kept_queryables_mut()?.release(handle)
    }

    /// [`Self::release_drained_subscriber`] for the queryables.
    pub fn release_drained_queryable(&mut self, cursor: &mut usize) -> Option<Queryable<F, P>> {
        release_drained(self.kept_queryables_mut()?, cursor)
    }

    /// The next queryable `query` reaches, with the tables held, the walk moved past it: the row's
    /// callback, which a call is begun on before the tables are let go, `None` when no row at or
    /// after the query's place is reached. The rows are walked in the table's order from the place
    /// after the last one reached, matched by the rule every fan-out of a peer's query keeps, so a
    /// query is handed to the rows the fan-out of its dispatch reaches, in its order, one call at a
    /// time; a row undeclared while an earlier call ran is retired and begins no call.
    #[cfg(all(feature = "codec-request", feature = "storage-profile"))]
    pub fn next_queryable_reached(
        &self,
        query: &mut crate::query::pinned::PinnedQuery<'_>,
    ) -> Option<&F::Queryable> {
        const {
            assert!(row_may_lie_in::<F::Queryable, P>(), "a callback whose calls read its row in place, on another thread, needs its row out of every &mut of the tables: in the arena, on the lent policy");
        }
        let queryables = self.kept_queryables()?;
        let mut cursor = query.reached_from();
        while let Some((handle, row)) = queryables.next_from(&mut cursor) {
            let found = QueryableRef {
                #[cfg(feature = "alloc")]
                id: u64::from(row.id),
                pattern: text(&row.key.key),
                facts: row.facts,
                origin: row.origin,
                complete: row.complete,
            };
            if query.reaches(found) {
                query.passed(handle.place());
                return Some(&row.callback);
            }
        }
        None
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
        self.kept_liveliness_subscribers()?
            .get(handle)?
            .callback
            .begin()
    }

    /// Let go of the liveliness subscriber `handle` named, undeclared while a call of it ran, once that call
    /// ended last: its row, to drop where no lock is held.
    pub fn release_liveliness_subscriber(
        &mut self,
        handle: LivelinessSubscriberHandle,
    ) -> Option<LivelinessSubscriber<F, P>> {
        self.kept_liveliness_subscribers_mut()?.release(handle)
    }

    /// [`Self::release_drained_subscriber`] for the liveliness subscribers.
    pub fn release_drained_liveliness_subscriber(
        &mut self,
        cursor: &mut usize,
    ) -> Option<LivelinessSubscriber<F, P>> {
        release_drained(self.kept_liveliness_subscribers_mut()?, cursor)
    }

    /// The next liveliness subscriber the peer token `fan` walks reaches, with a call begun on its
    /// row, with the tables held: [`Self::pin_next_subscriber`] for a token, the rows matched by
    /// the rule every token fan keeps (`token_reaches`). End each call with
    /// [`RowCallback::end`]; when it was the last call of a row undeclared meanwhile, let the row
    /// go with [`Self::release_drained_liveliness_subscriber`].
    pub fn pin_next_liveliness_subscriber(
        &self,
        fan: &mut PinnedTokenFan<'_>,
    ) -> Option<<F::LivelinessSubscriber as RowCallback>::Call> {
        const {
            assert!(row_may_lie_in::<F::LivelinessSubscriber, P>(), "a callback whose calls read its row in place, on another thread, needs its row out of every &mut of the tables: in the arena, on the lent policy");
        }
        let subscribers = self.kept_liveliness_subscribers()?;
        let mut cursor = fan.next;
        while let Some((_, row)) = subscribers.next_from(&mut cursor) {
            if !token_reaches(row, fan.key, fan.historical) {
                continue;
            }
            if let Some(call) = row.callback.begin() {
                fan.next = cursor;
                return Some(call);
            }
        }
        None
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
        self.kept_matching()?.get(handle)?.callback.begin()
    }

    /// Let go of the matching listener `handle` named, undeclared while a call of it ran, once that call
    /// ended last: its row, to drop where no lock is held.
    pub fn release_matching_listener(
        &mut self,
        handle: MatchingListenerHandle,
    ) -> Option<Matching<F>> {
        self.kept_matching_mut()?.release(handle)
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

    /// The queryables, as the tables keep them: the table, for rows whose callbacks keep
    /// queryables ([`RowCallbacks::QueryablePresence`]).
    pub fn queryables(&self) -> &QueryablesKept<F, P> {
        &self.queryables
    }

    /// The queryables' table, where the tables keep one.
    pub fn kept_queryables(&self) -> Option<&Queryables<F, P>> {
        <F::QueryablePresence as Presence>::get::<Queryables<F, P>>(&self.queryables)
    }

    /// The queryables' table, to write, where the tables keep one.
    pub fn kept_queryables_mut(&mut self) -> Option<&mut Queryables<F, P>> {
        <F::QueryablePresence as Presence>::get_mut::<Queryables<F, P>>(&mut self.queryables)
    }

    /// The queryables to ask, with the key expressions the session declared beside them as its
    /// own id space: a peer's query names its key through the one while the other is asked, so
    /// the two are borrowed apart.
    #[cfg(feature = "storage-profile")]
    pub fn queries_mut(
        &mut self,
    ) -> (
        crate::wireexpr_resolve::OwnSpace<'_, P>,
        &mut QueryablesKept<F, P>,
    ) {
        (
            crate::wireexpr_resolve::OwnSpace::of_keyexprs(&self.keyexprs),
            &mut self.queryables,
        )
    }

    /// The liveliness subscribers to tell, with the key expressions the session declared beside
    /// them as its own id space: a peer's token names its key through the one while the other is
    /// told, so the two are borrowed apart.
    #[cfg(feature = "storage-profile")]
    pub fn liveliness_mut(
        &mut self,
    ) -> (
        crate::wireexpr_resolve::OwnSpace<'_, P>,
        &mut LivelinessSubscribersKept<F, P>,
    ) {
        (
            crate::wireexpr_resolve::OwnSpace::of_keyexprs(&self.keyexprs),
            &mut self.liveliness_subscribers,
        )
    }

    /// The liveliness tokens, as the tables keep them.
    pub fn tokens(&self) -> &TokensKept<F, P> {
        &self.tokens
    }

    /// The liveliness subscribers, as the tables keep them.
    pub fn liveliness_subscribers(&self) -> &LivelinessSubscribersKept<F, P> {
        &self.liveliness_subscribers
    }

    /// The write filters, as the tables keep them.
    pub fn write_filters(&self) -> &WriteFiltersKept<F, P> {
        &self.write_filters
    }

    /// The matching listeners, as the tables keep them.
    pub fn matching_listeners(&self) -> &MatchingListenersKept<F, P> {
        &self.matching
    }

    /// The pending gets, as the tables keep them.
    pub fn pending_gets(&self) -> &PendingGetsKept<F, P> {
        &self.pending_gets
    }

    /// The slots of the table of declarations `table`, apart from its rows ([`Slots`]): none
    /// where the tables keep no table of the kind.
    pub fn slots_of(&self, table: DeclaredTable) -> Slots<'_> {
        match table {
            DeclaredTable::Keyexprs => self.keyexprs.slots(),
            DeclaredTable::Subscribers => self.subscribers.slots(),
            DeclaredTable::Interests => {
                self.kept_write_filters().map_or(Slots::NONE, |t| t.slots())
            }
            DeclaredTable::Queryables => self.kept_queryables().map_or(Slots::NONE, |t| t.slots()),
            DeclaredTable::Tokens => self.kept_tokens().map_or(Slots::NONE, |t| t.slots()),
            DeclaredTable::LivelinessSubscribers => self
                .kept_liveliness_subscribers()
                .map_or(Slots::NONE, |t| t.slots()),
        }
    }

    /// The liveliness tokens' table, where the tables keep one.
    pub fn kept_tokens(&self) -> Option<&Tokens<P>> {
        <F::LivelinessPresence as Presence>::get::<Tokens<P>>(&self.tokens)
    }

    /// The liveliness tokens' table, to write, where the tables keep one.
    pub fn kept_tokens_mut(&mut self) -> Option<&mut Tokens<P>> {
        <F::LivelinessPresence as Presence>::get_mut::<Tokens<P>>(&mut self.tokens)
    }

    /// The liveliness subscribers' table, where the tables keep one.
    pub fn kept_liveliness_subscribers(&self) -> Option<&LivelinessSubscribers<F, P>> {
        <F::LivelinessPresence as Presence>::get::<LivelinessSubscribers<F, P>>(
            &self.liveliness_subscribers,
        )
    }

    /// The liveliness subscribers' table, to write, where the tables keep one.
    pub fn kept_liveliness_subscribers_mut(&mut self) -> Option<&mut LivelinessSubscribers<F, P>> {
        <F::LivelinessPresence as Presence>::get_mut::<LivelinessSubscribers<F, P>>(
            &mut self.liveliness_subscribers,
        )
    }

    /// The write filters' table, where the tables keep one.
    pub fn kept_write_filters(&self) -> Option<&WriteFilters<P>> {
        <F::FilterPresence as Presence>::get::<WriteFilters<P>>(&self.write_filters)
    }

    /// The write filters' table, to write, where the tables keep one.
    pub fn kept_write_filters_mut(&mut self) -> Option<&mut WriteFilters<P>> {
        <F::FilterPresence as Presence>::get_mut::<WriteFilters<P>>(&mut self.write_filters)
    }

    /// The matching listeners' table, where the tables keep one.
    pub fn kept_matching(&self) -> Option<&MatchingListeners<F, P>> {
        <F::FilterPresence as Presence>::get::<MatchingListeners<F, P>>(&self.matching)
    }

    /// The matching listeners' table, to write, where the tables keep one.
    pub fn kept_matching_mut(&mut self) -> Option<&mut MatchingListeners<F, P>> {
        <F::FilterPresence as Presence>::get_mut::<MatchingListeners<F, P>>(&mut self.matching)
    }

    /// The pending gets' table, where the tables keep one.
    pub fn kept_pending_gets(&self) -> Option<&PendingGets<F, P>> {
        <F::GetPresence as Presence>::get::<PendingGets<F, P>>(&self.pending_gets)
    }

    /// The pending gets' table, to write, where the tables keep one.
    pub fn kept_pending_gets_mut(&mut self) -> Option<&mut PendingGets<F, P>> {
        <F::GetPresence as Presence>::get_mut::<PendingGets<F, P>>(&mut self.pending_gets)
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
            .field("queryables", &self.kept_queryables())
            .field(
                "tokens",
                &<F::LivelinessPresence as Presence>::get::<Tokens<P>>(&self.tokens),
            )
            .field(
                "liveliness_subscribers",
                &<F::LivelinessPresence as Presence>::get::<LivelinessSubscribers<F, P>>(
                    &self.liveliness_subscribers,
                ),
            )
            .field(
                "write_filters",
                &<F::FilterPresence as Presence>::get::<WriteFilters<P>>(&self.write_filters),
            )
            .field(
                "matching",
                &<F::FilterPresence as Presence>::get::<MatchingListeners<F, P>>(&self.matching),
            )
            .field(
                "pending_gets",
                &<F::GetPresence as Presence>::get::<PendingGets<F, P>>(&self.pending_gets),
            )
            .finish()
    }
}

impl<F: RowCallbacks> SessionTables<F, Lent> {
    /// The tables of a session, `rows` of each lent from `arena` in the order of
    /// [`TableRows`], their keys kept in `keys`, the session's key arena. Refused past the
    /// build's bound of a table or past what the arena has left.
    pub fn lent(arena: &mut Arena, keys: KeySpace, rows: &TableRows) -> Result<Self, LendRefused> {
        // Lent whole and given up whole: a refused table leaves the ones after it rowless, and
        // the set goes at once, not one table at a time behind each refusal.
        let mut lend = TableLender::new(arena);
        let tables = Self {
            keys: LentKeys::from(keys),
            next_entity: EntityIds::default(),
            next_expr: 1,
            next_request: 0,
            subscriber_epoch: 0,
            // A table whose rows are lent at open remembers no key: each slot of the cache would
            // be rows of its own, which only the arena could give it.
            memo: MatchMemo::new(0),
            key_gate: KeyGate::of_build(),
            keyexprs: SlotMap::lent_from(&mut lend, rows.keyexprs),
            subscribers: SlotMap::lent_from(&mut lend, rows.subscribers),
            queryables: <F::QueryablePresence as Presence>::lent_from::<Queryables<F, Lent>>(
                &mut lend,
                rows.queryables,
            ),
            tokens: <F::LivelinessPresence as Presence>::lent_from::<Tokens<Lent>>(
                &mut lend,
                rows.tokens,
            ),
            liveliness_subscribers: <F::LivelinessPresence as Presence>::lent_from::<
                LivelinessSubscribers<F, Lent>,
            >(&mut lend, rows.liveliness_subscribers),
            write_filters: <F::FilterPresence as Presence>::lent_from::<WriteFilters<Lent>>(
                &mut lend,
                rows.write_filters(),
            ),
            plane_bounds: PlaneBounds::of(rows),
            matching: <F::FilterPresence as Presence>::lent_from::<MatchingListeners<F, Lent>>(
                &mut lend,
                rows.matching_listeners,
            ),
            pending_gets: <F::GetPresence as Presence>::lent_from::<PendingGets<F, Lent>>(
                &mut lend,
                rows.pending_gets,
            ),
            #[cfg(feature = "storage-profile")]
            held: lend
                .lend_with(|arena| crate::reply_hold::HeldReplies::lent(arena, rows.held_replies)),
        };
        lend.finish()?;
        Ok(tables)
    }

    /// The bytes [`Self::lent`] takes of an arena for `rows`. `None` past the address space.
    /// A const fn, so a build whose limits are fixed lays its session's arena out when it compiles.
    pub const fn arena_bytes(rows: &TableRows) -> Option<usize> {
        let parts = [
            <Keyexprs<Lent>>::arena_bytes(rows.keyexprs),
            <Subscribers<F, Lent>>::arena_bytes(rows.subscribers),
            kept_bytes::<F::QueryablePresence>(<Queryables<F, Lent>>::arena_bytes(rows.queryables)),
            kept_bytes::<F::LivelinessPresence>(<Tokens<Lent>>::arena_bytes(rows.tokens)),
            kept_bytes::<F::LivelinessPresence>(<LivelinessSubscribers<F, Lent>>::arena_bytes(
                rows.liveliness_subscribers,
            )),
            kept_bytes::<F::FilterPresence>(<WriteFilters<Lent>>::arena_bytes(
                rows.write_filters(),
            )),
            kept_bytes::<F::FilterPresence>(<MatchingListeners<F, Lent>>::arena_bytes(
                rows.matching_listeners,
            )),
            kept_bytes::<F::GetPresence>(<PendingGets<F, Lent>>::arena_bytes(rows.pending_gets)),
            held_arena_bytes(rows.held_replies),
        ];
        let mut sum = Some(0_usize);
        let mut rest: &[Option<usize>] = &parts;
        while let [part, tail @ ..] = rest {
            sum = match (sum, *part) {
                (Some(sum), Some(part)) => sum.checked_add(part),
                _ => None,
            };
            rest = tail;
        }
        sum
    }
}

#[cfg(feature = "alloc")]
impl<F: RowCallbacks> SessionTables<F, crate::bounded::OnUse> {
    /// The tables of a session, each of at most the rows `rows` gives it, under the build's bound,
    /// none of them holding memory until its first row, their keys counted against the session's
    /// key budget (`keys`): what an open that takes its memory on use makes, from the limits it
    /// resolved. Nothing is taken, so nothing is refused here: a declaration past a table's count,
    /// or one the allocator or the budget has no room for, is refused when it is made.
    pub fn counted(keys: crate::on_use::BudgetKeys, rows: &TableRows) -> Self {
        Self {
            keys,
            next_entity: EntityIds::default(),
            next_expr: 1,
            next_request: 0,
            subscriber_epoch: 0,
            // The memory a table of fixed size keeps (`memo_slots`): the build's
            // `MATCH_MEMO_FIXED_SLOTS`, none unless the image asks for them.
            memo: MatchMemo::new(0),
            key_gate: KeyGate::of_build(),
            keyexprs: SlotMap::counted(rows.keyexprs),
            subscribers: SlotMap::counted(rows.subscribers),
            queryables: <F::QueryablePresence as Presence>::counted::<
                Queryables<F, crate::bounded::OnUse>,
            >(rows.queryables),
            tokens: <F::LivelinessPresence as Presence>::counted::<Tokens<crate::bounded::OnUse>>(
                rows.tokens,
            ),
            liveliness_subscribers: <F::LivelinessPresence as Presence>::counted::<
                LivelinessSubscribers<F, crate::bounded::OnUse>,
            >(rows.liveliness_subscribers),
            write_filters: <F::FilterPresence as Presence>::counted::<
                WriteFilters<crate::bounded::OnUse>,
            >(rows.write_filters()),
            plane_bounds: PlaneBounds::of(rows),
            matching: <F::FilterPresence as Presence>::counted::<
                MatchingListeners<F, crate::bounded::OnUse>,
            >(rows.matching_listeners),
            pending_gets: <F::GetPresence as Presence>::counted::<
                PendingGets<F, crate::bounded::OnUse>,
            >(rows.pending_gets),
            held: crate::reply_hold::HeldReplies::counted(rows.held_replies),
        }
    }
}

// SAFETY: the key arena handle is `LentKeys`, whose zero is no arena; the ids are counts of ids
// handed out, a zero expression id is minted as 1, the request id and the epoch are counts; the
// match memory and the held replies are `ZeroEmpty` of this policy; every table is a `SlotMap` of
// this policy (`ZeroEmpty`) or, absent, no bytes (`Presence` is sealed to the two); the plane
// bounds of zero are none. Nothing drops a value, every sequence holding none.
unsafe impl<F: RowCallbacks> ZeroEmpty for SessionTables<F, Region> {}

/// The lines a region's description holds for one [`SessionTables`] of the region policy, at most:
/// two for each of its eight tables, one for its held replies; and its one key arena handle.
pub const SESSION_TABLE_LINES: usize = 17;

/// The rows of a [`SessionTables`] of the region policy, which a region lays out beside the tables:
/// each table's [`SlotRows`] at the build's bound of it, none of a kind the build keeps none of.
pub struct SessionRows<F: RowCallbacks> {
    keyexprs: SlotRows<KeyexprRow<KeyRef>, { caps::MAX_DECLARED_KEYEXPRS }>,
    subscribers: SlotRows<Subscriber<F, Region>, { caps::MAX_SUBSCRIPTIONS }>,
    queryables: <F::QueryablePresence as Presence>::Table<
        SlotRows<Queryable<F, Region>, { caps::MAX_QUERYABLES }>,
    >,
    tokens: <F::LivelinessPresence as Presence>::Table<
        SlotRows<TokenRow<KeyRef>, { caps::MAX_LOCAL_TOKENS }>,
    >,
    liveliness_subscribers: <F::LivelinessPresence as Presence>::Table<
        SlotRows<LivelinessSubscriber<F, Region>, { caps::MAX_LIVELINESS_SUBSCRIPTIONS }>,
    >,
    write_filters:
        <F::FilterPresence as Presence>::Table<SlotRows<WriteFilterRow<KeyRef>, FILTER_ROWS>>,
    matching: <F::FilterPresence as Presence>::Table<
        SlotRows<Matching<F>, { caps::MAX_MATCHING_LISTENERS }>,
    >,
    pending_gets: <F::GetPresence as Presence>::Table<
        SlotRows<PendingGet<F, Region>, { caps::MAX_PENDING_QUERIES }>,
    >,
    #[cfg(feature = "storage-profile")]
    held: [core::mem::MaybeUninit<crate::reply_hold::HeldReply<PendingGetHandle, Region>>;
        caps::MAX_PENDING_REPLIES],
}

// SAFETY: each table's rows are `SlotRows` (`ZeroEmpty`) or, of a kind not kept, no bytes
// (`Presence` is sealed to the two); the held replies' rows are `MaybeUninit`.
unsafe impl<F: RowCallbacks> ZeroEmpty for SessionRows<F> {}

impl<F: RowCallbacks> SessionTables<F, Region> {
    /// The description of tables of the region policy at `at` in a region and their rows, a
    /// [`SessionRows`], at `rows`: a line for each column of each table the build keeps, one for
    /// the held replies, and the tables' handle to the region's key arena. What
    /// [`place_region`](crate::key_arena::place_region) reads to make zeroed tables a session's.
    pub const fn places(at: usize, rows: usize) -> RegionLines<SESSION_TABLE_LINES> {
        let mut lines = RegionLines::EMPTY
            .keys_at(at.wrapping_add(core::mem::offset_of!(Self, keys)))
            .seqs(&<Keyexprs<Region>>::places(
                at.wrapping_add(core::mem::offset_of!(Self, keyexprs)),
                rows.wrapping_add(core::mem::offset_of!(SessionRows<F>, keyexprs)),
            ))
            .seqs(&<Subscribers<F, Region>>::places(
                at.wrapping_add(core::mem::offset_of!(Self, subscribers)),
                rows.wrapping_add(core::mem::offset_of!(SessionRows<F>, subscribers)),
            ));
        if <F::QueryablePresence as Presence>::KEPT {
            lines = lines.seqs(&<Queryables<F, Region>>::places(
                at.wrapping_add(core::mem::offset_of!(Self, queryables)),
                rows.wrapping_add(core::mem::offset_of!(SessionRows<F>, queryables)),
            ));
        }
        if <F::LivelinessPresence as Presence>::KEPT {
            lines = lines
                .seqs(&<Tokens<Region>>::places(
                    at.wrapping_add(core::mem::offset_of!(Self, tokens)),
                    rows.wrapping_add(core::mem::offset_of!(SessionRows<F>, tokens)),
                ))
                .seqs(&<LivelinessSubscribers<F, Region>>::places(
                    at.wrapping_add(core::mem::offset_of!(Self, liveliness_subscribers)),
                    rows.wrapping_add(core::mem::offset_of!(
                        SessionRows<F>,
                        liveliness_subscribers
                    )),
                ));
        }
        if <F::FilterPresence as Presence>::KEPT {
            lines = lines
                .seqs(&<WriteFilters<Region>>::places(
                    at.wrapping_add(core::mem::offset_of!(Self, write_filters)),
                    rows.wrapping_add(core::mem::offset_of!(SessionRows<F>, write_filters)),
                ))
                .seqs(&<MatchingListeners<F, Region>>::places(
                    at.wrapping_add(core::mem::offset_of!(Self, matching)),
                    rows.wrapping_add(core::mem::offset_of!(SessionRows<F>, matching)),
                ));
        }
        if <F::GetPresence as Presence>::KEPT {
            lines = lines.seqs(&<PendingGets<F, Region>>::places(
                at.wrapping_add(core::mem::offset_of!(Self, pending_gets)),
                rows.wrapping_add(core::mem::offset_of!(SessionRows<F>, pending_gets)),
            ));
        }
        #[cfg(feature = "storage-profile")]
        {
            lines = lines.seq(
                crate::reply_hold::HeldReplies::<PendingGetHandle, Region>::place(
                    at.wrapping_add(core::mem::offset_of!(Self, held)),
                    rows.wrapping_add(core::mem::offset_of!(SessionRows<F>, held)),
                ),
            );
        }
        lines
    }
}

/// `bytes`, what a table of a kind takes of an arena, where the presence `K` keeps the kind, and
/// none where it keeps none: a kind left out lends no table.
const fn kept_bytes<K: Presence>(bytes: Option<usize>) -> Option<usize> {
    if K::KEPT {
        bytes
    } else {
        Some(0)
    }
}

/// Whether a row whose callback is `Cb` may lie in a table of policy `P`: a callback whose calls
/// read its row where it lies ([`RowCallback::READS_ROW_IN_PLACE`]) is read on another thread while
/// the tables are held, so its row lies only where no `&mut` of the tables, nor of what holds them,
/// reaches it: behind the pointer a table keeps where its policy keeps every row apart from the
/// table and never moves one ([`Storage::ROWS_STAY_APART`]), whenever it took the memory (P3, P11).
const fn row_may_lie_in<Cb: RowCallback, P: Storage>() -> bool {
    !Cb::READS_ROW_IN_PLACE || P::ROWS_STAY_APART
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
    type OwnPolicy = P;

    // The table set holds the key expressions the session declared: a peer's `M=0` key is read
    // from them where they lie.
    #[cfg(feature = "storage-profile")]
    fn own_space(&self) -> Option<crate::wireexpr_resolve::OwnSpace<'_, P>> {
        Some(crate::wireexpr_resolve::OwnSpace::of_keyexprs(
            &self.keyexprs,
        ))
    }

    fn epoch(&self) -> u64 {
        self.subscriber_epoch
    }

    fn next_subscription_id(&self) -> u64 {
        self.next_entity
            .next()
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
        self.next_entity.next()
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

    /// A key of a closed set is matched by its pattern like any other: the rows hold no entity of
    /// the image's to select by.
    fn deliver_from_peer<D: FnMut(Self::RowId, RowAccess<'_, Self::Sink>)>(
        &mut self,
        key: &str,
        class: Option<ClassId>,
        how: crate::pubsub::PeerDelivery,
        deliver: D,
    ) -> usize {
        if matches!(
            admit_from_peer(&mut self.key_gate, key, class),
            Admission::Refused
        ) {
            return 0;
        }
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

    #[inline]
    fn deliver_from_peer_marked<D: FnMut(Self::RowId, RowAccess<'_, Self::Sink>)>(
        &mut self,
        key: &str,
        class: Option<ClassId>,
        mark: &mut crate::match_set::MatchEntry,
        deliver: D,
    ) -> usize {
        fire_into_marked(
            &mut self.subscribers,
            mark,
            self.subscriber_epoch,
            key,
            &mut self.key_gate,
            class,
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

/// A message's walk of the subscribers it reaches, one row pinned at a time
/// ([`SessionTables::pin_next_subscriber`]): the key, read once, where the message came from, and
/// the place the next row is looked for from. Held by whoever delivers the message, beside the key,
/// across the calls it makes with the tables let go, so the tables keep nothing of a delivery under
/// way.
pub struct PinnedFanOut<'k> {
    key: &'k str,
    facts: KeyFacts,
    /// The message is a peer's, not the session's own: which origins of the rows admit it.
    remote: bool,
    /// The row of the image's allowance the session found for the peer the message came from.
    class: Option<ClassId>,
    /// A peer's message the key gate has not been asked of yet: asked at the first pin, so that a
    /// refusal is counted once for the message and not once for each row.
    ungated: bool,
    /// Deeper than the matcher's bound, or refused by the key gate: the message reaches no row.
    reaches_none: bool,
    /// The place the next row is looked for from: the one after the row pinned last.
    next: usize,
}

/// The calls of the subscribers one message reaches, pinned in one hold of the tables
/// ([`SessionTables::pin_subscribers`]), in the table's order: room for a call on every row the
/// table can hold, so one pin takes them all.
///
/// A fixed array the delivery holds in its own frame while it makes the calls with the tables let
/// go of, so it takes no heap; its cost is stack: `MAX_SUBSCRIPTIONS` calls of a row's address
/// each and a length, at the build's default of 100 subscribers 808 bytes on a 64-bit target and
/// 404 on a 32-bit one. A callback that puts on its own session from inside the call holds a second
/// one in a frame above the first, as a put holds the calls the round captured for it.
pub type PinnedSubscribers<F> = BoundedVec<
    <<F as RowCallbacks>::Subscriber as RowCallback>::Call,
    { caps::MAX_SUBSCRIPTIONS },
    Static,
>;

/// A peer token's walk of the liveliness subscribers it reaches, one row pinned at a time
/// ([`SessionTables::pin_next_liveliness_subscriber`]): its key, whether it is historical (an
/// answer to a CURRENT interest), and the place the next row is looked for from. Held by whoever
/// hands the token out, beside the key, as [`PinnedFanOut`] is.
pub struct PinnedTokenFan<'k> {
    key: &'k str,
    historical: bool,
    /// The place the next row is looked for from: the one after the row pinned last.
    next: usize,
}

impl<'k> PinnedTokenFan<'k> {
    /// The walk of the liveliness subscribers a token on `key` reaches, from the table's first row.
    pub fn new(key: &'k str, historical: bool) -> Self {
        Self {
            key,
            historical,
            next: 0,
        }
    }
}

/// Whether a peer token on `key` reaches the liveliness subscriber `row`: a row whose pattern
/// intersects the key, and, of a historical token, only one that asked for history.
fn token_reaches<Key: KeyBacking, Cb>(
    row: &LivelinessSubscriberRow<Key, Cb>,
    key: &str,
    historical: bool,
) -> bool {
    (!historical || row.history) && keyexpr_intersects(text(&row.key.key), key)
}

/// Whether the message `fan` walks reaches the subscriber `row`, by the rule every walk of the
/// subscribers keeps (`row_reaches`).
fn fan_reaches<Key: KeyBacking, Cb>(fan: &PinnedFanOut<'_>, row: &SubscriberRow<Key, Cb>) -> bool {
    let found = RowRef {
        pattern: text(&row.key.key),
        facts: row.facts,
        origin: row.origin,
    };
    row_reaches(&found, fan.key, fan.facts, fan.remote)
}

impl<'k> PinnedFanOut<'k> {
    /// The walk of the subscribers a peer's message on `key` reaches, from the table's first row:
    /// `class` is the row of the image's allowance the session found for the peer, which the key
    /// gate is asked with.
    pub fn new(key: &'k str, class: Option<ClassId>) -> Self {
        Self::from_origin(key, true, class)
    }

    /// The walk of the subscribers a message the session itself published on `key` reaches, from
    /// the table's first row: the rows whose origin admits the session's own messages. The
    /// application's own message is not put to the key gate.
    pub fn local(key: &'k str) -> Self {
        Self::from_origin(key, false, None)
    }

    fn from_origin(key: &'k str, remote: bool, class: Option<ClassId>) -> Self {
        let facts = KeyFacts::of(key);
        Self {
            key,
            facts,
            remote,
            class,
            ungated: remote,
            reaches_none: past_matcher_depth(key, facts),
            next: 0,
        }
    }
}

/// As the subscribers' rows: a row whose calls read it where it lies is handed shared, one only
/// the tables' holder reaches exclusively.
impl<Key: KeyBacking, Cb: RowCallback, P: Storage> QueryableRows
    for SlotMap<kind::Queryable, QueryableRow<Key, Cb>, { caps::MAX_QUERYABLES }, P>
{
    type Sink = Cb;
    type RowId = QueryableHandle;

    fn each_row_mut<F: FnMut(QueryableRef<'_>, QueryableHandle, RowAccess<'_, Cb>)>(
        &mut self,
        mut f: F,
    ) {
        if Cb::READS_ROW_IN_PLACE {
            for (_, handle, row) in self.live_handles() {
                let found = QueryableRef {
                    #[cfg(feature = "alloc")]
                    id: u64::from(row.id),
                    pattern: text(&row.key.key),
                    facts: row.facts,
                    origin: row.origin,
                    complete: row.complete,
                };
                f(found, handle, RowAccess::InPlace(&row.callback));
            }
        } else {
            // The row's fields are borrowed apart: its key to read, its callback to change.
            for (_, handle, row) in self.live_handles_mut() {
                let found = QueryableRef {
                    #[cfg(feature = "alloc")]
                    id: u64::from(row.id),
                    pattern: text(&row.key.key),
                    facts: row.facts,
                    origin: row.origin,
                    complete: row.complete,
                };
                f(found, handle, RowAccess::Held(&mut row.callback));
            }
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

/// The liveliness subscribers of tables that keep none: a peer's token reaches none of them, and is
/// kept as one no subscriber hears is.
impl<T: crate::declare::liveliness_subscriber::LocalLivelinessSubscribers>
    crate::declare::liveliness_subscriber::LocalLivelinessSubscribers for AbsentTable<T>
{
    type Sink = T::Sink;
    type RowId = T::RowId;

    fn fire_matching<D: FnMut(Self::RowId, RowAccess<'_, Self::Sink>)>(
        &mut self,
        _keyexpr: &str,
        _historical: bool,
        _deliver: D,
    ) -> usize {
        0
    }

    fn pattern_of(&self, _interest_id: u64) -> Option<&str> {
        None
    }

    fn row_of(&mut self, _interest_id: u64) -> Option<(Self::RowId, RowAccess<'_, Self::Sink>)> {
        None
    }

    fn mark_history_complete(&mut self, _interest_id: u64) {}
}

/// The queryables of tables that keep none: a peer's query finds none of them, and is ended as one
/// that reaches no queryable is.
impl<T: crate::query::LocalQueryables> crate::query::LocalQueryables for AbsentTable<T> {
    type Sink = T::Sink;
    type RowId = T::RowId;

    #[cfg(feature = "storage-profile")]
    fn has_local_queryable(&self, _query_keyexpr: &str, _require_complete: bool) -> bool {
        false
    }

    #[cfg(feature = "alloc")]
    fn respond_to_queryable_interest(
        &self,
        _interest_id: u64,
        _pattern: Option<&str>,
        _aggregate: bool,
        _staged: &mut alloc::vec::Vec<crate::query::QueryableInterestReply>,
    ) -> usize {
        0
    }

    fn fire_matching_queryables<D: FnMut(Self::RowId, RowAccess<'_, Self::Sink>)>(
        &mut self,
        _keyexpr: &str,
        _keyexpr_facts: KeyFacts,
        _is_remote: bool,
        _target: Option<crate::query_mode::QueryTarget>,
        _deliver: D,
    ) -> usize {
        0
    }
}

/// The queryables are asked as a table of their own, apart from the key expressions a peer's query
/// is resolved through ([`SessionTables::queries_mut`]).
impl<Key: KeyBacking, Cb: RowCallback, P: Storage> crate::query::LocalQueryables
    for SlotMap<kind::Queryable, QueryableRow<Key, Cb>, { caps::MAX_QUERYABLES }, P>
{
    type Sink = Cb;
    type RowId = QueryableHandle;

    #[cfg(feature = "storage-profile")]
    fn has_local_queryable(&self, query_keyexpr: &str, require_complete: bool) -> bool {
        any_local_queryable(self, query_keyexpr, require_complete)
    }

    #[cfg(feature = "alloc")]
    fn respond_to_queryable_interest(
        &self,
        interest_id: u64,
        pattern: Option<&str>,
        aggregate: bool,
        staged: &mut alloc::vec::Vec<crate::query::QueryableInterestReply>,
    ) -> usize {
        stage_queryable_interest(self, interest_id, pattern, aggregate, staged)
    }

    fn fire_matching_queryables<D: FnMut(QueryableHandle, RowAccess<'_, Self::Sink>)>(
        &mut self,
        keyexpr: &str,
        keyexpr_facts: KeyFacts,
        is_remote: bool,
        target: Option<crate::query_mode::QueryTarget>,
        deliver: D,
    ) -> usize {
        fire_queryables(self, keyexpr, keyexpr_facts, is_remote, target, deliver)
    }
}

/// As the subscribers' rows: a row whose calls read it where it lies is handed shared, one only
/// the tables' holder reaches exclusively. A row is found by its entity id, which is its
/// Interest's.
impl<Key: KeyBacking, Cb: RowCallback, P: Storage>
    crate::declare::liveliness_subscriber::LocalLivelinessSubscribers
    for SlotMap<
        kind::LivelinessSubscriber,
        LivelinessSubscriberRow<Key, Cb>,
        { caps::MAX_LIVELINESS_SUBSCRIPTIONS },
        P,
    >
{
    type Sink = Cb;
    type RowId = LivelinessSubscriberHandle;

    fn fire_matching<D: FnMut(LivelinessSubscriberHandle, RowAccess<'_, Cb>)>(
        &mut self,
        keyexpr: &str,
        historical: bool,
        mut deliver: D,
    ) -> usize {
        let reaches =
            |row: &LivelinessSubscriberRow<Key, Cb>| token_reaches(row, keyexpr, historical);
        let mut fired: usize = 0;
        if Cb::READS_ROW_IN_PLACE {
            for (_, handle, row) in self.live_handles() {
                if reaches(row) {
                    deliver(handle, RowAccess::InPlace(&row.callback));
                    fired = fired.saturating_add(1);
                }
            }
        } else {
            for (_, handle, row) in self.live_handles_mut() {
                if reaches(&*row) {
                    deliver(handle, RowAccess::Held(&mut row.callback));
                    fired = fired.saturating_add(1);
                }
            }
        }
        fired
    }

    fn pattern_of(&self, interest_id: u64) -> Option<&str> {
        self.iter()
            .find(|(_, row)| u64::from(row.id) == interest_id)
            .map(|(_, row)| text(&row.key.key))
    }

    fn row_of(
        &mut self,
        interest_id: u64,
    ) -> Option<(LivelinessSubscriberHandle, RowAccess<'_, Cb>)> {
        let handle = self
            .iter()
            .find(|(_, row)| u64::from(row.id) == interest_id)
            .map(|(handle, _)| handle)?;
        if Cb::READS_ROW_IN_PLACE {
            self.get(handle)
                .map(|row| (handle, RowAccess::InPlace(&row.callback)))
        } else {
            self.get_mut(handle)
                .map(|row| (handle, RowAccess::Held(&mut row.callback)))
        }
    }

    fn mark_history_complete(&mut self, interest_id: u64) {
        if let Some((_, row)) = self
            .iter()
            .find(|(_, row)| u64::from(row.id) == interest_id)
        {
            row.history_complete.set(true);
        }
    }
}

#[cfg(test)]
mod tests;
