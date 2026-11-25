// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The port between a wz C ABI and the engine that runs its sessions.
//!
//! A C ABI describes what a C program asks of a session; an engine runs the session. Today the
//! one engine is `wz-capi-core` (one OS thread and one tokio runtime per session); the next is
//! the cooperative engine, which the application steps as zenoh-pico's single-threaded arm does
//! (`docs/capi-pico-on-coop-engine.md`). This crate is what both sides name: the vocabulary a
//! request and its answer are spelled in, independent of any engine, async runtime or thread.
//!
//! ## What lives here
//!
//! A type belongs here when an ABI and an engine both have to name it and nothing in it is a
//! particular engine's. The ids an ABI's handles carry ([`SubId`], [`MatchId`], [`FilterId`],
//! [`TokenId`]), the callbacks and callback factories an ABI hands an engine
//! ([`SubscriberSink`], [`MatchingSink`], [`LivelinessSink`]), the
//! form a key takes on the wire ([`WireKey`]), what a write filter counts ([`FilterPlane`]) and
//! what a filtered put did ([`FilteredPut`], [`FanoutError`]). They lived in `wz-capi-core`'s
//! face registry, which re-exports them, so the zenoh-c ABI keeps its paths. Why an engine refused
//! a declaration is a [`Refusal`], which no id stands for. The multicast groups
//! an ABI asks a session to join, and what it tells them, are [`group`]'s, read by either engine.
//!
//! The operations an engine implements are [`SessionEngine`]: what a zenoh-pico client asks of a
//! session, which an ABI reaches through `Arc<dyn SessionEngine>` and nothing else; and
//! [`SessionDrive`], the session as a C handle holds it (its close, and how it is driven).
//!
//! A queryable's callbacks are minted with what the face's queries are held through
//! ([`QueryHolder`]), so a query a C program keeps past its handler ([`HeldQueryId`]) answers on
//! its own route whatever engine carried it.
//!
//! What stays with an engine is everything that names its sessions: the liveliness sample of the
//! tokio runtime, and the registry itself.
//!
//! ## Why a factory, not a callback
//!
//! An engine may hold several faces for one C session and replays every declaration onto each
//! face as it comes up, so a callback is needed once PER FACE: the ABI hands in something that
//! MINTS one, and the engine never learns what it closes over. The factory owns whatever the ABI
//! captured (its C closure), so the last factory released still runs the C `drop(context)`, which
//! is allowed to re-enter the session: an engine releases these outside its own locks.
//!
//! ## Where it builds
//!
//! `no_std` with `alloc`: an MCU image's pico ABI names the same port as the host's
//! (`docs/upstream-parity.md` step M5; the C ABI is one definition, a driver trait the host
//! runtime and the MCU slot host implement, and thin artefact crates binding the two). The `std`
//! feature, on by default, gives the port's lock to the process ([`sync`]); without it the lock
//! is a critical section the image links, or in a host library built without `std` the host's
//! own lock (`os-sys`). The cancellation token waits on the port's condition variable ([`os`])
//! in every build.

#![cfg_attr(not(feature = "std"), no_std)]
// Total functions in release code (docs/c-abi-architecture.md, P6): no panic is reachable from
// input. A module not yet converted is allowed by name with its row of the totality debt register
// (section 7 of that document), which scripts/lib/totality_debt_gate.py holds to these attributes.
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::arithmetic_side_effects
    )
)]

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use core::ops::Deref;

use wz_session_core::declare::liveliness_sample::LivelinessSample;
use wz_session_core::link_restriction::LinkRestriction;
use wz_session_core::sink::{SampleRef, SampleView};

pub mod cancellation;
pub mod decl_watch;
mod deliveries;
mod drive;
mod engine;
pub mod entity_place;
// A watcher of the faces' snapshots told through their rows, and one of their rows through their
// snapshots.
pub mod face_rows;
pub mod group;
pub mod held_key;
mod held_slab;
pub mod listeners;
pub mod lodge;
// What the doors of the observation plane do, for every C ABI: one behaviour, named by each ABI
// for itself. Only the features of the instruments compile it.
#[cfg(any(
    feature = "clock-source",
    feature = "event-ring",
    feature = "supervision",
    feature = "resource-snapshot"
))]
pub mod observation;
pub mod os;
mod peers;
mod query;
mod refusal;
// The limits of the process's runtime, which the machines it makes apart from any session read.
pub mod runtime_limits;
pub mod scout_ask;
pub mod sync;
// What each connectivity listener was told while its history is replayed (`SessionEngine::tell_came`).
pub mod told;
// A time base the program supplies, made from the calls each C ABI's door is handed.
#[cfg(feature = "time-base")]
pub mod time_base;
pub mod tls_material;
pub use decl_watch::{DeclPlane, DeclWatchEvent, DeclWatchId, DeclWatchSink};
pub use deliveries::EngineDeliveries;
pub use drive::{CalledFromReadTask, ReadTaskStartRefused, SessionClosed, SessionDrive};
pub use engine::{
    DeclarationReach, EngineHolder, KeyHolds, RedeclareRefusal, SessionEngine, Tickers,
};
pub use entity_place::{CacheBytes, EntityKind, EntityPlace, PlaceLender, ENTITY_KINDS};
pub use held_key::{HeldKey, KeyAsk, KeyNotHeld, SessionKeys};
pub use held_slab::HeldSlab;
pub use peers::{
    each_group_member, each_known_node, each_peer, KnownNode, PeerIdentity, PeerLists,
};
pub use query::{
    HeldQueryId, QblId, QueryHolder, QueryableSink, RawQueryCallback, RawQueryFn, ReplyCallback,
    SharedQueryFn,
};
pub use refusal::Refusal;
pub use scout_ask::ScoutAsk;

/// A C-level subscription id — what a `z_owned_subscriber_t` handle carries. It keys whatever an
/// engine holds for the one C subscription (the per-face subscribers it spawned, on an engine
/// with faces).
///
/// It is the entity id the declaration carries on the wire, so it has upstream's width
/// (`EntityId`, `u32`), and an engine that has handed out every one refuses the declaration
/// ([`SessionEngine::next_entity_id`]).
pub type SubId = wz_session_core::wire_id::EntityId;

/// A C-level matching-listener id, keying what an engine holds for one C declaration. Every value
/// is a live id: a refused declaration answers a [`Refusal`], never a number.
pub type MatchId = u64;

/// A C-level WRITE FILTER id — zenoh-pico's `_z_write_filter_t`, which a publisher or querier
/// holds for its whole life.
pub type FilterId = u64;

/// A subscriber's callback, as an ABI hands it to an engine. It is called through a shared borrow
/// ([`Self::call`]), from any thread and at any depth, a call from inside itself included:
/// zenoh-pico calls its subscriptions' callbacks with no lock of its session held, so a put a
/// callback makes on a key its own subscription matches calls it again from inside itself
/// (`vendor/zenoh-pico/src/session/subscription.c` @ `_z_trigger_subscriptions_impl`), and
/// upstream zenoh's callback is an `Arc<dyn Fn(Sample) + Send + Sync>`. It is let go of once, when
/// the engine is done with it, after its last call has returned: its drop is the program's.
pub enum SubscriberSink {
    /// A C program's closure: its function, its context and its drop, held as they are, with no
    /// heap ([`Self::raw`]).
    Raw(RawSampleCallback),
    /// A Rust program's closure, shared ([`Self::shared`]).
    Shared(Arc<SharedSampleFn>),
}

/// A Rust program's subscriber callback, as [`SubscriberSink::Shared`] shares it: upstream zenoh's
/// `Callback<Sample>` shape.
pub type SharedSampleFn = dyn Fn(&dyn SampleView) + Send + Sync;

/// The parts of a C program's closure an engine calls ([`SubscriberSink::Raw`]): plain values,
/// copied where they go; the drop runs once, when the [`SubscriberSink`] holding them is dropped.
/// It is handed the session's own sample ([`SampleRef`]), whose parts it reads as fields: one
/// indirect call per delivery, and none through a view.
#[derive(Clone, Copy)]
pub struct RawSampleCallback {
    call: unsafe fn(context: *mut core::ffi::c_void, sample: &SampleRef<'_>),
    context: *mut core::ffi::c_void,
    drop: Option<unsafe fn(context: *mut core::ffi::c_void)>,
}

// SAFETY: a raw callback is made only by `SubscriberSink::raw`, whose caller promises that its
// function may be called with its context from any thread, at once from several and from inside
// itself, and its drop once on any thread; the shared one is `Send + Sync` itself.
unsafe impl Send for SubscriberSink {}
// SAFETY: as `Send`.
unsafe impl Sync for SubscriberSink {}

impl SubscriberSink {
    /// A C program's closure: `call` with `context` for each sample, and `drop` with `context`
    /// once, when the engine lets it go.
    ///
    /// # Safety
    /// `call` may be called with `context` from any thread, at once from several and from inside
    /// itself, until `drop` is called; `drop`, when given, may be called with `context` once, on
    /// any thread, after the last call has returned.
    pub unsafe fn raw(
        call: unsafe fn(context: *mut core::ffi::c_void, sample: &SampleRef<'_>),
        context: *mut core::ffi::c_void,
        drop: Option<unsafe fn(context: *mut core::ffi::c_void)>,
    ) -> Self {
        Self::Raw(RawSampleCallback {
            call,
            context,
            drop,
        })
    }

    /// A Rust program's closure, shared.
    pub fn shared(call: impl Fn(&dyn SampleView) + Send + Sync + 'static) -> Self {
        Self::Shared(Arc::new(call))
    }

    /// Hand `sample` to the callback: a C program's is handed the session's sample read once off
    /// the view ([`SampleRef::of`]), for an engine that holds its sample as a view.
    pub fn call(&self, sample: &dyn SampleView) {
        match self {
            // SAFETY: `Self::raw`'s contract: the call may be made from here, now.
            Self::Raw(raw) => unsafe { (raw.call)(raw.context, &SampleRef::of(sample)) },
            Self::Shared(call) => call(sample),
        }
    }

    /// Hand the session's own `sample` to the callback as it lies, for an engine that holds its
    /// sample so: a C program's reads its parts with no call through a view.
    pub fn call_ref(&self, sample: &SampleRef<'_>) {
        match self {
            // SAFETY: `Self::raw`'s contract: the call may be made from here, now.
            Self::Raw(raw) => unsafe { (raw.call)(raw.context, sample) },
            Self::Shared(call) => call(sample),
        }
    }
}

impl Drop for SubscriberSink {
    fn drop(&mut self) {
        if let Self::Raw(RawSampleCallback {
            context,
            drop: Some(drop),
            ..
        }) = *self
        {
            // SAFETY: `Self::raw`'s contract: this is its one drop, after its last call, since a
            // call borrows the sink and the sink is dropped only once no borrow is left.
            unsafe { drop(context) };
        }
    }
}

/// A C-level liveliness token id — what a `z_owned_liveliness_token_t` handle carries: the
/// entity id the token is declared under, of the width [`SubId`] has for the same reason.
pub type TokenId = wz_session_core::wire_id::EntityId;

/// The id of one periodic job an engine runs ([`Tickers::start_ticker`]).
pub type TickerId = u64;

/// What a periodic job does each time it is due, and whether it goes on: `false` ends it.
///
/// It runs outside the engine's locks, so it may call back into the session (publish, declare).
pub type Tick = Arc<dyn Fn() -> bool + Send + Sync>;

/// A periodic job running on an engine, ended when this is dropped.
///
/// It holds the engine, so the engine lives as long as the job can be asked to stop; a job whose
/// owner is gone does not outlive it. It names the engine by its periodic jobs alone
/// ([`Tickers`]), so a build that reaches its engine as its own type makes no table of every
/// operation of the session for it. `H` is what holds the engine: the port's object by count by
/// default, or a holder of an engine's own type, which a holder generic over its engine keeps,
/// since an engine it names only as `?Sized` cannot be turned into the object, and an engine
/// placed in its session's memory is held by no `Arc`.
pub struct Ticker<H: Deref<Target: Tickers> = Arc<dyn Tickers>> {
    /// `None` once [`Self::detach`] let the job go on without this handle.
    engine: Option<H>,
    id: TickerId,
}

impl Ticker {
    /// Start `tick` on `engine` every `period_ms` ([`Tickers::start_ticker`]), refused as the
    /// engine refuses it. The handle keeps `engine`.
    pub fn start(engine: Arc<dyn Tickers>, period_ms: u64, tick: Tick) -> Result<Self, Refusal> {
        Self::start_on(engine, period_ms, tick)
    }
}

impl<H: Deref<Target: Tickers>> Ticker<H> {
    /// [`Ticker::start`] on an engine held by `H`.
    pub fn start_on(engine: H, period_ms: u64, tick: Tick) -> Result<Self, Refusal> {
        let id = engine.start_ticker(period_ms, tick)?;
        Ok(Self {
            engine: Some(engine),
            id,
        })
    }

    /// Let the job run on without this handle: it ends when it answers `false` (a job that holds
    /// what it works on weakly does, once that is gone) or with the engine.
    pub fn detach(mut self) {
        self.engine = None;
    }
}

impl<H: Deref<Target: Tickers>> Drop for Ticker<H> {
    fn drop(&mut self) {
        if let Some(engine) = self.engine.take() {
            engine.stop_ticker(self.id);
        }
    }
}

/// A liveliness subscriber's callback, as an ABI hands it to an engine: each token a peer declares
/// on the key is a `Put`, each it retracts a `Delete`. Called through a shared borrow, from any
/// thread and at any depth, and let go of once, after its last call, as [`SubscriberSink`] is.
pub enum LivelinessSink {
    /// A C program's closure: its function, its context and its drop, held as they are, with no
    /// heap ([`Self::raw`]).
    Raw(RawLivelinessCallback),
    /// A Rust program's closure, shared ([`Self::shared`]).
    Shared(Arc<SharedLivelinessFn>),
}

/// A Rust program's liveliness callback, as [`LivelinessSink::Shared`] shares it.
pub type SharedLivelinessFn = dyn for<'a> Fn(LivelinessSample<'a>) + Send + Sync;

/// The parts of a C program's closure an engine calls ([`LivelinessSink::Raw`]), as
/// [`RawSampleCallback`] holds a subscriber's.
#[derive(Clone, Copy)]
pub struct RawLivelinessCallback {
    call: unsafe fn(context: *mut core::ffi::c_void, sample: LivelinessSample<'_>),
    context: *mut core::ffi::c_void,
    drop: Option<unsafe fn(context: *mut core::ffi::c_void)>,
}

// SAFETY: as `SubscriberSink`'s: a raw callback is made only by `LivelinessSink::raw`, whose
// caller promises what the marker traits ask of it.
unsafe impl Send for LivelinessSink {}
// SAFETY: as `Send`.
unsafe impl Sync for LivelinessSink {}

impl LivelinessSink {
    /// A C program's closure: `call` with `context` for each change, and `drop` with `context`
    /// once, when the engine lets it go.
    ///
    /// # Safety
    /// As [`SubscriberSink::raw`]'s.
    pub unsafe fn raw(
        call: unsafe fn(context: *mut core::ffi::c_void, sample: LivelinessSample<'_>),
        context: *mut core::ffi::c_void,
        drop: Option<unsafe fn(context: *mut core::ffi::c_void)>,
    ) -> Self {
        Self::Raw(RawLivelinessCallback {
            call,
            context,
            drop,
        })
    }

    /// A Rust program's closure, shared.
    pub fn shared(call: impl for<'a> Fn(LivelinessSample<'a>) + Send + Sync + 'static) -> Self {
        Self::Shared(Arc::new(call))
    }

    /// Hand `sample` to the callback.
    pub fn call(&self, sample: LivelinessSample<'_>) {
        match self {
            // SAFETY: `Self::raw`'s contract: the call may be made from here, now.
            Self::Raw(raw) => unsafe { (raw.call)(raw.context, sample) },
            Self::Shared(call) => call(sample),
        }
    }
}

impl Drop for LivelinessSink {
    fn drop(&mut self) {
        if let Self::Raw(RawLivelinessCallback {
            context,
            drop: Some(drop),
            ..
        }) = *self
        {
            // SAFETY: `Self::raw`'s contract: this is its one drop, after its last call.
            unsafe { drop(context) };
        }
    }
}

/// Delivers ONE aggregated matching verdict to C.
///
/// Unlike [`SubscriberSink`] this is NOT a per-face factory, and the difference is the whole
/// design of the matching plane: a C program holds one matching listener and must be told about
/// the SESSION's verdict, not about each face's. A per-face pass-through would report the
/// opposite of the truth whenever one face matches and another does not.
///
/// Called through a shared borrow, from any thread and from inside itself, as a subscriber's
/// callback is ([`SubscriberSink`]), and let go of once, after its last call: its drop is the
/// program's.
pub enum MatchingSink {
    /// A C program's closure: its function, its context and its drop, held as they are, with no
    /// heap ([`Self::raw`]).
    Raw(RawMatchingCallback),
    /// A Rust program's closure, shared ([`Self::shared`]).
    Shared(Arc<dyn Fn(bool) + Send + Sync>),
}

/// The parts of a C program's closure an engine calls ([`MatchingSink::Raw`]): plain values; the
/// drop runs once, when the [`MatchingSink`] holding them is dropped.
#[derive(Clone, Copy)]
pub struct RawMatchingCallback {
    call: unsafe fn(context: *mut core::ffi::c_void, matching: bool),
    context: *mut core::ffi::c_void,
    drop: Option<unsafe fn(context: *mut core::ffi::c_void)>,
}

// SAFETY: as `SubscriberSink`'s: a raw callback is made only by `MatchingSink::raw`, whose caller
// promises what the marker traits ask of it; the shared one is `Send + Sync` itself.
unsafe impl Send for MatchingSink {}
// SAFETY: as `Send`.
unsafe impl Sync for MatchingSink {}

impl MatchingSink {
    /// A C program's closure: `call` with `context` for each status, and `drop` with `context`
    /// once, when the engine lets it go.
    ///
    /// # Safety
    /// As [`SubscriberSink::raw`]'s.
    pub unsafe fn raw(
        call: unsafe fn(context: *mut core::ffi::c_void, matching: bool),
        context: *mut core::ffi::c_void,
        drop: Option<unsafe fn(context: *mut core::ffi::c_void)>,
    ) -> Self {
        Self::Raw(RawMatchingCallback {
            call,
            context,
            drop,
        })
    }

    /// A Rust program's closure, shared.
    pub fn shared(call: impl Fn(bool) + Send + Sync + 'static) -> Self {
        Self::Shared(Arc::new(call))
    }

    /// Hand `matching` to the callback.
    pub fn call(&self, matching: bool) {
        match self {
            // SAFETY: `Self::raw`'s contract: the call may be made from here, now.
            Self::Raw(raw) => unsafe { (raw.call)(raw.context, matching) },
            Self::Shared(call) => call(matching),
        }
    }
}

impl Drop for MatchingSink {
    fn drop(&mut self) {
        if let Self::Raw(RawMatchingCallback {
            context,
            drop: Some(drop),
            ..
        }) = *self
        {
            // SAFETY: `Self::raw`'s contract: this is its one drop, after its last call, since a
            // call borrows the sink and the sink is dropped only once no borrow is left.
            unsafe { drop(context) };
        }
    }
}

/// Which declarations a write filter counts: pico's `_Z_WRITE_FILTER_SUBSCRIBER` for a
/// publisher, `_Z_WRITE_FILTER_QUERYABLE` for a querier (`vendor/zenoh-pico/src/net/filtering.c`
/// @ `ctx->target_type = expects_queryable ? _Z_WRITE_FILTER_QUERYABLE : _Z_WRITE_FILTER_SUBSCRIBER;`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterPlane {
    /// A publisher: does any peer subscribe to the key.
    Subscribers,
    /// A querier: does any peer answer on the key. `complete_required` is a target of
    /// `ALL_COMPLETE`, which counts only queryables declared complete.
    Queryables {
        /// See the variant.
        complete_required: bool,
    },
}

impl FilterPlane {
    /// Whether `self` and `other` count the same kind of declaration — subscribers, or
    /// queryables — whatever more either asks of a queryable. An Interest is held per kind and
    /// key, and a declaration of one kind reaches every filter and listener of that kind.
    pub fn same_kind(self, other: FilterPlane) -> bool {
        matches!(
            (self, other),
            (FilterPlane::Subscribers, FilterPlane::Subscribers)
                | (
                    FilterPlane::Queryables { .. },
                    FilterPlane::Queryables { .. }
                )
        )
    }
}

/// Why a fan-out publish could not be delivered to ANY face.
///
/// Named `FanoutError`, not `PublishError`: `wz_session_core::publish_options::PublishError` is
/// the per-session refusal, and two types with one name in one file is the shape a later reader
/// resolves wrongly.
///
/// R311y498 — a real type rather than `Result<_, ()>`, and not merely to satisfy
/// `clippy::result_unit_err`: a public function whose error carries no information leaves every
/// ABI mapping "something went wrong" onto its own generic code with no way to do better. The
/// variant is face-INDEPENDENT by construction — a per-face failure is skipped rather than
/// surfaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanoutError {
    /// The payload or keyexpr exceeded the bounded codec's capacity, so no face could have
    /// carried it.
    ExceedsCapacity,
    /// The publish stated something the engine does not honour ([`StatementNotHonoured`] names
    /// which): nothing was sent, to a link or to a subscriber of the session.
    NotHonoured(StatementNotHonoured),
    /// The publish may be dropped, another sender held the conduit (or the session) it would
    /// have been sent on, and the session's queue profile drops it at once and reports it
    /// (`HeldDrop::DropAtOnce`, the pico profile): a congestion drop its caller is told of, as
    /// zenoh-pico's put fails. Nothing was sent on that face. Under zenoh's profile a congestion
    /// drop is the publish's success, and this is never answered.
    HeldConduit,
}

impl From<StatementNotHonoured> for FanoutError {
    fn from(statement: StatementNotHonoured) -> Self {
        Self::NotHonoured(statement)
    }
}

impl From<LinksNotHonoured> for FanoutError {
    fn from(refusal: LinksNotHonoured) -> Self {
        Self::NotHonoured(refusal.into())
    }
}

/// A statement of a publish or a query that an engine cannot honour, by name: each is a policy of
/// the session model, off by default, that only some engines carry out. Taking the call as if
/// nothing were stated would make it something the caller did not ask for (a limited entity
/// unrestricted, a retry that never retries, a partial delivery of an all-or-none publish, a query
/// addressed to one node asked of every node), so the engine refuses it and sends or asks
/// nothing. A statement equal to the default (no set of links, no retry, not all-or-none, no
/// target) is no statement and is never refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementNotHonoured {
    /// A set of links (policy `entity-link-restriction`).
    Links,
    /// A retry for a publish that found no room (policy `publisher-admission-retry`).
    AdmissionRetry,
    /// The all-or-none form of a publish (policy `multi-route-atomic-tx`).
    AtomicTx,
    /// The one node a query is addressed to (policy `targeted-query`).
    TargetPeer,
}

impl StatementNotHonoured {
    /// The answer of an engine that honours none of a publish's statements: the first one
    /// `opts` makes is refused, and a publish that states none passes.
    pub fn of_publish(opts: &wz_session_core::publish_options::PublishOptions) -> Result<(), Self> {
        if opts.links.is_restricted() {
            Err(Self::Links)
        } else if opts.admission_retry.is_some() {
            Err(Self::AdmissionRetry)
        } else if opts.atomic_tx {
            Err(Self::AtomicTx)
        } else {
            Ok(())
        }
    }

    /// The answer of an engine that honours none of a query's statements: the first one `opts`
    /// makes is refused, and a query that states none passes.
    pub fn of_query(opts: &wz_session_core::query_options::QueryOptionsOf<'_>) -> Result<(), Self> {
        if opts.links.is_restricted() {
            Err(Self::Links)
        } else if opts.target_peer.is_some() {
            Err(Self::TargetPeer)
        } else {
            Ok(())
        }
    }
}

impl From<LinksNotHonoured> for StatementNotHonoured {
    fn from(_: LinksNotHonoured) -> Self {
        Self::Links
    }
}

impl core::fmt::Display for StatementNotHonoured {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Links => {
                "this engine does not limit a call to some of its links \
                 (policy entity-link-restriction)"
            }
            Self::AdmissionRetry => {
                "this engine does not retry a publish that found no room \
                 (policy publisher-admission-retry)"
            }
            Self::AtomicTx => {
                "this engine does not deliver a publish to all of its links or none \
                 (policy multi-route-atomic-tx)"
            }
            Self::TargetPeer => {
                "this engine does not address a query to one node (policy targeted-query)"
            }
        })
    }
}

impl core::error::Error for StatementNotHonoured {}

/// An engine's refusal of a set of links it cannot honour (policy `entity-link-restriction`).
///
/// An engine that does not number its links (one data plane, or one link per session) cannot
/// limit an entity or a call to some of them. Taking the call on every link would make a limited
/// entity unrestricted without saying so, so the engine refuses it by this name and declares,
/// sends and asks nothing. No set ([`LinkRestriction::Any`]) is never refused: it is the call
/// every engine makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinksNotHonoured;

impl LinksNotHonoured {
    /// The answer of an engine that limits nothing to some links: no set passes, and a set is
    /// refused.
    pub const fn unless_unrestricted(links: LinkRestriction) -> Result<(), Self> {
        if links.is_restricted() {
            Err(Self)
        } else {
            Ok(())
        }
    }
}

impl core::fmt::Display for LinksNotHonoured {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(
            "this engine does not limit an entity or a call to some of its links \
             (policy entity-link-restriction)",
        )
    }
}

impl core::error::Error for LinksNotHonoured {}

/// What a `zp_batch_*` call asks of every batch window of a session
/// ([`SessionEngine::batch_all`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchStep {
    /// Open a window (zenoh-pico `zp_batch_start`).
    Start,
    /// Write what the open windows hold and keep them open (zenoh-pico `zp_batch_flush`).
    Flush,
    /// Close the windows, writing what they hold (zenoh-pico `zp_batch_stop`).
    Stop,
}

/// What a put through a write filter did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilteredPut {
    /// The write filter said nothing matches: nothing was sent, and the put is answered as a
    /// success, as pico's is.
    Suppressed,
    /// The put was sent, with the answer a plain declared put gives.
    Sent(Result<usize, FanoutError>),
    /// The put is not plain on this node (a local subscriber wants it, or a face stamps what it
    /// sends): nothing was sent, and the caller takes the general publish.
    NotPlain,
}

/// How a C declaration's key goes on the WIRE, as distinct from the literal it matches on
/// locally.
///
/// The two differ whenever a declaring ABI names a key through one of its own keyexpr
/// declarations: the entity still matches the resolved literal, but the peer is told
/// `(mapping_id, suffix)`. `mapping_id == 0` is the literal itself, which is what zenoh-c's
/// session sends and the default here; the pico ABI announces through the declarations
/// zenoh-pico makes for its entities (`_z_declared_keyexpr_declare` and its non-wild-prefix
/// twin, `vendor/zenoh-pico/src/session/keyexpr.c`).
///
/// An engine records it with each declaration, because a face that joins later replays the
/// declaration and must announce it the same way. The id stays valid there: keyexpr
/// declarations are session-global and an engine replays them onto a new face FIRST.
///
/// ## What keeps the id declared
///
/// An entry that names `mapping_id` on the wire needs that declaration to outlive it. The engine
/// that records the entry holds the declaration in its own count of the declaration's holders,
/// under its lock, from the record to the entry's removal, as it holds the one the entry's
/// retraction names: the key carries no hold of its own, so a declaration has one count, the
/// engine's, as zenoh-pico's resource has one `_refcount`. For a BACKGROUND entity, which has no
/// handle and lives as long as the session, the entry is the only holder, which is exactly the
/// lifetime zenoh-pico gives the declaration, stored with the subscription in the session's
/// table.
///
/// An ABI whose declarations are retracted by an object of its own rather than by that count has
/// the key [`keep`](Self::keeping) the object alive, and the entry holding the key holds it. Entries
/// are always released OUTSIDE an engine's locks, so what they keep may re-enter the session as it
/// drops (a keyexpr retraction does).
#[derive(Default)]
pub struct WireKey {
    /// The keyexpr declaration the wire names, `0` for none.
    pub mapping_id: wz_session_core::wire_id::ExprId,
    /// What follows the declared prefix ([`Self::names_in`]).
    suffix: Suffix,
    keeps: Keeps,
    /// The declaration of the key of the entity this key announces, when the declaring ABI made
    /// one besides the one the wire names, `0` for none: the record of the entity holds it too
    /// ([`Self::with_own`]).
    own: wz_session_core::wire_id::ExprId,
    /// The row of the session's tables the declaration `mapping_id` was found at, by the holder
    /// that made the key ([`Self::at_row`]): an engine reads the declaration there while the row
    /// still holds the id, and searches for the id otherwise.
    row: Option<wz_session_core::session_tables::KeyexprHandle>,
}

/// The rest of a key past its declared prefix: none, a copy of its own, text that lies in what
/// the key keeps ([`WireKey::aliased_in`]), or the end of the key the wire key is handed with
/// ([`WireKey::aliased_tail`]), which every engine call takes beside it.
#[derive(Default)]
enum Suffix {
    #[default]
    None,
    Owned(String),
    Lent {
        at: core::ptr::NonNull<u8>,
        len: usize,
    },
    /// The last bytes of the key, by count.
    Tail(usize),
}

impl Suffix {
    /// The text the key has of its own or is lent; `None` for none and for a tail, which is read
    /// against the key.
    fn held(&self) -> Option<&str> {
        match self {
            Self::None | Self::Tail(_) => None,
            Self::Owned(rest) => Some(rest),
            // SAFETY: lent text lies, unchanged, in what the key keeps (`WireKey::aliased_in`),
            // and was a `str` there.
            Self::Lent { at, len } => Some(unsafe {
                core::str::from_utf8_unchecked(core::slice::from_raw_parts(at.as_ptr(), *len))
            }),
        }
    }
}

impl core::fmt::Debug for Suffix {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Tail(len) => f.debug_tuple("Tail").field(len).finish(),
            _ => core::fmt::Debug::fmt(&self.held(), f),
        }
    }
}

// SAFETY: lent text is read only, through shared borrows, and lies in what the key keeps, which
// is `Send + Sync`.
unsafe impl Send for Suffix {}
// SAFETY: as `Send`.
unsafe impl Sync for Suffix {}

/// What a key keeps alive for as long as a declaration made on it stays recorded.
#[derive(Default)]
enum Keeps {
    /// Nothing.
    #[default]
    Nothing,
    /// An object of the ABI's that retracts the declaration when the last holder lets it go, in a
    /// box of its own or lodged in a place of the ABI's.
    Anchor { _held: lodge::Kept },
}

impl core::fmt::Debug for WireKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WireKey")
            .field("mapping_id", &self.mapping_id)
            .field("suffix", &self.suffix)
            .field("keeps", &!matches!(self.keeps, Keeps::Nothing))
            .field("own", &self.own)
            .field("row", &self.row)
            .finish()
    }
}

/// Why a session took no more hold of a declaration ([`KeyHolds::retain_keyexpr`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldRefused {
    /// The declaration's count holds as many holders as it can.
    Full,
    /// The declaration is no longer held (its row went) or the session is closed: there is
    /// nothing to hold.
    Gone,
}

/// One hold on a keyexpr declaration of a session, counted by the engine's own count of the
/// declaration's holders ([`KeyHolds::retain_keyexpr`], [`KeyHolds::release_keyexpr`]).
///
/// It is the declaration's id, and the row of the session's tables the hold was taken in, by
/// which it is given back: a declaration retracted whatever held it leaves its id to a later one
/// once the ids wrap, and the row, whose generation moved on, names no declaration but its own.
/// It names no session and lets nothing go when it is dropped, so the object of the ABI's that
/// keeps it names its session beside it and gives it back to that session ([`Self::release`]); it
/// is neither copied nor cloned, so each hold is given back once, and one dropped unused is warned
/// of where it is made. What a session records holds its declarations in the same count itself,
/// and takes no `KeyHold` ([`WireKey`]).
#[must_use = "a hold is given back to its session (`KeyHold::release`), or its declaration stays"]
#[derive(Debug, PartialEq, Eq)]
pub struct KeyHold {
    mapping_id: wz_session_core::wire_id::ExprId,
    /// The row the hold was taken in; `None` for a copy its session took no hold for.
    row: Option<wz_session_core::session_tables::KeyexprHandle>,
}

impl KeyHold {
    /// The hold on `mapping_id` an engine took in `row` of its tables
    /// ([`SessionEngine::acquire_keyexpr`]), kept by this from here on.
    pub fn taken(
        mapping_id: wz_session_core::wire_id::ExprId,
        row: wz_session_core::session_tables::KeyexprHandle,
    ) -> Self {
        Self {
            mapping_id,
            row: Some(row),
        }
    }

    /// The declaration held.
    pub fn mapping_id(&self) -> wz_session_core::wire_id::ExprId {
        self.mapping_id
    }

    /// The row the hold was taken in, `None` when it holds nothing.
    pub fn row(&self) -> Option<wz_session_core::session_tables::KeyexprHandle> {
        self.row
    }

    /// One more hold on the same declaration, taken of `session`, the session this one is on.
    /// `None`, taking nothing, when the declaration's count holds as many holders as it can
    /// ([`HoldRefused::Full`]): a copy that held nothing would name a declaration the last
    /// counted holder's going retracts. A copy of a declaration no longer held, or of one on a
    /// closed session ([`HoldRefused::Gone`]), holds nothing, so that giving it back lets go of
    /// no hold another holder took.
    pub fn share<H: KeyHolds + ?Sized>(&self, session: &H) -> Option<Self> {
        let row = match self.row.map(|row| (row, session.retain_keyexpr(row))) {
            Some((row, Ok(()))) => Some(row),
            Some((_, Err(HoldRefused::Full))) => return None,
            Some((_, Err(HoldRefused::Gone))) | None => None,
        };
        Some(Self {
            mapping_id: self.mapping_id,
            row,
        })
    }

    /// A copy of a hold whose session is gone, which holds nothing.
    pub fn unheld(&self) -> Self {
        Self {
            mapping_id: self.mapping_id,
            row: None,
        }
    }

    /// Give the hold back to `session`, the session it was taken of; the last one retracts the
    /// declaration.
    pub fn release<H: KeyHolds + ?Sized>(self, session: &H) {
        if let Some(row) = self.row {
            session.release_keyexpr(row);
        }
    }

    /// Let go of a hold whose session is gone: the count it was one of went with the session, so
    /// there is nothing to give it back to.
    pub fn outlived_its_session(self) {
        let Self {
            mapping_id: _,
            row: _,
        } = self;
    }
}

/// What a key kept alive besides its name on the wire, taken out of the key that kept it
/// ([`WireKey::into_anchor`]): an object of the ABI's that retracts a declaration when its last
/// holder lets it go, or nothing. Dropping it lets the object go, which may reach the session, so
/// an engine drops it, with the row that keeps it, where it holds no lock of the session.
#[derive(Default)]
pub struct KeyAnchor {
    _keeps: Keeps,
}

/// A key as one link names it: the ABI's own, lent, or one the link's own form made, which holds
/// nothing of the session's.
pub enum LinkKey<'w> {
    /// The key as the ABI made it.
    Lent(&'w WireKey),
    /// The key as the link's form names it.
    Made(WireKey),
}

impl core::ops::Deref for LinkKey<'_> {
    type Target = WireKey;

    fn deref(&self) -> &WireKey {
        match *self {
            Self::Lent(wire) => wire,
            Self::Made(ref wire) => wire,
        }
    }
}

impl WireKey {
    /// The literal itself — no declaration.
    pub fn literal() -> Self {
        Self::default()
    }

    /// Declaration `mapping_id` followed by `suffix`.
    pub fn aliased(mapping_id: wz_session_core::wire_id::ExprId, suffix: Option<String>) -> Self {
        Self {
            mapping_id,
            suffix: suffix.map_or(Suffix::None, Suffix::Owned),
            keeps: Keeps::Nothing,
            own: 0,
            row: None,
        }
    }

    /// Declaration `mapping_id` followed by `rest` (none when it is empty), which lies in what
    /// `kept` keeps: the key copies nothing of it, and keeps `kept` for as long as a declaration
    /// made on it stays recorded.
    ///
    /// # Safety
    /// `rest` lies in the value `kept` counts and stays there, unchanged, while any count of it
    /// is held.
    pub unsafe fn aliased_in(
        mapping_id: wz_session_core::wire_id::ExprId,
        rest: &str,
        kept: lodge::Kept,
    ) -> Self {
        let suffix = match core::ptr::NonNull::new(rest.as_ptr().cast_mut()) {
            Some(at) if !rest.is_empty() => Suffix::Lent {
                at,
                len: rest.len(),
            },
            _ => Suffix::None,
        };
        Self {
            mapping_id,
            suffix,
            keeps: Keeps::Anchor { _held: kept },
            own: 0,
            row: None,
        }
    }

    /// Declaration `mapping_id` followed by the last `rest_len` bytes of the key the wire key is
    /// handed with (none when it is `0`): the key holds no text, and every engine call that takes
    /// it takes that key beside it ([`Self::names_in`]).
    pub fn aliased_tail(mapping_id: wz_session_core::wire_id::ExprId, rest_len: usize) -> Self {
        Self {
            mapping_id,
            suffix: if rest_len == 0 {
                Suffix::None
            } else {
                Suffix::Tail(rest_len)
            },
            keeps: Keeps::Nothing,
            own: 0,
            row: None,
        }
    }

    /// How the key goes on the wire, read against `keyexpr`, the key it was made for: the
    /// declaration's id and what follows it (`None` when it covers the whole key), or `0` and the
    /// whole of `keyexpr`. A tail that `keyexpr` cannot give (longer than it, or cutting a
    /// character) was made for another key, so the key is named whole, which every peer reads.
    pub fn names_in<'a>(
        &'a self,
        keyexpr: &'a str,
    ) -> (wz_session_core::wire_id::ExprId, Option<&'a str>) {
        if self.mapping_id == 0 {
            return (0, Some(keyexpr));
        }
        match self.suffix {
            Suffix::Tail(len) => match keyexpr
                .len()
                .checked_sub(len)
                .and_then(|at| keyexpr.get(at..))
            {
                Some(rest) => (self.mapping_id, Some(rest)),
                None => (0, Some(keyexpr)),
            },
            ref held => (self.mapping_id, held.held()),
        }
    }

    /// A lent rest copied into the key, before what it lies in is let go of. A tail lies in no
    /// keep, so it stays as it is.
    fn own_suffix(&mut self) {
        if let Suffix::Lent { .. } = self.suffix {
            self.suffix = self
                .suffix
                .held()
                .map_or(Suffix::None, |rest| Suffix::Owned(rest.into()));
        }
    }

    /// This key, holding `anchor` alive for as long as a declaration made on it stays recorded.
    pub fn keeping(mut self, anchor: lodge::Kept) -> Self {
        self.own_suffix();
        self.keeps = Keeps::Anchor { _held: anchor };
        self
    }

    /// This key, naming besides what goes on the wire `mapping_id`, the declaration of the key of
    /// the entity it announces, which the entity's record holds for as long as it stands, as
    /// zenoh-pico's subscription keeps its own declared key: the key takes no hold of it itself.
    pub fn with_own(mut self, mapping_id: wz_session_core::wire_id::ExprId) -> Self {
        self.own = mapping_id;
        self
    }

    /// This key, naming its declaration at `row`, the row of the session's tables the holder of
    /// the declaration took its hold in ([`KeyHold::row`]); `None` for a holder that knows none.
    pub fn at_row(mut self, row: Option<wz_session_core::session_tables::KeyexprHandle>) -> Self {
        self.row = row;
        self
    }

    /// The declaration the wire names, with the row the holder found it at ([`Self::at_row`]).
    pub fn declared(&self) -> wz_session_core::session_tables::KeyexprRef {
        wz_session_core::session_tables::KeyexprRef {
            id: self.mapping_id,
            row: self.row,
        }
    }

    /// The declaration of the key of the entity this key announces ([`Self::with_own`]), `0`
    /// for none.
    pub fn own_declaration(&self) -> wz_session_core::wire_id::ExprId {
        self.own
    }

    /// What the key kept alive, the key let go of: the one place an anchor leaves a key, so the
    /// row that records an entity keeps it, and lets it go with the row.
    pub fn into_anchor(self) -> KeyAnchor {
        KeyAnchor { _keeps: self.keeps }
    }

    /// Whether the key goes on the wire as its literal, naming no declaration.
    pub fn is_literal(&self) -> bool {
        self.mapping_id == 0
    }
}

/// `wire` as one link names its key, by what the link's key-wire form answered for it
/// (`SessionLinkActions::key_wire_on_link`): `None` for the declared form, which keeps `wire` as
/// the ABI made it; the literal; or an id of the dictionary every node of the deployment shares,
/// with the rest of the key, which no declaration precedes and which therefore keeps nothing.
///
/// The rest is the end of the key the link was asked about, so the key made names it by its
/// length and is read against that key ([`WireKey::names_in`]): naming it copies nothing.
#[cfg(feature = "shared-key-ids")]
pub fn wire_on_link(link: wz_session_core::shared_key_ids::KeyWire<'_>) -> Option<WireKey> {
    use wz_session_core::shared_key_ids::KeyWire;
    match link {
        KeyWire::Declared => None,
        KeyWire::Literal => Some(WireKey::literal()),
        KeyWire::Shared { id, suffix } => {
            Some(WireKey::aliased_tail(id, suffix.map_or(0, str::len)))
        }
    }
}

/// `form`, an Interest that asks about `keyexpr`, as one link names that key, by what the link's
/// key-wire form answered for it ([`wire_on_link`]): `None` for the declared form, which keeps
/// `form` as the ABI made it; the whole key under id 0 for the literal; an id of the dictionary
/// every node of the deployment shares, with the rest of the key, otherwise. What the Interest
/// asks (`aggregate`) is the ABI's either way.
///
/// An Interest names its key as a put, a query and a declaration on the same link do, so a peer
/// that reads keys only whole or by the dictionary reads the Interest too: a declaration of this
/// session's own, which such a peer never resolves, is not named under any form but `declared`.
#[cfg(feature = "shared-key-ids")]
pub fn interest_on_link(
    link: wz_session_core::shared_key_ids::KeyWire<'_>,
    keyexpr: &str,
    form: &wz_session_core::declare_form::InterestForm,
) -> Option<wz_session_core::declare_form::InterestForm> {
    wire_on_link(link).map(|wire| {
        let (mapping_id, suffix) = wire.names_in(keyexpr);
        wz_session_core::declare_form::InterestForm {
            mapping_id,
            suffix: suffix.map(String::from),
            aggregate: form.aggregate,
        }
    })
}

/// How an Interest names its key on a link of each key-wire form (`shared-key-ids`).
#[cfg(all(test, feature = "shared-key-ids"))]
mod link_form_tests {
    use super::*;
    use wz_session_core::declare_form::InterestForm;
    use wz_session_core::shared_key_ids::KeyWire;

    const KEY: &str = "lab/rig/alpha";

    /// How the ABI asks: by the session's own declaration 7 and the rest after it, aggregated.
    fn by_declaration() -> InterestForm {
        InterestForm {
            mapping_id: 7,
            suffix: Some(String::from("/alpha")),
            aggregate: true,
        }
    }

    #[test]
    fn an_interest_on_a_literal_link_names_its_key_whole() {
        assert_eq!(
            interest_on_link(KeyWire::Literal, KEY, &by_declaration()),
            Some(InterestForm {
                mapping_id: 0,
                suffix: Some(String::from(KEY)),
                aggregate: true,
            })
        );
    }

    #[test]
    fn an_interest_on_a_shared_link_names_the_dictionary_id_and_the_rest() {
        assert_eq!(
            interest_on_link(
                KeyWire::Shared {
                    id: 40,
                    suffix: Some("/alpha"),
                },
                KEY,
                &by_declaration(),
            ),
            Some(InterestForm {
                mapping_id: 40,
                suffix: Some(String::from("/alpha")),
                aggregate: true,
            })
        );
        assert_eq!(
            interest_on_link(
                KeyWire::Shared {
                    id: 41,
                    suffix: None,
                },
                KEY,
                &by_declaration(),
            ),
            Some(InterestForm {
                mapping_id: 41,
                suffix: None,
                aggregate: true,
            })
        );
    }

    /// A key on a link of the shared form names the dictionary's id and the rest of the key, read
    /// where the key lies rather than copied into the wire key.
    ///
    /// # Control
    ///
    /// A wire key that copies the rest (`WireKey::aliased` over `String::from`) reds the pointer
    /// assertion; one whose length is not the rest's reds the first.
    #[test]
    fn a_key_on_a_shared_link_names_the_end_of_the_key_where_it_lies() {
        let rest = KEY.get("lab/rig".len()..).expect("the rest of the key");
        let wire = wire_on_link(KeyWire::Shared {
            id: 40,
            suffix: Some(rest),
        })
        .expect("the shared form names the key its own way");
        assert_eq!(wire.names_in(KEY), (40, Some("/alpha")));
        assert_eq!(
            wire.names_in(KEY).1.map(str::as_ptr),
            Some(rest.as_ptr()),
            "the rest is read where the key lies"
        );
        let whole = wire_on_link(KeyWire::Shared {
            id: 41,
            suffix: None,
        })
        .expect("the shared form names the key its own way");
        assert_eq!(whole.names_in(KEY), (41, None));
        assert!(wire_on_link(KeyWire::Declared).is_none());
    }

    #[test]
    fn an_interest_on_a_declared_link_is_left_as_the_abi_made_it() {
        assert_eq!(
            interest_on_link(KeyWire::Declared, KEY, &by_declaration()),
            None
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A C program's callback is handed the session's own sample as it lies when the engine holds
    /// one ([`SubscriberSink::call_ref`]), and one read once off a view otherwise
    /// ([`SubscriberSink::call`]), with the parts the view handed. Turned red by a raw call that
    /// rebuilds a sample the engine already holds.
    #[test]
    fn a_raw_sink_is_handed_the_sessions_sample_as_it_lies() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        use wz_session_core::reliability::Reliability;
        use wz_session_core::sample::SampleKind;
        static HANDED: AtomicUsize = AtomicUsize::new(0);
        static READ: AtomicUsize = AtomicUsize::new(0);
        unsafe fn note(_context: *mut core::ffi::c_void, sample: &SampleRef<'_>) {
            HANDED.store(core::ptr::from_ref(sample) as usize, Ordering::SeqCst);
            let attachment = sample.attachment.map_or(0, <[u8]>::len);
            READ.store(
                sample.keyexpr.len() + sample.payload.len() + attachment,
                Ordering::SeqCst,
            );
        }
        // SAFETY: `note` reads only the sample it is handed, from any thread; nothing is dropped.
        let sink = unsafe { SubscriberSink::raw(note, core::ptr::null_mut(), None) };
        let mut sample = SampleRef::new("demo/ref", b"pay", SampleKind::Put, Reliability::Reliable);
        sample.attachment = Some(&b"att"[..]);
        let at = core::ptr::from_ref(&sample) as usize;

        sink.call_ref(&sample);
        assert_eq!(HANDED.load(Ordering::SeqCst), at, "the engine's own sample");
        assert_eq!(READ.load(Ordering::SeqCst), 14);

        READ.store(0, Ordering::SeqCst);
        sink.call(&sample);
        assert_ne!(
            HANDED.load(Ordering::SeqCst),
            at,
            "a view is read into a sample of its own"
        );
        assert_eq!(
            READ.load(Ordering::SeqCst),
            14,
            "with every part the view handed"
        );
    }

    #[test]
    fn an_engine_that_limits_nothing_refuses_a_set_and_passes_none() {
        assert_eq!(
            LinksNotHonoured::unless_unrestricted(LinkRestriction::Any),
            Ok(())
        );
        let one = LinkRestriction::only([1]).expect("one slot");
        assert_eq!(
            LinksNotHonoured::unless_unrestricted(one),
            Err(LinksNotHonoured)
        );
        assert_eq!(
            FanoutError::from(LinksNotHonoured),
            FanoutError::NotHonoured(StatementNotHonoured::Links)
        );
    }

    /// Each statement of a publish and of a query is refused by its own name, the defaults are
    /// no statement, and a statement is refused even when another one is not made.
    #[test]
    fn each_statement_is_refused_by_its_name_and_the_defaults_pass() {
        use wz_session_core::admission_retry::AdmissionRetry;
        use wz_session_core::publish_options::PublishOptions;
        use wz_session_core::query_options::QueryOptions;

        let one = LinkRestriction::only([1]).expect("one slot");
        let retry = AdmissionRetry {
            attempts: 2,
            delay_ms: 5,
        };
        assert_eq!(
            StatementNotHonoured::of_publish(&PublishOptions::put()),
            Ok(())
        );
        assert_eq!(
            StatementNotHonoured::of_publish(&PublishOptions::put().with_links(one)),
            Err(StatementNotHonoured::Links)
        );
        assert_eq!(
            StatementNotHonoured::of_publish(&PublishOptions::put().with_admission_retry(retry)),
            Err(StatementNotHonoured::AdmissionRetry)
        );
        assert_eq!(
            StatementNotHonoured::of_publish(&PublishOptions::put().with_atomic_tx()),
            Err(StatementNotHonoured::AtomicTx)
        );
        assert_eq!(
            StatementNotHonoured::of_query(&QueryOptions::default()),
            Ok(())
        );
        assert_eq!(
            StatementNotHonoured::of_query(&QueryOptions::default().with_links(one)),
            Err(StatementNotHonoured::Links)
        );
        assert_eq!(
            StatementNotHonoured::of_query(&QueryOptions::default().with_target_peer([0xc7])),
            Err(StatementNotHonoured::TargetPeer)
        );
        assert_eq!(
            FanoutError::from(StatementNotHonoured::AtomicTx),
            FanoutError::NotHonoured(StatementNotHonoured::AtomicTx)
        );
    }

    #[test]
    fn a_literal_key_names_no_declaration() {
        assert!(WireKey::literal().is_literal());
        assert!(!WireKey::aliased(3, None).is_literal());
    }

    /// A key names the declaration of its entity's own key apart from what goes on the wire, and
    /// keeps it through `keeping`. Turned red by a `with_own` that writes the wire's id, or by a
    /// `keeping` that drops it.
    #[test]
    fn a_key_names_its_entitys_own_declaration_apart_from_the_wire() {
        assert_eq!(WireKey::literal().own_declaration(), 0);
        let key = WireKey::literal().with_own(5);
        assert!(key.is_literal(), "the wire still names no declaration");
        assert_eq!(key.own_declaration(), 5);
        let kept = key.keeping(crate::lodge::Kept::shared(Arc::new(())));
        assert_eq!(kept.own_declaration(), 5);
    }

    /// A key names its declaration with the row its holder gave, kept through `keeping` and
    /// `with_own`, and with none when no holder gave one. Turned red by a key that drops the row
    /// it was given, or by a `declared` that names another id than the wire's.
    #[test]
    fn a_key_names_its_declaration_with_the_row_its_holder_gave() {
        use wz_session_core::session_tables::KeyexprRef;
        let row = wz_session_core::slot_map::Handle::from_bits(
            core::num::NonZeroU32::new(0x0003_0002).expect("not zero"),
        );
        assert_eq!(WireKey::literal().declared(), KeyexprRef::default());
        assert_eq!(WireKey::aliased(7, None).declared(), KeyexprRef::by_id(7));
        let key = WireKey::aliased_tail(7, 0).at_row(row).with_own(5);
        let kept = key.keeping(crate::lodge::Kept::shared(Arc::new(())));
        assert_eq!(kept.declared(), KeyexprRef { id: 7, row });
    }

    /// A tail is read against the key the wire key is handed with: the end of it, of the length
    /// the key was made with, and the whole key under no declaration when the key cannot give it
    /// (shorter, or cut inside a character).
    ///
    /// # Control
    ///
    /// A `names_in` that reads the tail from the front of the key reds the first assertion; one
    /// that cuts a key it cannot give reds the "shorter" and "cut inside a character" ones.
    #[test]
    fn a_tail_is_the_end_of_the_key_it_is_handed_with() {
        let key = WireKey::aliased_tail(9, "/rest".len());
        assert_eq!(key.names_in("demo/data/rest"), (9, Some("/rest")));
        assert_eq!(key.names_in("abc"), (0, Some("abc")), "shorter");
        assert_eq!(
            key.names_in("a/\u{d55c}\u{ae00}"),
            (0, Some("a/\u{d55c}\u{ae00}")),
            "cut inside a character"
        );
        assert_eq!(WireKey::aliased_tail(9, 0).names_in("demo/data"), (9, None));
        assert_eq!(
            WireKey::literal().names_in("demo/data"),
            (0, Some("demo/data"))
        );
    }

    /// A rest that lies in what the key keeps is lent, not copied, to the key; keeping something
    /// else instead copies it first, so it never outlives what it lay in.
    ///
    /// # Control
    ///
    /// A key that copies the rest it is given reds the first assertion; a `keeping` that leaves
    /// the rest lent reds the last.
    #[test]
    fn a_kept_rest_is_lent_to_the_key() {
        let text: Arc<String> = Arc::new(String::from("demo/data/rest"));
        let rest = text.get("demo/data".len()..).expect("the rest of the key");
        // SAFETY: `rest` lies in the string the keep counts, which nothing changes.
        let key = unsafe { WireKey::aliased_in(9, rest, crate::lodge::Kept::shared(text.clone())) };
        assert_eq!(
            key.names_in("demo/data/rest").1.map(str::as_ptr),
            Some(rest.as_ptr()),
            "lent"
        );
        assert_eq!(key.names_in("demo/data/rest"), (9, Some("/rest")));
        let other: Arc<dyn Send + Sync> = Arc::new(());
        let rekept = key.keeping(crate::lodge::Kept::shared(other));
        assert_eq!(rekept.names_in("demo/data/rest"), (9, Some("/rest")));
        assert_ne!(
            rekept.names_in("demo/data/rest").1.map(str::as_ptr),
            Some(rest.as_ptr()),
            "keeping something else copies the rest first"
        );
    }

    /// A kept anchor lives as long as the key, and as what the key kept once it is let go of,
    /// until that is dropped. Turned red by an `into_anchor` that leaves the anchor behind with
    /// the key.
    #[test]
    fn a_kept_anchor_lives_until_what_the_key_kept_is_dropped() {
        let anchor: Arc<dyn Send + Sync> = Arc::new(());
        let key = WireKey::aliased(7, Some(String::from("rest")))
            .keeping(crate::lodge::Kept::shared(anchor.clone()));
        assert_eq!(Arc::strong_count(&anchor), 2);
        let kept = key.into_anchor();
        assert_eq!(Arc::strong_count(&anchor), 2, "what the key kept keeps it");
        drop(kept);
        assert_eq!(Arc::strong_count(&anchor), 1);
    }

    /// A session's count of a declaration's holders as a test keeps it: each hold taken and each
    /// given back, by the bits of its row, in order, up to four of each; it refuses every hold
    /// asked once `refuses` is set.
    #[derive(Default)]
    struct CountedHolds {
        retained: Rows,
        released: Rows,
        /// 0 takes every hold; 1 refuses as full; 2 as gone.
        refuses: core::sync::atomic::AtomicU8,
    }

    /// Up to four rows, as the bits of their handles, in the order they were written.
    #[derive(Default)]
    struct Rows {
        rows: [core::sync::atomic::AtomicU32; 4],
        len: core::sync::atomic::AtomicUsize,
    }

    impl Rows {
        fn push(&self, row: wz_session_core::session_tables::KeyexprHandle) {
            let at = self.len.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
            self.rows[at].store(row.to_bits().get(), core::sync::atomic::Ordering::SeqCst);
        }

        fn read(&self) -> alloc::vec::Vec<u32> {
            let len = self.len.load(core::sync::atomic::Ordering::SeqCst);
            self.rows[..len]
                .iter()
                .map(|row| row.load(core::sync::atomic::Ordering::SeqCst))
                .collect()
        }
    }

    impl CountedHolds {
        fn refuse(&self, why: HoldRefused) {
            let code = match why {
                HoldRefused::Full => 1,
                HoldRefused::Gone => 2,
            };
            self.refuses
                .store(code, core::sync::atomic::Ordering::SeqCst);
        }
    }

    impl KeyHolds for CountedHolds {
        fn release_keyexpr(&self, row: wz_session_core::session_tables::KeyexprHandle) {
            self.released.push(row);
        }

        fn retain_keyexpr(
            &self,
            row: wz_session_core::session_tables::KeyexprHandle,
        ) -> Result<(), HoldRefused> {
            match self.refuses.load(core::sync::atomic::Ordering::SeqCst) {
                1 => Err(HoldRefused::Full),
                2 => Err(HoldRefused::Gone),
                _ => {
                    self.retained.push(row);
                    Ok(())
                }
            }
        }
    }

    /// The row of slot 4 at generation 1, as the bits of its handle.
    const ROW_BITS: u32 = 0x0001_0004;

    /// The row of slot 4 at generation 1.
    fn row() -> wz_session_core::session_tables::KeyexprHandle {
        core::num::NonZeroU32::new(ROW_BITS)
            .and_then(wz_session_core::session_tables::KeyexprHandle::from_bits)
            .expect("an index half that is not zero")
    }

    /// A hold shared is one more hold of the session's count, and each hold is given back once,
    /// by its row, to the session it is handed. Turned red by `KeyHold::share` taking no hold of
    /// the session (`retained` empty), or by `KeyHold::release` giving none back.
    #[test]
    fn a_hold_is_shared_and_given_back_once_to_its_session() {
        let session = CountedHolds::default();
        let named = KeyHold::taken(4, row());
        let shared = named.share(&session).expect("a count with room");
        assert_eq!(session.retained.read(), [ROW_BITS]);
        assert_eq!(shared.mapping_id(), 4);
        assert_eq!(shared.row(), Some(row()));
        shared.release(&session);
        assert_eq!(session.released.read(), [ROW_BITS]);
        named.release(&session);
        assert_eq!(session.released.read(), [ROW_BITS, ROW_BITS]);
    }

    /// A share past a full count is refused, and a copy of a declaration no longer held, or of a
    /// hold whose session is gone, holds nothing and gives nothing back: a hold given back by such
    /// a copy would let go of one another holder took. Turned red by a `KeyHold::share` that makes
    /// a copy past a full count (`Some`), or a copy that keeps a row its session took no hold of
    /// (`released` not empty).
    #[test]
    fn a_share_past_a_full_count_is_refused_and_an_unheld_copy_gives_nothing_back() {
        let session = CountedHolds::default();
        let named = KeyHold::taken(4, row());
        session.refuse(HoldRefused::Full);
        assert_eq!(named.share(&session), None, "no copy past a full count");
        session.refuse(HoldRefused::Gone);
        let gone = named
            .share(&session)
            .expect("a copy of what is no longer held");
        assert_eq!(gone.mapping_id(), 4, "the copy names the declaration");
        assert_eq!(gone.row(), None);
        let outlived = named.unheld();
        assert_eq!(outlived.row(), None);
        gone.release(&session);
        outlived.release(&session);
        assert!(session.retained.read().is_empty());
        assert!(session.released.read().is_empty());
        named.release(&session);
        assert_eq!(session.released.read(), [ROW_BITS], "CONTROL: the held one");
    }

    /// An engine's periodic jobs as a test counts them: the ids it gave and the jobs it stopped.
    #[derive(Default)]
    struct CountedJobs {
        started: core::sync::atomic::AtomicU64,
        stopped: core::sync::atomic::AtomicU64,
        refuses: bool,
    }

    impl Tickers for CountedJobs {
        fn start_ticker(&self, _period_ms: u64, _tick: Tick) -> Result<TickerId, Refusal> {
            if self.refuses {
                return Err(Refusal::NotBuilt);
            }
            Ok(self
                .started
                .fetch_add(1, core::sync::atomic::Ordering::SeqCst))
        }

        fn stop_ticker(&self, _id: TickerId) {
            self.stopped
                .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        }
    }

    /// A holder that names its engine by its own type keeps it as that type, and its handle stops
    /// the job on drop as the port's object's does; a detached one leaves it running.
    #[test]
    fn a_job_on_an_engine_of_its_own_type_stops_with_its_handle() {
        use core::sync::atomic::Ordering;
        let jobs = Arc::new(CountedJobs::default());
        let tick: Tick = Arc::new(|| true);
        let held: Ticker<Arc<CountedJobs>> =
            Ticker::start_on(Arc::clone(&jobs), 5, Arc::clone(&tick)).expect("started");
        assert_eq!(Arc::strong_count(&jobs), 2, "the handle keeps the engine");
        drop(held);
        assert_eq!(jobs.stopped.load(Ordering::SeqCst), 1);
        assert_eq!(Arc::strong_count(&jobs), 1);

        Ticker::start_on(Arc::clone(&jobs), 5, Arc::clone(&tick))
            .expect("started")
            .detach();
        assert_eq!(jobs.started.load(Ordering::SeqCst), 2);
        assert_eq!(
            jobs.stopped.load(Ordering::SeqCst),
            1,
            "a detached job is not stopped"
        );

        let object: Arc<dyn Tickers> = jobs.clone();
        drop(Ticker::start(object, 5, Arc::clone(&tick)).expect("started"));
        assert_eq!(jobs.stopped.load(Ordering::SeqCst), 2);

        let refusing = Arc::new(CountedJobs {
            refuses: true,
            ..CountedJobs::default()
        });
        assert!(matches!(
            Ticker::start_on(refusing, 5, tick),
            Err(Refusal::NotBuilt)
        ));
    }
}
