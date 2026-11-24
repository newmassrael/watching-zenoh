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
//! ([`QueryHolder`]), so a query a C program keeps past its handler ([`HeldQuery`]) answers on its
//! own route whatever engine carried it.
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

use wz_session_core::declare::liveliness_sample::LivelinessSample;
use wz_session_core::link_restriction::LinkRestriction;
use wz_session_core::sink::SampleView;

// Totality debt TD-228 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod cancellation;
pub mod decl_watch;
mod drive;
mod engine;
pub mod entity_place;
pub mod group;
pub mod held_key;
// Totality debt TD-229 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod listeners;
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
pub mod sync;
// A time base the program supplies, made from the calls each C ABI's door is handed.
#[cfg(feature = "time-base")]
pub mod time_base;
pub mod tls_material;
pub use decl_watch::{DeclPlane, DeclWatchEvent, DeclWatchId, DeclWatchSink};
pub use drive::{CalledFromReadTask, ReadTaskStartRefused, SessionClosed, SessionDrive};
pub use engine::{RedeclareRefusal, SessionEngine};
pub use entity_place::{EntityKind, EntityPlace, PlaceLender, ENTITY_KINDS};
pub use held_key::{HeldKey, KeyAsk, KeyNotHeld, SessionKeys};
pub use peers::{
    each_group_member, each_known_node, each_peer, KnownNode, PeerIdentity, PeerLists,
};
pub use query::{HeldQuery, QblId, QueryCallback, QueryHolder, QueryableSink, ReplyCallback};
pub use refusal::Refusal;

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
#[derive(Clone, Copy)]
pub struct RawSampleCallback {
    call: unsafe fn(context: *mut core::ffi::c_void, sample: &dyn SampleView),
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
        call: unsafe fn(context: *mut core::ffi::c_void, sample: &dyn SampleView),
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

    /// Hand `sample` to the callback.
    pub fn call(&self, sample: &dyn SampleView) {
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

/// The id of one periodic job an engine runs ([`SessionEngine::start_ticker`]).
pub type TickerId = u64;

/// What a periodic job does each time it is due, and whether it goes on: `false` ends it.
///
/// It runs outside the engine's locks, so it may call back into the session (publish, declare).
pub type Tick = Arc<dyn Fn() -> bool + Send + Sync>;

/// A periodic job running on an engine, ended when this is dropped.
///
/// It holds the engine, so the engine lives as long as the job can be asked to stop; a job whose
/// owner is gone does not outlive it.
pub struct Ticker {
    /// `None` once [`Self::detach`] let the job go on without this handle.
    engine: Option<Arc<dyn SessionEngine>>,
    id: TickerId,
}

impl Ticker {
    /// Start `tick` on `engine` every `period_ms` ([`SessionEngine::start_ticker`]), refused as
    /// the engine refuses it.
    pub fn start(
        engine: &Arc<dyn SessionEngine>,
        period_ms: u64,
        tick: Tick,
    ) -> Result<Self, Refusal> {
        let id = engine.start_ticker(period_ms, tick)?;
        Ok(Self {
            engine: Some(Arc::clone(engine)),
            id,
        })
    }

    /// Let the job run on without this handle: it ends when it answers `false` (a job that holds
    /// what it works on weakly does, once that is gone) or with the engine.
    pub fn detach(mut self) {
        self.engine = None;
    }
}

impl Drop for Ticker {
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
pub type MatchingSink = Arc<dyn Fn(bool) + Send + Sync>;

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
    #[inline(never)]
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
    pub fn of_query(opts: &wz_session_core::query_options::QueryOptions) -> Result<(), Self> {
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
/// An entry that names `mapping_id` on the wire needs that declaration to outlive it, and the ABI
/// that made the declaration is the one that knows what retracts it. So the key carries what it
/// [`keeps`](Self::keeping) alive, and the entry holding the key holds that. For an entity with a
/// handle the ABI usually holds its own reference too; for a BACKGROUND entity, which has no
/// handle and lives as long as the session, the entry is the only holder — which is exactly the
/// lifetime zenoh-pico gives the declaration, stored with the subscription in the session's
/// table.
///
/// Entries are always released OUTSIDE an engine's locks, so what they keep may re-enter the
/// session as it drops (a keyexpr retraction does).
#[derive(Clone, Default)]
pub struct WireKey {
    /// The keyexpr declaration the wire names, `0` for none.
    pub mapping_id: wz_session_core::wire_id::ExprId,
    /// What follows the declared prefix, `None` when it covers the whole key.
    pub suffix: Option<String>,
    keeps: Keeps,
    /// One hold on the declaration of the key of the entity this key announces, when that is not
    /// the declaration the wire names: the entity's retraction names it, so it is held for as long
    /// as the entry is ([`Self::holding_also`]).
    also: Option<KeyHold>,
}

/// What a key keeps alive for as long as a declaration made on it stays recorded.
#[derive(Clone, Default)]
enum Keeps {
    /// Nothing.
    #[default]
    Nothing,
    /// An object of the ABI's that retracts the declaration when the last holder lets it go.
    Anchor { _held: Arc<dyn Send + Sync> },
    /// One hold on the declaration, counted by the engine itself.
    Hold { _held: KeyHold },
}

impl core::fmt::Debug for WireKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WireKey")
            .field("mapping_id", &self.mapping_id)
            .field("suffix", &self.suffix)
            .field("keeps", &!matches!(self.keeps, Keeps::Nothing))
            .field("also", &self.also.as_ref().map(KeyHold::mapping_id))
            .finish()
    }
}

/// One hold on a keyexpr declaration of a session, taken from and given back to the engine's own
/// count of the declaration's holders ([`SessionEngine::retain_keyexpr`],
/// [`SessionEngine::release_keyexpr`]): a copy takes another hold, a drop lets its hold go. It
/// keeps nothing of its own on the heap, and once the session is gone a copy and a drop do
/// nothing.
pub struct KeyHold {
    engine: alloc::sync::Weak<dyn SessionEngine>,
    mapping_id: wz_session_core::wire_id::ExprId,
}

impl KeyHold {
    /// The hold on `mapping_id` that the caller took through `engine`
    /// ([`SessionEngine::acquire_keyexpr`]), kept by this from here on.
    pub fn taken(
        engine: alloc::sync::Weak<dyn SessionEngine>,
        mapping_id: wz_session_core::wire_id::ExprId,
    ) -> Self {
        Self { engine, mapping_id }
    }

    /// The declaration held.
    pub fn mapping_id(&self) -> wz_session_core::wire_id::ExprId {
        self.mapping_id
    }

    /// Whether the hold is on `engine`'s session, by address.
    pub fn is_on(&self, engine: *const ()) -> bool {
        core::ptr::addr_eq(self.engine.as_ptr(), engine)
    }
}

impl Clone for KeyHold {
    fn clone(&self) -> Self {
        if let Some(engine) = self.engine.upgrade() {
            engine.retain_keyexpr(self.mapping_id);
        }
        Self {
            engine: self.engine.clone(),
            mapping_id: self.mapping_id,
        }
    }
}

impl Drop for KeyHold {
    fn drop(&mut self) {
        if let Some(engine) = self.engine.upgrade() {
            engine.release_keyexpr(self.mapping_id);
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
            suffix,
            keeps: Keeps::Nothing,
            also: None,
        }
    }

    /// This key, holding `anchor` alive for as long as a declaration made on it stays recorded.
    pub fn keeping(mut self, anchor: Arc<dyn Send + Sync>) -> Self {
        self.keeps = Keeps::Anchor { _held: anchor };
        self
    }

    /// This key, holding the declaration `hold` holds for as long as a declaration made on it
    /// stays recorded, in the engine's own count and with nothing of its own on the heap.
    pub fn holding(mut self, hold: KeyHold) -> Self {
        self.keeps = Keeps::Hold { _held: hold };
        self
    }

    /// This key, holding besides what it names the declaration `hold` holds, of the key of the
    /// entity it announces, which the entity's retraction names: one more hold in the engine's own
    /// count, with nothing of its own on the heap.
    pub fn holding_also(mut self, hold: KeyHold) -> Self {
        self.also = Some(hold);
        self
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
#[cfg(feature = "shared-key-ids")]
pub fn wire_on_link(link: wz_session_core::shared_key_ids::KeyWire<'_>) -> Option<WireKey> {
    use wz_session_core::shared_key_ids::KeyWire;
    match link {
        KeyWire::Declared => None,
        KeyWire::Literal => Some(WireKey::literal()),
        KeyWire::Shared { id, suffix } => Some(WireKey::aliased(id, suffix.map(String::from))),
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
    wire_on_link(link).map(|wire| wz_session_core::declare_form::InterestForm {
        suffix: if wire.is_literal() {
            Some(String::from(keyexpr))
        } else {
            wire.suffix
        },
        mapping_id: wire.mapping_id,
        aggregate: form.aggregate,
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

    #[test]
    fn a_kept_anchor_lives_as_long_as_the_key() {
        let anchor: Arc<dyn Send + Sync> = Arc::new(());
        let key = WireKey::aliased(7, Some(String::from("rest"))).keeping(anchor.clone());
        assert_eq!(Arc::strong_count(&anchor), 2);
        let copy = key.clone();
        assert_eq!(Arc::strong_count(&anchor), 3);
        drop(key);
        drop(copy);
        assert_eq!(Arc::strong_count(&anchor), 1);
    }
}
