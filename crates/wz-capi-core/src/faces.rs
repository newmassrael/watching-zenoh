// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The C session's face registry and subscription SSOT — the join between
//! pico's "one session, N peers" model and wz's "one session, one peer".
//!
//! ## Why a registry rather than a session
//!
//! pico models a session as a PEER LIST: `_z_transport_peer_unicast_slist_t
//! *_peers` (`~/zenoh-pico/include/zenoh-pico/transport/transport.h:200`). A
//! `client` session holds exactly one peer (the router it dialed); a `listen`
//! peer session accepts multiple CONCURRENT inbound peers.
//!
//! DIVERGENCE (named, not mirrored): pico caps a listener at
//! `Z_LISTEN_MAX_CONNECTION_NB` = 10 and REFUSES the 11th before its handshake
//! (`src/transport/unicast/accept.c:85-92`,
//! `include/zenoh-pico/config.h.in:213`; pinned by
//! `tests/z_test_peer_unicast.c` — 10 admitted, the 11th rejected). wz's
//! `accept_loop` enforces NO connection cap and holds unbounded faces, so a
//! program relying on the 11th `z_open` failing as back-pressure sees it
//! succeed here. The cap is an embedded static-array-sizing artifact with no
//! hosted-runtime rationale, so this is a deliberate superset, not a bug;
//! matching it would need a configurable pre-handshake cap in `accept_loop`
//! (which has no such knob today) and is deferred.
//!
//! wz models a unicast `Session` as exactly ONE peer (its engine is an
//! `Engine<SessionFsmUnicastPolicy>`) and holds N peers as N sessions
//! multiplexed on one accept loop ([`wz_runtime_tokio::accept_loop`]). So the
//! C handle cannot BE a wz session; it is a REGISTRY of per-face wz sessions
//! plus the C-declared subscription SSOT replayed onto each face as it comes
//! up. `connect` fills exactly one face, `listen` fills N — the same shape
//! pico's `_peers` list has for the same two roles (see the cap divergence
//! above).
//!
//! ## Why per-face sessions, not one shared observer
//!
//! Each face gets its OWN [`TokioSession`], hence its own
//! [`ApplicationLayerObserver`]. That is load-bearing, not incidental: the
//! observer's peer-declared keyexpr alias table (expr-id -> keyexpr) is a
//! PER-PEER id space. One observer shared across N faces would conflate them
//! — peer A's `id=7 -> "home/temp"` and peer B's `id=7 -> "office/light"`
//! would collide and silently mis-route every aliased sample. Per-face
//! sessions make that unrepresentable rather than merely untested, and the
//! fan-out lives here at the C layer, where the subscription SSOT already is.
//!
//! ## Declare-before-peer
//!
//! pico supports declaring subscribers before any peer connects: declarations
//! live in the session's local tables and are pushed to each peer as it joins
//! (`src/transport/unicast/accept.c:148-149`). Here that falls out of the
//! registry for free — [`SharedSession::declare_subscriber`] records a
//! [`SubEntry`] in the SSOT and declares it on whatever faces exist (possibly
//! none); [`SharedSession::face_up`] replays the whole SSOT onto each new
//! face.
//!
//! ## Locking discipline
//!
//! Every path that can invoke the C side — dispatching a sample (fires the
//! subscriber callback) or dropping a subscriber / the last closure reference
//! (fires the C `drop(context)`) — first moves what it needs OUT of the
//! registry lock and only then calls into C. A pico callback is explicitly
//! allowed to re-enter the session (`z_put` from inside a subscriber callback
//! is a supported pattern, and this crate's own round-trip test does it), so
//! holding the lock across a C call would deadlock.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};

use tokio::sync::Notify;

use crate::group::{retire_copies, FaceGroup, GroupAggregate, GroupError, GroupId};
use wz_runtime_tokio::accept_loop::{FaceForwarder, FaceId};
use wz_runtime_tokio::advanced_publisher::{AdvancedPublisher, AdvancedPublisherOptions};
use wz_runtime_tokio::advanced_subscriber::{
    AdvancedSubscriber, AdvancedSubscriberOptions, DeclarationForms, EntityForm, Miss,
};
use wz_runtime_tokio::declare::LivelinessSample;
use wz_runtime_tokio::group::Member;
use wz_runtime_tokio::locality::Locality;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::qos::Priority;
use wz_runtime_tokio::query_sink::{QueryView, ReplyOut};
use wz_runtime_tokio::runtime_impl::{TokioRuntime, TokioTime};
use wz_runtime_tokio::session::{
    InterestForm, LocalDeliveryDrain, MatchingInterestHold, MatchingListener, MatchingStatus,
    PublishAliasError, PublishError, PublishOptions, QueryOptions, Queryable, QueryableOptions,
    RetractionKey, SubscribeOptions, Subscriber, TokioSession,
};
use wz_runtime_tokio::session::{
    LivelinessOptions, LivelinessSubscriber, LivelinessSubscriberOptions, LivelinessToken,
};
use wz_runtime_tokio::session_glue::{
    new_session_actions, BoxedLinkDriver, IterationEvent, LinkKind, LinkSendOutcome,
    SessionLinkActions,
};
use wz_runtime_tokio::sink::SampleView;
use wz_runtime_tokio::sync::Mutex as WzMutex;
use wz_runtime_tokio::Reliability;

// R311y498 — NO `use crate::pubsub` / `use crate::query` here, deliberately.
//
// This registry used to import the C closure TYPES and the `make_*_callback`
// constructors that turn them into wz callbacks, which pointed the dependency
// the wrong way: the ABI-neutral face/declaration model reached UP into one
// specific C ABI's closure shape. That is what made it impossible to put a
// second C ABI (§5.27 `api-compat-c`, the zenoh-c drop-in) over the same session
// model without either duplicating this file or generalising it.
//
// The dependency is inverted through the three FACTORY aliases below: the ABI
// shim hands in something that MINTS a callback, and this file never learns what
// it closes over. A factory rather than a ready-made callback because a callback
// is needed once PER FACE — every declaration is replayed onto each new face
// (`face_up`), so a single pre-built callback could not be reused.
//
// The C drop semantics are preserved exactly, and they are the delicate part:
// the factory owns whatever the shim captured (its `Arc<CClosure>`), so the last
// factory released still runs the C `drop(context)` — which is why every release
// below stays OUTSIDE the registry lock.

/// Mints one subscriber callback per face — the inverted form of what used to be
/// `make_subscriber_callback(Arc<CClosure>)`.
pub type SubscriberSink =
    Arc<dyn Fn() -> Box<dyn FnMut(&dyn SampleView) + Send + 'static> + Send + Sync>;

/// Mints one liveliness-subscriber callback per face.
pub type LivelinessSink =
    Arc<dyn Fn() -> Box<dyn for<'a> FnMut(LivelinessSample<'a>) + Send + 'static> + Send + Sync>;

/// Mints one queryable callback per face.
///
/// Unlike its three siblings this factory receives the FACE'S OWN session, and
/// that argument is load-bearing rather than convenience. A queryable handler
/// may let its query ESCAPE the dispatch (zenoh-pico's
/// `z_query_take_from_loaned`, which is how a channel-based queryable answers
/// from the application thread), and an escaped query owes two things its
/// dispatch cannot supply: the deferred replies, and the `ResponseFinal` that
/// must NOT be emitted until the last holder drops. Both are session
/// operations, so the shim needs the face's session to build them
/// ([`wz_runtime_tokio::session::Session::hold_query`]). Handing it in
/// here — rather than letting the shim keep a registry-wide session list — is
/// what keeps the escape bound to the ONE face the query arrived on; for the
/// local plane that face is the session itself, and the held query answers
/// into its own pending GET (R2953).
pub type QueryableSink = Arc<
    dyn Fn(&TokioSession) -> Box<dyn FnMut(&dyn QueryView, &mut dyn ReplyOut) + Send + 'static>
        + Send
        + Sync,
>;

/// Delivers ONE aggregated matching verdict to C.
///
/// Unlike the four sinks above this is NOT a per-face factory, and the
/// difference is the whole design of the matching plane: a C program holds one
/// matching listener and must be told about the SESSION's verdict, not about
/// each face's. See [`SharedSession::declare_matching_listener`] for why a
/// per-face pass-through would report the opposite of the truth.
pub type MatchingSink = Arc<dyn Fn(bool) + Send + Sync>;

/// A C-level matching-listener id, keying the per-face wz listeners one C
/// declaration spawned.
pub type MatchId = u64;

/// A C-level WRITE FILTER id — zenoh-pico's `_z_write_filter_t`, which a
/// publisher or querier holds for its whole life.
pub type FilterId = u64;

/// Which declarations a write filter counts: pico's
/// `_Z_WRITE_FILTER_SUBSCRIBER` for a publisher, `_Z_WRITE_FILTER_QUERYABLE`
/// for a querier (`vendor/zenoh-pico/src/net/filtering.c` @
/// `ctx->target_type = expects_queryable ? _Z_WRITE_FILTER_QUERYABLE : _Z_WRITE_FILTER_SUBSCRIBER;`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterPlane {
    /// A publisher: does any peer subscribe to the key.
    Subscribers,
    /// A querier: does any peer answer on the key. `complete_required` is a
    /// target of `ALL_COMPLETE`, which counts only queryables declared complete.
    Queryables {
        /// See the variant.
        complete_required: bool,
    },
}

/// A C-declared write filter — the SSOT replayed onto every face that comes up,
/// as every other entry here is.
struct FilterEntry {
    id: FilterId,
    plane: FilterPlane,
    /// The LITERAL the peers' declarations are matched against.
    keyexpr: String,
    /// How the peer is asked, or `None` to ask nothing: zenoh-pico sends no
    /// Interest at all from a peer with no router among its peers
    /// (`vendor/zenoh-pico/src/net/primitives.c` @ `_z_add_interest`), and
    /// learns only what peers volunteer.
    ask: Option<InterestForm>,
}

/// Why a fan-out publish could not be delivered to ANY face.
///
/// Named `FanoutError`, not `PublishError`: wz-runtime-tokio already exports a
/// per-session `PublishError` that this module imports, and two types with one
/// name in one file is the shape a later reader resolves wrongly.
///
/// R311y498 — a real type rather than `Result<_, ()>`, and not merely to satisfy
/// `clippy::result_unit_err`: this became public when the model moved out of the
/// ABI crate, and a public function whose error carries no information leaves
/// every shim mapping "something went wrong" onto its own generic code with no
/// way to do better. The variant is face-INDEPENDENT by construction — a
/// per-face failure is skipped rather than surfaced (see the fan-out docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanoutError {
    /// The payload or keyexpr exceeded the bounded codec's capacity, so no face
    /// could have carried it.
    ExceedsCapacity,
}

/// How ONE leg of a publish fan-out ended, which is all [`SharedSession`]'s fan-out needs
/// to know about a call that is otherwise a bytes publish, an SHM publish or either of
/// them on a declared key.
enum Leg {
    /// The leg ran, and this many subscriber callbacks fired.
    Delivered(usize),
    /// The leg did not run for a reason particular to its face (the link was released or
    /// is reconnecting, or the face was never told an alias): best-effort, so the surviving
    /// faces still receive the sample, as pico's multi-peer send does.
    Skipped,
    /// The leg failed for a reason that is the same on every face, such as a payload or
    /// keyexpr the bounded codec cannot carry.
    Refused,
}

impl Leg {
    /// A literal-key publish's result, classified.
    fn of_publish(result: Result<usize, PublishError>) -> Self {
        match result {
            Ok(n) => Leg::Delivered(n),
            Err(PublishError::TransportUnavailable) => Leg::Skipped,
            Err(_) => Leg::Refused,
        }
    }

    /// A declared-key publish's result, classified: an alias this face does not know is as
    /// per-face as a link that is down (it is reachable without any bug, when a face's
    /// declare failed mid-teardown).
    fn of_alias(result: Result<usize, PublishAliasError>) -> Self {
        match result {
            Ok(n) => Leg::Delivered(n),
            Err(PublishAliasError::UnknownMapping(_) | PublishAliasError::TransportUnavailable) => {
                Leg::Skipped
            }
            Err(_) => Leg::Refused,
        }
    }
}

/// How a C declaration's key goes on the WIRE, as distinct from the literal it
/// matches on locally.
///
/// The two differ whenever a declaring ABI names a key through one of its own
/// keyexpr declarations: the entity still matches the resolved literal, but the
/// peer is told `(mapping_id, suffix)`. `mapping_id == 0` is the literal
/// itself, which is what zenoh-c's session sends and the default here; the
/// pico ABI announces through the declarations zenoh-pico makes for its
/// entities (`_z_declared_keyexpr_declare` and its non-wild-prefix twin,
/// `vendor/zenoh-pico/src/session/keyexpr.c`).
///
/// Recorded on each SSOT entry, because a face that joins later replays the
/// declaration and must announce it the same way. The id stays valid there:
/// keyexpr declarations are session-global and replayed onto a new face FIRST
/// (see [`SharedSession::face_up`]).
///
/// ## What keeps the id declared
///
/// An entry that names `mapping_id` on the wire needs that declaration to
/// outlive it, and the ABI that made the declaration is the one that knows what
/// retracts it. So the key carries what it [`keeps`](Self::keeping) alive, and
/// the entry holding the key holds that. For an entity with a handle the ABI
/// usually holds its own reference too; for a BACKGROUND entity, which has no
/// handle and lives as long as the session, the entry is the only holder —
/// which is exactly the lifetime zenoh-pico gives the declaration, stored with
/// the subscription in the session's table.
///
/// Entries are always released OUTSIDE the registry lock, so what they keep may
/// re-enter the session as it drops (a keyexpr retraction does).
#[derive(Clone, Default)]
pub struct WireKey {
    /// The keyexpr declaration the wire names, `0` for none.
    pub mapping_id: u64,
    /// What follows the declared prefix, `None` when it covers the whole key.
    pub suffix: Option<String>,
    keeps: Option<Arc<dyn Send + Sync>>,
}

impl std::fmt::Debug for WireKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireKey")
            .field("mapping_id", &self.mapping_id)
            .field("suffix", &self.suffix)
            .field("keeps", &self.keeps.is_some())
            .finish()
    }
}

impl WireKey {
    /// The literal itself — no declaration.
    pub fn literal() -> Self {
        Self::default()
    }

    /// Declaration `mapping_id` followed by `suffix`.
    pub fn aliased(mapping_id: u64, suffix: Option<String>) -> Self {
        Self {
            mapping_id,
            suffix,
            keeps: None,
        }
    }

    /// This key, holding `anchor` alive for as long as a declaration made on
    /// it stays recorded.
    pub fn keeping(mut self, anchor: Arc<dyn Send + Sync>) -> Self {
        self.keeps = Some(anchor);
        self
    }

    fn is_literal(&self) -> bool {
        self.mapping_id == 0
    }
}

/// Declare a subscriber on one face in `wire`'s form.
fn declare_subscriber_on(
    session: &TokioSession,
    keyexpr: &str,
    wire: &WireKey,
    options: SubscribeOptions,
    callback: impl FnMut(&dyn SampleView) + Send + 'static,
) -> Option<Subscriber<TokioRuntime>> {
    if wire.is_literal() {
        session
            .declare_subscriber(keyexpr.to_string(), options, callback)
            .ok()
    } else {
        session
            .declare_subscriber_aliased(wire.mapping_id, wire.suffix.as_deref(), options, callback)
            .ok()
    }
}

/// Declare a queryable on one face in `wire`'s form.
fn declare_queryable_on(
    session: &TokioSession,
    keyexpr: &str,
    wire: &WireKey,
    options: QueryableOptions,
    callback: impl FnMut(&dyn QueryView, &mut dyn ReplyOut) + Send + 'static,
) -> Option<Queryable<TokioRuntime>> {
    if wire.is_literal() {
        session
            .declare_queryable(keyexpr.to_string(), options, callback)
            .ok()
    } else {
        session
            .declare_queryable_aliased(wire.mapping_id, wire.suffix.as_deref(), options, callback)
            .ok()
    }
}

/// Declare a liveliness token on one face in `wire`'s form.
fn declare_token_on(
    session: &TokioSession,
    keyexpr: &str,
    wire: &WireKey,
    options: LivelinessOptions,
) -> Option<LivelinessToken<TokioRuntime>> {
    if wire.is_literal() {
        session.declare_token(keyexpr.to_string(), options).ok()
    } else {
        session
            .declare_token_aliased(wire.mapping_id, wire.suffix.as_deref(), options)
            .ok()
    }
}

/// Declare a liveliness subscriber on one face in `wire`'s form.
fn declare_liveliness_subscriber_on(
    session: &TokioSession,
    keyexpr: &str,
    wire: &WireKey,
    options: LivelinessSubscriberOptions,
    sink: impl for<'a> FnMut(LivelinessSample<'a>) + Send + 'static,
) -> Option<LivelinessSubscriber<TokioRuntime>> {
    if wire.is_literal() {
        session
            .declare_liveliness_subscriber(keyexpr.to_string(), options, sink)
            .ok()
    } else {
        session
            .declare_liveliness_subscriber_aliased(
                wire.mapping_id,
                wire.suffix.as_deref(),
                options,
                sink,
            )
            .ok()
    }
}

/// A C-level subscription id — what a `z_owned_subscriber_t` handle carries.
/// It keys the per-face wz [`Subscriber`]s this one C subscription spawned.
pub type SubId = u64;

/// A C-level queryable id — what a `z_owned_queryable_t` handle carries. The
/// responder-side mirror of [`SubId`], keying the per-face wz [`Queryable`]s
/// one C queryable declaration spawned.
pub type QblId = u64;

/// A C-level ADVANCED publisher id — what a `ze_owned_advanced_publisher_t`
/// carries. Its own id space rather than a shared one with [`SubId`]: an
/// advanced publisher is a distinct C type with its own undeclare, so nothing
/// ever has to look it up in two maps.
pub type AdvPubId = u64;

/// A C-level ADVANCED subscriber id — what a `ze_owned_advanced_subscriber_t`
/// carries. Separate from [`SubId`] for the same reason as [`AdvPubId`].
pub type AdvSubId = u64;

/// Mints one advanced-subscriber `(on_sample, on_miss)` callback PAIR per face.
///
/// A pair rather than two sinks because an advanced subscriber is declared with
/// both at once and the two share the C program's one subscription: the sample
/// closure it moved in, and the miss closure it may install afterwards through
/// `ze_advanced_subscriber_declare_sample_miss_listener`.
#[allow(clippy::type_complexity)]
pub type AdvancedSubscriberSink = Arc<
    dyn Fn() -> (
            Box<dyn FnMut(wz_runtime_tokio::sample::Sample) + Send + 'static>,
            Box<dyn FnMut(Miss) + Send + 'static>,
        ) + Send
        + Sync,
>;

/// The face id the dial (`connect`) role occupies. A dialed session has
/// exactly one peer, so it needs no id space of its own; the accept role's
/// ids come from the accept loop's own monotonic `FaceId`.
pub const DIAL_FACE_ID: u64 = 0;

/// One connected peer: its wz session, plus the wz subscribers this face
/// carries keyed by the C subscription id that spawned them. Dropping the
/// entry drops the subscribers (each emitting its wire undeclare) and then
/// the session.
struct FaceEntry {
    session: TokioSession,
    subs: BTreeMap<SubId, Subscriber<TokioRuntime>>,
    qbls: BTreeMap<QblId, Queryable<TokioRuntime>>,
    /// Per-face liveliness TOKENS. Dropping one emits that face's UndeclToken,
    /// which is how a C `z_drop` on the owned token reaches every peer.
    tokens: BTreeMap<TokenId, LivelinessToken<TokioRuntime>>,
    /// Per-face liveliness SUBSCRIBERS, keyed by the C subscription id so they
    /// share `SubId` space with the ordinary ones — a C `z_owned_subscriber_t`
    /// is the same type either way, so its undeclare must find both.
    live_subs: BTreeMap<SubId, LivelinessSubscriber<TokioRuntime>>,
    /// Per-face matching listeners, keyed by the C listener id. Holding the
    /// handle is what keeps the watch installed; dropping it undeclares that
    /// face's half of one C listener.
    matches: BTreeMap<MatchId, MatchingListener<TokioRuntime>>,
    /// Per-face WRITE FILTER interests. Holding one is what keeps this peer
    /// answering the filter's question; dropping it sends that face's
    /// `Interest(Final)`. Only filters that ask carry an entry.
    filters: BTreeMap<FilterId, MatchingInterestHold<TokioRuntime, TokioTime>>,
    /// Per-face ADVANCED publishers. Dropping one tears down that face's `@adv`
    /// cache queryable + liveliness token (RAII inside `AdvancedPublisher`).
    adv_pubs: BTreeMap<AdvPubId, AdvancedPublisher<TokioRuntime, TokioTime>>,
    /// Per-face ADVANCED subscribers, same replay contract as `subs`.
    adv_subs: BTreeMap<AdvSubId, AdvancedSubscriber<TokioRuntime>>,
    /// R2932 — this session's copy of each C GROUP, same replay contract as
    /// `subs`. Each copy forwards what it hears into the C group's
    /// [`GroupAggregate`], which is what the C program reads.
    groups: BTreeMap<GroupId, FaceGroup>,
    /// R311y532 — the tokio runtime this face is DRIVEN by.
    ///
    /// Captured at `face_up`, which runs inside that runtime, and entered
    /// again by any declaration that spawns. R311y532 added it because the
    /// advanced publisher's heartbeat beacon was a bare `tokio::spawn`, so
    /// `AdvancedPublisher::declare` failed `NoRuntime` when called from the C
    /// APPLICATION thread — which is exactly where a C program declares. A
    /// dialed session brings its face up BEFORE `z_open` returns, so that was
    /// the ordinary path, not a corner: measured, the declare failed and was
    /// swallowed by the best-effort loop, and the publisher then put to nobody
    /// while still reporting `Z_OK`.
    ///
    /// R2366 — THAT PARTICULAR CAUSE IS GONE. The beacon names its subsystem
    /// now (`WzRuntime::Net`, `advanced_publisher.rs`) and resolves its runtime
    /// through the process partition, so it no longer asks the caller's thread
    /// for one. The guard STAYS, and deliberately: this field's contract is
    /// "any declaration that spawns", not "the beacon", and nothing has
    /// measured the rest of a declare's body to be runtime-free. What changed
    /// is that the guard is now a defence rather than the only thing holding
    /// the C entry point up.
    ///
    /// R2580 — OPTIONAL, because the local plane is about to become a
    /// `FaceEntry` too and it is constructed in `SharedSession::new`, which
    /// runs on the C APPLICATION thread where `Handle::current()` panics.
    /// `None` is therefore "this face has no captured runtime", not "the
    /// runtime is gone": the two `enter()` sites simply do not enter. That is
    /// sound for the plane on this field's own terms — its contract is "any
    /// declaration that spawns", and R2366 already moved the one measured
    /// spawner (the advanced publisher's beacon) onto the process partition,
    /// so it no longer asks the caller's thread for a runtime. A real face
    /// still captures `Some` at `face_up` and loses nothing.
    runtime: Option<tokio::runtime::Handle>,
    /// R311y296 — the signal that this face's drive loop should re-arm its wake
    /// because a `z_get` just registered a pending query with a nearer deadline
    /// than whatever the loop is currently parked on. Owned per face because
    /// each face has its own session, pending table, and drive wake.
    revised: Arc<Notify>,
}

/// A C-declared subscription — the SSOT replayed onto every face that comes
/// up. `closure` is shared (an `Arc`) across every face's callback, so the C
/// `drop(context)` fires exactly once, when the last face's subscriber and
/// this entry are both gone.
struct SubEntry {
    id: SubId,
    keyexpr: String,
    /// R311y554 — the C caller's `allowed_origin`, kept in the SSOT because a
    /// face that joins later must replay the subscription with the SAME filter
    /// the C program asked for. A per-face default here would make the
    /// declaration mean one thing on the face that was up at declare time and
    /// another on every face after it.
    allowed_origin: Locality,
    /// How the peer is told the key — see [`WireKey`].
    wire: WireKey,
    /// The key the retraction names beside the id, when the declaring ABI's
    /// reference library names one — see
    /// [`SubscribeOptions::with_retraction_naming`]. Kept for the same reason
    /// as `wire`: a face that joins later replays the subscription and must
    /// retract it the way the first face does.
    retraction: Option<RetractionKey>,
    sink: SubscriberSink,
}

/// A C-declared queryable — the responder-side SSOT, replayed onto every face
/// exactly as [`SubEntry`] is. pico does the same for the responder plane:
/// a new peer is sent the session's current queryable declarations
/// (`_z_interest_send_decl_queryable`,
/// `~/zenoh-pico/src/session/interest.c`), so a queryable declared before any
/// peer connected still answers that peer's queries.
struct QblEntry {
    id: QblId,
    keyexpr: String,
    complete: bool,
    /// R311y554 — the C caller's `allowed_origin`; kept for the same reason
    /// [`SubEntry::allowed_origin`] is.
    allowed_origin: Locality,
    /// How the peer is told the key — see [`WireKey`].
    wire: WireKey,
    /// The key the retraction names beside the id — see
    /// [`SubEntry::retraction`].
    retraction: Option<RetractionKey>,
    sink: QueryableSink,
}

/// A C-declared keyexpr alias — the third SSOT, replayed onto every face
/// exactly as [`SubEntry`] and [`QblEntry`] are.
///
/// The mapping id is allocated ONCE per C declaration and reused on every
/// face, which is pico's model rather than a shortcut: `_z_get_resource_id`
/// is a session-global counter and the same id is announced to every peer.
/// It is safe because a keyexpr mapping table is DIRECTIONAL — each peer
/// holds our ids in its own inbound table, so two peers cannot collide, and
/// a peer's own outbound ids live in a different table entirely.
struct KexprEntry {
    id: u64,
    keyexpr: String,
    /// How many holders the declaration has: `1` for one made through
    /// [`SharedSession::declare_keyexpr`], and one more for each
    /// [`SharedSession::acquire_keyexpr`] that found it. The key is retracted
    /// when [`SharedSession::release_keyexpr`] takes the count to zero, which is
    /// zenoh-pico's resource table (`_refcount` in
    /// `vendor/zenoh-pico/src/session/resource.c`).
    holders: usize,
}

/// A C-declared liveliness TOKEN — the fourth SSOT. Replayed onto every face
/// exactly as the others are, which is what makes a token declared before any
/// peer connected visible to that peer when it arrives. Upstream's
/// `z_liveliness.c` declares and then sleeps, so that is the common case, not
/// the corner one.
struct TokenEntry {
    id: TokenId,
    keyexpr: String,
    /// How the peer is told the key — see [`WireKey`].
    wire: WireKey,
    /// The declaring ABI's retraction shape, kept so a replayed token retracts
    /// the way the first one does.
    options: LivelinessOptions,
}

/// A C-declared liveliness SUBSCRIPTION — the fifth SSOT. Shares `SubId` space
/// with the ordinary subscriptions because both are handed back to C as a
/// `z_owned_subscriber_t`; `undeclare_subscriber` therefore looks in both maps.
struct LiveSubEntry {
    id: SubId,
    keyexpr: String,
    history: bool,
    /// How the peer is told the key — see [`WireKey`].
    wire: WireKey,
    sink: LivelinessSink,
}

/// A C-declared ADVANCED publisher — the sixth SSOT, replayed onto every face
/// exactly as the others are. The options are `Copy`, so the entry stores them
/// by value and every replay declares an identical publisher.
struct AdvPubEntry {
    id: AdvPubId,
    keyexpr: String,
    options: AdvancedPublisherOptions,
}

/// A host's [`DeclarationForms`] with the identity of the C advanced subscriber
/// they were supplied for — its registry id, which is what the C handle reports.
///
/// Every other question goes to the host unchanged.
struct IdentifiedForms {
    id: AdvSubId,
    host: Arc<dyn DeclarationForms>,
}

/// What the LOCAL plane is told about naming: nothing. Every answer is the
/// literal form, which is the trait's default for each.
///
/// The local plane has no wire. A key declaration exists to shorten what a peer
/// is sent, so naming the local plane's entities by one would hold a declaration
/// for an entity no peer sees — and, since that declaration is shared with the
/// wire face's entities, would hold it past the wire face's own, which is where
/// a peer sees it retracted.
struct Unnamed;

impl DeclarationForms for Unnamed {}

impl DeclarationForms for IdentifiedForms {
    fn entity_id(&self) -> Option<u32> {
        // A counter that has outrun `u32` has no spelling in the detection
        // key: the per-declaration id is the honest answer then.
        u32::try_from(self.id).ok()
    }

    fn subscriber(&self, keyexpr: &str) -> EntityForm {
        self.host.subscriber(keyexpr)
    }

    fn late_publishers(&self, keyexpr: &str) -> EntityForm {
        self.host.late_publishers(keyexpr)
    }

    fn heartbeat(&self, keyexpr: &str) -> EntityForm {
        self.host.heartbeat(keyexpr)
    }

    fn token(&self, keyexpr: &str) -> EntityForm {
        self.host.token(keyexpr)
    }

    fn retain(&self, anchor: Arc<dyn Send + Sync>) {
        self.host.retain(anchor)
    }
}

/// A C-declared ADVANCED subscriber — the seventh SSOT.
struct AdvSubEntry {
    id: AdvSubId,
    keyexpr: String,
    options: AdvancedSubscriberOptions,
    sink: AdvancedSubscriberSink,
}

/// R2932 — a C-joined GROUP, the eighth SSOT. The aggregate carries the group
/// id and the local member, so a replay joins the same group as the same
/// member; `priority` is the one join knob the aggregate does not need.
struct GroupEntry {
    id: GroupId,
    agg: Arc<GroupAggregate>,
    priority: Priority,
}

/// A C-level liveliness token id, keying the per-face wz tokens one C
/// declaration spawned.
pub type TokenId = u64;

/// The cross-face aggregate behind ONE C matching listener.
///
/// `faces` is the set of face ids whose own wz listener currently reports a
/// match; the session verdict is `!faces.is_empty()`. `last` is the verdict
/// already DELIVERED to C, so a change that does not move the aggregate stays
/// silent — pico's transition semantics, applied at the level the C program
/// observes.
///
/// It carries its own mutex rather than living in [`Inner`] on purpose. The
/// per-face wz callback runs on the drive thread from
/// `Session::drain_deferred_fires`, and it must both update this state and
/// invoke the C closure; routing that through the registry lock would put a C
/// callback under the lock a re-entrant `z_declare_*` needs, which is the
/// deadlock the whole file's snapshot-then-call discipline exists to avoid.
///
/// R311y528 — this mutex is held ACROSS the C call, and the earlier "held only
/// across the set update, never across the C call" discipline was the bug. See
/// [`deliver_matching_flip`] for why it has to be, and the MATCHING LOCK ORDER
/// rule in that same doc comment for the invariant that makes it safe.
/// R311y535 — the aggregate OWNS the C sink, and that is what makes
/// `z_undeclare_matching_listener` free the C context SYNCHRONOUSLY.
///
/// Until this round the sink was an `Arc` CLONED into every consumer: the
/// [`MatchEntry`], each per-face callback ([`face_matching_callback`]), and
/// [`SharedSession::face_down`]'s purge snapshot. The C `drop(context)` then ran
/// whenever the LAST of those clones happened to fall, which is not a moment any
/// caller controls. Measured: `z_undeclare_matching_listener` returned with the
/// context still alive in 1 run of 21, because a concurrent `face_down` on the
/// drive thread was mid-purge and still holding a clone; the drop landed ~5 ms
/// later on that thread. pico frees the context inside its undeclare, so this was
/// a CONTRACT divergence, not merely a flaky test.
///
/// With one owner there are no clones to outlive the undeclare, and the mutex
/// that already serialises C delivery (see [`deliver_matching_flip`]) becomes the
/// exclusion that makes the release deterministic: undeclare takes the lock,
/// which cannot be granted while a delivery is in flight, `take`s the sink, and
/// drops it after releasing. Any delivery that arrives afterwards finds `None`
/// and is silently correct — a listener that has been undeclared has no C to
/// notify.
struct MatchAggregate {
    faces: BTreeSet<u64>,
    last: bool,
    /// `None` once retired by `undeclare_matching_listener`.
    sink: Option<MatchingSink>,
}

impl MatchAggregate {
    fn new(sink: MatchingSink) -> Self {
        Self {
            faces: BTreeSet::new(),
            last: false,
            sink: Some(sink),
        }
    }
}

impl MatchAggregate {
    /// Record face `id`'s verdict and return `Some(new_aggregate)` when the
    /// SESSION verdict changed, `None` when it did not.
    fn apply(&mut self, id: u64, matching: bool) -> Option<bool> {
        if matching {
            self.faces.insert(id);
        } else {
            self.faces.remove(&id);
        }
        self.settle()
    }

    /// Drop face `id` entirely — a face that went DOWN can no longer be the
    /// reason C believes a subscriber exists. Same flip-only return.
    fn forget(&mut self, id: u64) -> Option<bool> {
        self.faces.remove(&id);
        self.settle()
    }

    fn settle(&mut self) -> Option<bool> {
        let now = !self.faces.is_empty();
        if now == self.last {
            return None;
        }
        self.last = now;
        Some(now)
    }
}

/// A C-declared matching listener — the SIXTH SSOT, replayed onto every face
/// exactly as [`SubEntry`] and [`QblEntry`] are.
///
/// `state` is shared with every per-face callback this entry spawned; the entry
/// holds the per-face wz listener handles inside [`FaceEntry::matches`].
struct MatchEntry {
    id: MatchId,
    keyexpr: String,
    /// R311y535 — the C sink is NOT here. It lives inside the
    /// [`MatchAggregate`] behind `state`, so exactly one place owns it and
    /// `undeclare_matching_listener` can retire it deterministically.
    state: Arc<StdMutex<MatchAggregate>>,
    scope: MatchScope,
}

/// Which remote declaration a C matching listener watches.
///
/// R311y528 — carried on the SSOT entry rather than passed at the declare call
/// only, because `face_up` REPLAYS every entry onto each new face and has to
/// install the same kind of watch the original declare did. A scope that lived
/// only at the call site would silently degrade every replayed querier watch
/// into a publisher one, and the failure would appear as "matching works until
/// a peer reconnects".
#[derive(Clone, Copy, PartialEq, Eq)]
enum MatchScope {
    /// pico `z_publisher_*_matching_*`: watch remote SUBSCRIBERS.
    RemoteSubscribers,
    /// pico `z_querier_*_matching_*`: watch remote QUERYABLES.
    RemoteQueryables,
}

impl MatchScope {
    /// Install this scope's per-face watch on `session` for `keyexpr`.
    ///
    /// One function rather than a match at each of the two call sites (declare
    /// and `face_up` replay) for the same reason `face_matching_callback` is one
    /// function: the two must not drift.
    fn install(
        self,
        session: &TokioSession,
        keyexpr: &str,
        callback: impl FnMut(MatchingStatus) + Send + 'static,
    ) -> Option<MatchingListener<TokioRuntime>> {
        match self {
            MatchScope::RemoteSubscribers => session
                .declare_publisher(keyexpr.to_owned(), PublishOptions::put())
                .declare_matching_listener(callback)
                .ok(),
            MatchScope::RemoteQueryables => session
                .declare_querier(keyexpr.to_owned(), QueryOptions::default())
                .declare_matching_listener(callback)
                .ok(),
        }
    }
}

/// Fold `update` into one entry's aggregate and, when the SESSION verdict
/// flipped, deliver it to C — **both under the same aggregate mutex**.
///
/// ## MATCHING LOCK ORDER — the one rule this plane rests on
///
/// **A [`MatchAggregate`] mutex is never acquired while the registry lock is
/// held.** Every path that needs both snapshots what it needs out of the
/// registry first: `declare_matching_listener` phase 2 drops its guard before
/// installing, and [`SharedSession::face_down`] collects `(state, sink)` pairs
/// and releases before folding. So the only order that exists is
/// `aggregate -> registry` — the one a C callback re-entering `z_declare_*` from
/// inside this function takes — and no thread takes it backwards.
///
/// Reaching an aggregate any other way is what a future call site would have to
/// do to break this, so a new one belongs here rather than open-coding the fold.
/// The two existing callers are [`face_matching_callback`] and
/// [`SharedSession::face_down`].
///
/// ## Why the C call is inside the lock (R311y528 — this was a real defect)
///
/// Two threads reach one entry's `sink`: the drive thread, through
/// [`face_matching_callback`] and through [`SharedSession::face_down`]'s purge;
/// and the C application thread, through `declare_matching_listener` phase 2,
/// where an already-matching per-face registration fires `true` synchronously.
/// Phase 1 publishes the [`MatchEntry`] under the registry lock BEFORE phase 2
/// installs, so `face_down` can already see an entry whose C-thread registration
/// is still running. A peer dropping in that window produced two concurrent
/// `call(context)` on one C context — exactly the data race pico's
/// single-threaded-callback contract forbids, and the same class R311y288 fixed
/// on the publish plane.
///
/// Releasing the mutex before `sink` (what this code did until R311y528) also
/// lost ORDERING even when the calls did not overlap: two threads could compute
/// `true` then `false` and deliver them in the opposite order, leaving C with a
/// verdict the aggregate disagrees with. Folding and delivering under one
/// acquisition makes the pair atomic, so C observes exactly the sequence of
/// flips the aggregate computed.
///
/// ## Why holding it is deadlock-free
///
/// By the lock order above: no caller holds the registry lock when it gets
/// here, so a C callback that re-enters the session — `z_put`,
/// `z_declare_subscriber`, `z_publisher_get_matching_status`, even
/// `z_publisher_declare_matching_listener` on the same keyexpr — takes the
/// registry lock with only this aggregate held, and nothing takes them the other
/// way round. A re-entrant declare allocates a NEW entry with a NEW aggregate,
/// so it cannot block on this one; `z_undeclare_matching_listener` for this very
/// id takes the registry lock, removes the entry and calls
/// `MatchingListener::undeclare`, which retracts the watch without firing
/// (`wz-runtime-tokio/src/session/matching_listener.rs`), so it never re-enters
/// this function. The `state` and `sink` handles are `Arc` clones held by the
/// caller, so that undeclare cannot free what this call is using.
///
/// ## R311y535 — the sink comes from the aggregate, and a re-entrant undeclare
///
/// The `sink` parameter is gone: the aggregate owns it (see [`MatchAggregate`]),
/// so a flip delivers through `agg.sink` under the acquisition it already held.
/// A retired listener has `None` there and delivers nothing.
///
/// [`IN_MATCHING_DELIVERY`] is set around the C call because
/// `undeclare_matching_listener` now WAITS on this mutex to retire the sink, and
/// a C callback that undeclares its own listener from inside the call would
/// otherwise wait on the mutex its own frame holds. The flag lets that one case
/// fall back to the pre-R311y535 behaviour — release by `Arc` drop, whenever the
/// frame unwinds — which is the only thing a caller inside its own context can
/// safely be given.
fn deliver_matching_flip(
    state: &StdMutex<MatchAggregate>,
    update: impl FnOnce(&mut MatchAggregate) -> Option<bool>,
) {
    let mut agg = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(now) = update(&mut agg) {
        if let Some(sink) = agg.sink.as_ref() {
            let _guard = MatchingDeliveryGuard::enter();
            sink(now);
        }
    }
    // `agg` is dropped HERE, after the C call — see the doc comment.
}

/// Take the C sink out of an aggregate so the CALLER can drop it — the
/// mechanism behind `z_undeclare_matching_listener`'s synchronous release
/// (R311y535).
///
/// Acquiring the aggregate mutex is the whole point and not incidental
/// bookkeeping: [`deliver_matching_flip`] holds that mutex ACROSS its C call, so
/// this cannot be granted while any thread is inside the callback. When it
/// returns `Some`, no thread is using the context and no thread can start,
/// because a later delivery finds `None`.
///
/// It returns the sink instead of dropping it so the drop happens OUTSIDE the
/// guard: the C `drop(context)` may re-enter the session, and this file's
/// discipline is that no C code runs holding a lock it might need.
///
/// `None` means there is nothing for the caller to free — either the listener
/// was already retired, or THIS THREAD is inside a matching callback, where
/// waiting on the mutex would be waiting on its own frame. In that one case the
/// sink stays put and falls with the entry's last `Arc`, which is all a caller
/// undeclaring from inside its own context can be given.
fn retire_matching_sink(state: &StdMutex<MatchAggregate>) -> Option<MatchingSink> {
    if MatchingDeliveryGuard::active() {
        return None;
    }
    let mut agg = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    agg.sink.take()
}

thread_local! {
    /// Depth of [`deliver_matching_flip`] C calls on THIS thread — see that
    /// function's doc for why `undeclare_matching_listener` consults it.
    static IN_MATCHING_DELIVERY: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// RAII depth counter for [`IN_MATCHING_DELIVERY`]. A counter rather than a bool
/// because a C callback may re-enter the session and reach a SECOND delivery
/// (a different listener's aggregate), and a bool would clear the outer frame's
/// mark when the inner one returned.
struct MatchingDeliveryGuard;

impl MatchingDeliveryGuard {
    fn enter() -> Self {
        IN_MATCHING_DELIVERY.with(|d| d.set(d.get() + 1));
        Self
    }

    /// Whether this thread is inside a C matching callback right now.
    fn active() -> bool {
        IN_MATCHING_DELIVERY.with(|d| d.get()) > 0
    }
}

impl Drop for MatchingDeliveryGuard {
    fn drop(&mut self) {
        IN_MATCHING_DELIVERY.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

/// The per-face callback one [`MatchEntry`] installs on face `face_id`: fold
/// this face's verdict into the aggregate and deliver to C only on a SESSION
/// flip.
///
/// One function rather than the closure written twice, because the two call
/// sites are the declare path and the `face_up` replay path and they must not
/// drift — a replay that folded differently from the original would make the
/// verdict depend on when a peer happened to connect.
///
/// Runs from `Session::drain_deferred_fires`, which is called with the observer
/// lock released and — per the lock order in [`deliver_matching_flip`] — never with the registry
/// lock held.
fn face_matching_callback(
    face_id: u64,
    entry: &MatchEntry,
) -> impl FnMut(MatchingStatus) + Send + 'static {
    // R311y535 — the STATE only. This closure used to carry a sink clone too,
    // and since it lives inside the per-face `FaceEntry`, a face removed by
    // `face_down` kept the C context alive until that entry was dropped —
    // outliving an `z_undeclare_matching_listener` that ran in between.
    let state = entry.state.clone();
    move |status| {
        deliver_matching_flip(&state, |agg| agg.apply(face_id, status.matching));
    }
}

/// The link driver under the [face-independent local plane](SharedSession::local).
///
/// The plane is a real unicast [`TokioSession`] because the query / queryable
/// surface is unicast-typestate-only, and a unicast session is built from a
/// [`SessionLinkActions`] bundle, which is built from a link driver. Nothing
/// drives this one's FSM and nobody reads what it writes, so every method is
/// the honest no-op: the plane's whole job is the LOOPBACK half of `publish` /
/// `query`, which never reaches the wire.
///
/// The bytes handed to `send_blocking` are the declares the plane emits for its
/// own registrations (a `Declare(DeclSubscriber)` per local subscriber, and the
/// matching undeclares). Discarding them is correct rather than lossy: the WIRE
/// announcement of a C declaration is the FACES' job — every face replays the
/// whole SSOT in [`SharedSession::face_up`] — and announcing the same
/// subscription twice from one session is what would be wrong.
struct InertLinkDriver;

impl BoxedLinkDriver for InertLinkDriver {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        LinkSendOutcome::Sent
    }
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

/// R2259 (open-debt item 593) — one PHYSICAL link of an established face, as
/// zenoh-c's `z_owned_link_t` reports it.
///
/// Every field is READ off the face, never defaulted into a plausible-looking
/// value: `interfaces` keeps `LinkSubject`'s three-state answer (resolved,
/// resolved-empty, undetermined) rather than flattening a failed lookup to an
/// empty set the way upstream does, and `protocol` is `None` for a driver that
/// cannot name itself. The C accessors are what decide how to spell "unknown"
/// at the ABI, and they can only do that honestly if the unknown survives here.
#[derive(Debug, Clone)]
pub struct LinkSnapshot {
    /// This end's locator (`z_link_src`).
    pub src: String,
    /// The peer end's locator (`z_link_dst`).
    pub dst: String,
    /// The KIND of link, or `None` when the driver cannot say (`z_link_is_streamed`,
    /// `z_link_reliability`).
    ///
    /// R2794 (open-debt item 814) — the kind, not the protocol a rule sees. This
    /// was `protocol: Option<InterceptorLink>` copied off the ACL subject, and the
    /// two accessors above were answered from it. That was right only while one
    /// enum held both answers: the datagram link is `quic` to a rule and still
    /// unstreamed and best-effort to zenoh-c, and only its kind can say so.
    pub kind: Option<LinkKind>,
    /// The NICs this link's local address sits on (`z_link_interfaces`), with
    /// `None` meaning "could not be determined" — see `LinkSubject`.
    pub interfaces: Option<Vec<String>>,
    /// The negotiated outbound frame budget (`z_link_mtu`), clamped into the
    /// `uint16_t` upstream returns.
    pub mtu: u16,
}

/// R2259 (open-debt item 593) — one ESTABLISHED face as zenoh-c's
/// `z_owned_transport_t` reports it, plus the links under it.
///
/// The transport half is exactly the 19 bytes `zenoh_opaque.h` gives
/// `z_owned_transport_t` — zid, whatami, and the two negotiated booleans — which
/// is why `zc_internal_create_transport` can construct one from four scalars and
/// why the C type is a VALUE rather than a handle. The links are carried
/// alongside rather than inside for the same reason upstream separates them: a
/// transport outlives any one of its links.
#[derive(Debug, Clone)]
pub struct FaceSnapshot {
    /// The peer's zid (`z_transport_zid`, `z_link_zid`).
    pub zid: [u8; 16],
    /// The peer's role as the raw 2-bit INIT wire form (`z_transport_whatami`).
    pub whatami: u8,
    /// Whether QoS was negotiated on this transport (`z_transport_is_qos`).
    pub is_qos: bool,
    /// Whether this is a multicast transport (`z_transport_is_multicast`).
    ///
    /// Always `false` for a face: wz's C surface establishes UNICAST transports
    /// only, and the honest report for one is that it is not multicast. The
    /// field exists because `zc_internal_create_transport` can build a
    /// transport value that IS multicast — upstream's own test door — and that
    /// value must round-trip through the same accessor.
    pub is_multicast: bool,
    /// Whether SHM was negotiated on this transport (`z_transport_is_shm`).
    ///
    /// Reported on every build, unlike the C accessor that consumes it: upstream
    /// only widens `z_owned_transport_t` to twenty bytes under
    /// `Z_FEATURE_SHARED_MEMORY`, but the FACT is one wz can state either way,
    /// and gating the field would make the ABI's shape decide what the session
    /// is allowed to know.
    pub is_shm: bool,
    /// This face's physical links, one entry each — see
    /// [`SessionLinkActions::link_endpoints_all`].
    pub links: Vec<LinkSnapshot>,
}

impl FaceSnapshot {
    /// Snapshot one face's session, or `None` when its INIT has not populated
    /// the identity slots yet.
    ///
    /// The `None` is the half-open case [`SharedSession::peer_identities`]
    /// skips, and it is a REFUSAL rather than a default: a transport reported
    /// with a zero zid is a peer the C application can neither match nor dial.
    fn of(session: &TokioSession) -> Option<Self> {
        let actions = session.actions();
        let peer = actions.peer_zid()?;
        let whatami = actions.peer_whatami_wire()?;
        let mut zid = [0u8; 16];
        let n = peer.len().min(16);
        zid[..n].copy_from_slice(&peer[..n]);
        let subject = actions.link_subject().cloned();
        let mtu = u16::try_from(actions.negotiated_batch_mtu()).unwrap_or(u16::MAX);
        let links = actions
            .link_endpoints_all()
            .into_iter()
            .map(|e| LinkSnapshot {
                src: e.src,
                dst: e.dst,
                kind: subject.as_ref().and_then(|s| s.kind),
                interfaces: subject.as_ref().and_then(|s| s.interfaces.clone()),
                mtu,
            })
            .collect();
        // A build without `transport-qos` never negotiates the ext, so `false`
        // is the MEASURED answer here rather than a stand-in: there is no
        // conduit split to report. `is_qos` itself is gated, so this is also the
        // only spelling that compiles in both configurations.
        #[cfg(feature = "transport-qos")]
        let is_qos = actions.is_qos();
        #[cfg(not(feature = "transport-qos"))]
        let is_qos = false;
        // Same shape, same reason, for the SHM ext.
        #[cfg(feature = "transport-shm")]
        let is_shm = actions.is_shm();
        #[cfg(not(feature = "transport-shm"))]
        let is_shm = false;
        Some(Self {
            zid,
            whatami,
            is_qos,
            is_multicast: false,
            is_shm,
            links,
        })
    }
}

/// R2259 (open-debt item 593) — which way a face moved, the input to the `kind`
/// a `z_link_event_t` / `z_transport_event_t` carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaceEventKind {
    /// The face reached Established (`Z_SAMPLE_KIND_PUT`).
    Up,
    /// The face left the live set (`Z_SAMPLE_KIND_DELETE`).
    Down,
}

/// R2259 (open-debt item 593) — a face-lifecycle observer, as
/// [`SharedSession::watch_faces`] holds it.
///
/// `Arc` rather than `Box` because `SharedSession::fire_face_event` clones the
/// sink list OUT of the registry lock before invoking any of them; see that
/// method for why that is load-bearing rather than tidy.
pub type FaceEventSink = Arc<dyn Fn(FaceEventKind, &FaceSnapshot) + Send + Sync>;

#[derive(Default)]
struct Inner {
    faces: BTreeMap<u64, FaceEntry>,
    /// R2259 (open-debt item 593) — the face-lifecycle observers the C
    /// link/transport event planes register, keyed by the id
    /// [`SharedSession::watch_faces`] hands back.
    ///
    /// A `Vec` of `(id, sink)` rather than a map because the population is a
    /// handful of listeners iterated on every face transition and looked up only
    /// when one is undeclared: iteration order IS the delivery order, and a
    /// `BTreeMap` would silently make that "by id" rather than "by declaration",
    /// which is not a promise upstream makes but is one a test would come to
    /// depend on.
    face_watchers: Vec<(u64, FaceEventSink)>,
    /// The allocator behind [`SharedSession::watch_faces`]. Its own space, for
    /// the reason `next_entity_id` has one: an id shared with another plane
    /// makes two unrelated undeclares able to collide.
    next_face_watcher_id: u64,
    /// The local plane's own handles for the SSOT declarations, keyed by the
    /// same C-level ids the per-face maps use.
    ///
    /// Held here rather than beside the plane itself so the whole
    /// declare / undeclare discipline — mutate under the registry lock, drop the
    /// released handles OUTSIDE it — is the one discipline the faces already
    /// follow. A `Subscriber` / `Queryable` handle owns an `Arc<CClosure>`, so
    /// releasing the last one runs the C `drop(context)`.
    /// R2580 — the local plane AS A FACE, which is the repair for a defect
    /// this field's two predecessors (`local_subs`, `local_qbls`) WERE.
    ///
    /// MEASURED: `FaceEntry` carries eight declaration slots and the plane used
    /// to carry two, so six planes — liveliness tokens, liveliness subscribers,
    /// matching listeners, advanced publishers, advanced subscribers — had
    /// nowhere to put a local handle and every one of them simply skipped the
    /// plane. That is eleven wrong call sites from ONE modelling decision, not
    /// eleven oversights: a declaration site had to REMEMBER the plane, and
    /// most did not. Giving the plane a face's shape means it has every slot by
    /// construction and there is nothing left to forget.
    ///
    /// It is NOT a member of `faces`, and that is the other half of the repair:
    /// the wire-subject readers (`face_snapshots`, `peer_identities`, the three
    /// `batch_*` fans) keep walking `faces` and need no exclusion clause. The
    /// narrow meaning stays the default exactly where it is the correct one,
    /// instead of becoming a list that rots.
    ///
    /// `Option` only because `Inner` derives `Default` and a `TokioSession` has
    /// no default; [`SharedSession::new`] populates it immediately and nothing
    /// clears it. The `None` never reaches a caller — every declaration goes
    /// through [`Inner::declaration_targets`], which is the one place that
    /// unwraps it.
    local_face: Option<FaceEntry>,
    subs: Vec<SubEntry>,
    next_sub_id: SubId,
    /// R311y559 — the session-scope ENTITY id counter the C ABIs' `z_*_id`
    /// accessors report, for the handles that are NOT registered in a
    /// per-kind map.
    ///
    /// Subscribers and queryables already have ids (`SubId` / `QblId`) because
    /// the registry keys their per-face replicas on them. Publishers and
    /// queriers have no such map — they are local handles that fan out through
    /// the session — yet zenoh assigns every declared entity a global
    /// `(zid, eid)` and `z_publisher_id` / `z_querier_id` hand it back. This is
    /// that allocator. A SEPARATE space from `next_sub_id` on purpose: the two
    /// number different things, and sharing one counter would make an entity's
    /// id depend on how many subscribers happened to be declared first, which
    /// is exactly the sort of coupling that reads as stable until it is not.
    next_entity_id: u64,
    qbls: Vec<QblEntry>,
    next_qbl_id: QblId,
    tokens: Vec<TokenEntry>,
    next_token_id: TokenId,
    live_subs: Vec<LiveSubEntry>,
    matches: Vec<MatchEntry>,
    next_match_id: MatchId,
    filters: Vec<FilterEntry>,
    next_filter_id: FilterId,
    adv_pubs: Vec<AdvPubEntry>,
    next_adv_pub_id: AdvPubId,
    adv_subs: Vec<AdvSubEntry>,
    next_adv_sub_id: AdvSubId,
    groups: Vec<GroupEntry>,
    next_group_id: GroupId,
    kexprs: Vec<KexprEntry>,
    /// Next alias id to hand out. Starts at 0 and is PRE-incremented, so the
    /// first id issued is 1: zero is reserved on the wire
    /// (`SendDeclareError::ReservedMappingIdZero`) and is also this crate's
    /// "not declared" discriminant in `z_loaned_keyexpr_t::_mapping`.
    next_kexpr_id: u64,
}

impl Inner {
    /// R2580 — EVERY SESSION A DECLARATION REACHES: the live faces, and the
    /// local plane. The one answer to that question, so no declaration site
    /// decides it for itself.
    ///
    /// The eleven sites this replaces each wrote `faces.values_mut()` and six
    /// of them were wrong, because the plane held no slot for what they were
    /// declaring. Now the plane is a `FaceEntry` with all eight slots and this
    /// is the iterator they walk, so being correct costs a site nothing and
    /// being wrong is no longer expressible.
    ///
    /// ⚠ NOT the iterator for a question about the WIRE. `face_snapshots`,
    /// `peer_identities` and the three `batch_*` fans keep `self.faces`: a
    /// local plane is not a transport, has no peer identity, and has no batch
    /// window. Those five are correct as they stand and this method is not for
    /// them.
    fn declaration_targets(&mut self) -> impl Iterator<Item = &mut FaceEntry> {
        self.faces.values_mut().chain(self.local_face.iter_mut())
    }

    /// The shared-reference twin of [`Self::declaration_targets`], for the fans
    /// that USE a declaration rather than install one — the advanced publisher's
    /// `put` and `delete`, which reach handles they do not mutate.
    ///
    /// Two methods because `&` and `&mut` cannot be one in Rust, not because
    /// they answer different questions: they must always name the same set, and
    /// a `put` that skipped the plane would publish to every peer while the
    /// session's own advanced subscriber heard nothing.
    fn declaration_targets_ref(&self) -> impl Iterator<Item = &FaceEntry> {
        self.faces.values().chain(self.local_face.iter())
    }

    /// [`Self::declaration_targets`] as values a declaration can be made on
    /// AFTER the registry lock is released: each target's key, its session and
    /// the runtime that drives it.
    ///
    /// For a declaration that must not run under the lock — one that calls back
    /// into a host which takes the lock itself (see
    /// [`SharedSession::declare_advanced_subscriber`]). The key is how the
    /// finished declaration finds its way back
    /// ([`SharedSession::attach_advanced_subscriber`]).
    fn declaration_target_handles(
        &self,
    ) -> Vec<(
        DeclarationTarget,
        TokioSession,
        Option<tokio::runtime::Handle>,
    )> {
        self.faces
            .iter()
            .map(|(id, face)| {
                (
                    DeclarationTarget::Face(*id),
                    face.session.clone(),
                    face.runtime.clone(),
                )
            })
            .chain(self.local_face.iter().map(|face| {
                (
                    DeclarationTarget::Local,
                    face.session.clone(),
                    face.runtime.clone(),
                )
            }))
            .collect()
    }
}

/// Where a declaration made outside the registry lock is filed when it is done:
/// a live face by id, or the session's own local plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeclarationTarget {
    Face(u64),
    Local,
}

/// The registry behind a `z_owned_session_t`, shared between the C thread
/// (which declares and publishes) and the drive thread (which brings faces up
/// and dispatches inbound samples).
pub struct SharedSession {
    inner: StdMutex<Inner>,
    clock: TokioTime,
    /// This session's zid — see [`SharedSession::zid`].
    zid: [u8; 16],
    /// R311y557 — THE FACE-INDEPENDENT LOCAL PLANE.
    ///
    /// One session-scope [`TokioSession`] over an [`InertLinkDriver`], carrying
    /// every C declaration a second time and serving the LOOPBACK half of
    /// `publish` / `query` alone. The faces carry the wire half and nothing
    /// else: every fan-out below hands each face [`Locality::Remote`] and the
    /// plane [`Locality::SessionLocal`], so the two halves are disjoint by
    /// construction rather than by a first-face convention.
    ///
    /// ## What it closes
    ///
    /// Before it, in-process delivery was a property of the FIRST FACE, so a
    /// session with no peer delivered nothing to its own subscriber — a
    /// divergence from zenoh-c, whose subscriber table is session-scope, and one
    /// reachable as an ordinary race rather than only as a configuration: a
    /// `z_open(listen=..)` publishes before its first peer connects, and a
    /// client's `z_put` can beat its own dial. `publish_all_delivers_locally_with_no_face`
    /// is the measurement; it asserted the OPPOSITE until this landed.
    ///
    /// ## Why it also removes a hazard the first-face rule carried
    ///
    /// The fan split had to reason about WHICH face takes the single local leg
    /// (`publish_aliased_all` needed a face owning the mapping; `issue_get`
    /// needed a `continue` arm for a local-only get whose leg was already
    /// placed). With a dedicated plane the local leg has exactly one home and
    /// none of those arms exists, so a C subscription cannot be delivered to
    /// twice by two faces however the face set moves under it.
    ///
    /// ## Who drains it
    ///
    /// The plane is [`LocalDeliveryDrain::DriveTask`] like every face session,
    /// and the `unsafe impl Sync` premise behind every C closure on these ABIs —
    /// the C application thread never invokes it — is kept by draining it from
    /// the drive role's own `select!` arm ([`Self::drive_local_plane`]), which
    /// is the SAME task the faces dispatch on. A `tokio::spawn`ed drain would
    /// have satisfied "not the C thread" and still broken the premise, because
    /// the per-session runtime has two workers.
    local: TokioSession,
    /// The local plane's re-arm signal — the twin of [`FaceEntry::revised`].
    ///
    /// Staging a fire does not make a drive loop iterate (R311y555 measured the
    /// cost of assuming it does: every in-process delivery rode the ~3333 ms
    /// keepalive tick). Every path that stages onto the plane notifies this, and
    /// [`Self::drive_local_plane`] is what waits on it.
    local_wake: Arc<Notify>,
}

impl SharedSession {
    /// `zid` is this session's own 16-byte identity — the same one the faces put
    /// on the wire. The local plane takes it so its loopback samples carry the
    /// identity the session actually has, which is what the subscriber
    /// registry's self-echo guard reads.
    /// This session's own zid, right-zero-padded to the wire's 16 bytes
    /// (R311y559).
    ///
    /// The `(zid, eid)` global id every `z_*_id` accessor reports needs the zid
    /// half, and the handles that answer those accessors hold only the shared
    /// registry — not the `SessionState` where the zid was minted. Recorded
    /// here rather than threaded through each handle so the two readers cannot
    /// disagree: `SessionState::zid` and this are the SAME bytes, both taken
    /// from the one choice `open_blocking` makes — a fresh sixteen bytes, or a
    /// configured id zero-padded to sixteen (`drive::ConfiguredZid`).
    pub fn zid(&self) -> [u8; 16] {
        self.zid
    }

    /// R311y820 — FALLIBLE, because the params builder it shares with both
    /// drive roles now draws the cookie signing key from OS entropy. The local
    /// plane never handshakes, so this key never reaches a wire cookie — but it
    /// takes the same path anyway rather than keeping a literal here with an
    /// "it is inert" note, because that note is exactly the shape that let the
    /// literal survive at four sites until R311y820 counted them.
    pub fn new(
        clock: TokioTime,
        zid: Vec<u8>,
    ) -> Result<Self, wz_runtime_tokio::session_glue::EntropyUnavailable> {
        let driver: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(InertLinkDriver);
        // `WhatAmI::Peer`: the plane never handshakes, so the role is inert on
        // the wire, and Peer is what a session that both publishes and answers
        // queries is. The params otherwise come from the one builder both drive
        // roles use, so the plane cannot drift from them.
        let mut zid_bytes = [0u8; 16];
        let n = zid.len().min(16);
        zid_bytes[..n].copy_from_slice(&zid[..n]);
        // The plane's driver is inert and queues nothing onto a link, so no
        // transmit model reaches it; zenoh's default is passed as the neutral
        // value rather than the calling ABI's.
        let params = crate::drive::init_params(
            wz_runtime_tokio::session_glue::WhatAmI::Peer,
            zid,
            wz_runtime_tokio::session_glue::TxQueueConf::default(),
        )?;
        let actions = new_session_actions(driver, params, clock);
        let observer = Arc::new(WzMutex::new(ApplicationLayerObserver::new()));
        // R2932 — the plane's wake is handed to the plane itself, so a loopback
        // publish this file does not make (a group's keep-alive beacon, on its
        // own task) still wakes `drive_local_plane`. The explicit notifies after
        // this file's own publishes stay: they are the same permit, and
        // `notify_one` stores at most one.
        let local_wake = Arc::new(Notify::new());
        let local = TokioSession::new(actions, observer, Arc::new(clock))
            .with_local_delivery_drain(LocalDeliveryDrain::DriveTask)
            .with_local_stage_wake(Arc::clone(&local_wake));
        // R2580 — the plane's face-shaped entry. Its `session` is a CLONE of
        // the field above rather than a move: the two name one session, and the
        // field stays where it is because `local_session` / `drive_local_plane`
        // reach it OUTSIDE the registry lock, which is a locking discipline this
        // repair had no business changing.
        // Struct-update rather than `default()` then assign: clippy's
        // `field_reassign_with_default` refuses the latter, and gate 6 is where
        // it surfaced — `cargo check` and `cargo test` both passed, because
        // neither runs clippy.
        let inner = Inner {
            local_face: Some(FaceEntry {
                session: local.clone(),
                subs: BTreeMap::new(),
                qbls: BTreeMap::new(),
                tokens: BTreeMap::new(),
                live_subs: BTreeMap::new(),
                matches: BTreeMap::new(),
                // The plane asks nobody: a write filter counts what PEERS
                // declare, and the plane's link is inert.
                filters: BTreeMap::new(),
                adv_pubs: BTreeMap::new(),
                adv_subs: BTreeMap::new(),
                groups: BTreeMap::new(),
                // `None`: this constructor runs on the C application thread,
                // where `Handle::current()` panics. See the field.
                runtime: None,
                // The plane's re-arm signal is `local_wake`, held beside the
                // session for the same outside-the-lock reason; this one is
                // never notified.
                revised: Arc::new(Notify::new()),
            }),
            ..Default::default()
        };
        Ok(Self {
            zid: zid_bytes,
            inner: StdMutex::new(inner),
            clock,
            local,
            local_wake,
        })
    }

    /// The local plane's session — what the ABI shims issue the LOCAL leg of a
    /// `z_get` on (the publish legs stay inside this file).
    pub fn local_session(&self) -> &TokioSession {
        &self.local
    }

    /// Wake the local plane's drain. Call after staging anything on it.
    pub fn wake_local_plane(&self) {
        self.local_wake.notify_one();
    }

    /// Run the local plane's staged fires, returning how many ran.
    ///
    /// Public because it is both the drive loop's step and the only way a test
    /// without a drive thread can observe a delivery: `publish` returns the
    /// number of subscribers MATCHED, which is a different claim from the
    /// callback having run (R311y555's lesson, one level down).
    pub fn drain_local_plane(&self) -> usize {
        self.local.drain_deferred_fires()
    }

    /// The drive roles' `select!` arm for the local plane: drain, then sleep on
    /// the wake. Never returns.
    ///
    /// Draining BEFORE the first await is deliberate — a `z_put` that lands
    /// between `z_open` returning and this arm being first polled has already
    /// staged, and its `notify_one` permit is stored either way, so neither
    /// order can lose a delivery; draining first makes the very first poll
    /// deliver instead of waiting for a second event.
    pub async fn drive_local_plane(&self) {
        loop {
            self.drain_local_plane();
            self.local_wake.notified().await;
        }
    }

    /// The registry lock, poison-tolerant. A C callback that panics is caught
    /// at the FFI boundary (`crate::ffi`), so poisoning should not happen; if
    /// it somehow does, the registry is still structurally sound (a panic
    /// cannot leave a `BTreeMap` torn), and refusing to serve the session
    /// afterwards would be a worse failure than continuing.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A face reached Established: build its session and replay the whole
    /// declaration SSOT — subscriptions AND queryables — onto it (pico's
    /// push-declarations-to-the-new-peer, `accept.c:148-149`).
    pub fn face_up(&self, id: u64, actions: &Arc<SessionLinkActions>) {
        let observer = Arc::new(WzMutex::new(ApplicationLayerObserver::new()));
        // This face's LOCAL zid, read off the handshake params the same way
        // `Session::new` does. The advanced publisher stamps it into every
        // sample's `SourceInfo` and renders it into the `@adv` keyexpr, so it
        // must be the identity this face actually negotiated rather than a
        // registry-wide copy.
        let zid = actions.params.zid.clone();
        // R311y554 — THE hand-off that makes `allowed_destination` honourable.
        //
        // Every C closure on this ABI is `unsafe impl Sync` on one premise: the
        // C application thread never invokes it. Before this line the premise
        // was kept by REFUSING local delivery (`Locality::Remote` pinned in
        // `put_options` / `queryable_options`), because `Session::publish`
        // drains the fires it stages on whatever thread called it — so a
        // C-thread `z_put` matching a local subscription would have run that
        // callback while the drive thread ran the same C context for another
        // face. `DriveTask` moves the drain instead of forbidding the delivery:
        // the C thread stages and returns, [`Self::next_reply_deadline_ms`]
        // reports the face due NOW, its `deadline_revised` wake gets the loop
        // back, and [`Self::dispatch`] drains — on the one thread the premise
        // allows. The premise is unchanged; what changed is that honouring the
        // field no longer breaks it.
        let session = TokioSession::new(actions.clone(), observer, Arc::new(self.clock))
            .with_local_delivery_drain(LocalDeliveryDrain::DriveTask);

        let mut guard = self.lock();
        // Keyexpr aliases replay FIRST, before the subscriber and queryable
        // declares below. Ordering is load-bearing on the reliable channel: a
        // peer resolves an aliased id through the mapping table it built from
        // our DeclareKeyExpr, so any declaration or Push that could reference
        // the alias must not reach it earlier. Cheap to guarantee here, and
        // impossible to notice if it were wrong until a race showed up.
        for entry in &guard.kexprs {
            // Best-effort per face, exactly as the sub/qbl replays below: a
            // face mid-teardown drops its declare and the SSOT entry survives
            // for the next face.
            let _ = session
                .actions()
                .send_declare_keyexpr(entry.id, &entry.keyexpr);
        }
        let mut subs = BTreeMap::new();
        for entry in &guard.subs {
            if let Some(sub) = declare_subscriber_on(
                &session,
                &entry.keyexpr,
                &entry.wire,
                SubscribeOptions::default()
                    .with_allowed_origin(entry.allowed_origin)
                    .with_retraction_naming(entry.retraction.clone()),
                (entry.sink)(),
            ) {
                subs.insert(entry.id, sub);
            }
        }
        let mut qbls = BTreeMap::new();
        for entry in &guard.qbls {
            if let Some(qbl) = declare_queryable_on(
                &session,
                &entry.keyexpr,
                &entry.wire,
                queryable_options(entry.complete, entry.allowed_origin)
                    .with_retraction_naming(entry.retraction.clone()),
                (entry.sink)(&session),
            ) {
                qbls.insert(entry.id, qbl);
            }
        }
        // Drop any replaced entry OUTSIDE the lock: `insert` returns the
        // previous `FaceEntry` for this id, whose teardown drops subscribers /
        // queryables and may release the last `Arc<CClosure>` — running the C
        // `drop(context)` under the registry lock. A fresh face id makes this
        // `None` in practice; the discipline is uniform rather than
        // conditional on that.
        // Liveliness replay: tokens first, then the liveliness subscriptions.
        // A token this session already holds must be ANNOUNCED to the new peer
        // (pico pushes its declarations at accept time), and a liveliness
        // subscription must be re-declared so the new peer's tokens reach the
        // one C callback.
        let mut tokens = BTreeMap::new();
        for entry in &guard.tokens {
            if let Some(tok) =
                declare_token_on(&session, &entry.keyexpr, &entry.wire, entry.options.clone())
            {
                tokens.insert(entry.id, tok);
            }
        }
        let mut live_subs = BTreeMap::new();
        for entry in &guard.live_subs {
            let mut opts = LivelinessSubscriberOptions::default();
            opts.history = entry.history;
            if let Some(sub) = declare_liveliness_subscriber_on(
                &session,
                &entry.keyexpr,
                &entry.wire,
                opts,
                (entry.sink)(),
            ) {
                live_subs.insert(entry.id, sub);
            }
        }
        // Matching-listener replay. A C listener declared before this peer
        // connected must watch it too, so each entry gets a per-face wz
        // listener whose callback folds THIS face's verdict into the entry's
        // cross-face aggregate.
        //
        // Registering under the registry lock is safe HERE for a reason worth
        // stating, because it is not the general rule in this file:
        // `Publisher::declare_matching_listener` delivers an already-matching
        // registration synchronously, which would put a C callback under the
        // lock. It cannot fire here — `session` was constructed a few lines
        // above with a FRESH `ApplicationLayerObserver`, so its remote-
        // subscriber registry is empty and the initial verdict is necessarily
        // `false`. A future refactor that hands `face_up` an already-populated
        // observer must move this replay out of the lock.
        let mut matches = BTreeMap::new();
        for entry in &guard.matches {
            if let Some(listener) =
                entry
                    .scope
                    .install(&session, &entry.keyexpr, face_matching_callback(id, entry))
            {
                matches.insert(entry.id, listener);
            }
        }
        // R2962 — write filters: ask the new peer the question each one holds.
        // A hold has no callback, so taking it under the lock cannot re-enter
        // (unlike the matching listeners above, which is why THOSE are
        // installed where they are). Filters that ask nothing keep no hold.
        let mut filters = BTreeMap::new();
        for entry in &guard.filters {
            if let Some(form) = &entry.ask {
                let hold = match entry.plane {
                    FilterPlane::Subscribers => {
                        session.hold_subscribers_interest(&entry.keyexpr, form)
                    }
                    FilterPlane::Queryables { .. } => {
                        session.hold_queryables_interest(&entry.keyexpr, form)
                    }
                };
                filters.insert(entry.id, hold);
            }
        }
        // Advanced pub/sub replay, on the same best-effort per-face contract
        // as the four planes above. An advanced publisher declares its own
        // `@adv` cache queryable and liveliness token on the face it binds to,
        // so a per-face declaration is not merely convenient here — it is the
        // only shape in which those two reach the peer at all.
        let mut adv_pubs = BTreeMap::new();
        for entry in &guard.adv_pubs {
            if let Ok(pub_) = AdvancedPublisher::declare(
                &session,
                entry.keyexpr.clone(),
                // R2619 — cloned, not copied: `AdvancedPublisherOptions` owns a
                // `String` since it gained `publisher_detection_metadata`, so
                // it is `Clone` and no longer `Copy`. The keyexpr beside it was
                // already cloned for the same reason.
                entry.options.clone(),
                zid.to_vec(),
            ) {
                adv_pubs.insert(entry.id, pub_);
            }
        }
        // The advanced subscribers are NOT replayed here. Each declares a
        // sequence of entities, and a host that declares keys takes this lock to
        // declare the next one — so they are declared once the lock is released,
        // from the snapshot taken here. Taking it in the SAME critical section as
        // the face's insertion is what makes that safe: an entry recorded after
        // this point finds the face in `declaration_target_handles`, and one
        // recorded before it is in the snapshot, so each is declared on this face
        // exactly once. See [`Self::declare_advanced_subscriber`].
        let adv_sub_replays: Vec<_> = guard
            .adv_subs
            .iter()
            .map(|entry| {
                (
                    entry.id,
                    entry.keyexpr.clone(),
                    // R311y826 — cloned, not moved: `AdvancedSubscriberOptions`
                    // stopped being `Copy` when detection gained an owned
                    // metadata key expression, and this entry is replayed on
                    // every reconnect.
                    entry.options.clone(),
                    Arc::clone(&entry.sink),
                )
            })
            .collect();
        let adv_subs = BTreeMap::new();
        let replay_session = session.clone();
        // R2932 — the groups, so a member joined before this peer connected
        // announces itself to it. Best-effort per face like every replay above:
        // the join's only fallible checks (canon, wildcards) already passed on
        // the local plane when the C program joined.
        let mut groups = BTreeMap::new();
        for entry in &guard.groups {
            if let Ok(copy) =
                FaceGroup::join(&session, &entry.agg, Locality::Remote, entry.priority)
            {
                groups.insert(entry.id, copy);
            }
        }
        // R2259 (item 593) — taken BEFORE the entry moves into the map, and
        // fired after the lock drops. The face is Established by the time
        // `face_up` runs (both callers reach it past a completed handshake), so
        // the identity slots this reads are already populated.
        let snapshot = FaceSnapshot::of(&session);
        let replaced = guard.faces.insert(
            id,
            FaceEntry {
                session,
                subs,
                qbls,
                tokens,
                live_subs,
                matches,
                filters,
                adv_pubs,
                adv_subs,
                groups,
                // `face_up` runs on the drive task, so this IS the runtime the
                // face is driven by. Always `Some` for a real face; see the
                // field for why the type admits `None`.
                runtime: Some(tokio::runtime::Handle::current()),
                revised: Arc::new(Notify::new()),
            },
        );
        drop(guard);
        // R2932 — a replaced entry's group copies are copies of a session that
        // is gone, so their members leave the union the way `face_down`'s do.
        if let Some(mut old) = replaced {
            retire_copies(std::mem::take(&mut old.groups).into_values());
        }
        // The advanced subscribers, outside the lock — see where the snapshot is
        // taken. This runs on the drive task, which is the runtime the face is
        // driven by, so a declaration that spawns has the one it needs.
        for (adv_id, keyexpr, options, sink) in adv_sub_replays {
            let (on_sample, on_miss) = (sink)();
            // R2814 — the seeded form: this is a replay of a subscriber the C
            // program already holds, so its miss listener exists before the
            // face's startup history GET can report anything.
            if let Ok(sub) = AdvancedSubscriber::declare_with_options_and_miss_listener(
                &replay_session,
                keyexpr,
                options,
                on_sample,
                on_miss,
            ) {
                self.attach_advanced_subscriber(
                    DeclarationTarget::Face(id),
                    &replay_session,
                    adv_id,
                    sub,
                );
            }
        }
        // Outside the lock, for the reason `fire_face_event` states: a C
        // listener may re-enter this registry.
        if let Some(snapshot) = snapshot {
            self.fire_face_event(FaceEventKind::Up, &snapshot);
        }
    }

    /// A face left the live set (peer Close / link loss).
    ///
    /// R311y522 — before the entry is dropped, every remote liveliness token
    /// that face announced is delivered to the C application as a `Delete`.
    /// This is the ACCEPT-side half of the R311y521 flush, and pico draws no
    /// dial/accept distinction: it fires
    /// `_z_liveliness_subscription_undeclare_all` from unicast transport
    /// FAILURE generally (`src/transport/unicast/lease.c:74-78`).
    ///
    /// Without it, dropping the entry silently discarded the whole per-face
    /// observer — registry cleaned, application never told. A C program that
    /// declared `z_liveliness_declare_subscriber` therefore kept believing a
    /// token was alive after the peer that announced it was gone, and no
    /// `UndeclToken` can rescue that: the link that would carry one is exactly
    /// what died.
    ///
    /// ## The drain is not optional, and it is the whole reason this was hard
    ///
    /// `flush_liveliness_on_link_loss` does NOT run the C callback. The
    /// registry's slot holds a DEFERRED-FIRE staging sink (R311lg): it copies
    /// each matched sample onto the session's fire queue so the callback runs
    /// after the observer lock drops, which is what lets a C callback re-enter
    /// the session without self-deadlocking. The drive loop normally drains
    /// that queue — but this runs AFTER the drive loop has returned, so
    /// nothing else ever will. Flushing without draining stages Deletes that
    /// no one delivers, which measures as "1 slot fired" and reaches the
    /// application as silence.
    ///
    /// Flushing the WHOLE observer is correct HERE, where it would not be on a
    /// node with one shared observer: `face_up` builds a fresh
    /// `ApplicationLayerObserver` per face, so this observer's remote tokens
    /// all came from THIS face. That per-face scoping is what lets pico's
    /// single-session "flush everything" transcribe without attribution.
    pub fn face_down(&self, id: u64) {
        // Drop OUTSIDE the lock: dropping the entry drops its subscribers,
        // and the last one may release the final `Arc<CClosure>` and run the
        // C `drop(context)`.
        let removed = self.lock().faces.remove(&id);
        // R2259 (item 593) — the DEPARTED face's identity, taken while the
        // entry is still alive. There is no other moment: `face_down` is handed
        // an id, and once the entry drops nothing can say which peer it was.
        if let Some(snapshot) = removed.as_ref().and_then(|e| FaceSnapshot::of(&e.session)) {
            self.fire_face_event(FaceEventKind::Down, &snapshot);
        }
        if let Some(entry) = &removed {
            // Both steps run BEFORE the drop: the sinks that must receive the
            // Deletes are owned by the entry being dropped.
            let observer = entry.session.observer();
            let staged = match observer.lock() {
                Ok(mut o) => o.flush_liveliness_on_link_loss(),
                // A panicking C callback poisons the mutex; recover rather
                // than skip the flush, matching this file's other `lock()`.
                Err(poisoned) => poisoned.into_inner().flush_liveliness_on_link_loss(),
            };
            if staged > 0 {
                // Runs the C callbacks, with the observer lock released.
                entry.session.drain_deferred_fires();
            }
        }
        // Purge the departed face from every matching aggregate. Same reasoning
        // as the liveliness flush above and the same failure mode: this face's
        // subscribers cannot undeclare, because the link that would carry the
        // UndeclSubscriber is what died. Its per-face wz listener therefore
        // never fires `false`, so without this the face stays in the aggregate
        // set forever and a C program is told it still has matching subscribers
        // after its only subscribing peer vanished — and, worse, the aggregate
        // never flips again, so a genuine later `true` is suppressed as
        // "no change".
        //
        // R311y528 — the `(state, sink)` pairs are snapshotted out of the
        // registry lock BEFORE either is touched, and the fold + C delivery then
        // run under the aggregate mutex alone. Folding under the registry lock
        // (what this did until R311y528) established a `registry -> aggregate`
        // order, which is the half of the ABBA pair that made holding the
        // aggregate across the C call unsafe. See `deliver_matching_flip`.
        //
        // R311y535 — the snapshot is now STATE ONLY. It used to carry a sink
        // clone per entry and hold the whole vector across every delivery, which
        // is the clone that made `z_undeclare_matching_listener` non-deterministic:
        // a C thread undeclaring while this loop ran found a strong count of 2 and
        // the C `drop(context)` landed later, on this thread. The aggregate now
        // owns the sink, so nothing here can outlive an undeclare.
        let watches: Vec<Arc<StdMutex<MatchAggregate>>> = {
            let guard = self.lock();
            guard
                .matches
                .iter()
                .map(|entry| entry.state.clone())
                .collect()
        };
        for state in watches {
            deliver_matching_flip(&state, |agg| agg.forget(id));
        }
        // R2932 — the same reasoning for the group plane: nothing will carry a
        // Leave over a dead link, so the members only this face could see
        // leave the union here. Outside the registry lock, because it delivers.
        if let Some(mut entry) = removed {
            retire_copies(std::mem::take(&mut entry.groups).into_values());
            drop(entry);
        }
    }

    /// Drop EVERY face — what `z_close` runs once its drive thread has joined.
    ///
    /// # Why `z_close` must do this, and why it is not merely tidy
    ///
    /// This is pico's `_z_session_close` → `_z_flush_pending_queries`
    /// (`~/zenoh-pico/src/session/utils.c:194`, `src/session/query.c:276-283`):
    /// closing a session ENDS every in-flight get, running each pending query's
    /// drop handler.
    ///
    /// Without it a `z_get` outstanding at `z_close` would never complete. The
    /// accept loop's shutdown path breaks out and drops its own per-face
    /// `OpenedSession`s, but it never calls `deregister` — that runs only when a
    /// face's own drive finishes (`accept_loop.rs`, the `Step::Driven` arm). So
    /// the registry's `FaceEntry`s — each holding its OWN `TokioSession`, hence
    /// its own `ReplyRegistry` and every pending entry's `Arc` clone — would
    /// outlive the drive thread with nothing left to sweep them. The C
    /// `drop(context)`, which IS the get's completion signal, would fire only at
    /// `z_session_drop`, and never at all for a program that keeps the handle
    /// (`z_close` does not free it). A `z_get` issued AFTER `z_close` would be
    /// worse: it would find the orphaned faces, register a deadlined entry, and
    /// hang forever — where pico completes it at once (a closed session has an
    /// empty peer set).
    ///
    /// It also removes a role asymmetry that made identical C code behave
    /// differently: the DIAL role already drops its face explicitly after its
    /// drive returns (`session::drive_dial`), so only `listen` leaked.
    ///
    /// Running the C `drop(context)` on the calling (C) thread is sound here and
    /// is pico's own behaviour: by the time this runs the drive thread has been
    /// joined, so no `call` can be in flight to race it — and the `Arc` refcount
    /// serialises it regardless (see the `unsafe impl Sync for CReplyClosure`).
    pub fn clear_faces(&self) {
        // Take OUTSIDE the lock, drop OUTSIDE the lock — the standing
        // discipline: dropping a face runs the C `drop(context)` for any
        // closure it held the last reference to.
        let faces = std::mem::take(&mut self.lock().faces);
        // R2932 — a closed session sees no peer, so a C group's union loses
        // every member it heard over the wire, as `face_down` would take them.
        for mut entry in faces.into_values() {
            retire_copies(std::mem::take(&mut entry.groups).into_values());
            drop(entry);
        }
    }

    /// One inbound iteration event for `id` — dispatched into that face's own
    /// session (and so its own observer, keeping the peer's keyexpr alias id
    /// space private to it), then that face's expired `z_get`s are swept.
    ///
    /// # The sweep must live HERE, and only here
    ///
    /// This is the `on_event` path — the drive thread — for BOTH roles (the
    /// dial role's own drive closure and, via [`CApiForwarder::forward`], every
    /// accepted face). That is the one thread on which a C closure may be
    /// invoked, and sweeping a timed-out `z_get` FIRES the C reply closure's
    /// `on_final`. Calling [`TokioSession::sweep_expired_queries`] from the C
    /// application thread instead — e.g. straight out of `z_get` — would run
    /// that closure's `drop`/final concurrently with a drive-thread `call` on
    /// another face: two C callbacks at once on one context, which is exactly
    /// the unsound-`Sync` bug R311y288 fixed on the publish plane.
    ///
    /// The hazard is real rather than theoretical, and it is NOT contained by
    /// the `Locality::Remote` pin that protects the queryable plane: unlike
    /// [`TokioSession::query`], whose in-process fan and drain are both gated on
    /// `allows_local`, `sweep_expired_queries`' `drain_deferred_fires` is
    /// UNGATED (`session/mod.rs`) — it takes the whole per-session deferred
    /// queue and runs it on the CALLING thread whatever the locality. So the
    /// only thing keeping it sound is the caller, and the caller is this
    /// function.
    ///
    /// Cadence comes from the wake this face arms via
    /// [`CApiForwarder::next_extra_deadline_ms`] /
    /// [`Self::next_reply_deadline_ms`], so an expiring `z_get` wakes the drive
    /// loop and lands here on time rather than on the ~3333 ms keepalive
    /// cadence. Sweeping on EVERY event (not only a deadline wake) is
    /// deliberate: it is idempotent and cheap when nothing is expired, and it
    /// means inbound traffic also clears the table.
    pub fn dispatch(&self, id: u64, event: IterationEvent<'_>) {
        // Clone the session out of the lock first: the dispatch fires the C
        // subscriber callback, which may re-enter this session (`z_put` from
        // inside a callback is a supported pico pattern), so holding the lock
        // across it would deadlock. The sweep below fires the C reply
        // closure's final and is re-entrant the same way, so it too runs with
        // the lock released.
        let session = self.lock().faces.get(&id).map(|face| face.session.clone());
        if let Some(session) = session {
            session.dispatch_iteration_event(event);
            session.sweep_expired_queries();
            // R311y533 — the LIVELINESS-GET table has the same deadline
            // contract and, until this line, no enforcer under the C ABI.
            // `z_liveliness_get` arms a 10 s default (pico's own rule for
            // `timeout_ms == 0`), but the only host that ever swept the table
            // was `wz-ap-demo`'s sweep ticker. Measured: upstream's
            // `z_get_liveliness.c` on wz blocked in `z_recv` forever whenever
            // the peer's snapshot did not terminate, because the C reply
            // closure's `drop` — the thing that closes the channel — runs only
            // when the pending entry's sink is dropped.
            //
            // Same thread and the same soundness argument as the query sweep
            // directly above: firing a snapshot's synthetic timeout reply and
            // its final invokes C callbacks, and this is the one thread on
            // which that is allowed.
            session.sweep_expired_liveliness_gets();
            // R311y554 — the DRIVE-TASK half of the local-delivery hand-off.
            //
            // A C-thread `z_put` whose `allowed_destination` allows local
            // stages its subscriber fires and returns without running them
            // (`LocalDeliveryDrain::DriveTask`, set in `face_up`). This is where
            // they run. Explicit rather than left to the two sweeps above,
            // because both are feature-gated (`query-get` / `liveliness-get`)
            // and the hand-off must hold in EVERY feature subset that has a
            // subscriber plane — which is all of them. Idempotent and cheap: an
            // empty queue costs one length read, and the drain is re-entrant
            // (a callback that publishes again is drained by the same loop).
            session.drain_deferred_fires();
        }
    }

    /// When face `id`'s earliest pending `z_get` is due, or `None` if it has
    /// none — the wake [`Self::dispatch`]'s sweep rides on.
    ///
    /// Per-face because each face has its OWN session (and so its own pending
    /// table): a `z_get` fans one wz `query` per face, and each face's drive
    /// loop arms only its own deadline. A face with no pending get arms
    /// nothing, so an idle session's cadence is unchanged.
    pub fn next_reply_deadline_ms(&self, id: u64) -> Option<u64> {
        let session = self.lock().faces.get(&id).map(|face| face.session.clone());
        session.and_then(|session| {
            // R311y533 — the EARLIER of the two pending tables that carry
            // deadlines. Sweeping on every event (above) bounds a snapshot's
            // overrun to the next inbound message or keepalive tick; arming the
            // wake is what makes it expire ON its deadline instead, and on a
            // face with no other traffic it is the only thing that gets the
            // drive loop back at all.
            // R311y554 — a staged-but-undrained local fire makes this face due
            // NOW. Without it the hand-off would still be correct but slow: the
            // fires would wait for the next inbound message or the ~3333 ms
            // keepalive tick, so an in-process `z_put` into an otherwise idle
            // session would deliver seconds late. Reported as "now" on this
            // session's own monotonic scale, so the `min` below and the
            // driver's `saturating_sub` both read it as a zero-length sleep.
            //
            // It cannot hot-spin: `dispatch` drains before the loop re-reads
            // this, so the second read finds the queue empty.
            if session.has_pending_fires() {
                use wz_runtime_core::TimeSource as _;
                return Some(self.clock.now_monotonic_ms());
            }
            let reply = session.next_reply_deadline_ms();
            let liveliness = session.next_liveliness_get_deadline_ms();
            match (reply, liveliness) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (only, None) | (None, only) => only,
            }
        })
    }

    /// Publish to every connected peer (pico `z_put` / `z_publisher_put`
    /// semantics: the write goes to the session's whole peer set).
    ///
    /// Best-effort per face, matching pico's multi-peer send, which discards
    /// each peer's send result and returns OK even if some/all peer sends fail
    /// (`~/zenoh-pico/src/transport/common/tx.c:92-95,139-150` — contrast the
    /// single-peer path's `_Z_RETURN_IF_ERR`). Concretely a face mid-teardown
    /// yields `PublishError::TransportUnavailable` (the F2 gate — per-face and
    /// transient); swallowing it and continuing means a healthy peer ordered
    /// after it in the map still receives the sample. Only a DETERMINISTIC,
    /// face-independent error — the payload/keyexpr overflowing the bounded
    /// codec (`ExceedsCapacity`), which would fail identically on every face —
    /// is surfaced. Zero faces is `Ok(0)`: a put with no peer connected simply
    /// has no recipient (pico's empty peer list → OK).
    ///
    /// # The local leg runs ONCE, and that is the whole of the "fan split"
    ///
    /// R311y554 — `opts.allowed_destination` now reaches this function meaning
    /// what the C caller said, so the two legs have to be separated. wz holds N
    /// faces where pico holds one transport, and a C subscription is declared
    /// on EVERY face's session — so handing the caller's locality unchanged to
    /// each face would deliver one in-process put to the same C callback N
    /// times. The wire leg is per-face by nature; the local leg is a property
    /// of the session, so it is issued exactly once, on the first face, with
    /// [`Locality::SessionLocal`] (which suppresses that face's wire leg — it
    /// already sent in the loop above).
    ///
    /// R311y557 — the local leg no longer belongs to a FACE. It runs on the
    /// session-scope [local plane](Self::local), so it runs identically at zero
    /// faces and at N, and the "first face takes it" convention (with the
    /// zenoh-c divergence it carried at zero faces) is gone.
    pub fn publish_all(
        &self,
        keyexpr: &str,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        self.fan_out(opts, |session, leg| {
            Leg::of_publish(session.publish(keyexpr, payload, leg))
        })
    }

    /// [`Self::publish_all`] for a payload that lives in SHARED MEMORY: each face that
    /// negotiated it is sent the chunk's descriptor and each face that did not is sent the
    /// bytes read back out of the chunk, which is `Session::publish_shm`'s contract per
    /// face. The local leg runs once, and hands a subscriber of this session the chunk
    /// itself rather than a copy of its bytes.
    ///
    /// The fan-out, the one local leg and the error classification are the private
    /// fan-out's, shared with the byte publish, so the two cannot disagree about any of
    /// them; what differs is the call each leg makes.
    #[cfg(feature = "transport-shm")]
    pub fn publish_shm_all(
        &self,
        keyexpr: &str,
        payload: &wz_runtime_tokio::shm_provider::ShmBackedPayload,
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        self.fan_out(opts, |session, leg| {
            Leg::of_publish(session.publish_shm(keyexpr, payload, leg))
        })
    }

    /// [`Self::publish_aliased_all`] for a payload that lives in shared memory: the key is
    /// named on the wire by the declared id, and the payload is the descriptor where a face
    /// negotiated shared memory.
    #[cfg(feature = "transport-shm")]
    pub fn publish_shm_aliased_all(
        &self,
        mapping_id: u64,
        suffix: Option<&str>,
        payload: &wz_runtime_tokio::shm_provider::ShmBackedPayload,
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        self.fan_out(opts, |session, leg| {
            Leg::of_alias(session.publish_shm_aliased_auto(mapping_id, suffix, payload, leg))
        })
    }

    /// The fan-out every publish shares: the wire leg to each face, then the local leg
    /// once, with `send` making the one call a leg is.
    ///
    /// ## The classification is the part that must not drift
    ///
    /// A face that fails TRANSIENTLY (link released, reconnecting, an alias it was never
    /// told) is skipped and the surviving faces still receive the sample, because pico's
    /// multi-peer send discards each peer's result; a DETERMINISTIC failure, one that would
    /// fail identically on every face, is surfaced. [`Leg`] carries that decision out of
    /// the call, and the two constructors name which errors are which.
    ///
    /// ## The local leg is issued ONCE, with the plane's own session
    ///
    /// R311y555 -- WAKE THE DRAIN. Staging a fire does not make a drive loop iterate;
    /// without the notification the delivery rides the next inbound message or the keepalive
    /// tick, MEASURED at 3.334 s.
    fn fan_out<F>(&self, opts: &PublishOptions, send: F) -> Result<usize, FanoutError>
    where
        F: Fn(&TokioSession, PublishOptions) -> Leg,
    {
        let sessions = self.face_sessions_with_wake();
        let mut delivered = 0usize;
        if opts.allowed_destination.allows_remote() {
            let remote = opts.clone().with_locality(Locality::Remote);
            for (session, _) in &sessions {
                match send(session, remote.clone()) {
                    Leg::Delivered(n) => delivered += n,
                    Leg::Skipped => {}
                    Leg::Refused => return Err(FanoutError::ExceedsCapacity),
                }
            }
        }
        if opts.allowed_destination.allows_local() {
            let local = opts.clone().with_locality(Locality::SessionLocal);
            match send(&self.local, local) {
                Leg::Delivered(n) => delivered += n,
                // The plane's link is inert, so the skipped arm is unreachable through
                // it; kept because the local leg's error handling must not be more
                // brittle than the wire leg's if the plane ever changes.
                Leg::Skipped => {}
                Leg::Refused => return Err(FanoutError::ExceedsCapacity),
            }
            self.local_wake.notify_one();
        }
        Ok(delivered)
    }

    /// Fan a publish on `keyexpr` over every face, naming it on the wire as
    /// `wire` says — [`Self::publish_all`] for a literal, otherwise
    /// [`Self::publish_aliased_all`] on the alias.
    pub fn publish_on_wire_all(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        if wire.is_literal() {
            self.publish_all(keyexpr, payload, opts)
        } else {
            self.publish_aliased_all(wire.mapping_id, wire.suffix.as_deref(), payload, opts)
        }
    }

    /// Fan an ALIASED publish over every face (pico `_z_write` on a
    /// `_z_declared_keyexpr_t` whose declaration is live).
    ///
    /// Each face resolves the literal from its OWN outbound mapping table via
    /// `publish_aliased_auto`, which is why the id can be session-global while
    /// the resolution stays per-face: the table was populated by that face's
    /// own `send_declare_keyexpr`, either at declare time or on replay.
    ///
    /// `UnknownMapping` on a face is treated as the per-face transient
    /// [`Self::publish_all`] treats `TransportUnavailable`. It is reachable
    /// without any bug: a face whose declare failed mid-teardown never got the
    /// table entry, and skipping it lets the healthy peers still receive the
    /// sample. Every other error is deterministic and face-independent, so it
    /// is surfaced.
    ///
    /// R2959 — `suffix` is what follows the declared prefix, `None` when the
    /// declaration covers the whole key. zenoh-pico declares a PREFIX for some
    /// entities and publishes on `id + remainder`
    /// (`_z_declared_keyexpr_alias_to_wire`,
    /// `vendor/zenoh-pico/src/session/keyexpr.c`), so an alias is not always
    /// the whole key.
    pub fn publish_aliased_all(
        &self,
        mapping_id: u64,
        suffix: Option<&str>,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        // R311y554 / R311y557 — the same one-local-leg split as
        // [`Self::publish_all`]; see that function for why N faces must not each
        // deliver the sample to the one C callback. The aliased local leg needs
        // no "first face that OWNS the mapping" search any more: the local plane
        // took `send_declare_keyexpr` in [`Self::declare_keyexpr`] alongside
        // every face, so it always resolves an alias the caller could legally
        // publish on, and it resolves it whether or not any face does.
        // An id the local plane does not know is an id no face was told about either
        // (`declare_keyexpr` announces to both, and `undeclare_keyexpr` retracts from
        // both), so an unknown mapping is the caller publishing on an alias it never
        // declared, and is skipped on every leg (see [`Leg::of_alias`]).
        self.fan_out(opts, |session, leg| {
            Leg::of_alias(session.publish_aliased_auto(mapping_id, suffix, payload, leg))
        })
    }

    /// Record a C keyexpr declaration in the SSOT and announce it on every live
    /// face, returning the allocated mapping id (never 0).
    ///
    /// Same declare-before-peer semantics as [`Self::declare_subscriber`]: with
    /// no face yet, nothing goes on the wire and the entry is still recorded,
    /// so every FUTURE face replays it in [`Self::face_up`].
    ///
    /// Returns `None` when the id space is exhausted. The space is the WIRE's,
    /// not ours: zenoh types `DeclareKeyExpr.id` as `ExprId = u16` and pico's
    /// `_z_decl_kexpr_t` holds a `uint16_t`, so ids above `u16::MAX` are
    /// rejected by `send_declare_keyexpr` and must not be handed out. Refusing
    /// is the honest answer — wrapping would silently re-issue a live id and
    /// re-point a peer's existing alias at a different keyexpr.
    pub fn declare_keyexpr(&self, keyexpr: String) -> Option<u64> {
        let mut guard = self.lock();
        let id = guard.next_kexpr_id.checked_add(1)?;
        if id > u64::from(u16::MAX) {
            return None;
        }
        guard.next_kexpr_id = id;

        for face in guard.faces.values() {
            let _ = face.session.actions().send_declare_keyexpr(id, &keyexpr);
        }
        // R311y557 — the LOCAL PLANE takes the same alias. Its declare goes to
        // the inert driver, so nothing extra reaches any peer; what it populates
        // is the plane's own OUTBOUND mapping table, which is what
        // [`Self::publish_aliased_all`]'s local leg resolves against. Without
        // it an aliased put would deliver on the wire and to nobody in-process.
        let _ = self.local.actions().send_declare_keyexpr(id, &keyexpr);
        guard.kexprs.push(KexprEntry {
            id,
            keyexpr,
            holders: 1,
        });
        Some(id)
    }

    /// Declare a keyexpr the way zenoh-pico's resource table does: a key the
    /// session already holds is answered with the SAME id and one more holder,
    /// and the declaration is announced again all the same.
    ///
    /// pico looks the key up before it allocates
    /// (`vendor/zenoh-pico/src/session/resource.c` @
    /// `// declaration of already declared resource`) and then sends the
    /// declaration whether or not the key was new
    /// (`vendor/zenoh-pico/src/net/primitives.c` @
    /// `z_result_t _z_declare_resource(_z_session_t *zn, const _z_string_t *key, uint16_t *out_id) {`).
    /// Every entity that declares a key — a publisher, a subscriber's prefix, a
    /// token, and the components an advanced publisher or subscriber is made of —
    /// goes through it, so the ids and the messages depend on it.
    ///
    /// [`Self::declare_keyexpr`] is unchanged and is what the other ABI uses:
    /// each call there is its own declaration with its own id.
    ///
    /// `None` when the id space is exhausted, as for [`Self::declare_keyexpr`].
    pub fn acquire_keyexpr(&self, keyexpr: String) -> Option<u64> {
        {
            let mut guard = self.lock();
            if let Some(entry) = guard.kexprs.iter_mut().find(|e| e.keyexpr == keyexpr) {
                entry.holders += 1;
                let id = entry.id;
                for face in guard.faces.values() {
                    let _ = face.session.actions().resend_declare_keyexpr(id, &keyexpr);
                }
                let _ = self.local.actions().resend_declare_keyexpr(id, &keyexpr);
                return Some(id);
            }
        }
        self.declare_keyexpr(keyexpr)
    }

    /// Let go of one holder of a keyexpr [`Self::acquire_keyexpr`] (or
    /// [`Self::declare_keyexpr`]) returned, retracting the key when it was the
    /// last. Nothing goes on the wire while another holder remains: pico sends
    /// its undeclaration only when the count reaches zero
    /// (`vendor/zenoh-pico/src/session/resource.c` @
    /// `_z_resource_slist_value(res_ptr)->_refcount--;`).
    ///
    /// The count and the retraction are one step under one lock: releasing the
    /// lock between them would let an [`Self::acquire_keyexpr`] find the entry at
    /// zero, take a holder, and then have its key retracted from under it.
    pub fn release_keyexpr(&self, mapping_id: u64) {
        let mut guard = self.lock();
        let Some(entry) = guard.kexprs.iter_mut().find(|e| e.id == mapping_id) else {
            return;
        };
        entry.holders = entry.holders.saturating_sub(1);
        if entry.holders > 0 {
            return;
        }
        self.retract_keyexpr_locked(&mut guard, mapping_id);
    }

    /// The keyexpr declarations this session currently holds, `(id, keyexpr)`
    /// in declaration order — the SSOT every new face is replayed from.
    pub fn keyexpr_declarations(&self) -> Vec<(u64, String)> {
        self.lock()
            .kexprs
            .iter()
            .map(|entry| (entry.id, entry.keyexpr.clone()))
            .collect()
    }

    /// Retract a C keyexpr declaration: drop the SSOT entry so no future face
    /// replays it, and emit the wire undeclare on every live face.
    ///
    /// No cross-lock drop dance is needed here, unlike the subscriber and
    /// queryable twins: a [`KexprEntry`] owns a `String` and no `Arc<CClosure>`,
    /// so releasing it cannot run C code.
    pub fn undeclare_keyexpr(&self, mapping_id: u64) {
        let mut guard = self.lock();
        self.retract_keyexpr_locked(&mut guard, mapping_id);
    }

    /// The retraction itself, for a caller that already holds the registry lock
    /// — [`Self::undeclare_keyexpr`] and [`Self::release_keyexpr`], which must
    /// not let it go between deciding and doing.
    fn retract_keyexpr_locked(&self, guard: &mut Inner, mapping_id: u64) {
        if let Some(pos) = guard.kexprs.iter().position(|e| e.id == mapping_id) {
            guard.kexprs.remove(pos);
        }
        for face in guard.faces.values() {
            face.session.actions().send_undeclare_kexpr(mapping_id);
        }
        // R311y557 — retract from the local plane too, so a subsequent aliased
        // put on a retracted id answers `UnknownMapping` on BOTH legs rather
        // than continuing to deliver in-process.
        self.local.actions().send_undeclare_kexpr(mapping_id);
    }

    /// Record a C liveliness TOKEN in the SSOT and declare it on every live
    /// face, returning its id.
    ///
    /// Declare-before-peer, like every other declaration here: with no face
    /// yet nothing goes on the wire and the entry is still recorded, so each
    /// future face announces it in [`Self::face_up`]. That is the ordinary case
    /// for upstream's `z_liveliness.c`, which declares and then sleeps.
    ///
    /// `None` when the id space is exhausted, which cannot happen in practice
    /// (u64) but is surfaced rather than wrapped, for the same reason
    /// [`Self::declare_keyexpr`] refuses: a reused id would retract a live
    /// token belonging to someone else.
    pub fn declare_liveliness_token(&self, keyexpr: String) -> Option<TokenId> {
        self.declare_liveliness_token_on_wire(keyexpr, WireKey::literal(), LivelinessOptions::new())
    }

    /// [`Self::declare_liveliness_token`], announced as `wire` and retracted
    /// the way `options` says — the declaring ABI's two choices.
    pub fn declare_liveliness_token_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        options: LivelinessOptions,
    ) -> Option<TokenId> {
        let mut guard = self.lock();
        let id = guard.next_token_id.checked_add(1)?;
        guard.next_token_id = id;

        // R2580 — the local plane is in this walk. MEASURED against
        // `libzenohc.so` before the repair: a token declared here and a
        // liveliness subscriber on the SAME session saw nothing (`after=0`
        // against upstream's `1`), while across a real face both saw it. The
        // machinery was never broken; the declaration just never reached the
        // plane, because the plane had no `tokens` slot to reach.
        for face in guard.declaration_targets() {
            if let Some(tok) = declare_token_on(&face.session, &keyexpr, &wire, options.clone()) {
                face.tokens.insert(id, tok);
            }
        }
        guard.tokens.push(TokenEntry {
            id,
            keyexpr,
            wire,
            options,
        });
        Some(id)
    }

    /// Retract a C liveliness token: drop the SSOT entry so no future face
    /// announces it, and drop every face's wz token — each emitting that face's
    /// UndeclToken, which is what tells subscribers the resource is gone.
    pub fn undeclare_liveliness_token(&self, id: TokenId) {
        let mut dropped = Vec::new();
        let mut dropped_entry = None;
        {
            let mut guard = self.lock();
            // R2959 — moved OUT, like every other plane's entry: its `WireKey`
            // may keep a keyexpr declaration alive, and releasing the last one
            // retracts it through this registry.
            if let Some(pos) = guard.tokens.iter().position(|e| e.id == id) {
                dropped_entry = Some(guard.tokens.remove(pos));
            }
            // R2580 — including the plane's, or a C `z_drop` on the token would
            // leave the in-process copy alive and the DELETE sample unsent.
            for face in guard.declaration_targets() {
                if let Some(tok) = face.tokens.remove(&id) {
                    dropped.push(tok);
                }
            }
        }
        // Drop OUTSIDE the lock. A token teardown emits on the wire and can
        // re-enter the session, which the non-reentrant registry mutex would
        // deadlock on — the same discipline every other teardown here follows.
        // The per-face tokens go first, so their retractions reach the wire
        // before the entry's keyexpr declaration can be released.
        drop(dropped);
        drop(dropped_entry);
    }

    /// Record a C liveliness SUBSCRIPTION in the SSOT and declare it on every
    /// live face, returning its id.
    ///
    /// Shares [`SubId`] space with [`Self::declare_subscriber`] on purpose: C
    /// gets back a `z_owned_subscriber_t` either way, so one id space is what
    /// lets [`Self::undeclare_subscriber`] serve both without the caller
    /// having to remember which kind it holds.
    pub fn declare_liveliness_subscriber(
        &self,
        keyexpr: String,
        options: LivelinessSubscriberOptions,
        sink: LivelinessSink,
    ) -> SubId {
        self.declare_liveliness_subscriber_on_wire(keyexpr, WireKey::literal(), options, sink)
    }

    /// [`Self::declare_liveliness_subscriber`], its interest announced as
    /// `wire`.
    pub fn declare_liveliness_subscriber_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        options: LivelinessSubscriberOptions,
        sink: LivelinessSink,
    ) -> SubId {
        let mut guard = self.lock();
        let id = guard.next_sub_id;
        guard.next_sub_id = guard.next_sub_id.wrapping_add(1);

        // R2580 — the plane included, which is the receiving half of the same
        // measurement: without it this subscriber cannot hear a token its own
        // session declared, however many peers it has or has not.
        for face in guard.declaration_targets() {
            if let Some(sub) = declare_liveliness_subscriber_on(
                &face.session,
                &keyexpr,
                &wire,
                options.clone(),
                sink(),
            ) {
                face.live_subs.insert(id, sub);
            }
        }
        guard.live_subs.push(LiveSubEntry {
            id,
            keyexpr,
            history: options.history,
            wire,
            sink,
        });
        id
    }

    /// A snapshot of every connected face's session, taken OUT of the registry
    /// lock — what a fan-out operation iterates.
    ///
    /// Returning a snapshot rather than lending the guard is the crate's
    /// standing locking discipline made reusable: every fan (`publish_all`,
    /// `z_get`) may invoke C code, and a pico callback is allowed to re-enter
    /// the session, so walking `guard.faces` while calling into a face would
    /// deadlock the non-reentrant mutex.
    pub fn face_sessions(&self) -> Vec<TokioSession> {
        self.lock()
            .faces
            .values()
            .map(|face| face.session.clone())
            .collect()
    }

    /// R2579 — every session a DECLARATION made through this registry reaches:
    /// the faces AND the face-independent local plane. The read-side twin of
    /// what [`Self::declare_subscriber`] and [`Self::declare_queryable`] write,
    /// which both end with `self.local.declare_*`.
    ///
    /// ⚠ The plane is named in prose rather than linked: the field is PRIVATE,
    /// and a `[…](Self::local)` link is one `cargo doc --all-features` counts as
    /// broken. That cost this round a push — the C1bz budget for this crate went
    /// 7 -> 8 and gate 4 refused it. `publish_all` a few methods up carries the
    /// same link and is one of the seven already budgeted; do not copy it.
    ///
    /// ## Why this is not [`Self::face_sessions`], measured rather than argued
    ///
    /// The two are not interchangeable and neither is a superset worth
    /// collapsing to. Of the readers built on `face_sessions`, five are RIGHT to
    /// exclude the local plane because their subject is the WIRE:
    /// `face_snapshots` and `peer_identities` answer about transports, and a
    /// local plane is not one; `batch_start_all` / `batch_flush_all` /
    /// `batch_stop_all` drive a batching window that exists per link. The
    /// matching polls are the ones that are not about the wire — upstream
    /// computes a matching verdict over the WHOLE session, session-local
    /// entities included (`zenoh/src/api/session.rs` @ `.any(|q| q.complete`).
    ///
    /// Built on `face_sessions`, they had a hole with a precise shape, and the
    /// shape is why it survived: `declare_queryable` registers on every face
    /// session as WELL as on the plane, so any face carries a copy and the poll
    /// answers correctly THROUGH it. The plane is load-bearing only when the
    /// face set is EMPTY — and that is exactly the configuration no fixture
    /// had, because an interop fixture connects something by definition.
    ///
    /// MEASURED at R2579 with one C program compiled once and linked twice,
    /// against `libzenohc.so` and against this ABI: with a peer, both report
    /// `false` then `true` across a session-local `z_declare_queryable`; with
    /// NO peer, upstream still reports `true` and this ABI reported `false`.
    ///
    /// Same snapshot-out-of-the-lock discipline as `face_sessions`, and for the
    /// same reason: a consulted session takes its own observer mutex.
    pub fn matching_planes(&self) -> Vec<TokioSession> {
        let mut planes = self.face_sessions();
        planes.push(self.local.clone());
        planes
    }

    /// R2259 (open-debt item 593) — every ESTABLISHED face as the C
    /// link/transport planes see it: the input to `z_info_transports` and
    /// `z_info_links`.
    ///
    /// Built on the same `face_sessions` walk and the same "skip a face whose
    /// INIT has not populated the slots" rule as
    /// [`peer_identities`](Self::peer_identities), because it answers the same
    /// question one level richer — a half-open face is not a transport, and
    /// reporting one with a zero id would put a peer on the C side that no peer
    /// is.
    pub fn face_snapshots(&self) -> Vec<FaceSnapshot> {
        self.face_sessions()
            .iter()
            .filter_map(FaceSnapshot::of)
            .collect()
    }

    /// R2259 (open-debt item 593) — register a face-lifecycle observer, and get
    /// back the id that undeclares it.
    ///
    /// `sink` runs on the DRIVE task, inside `face_up` / `face_down`, which is
    /// the same role every other C callback on this ABI is invoked from — the
    /// `unsafe impl Sync` premise behind a C closure here is that the C
    /// application thread never invokes it, and that premise is what makes this
    /// the right seam rather than a poll from the C side.
    pub fn watch_faces(&self, sink: FaceEventSink) -> u64 {
        let mut guard = self.lock();
        guard.next_face_watcher_id += 1;
        let id = guard.next_face_watcher_id;
        guard.face_watchers.push((id, sink));
        id
    }

    /// R2259 — drop a face-lifecycle observer. `true` when one was registered
    /// under `id`, so an undeclare of an already-undeclared listener is
    /// distinguishable from one that was never declared.
    pub fn unwatch_faces(&self, id: u64) -> bool {
        let mut guard = self.lock();
        let before = guard.face_watchers.len();
        guard.face_watchers.retain(|(held, _)| *held != id);
        guard.face_watchers.len() != before
    }

    /// R2259 — deliver one face transition to every registered observer.
    ///
    /// The sinks are CLONED OUT of the lock before any runs. A sink reaches C
    /// code, and C code is free to re-enter this registry — declaring a
    /// subscriber, or undeclaring the very listener being invoked — so holding
    /// the lock across the call would deadlock on exactly the paths a C program
    /// is most likely to take. That is the same discipline `face_down` states
    /// for dropping a `FaceEntry` outside the lock.
    fn fire_face_event(&self, kind: FaceEventKind, snapshot: &FaceSnapshot) {
        let sinks: Vec<FaceEventSink> = self
            .lock()
            .face_watchers
            .iter()
            .map(|(_, sink)| sink.clone())
            .collect();
        for sink in sinks {
            sink(kind, snapshot);
        }
    }

    /// This registry's monotonic clock reading, in milliseconds.
    ///
    /// R311y529 — exposed for `z_timestamp_new`, which needs a time source and
    /// must use the SAME one the session drives on: two clocks would let a
    /// stamped sample carry a time the session's own scheduling disagrees with.
    pub fn now_monotonic_ms(&self) -> u64 {
        use wz_runtime_core::TimeSource;
        self.clock.now_monotonic_ms()
    }

    /// Every connected peer's `(zid, whatami)`, as the INIT exchange recorded
    /// them — the input to pico's `z_info_peers_zid` / `z_info_routers_zid`.
    ///
    /// A face whose INIT has not populated the slots yet is SKIPPED rather than
    /// reported with a zero id: pico enumerates established transports, and a
    /// half-open face is not one. `whatami` is the raw 2-bit wire form
    /// (0 Router, 1 Peer, 2 Client) so the split between the two `z_info_*`
    /// exports is made at the ABI boundary, where pico makes it, rather than
    /// here.
    pub fn peer_identities(&self) -> Vec<(Vec<u8>, u8)> {
        self.face_sessions()
            .into_iter()
            .filter_map(|session| {
                let actions = session.actions();
                Some((actions.peer_zid()?, actions.peer_whatami_wire()?))
            })
            .collect()
    }

    /// Whether any connected peer is a ROUTER — zenoh-pico's
    /// `_z_session_has_router_peer`, the condition under which a peer-mode
    /// session sends Interests at all. R2962.
    ///
    /// Read off the same INIT record as [`Self::peer_identities`], so a
    /// half-open face is not counted, and `0` is the wire form of a router.
    pub fn has_router_peer(&self) -> bool {
        const WIRE_ROUTER: u8 = 0;
        self.peer_identities()
            .into_iter()
            .any(|(_, whatami)| whatami == WIRE_ROUTER)
    }

    /// Open a TX batching window on every face (pico `zp_batch_start`).
    ///
    /// pico has ONE transport, so its batch control is a single call; wz holds N
    /// faces, so the window is opened on each. Returns the number of faces that
    /// accepted it — a session with no peer batches nothing and reports 0, which
    /// is not an error (pico's own `zp_batch_start` on a closed session is the
    /// error case, and that maps to the handle being invalid, not to zero
    /// faces).
    pub fn batch_start_all(&self) -> usize {
        self.face_sessions()
            .into_iter()
            .filter(|session| session.batch_start().is_ok())
            .count()
    }

    /// Flush every face's open batch window (pico `zp_batch_flush`).
    pub fn batch_flush_all(&self) -> usize {
        self.face_sessions()
            .into_iter()
            .filter(|session| session.batch_flush().is_ok())
            .count()
    }

    /// Close every face's batch window, draining what it holds (pico
    /// `zp_batch_stop`).
    pub fn batch_stop_all(&self) -> usize {
        self.face_sessions()
            .into_iter()
            .filter(|session| session.batch_stop().is_ok())
            .count()
    }

    /// A snapshot of every connected face's session PAIRED with its re-arm
    /// signal — what [`crate::get::fan_get`] iterates.
    ///
    /// Paired rather than looked up per face afterwards because the two must
    /// come from the same snapshot: a face that leaves the registry between the
    /// two reads would otherwise have its query issued and its wake never
    /// notified.
    pub fn face_sessions_with_wake(&self) -> Vec<(TokioSession, Arc<Notify>)> {
        self.lock()
            .faces
            .values()
            .map(|face| (face.session.clone(), face.revised.clone()))
            .collect()
    }

    /// Face `id`'s drive-loop re-arm signal (see [`FaceEntry::revised`]).
    pub fn deadline_revised(&self, id: u64) -> Option<Arc<Notify>> {
        self.lock().faces.get(&id).map(|face| face.revised.clone())
    }

    /// Record a C subscription in the SSOT and declare it on every live face.
    ///
    /// The SSOT entry is the LOCAL registration and is recorded
    /// unconditionally, mirroring pico: `_z_register_subscriber` records the
    /// subscription in the session tables first and its wire announce to peers
    /// is best-effort after (`~/zenoh-pico/src/net/primitives.c:209-248`). So a
    /// per-face wire declare that fails (a face mid-teardown) is ignored exactly
    /// as [`Self::face_up`] ignores a failed replay, and the SSOT entry persists
    /// so every FUTURE face still gets it. With no face yet (a listener before
    /// its first peer) this declares nothing on the wire and still records the
    /// entry — pico's declare-before-peer. Infallible today; keyexpr canonicity
    /// validation is a separate follow-up.
    /// Allocate the next session-scope ENTITY id (R311y559).
    ///
    /// The `eid` half of the `(zid, eid)` global id `z_publisher_id` /
    /// `z_querier_id` and their advanced siblings report. Allocated at DECLARE
    /// and held by the handle, never re-derived per call: upstream's id is
    /// stable for a handle's whole life, and a counter read per accessor would
    /// hand back a different answer each time it was asked.
    pub fn next_entity_id(&self) -> u64 {
        let mut guard = self.lock();
        let id = guard.next_entity_id;
        guard.next_entity_id = guard.next_entity_id.wrapping_add(1);
        id
    }

    pub fn declare_subscriber(
        &self,
        keyexpr: String,
        allowed_origin: Locality,
        sink: SubscriberSink,
    ) -> SubId {
        self.declare_subscriber_on_wire(keyexpr, WireKey::literal(), allowed_origin, None, sink)
    }

    /// [`Self::declare_subscriber`], announced to every peer as `wire` and
    /// retracted naming `retraction` when the declaring ABI's reference
    /// library does (`None` retracts by id alone).
    pub fn declare_subscriber_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        allowed_origin: Locality,
        retraction: Option<RetractionKey>,
        sink: SubscriberSink,
    ) -> SubId {
        let mut guard = self.lock();
        let id = guard.next_sub_id;
        guard.next_sub_id = guard.next_sub_id.wrapping_add(1);

        // R311y557 — the LOCAL PLANE is in this walk, which is what makes an
        // in-process put reach this subscriber whether or not a peer exists.
        // Its `allowed_origin` is the caller's own, so a `Remote`-only
        // subscriber still refuses its own session's put — the filter is
        // applied by the registry, not by which registry holds it.
        //
        // R2580 — and it is in the walk rather than in a second block after it.
        // The second block is what the other six planes did not have.
        for face in guard.declaration_targets() {
            if let Some(sub) = declare_subscriber_on(
                &face.session,
                &keyexpr,
                &wire,
                SubscribeOptions::default()
                    .with_allowed_origin(allowed_origin)
                    .with_retraction_naming(retraction.clone()),
                sink(),
            ) {
                face.subs.insert(id, sub);
            }
        }
        guard.subs.push(SubEntry {
            id,
            keyexpr,
            allowed_origin,
            wire,
            retraction,
            sink,
        });
        id
    }

    /// Record a C matching listener in the SSOT and install it on every live
    /// face, delivering the CURRENT session verdict if it is already `true`.
    ///
    /// ## Why the verdict is aggregated instead of passed through
    ///
    /// A C program holds ONE `z_owned_matching_listener_t` and asks one
    /// question: does anybody out there subscribe to what I publish. wz answers
    /// it per FACE, because the remote-subscriber registry is per-session and a
    /// session is per-peer. Forwarding each face's verdict straight to C would
    /// therefore report the opposite of the truth in the ordinary two-peer
    /// case: peer B undeclaring its subscriber would deliver
    /// `matching = false` — upstream's `z_pub.c` prints "Publisher has NO MORE
    /// matching subscribers." — while peer A is still subscribed and every
    /// subsequent put still reaches it. pico has no such split (one session,
    /// one write-filter context, `src/net/filtering.c`), so parity here is
    /// specifically the aggregation: the C verdict is the OR across faces, and
    /// it is delivered only when that OR moves.
    ///
    /// ## Registration happens OUTSIDE the registry lock
    ///
    /// Deliberate, and not merely tidy: `Publisher::declare_matching_listener`
    /// delivers an already-matching registration synchronously (pico's
    /// fire-before-insert), so installing it under the lock would run a C
    /// callback while holding the mutex every `z_declare_*` needs — and that
    /// callback is entitled to declare. So the SSOT entry is pushed under the
    /// lock, the per-face installs run unlocked, and the handles are filed back
    /// in a second short critical section. A face that left in between simply
    /// has no handle filed; its listener handle is dropped after the lock is
    /// released.
    pub fn declare_matching_listener(&self, keyexpr: String, sink: MatchingSink) -> MatchId {
        self.declare_matching_listener_scoped(keyexpr, sink, MatchScope::RemoteSubscribers)
    }

    /// The shared body of the publisher and querier declare forms — see
    /// [`MatchScope`] for why the scope is recorded on the entry.
    fn declare_matching_listener_scoped(
        &self,
        keyexpr: String,
        sink: MatchingSink,
        scope: MatchScope,
    ) -> MatchId {
        // R311y535 — the sink moves INTO the aggregate, which is now its ONE
        // owner. The `MatchEntry` keeps only the shared handle.
        let state = Arc::new(StdMutex::new(MatchAggregate::new(sink)));
        // Phase 1 — allocate the id, publish the SSOT entry, snapshot the faces.
        let (id, faces) = {
            let mut guard = self.lock();
            let id = guard.next_match_id;
            guard.next_match_id = guard.next_match_id.wrapping_add(1);
            let faces: Vec<(u64, TokioSession)> = guard
                .faces
                .iter()
                .map(|(fid, face)| (*fid, face.session.clone()))
                .collect();
            guard.matches.push(MatchEntry {
                id,
                keyexpr: keyexpr.clone(),
                state: state.clone(),
                scope,
            });
            (id, faces)
        };

        // Phase 2 — install per face with NO lock held, so an already-matching
        // face may deliver its `true` to C right here.
        let mut installed = Vec::new();
        {
            let guard = self.lock();
            let entry = guard
                .matches
                .iter()
                .find(|e| e.id == id)
                .expect("the entry pushed in phase 1 is still present");
            let callbacks: Vec<_> = faces
                .iter()
                .map(|(fid, _)| face_matching_callback(*fid, entry))
                .collect();
            drop(guard);
            for ((fid, session), callback) in faces.into_iter().zip(callbacks) {
                if let Some(listener) = scope.install(&session, &keyexpr, callback) {
                    installed.push((fid, listener));
                }
            }
        }

        // Phase 3 — file the handles back; a face that left keeps none.
        let mut orphans = Vec::new();
        {
            let mut guard = self.lock();
            for (fid, listener) in installed {
                match guard.faces.get_mut(&fid) {
                    Some(face) => {
                        face.matches.insert(id, listener);
                    }
                    None => orphans.push(listener),
                }
            }
        }
        drop(orphans);
        id
    }

    /// The QUERIER-side twin of [`Self::declare_matching_listener`]: watch for
    /// remote QUERYABLES rather than remote subscribers.
    ///
    /// R311y528 — the publisher half shipped at R311y527 and this one did not,
    /// which left `z_querier_get_matching_status` and the two
    /// `z_querier_declare_*_matching_listener` forms unexported while all 19
    /// publisher-side names were present. That asymmetry is the exact shape the
    /// matching module's own header warns about, and it went unnoticed because
    /// the ranking was by PROGRAMS BLOCKED and no upstream example calls the
    /// querier form.
    ///
    /// Everything else — the cross-face OR, the three-phase install, the
    /// [`deliver_matching_flip`] serialisation — is shared with the publisher
    /// path by construction: the only difference is which declaration the
    /// per-face watch is installed on.
    pub fn declare_querier_matching_listener(
        &self,
        keyexpr: String,
        sink: MatchingSink,
    ) -> MatchId {
        self.declare_matching_listener_scoped(keyexpr, sink, MatchScope::RemoteQueryables)
    }

    /// The SESSION's matching verdict for a QUERIER's `keyexpr` (pico
    /// `z_querier_get_matching_status`): `true` when any connected peer has a
    /// matching QUERYABLE, or this session itself declared one. The publisher
    /// twin is [`Self::has_matching`].
    ///
    /// R2579 — over [`Self::matching_planes`], not `face_sessions`: the doc on
    /// that method carries the measurement, and the clause this sentence used to
    /// open with ("ANY connected peer") was the defect written down.
    pub fn has_matching_queryable(&self, keyexpr: &str) -> bool {
        self.matching_planes().into_iter().any(|session| {
            session
                .declare_querier(keyexpr.to_owned(), QueryOptions::default())
                .get_matching_status()
                .matching
        })
    }

    /// The SESSION's matching verdict for `keyexpr` (pico
    /// `z_publisher_get_matching_status`): `true` when any connected peer has a
    /// matching subscriber, or this session itself declared one.
    ///
    /// The OR is the same aggregation [`Self::declare_matching_listener`]
    /// delivers, computed fresh here rather than read off a listener's cached
    /// state — so the poll answers correctly for a publisher that never declared
    /// a listener at all, and cannot disagree with one that did.
    ///
    /// ⚠ R2579 — it CAN still disagree with one, and in one direction only:
    /// this poll now reads [`Self::matching_planes`] while
    /// `declare_matching_listener_scoped` still installs per FACE, so a
    /// session-local subscriber with no peer connected is seen by the poll and
    /// not by the listener. Closing that is the same repair applied to the
    /// watch, and it needs a measurement this round did not take: whether the
    /// runtime's own `matching_watches` re-evaluates on a session-LOCAL
    /// declaration at all, since its documented re-evaluation arms are the
    /// REMOTE `DeclSubscriber` / `UndeclSubscriber` ones.
    ///
    /// Sessions are snapshotted out of the lock before being consulted, the
    /// same discipline as every other fan-out here: `get_matching_status` takes
    /// the face's observer mutex, and taking it under the registry lock would
    /// invert the two locks' order against the drive thread.
    pub fn has_matching(&self, keyexpr: &str) -> bool {
        self.matching_planes().into_iter().any(|session| {
            session
                .declare_publisher(keyexpr.to_owned(), PublishOptions::put())
                .get_matching_status()
                .matching
        })
    }

    /// Declare a WRITE FILTER — zenoh-pico's `_z_write_filter_create`, which a
    /// publisher or querier does once, at declare.
    ///
    /// `ask` is how every peer is asked what the filter counts, or `None` to ask
    /// none of them (a pico peer with no router among its peers asks nobody); the
    /// entry is replayed onto every
    /// face that comes up later, as each other declaration here is. The filter
    /// reads what peers DECLARE, so it needs no callback and has no cached
    /// state: [`Self::write_filter_active`] asks the registries when it is
    /// asked, which is why it cannot drift from what the peers said.
    ///
    /// The local plane is not asked and not counted. zenoh-pico's default build
    /// counts no session-local subscriber (`Z_FEATURE_LOCAL_SUBSCRIBER` is 0),
    /// and the plane's link is inert.
    pub fn declare_write_filter(
        &self,
        plane: FilterPlane,
        keyexpr: String,
        ask: Option<InterestForm>,
    ) -> FilterId {
        let mut guard = self.lock();
        guard.next_filter_id = guard.next_filter_id.wrapping_add(1);
        let id = guard.next_filter_id;
        if let Some(form) = &ask {
            for face in guard.faces.values_mut() {
                let hold = match plane {
                    FilterPlane::Subscribers => {
                        face.session.hold_subscribers_interest(&keyexpr, form)
                    }
                    FilterPlane::Queryables { .. } => {
                        face.session.hold_queryables_interest(&keyexpr, form)
                    }
                };
                face.filters.insert(id, hold);
            }
        }
        guard.filters.push(FilterEntry {
            id,
            plane,
            keyexpr,
            ask,
        });
        id
    }

    /// Retract a write filter: drop the SSOT entry so no future face asks, and
    /// release every face's Interest (each emitting its `Interest(Final)` once
    /// no other holder of that key remains).
    ///
    /// Released OUTSIDE the registry lock, as every teardown here is: a hold's
    /// drop reaches the face's session and its link.
    pub fn undeclare_write_filter(&self, id: FilterId) {
        let mut dropped = Vec::new();
        {
            let mut guard = self.lock();
            if let Some(pos) = guard.filters.iter().position(|e| e.id == id) {
                guard.filters.remove(pos);
            }
            for face in guard.faces.values_mut() {
                if let Some(hold) = face.filters.remove(&id) {
                    dropped.push(hold);
                }
            }
        }
        drop(dropped);
    }

    /// Whether the filter says NOTHING matches — zenoh-pico's
    /// `_z_write_filter_active`, and the reason a put, delete or get is not
    /// sent. `true` until a peer has declared something the filter counts, which
    /// is the state a filter is CREATED in (`ctx->state = WRITE_FILTER_ACTIVE`),
    /// so a publisher with no peer yet suppresses, as upstream's does.
    ///
    /// An unknown id answers `false`: not filtered. A handle that outlived its
    /// filter should send rather than drop silently.
    ///
    /// The registries are read OUTSIDE the registry lock: a face's observer
    /// mutex is taken to answer, and holding this one across it would invert
    /// their order against the drive thread.
    pub fn write_filter_active(&self, id: FilterId) -> bool {
        let (plane, keyexpr, sessions) = {
            let guard = self.lock();
            let Some(entry) = guard.filters.iter().find(|e| e.id == id) else {
                return false;
            };
            let sessions: Vec<TokioSession> = guard
                .faces
                .values()
                .map(|face| face.session.clone())
                .collect();
            (entry.plane, entry.keyexpr.clone(), sessions)
        };
        // `Remote`: only what a peer declared counts. See `declare_write_filter`.
        let matching = sessions.iter().any(|session| match plane {
            FilterPlane::Subscribers => {
                session.remote_subscribers_match(&keyexpr, Locality::Remote)
            }
            FilterPlane::Queryables { complete_required } => {
                session.remote_queryables_match(&keyexpr, Locality::Remote, complete_required)
            }
        });
        !matching
    }

    /// Drop a C matching listener: remove the SSOT entry so no future face
    /// installs it, and undeclare every face's watch.
    ///
    /// The per-face `MatchingListener::undeclare` is called explicitly rather
    /// than left to the handle's drop, because wz's handle has no `Drop` hook —
    /// dropping it leaves the watch installed, which would keep firing the
    /// aggregate for a listener C has already released.
    pub fn undeclare_matching_listener(&self, id: MatchId) {
        let mut removed = Vec::new();
        let mut entry = None;
        {
            let mut guard = self.lock();
            if let Some(pos) = guard.matches.iter().position(|e| e.id == id) {
                entry = Some(guard.matches.remove(pos));
            }
            // R2580 — the plane's watch too, now that it has one.
            for face in guard.declaration_targets() {
                if let Some(listener) = face.matches.remove(&id) {
                    removed.push(listener);
                }
            }
        }
        // OUTSIDE the lock: `undeclare` reaches into the face session's
        // observer.
        for listener in removed {
            listener.undeclare();
        }
        // R311y535 — RETIRE the sink, which is what makes this call free the C
        // context before it returns rather than whenever the last `Arc` clone
        // happened to fall. Taking the aggregate mutex is the exclusion: a
        // delivery in flight holds it across its C call
        // ([`deliver_matching_flip`]), so the lock is granted only once no
        // thread is inside the callback, and a delivery that arrives afterwards
        // finds `None`.
        //
        // The taken sink is dropped AFTER the guard, per this file's
        // drop-outside-the-lock discipline: the C `drop(context)` may re-enter
        // the session, and it must not do so holding an aggregate.
        //
        // The re-entrant case is the exception and is handled rather than
        // deadlocked: when this thread is already inside a matching callback,
        // the mutex it would wait on is the one its own frame holds. There, the
        // sink is left in place and released by `Arc` drop when the entry falls,
        // which is the pre-R311y535 behaviour and the only outcome available to
        // a caller undeclaring from inside its own context.
        let retired = entry
            .as_ref()
            .and_then(|entry| retire_matching_sink(&entry.state));
        drop(retired);
        drop(entry);
    }

    /// Drop a C subscription: remove it from the SSOT so no future face
    /// replays it, and drop every face's wz subscriber for it (each emitting
    /// its wire undeclare).
    pub fn undeclare_subscriber(&self, id: SubId) {
        let mut dropped = Vec::new();
        let mut dropped_entry = None;
        let mut dropped_live = Vec::new();
        let mut dropped_live_entry = None;
        {
            let mut guard = self.lock();
            // Remove the SSOT entry into a binding rather than `retain`-dropping
            // it in place: with no live face (a listener that never had a peer,
            // or one whose per-face declares all failed) the entry holds the
            // LAST `Arc<CClosure>`, so dropping it here would run the C
            // `drop(context)` under the lock.
            if let Some(pos) = guard.subs.iter().position(|entry| entry.id == id) {
                dropped_entry = Some(guard.subs.remove(pos));
            }
            // R311y557 — the local plane's copy comes out in the same walk and
            // into the same out-of-lock drop list: with no face at all the plane
            // holds the last `Arc<CClosure>` and dropping it here would run the
            // C `drop(context)` under the registry lock — precisely the case the
            // SSOT entry above was already careful about.
            for face in guard.declaration_targets() {
                if let Some(sub) = face.subs.remove(&id) {
                    dropped.push(sub);
                }
            }
            // The LIVELINESS subscriptions share this id space (see
            // `declare_liveliness_subscriber`), so an id belongs to exactly one
            // of the two maps and both must be searched — a `z_owned_subscriber_t`
            // does not record which kind it came from, and it should not have to.
            if let Some(pos) = guard.live_subs.iter().position(|entry| entry.id == id) {
                let entry = guard.live_subs.remove(pos);
                dropped_live_entry = Some(entry);
            }
            // R2580 — the plane's liveliness subscriber comes out here too, the
            // twin of the ordinary-subscriber walk above.
            for face in guard.declaration_targets() {
                if let Some(sub) = face.live_subs.remove(&id) {
                    dropped_live.push(sub);
                }
            }
        }
        // Drop OUTSIDE the lock: releasing the last `Arc<CClosure>` — whether
        // the final per-face subscriber or the SSOT entry — runs the C
        // `drop(context)`, which must not run under the registry lock (a drop
        // that re-enters the session would deadlock the non-reentrant mutex).
        drop(dropped);
        drop(dropped_entry);
        drop(dropped_live);
        drop(dropped_live_entry);
    }

    /// Record a C ADVANCED publisher in the SSOT and declare it on every live
    /// face, with the same declare-before-peer semantics as every other plane
    /// here: no face yet -> the entry is still recorded and every future face
    /// replays it.
    ///
    /// The per-face declaration is not an implementation detail of this
    /// registry, it is what the plane needs: an advanced publisher owns an
    /// `@adv` cache queryable and an `@adv` liveliness token, and both are
    /// per-session entities a subscriber reaches over ONE face.
    pub fn declare_advanced_publisher(
        &self,
        keyexpr: String,
        options: AdvancedPublisherOptions,
    ) -> AdvPubId {
        let mut guard = self.lock();
        let id = guard.next_adv_pub_id;
        guard.next_adv_pub_id = guard.next_adv_pub_id.wrapping_add(1);
        // R2580 — the plane included. MEASURED against `libzenohc.so`: an
        // advanced publisher and an advanced subscriber on ONE session saw
        // nothing (`after=0` against upstream's `2`), while across a real face
        // both saw both puts. ⚠ The plane's `runtime` is `None`, so the guard
        // below does not enter for it; that is sound on this field's own terms
        // (R2366 moved the one measured spawner onto the process partition) and
        // the in-process leg is what holds it to that.
        for face in guard.declaration_targets() {
            let zid = face.session.actions().params.zid.clone();
            // Enter the face's own runtime: this call site is the C application
            // thread, and a declaration may spawn. R2366 moved the beacon onto
            // the `net` subsystem, which needs no ambient runtime, so this is
            // now a defence for the rest of the declare rather than the single
            // thing the beacon depended on. See `FaceEntry::runtime`.
            let _guard = face.runtime.as_ref().map(|rt| rt.enter());
            if let Ok(pub_) =
                // R2619 — cloned per face, as the keyexpr beside it already is:
                // the options own a `String` now and this loop declares one
                // publisher per face from the same value.
                AdvancedPublisher::declare(
                    &face.session,
                    keyexpr.clone(),
                    options.clone(),
                    zid,
                )
            {
                face.adv_pubs.insert(id, pub_);
            }
        }
        guard.adv_pubs.push(AdvPubEntry {
            id,
            keyexpr,
            options,
        });
        id
    }

    /// Publish one payload through a C advanced publisher, on every face that
    /// carries it. Returns the number of faces that accepted it.
    ///
    /// Best-effort per face, like the ordinary fan-out publish: a face
    /// mid-teardown is skipped rather than failing the whole put, because a C
    /// caller has no per-face handle to retry with.
    pub fn advanced_publisher_put(&self, id: AdvPubId, payload: &[u8]) -> usize {
        let guard = self.lock();
        let mut delivered = 0usize;
        // R2580 — the plane included, or the put reaches every peer and not the
        // session's own advanced subscriber.
        for face in guard.declaration_targets_ref() {
            if let Some(pub_) = face.adv_pubs.get(&id) {
                if pub_.put(payload).is_ok() {
                    delivered += 1;
                }
            }
        }
        delivered
    }

    /// R3063 -- [`Self::advanced_publisher_put`] for a payload that is a CHUNK of shared memory: each
    /// face sends the sample as the chunk's descriptor to a peer that negotiated shared memory and as
    /// its bytes to one that did not, stamps and sequences it exactly as the bytes would be, and
    /// caches the chunk, not a copy of it, so a recovery reply replays it as shared memory. A face
    /// takes the reference its receiver will release on its own, so several faces are several
    /// references.
    #[cfg(feature = "transport-shm")]
    pub fn advanced_publisher_put_shm(
        &self,
        id: AdvPubId,
        payload: &std::sync::Arc<wz_runtime_tokio::shm_provider::ShmBackedPayload>,
    ) -> usize {
        let guard = self.lock();
        let mut delivered = 0usize;
        // The plane included, for the reason the byte put names.
        for face in guard.declaration_targets_ref() {
            if let Some(pub_) = face.adv_pubs.get(&id) {
                if pub_
                    .put_shm_with(
                        payload,
                        wz_runtime_tokio::advanced_publisher::AdvancedPutOptions::default(),
                    )
                    .is_ok()
                {
                    delivered += 1;
                }
            }
        }
        delivered
    }

    /// Publish a DELETE through a C advanced publisher, on every face that
    /// carries it (R311y559). `true` when at least one face accepted it.
    ///
    /// Best-effort per face for the same reason [`Self::advanced_publisher_put`]
    /// is: a C caller has no per-face handle to retry with.
    pub fn advanced_publisher_delete(&self, id: AdvPubId) -> bool {
        let guard = self.lock();
        let mut delivered = false;
        // R2580 — the plane included, same reason as the put.
        for face in guard.declaration_targets_ref() {
            if let Some(pub_) = face.adv_pubs.get(&id) {
                delivered |= pub_.delete().is_ok();
            }
        }
        delivered
    }

    /// Retract a C advanced publisher: drop the SSOT entry so no future face
    /// replays it, and drop every live face's publisher (which undeclares that
    /// face's `@adv` cache queryable + liveliness token through RAII).
    pub fn undeclare_advanced_publisher(&self, id: AdvPubId) {
        let mut dropped = Vec::new();
        {
            let mut guard = self.lock();
            if let Some(pos) = guard.adv_pubs.iter().position(|entry| entry.id == id) {
                guard.adv_pubs.remove(pos);
            }
            // R2580 — the plane's copy too.
            for face in guard.declaration_targets() {
                if let Some(pub_) = face.adv_pubs.remove(&id) {
                    dropped.push(pub_);
                }
            }
        }
        // Outside the lock: the teardown emits undeclares and may run C drops.
        drop(dropped);
    }

    /// Record a C ADVANCED subscriber in the SSOT and declare it on every live
    /// face. Mirror of [`Self::declare_advanced_publisher`].
    pub fn declare_advanced_subscriber(
        &self,
        keyexpr: String,
        options: AdvancedSubscriberOptions,
        sink: AdvancedSubscriberSink,
    ) -> AdvSubId {
        self.declare_advanced_subscriber_with(keyexpr, options, None, sink)
    }

    /// [`Self::declare_advanced_subscriber`] for a host that declares KEYS:
    /// `forms` says how each entity of the subscriber is named on the wire
    /// ([`DeclarationForms`]).
    ///
    /// The registry adds the one thing it owns and a host has no way to know
    /// before this call returns: the subscriber's identity, its own
    /// [`AdvSubId`]. The subscriber is declared once per face, each face with
    /// its own plain subscription id, and the identity the C handle reports and
    /// the detection token is named with has to be the same on all of them.
    pub fn declare_advanced_subscriber_declaring_keys(
        &self,
        keyexpr: String,
        options: AdvancedSubscriberOptions,
        forms: Arc<dyn DeclarationForms>,
        sink: AdvancedSubscriberSink,
    ) -> AdvSubId {
        self.declare_advanced_subscriber_with(keyexpr, options, Some(forms), sink)
    }

    fn declare_advanced_subscriber_with(
        &self,
        keyexpr: String,
        mut options: AdvancedSubscriberOptions,
        forms: Option<Arc<dyn DeclarationForms>>,
        sink: AdvancedSubscriberSink,
    ) -> AdvSubId {
        // ## THE PER-FACE DECLARATIONS RUN OUTSIDE THE REGISTRY LOCK
        //
        // An advanced subscriber is not one declaration but a sequence — the
        // subscription, a startup history GET, the late-publisher and heartbeat
        // subscriptions, a detection token — and a host that declares keys
        // ([`wz_runtime_tokio::advanced_subscriber::DeclarationForms`]) declares
        // a key for each of them as it goes, which takes this lock.
        // Holding it across the sequence deadlocks that host on its first key.
        //
        // The history GET is the same hazard in another costume and was there
        // before any host declared a key: in loopback it completes inside the
        // declaration and runs the C sample callback, which a C program is
        // entitled to use to re-enter the session. The matching listeners are
        // installed outside the lock for the same reason.
        //
        // ## What makes that safe
        //
        // The entry is recorded and the targets taken in ONE critical section.
        // A face that comes up afterwards replays the entry (`face_up` takes its
        // own snapshot under the same lock it inserts the face under), and a
        // face that is already up is in `targets` — so every face declares the
        // subscriber exactly once, whichever side of this section it is on.
        let hosted = forms.is_some();
        let (id, targets) = {
            let mut guard = self.lock();
            let id = guard.next_adv_sub_id;
            guard.next_adv_sub_id = guard.next_adv_sub_id.wrapping_add(1);
            if let Some(host) = forms {
                options = options.with_declaration_forms(Arc::new(IdentifiedForms { id, host }));
            }
            guard.adv_subs.push(AdvSubEntry {
                id,
                keyexpr: keyexpr.clone(),
                options: options.clone(),
                sink: Arc::clone(&sink),
            });
            (id, guard.declaration_target_handles())
        };
        // R2580 — the plane included; the receiving half of the advanced
        // measurement recorded on `declare_advanced_publisher`.
        for (target, session, runtime) in targets {
            let (on_sample, on_miss) = (sink)();
            // Same reason as the publisher's: a `recovery.periodic_queries`
            // subscriber spawns a background task at declare time — and, since
            // R2366, that task names the `app` subsystem, so this guard is the
            // same defence-in-depth the publisher's now is.
            let _guard = runtime.as_ref().map(|rt| rt.enter());
            // The local plane has no wire to name anything on; see [`Unnamed`].
            let for_target = match target {
                DeclarationTarget::Local if hosted => {
                    options
                        .clone()
                        .with_declaration_forms(Arc::new(IdentifiedForms {
                            id,
                            host: Arc::new(Unnamed),
                        }))
                }
                // Cloned per face: the loop declares one subscriber on each,
                // and the options are no longer `Copy` (R311y826).
                _ => options.clone(),
            };
            // R2814 — seeded for the same reason as the replay in `face_up`.
            if let Ok(sub) = AdvancedSubscriber::declare_with_options_and_miss_listener(
                &session,
                keyexpr.clone(),
                for_target,
                on_sample,
                on_miss,
            ) {
                self.attach_advanced_subscriber(target, &session, id, sub);
            }
        }
        id
    }

    /// File a per-face advanced subscriber declared outside the registry lock
    /// ([`Self::declare_advanced_subscriber`], [`Self::face_up`]) in its face.
    ///
    /// It is filed only if what it was declared for still stands: the C
    /// subscriber is still declared (it may have been undeclared while this was
    /// being made), and the target is still the very session it was declared on
    /// (a face id is reused by a reconnect, and a subscriber declared on the old
    /// session filed under the new one would be retracted on a session that is
    /// gone). Otherwise it is dropped — outside the lock, because dropping it
    /// retracts its entities and releases its C closures.
    fn attach_advanced_subscriber(
        &self,
        target: DeclarationTarget,
        session: &TokioSession,
        id: AdvSubId,
        sub: AdvancedSubscriber<TokioRuntime>,
    ) {
        let rejected = {
            let mut guard = self.lock();
            let declared = guard.adv_subs.iter().any(|entry| entry.id == id);
            let face = match target {
                DeclarationTarget::Face(face_id) => guard.faces.get_mut(&face_id),
                DeclarationTarget::Local => guard.local_face.as_mut(),
            };
            match face {
                Some(face) if declared && face.session.is_same_session(session) => {
                    face.adv_subs.insert(id, sub)
                }
                _ => Some(sub),
            }
        };
        drop(rejected);
    }

    /// Retract a C advanced subscriber. Mirror of
    /// [`Self::undeclare_advanced_publisher`].
    pub fn undeclare_advanced_subscriber(&self, id: AdvSubId) {
        let mut dropped = Vec::new();
        let mut dropped_entry = None;
        {
            let mut guard = self.lock();
            if let Some(pos) = guard.adv_subs.iter().position(|entry| entry.id == id) {
                dropped_entry = Some(guard.adv_subs.remove(pos));
            }
            // R2580 — the plane's copy too.
            for face in guard.declaration_targets() {
                if let Some(sub) = face.adv_subs.remove(&id) {
                    dropped.push(sub);
                }
            }
        }
        // Outside the lock: the SSOT entry holds the sink factory, whose last
        // release runs the C `drop(context)`.
        drop(dropped);
        drop(dropped_entry);
    }

    /// The keyexpr a C advanced subscriber was declared on, for the derived
    /// `<ke>/@adv/pub/**` publisher-detection subscription.
    pub fn advanced_subscriber_keyexpr(&self, id: AdvSubId) -> Option<String> {
        let guard = self.lock();
        guard
            .adv_subs
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| entry.keyexpr.clone())
    }

    /// R2932 — join the zenoh-ext GROUP `gid` as `member`: record it in the
    /// SSOT and join it on the local plane and on every live face. Returns
    /// the C-level id and the [`GroupAggregate`] the C program reads.
    ///
    /// The PLANE joins first and its result is the verdict. Its join makes
    /// every check a join can fail (canonical ids, no wildcards) and nothing a
    /// per-face join adds can fail differently, so a refusal there is the
    /// refusal the C program gets and nothing is recorded. The faces are then
    /// best-effort, like every other per-face declaration: a face mid-teardown
    /// is skipped, and `face_up` covers every face that arrives later.
    pub fn join_group(
        &self,
        gid: String,
        member: Member,
        priority: Priority,
    ) -> Result<(GroupId, Arc<GroupAggregate>), GroupError> {
        let agg = Arc::new(GroupAggregate::new(gid, member));
        let mut guard = self.lock();
        // `local_face` is `Some` for the session's whole life (see the field);
        // the `Option` is only `Inner: Default`'s.
        let plane_copy = guard
            .local_face
            .as_ref()
            .map(|plane| FaceGroup::join(&plane.session, &agg, Locality::SessionLocal, priority))
            .transpose()?;
        let id = guard.next_group_id;
        guard.next_group_id = guard.next_group_id.wrapping_add(1);
        for face in guard.faces.values_mut() {
            if let Ok(copy) = FaceGroup::join(&face.session, &agg, Locality::Remote, priority) {
                face.groups.insert(id, copy);
            }
        }
        if let (Some(plane), Some(copy)) = (guard.local_face.as_mut(), plane_copy) {
            plane.groups.insert(id, copy);
        }
        guard.groups.push(GroupEntry {
            id,
            agg: Arc::clone(&agg),
            priority,
        });
        drop(guard);
        // The plane copy announced itself with a loopback publish; the plane's
        // stage wake already fired for it, and this is the same permit.
        self.wake_local_plane();
        Ok((id, agg))
    }

    /// R2932 — leave a C group: drop the SSOT entry so no future face replays
    /// it, and drop every session's copy.
    ///
    /// The C sink is retired FIRST, so the teardown cannot deliver into a
    /// group the C program has already released, and so its `drop(context)`
    /// runs before this returns — unless this is called from inside that
    /// group's own callback, where the sink falls with the aggregate instead
    /// (see `GroupAggregate::retire`).
    pub fn leave_group(&self, id: GroupId) {
        let mut copies = Vec::new();
        let agg = {
            let mut guard = self.lock();
            let agg = guard
                .groups
                .iter()
                .position(|entry| entry.id == id)
                .map(|pos| guard.groups.remove(pos).agg);
            for face in guard.declaration_targets() {
                if let Some(copy) = face.groups.remove(&id) {
                    copies.push(copy);
                }
            }
            agg
        };
        let sink = agg.as_ref().and_then(|agg| agg.retire());
        // Outside the lock: dropping a copy undeclares its subscriber and
        // queryable on that session.
        drop(copies);
        drop(sink);
    }

    /// Record a C queryable in the SSOT and declare it on every live face —
    /// the responder-side mirror of [`Self::declare_subscriber`], with the
    /// same declare-before-peer semantics (no face yet → the entry is still
    /// recorded and every future face replays it).
    ///
    /// Per-face rid independence makes cross-face request-id collision
    /// unrepresentable rather than merely unlikely: each face's wz session
    /// allocates its own request ids (`alloc_next_request_id` is per
    /// `SessionLinkActions`), so two peers querying concurrently cannot
    /// correlate onto one another's reply chain.
    pub fn declare_queryable(
        &self,
        keyexpr: String,
        complete: bool,
        allowed_origin: Locality,
        sink: QueryableSink,
    ) -> QblId {
        self.declare_queryable_on_wire(
            keyexpr,
            WireKey::literal(),
            complete,
            allowed_origin,
            None,
            sink,
        )
    }

    /// [`Self::declare_queryable`], announced to every peer as `wire` and
    /// retracted naming `retraction` when the declaring ABI's reference
    /// library does (`None` retracts by id alone).
    pub fn declare_queryable_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        complete: bool,
        allowed_origin: Locality,
        retraction: Option<RetractionKey>,
        sink: QueryableSink,
    ) -> QblId {
        let mut guard = self.lock();
        let id = guard.next_qbl_id;
        guard.next_qbl_id = guard.next_qbl_id.wrapping_add(1);

        // R311y557 — the LOCAL PLANE is in this walk, which is what an
        // in-process `z_get` reaches. The sink factory receives each target's
        // OWN session for the reason it always did: an escaped query owes its
        // deferred replies and its `ResponseFinal` to the session the query
        // arrived on, and for a local query that session is the plane's.
        for face in guard.declaration_targets() {
            let callback = sink(&face.session);
            if let Some(qbl) = declare_queryable_on(
                &face.session,
                &keyexpr,
                &wire,
                queryable_options(complete, allowed_origin)
                    .with_retraction_naming(retraction.clone()),
                callback,
            ) {
                face.qbls.insert(id, qbl);
            }
        }
        guard.qbls.push(QblEntry {
            id,
            keyexpr,
            complete,
            allowed_origin,
            wire,
            retraction,
            sink,
        });
        id
    }

    /// Drop a C queryable: remove it from the SSOT so no future face replays
    /// it, and drop every face's wz queryable for it (each emitting its wire
    /// `Declare(UndeclQueryable)`). Mirror of [`Self::undeclare_subscriber`],
    /// including the drop-outside-the-lock discipline.
    pub fn undeclare_queryable(&self, id: QblId) {
        let mut dropped = Vec::new();
        let mut dropped_entry = None;
        {
            let mut guard = self.lock();
            if let Some(pos) = guard.qbls.iter().position(|entry| entry.id == id) {
                dropped_entry = Some(guard.qbls.remove(pos));
            }
            // R311y557 — the local plane's copy comes out in the same walk and
            // into the same out-of-lock drop list (see `undeclare_subscriber`
            // for why the plane's handle can be the last one alive).
            for face in guard.declaration_targets() {
                if let Some(qbl) = face.qbls.remove(&id) {
                    dropped.push(qbl);
                }
            }
        }
        // Drop OUTSIDE the lock — see `undeclare_subscriber`: the last
        // `Arc<CQueryClosure>` release runs the C `drop(context)`.
        drop(dropped);
        drop(dropped_entry);
    }
}

/// The wz queryable options one C `z_queryable_options_t` maps to.
///
/// R311y554 — `allowed_origin` is now the CALLER's, where it used to be pinned
/// `Locality::Remote`. The pin rested on two arguments and exactly one of them
/// was about this function:
///
/// **The soundness argument, which was real and is now discharged elsewhere.**
/// `Locality::Any::allows_local()` is TRUE (`wz-session-core/src/locality.rs`),
/// the `unsafe impl Sync for CQueryClosure` rests on the C application thread
/// never invoking the queryable handler, and `Session::query` ran its in-process
/// fan AND its drain on whatever thread called it. So an `Any` queryable made
/// that `unsafe impl` false the moment a C-thread `z_get` landed. What fixes it
/// is not a locality pin but [`LocalDeliveryDrain::DriveTask`], adopted by every
/// session this crate builds ([`SharedSession::face_up`]): the C thread stages,
/// the drive task drains, and there is still exactly one thread that ever calls
/// into C. Worth stating plainly, because the pin was ALSO the only thing
/// containing the same hazard on the `z_get` side — a default-locality get made
/// `Session::query` drain the whole per-session queue on the C thread whether or
/// not any local queryable matched, and no locality pin on THIS function could
/// have stopped that.
///
/// **The fidelity argument, which was always about the pico ABI, not this one.**
/// zenoh-pico's `Z_FEATURE_LOCAL_QUERYABLE` defaults to 0
/// (`vendor/zenoh-pico/CMakeLists.txt:353`), which is why its
/// `z_queryable_options_t` has no `allowed_origin` field in a default build.
/// zenoh-c has no such switch: its struct always carries the field
/// (`zenoh_commons.h:450-459`) and zenoh always serves local queries. So the two
/// ABIs want DIFFERENT defaults, which is exactly why the value is now a
/// parameter: `wz-capi-c` passes what the C caller wrote, `wz-capi-pico` passes
/// `Locality::Remote` and documents it against the CMake default.
fn queryable_options(complete: bool, allowed_origin: Locality) -> QueryableOptions {
    QueryableOptions::new()
        .with_complete(complete)
        .with_allowed_origin(allowed_origin)
}

/// The [`FaceForwarder`] the accept loop threads its held faces through. The
/// stock forwarders route BETWEEN faces (a router); this one instead lands
/// each face in the C session's registry and dispatches its inbound events
/// into that face's own session, which is what fires the C subscriber
/// callback. It holds `Arc<SharedSession>` (so it is `Send`, unlike the
/// `Rc`/`RefCell` routing forwarders) because the same registry is reachable
/// from the C thread.
pub struct CApiForwarder {
    shared: Arc<SharedSession>,
}

impl CApiForwarder {
    pub fn new(shared: Arc<SharedSession>) -> Self {
        Self { shared }
    }
}

impl FaceForwarder for CApiForwarder {
    fn register(&self, id: FaceId, actions: &Arc<SessionLinkActions>) {
        self.shared.face_up(id.0, actions);
    }

    fn deregister(&self, id: FaceId) {
        self.shared.face_down(id.0);
    }

    fn forward(&self, id: FaceId, event: IterationEvent<'_>) {
        self.shared.dispatch(id.0, event);
    }

    /// Arm this face's drive loop on its earliest pending `z_get` deadline, so
    /// [`SharedSession::dispatch`]'s sweep runs when a get is actually due.
    ///
    /// Without this the accepted faces would sweep only on the keepalive wake
    /// (~3333 ms for this crate's 10 s lease), because a query timing out is by
    /// definition traffic-free — so nothing else would wake the loop and a
    /// `timeout_ms = 100` get would report its final 33x late.
    fn next_extra_deadline_ms(&self, id: FaceId) -> Option<u64> {
        self.shared.next_reply_deadline_ms(id.0)
    }

    /// Let a C-thread `z_get` wake this face's drive loop so it re-arms on the
    /// new pending query's deadline. Without it the deadline above would only
    /// be re-read at the loop's next wake — the keepalive one, ~3333 ms away —
    /// and every get issued into an idle session would be that late.
    fn deadline_revised(&self, id: FaceId) -> Option<Arc<tokio::sync::Notify>> {
        self.shared.deadline_revised(id.0)
    }
}

#[cfg(test)]
mod matching_aggregate_tests {
    use super::*;

    /// A dummy session identity for the registry unit tests — the shape
    /// `open_blocking` mints, without the entropy call.
    fn test_zid() -> Vec<u8> {
        vec![0x11; 16]
    }

    /// R2962 — a write filter is created in the state ACTIVE, which reads as
    /// "nothing matches": zenoh-pico's `ctx->state = WRITE_FILTER_ACTIVE`, and
    /// the reason a publisher with no peer yet sends nothing. An id that has
    /// outlived its filter answers the OTHER way, so a stale handle sends
    /// rather than dropping silently.
    ///
    /// Face-free by construction: what a peer's declaration does to the state
    /// needs a face and is the differential's business
    /// (`pico_keyexpr_declaration_twice_and_diff`), which opens a filter with a
    /// real router's answer.
    #[test]
    fn a_write_filter_starts_active_and_a_retracted_one_does_not_suppress() {
        let shared = SharedSession::new(TokioTime::new(), test_zid()).expect("test host entropy");
        let publisher =
            shared.declare_write_filter(FilterPlane::Subscribers, "wz/wf/pub".to_owned(), None);
        let querier = shared.declare_write_filter(
            FilterPlane::Queryables {
                complete_required: true,
            },
            "wz/wf/qry".to_owned(),
            None,
        );
        assert_ne!(publisher, querier, "each filter is its own entry");
        assert!(shared.write_filter_active(publisher));
        assert!(shared.write_filter_active(querier));

        shared.undeclare_write_filter(publisher);
        assert!(
            !shared.write_filter_active(publisher),
            "a handle that outlived its filter must send"
        );
        assert!(
            shared.write_filter_active(querier),
            "and retracting one leaves the other's state alone"
        );
        assert!(!shared.has_router_peer(), "no face, so no router peer");
    }

    /// R311y557 — the CLOSING measurement for what R311y554 pinned as a named
    /// divergence, and the test that entry said would have to change.
    ///
    /// It asserted `delivered == 0` with the reasoning that the subscriber
    /// registries live on the per-face sessions, so a session with no peer had
    /// none holding the subscription. zenoh-c WOULD deliver here (its subscriber
    /// table is session-scope), so that was a real divergence, and it was
    /// reachable as an ordinary race rather than only as a configuration.
    ///
    /// Both halves are asserted, because they are separately omittable and only
    /// one of them was ever the hard part (R311y555, one level up): `publish`
    /// returns how many subscribers MATCHED, and the callback running is a
    /// different claim that only the drain establishes.
    #[test]
    fn publish_all_delivers_locally_with_no_face() {
        let shared = SharedSession::new(TokioTime::new(), test_zid()).expect("test host entropy");
        let seen = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let sink_log = seen.clone();
        let sink: SubscriberSink = Arc::new(move || {
            let log = sink_log.clone();
            Box::new(move |sample: &dyn SampleView| {
                log.lock()
                    .expect("test mutex")
                    .push(sample.payload().to_vec());
            })
        });
        shared.declare_subscriber("wz/no/face".to_owned(), Locality::Any, sink);

        let delivered = shared
            .publish_all(
                "wz/no/face",
                b"x",
                &PublishOptions::put().with_locality(Locality::Any),
            )
            .expect("a faceless publish is not an error");
        assert_eq!(
            delivered, 1,
            "the local plane holds the subscription independently of any face, \
             so an Any put with no peer connected still matches it"
        );
        assert_eq!(
            shared.drain_local_plane(),
            1,
            "the matched fire is STAGED by the publish and RUN by the drain — \
             the two are separately omittable and a match count alone would not \
             prove the callback ran"
        );
        assert_eq!(
            seen.lock().expect("test mutex").as_slice(),
            &[b"x".to_vec()],
            "the C subscriber callback received the payload exactly once"
        );
    }

    /// R311y557 — a REMOTE-only subscriber still refuses its own session's put,
    /// with the local plane holding the subscription.
    ///
    /// The plane is not a bypass of `allowed_origin`: the filter is applied by
    /// the subscriber registry, and the plane registers with the caller's own
    /// value. Without this the plane would have SILENTLY widened every
    /// `Remote`-origin C subscriber, and the fan's own exactly-once leg could
    /// not tell the difference (it declares `Any`).
    #[test]
    fn a_remote_origin_subscriber_is_not_widened_by_the_local_plane() {
        let shared = SharedSession::new(TokioTime::new(), test_zid()).expect("test host entropy");
        let hits = Arc::new(StdMutex::new(0usize));
        let sink_hits = hits.clone();
        let sink: SubscriberSink = Arc::new(move || {
            let hits = sink_hits.clone();
            Box::new(move |_sample: &dyn SampleView| {
                *hits.lock().expect("test mutex") += 1;
            })
        });
        shared.declare_subscriber("wz/remote/only".to_owned(), Locality::Remote, sink);

        let delivered = shared
            .publish_all(
                "wz/remote/only",
                b"x",
                &PublishOptions::put().with_locality(Locality::Any),
            )
            .expect("a faceless publish is not an error");
        assert_eq!(
            delivered, 0,
            "a Remote-origin subscriber matches no local put"
        );
        assert_eq!(shared.drain_local_plane(), 0, "and stages nothing to run");
        assert_eq!(*hits.lock().expect("test mutex"), 0);
    }

    /// R311y557 — the ALIASED local leg, which shipped at R311y554 with no
    /// driver at all (the debt ledger's "cheapest real gap on this list").
    ///
    /// It is the aliased twin of `publish_all_delivers_locally_with_no_face`,
    /// and it is what proves the plane took `send_declare_keyexpr` in
    /// [`SharedSession::declare_keyexpr`]: without that the plane cannot resolve
    /// the id, `publish_aliased_auto` answers `UnknownMapping`, and an aliased
    /// put delivers on the wire and to nobody in-process.
    #[test]
    fn publish_aliased_all_delivers_locally_with_no_face() {
        let shared = SharedSession::new(TokioTime::new(), test_zid()).expect("test host entropy");
        let seen = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let sink_log = seen.clone();
        let sink: SubscriberSink = Arc::new(move || {
            let log = sink_log.clone();
            Box::new(move |sample: &dyn SampleView| {
                log.lock()
                    .expect("test mutex")
                    .push(sample.payload().to_vec());
            })
        });
        shared.declare_subscriber("wz/alias/target".to_owned(), Locality::Any, sink);
        let mapping = shared
            .declare_keyexpr("wz/alias/target".to_owned())
            .expect("the first alias id is not exhausted");

        let delivered = shared
            .publish_aliased_all(
                mapping,
                None,
                b"aliased",
                &PublishOptions::put().with_locality(Locality::Any),
            )
            .expect("a faceless aliased publish is not an error");
        assert_eq!(delivered, 1, "the plane resolved the alias and matched");
        assert_eq!(shared.drain_local_plane(), 1);
        assert_eq!(
            seen.lock().expect("test mutex").as_slice(),
            &[b"aliased".to_vec()]
        );
    }

    /// R311y557 — an UNDECLARED alias stops delivering in-process.
    ///
    /// The negative arm that makes the test above a claim about the mapping
    /// rather than about the keyexpr: with the plane's retraction omitted this
    /// still delivers, because the plane's outbound table would keep the entry
    /// the faces had dropped.
    #[test]
    fn an_undeclared_alias_no_longer_delivers_locally() {
        let shared = SharedSession::new(TokioTime::new(), test_zid()).expect("test host entropy");
        let hits = Arc::new(StdMutex::new(0usize));
        let sink_hits = hits.clone();
        let sink: SubscriberSink = Arc::new(move || {
            let hits = sink_hits.clone();
            Box::new(move |_sample: &dyn SampleView| {
                *hits.lock().expect("test mutex") += 1;
            })
        });
        shared.declare_subscriber("wz/alias/gone".to_owned(), Locality::Any, sink);
        let mapping = shared
            .declare_keyexpr("wz/alias/gone".to_owned())
            .expect("the first alias id is not exhausted");
        shared.undeclare_keyexpr(mapping);

        let delivered = shared
            .publish_aliased_all(
                mapping,
                None,
                b"aliased",
                &PublishOptions::put().with_locality(Locality::Any),
            )
            .expect("publishing on a retracted alias is not a fanout error");
        assert_eq!(delivered, 0, "the retracted id resolves on neither leg");
        assert_eq!(shared.drain_local_plane(), 0);
        assert_eq!(*hits.lock().expect("test mutex"), 0);
    }

    /// A key acquired twice is ONE declaration with two holders, and it stays
    /// declared until the second holder lets go.
    ///
    /// Read off the local plane's alias table, because that is where a
    /// retraction shows: while the key is held the alias resolves and an aliased
    /// put reaches the subscriber, and once the LAST holder has released it the
    /// same put reaches nobody. The first release is the arm that matters — a
    /// count that retracted on it would leave the second holder naming an id the
    /// peer no longer has.
    #[test]
    fn a_key_acquired_twice_is_retracted_by_its_last_holder() {
        let shared = SharedSession::new(TokioTime::new(), test_zid()).expect("test host entropy");
        let hits = Arc::new(StdMutex::new(0usize));
        let sink_hits = hits.clone();
        let sink: SubscriberSink = Arc::new(move || {
            let hits = sink_hits.clone();
            Box::new(move |_sample: &dyn SampleView| {
                *hits.lock().expect("test mutex") += 1;
            })
        });
        shared.declare_subscriber("wz/res/shared".to_owned(), Locality::Any, sink);
        let first = shared
            .acquire_keyexpr("wz/res/shared".to_owned())
            .expect("the first id is not exhausted");
        let second = shared
            .acquire_keyexpr("wz/res/shared".to_owned())
            .expect("a held key answers with its id");
        assert_eq!(first, second, "the same key is the same id");
        assert_eq!(
            shared.keyexpr_declarations().len(),
            1,
            "and one declaration, not two"
        );

        let put = |shared: &SharedSession| {
            let delivered = shared
                .publish_aliased_all(
                    first,
                    None,
                    b"x",
                    &PublishOptions::put().with_locality(Locality::Any),
                )
                .expect("an aliased publish is not a fanout error");
            (delivered, shared.drain_local_plane())
        };

        shared.release_keyexpr(first);
        assert_eq!(
            put(&shared),
            (1, 1),
            "one holder is left, so the alias still resolves"
        );
        assert_eq!(shared.keyexpr_declarations().len(), 1);

        shared.release_keyexpr(second);
        assert_eq!(
            put(&shared),
            (0, 0),
            "the last holder has let go, so the alias resolves on neither leg"
        );
        assert!(shared.keyexpr_declarations().is_empty());
        assert_eq!(*hits.lock().expect("test mutex"), 1);
    }

    /// `declare_keyexpr` is not `acquire_keyexpr`: each call is its own
    /// declaration with its own id, which is what the other ABI relies on and
    /// what this change must leave alone.
    #[test]
    fn declare_keyexpr_still_gives_every_call_its_own_id() {
        let shared = SharedSession::new(TokioTime::new(), test_zid()).expect("test host entropy");
        let first = shared
            .declare_keyexpr("wz/res/own".to_owned())
            .expect("the first id is not exhausted");
        let second = shared
            .declare_keyexpr("wz/res/own".to_owned())
            .expect("the second id is not exhausted");
        assert_ne!(first, second);
        assert_eq!(shared.keyexpr_declarations().len(), 2);
    }

    /// R311y557 — `z_delete`'s local leg end to end through the registry, which
    /// the debt ledger recorded as unit-tested-only on the option struct and
    /// never driven through a delivery.
    ///
    /// The kind is what is asserted, not just the arrival: a Del that arrived as
    /// a Put would satisfy an arrival-only assertion and mean the opposite thing
    /// to the C subscriber.
    #[test]
    fn a_delete_reaches_the_local_plane_as_a_del() {
        let shared = SharedSession::new(TokioTime::new(), test_zid()).expect("test host entropy");
        let kinds = Arc::new(StdMutex::new(Vec::<bool>::new()));
        let sink_kinds = kinds.clone();
        let sink: SubscriberSink = Arc::new(move || {
            let kinds = sink_kinds.clone();
            Box::new(move |sample: &dyn SampleView| {
                kinds
                    .lock()
                    .expect("test mutex")
                    .push(sample.kind() == wz_runtime_tokio::sample::SampleKind::Del);
            })
        });
        shared.declare_subscriber("wz/del/local".to_owned(), Locality::Any, sink);

        let delivered = shared
            .publish_all(
                "wz/del/local",
                &[],
                &PublishOptions::del().with_locality(Locality::Any),
            )
            .expect("a faceless delete is not an error");
        assert_eq!(delivered, 1);
        assert_eq!(shared.drain_local_plane(), 1);
        assert_eq!(
            kinds.lock().expect("test mutex").as_slice(),
            &[true],
            "the local leg carries the Del kind, not a Put with an empty payload"
        );
    }

    /// R311y528 — THE defect this round closed, asserted at the mechanism.
    ///
    /// Two threads reach one C matching closure: the drive thread (per-face
    /// callback, and `face_down`'s purge) and the C application thread (an
    /// already-matching registration delivering synchronously). What makes that
    /// sound is that [`deliver_matching_flip`] holds the entry's aggregate mutex
    /// ACROSS the call, so the two cannot overlap.
    ///
    /// The assertion is a `try_lock` from INSIDE the sink and is fully
    /// deterministic — no threads, no sleeps, no window to get unlucky in.
    /// `std::sync::Mutex::try_lock` reports `WouldBlock` for a lock already held
    /// by the calling thread, so "the mutex is held right now" is directly
    /// observable at the one instant that matters. R311y527's code released the
    /// mutex before the sink; against that build this reads `Ok` and reds.
    #[test]
    fn the_aggregate_mutex_is_held_across_the_c_call() {
        let observed = Arc::new(StdMutex::new(Vec::new()));
        let log = observed.clone();

        // R311y535 — `Arc::new_cyclic` because the aggregate now OWNS the sink
        // while this particular sink observes the aggregate. That cycle is this
        // test's alone: a real C sink never reaches back into wz state.
        let state = Arc::new_cyclic(|weak: &std::sync::Weak<StdMutex<MatchAggregate>>| {
            let probe = weak.clone();
            StdMutex::new(MatchAggregate::new(Arc::new(move |now| {
                log.lock().unwrap().push(now);
                let probe = probe
                    .upgrade()
                    .expect("the aggregate is alive during its own call");
                assert!(
                    probe.try_lock().is_err(),
                    "the aggregate mutex was NOT held across the C call -- two \
                     threads can then invoke one C context concurrently"
                );
            })))
        });

        deliver_matching_flip(&state, |agg| agg.apply(7, true));
        assert_eq!(*observed.lock().unwrap(), vec![true], "the flip delivered");
    }

    /// The OR across faces, at the fold: a second matching face is NOT a second
    /// `true`, one face leaving while another still matches is SILENT, and only
    /// the last one leaving delivers `false`.
    ///
    /// This is the aggregation `MatchAggregate` exists for. A build that
    /// forwarded each face's verdict straight through would deliver
    /// `[true, true, false, false]` here.
    #[test]
    fn the_verdict_is_the_or_across_faces() {
        let observed = Arc::new(StdMutex::new(Vec::new()));
        let log = observed.clone();
        let sink: MatchingSink = Arc::new(move |now| log.lock().unwrap().push(now));
        let state = Arc::new(StdMutex::new(MatchAggregate::new(sink)));

        deliver_matching_flip(&state, |agg| agg.apply(1, true));
        deliver_matching_flip(&state, |agg| agg.apply(2, true));
        deliver_matching_flip(&state, |agg| agg.apply(1, false));
        deliver_matching_flip(&state, |agg| agg.apply(2, false));

        assert_eq!(
            *observed.lock().unwrap(),
            vec![true, false],
            "the C side must see the SESSION verdict flip twice, not once per face"
        );
    }

    /// `face_down`'s purge and an ordinary `false` from the same face must not
    /// both flip: whichever lands first owns the transition.
    ///
    /// This is why the purge uses `forget` (idempotent removal) rather than
    /// `apply(id, false)` — but both settle through the same `settle()`, so the
    /// property to pin is that the second one is silent.
    #[test]
    fn a_purge_after_an_ordinary_false_is_silent() {
        let observed = Arc::new(StdMutex::new(Vec::new()));
        let log = observed.clone();
        let sink: MatchingSink = Arc::new(move |now| log.lock().unwrap().push(now));
        let state = Arc::new(StdMutex::new(MatchAggregate::new(sink)));

        deliver_matching_flip(&state, |agg| agg.apply(3, true));
        deliver_matching_flip(&state, |agg| agg.apply(3, false));
        deliver_matching_flip(&state, |agg| agg.forget(3));

        assert_eq!(*observed.lock().unwrap(), vec![true, false]);
    }

    /// Two threads folding into ONE entry deliver strictly serialised, ordered
    /// calls — never overlapping, and never `false` before the `true` that the
    /// aggregate computed first.
    ///
    /// The in-flight counter can only under-report (a scheduler that never
    /// overlaps the two threads passes trivially), so this CORROBORATES
    /// [`the_aggregate_mutex_is_held_across_the_c_call`] rather than replacing
    /// it — that one is the deterministic proof. What this adds is the ORDER
    /// property, which the single-threaded probe cannot see: releasing the mutex
    /// before the sink lost ordering even when the calls did not overlap.
    #[test]
    fn concurrent_folds_deliver_serialised_and_in_order() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let inflight = Arc::new(AtomicUsize::new(0));
        let overlaps = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(StdMutex::new(Vec::new()));

        let sink: MatchingSink = {
            let inflight = inflight.clone();
            let overlaps = overlaps.clone();
            let log = observed.clone();
            Arc::new(move |now| {
                if inflight.fetch_add(1, Ordering::SeqCst) != 0 {
                    overlaps.fetch_add(1, Ordering::SeqCst);
                }
                log.lock().unwrap().push(now);
                std::thread::yield_now();
                inflight.fetch_sub(1, Ordering::SeqCst);
            })
        };
        let state = Arc::new(StdMutex::new(MatchAggregate::new(sink)));

        // Face 1 arrives and stays; then two threads race the arrival of face 2
        // against the departure of face 1. Whatever the interleaving, the
        // aggregate is non-empty throughout, so the CORRECT observation is that
        // nothing further is delivered at all.
        deliver_matching_flip(&state, |agg| agg.apply(1, true));

        let a = {
            let state = state.clone();
            std::thread::spawn(move || {
                for _ in 0..200 {
                    deliver_matching_flip(&state, |agg| agg.apply(2, true));
                }
            })
        };
        let b = {
            let state = state.clone();
            std::thread::spawn(move || {
                for _ in 0..200 {
                    deliver_matching_flip(&state, |agg| agg.forget(2));
                }
            })
        };
        a.join().unwrap();
        b.join().unwrap();

        assert_eq!(
            overlaps.load(Ordering::SeqCst),
            0,
            "two threads were inside the C sink at once"
        );
        assert_eq!(
            *observed.lock().unwrap(),
            vec![true],
            "face 1 never left, so the session verdict never moved off true"
        );
    }

    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A sink whose `Drop` is observable — the C `drop(context)` stand-in.
    struct DropProbe(Arc<AtomicUsize>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// R311y535 — retiring an aggregate releases the C context AT THE CALL, and
    /// a delivery that arrives afterwards is silent.
    ///
    /// This is the half of `z_undeclare_matching_listener`'s contract that was
    /// wrong: the sink used to be an `Arc` cloned into the entry, every per-face
    /// callback and `face_down`'s purge snapshot, so `drop(context)` ran when the
    /// LAST clone fell — a moment no caller chose. Against that build this test
    /// reds on the first assertion, because the undeclare path dropped one clone
    /// of several.
    #[test]
    fn retiring_an_aggregate_frees_the_context_at_the_call_and_silences_it() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(StdMutex::new(Vec::new()));

        let state = {
            let probe = DropProbe(dropped.clone());
            let log = observed.clone();
            Arc::new(StdMutex::new(MatchAggregate::new(Arc::new(move |now| {
                // Keep the probe owned BY the closure, exactly as a C sink owns
                // its context, so the probe's drop is the closure's drop.
                let _ = &probe;
                log.lock().unwrap().push(now);
            }))))
        };

        deliver_matching_flip(&state, |agg| agg.apply(1, true));
        assert_eq!(dropped.load(Ordering::SeqCst), 0, "not dropped while live");

        // The production retirement path, not a copy of it.
        let retired = retire_matching_sink(&state);
        assert!(retired.is_some(), "a live aggregate yields its sink");
        drop(retired);
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            1,
            "the context must be freed BY the retirement, not whenever the last \
             Arc clone happens to fall"
        );

        // A flip that arrives after retirement has no C to reach.
        deliver_matching_flip(&state, |agg| agg.forget(1));
        assert_eq!(
            *observed.lock().unwrap(),
            vec![true],
            "a retired listener must deliver nothing"
        );
        assert!(
            retire_matching_sink(&state).is_none(),
            "retiring twice must not produce a second context to free"
        );
    }

    /// R311y535 — a retirement WAITS for a delivery that is in flight, which is
    /// what makes the release safe rather than merely prompt.
    ///
    /// Deterministic, not timing-based: the sink parks on a channel, so the
    /// delivery is provably still inside the C call when the retiring thread
    /// starts. The retirement is then observed NOT to have completed, released,
    /// and observed to complete. Against a build that took the sink without the
    /// aggregate mutex, the middle assertion reds — and that build would be
    /// freeing a context another thread is executing in.
    #[test]
    fn a_retirement_waits_for_a_delivery_in_flight() {
        use std::sync::mpsc;

        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let release_rx = StdMutex::new(release_rx);

        let state = Arc::new(StdMutex::new(MatchAggregate::new(Arc::new(move |_now| {
            entered_tx.send(()).expect("the test thread is waiting");
            release_rx
                .lock()
                .unwrap()
                .recv()
                .expect("the test thread releases the sink");
        }))));

        let deliverer = {
            let state = state.clone();
            std::thread::spawn(move || deliver_matching_flip(&state, |agg| agg.apply(1, true)))
        };
        entered_rx.recv().expect("the sink is entered");

        let retired = Arc::new(AtomicUsize::new(0));
        let retirer = {
            let state = state.clone();
            let retired = retired.clone();
            std::thread::spawn(move || {
                let sink = retire_matching_sink(&state);
                retired.store(1, Ordering::SeqCst);
                drop(sink);
            })
        };

        // The sink is parked INSIDE the C call, so the retirement cannot have
        // completed. A generous window: this is proving it is still blocked, and
        // a slow machine only makes the claim stronger.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(
            retired.load(Ordering::SeqCst),
            0,
            "the retirement completed while a delivery was INSIDE the C call — \
             it would be freeing a context another thread is executing in"
        );

        release_tx.send(()).expect("the sink is parked");
        deliverer.join().expect("the delivery completes");
        retirer.join().expect("the retirement completes");
        assert_eq!(
            retired.load(Ordering::SeqCst),
            1,
            "the retirement must complete once the delivery leaves the C call"
        );
    }

    /// R311y535 — a listener undeclared FROM INSIDE its own callback does not
    /// deadlock; it falls back to release-by-`Arc`-drop.
    ///
    /// The re-entrant case is the one where waiting is impossible: the mutex the
    /// retirement wants is the one this thread's own frame holds. Without the
    /// [`MatchingDeliveryGuard`] check this test HANGS rather than failing, which
    /// is why it exists as its own leg.
    #[test]
    fn a_retirement_from_inside_the_callback_does_not_deadlock() {
        let reentered = Arc::new(AtomicUsize::new(0));
        let state = Arc::new_cyclic(|weak: &std::sync::Weak<StdMutex<MatchAggregate>>| {
            let weak = weak.clone();
            let reentered = reentered.clone();
            StdMutex::new(MatchAggregate::new(Arc::new(move |_now| {
                let state = weak.upgrade().expect("alive during its own call");
                // The re-entrant undeclare. It must RETURN, and it must decline
                // to take the sink rather than block on this frame's own lock.
                assert!(
                    retire_matching_sink(&state).is_none(),
                    "a re-entrant retirement must decline, not take a context \
                     the current frame is executing in"
                );
                reentered.fetch_add(1, Ordering::SeqCst);
            })))
        });

        deliver_matching_flip(&state, |agg| agg.apply(1, true));
        assert_eq!(
            reentered.load(Ordering::SeqCst),
            1,
            "the callback ran to completion"
        );
        // Outside the callback the ordinary path still works.
        assert!(
            retire_matching_sink(&state).is_some(),
            "the sink is still there to retire once the callback has left"
        );
    }
}
