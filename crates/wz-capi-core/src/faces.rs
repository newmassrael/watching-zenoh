// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//! `SubEntry` in the SSOT and declares it on whatever faces exist (possibly
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

use crate::cancellation::CancellableFan;
#[cfg(feature = "group")]
use crate::group::{retire_copies, FaceGroup, GroupAggregate, GroupError, GroupId};
#[cfg(feature = "peer")]
use wz_runtime_tokio::accept_loop::{DialIntentSender, FaceForwarder, FaceId};
use wz_runtime_tokio::declare::{LivelinessSample, LivelinessSampleKind};
#[cfg(feature = "gossip")]
use wz_runtime_tokio::gossip_plane::{FaceIdentity, GossipPlane, Outbound};
use wz_runtime_tokio::keyexpr_match::keyexpr_intersects_text;

#[cfg(feature = "peer")]
use crate::gossip::GossipPolicy;
#[cfg(feature = "group")]
use wz_runtime_tokio::group::Member;
use wz_runtime_tokio::locality::Locality;
use wz_runtime_tokio::node_clock::NodeHlc;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
#[cfg(feature = "group")]
use wz_runtime_tokio::qos::Priority;
use wz_runtime_tokio::query_sink::{QueryView, ReplyOut};
use wz_runtime_tokio::reply::ReplyHandle;
use wz_runtime_tokio::reply_sink::ReplyView;
use wz_runtime_tokio::runtime_impl::{TokioRuntime, TokioTime};
use wz_runtime_tokio::session::{
    InterestForm, LocalDeliveryDrain, MatchingInterestHold, MatchingListener, MatchingStatus,
    PublishAliasError, PublishError, PublishOptions, QueryAliasError, QueryOptions, Queryable,
    QueryableOptions, RetractionKey, SubscribeOptions, Subscriber, TokioQueryHolder, TokioSession,
};
use wz_runtime_tokio::session::{
    LivelinessOptions, LivelinessSubscriber, LivelinessSubscriberOptions, LivelinessToken,
};
#[cfg(feature = "peer")]
use wz_runtime_tokio::session_glue::WhatAmI;
use wz_runtime_tokio::session_glue::{
    new_session_actions, BoxedLinkDriver, DriverLoopOutcome, IterationEvent, LinkSendOutcome,
    SessionLinkActions,
};
use wz_runtime_tokio::sink::SampleView;
use wz_runtime_tokio::sync::PlainMutex as WzMutex;
use wz_runtime_tokio::Reliability;

#[cfg(feature = "multicast-transport")]
mod multicast;
#[cfg(feature = "multicast-transport")]
pub use multicast::{dispatch_mcast_event, sweep_mcast_face, McastFaceParts};

// R311y498 — NO `use crate::pubsub` / `use crate::query` here, deliberately.
//
// This registry used to import the C closure TYPES and the `make_*_callback`
// constructors that turn them into wz callbacks, which pointed the dependency
// the wrong way: the ABI-neutral face/declaration model reached UP into one
// specific C ABI's closure shape. That is what made it impossible to put a
// second C ABI (§5.27 `api-compat-c`, the zenoh-c drop-in) over the same session
// model without either duplicating this file or generalising it.
//
// The dependency is inverted through the FACTORY aliases below: the ABI
// shim hands in something that MINTS a callback, and this file never learns what
// it closes over. A factory rather than a ready-made callback because a callback
// is needed once PER FACE — every declaration is replayed onto each new face
// (`face_up`), so a single pre-built callback could not be reused.
//
// The C drop semantics are preserved exactly, and they are the delicate part:
// the factory owns whatever the shim captured (its `Arc<CClosure>`), so the last
// factory released still runs the C `drop(context)` — which is why every release
// below stays OUTSIDE the registry lock.
//
// The vocabulary an ABI and an engine both name — the subscriber and matching
// factories, the ids, a key's wire form, the write filter's plane and its answer —
// lives in `wz-capi-port`, so a C ABI over another engine names the same types
// (docs/capi-pico-on-coop-engine.md). It is re-exported here, so every path into
// this module keeps resolving. What stays is what names this engine's sessions.
pub use wz_capi_port::{
    FanoutError, FilterId, FilterPlane, FilteredPut, LivelinessSink, MatchId, MatchingSink, SubId,
    SubscriberSink, TokenId, WireKey,
};

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
///
/// The session is handed as a [`TokioQueryHolder`] rather than a `TokioSession` because a
/// group face's session is a multicast one, and a query that came over the group escapes on
/// the group (open-debt item 913).
pub type QueryableSink = Arc<
    dyn Fn(&TokioQueryHolder) -> Box<dyn FnMut(&dyn QueryView, &mut dyn ReplyOut) + Send + 'static>
        + Send
        + Sync,
>;

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
    /// Whether the session's OWN entities count, as they do in zenoh-pico when its
    /// local subscriber or queryable switch is on and the entity's locality admits
    /// session-local traffic (`ctx->allow_local`, `vendor/zenoh-pico/src/net/filtering.c` @
    /// `_z_write_filter_ctx_add_local_match`). They are read fresh from the
    /// declarations every time ([`Inner::local_entity_matches`]), never cached.
    count_local: bool,
    /// The last answer worked out for this filter and what it was worked out from: the
    /// set of faces and the declarations the faces' peers had made. While neither has
    /// moved the answer is the same, which is what lets a put skip the work of asking.
    #[cfg(target_has_atomic = "64")]
    cache: Option<FilterCache>,
}

/// A write filter's answer ([`SharedSession::write_filter_active`]) with the state of the
/// world it was computed from.
#[cfg(target_has_atomic = "64")]
#[derive(Clone, Copy)]
struct FilterCache {
    /// [`Inner::face_set_generation`] at the time.
    generation: u64,
    /// The sum of the faces' counters for the filter's plane at the time. Each only ever
    /// goes up, so for one generation of the face set a sum that is equal is a sum no
    /// counter has moved in.
    epoch_sum: u64,
    /// The answer: true when nothing matches and the put is dropped.
    inactive: bool,
}

/// The two counters of one face's session, subscribers first; `None` for a session that
/// has none, and a face set with one such face has no cached answers.
#[cfg(target_has_atomic = "64")]
type FaceEpochs = Option<(
    Arc<std::sync::atomic::AtomicU64>,
    Arc<std::sync::atomic::AtomicU64>,
)>;

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

/// What a publish names its key by, as the fan-out sees it.
#[derive(Clone, Copy)]
enum PutKey<'a> {
    /// The literal. Every leg can name it, and a face whose peer said it wants nothing
    /// the key reaches is left unwritten.
    Literal(&'a str),
    /// A declared alias the caller holds no literal for: a face resolves it through its
    /// own table, a group told the session's keyexprs is sent the alias, and any other
    /// group the literal it stands for.
    // Read only by the group leg, which a build without the multicast transport has not.
    #[cfg_attr(not(feature = "multicast-transport"), allow(dead_code))]
    Alias {
        mapping_id: u64,
        suffix: Option<&'a str>,
    },
    /// A declared alias together with the literal it stands for, which the caller holds:
    /// every leg can name the literal, and a group told the session's keyexprs is sent the
    /// alias (open-debt item 913).
    #[cfg_attr(not(feature = "multicast-transport"), allow(dead_code))]
    Declared {
        literal: &'a str,
        mapping_id: u64,
        suffix: Option<&'a str>,
    },
}

impl<'a> PutKey<'a> {
    /// The literal, when the caller holds it.
    fn literal(self) -> Option<&'a str> {
        match self {
            PutKey::Literal(literal) | PutKey::Declared { literal, .. } => Some(literal),
            PutKey::Alias { .. } => None,
        }
    }
}

/// What a group leg sends of a publish's payload: its bytes, whatever form the faces are
/// sent it in, and the chunk of shared memory they lie in when they lie in one. A group that
/// is a shared-memory one is sent the chunk's descriptor; any other group reaches it as the
/// bytes read back out of the chunk, as a face that did not negotiate shared memory does.
trait LegBytes {
    /// Read by the group leg alone, which a build without the multicast transport lacks.
    #[cfg_attr(
        not(feature = "multicast-transport"),
        expect(dead_code, reason = "only a group leg sends the bytes of a payload")
    )]
    fn leg_bytes(&self) -> &[u8];

    /// The chunk of shared memory the bytes lie in, if they do.
    #[cfg(feature = "transport-shm")]
    fn shm_chunk(&self) -> Option<&dyn wz_runtime_tokio::shm_provider::ShmPublishable> {
        None
    }
}

impl LegBytes for &[u8] {
    fn leg_bytes(&self) -> &[u8] {
        self
    }
}

#[cfg(feature = "transport-shm")]
impl LegBytes for Arc<wz_runtime_tokio::shm_provider::ShmBackedPayload> {
    fn leg_bytes(&self) -> &[u8] {
        self.bytes()
    }

    fn shm_chunk(&self) -> Option<&dyn wz_runtime_tokio::shm_provider::ShmPublishable> {
        Some(self)
    }
}

#[cfg(feature = "transport-shm")]
impl LegBytes for wz_session_core::extshm::ShmSendHandle {
    fn leg_bytes(&self) -> &[u8] {
        self.bytes()
    }

    fn shm_chunk(&self) -> Option<&dyn wz_runtime_tokio::shm_provider::ShmPublishable> {
        Some(self)
    }
}

/// The faces and the groups one fan-out sends to; see [`SharedSession`]'s `fan_targets`.
struct FanTargets {
    faces: Arc<Vec<TokioSession>>,
    #[cfg(feature = "multicast-transport")]
    groups: Arc<Vec<multicast::McastLeg>>,
}

/// The faces and the groups one get's wire legs go to, each face with its re-arm signal;
/// see [`SharedSession`]'s `query_targets`.
struct QueryTargets {
    faces: Vec<(TokioSession, Arc<Notify>)>,
    #[cfg(feature = "multicast-transport")]
    groups: Arc<Vec<multicast::McastLeg>>,
}

impl FanTargets {
    /// Whether a group is among the targets.
    #[cfg(feature = "multicast-transport")]
    fn has_groups(&self) -> bool {
        !self.groups.is_empty()
    }

    /// A build without the multicast transport has no group.
    #[cfg(not(feature = "multicast-transport"))]
    fn has_groups(&self) -> bool {
        false
    }

    /// Whether a group a write filter does not ask is among the targets: one zenoh-pico sends
    /// a put to whatever the filter says ([`crate::drive::GroupDeclarations::asks_for_filters`]).
    #[cfg(feature = "multicast-transport")]
    fn has_unasked_groups(&self) -> bool {
        self.groups
            .iter()
            .any(|group| !group.declarations.asks_for_filters())
    }

    /// A build without the multicast transport has no group.
    #[cfg(not(feature = "multicast-transport"))]
    fn has_unasked_groups(&self) -> bool {
        false
    }
}

/// One leg of a get, as [`SharedSession::fan_query`] hands it to the ABI that issues
/// it: which session the leg is issued on, and so how it may name its key and with
/// which locality it goes.
///
/// The ABI issues every leg through it and never names a transport: a leg that went
/// out on a group (open-debt item 913) is issued by the same call as one that went to a
/// face, and an ABI cannot forget the group's leg or name its key by an alias a group
/// was never told.
#[derive(Clone, Copy)]
pub enum QueryLeg<'a> {
    /// A unicast face: the wire leg to its one peer, which may name the key by an alias
    /// the face was told.
    Face(&'a TokioSession),
    /// The local plane: the session's own queryables.
    Local(&'a TokioSession),
    /// A group the session joined: the wire leg to every member with one send, which
    /// names the key by its literal, a group being told no declaration.
    #[cfg(feature = "multicast-transport")]
    Group(&'a wz_runtime_tokio::session::TokioMulticastSession),
}

impl QueryLeg<'_> {
    /// The locality the leg is issued with: [`Locality::SessionLocal`] on the plane,
    /// [`Locality::Remote`] on a wire leg. It is the leg's and not the caller's: each
    /// leg is one half of the caller's destination, and the halves are disjoint.
    pub fn locality(&self) -> Locality {
        match self {
            QueryLeg::Local(_) => Locality::SessionLocal,
            QueryLeg::Face(_) => Locality::Remote,
            #[cfg(feature = "multicast-transport")]
            QueryLeg::Group(_) => Locality::Remote,
        }
    }

    /// Issue the get on this leg, asking by the literal `keyexpr`, with `opts` at the
    /// leg's own [`locality`](Self::locality).
    pub fn query(
        &self,
        keyexpr: &str,
        opts: QueryOptions,
        on_reply: impl FnMut(&dyn ReplyView) + Send + 'static,
    ) -> Result<ReplyHandle, QueryAliasError> {
        let opts = opts.with_allowed_destination(self.locality());
        match self {
            QueryLeg::Face(session) | QueryLeg::Local(session) => {
                session.query(keyexpr, opts, on_reply, |_rid| {})
            }
            #[cfg(feature = "multicast-transport")]
            QueryLeg::Group(session) => session.query(keyexpr, opts, on_reply, |_rid| {}),
        }
    }

    /// [`Self::query`] asking as `wire` names the key where the leg can: a face by the
    /// declared alias, the plane and a group by the literal (the plane has no wire to
    /// name it on, and a group is told no declaration). The reply is still matched
    /// against `keyexpr`.
    pub fn query_on_wire(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        opts: QueryOptions,
        on_reply: impl FnMut(&dyn ReplyView) + Send + 'static,
    ) -> Result<ReplyHandle, QueryAliasError> {
        match self {
            QueryLeg::Face(session) if !wire.is_literal() => session.query_aliased(
                wire.mapping_id,
                wire.suffix.as_deref(),
                keyexpr,
                opts.with_allowed_destination(self.locality()),
                on_reply,
                |_rid| {},
            ),
            _ => self.query(keyexpr, opts, on_reply),
        }
    }

    /// [`Self::query`] whose VALUE is a chunk of shared memory: a face that negotiated
    /// shared memory is sent its descriptor, and every other leg the bytes read back out
    /// of it, a group included (see `Session::query_shm`).
    #[cfg(all(feature = "transport-shm", feature = "query"))]
    pub fn query_shm(
        &self,
        keyexpr: &str,
        opts: QueryOptions,
        value: &wz_runtime_tokio::shm_provider::ShmBackedPayload,
        on_reply: impl FnMut(&dyn ReplyView) + Send + 'static,
    ) -> Result<ReplyHandle, QueryAliasError> {
        let opts = opts.with_allowed_destination(self.locality());
        match self {
            QueryLeg::Face(session) | QueryLeg::Local(session) => {
                session.query_shm(keyexpr, opts, value, on_reply, |_rid| {})
            }
            #[cfg(feature = "multicast-transport")]
            QueryLeg::Group(session) => {
                session.query_shm(keyexpr, opts, value, on_reply, |_rid| {})
            }
        }
    }

    /// What undoes the leg issued as `rid` when its get is cancelled: its pending
    /// query, taken off the session it was issued on.
    fn canceller(&self, rid: u64) -> Box<dyn FnOnce() + Send> {
        match self {
            QueryLeg::Face(session) | QueryLeg::Local(session) => {
                let session = (*session).clone();
                Box::new(move || {
                    session.cancel_pending_query(rid);
                })
            }
            #[cfg(feature = "multicast-transport")]
            QueryLeg::Group(session) => {
                let session = (*session).clone();
                Box::new(move || {
                    session.cancel_pending_query(rid);
                })
            }
        }
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

/// A C-level queryable id — what a `z_owned_queryable_t` handle carries. The
/// responder-side mirror of [`SubId`], keying the per-face wz [`Queryable`]s
/// one C queryable declaration spawned.
pub type QblId = u64;

/// The first face id of the dial (`connect`) role: a client's one face is this
/// id, and a peer's faces are this id plus the index of their endpoint.
///
/// R3067 -- the dial role has an id space of its own, because a session may
/// both dial and listen and the two must not meet in the registry. The accept
/// loop mints its ids by counting up from 0 (`accept_loop`'s own `next_id`), so
/// the dial role sits at the top of the range, where a counter that has to
/// reach it would first have to outlive any process. Before this the two roles
/// shared the low ids and were kept apart only by a session never being both,
/// which a config stating `listen` and `connect` together now is.
pub const DIAL_FACE_ID: u64 = 1 << 62;

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
    /// R2932 — this session's copy of each C GROUP, same replay contract as
    /// `subs`. Each copy forwards what it hears into the C group's
    /// [`GroupAggregate`], which is what the C program reads.
    #[cfg(feature = "group")]
    groups: BTreeMap<GroupId, FaceGroup>,
    /// R311y296 — the signal that this face's drive loop should re-arm its wake
    /// because a `z_get` just registered a pending query with a nearer deadline
    /// than whatever the loop is currently parked on. Owned per face because
    /// each face has its own session, pending table, and drive wake.
    revised: Arc<Notify>,
    /// R3067 -- the remote node this face is a link to, when its handshake
    /// named one. A session keeps ONE face per remote zid, as zenoh's transport
    /// manager keeps one transport per zid: see [`SharedSession::face_up`].
    peer_zid: Option<Vec<u8>>,
    /// Whether this session dialled the link (the dial role's face) and not took it off its
    /// port. Two links to one node that went opposite ways are decided by
    /// [`wz_session_core::link_admission::judge_second_link`], which reads it.
    dialled: bool,
}

/// What the registry does with a face that comes up to a node.
#[derive(Debug, PartialEq, Eq)]
enum Admission {
    /// No other face links this session to the node: the face is held.
    Admit,
    /// A face that stays already does: the new link is closed.
    Refuse,
    /// The new link is the one to keep: the face `0` is closed and removed, and the new one
    /// takes its place.
    Replace(u64),
}

/// The decision for a link `dialled` (or not) that has completed its handshake to the node
/// `zid`, as face `id`, against the faces `held` (each its id, the node it links to and whether
/// this session dialled it). The rule is `wz_session_core::link_admission`'s, which the
/// cooperative engine's face table calls too: the first up when two links went the same way, and
/// of two that went opposite ways the one the lower zid dialled, so that both ends of a link
/// keep the same one. A face with no zid (its handshake named none) cannot be matched and is
/// held.
fn admission_of<'a>(
    local_zid: &[u8],
    held: impl Iterator<Item = (u64, Option<&'a [u8]>, bool)>,
    id: u64,
    zid: Option<&[u8]>,
    dialled: bool,
) -> Admission {
    use wz_session_core::link_admission::{judge_second_link, SecondLink};
    let Some(zid) = zid else {
        return Admission::Admit;
    };
    for (held_id, held_zid, held_dialled) in held {
        if held_id == id {
            continue;
        }
        let Some(held_zid) = held_zid else { continue };
        if !wz_runtime_tokio::zid_hex::same_zid(held_zid, zid) {
            continue;
        }
        return match judge_second_link(held_dialled, dialled, local_zid, zid) {
            SecondLink::Refuse => Admission::Refuse,
            SecondLink::Replace => Admission::Replace(held_id),
        };
    }
    Admission::Admit
}

impl FaceEntry {
    /// R2932 — retire this face's group copies: their members leave the union the way a
    /// dead link's do, since nothing will carry a Leave over it. Outside the registry lock,
    /// because it delivers. A build without the group plane has no copies to retire.
    fn retire_groups(&mut self) {
        #[cfg(feature = "group")]
        retire_copies(std::mem::take(&mut self.groups).into_values());
    }
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

/// One leg of a liveliness subscription: what a [`LivelinessSink`] mints.
type LivelinessLeg = Box<dyn for<'a> FnMut(LivelinessSample<'a>) + Send + 'static>;

/// Tell the liveliness subscriptions behind `legs` that the token `token_id` on `keyexpr` is
/// `kind`: a put when it comes alive, a delete when it is retracted. Called with no lock held.
fn tell_liveliness(
    legs: Vec<LivelinessLeg>,
    kind: LivelinessSampleKind,
    keyexpr: &str,
    token_id: TokenId,
) {
    for mut leg in legs {
        leg(LivelinessSample {
            kind,
            keyexpr,
            token_id,
        });
    }
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

/// R2932 — a C-joined GROUP, the eighth SSOT. The aggregate carries the group
/// id and the local member, so a replay joins the same group as the same
/// member; `priority` is the one join knob the aggregate does not need.
#[cfg(feature = "group")]
struct GroupEntry {
    id: GroupId,
    agg: Arc<GroupAggregate>,
    priority: Priority,
}

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
    /// What the listener watches, as a write filter names it.
    ///
    /// R311y528 — carried on the SSOT entry rather than passed at the declare call
    /// only, because `face_up` REPLAYS every entry onto each new face and has to
    /// install the same kind of watch the original declare did. A plane that lived
    /// only at the call site would silently degrade every replayed querier watch
    /// into a publisher one, and the failure would appear as "matching works until
    /// a peer reconnects".
    plane: FilterPlane,
    /// Whether the session's OWN entities count toward the verdict, as one more
    /// member of the aggregate ([`LOCAL_PLANE_MEMBER`]) beside the faces — see
    /// [`FilterEntry::count_local`].
    count_local: bool,
    /// Whether the peers' declarations count: a listener of the session's own entities alone
    /// (a locality of `SessionLocal`) installs no watch on a face, now or when one comes up.
    count_remote: bool,
    /// Whether the listener counts as zenoh's Rust session does and not as zenoh-pico: the
    /// session's own entities whatever origin each accepts (and not only those that admit
    /// session-local traffic), and a queryable of a peer only when its key includes the
    /// querier's (and not when it merely intersects it).
    upstream_rule: bool,
}

/// The member a [`MatchAggregate`] files the session's own entities under, beside the
/// ids of its faces. Face ids count up from zero and never reach it.
const LOCAL_PLANE_MEMBER: u64 = u64::MAX;

/// Install the per-face watch of what `plane` counts on `session` for `keyexpr`: a publisher's
/// for the subscribers, a querier's for the queryables.
///
/// One function rather than a match at each of the two call sites (declare and `face_up`
/// replay) for the same reason `face_matching_callback` is one function: the two must not
/// drift.
fn install_matching_watch(
    plane: FilterPlane,
    session: &TokioSession,
    keyexpr: &str,
    upstream_rule: bool,
    callback: impl FnMut(MatchingStatus) + Send + 'static,
) -> Option<MatchingListener<TokioRuntime>> {
    // What a face's watch counts is what the peer behind the face declares: a subscriber or a
    // queryable of the session itself is also declared on the face's session, and counts through
    // the local fold of the aggregate when the listener asks for it, not here, so that a listener
    // of remote declarations alone is never told of a local one.
    match plane {
        FilterPlane::Subscribers => session
            .declare_publisher(
                keyexpr.to_owned(),
                PublishOptions::put().with_locality(Locality::Remote),
            )
            .declare_matching_listener(callback)
            .ok(),
        FilterPlane::Queryables { complete_required } => session
            .declare_querier(
                keyexpr.to_owned(),
                querier_watching_remote(complete_required, upstream_rule),
            )
            .declare_matching_listener(callback)
            .ok(),
    }
}

/// The options of the querier a queryable watch is made through: one whose target is
/// `ALL_COMPLETE` when only a complete queryable counts, as zenoh's querier asks
/// (`zenoh/src/api/querier.rs` @ `self.target == QueryTarget::AllComplete,`), for the runtime's
/// querier counts complete queryables for that target alone.
fn querier_watching(complete_required: bool) -> QueryOptions {
    if complete_required {
        QueryOptions::default().with_target(wz_session_core::query_mode::QueryTarget::AllComplete)
    } else {
        QueryOptions::default()
    }
}

/// [`querier_watching`] for the watch of a face, which counts what the peer behind the face
/// declares and nothing of the session itself: see [`install_matching_watch`].
fn querier_watching_remote(complete_required: bool, upstream_rule: bool) -> QueryOptions {
    querier_watching(complete_required)
        .with_allowed_destination(Locality::Remote)
        .with_remote_inclusion(upstream_rule)
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

/// The snapshot of a face and of its links, and the event a watcher is told, are the session's
/// own model (`wz_session_core::face`): what a transport and a link of the C plane report is read
/// off a session's actions the same way whichever engine holds the session.
pub use wz_session_core::face::{
    FaceEventKind, FaceEventSink, FaceSnapshot, GroupLink, LinkSnapshot,
};

/// Snapshot one face's session, or `None` when its INIT has not populated the identity slots
/// yet: the half-open case [`SharedSession::peer_identities`] skips.
fn snapshot_of(session: &TokioSession) -> Option<FaceSnapshot> {
    FaceSnapshot::of_actions(session.actions())
}

#[derive(Default)]
struct Inner {
    faces: BTreeMap<u64, FaceEntry>,
    /// The sessions of `faces`, as one shared list that a sender takes a reference to instead
    /// of collecting a new one per message ([`SharedSession::face_set`]). Rebuilt by
    /// [`Self::refresh_face_set`] at each of the three places `faces` changes, under the lock
    /// that changes it, so a reader sees the faces as of a whole step and never a half one.
    face_set: Arc<Vec<TokioSession>>,
    /// The two counters ([`TokioSession::remote_declaration_epochs`]) of each session of
    /// [`Self::face_set`], in the same order, and the number of times that set has been
    /// rebuilt. Together they say whether anything a write filter's answer depends on has
    /// changed since it was last worked out ([`SharedSession::write_filter_active`]).
    #[cfg(target_has_atomic = "64")]
    face_epochs: Arc<Vec<FaceEpochs>>,
    /// How many times [`Self::face_set`], or the set of groups, has been rebuilt.
    face_set_generation: u64,
    /// `resource-snapshot` — what the receive paths of the faces that have gone had counted when
    /// they went ([`SharedSession::face_down`] retires a face in the step that removes it), so the
    /// node's reading never falls when a link does.
    #[cfg(feature = "resource-snapshot")]
    receive_ledger: wz_session_core::resource_snapshot::BuildReceiveLedger,
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
    /// The locators the session's listeners actually got, without the loopback ones: where a
    /// neighbour can dial this node. Set as listeners bind, whether or not the session gossips
    /// ([`SharedSession::set_listen_locators`]).
    listen_locators: Vec<String>,
    /// The locators of the multicast groups the session joined, by group face: a group named with
    /// port 0 is given its port by the system when it is bound, and the locator holds that port.
    /// Apart from [`Self::listen_locators`] because a listener's `set_listen_locators` replaces
    /// that list, and because no neighbour dials a group.
    group_locators: BTreeMap<u64, String>,
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
    /// Open-debt item 913 — the groups the session joined, each ONE face to every
    /// member of its group, keyed by the id the drive role gave it. Not members of
    /// `faces`: a group carries the session's subscribers and queryables and is
    /// reached by a publish and a get, and nothing else a unicast face holds (see
    /// the `multicast` module).
    #[cfg(feature = "multicast-transport")]
    mcast_faces: BTreeMap<u64, multicast::McastFaceEntry>,
    /// The group faces as one shared list for the senders, rebuilt with
    /// `mcast_faces` under the lock that changes it, as `face_set` is.
    #[cfg(feature = "multicast-transport")]
    mcast_set: Arc<Vec<multicast::McastLeg>>,
    /// The two counters of each group a write filter asks, as [`Self::face_epochs`] holds the
    /// faces': what the group's members declared moves a filter's answer as a peer's does.
    #[cfg(all(feature = "multicast-transport", target_has_atomic = "64"))]
    mcast_epochs: Arc<Vec<FaceEpochs>>,
    subs: Vec<SubEntry>,
    /// R311y559 — the session-scope ENTITY id counter: the `eid` of every entity the session
    /// declares, the one the C ABIs' `z_*_id` accessors report.
    ///
    /// Open-debt item 913 — ONE counter for every kind, from 1, and the registry's own keys
    /// (`SubId`, `QblId`, `TokenId`) are drawn from it. Both upstreams number every entity of a
    /// session from one counter: zenoh-pico's `_z_get_entity_id` serves publishers,
    /// subscribers, queryables, queriers and tokens alike
    /// (`vendor/zenoh-pico/src/session/utils.c` @ `zn->_entity_id = 1;`), and zenoh's runtime from
    /// `next_id: AtomicU32::new(1)` (`zenoh/src/net/runtime/mod.rs` @
    /// `next_id: AtomicU32::new(1), // 0 is reserved for routing core`). It used to be a
    /// separate space from per-kind counters that started at 0, on the reasoning that an id
    /// depending on how many entities of another kind came first was a coupling to avoid; it is
    /// the upstreams' rule, and a pico peer reads it off the wire: the id pico declares a
    /// subscriber with on a group is this one (MEASURED: `decl_subscriber(1, ..)` for the
    /// first entity of a session).
    next_entity_id: u64,
    qbls: Vec<QblEntry>,
    tokens: Vec<TokenEntry>,
    live_subs: Vec<LiveSubEntry>,
    matches: Vec<MatchEntry>,
    next_match_id: MatchId,
    filters: Vec<FilterEntry>,
    next_filter_id: FilterId,
    #[cfg(feature = "group")]
    groups: Vec<GroupEntry>,
    #[cfg(feature = "group")]
    next_group_id: GroupId,
    kexprs: Vec<KexprEntry>,
    /// Next alias id to hand out. Starts at 0 and is PRE-incremented, so the
    /// first id issued is 1: zero is reserved on the wire
    /// (`SendDeclareError::ReservedMappingIdZero`) and is also this crate's
    /// "not declared" discriminant in `z_loaned_keyexpr_t::_mapping`.
    next_kexpr_id: u64,
}

impl Inner {
    /// The next session-scope entity id ([`Inner::next_entity_id`]).
    fn take_entity_id(&mut self) -> u64 {
        let id = self.next_entity_id;
        self.next_entity_id = id.wrapping_add(1);
        id
    }

    /// [`Self::take_entity_id`], or `None` once the space is spent, for a declaration whose
    /// retraction names it by id alone and must not wrap onto a live one.
    fn try_take_entity_id(&mut self) -> Option<u64> {
        let id = self.next_entity_id;
        self.next_entity_id = id.checked_add(1)?;
        Some(id)
    }

    /// Rebuild [`Self::face_set`] from `faces`. Call it right after `faces` changes, with the
    /// lock still held.
    fn refresh_face_set(&mut self) {
        self.face_set = Arc::new(
            self.faces
                .values()
                .map(|face| face.session.clone())
                .collect(),
        );
        #[cfg(target_has_atomic = "64")]
        {
            self.face_epochs = Arc::new(
                self.faces
                    .values()
                    .map(|face| face.session.remote_declaration_epochs())
                    .collect(),
            );
        }
        self.face_set_generation = self.face_set_generation.wrapping_add(1);
    }

    /// The faces and the groups a fan-out sends to, as of this step of the registry.
    fn fan_targets(&self) -> FanTargets {
        FanTargets {
            faces: self.face_set.clone(),
            #[cfg(feature = "multicast-transport")]
            groups: self.mcast_set.clone(),
        }
    }

    /// What a write filter's answer on `plane` depends on, as a number to compare: how many
    /// times the face set has been rebuilt, and the sum of the faces' counters for that
    /// plane. Two equal tokens are the same world (see [`FilterCache`]); `None` when some
    /// face has no counters, and then nothing is kept.
    #[cfg(target_has_atomic = "64")]
    fn filter_token(&self, plane: FilterPlane) -> Option<(u64, u64)> {
        use std::sync::atomic::Ordering::Acquire;
        let mut sum = 0u64;
        #[cfg(feature = "multicast-transport")]
        let groups = self.mcast_epochs.iter();
        #[cfg(not(feature = "multicast-transport"))]
        let groups = core::iter::empty();
        for epochs in self.face_epochs.iter().chain(groups) {
            let (subscribers, queryables) = epochs.as_ref()?;
            let counter = match plane {
                FilterPlane::Subscribers => subscribers,
                FilterPlane::Queryables { .. } => queryables,
            };
            sum = sum.wrapping_add(counter.load(Acquire));
        }
        Some((self.face_set_generation, sum))
    }

    /// Whether this session itself holds an entity a write filter or a matching listener
    /// on `plane` and `keyexpr` sees when it counts the session's own entities: a
    /// subscriber, or a queryable, whose `allowed_origin` admits session-local traffic and
    /// whose key meets `keyexpr` — complete and including it, for a querier whose target
    /// requires completeness. zenoh-pico's local half of the write filter
    /// (`vendor/zenoh-pico/src/net/filtering.c` @ `_z_write_filter_session_register`).
    ///
    /// With `any_origin` the origin an entity accepts is not read and every entity counts, as
    /// upstream's matching status counts them: `Session::matching_status_local` walks the
    /// session's subscribers and queryables whatever origin each was declared for.
    fn local_entity_matches(&self, plane: FilterPlane, keyexpr: &str, any_origin: bool) -> bool {
        use wz_runtime_tokio::keyexpr_match::keyexpr_includes_target;
        match plane {
            FilterPlane::Subscribers => self.subs.iter().any(|sub| {
                (any_origin || sub.allowed_origin.allows_local())
                    && keyexpr_intersects_text(keyexpr, &sub.keyexpr)
            }),
            FilterPlane::Queryables { complete_required } => self.qbls.iter().any(|qbl| {
                (any_origin || qbl.allowed_origin.allows_local())
                    && if complete_required {
                        let target: Vec<&str> = keyexpr.split('/').collect();
                        qbl.complete && keyexpr_includes_target(&qbl.keyexpr, &target)
                    } else {
                        keyexpr_intersects_text(keyexpr, &qbl.keyexpr)
                    }
            }),
        }
    }

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
    /// The plane's drain is the calling ABI's choice ([`SessionResources::local_delivery`]).
    ///
    /// zenoh-pico's is [`LocalDeliveryDrain::DriveTask`] like every face session:
    /// a callback runs only from the executor, so the plane is drained from the
    /// drive role's own `select!` arm ([`Self::drive_local_plane`]), which is the
    /// SAME task the faces dispatch on. A `tokio::spawn`ed drain would have
    /// satisfied "not the C thread" and still broken that, because the
    /// per-session runtime has two workers.
    ///
    /// zenoh-c's is [`LocalDeliveryDrain::Caller`] (R3069): a delivery the node
    /// makes to itself runs inside the call that causes it, on the calling thread,
    /// as the real library runs it. The drive arm still drains whatever a path
    /// that stages without draining left behind (a declaration's matching flip).
    local: TokioSession,
    /// The local plane's re-arm signal — the twin of [`FaceEntry::revised`].
    ///
    /// Staging a fire does not make a drive loop iterate (R311y555 measured the
    /// cost of assuming it does: every in-process delivery rode the ~3333 ms
    /// keepalive tick). Every path that stages onto the plane notifies this, and
    /// [`Self::drive_local_plane`] is what waits on it.
    local_wake: Arc<Notify>,
    /// R3064 -- THE NODE'S CLOCK, built once from the session's `timestamping` config and installed
    /// on the local plane and on every face session this registry makes, so they share one.
    ///
    /// ONE per node is the contract and not a convenience: [`NodeHlc`] documents that two clocks
    /// with the same `uhlc::ID` are worse than none, and a C session is several `TokioSession`s
    /// (the plane and a session per face) over ONE zid. Before this field each of them built its
    /// own from its own handshake facts and the shipped defaults, so a config that enabled
    /// timestamping reached none of them: the key was read by the config reader and ignored by
    /// the node.
    node_hlc: NodeHlc,
    /// R3065 -- the shared-memory reader this node was opened over, installed on the plane and on
    /// every face session for the same reason the clock is one: a descriptor arrives on whichever
    /// session the peer's face is, and each must read it through the node's own clients.
    shm_clients: OpenShmClients,
    /// R3073 -- whether a face this node reaches as a peer is ended with the initial interest's
    /// `DeclareFinal`; see [`SessionResources::initial_interest`].
    initial_interest: bool,
    /// See [`SessionResources::liveliness_to_self`].
    liveliness_to_self: bool,
    /// R3074 -- the gossip plane, for a node that gossips: what introduces the nodes that
    /// each hold a face to this one. See [`SessionResources::gossip`].
    #[cfg(feature = "gossip")]
    gossip: Option<Arc<GossipPlane>>,
    /// The authentication the node's config asks for, installed on every session the node opens
    /// before its first wire byte. See [`SessionResources::auth`].
    auth: Option<crate::node_auth::NodeAuth>,
    /// The prefix the node's keys carry on the wire, installed on every session the node opens
    /// before its first wire byte. See [`SessionResources::namespace`].
    #[cfg(feature = "routing-namespace")]
    namespace: Option<wz_session_core::keyexpr_prefix::OwnedNonWildKeyExpr>,
    /// The policy the node's config states for its traffic, installed on every face. When it is
    /// not inert the send and receive lanes that step around a per-message verdict are off for
    /// this node's sessions. See [`SessionResources::policy`].
    policy: crate::node_policy::NodePolicy,
    /// The session's closed latch: set once by `SessionState::close` and never cleared. It lives
    /// HERE, and the drive loop races against this same `Arc`, so that an entity that outlives
    /// the session handle (a publisher, a querier, a query being answered) asks the one fact the
    /// drive thread and the C thread already agree on instead of a second flag kept beside it.
    /// It is what pico's `Z_FEATURE_SESSION_CHECK` reads through `_z_session_weak_upgrade_if_open`
    /// (`vendor/zenoh-pico/src/api/api.c`, the publisher put and delete, the querier get, the
    /// query replies and the batch calls).
    closed: Arc<std::sync::atomic::AtomicBool>,
    /// The periodic jobs a C ABI started on the session ([`SessionEngine::start_ticker`]), each a
    /// task of the `net` runtime that ends when its entry leaves the table. Dropped with the
    /// session, so a job outlives neither it nor its `stop_ticker`. Only the advanced plane
    /// starts one, so a build without it carries neither the table nor the task.
    #[cfg(feature = "advanced")]
    tickers: StdMutex<BTreeMap<u64, wz_runtime_tokio::periodic::PeriodicTask>>,
}

/// R3065 -- the shared-memory reader's clients a session is opened over: a set the node's
/// storage resolved into, or `None` for the default reader (POSIX alone), which every session
/// had before the C ABI could be given one. Without the SHM feature there is no reader to
/// configure and the type is a unit struct that carries nothing.
#[cfg(feature = "transport-shm")]
pub type OpenShmClients = Option<ShmReader>;

/// How a session reads a shared-memory descriptor it was sent, when its host chose.
///
/// The engine's reader maps a chunk through the clients of a set, one for each protocol, and
/// hands the application a view of the page. A host whose application holds its own types for a
/// chunk of shared memory (the Rust API's `ZShm`) needs the reader to hand it THOSE, so it
/// supplies the resolver itself and keeps what a chunk is to itself.
#[cfg(feature = "transport-shm")]
#[derive(Clone)]
pub enum ShmReader {
    /// The reader is the engine's, over this set of clients.
    Clients(Arc<wz_runtime_tokio::shm_clients::ShmClientSet>),
    /// The reader is the host's: this makes one for each session. The protocols the session
    /// offers are the default (POSIX alone), so a resolver of this kind reads POSIX chunks.
    Host(
        Arc<dyn Fn() -> Box<dyn wz_session_core::extshm::ShmResolver + Send + Sync> + Send + Sync>,
    ),
}
/// See the SHM-feature definition above.
#[cfg(not(feature = "transport-shm"))]
#[derive(Clone, Copy, Debug)]
pub struct OpenShmClients;

/// The reader a session has when it was not given one: the default (POSIX alone). One name for
/// both builds, because the type is an `Option` in one and a unit struct in the other and neither
/// spells "none" the same way.
#[cfg(feature = "transport-shm")]
pub const fn no_shm_clients() -> OpenShmClients {
    None
}

/// See the SHM-feature definition above.
#[cfg(not(feature = "transport-shm"))]
pub const fn no_shm_clients() -> OpenShmClients {
    OpenShmClients
}

/// R3065 -- what a node gives every session of its registry: ONE clock and ONE shared-memory
/// reader, so the plane and the faces are a single node however many of them there are.
#[derive(Clone)]
pub struct SessionResources {
    /// The node clock; see [`SharedSession`]'s field.
    pub node_hlc: NodeHlc,
    /// The shared-memory reader's clients; see [`OpenShmClients`].
    pub shm_clients: OpenShmClients,
    /// R3069 -- who runs the callbacks of a delivery the node makes to ITSELF: a put or a get
    /// whose subscribers and queryables are in the same session. The calling ABI chooses,
    /// because the two ABIs promise their C programs different things: zenoh-pico runs a
    /// callback only from its executor ([`LocalDeliveryDrain::DriveTask`]), and zenoh-c runs it
    /// inside the call that caused it ([`LocalDeliveryDrain::Caller`]). It governs the local
    /// plane; a face session's loopback is always `Locality::Remote`, so it has none.
    pub local_delivery: LocalDeliveryDrain,
    /// Whether the liveliness tokens of the node are told to its own liveliness subscribers and
    /// answer its own liveliness gets. Upstream zenoh's session does both. zenoh-pico's does
    /// neither: its history walks the tokens of its peers alone (`vendor/zenoh-pico/src/net/
    /// liveliness.c` @ `_z_keyexpr_intmap_iterator_make(&zn->_remote_tokens)`), so its ABI says
    /// `false`. The tokens are delivered inside the call that declares or retracts one, on the
    /// calling thread, which is the drain the ABI that says `true` has chosen.
    pub liveliness_to_self: bool,
    /// R3073 -- whether the node ends the declarations it replays to a new face with the
    /// `DeclareFinal` of the INITIAL interest (id 0), which is what a zenoh peer's open waits for
    /// before it returns: without it that open runs out `scouting/delay` (500 ms, against about
    /// ten when the other end is a zenoh peer) and says so in its log ("Scouting delay elapsed
    /// before start conditions are met"). The calling ABI chooses, as it does for the drain:
    /// zenoh-c's peer hat sends it to a peer it meets as a north-bound peer
    /// (`wz_session_core::extbound::sends_initial_interest_final`); zenoh-pico's session ends
    /// its push to every peer link it adds as a peer, accepted or opened, the same way, and
    /// sends none in client mode, which that rule already does not either. R3093 -- the pico ABI
    /// says `true` as well; it said `false` on the belief that pico sends only to an accepted
    /// peer, and a zenoh peer that dialled its listener waited out `scouting/delay`.
    pub initial_interest: bool,
    /// R3074 -- whether the node gossips: it tells a face it meets which nodes it knows and
    /// where they are, and dials the nodes it is told of. zenoh's peer does by default, its
    /// config's gossip switch being on, and it is what makes two peers that each reached a third
    /// reach each other when no scouting finds them. `None` for a node that does not, which is
    /// zenoh-pico's ABI (its peers are introduced by scouting alone) and any role that is a
    /// client. A build without the `peer` feature has no such field.
    #[cfg(feature = "peer")]
    pub gossip: Option<GossipSetup>,
    /// The authentication the node's config asks for (`transport/auth/usrpwd/dictionary_file`):
    /// a listener that holds one admits only the peers that hold a user of it. `None` is a node
    /// that authenticates nobody, which every node was until the config's key reached a session.
    pub auth: Option<crate::node_auth::NodeAuth>,
    /// The traffic policy the node's config states (`access_control`, `low_pass_filter`,
    /// `downsampling`). Inert for a node that states none, which is every node until the keys
    /// reached a session.
    pub policy: crate::node_policy::NodePolicy,
    /// The `namespace` the node's config states: every key a session of the node publishes
    /// leaves prefixed with it and every key it receives is relative to it. `None` is a node
    /// whose keys are the wire's, which every node was until the key reached a session.
    #[cfg(feature = "routing-namespace")]
    pub namespace: Option<wz_session_core::keyexpr_prefix::OwnedNonWildKeyExpr>,
}

/// What a node that gossips is given: the role it gossips as, how it gossips (whom it tells, whom
/// it dials), and where the nodes it learns of are posted to be dialled. The drive role drains
/// the other end of the channel, since dialling is its work and not the registry's.
#[cfg(feature = "peer")]
#[derive(Clone)]
pub struct GossipSetup {
    pub whatami: WhatAmI,
    pub policy: GossipPolicy,
    pub dials: DialIntentSender,
}

impl Default for SessionResources {
    /// No clock, the default reader and the executor's thread for a local delivery, no
    /// initial interest and no gossip: what a node was before it could be given any of them.
    fn default() -> Self {
        Self {
            node_hlc: NodeHlc::disabled(),
            shm_clients: no_shm_clients(),
            local_delivery: LocalDeliveryDrain::DriveTask,
            liveliness_to_self: false,
            initial_interest: false,
            #[cfg(feature = "peer")]
            gossip: None,
            auth: None,
            policy: crate::node_policy::NodePolicy::default(),
            #[cfg(feature = "routing-namespace")]
            namespace: None,
        }
    }
}

/// Give `session` the node's shared-memory reader when it has one of its own; without one the
/// session keeps the default POSIX reader every session is built with.
#[cfg(feature = "transport-shm")]
fn install_shm_reader(session: &TokioSession, clients: &OpenShmClients) {
    if let Some(resolver) = shm_resolver_of(clients) {
        session.set_shm_resolver(resolver);
    }
}

/// The reader a node was opened over, made anew for one session to hold; `None` for a node
/// that keeps the default POSIX reader every session is built with.
#[cfg(feature = "transport-shm")]
fn shm_resolver_of(
    clients: &OpenShmClients,
) -> Option<Box<dyn wz_session_core::extshm::ShmResolver + Send + Sync>> {
    match clients {
        Some(ShmReader::Clients(clients)) => Some(Box::new(
            wz_runtime_tokio::shm_clients::ShmClientResolver::new(Arc::clone(clients)),
        )),
        Some(ShmReader::Host(make)) => Some(make()),
        None => None,
    }
}

/// Without the SHM feature there is no reader to install.
#[cfg(not(feature = "transport-shm"))]
fn install_shm_reader(_session: &TokioSession, _clients: &OpenShmClients) {}

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
        Self::new_with_resources(clock, zid, SessionResources::default())
    }

    /// [`Self::new`] for a node that holds the clock `node_hlc` (R3064): the plane and every face
    /// session made later carry a clone of it. `new` is the node that holds none, which is what
    /// every session was until the C ABI read its `timestamping` config.
    pub fn new_with_node_clock(
        clock: TokioTime,
        zid: Vec<u8>,
        node_hlc: NodeHlc,
    ) -> Result<Self, wz_runtime_tokio::session_glue::EntropyUnavailable> {
        Self::new_with_resources(
            clock,
            zid,
            SessionResources {
                node_hlc,
                ..SessionResources::default()
            },
        )
    }

    /// [`Self::new`] for a node with the `resources` it was opened over (R3065): the plane and
    /// every face session made later are given the clock and the shared-memory reader in them, so
    /// the node is ONE node, however many sessions it grows.
    pub fn new_with_resources(
        clock: TokioTime,
        zid: Vec<u8>,
        resources: SessionResources,
    ) -> Result<Self, wz_runtime_tokio::session_glue::EntropyUnavailable> {
        let SessionResources {
            node_hlc,
            shm_clients,
            local_delivery,
            liveliness_to_self,
            initial_interest,
            #[cfg(feature = "peer")]
            gossip,
            auth,
            policy,
            #[cfg(feature = "routing-namespace")]
            namespace,
        } = resources;
        // Built over the node's own wire zid, before `zid` is moved into the plane's params.
        // A zid the graph cannot hold (empty or all zero) leaves the node not gossiping rather
        // than failing the open: the session's own zid is random and never is one.
        #[cfg(feature = "gossip")]
        let gossip = gossip
            .and_then(|setup| {
                GossipPlane::with_policy(&zid, setup.whatami, setup.policy, setup.dials)
            })
            .map(Arc::new);
        // Without the feature a setup cannot be made (its policy has no value), so there is
        // nothing to build and nothing to keep.
        #[cfg(all(feature = "peer", not(feature = "gossip")))]
        let _: Option<GossipSetup> = gossip;
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
            crate::drive::LinkConf {
                tx: crate::drive::LinkTx {
                    queue: wz_runtime_tokio::session_glue::TxQueueConf::default(),
                    batch_size: crate::drive::DEFAULT_BATCH_SIZE,
                    lease_ms: crate::drive::DEFAULT_LEASE_MS,
                    keep_alive: wz_runtime_tokio::session_glue::KeepAliveConf::default(),
                    sn_resolution: wz_runtime_tokio::policy::SnResolution::default(),
                },
                rx: wz_runtime_tokio::session_glue::LinkRxConf::default(),
                accept: wz_runtime_tokio::accept_bounds::AcceptBounds::default(),
            },
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
            .with_node_clock(node_hlc.clone())
            .with_local_delivery_drain(local_delivery)
            .with_local_stage_wake(Arc::clone(&local_wake));
        // R3065 -- a node opened over a client storage reads what its OWN peers send through it,
        // the plane included (a local get answered by a peer's queryable is read here).
        install_shm_reader(&local, &shm_clients);
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
                #[cfg(feature = "group")]
                groups: BTreeMap::new(),
                // The plane's re-arm signal is `local_wake`, held beside the
                // session for the same outside-the-lock reason; this one is
                // never notified.
                revised: Arc::new(Notify::new()),
                // The plane is no link to anyone.
                peer_zid: None,
                dialled: false,
            }),
            // Both upstreams number a session's first entity 1.
            next_entity_id: 1,
            ..Default::default()
        };
        Ok(Self {
            zid: zid_bytes,
            inner: StdMutex::new(inner),
            clock,
            local,
            local_wake,
            node_hlc,
            shm_clients,
            liveliness_to_self,
            initial_interest,
            #[cfg(feature = "gossip")]
            gossip,
            auth,
            #[cfg(feature = "routing-namespace")]
            namespace,
            policy,
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(feature = "advanced")]
            tickers: StdMutex::new(BTreeMap::new()),
        })
    }

    /// The closed latch the drive loop stops on (see the `closed` field): the drive takes this
    /// `Arc` rather than making its own, so the two can never disagree.
    pub fn closed_latch(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.closed.clone()
    }

    /// Whether the session this node belongs to has been closed (pico's session check).
    pub fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The authentication the node holds, for the sessions it dials and accepts.
    pub fn node_auth(&self) -> Option<&crate::node_auth::NodeAuth> {
        self.auth.as_ref()
    }

    /// The namespace the node's keys are prefixed with, for the sessions it dials and accepts.
    #[cfg(feature = "routing-namespace")]
    pub fn node_namespace(&self) -> Option<&wz_session_core::keyexpr_prefix::OwnedNonWildKeyExpr> {
        self.namespace.as_ref()
    }

    /// Whether this node states a traffic policy. Read on the data path, so it is a pointer test.
    pub fn has_policy(&self) -> bool {
        !self.policy.is_inert()
    }

    /// The node's INGRESS admission for the frame face `id` just decoded: a message the policy
    /// denies is dropped from `outcome` before any subscriber, queryable or reply sink sees it.
    /// The drive loop calls this for a whole frame and again for a fragment chain that
    /// completes. A node with no policy returns at the first test, which is every node that
    /// states none.
    pub fn ingress(&self, id: u64, outcome: &mut DriverLoopOutcome) {
        if !self.has_policy() {
            return;
        }
        #[cfg(feature = "interceptors")]
        {
            // Cloned out of the lock first: the verdict resolves the message's key through the
            // face's own alias table, under the observer lock, and the registry's must not be
            // held across that.
            let session = self.lock().faces.get(&id).map(|face| face.session.clone());
            if let Some(session) = session {
                session.apply_acl_ingress(outcome);
            }
        }
        #[cfg(not(feature = "interceptors"))]
        let _ = (id, outcome);
    }

    /// The next timestamp off this node's clock, or `None` when the node holds none (its role does
    /// not stamp, or the build has no clock): upstream's `runtime.hlc()` followed by
    /// `new_timestamp`. Strictly increasing from one call to the next.
    pub fn node_timestamp(&self) -> Option<wz_session_core::sample::TimestampHint> {
        self.node_hlc.stamp()
    }

    /// Record where this node's listeners can be reached: the locators they actually got, without
    /// the loopback ones, as upstream's `get_locators_noloopback` lists them. Replaces the list,
    /// so a caller that adds a listener passes all of them.
    pub fn set_listen_locators(&self, locators: Vec<String>) {
        self.lock().listen_locators = locators;
    }

    /// The locators [`Self::set_listen_locators`] was given: none for a node that listens on
    /// nothing, or whose listeners have not bound yet.
    pub fn listen_locators(&self) -> Vec<String> {
        let guard = self.lock();
        let mut locators = guard.listen_locators.clone();
        locators.extend(guard.group_locators.values().cloned());
        locators
    }

    /// Record the locator group face `id` is bound to, which lists beside the listeners'.
    /// Ended with the face ([`Self::mcast_face_down`]).
    #[cfg(feature = "multicast-transport")]
    pub fn set_group_locator(&self, id: u64, locator: String) {
        self.lock().group_locators.insert(id, locator);
    }

    /// Where this node can be reached, for the entries gossip sends about it: the locators of
    /// its listener, as a neighbour would dial them. Called once the listener is bound and
    /// before the first face comes up, so the first list a neighbour is sent carries them. A
    /// node that does not gossip ignores it.
    pub fn set_gossip_locators(&self, locators: Vec<String>) {
        #[cfg(feature = "gossip")]
        if let Some(gossip) = &self.gossip {
            gossip.set_self_locators(locators);
        }
        #[cfg(not(feature = "gossip"))]
        let _ = locators;
    }

    /// Send what the gossip plane answered, each message on the face it names. `new_face` is
    /// the face a caller holds the registry lock for and has not inserted yet, with its actions;
    /// every other face is looked up in `faces`.
    #[cfg(feature = "gossip")]
    fn send_gossip(
        faces: &BTreeMap<u64, FaceEntry>,
        new_face: Option<(u64, &Arc<SessionLinkActions>)>,
        outbound: Vec<Outbound>,
    ) {
        for out in outbound {
            let actions = match new_face {
                Some((id, actions)) if id == out.face => Some(actions),
                _ => faces.get(&out.face).map(|face| face.session.actions()),
            };
            // Best-effort per face, as every replay in `face_up`: a face that is ending drops
            // it, and the next list it would have carried supersedes it.
            if let Some(actions) = actions {
                let _ = actions.send_network_message(out.into_message(), true, false);
            }
        }
    }

    /// The local plane's session. A get's and a publish's local legs are issued on
    /// it inside this file ([`Self::fan_query`], the publish fan-out); the ABIs
    /// reach it for what else is session-scope (a held query, the clock).
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
    ///
    /// ## Queries that wait on the local plane
    ///
    /// A get whose leg is the local plane waits on it for as long as the queryable holds the
    /// query it was handed, and a queryable may hold one past the call that delivered it (the
    /// Rust API's does). Such a get ends at its deadline like any other, with the timeout reply
    /// and then its final, and the faces are not there to say when: this arm sweeps the plane's
    /// own pending table and sleeps until the earliest deadline in it, as a face's drive does for
    /// its own. A plane with no get pending has no deadline, and sleeps on the wake alone.
    pub async fn drive_local_plane(&self) {
        loop {
            self.drain_local_plane();
            #[cfg(feature = "query")]
            {
                if self.local.sweep_expired_queries_staged() > 0 {
                    self.drain_local_plane();
                }
                if let Some(due) = self.local.next_reply_deadline_ms() {
                    use wz_runtime_core::TimeSource as _;
                    let wait = due.saturating_sub(self.local.clock().now_monotonic_ms());
                    // The wake or the deadline, whichever comes first; a wake that is not the
                    // deadline sweeps nothing and sleeps again.
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_millis(wait),
                        self.local_wake.notified(),
                    )
                    .await;
                    continue;
                }
            }
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
    ///
    /// R3067 -- `false` when the face is NOT admitted: the node it links to is
    /// already held by another face, and nothing is declared to it. A session
    /// that both dials and listens meets the same peer twice whenever the two
    /// dial each other, and two faces to one node would deliver every sample
    /// twice (measured: 30 duplicates over a six-second window between two wz
    /// peers that each listen on and connect to the other, where the real
    /// library keeps one transport and delivers each sample once). Zenoh's
    /// transport manager keeps one transport per zid and adds a further link to
    /// it only while `max_links` allows, which is 1
    /// (`io/zenoh-transport/src/unicast/manager.rs` @
    /// `init_existing_transport_unicast`); the face that came second is the
    /// refused link, and the caller closes it.
    ///
    /// `dialled` says whether this session dialled the link (the dial role) or took it off its
    /// port. Two links to one node that went the same way keep the first up, as above. Two that
    /// went opposite ways are two nodes that dialled each other at the same moment, which "the
    /// first up" decides differently at the two ends (each keeps the link that completed first on
    /// its side, and each closes the one the other kept): the rule then reads the two zids,
    /// which both ends read alike, and keeps the link the lower zid dialled
    /// ([`wz_session_core::link_admission`]). When that is the NEW link, the held face is closed
    /// (`MaxLinks`, the reason zenoh gives) and removed, and the new one takes its place.
    pub fn face_up(&self, id: u64, actions: &Arc<SessionLinkActions>, dialled: bool) -> bool {
        let observer = Arc::new(WzMutex::new(ApplicationLayerObserver::new()));
        // R311y554 — THE hand-off that makes `allowed_destination` honourable.
        //
        // A FACE session's drain is `DriveTask` for both ABIs, and it is a
        // face's own premise: what arrives from this peer, and what a C thread
        // stages on this face (a get's wire leg, a declaration's replay), runs on
        // the drive task, where the face's reply sweep and its deadline wake
        // live. (A face's loopback is `Locality::Remote`, so it has no
        // same-session delivery of its own; that goes through the local plane,
        // whose drain the calling ABI chooses, [`SessionResources::local_delivery`].)
        //
        // R311y554 — this is the hand-off that made `allowed_destination`
        // honourable. Before it a local delivery was REFUSED (`Locality::Remote`
        // pinned in `put_options` / `queryable_options`), because
        // `Session::publish` drains the fires it stages on whatever thread called
        // it, which then ran a callback on the C thread while the drive thread
        // ran the same C context for another face. `DriveTask` moves the drain
        // instead of forbidding the delivery: the C thread stages and returns,
        // [`Self::next_reply_deadline_ms`] reports the face due NOW, its
        // `deadline_revised` wake gets the loop back, and [`Self::dispatch`]
        // drains. zenoh-pico still wants that for the plane; zenoh-c, whose
        // callbacks run on the calling thread, does not (R3069).
        let session = TokioSession::new(actions.clone(), observer, Arc::new(self.clock))
            .with_node_clock(self.node_hlc.clone())
            .with_local_delivery_drain(LocalDeliveryDrain::DriveTask);
        // This face's events are dispatched through the face session's own subscriber
        // registry (`Self::dispatch`) and nothing here filters or forwards the owned
        // messages of a frame, so the drive loop may report a frame of plain Puts as the
        // places of its records and skip building a message for each.
        //
        // Unless the node states a traffic policy: a verdict is read from a message, and a
        // frame reported as places in the datagram has none to read, so a policy that sat
        // beside this lane would be stepped around by exactly the traffic the lane exists for
        // (the receive bypass `tests/interceptors.rs` measures). The policy is installed on the
        // face's session first, both flows, and the lane stays off for this node's faces only.
        #[cfg(feature = "interceptors")]
        self.policy.install_on(&session);
        actions.set_plain_put_lane(!self.has_policy());
        // R3065 -- the face reads what its peer sends through the node's own clients.
        install_shm_reader(&session, &self.shm_clients);

        let mut guard = self.lock();
        // Decided under the lock that inserts the face, so two faces that come up
        // together cannot both pass: the one that takes the lock second sees the
        // first.
        let peer_zid = actions.peer_zid();
        loop {
            let verdict = admission_of(
                &self.zid,
                guard
                    .faces
                    .iter()
                    .map(|(held, face)| (*held, face.peer_zid.as_deref(), face.dialled)),
                id,
                peer_zid.as_deref(),
                dialled,
            );
            match verdict {
                Admission::Admit => break,
                Admission::Refuse => return false,
                Admission::Replace(held_id) => {
                    // The held link is the one to close: it is told why, the way zenoh tells a
                    // link refused for the node it already holds, and its face leaves the
                    // registry, with the events and the replay state that go with it, before
                    // this one is admitted. Both happen OUTSIDE the lock, which a close and a
                    // face's departure take again. The decision is read again after, because the
                    // registry may have changed while the lock was open.
                    let held = guard
                        .faces
                        .get(&held_id)
                        .map(|face| face.session.actions().clone());
                    drop(guard);
                    if let Some(held) = held {
                        held.send_close_with_reason(
                            wz_session_core::close_reason::CloseReason::MaxLinks,
                        );
                    }
                    self.face_down(held_id);
                    guard = self.lock();
                }
            }
        }
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
                (entry.sink)(&TokioQueryHolder::Unicast(session.clone())),
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
        for entry in guard.matches.iter().filter(|entry| entry.count_remote) {
            if let Some(listener) = install_matching_watch(
                entry.plane,
                &session,
                &entry.keyexpr,
                entry.upstream_rule,
                face_matching_callback(id, entry),
            ) {
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
        // R3074 -- gossip: the new face is told every node this one knows and where each can be
        // reached, and the faces that hear of a new link are told this one is up. Sent from
        // here, with the face's identity read off its handshake (this runs past a completed
        // one), so a face that was refused above is never announced. The plane takes its own
        // lock for the decision and returns, so what is sent here is sent under this lock only.
        #[cfg(feature = "gossip")]
        if let Some(gossip) = &self.gossip {
            let outbound = gossip.face_up(id, &FaceIdentity::of(actions));
            Self::send_gossip(&guard.faces, Some((id, actions)), outbound);
        }
        // R3073 -- the LAST line of the replay: a peer this node meets as a north-bound peer is
        // told that what it has been sent is everything this node held, which is the message its
        // open waits for. Per face, under the lock the replays above ran under, so it cannot
        // precede a declaration this face is owed from the registry.
        if self.initial_interest {
            let _ = session.send_initial_interest_final();
        }
        // R2932 — the groups, so a member joined before this peer connected
        // announces itself to it. Best-effort per face like every replay above:
        // the join's only fallible checks (canon, wildcards) already passed on
        // the local plane when the C program joined.
        #[cfg(feature = "group")]
        let mut groups = BTreeMap::new();
        #[cfg(feature = "group")]
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
        let snapshot = snapshot_of(&session);
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
                #[cfg(feature = "group")]
                groups,
                revised: Arc::new(Notify::new()),
                peer_zid,
                dialled,
            },
        );
        guard.refresh_face_set();
        drop(guard);
        // R2932 — a replaced entry's group copies are copies of a session that
        // is gone, so their members leave the union the way `face_down`'s do.
        if let Some(mut old) = replaced {
            old.retire_groups();
        }
        // Outside the lock, for the reason `fire_face_event` states: a C
        // listener may re-enter this registry.
        if let Some(snapshot) = snapshot {
            self.fire_face_event(FaceEventKind::Up, &snapshot);
        }
        true
    }

    /// Whether some face already links this session to the node `zid`.
    ///
    /// The accept loop asks it before it admits an inbound link, so a node that
    /// is already held by a face the DIAL role made is not given a second one
    /// ([`Self::face_up`] states the rule).
    pub fn holds_peer(&self, zid: &[u8]) -> bool {
        // By the id and not its spelling: a caller holds the id from the routing graph
        // (trimmed) and a face holds the bytes its peer sent.
        self.lock().faces.values().any(|face| {
            face.peer_zid
                .as_deref()
                .is_some_and(|held| wz_runtime_tokio::zid_hex::same_zid(held, zid))
        })
    }

    /// Whether a link the node `zid` dialled to this session's port is refused, because a face
    /// that stays already links the session to it. The accept loop asks it before it admits the
    /// link, which is [`Self::holds_peer`] for a link that is not the one to keep: a face the
    /// dial role made yields to an inbound link the lower zid dialled (the rule is
    /// [`Self::face_up`]'s), and that link is then admitted and replaces it.
    pub fn refuses_inbound_from(&self, zid: &[u8]) -> bool {
        let guard = self.lock();
        // No face has id `u64::MAX`, so every held face is a candidate.
        admission_of(
            &self.zid,
            guard
                .faces
                .iter()
                .map(|(held, face)| (*held, face.peer_zid.as_deref(), face.dialled)),
            u64::MAX,
            Some(zid),
            false,
        ) == Admission::Refuse
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
        // R3074 -- the node at the far end leaves the gossip graph with its face, so a node that
        // returns is told of as a new one. Upstream's gossip tells nobody that a link went.
        #[cfg(feature = "gossip")]
        if let Some(gossip) = &self.gossip {
            gossip.face_down(id);
        }
        // Drop OUTSIDE the lock: dropping the entry drops its subscribers,
        // and the last one may release the final `Arc<CClosure>` and run the
        // C `drop(context)`.
        let removed = {
            let mut guard = self.lock();
            let removed = guard.faces.remove(&id);
            // In the same step as the removal, so a reader (which holds this lock) sees the
            // face's count in one place and never in two or in none.
            #[cfg(feature = "resource-snapshot")]
            if let Some(entry) = &removed {
                guard
                    .receive_ledger
                    .retire(&entry.session.actions().message_reading());
            }
            guard.refresh_face_set();
            removed
        };
        // R2259 (item 593) — the DEPARTED face's identity, taken while the
        // entry is still alive. There is no other moment: `face_down` is handed
        // an id, and once the entry drops nothing can say which peer it was.
        if let Some(snapshot) = removed.as_ref().and_then(|e| snapshot_of(&e.session)) {
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
            entry.retire_groups();
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
        let faces = {
            let mut guard = self.lock();
            let faces = std::mem::take(&mut guard.faces);
            guard.refresh_face_set();
            faces
        };
        // Open-debt item 913 — and the groups: a get pending on one ends with its
        // session, as a unicast face's does.
        #[cfg(feature = "multicast-transport")]
        {
            let groups = {
                let mut guard = self.lock();
                let groups = std::mem::take(&mut guard.mcast_faces);
                guard.refresh_mcast_set();
                groups
            };
            drop(groups);
        }
        // R2932 — a closed session sees no peer, so a C group's union loses
        // every member it heard over the wire, as `face_down` would take them.
        for mut entry in faces.into_values() {
            entry.retire_groups();
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
            // R3074 -- a topology list that arrived on this face is gossip's, and what it
            // answers (a node to be told of, a list to pass on) is sent on the faces it names.
            // The plane decides under its own lock and returns, so this holds no lock across a
            // send; the registry's is taken for the lookup of each target alone.
            #[cfg(feature = "gossip")]
            if let (
                Some(gossip),
                IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }),
            ) = (&self.gossip, &event)
            {
                let outbound = gossip.inbound(id, messages);
                if !outbound.is_empty() {
                    let faces = self.lock();
                    Self::send_gossip(&faces.faces, None, outbound);
                }
            }
            session.dispatch_iteration_event(event);
            // The sweeps only STAGE what they expire; the one drain at the end of
            // this call runs it, so a frame that expires nothing pays one drain
            // and not three.
            #[cfg(feature = "query")]
            session.sweep_expired_queries_staged();
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
            #[cfg(feature = "liveliness-get")]
            session.sweep_expired_liveliness_gets_staged();
            // R311y554 — the DRIVE-TASK half of the local-delivery hand-off.
            //
            // What a C thread staged on THIS face session (and, for an ABI whose
            // plane drains on the drive task, a C-thread `z_put` whose
            // `allowed_destination` allows local: it stages its subscriber fires
            // and returns without running them, `LocalDeliveryDrain::DriveTask`,
            // set in `face_up`). This is where they run. Explicit rather than
            // left to the two sweeps above,
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
            #[cfg(feature = "query")]
            let reply = session.next_reply_deadline_ms();
            // No get, no pending reply to expire.
            #[cfg(not(feature = "query"))]
            let reply: Option<u64> = None;
            #[cfg(feature = "liveliness-get")]
            let reply = match (reply, session.next_liveliness_get_deadline_ms()) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (only, None) | (None, only) => only,
            };
            reply
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
    /// session-scope local plane (`Self::local`), so it runs identically at zero
    /// faces and at N, and the "first face takes it" convention (with the
    /// zenoh-c divergence it carried at zero faces) is gone.
    pub fn publish_all(
        &self,
        keyexpr: &str,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        self.fan_out(opts, PutKey::Literal(keyexpr), payload, |session, leg| {
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
        payload: Arc<wz_runtime_tokio::shm_provider::ShmBackedPayload>,
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        self.fan_out_with(
            opts,
            PutKey::Literal(keyexpr),
            payload,
            |session, leg, payload| Leg::of_publish(session.publish_shm(keyexpr, payload, leg)),
            |session, leg, payload| {
                Leg::Delivered(session.deliver_shm_local_owned(keyexpr, payload, leg))
            },
        )
    }

    /// [`Self::publish_aliased_all`] for a payload that lives in shared memory: the key is
    /// named on the wire by the declared id, and the payload is the descriptor where a face
    /// negotiated shared memory.
    #[cfg(feature = "transport-shm")]
    pub fn publish_shm_aliased_all(
        &self,
        mapping_id: u64,
        suffix: Option<&str>,
        payload: Arc<wz_runtime_tokio::shm_provider::ShmBackedPayload>,
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        self.fan_out_with(
            opts,
            PutKey::Alias { mapping_id, suffix },
            payload,
            |session, leg, payload| {
                Leg::of_alias(session.publish_shm_aliased_auto(mapping_id, suffix, payload, leg))
            },
            |session, leg, payload| {
                Leg::of_alias(
                    session.deliver_shm_local_aliased_owned(mapping_id, suffix, payload, leg),
                )
            },
        )
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
    fn fan_out<F>(
        &self,
        opts: &PublishOptions,
        key: PutKey<'_>,
        payload: &[u8],
        send: F,
    ) -> Result<usize, FanoutError>
    where
        F: Fn(&TokioSession, PublishOptions) -> Leg,
    {
        self.fan_out_with(
            opts,
            key,
            payload,
            |session, leg, _| send(session, leg),
            |session, leg, _| send(session, leg),
        )
    }

    /// [`Self::fan_out`] for a publish whose payload the caller GIVES UP: `payload` is lent to
    /// each wire leg and handed over to the local leg, which runs last. R3069 -- a local
    /// subscriber's callback now runs inside the put, and what it is handed must be the
    /// buffer the put moved, not a second reference beside the put's own (see
    /// [`wz_runtime_tokio::session::Session::deliver_shm_local_owned`]).
    fn fan_out_with<P, R, L>(
        &self,
        opts: &PublishOptions,
        key: PutKey<'_>,
        payload: P,
        remote_leg: R,
        local_leg: L,
    ) -> Result<usize, FanoutError>
    where
        P: LegBytes,
        R: Fn(&TokioSession, PublishOptions, &P) -> Leg,
        L: FnOnce(&TokioSession, PublishOptions, P) -> Leg,
    {
        let targets = self.fan_targets();
        let mut delivered = 0usize;
        if opts.allowed_destination.allows_remote() {
            let remote = opts.clone().with_locality(Locality::Remote);
            let literal = key.literal();
            for session in targets.faces.iter() {
                // A peer that has said it wants nothing this key reaches is not written to (see
                // `Session::peer_wants_no_put_on`); a put with no literal key in hand, an alias
                // alone, is written to every face as before.
                if literal.is_some_and(|key| session.peer_wants_no_put_on(key)) {
                    continue;
                }
                match remote_leg(session, remote.clone(), &payload) {
                    Leg::Delivered(n) => delivered += n,
                    Leg::Skipped => {}
                    Leg::Refused => return Err(FanoutError::ExceedsCapacity),
                }
            }
            delivered += self.group_fan(&targets, &remote, key, &payload)?;
        }
        if opts.allowed_destination.allows_local() {
            let local = opts.clone().with_locality(Locality::SessionLocal);
            match local_leg(&self.local, local, payload) {
                Leg::Delivered(n) => {
                    delivered += n;
                    // Only a delivery stages anything for the drain to run; a
                    // publish no subscriber of this session matched woke the
                    // drive loop for nothing, once per message.
                    if n > 0 {
                        self.local_wake.notify_one();
                    }
                }
                // The plane's link is inert, so the skipped arm is unreachable through
                // it; kept because the local leg's error handling must not be more
                // brittle than the wire leg's if the plane ever changes.
                Leg::Skipped => {}
                Leg::Refused => return Err(FanoutError::ExceedsCapacity),
            }
        }
        Ok(delivered)
    }

    /// The faces and the groups a fan-out sends to, read in ONE step of the registry, so a
    /// face and a group that come or go together are both in it or both out.
    fn fan_targets(&self) -> FanTargets {
        self.lock().fan_targets()
    }

    /// The group legs of a publish (open-debt item 913): ONE send per group reaches every
    /// member. A group told the session's keyexprs
    /// ([`crate::drive::GroupDeclarations::declares_keyexprs`]) is sent an alias as the alias,
    /// as zenoh-pico names a put's key with its multicast declarations on; any other group
    /// is told no declaration, so the key goes by its literal, and an alias is resolved to
    /// it through the local plane, which holds every declaration this session made
    /// ([`Self::declare_keyexpr`]); an alias the plane does not know is one no face was told
    /// of either, and is skipped here as it is there. Best-effort per group, as per face: a
    /// group whose link is down is skipped, and only an error every leg would meet is
    /// surfaced.
    #[cfg(feature = "multicast-transport")]
    fn group_fan(
        &self,
        targets: &FanTargets,
        remote: &PublishOptions,
        key: PutKey<'_>,
        payload: &dyn LegBytes,
    ) -> Result<usize, FanoutError> {
        if targets.groups.is_empty() {
            return Ok(0);
        }
        let literal = match key {
            PutKey::Literal(literal) | PutKey::Declared { literal, .. } => {
                std::borrow::Cow::Borrowed(literal)
            }
            PutKey::Alias { mapping_id, suffix } => {
                let Some(mut literal) = self.local.actions().resolve_outbound_mapping(mapping_id)
                else {
                    return Ok(0);
                };
                if let Some(suffix) = suffix {
                    literal.push_str(suffix);
                }
                std::borrow::Cow::Owned(literal)
            }
        };
        let declared = match key {
            PutKey::Alias { mapping_id, suffix }
            | PutKey::Declared {
                mapping_id, suffix, ..
            } => Some(wz_runtime_tokio::session::GroupKey { mapping_id, suffix }),
            PutKey::Literal(_) => None,
        };
        let mut delivered = 0usize;
        for group in targets.groups.iter() {
            let name = declared.filter(|_| group.declarations.declares_keyexprs());
            // A chunk of shared memory goes to a group that is a shared-memory one as its
            // descriptor, the one send that reaches every member; any other group, and a
            // payload in no chunk, is sent the bytes.
            #[cfg(feature = "transport-shm")]
            if let (true, Some(chunk)) = (group.shm, payload.shm_chunk()) {
                // The wire leg fires no subscriber of this session: the count is the bytes
                // leg's, which is zero for a send that carries no loopback.
                let sent = group
                    .session
                    .publish_shm_on_group(&literal, name, chunk, remote.clone())
                    .map(|()| 0);
                match Leg::of_publish(sent) {
                    Leg::Delivered(n) => delivered += n,
                    Leg::Skipped => {}
                    Leg::Refused => return Err(FanoutError::ExceedsCapacity),
                }
                continue;
            }
            let bytes = payload.leg_bytes();
            let sent = match name {
                Some(name) => {
                    group
                        .session
                        .publish_named_on_group(&literal, name, bytes, remote.clone())
                }
                None => group.session.publish(&literal, bytes, remote.clone()),
            };
            match Leg::of_publish(sent) {
                Leg::Delivered(n) => delivered += n,
                Leg::Skipped => {}
                Leg::Refused => return Err(FanoutError::ExceedsCapacity),
            }
        }
        Ok(delivered)
    }

    /// A build without the multicast transport has no group to reach.
    #[cfg(not(feature = "multicast-transport"))]
    fn group_fan(
        &self,
        _targets: &FanTargets,
        _remote: &PublishOptions,
        _key: PutKey<'_>,
        _payload: &dyn LegBytes,
    ) -> Result<usize, FanoutError> {
        Ok(0)
    }

    /// Whether some peer of this session negotiated shared memory and reads the default (POSIX)
    /// protocol, or some group of it is a shared-memory one: whether a payload put into shared
    /// memory would be sent to anyone as a descriptor. A host that promotes large payloads into
    /// shared memory asks first, so that it copies nothing for a session none of whose peers
    /// could read it.
    #[cfg(feature = "transport-shm")]
    pub fn has_shm_peer(&self) -> bool {
        let targets = self.fan_targets();
        #[cfg(feature = "multicast-transport")]
        if targets.groups.iter().any(|group| group.shm) {
            return true;
        }
        targets
            .faces
            .iter()
            .any(|session| session.actions().shm_admits(0))
    }

    /// [`Self::publish_on_wire_all`] for a payload that is a buffer of shared memory some owner
    /// of a segment holds, which is how a program that supplies its own provider publishes: each
    /// face that negotiated shared memory is sent the buffer's descriptor, each that did not the
    /// bytes read back out of it, and a subscriber of this session is handed the buffer.
    #[cfg(feature = "transport-shm")]
    pub fn publish_shm_handle_on_wire_all(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        payload: wz_session_core::extshm::ShmSendHandle,
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        if wire.is_literal() {
            self.fan_out_with(
                opts,
                PutKey::Literal(keyexpr),
                payload,
                |session, leg, payload| Leg::of_publish(session.publish_shm(keyexpr, payload, leg)),
                |session, leg, payload| {
                    Leg::of_publish(session.publish_shm(keyexpr, &payload, leg))
                },
            )
        } else {
            let mapping_id = wire.mapping_id;
            let suffix = wire.suffix.as_deref();
            self.fan_out_with(
                opts,
                PutKey::Declared {
                    literal: keyexpr,
                    mapping_id,
                    suffix,
                },
                payload,
                |session, leg, payload| {
                    Leg::of_alias(
                        session.publish_shm_aliased_auto(mapping_id, suffix, payload, leg),
                    )
                },
                |session, leg, payload| {
                    Leg::of_alias(
                        session.publish_shm_aliased_auto(mapping_id, suffix, &payload, leg),
                    )
                },
            )
        }
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
            self.publish_aliased_all_for(
                Some(keyexpr),
                wire.mapping_id,
                wire.suffix.as_deref(),
                payload,
                opts,
            )
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
        self.publish_aliased_all_for(None, mapping_id, suffix, payload, opts)
    }

    /// [`Self::publish_aliased_all`] for a caller that also holds the literal key the alias
    /// stands for, which is what lets a peer that wants nothing the key reaches be left
    /// unwritten; without it every face is written to.
    fn publish_aliased_all_for(
        &self,
        key: Option<&str>,
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
        let key = match key {
            Some(literal) => PutKey::Declared {
                literal,
                mapping_id,
                suffix,
            },
            None => PutKey::Alias { mapping_id, suffix },
        };
        self.fan_out(opts, key, payload, |session, leg| {
            Leg::of_alias(session.publish_aliased_auto(mapping_id, suffix, payload, leg))
        })
    }

    /// [`Self::publish_aliased_all`] for a caller that holds the literal the alias stands for:
    /// a publisher declared over a key keeps it, and handing it over spares every face the
    /// lookup that finds it again (a lock on the face's outbound table and a copy of the
    /// string, once per face and once more for the local leg, per message).
    ///
    /// The faces are the ones the key was announced on: [`Self::face_up`] replays every
    /// declaration before a face is visible to a sender, so a face in the registry holds the
    /// mapping, and the lookup was a check of something already true. A face whose declare
    /// failed mid-teardown is a face that is going away.
    pub fn publish_declared_all(
        &self,
        keyexpr: &str,
        mapping_id: u64,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        let key = PutKey::Declared {
            literal: keyexpr,
            mapping_id,
            suffix: None,
        };
        self.fan_out(opts, key, payload, |session, leg| {
            Leg::of_alias(
                session
                    .publish_aliased(mapping_id, None, keyexpr, payload, leg)
                    .map_err(PublishAliasError::from),
            )
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
        // Open-debt item 913 — and every group told the session's keyexprs.
        #[cfg(feature = "multicast-transport")]
        Self::announce_keyexpr_on_groups(&guard, id, &keyexpr);
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
                #[cfg(feature = "multicast-transport")]
                Self::announce_keyexpr_on_groups(&guard, id, &keyexpr);
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
    /// queryable twins: a `KexprEntry` owns a `String` and no `Arc<CClosure>`,
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
        #[cfg(feature = "multicast-transport")]
        Self::retract_keyexpr_on_groups(guard, mapping_id);
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
        let id = guard.try_take_entity_id()?;

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
        // Open-debt item 913 — and every group the session joined is told of it, as its ABI
        // says.
        #[cfg(feature = "multicast-transport")]
        Self::announce_token_on_groups(&guard, id, &keyexpr, &wire);
        // The session's own liveliness subscribers, told of the token once the registry is
        // unlocked: what they run may re-enter the session.
        let legs = self.own_liveliness_legs(&guard, &keyexpr);
        guard.tokens.push(TokenEntry {
            id,
            keyexpr: keyexpr.clone(),
            wire,
            options,
        });
        drop(guard);
        tell_liveliness(legs, LivelinessSampleKind::Put, &keyexpr, id);
        Some(id)
    }

    /// Retract a C liveliness token: drop the SSOT entry so no future face
    /// announces it, and drop every face's wz token — each emitting that face's
    /// UndeclToken, which is what tells subscribers the resource is gone.
    pub fn undeclare_liveliness_token(&self, id: TokenId) {
        let mut dropped = Vec::new();
        let mut dropped_entry = None;
        let mut told = None;
        {
            let mut guard = self.lock();
            // R2959 — moved OUT, like every other plane's entry: its `WireKey`
            // may keep a keyexpr declaration alive, and releasing the last one
            // retracts it through this registry.
            if let Some(pos) = guard.tokens.iter().position(|e| e.id == id) {
                let keyexpr = guard.tokens[pos].keyexpr.clone();
                told = Some((self.own_liveliness_legs(&guard, &keyexpr), keyexpr));
                // Open-debt item 913 — retracted from every group told of it, by the key the
                // entry holds.
                #[cfg(feature = "multicast-transport")]
                Self::retract_token_on_groups(
                    &guard,
                    id,
                    &guard.tokens[pos].keyexpr,
                    &guard.tokens[pos].wire,
                );
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
        // And the session's own liveliness subscribers, last: the token is gone from the wire
        // when they hear of it.
        if let Some((legs, keyexpr)) = told {
            tell_liveliness(legs, LivelinessSampleKind::Delete, &keyexpr, id);
        }
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
        let id = guard.take_entity_id();

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
        // A history lists the tokens the session itself holds as it lists those of its peers.
        let history: Vec<(TokenId, String)> = if options.history && self.liveliness_to_self {
            guard
                .tokens
                .iter()
                .filter(|token| keyexpr_intersects_text(&keyexpr, &token.keyexpr))
                .map(|token| (token.id, token.keyexpr.clone()))
                .collect()
        } else {
            Vec::new()
        };
        let leg = (!history.is_empty()).then(|| sink());
        guard.live_subs.push(LiveSubEntry {
            id,
            keyexpr,
            history: options.history,
            wire,
            sink,
        });
        drop(guard);
        if let Some(mut leg) = leg {
            for (token_id, key) in &history {
                leg(LivelinessSample {
                    kind: LivelinessSampleKind::Put,
                    keyexpr: key,
                    token_id: *token_id,
                });
            }
        }
        id
    }

    /// The legs of the liveliness subscriptions that the token on `keyexpr` is told to, one per
    /// subscription whose key meets it, when the node tells its own subscribers of its own tokens
    /// ([`SessionResources::liveliness_to_self`]); none otherwise. Minted under the registry's
    /// lock, run after it is let go.
    fn own_liveliness_legs(&self, guard: &Inner, keyexpr: &str) -> Vec<LivelinessLeg> {
        if !self.liveliness_to_self {
            return Vec::new();
        }
        guard
            .live_subs
            .iter()
            .filter(|sub| keyexpr_intersects_text(&sub.keyexpr, keyexpr))
            .map(|sub| (sub.sink)())
            .collect()
    }

    /// Answer a liveliness get with the liveliness tokens of the session itself that meet
    /// `keyexpr`, one reply each, as the leg of the get that no peer is behind: upstream's get
    /// finds the tokens of its own session as well as those of its peers, and zenoh-pico's finds
    /// those of its peers alone ([`SessionResources::liveliness_to_self`]). Returns how many were
    /// found. The replies are made here, one after the other, and not staged.
    pub fn answer_liveliness_get_locally(
        &self,
        keyexpr: &str,
        mut reply: impl FnMut(&dyn ReplyView),
    ) -> usize {
        if !self.liveliness_to_self {
            return 0;
        }
        let found: Vec<String> = self
            .lock()
            .tokens
            .iter()
            .filter(|token| keyexpr_intersects_text(keyexpr, &token.keyexpr))
            .map(|token| token.keyexpr.clone())
            .collect();
        for key in &found {
            reply(&wz_session_core::reply_sink::BorrowedReply {
                rid: 0,
                keyexpr: key,
                kind: wz_runtime_tokio::reply_sink::ReplyKind::Put,
                payload: &[],
                err_encoding: None,
                attachment: None,
                put_encoding: None,
            });
        }
        found.len()
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

    /// `resource-snapshot` — what the receive paths of the unicast faces have counted, those that
    /// are up and those that have gone ([`Inner::receive_ledger`]), as one reading that only
    /// grows. Taken under the registry lock, which is what keeps a face that goes down in the
    /// middle from being counted twice or not at all; the readings themselves are atomic loads.
    /// The groups the session has joined are in it too, each as the one meter of its face, which
    /// counts the transport messages every member of the group delivered.
    #[cfg(feature = "resource-snapshot")]
    pub fn message_reading(&self) -> wz_session_core::resource_snapshot::BuildMessageReading {
        let guard = self.lock();
        let live = guard
            .faces
            .values()
            .map(|face| face.session.actions().message_reading());
        #[cfg(feature = "multicast-transport")]
        let live = live.chain(
            guard
                .mcast_faces
                .values()
                .map(|face| face.messages.reading()),
        );
        guard.receive_ledger.total(live)
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
            .filter_map(snapshot_of)
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

    /// The sessions of the live faces, as one shared list: a reference to what the registry
    /// keeps, not a list collected and cloned from it, which is what a sender that only needs
    /// the sessions takes for every message. A list taken here is the faces as of one step of
    /// the registry; a face that comes or goes after is not in it.
    pub fn face_set(&self) -> Arc<Vec<TokioSession>> {
        self.lock().face_set.clone()
    }

    /// A Put on a key the caller declared, from options that stay the same for its stream
    /// ([`PublishOptions::plain_put_params`]), sent to every face with none of the per-message
    /// set-up of [`Self::publish_declared_all`]: no clone of the options, no list of faces
    /// built, no metadata bundle, no loopback leg.
    ///
    /// `None` when the put is not plain HERE, and nothing has been sent: this node's own
    /// subscriber wants it (the loopback leg then has work that only the general publish
    /// does), or a face stamps what it sends (so the put would carry a timestamp). The caller
    /// then takes [`Self::publish_declared_all`], which does both. `Some` is what that call
    /// would have answered.
    pub fn put_plain_declared(
        &self,
        keyexpr: &str,
        mapping_id: u64,
        payload: &[u8],
        params: &wz_runtime_tokio::session::PlainPutParams,
    ) -> Option<Result<usize, FanoutError>> {
        if params.destination.allows_local() && self.local.has_local_delivery_for(keyexpr) {
            return None;
        }
        let targets = self.fan_targets();
        self.put_plain_to(&targets, keyexpr, mapping_id, payload, params)
    }

    /// [`Self::put_plain_declared`] for a publisher that has a write filter
    /// ([`Self::declare_write_filter`]): the filter's answer and the faces are read in ONE
    /// step of the registry rather than two, when the filter's kept answer is still the
    /// current one, which is every put but the first after a declaration changed.
    ///
    /// [`FilteredPut::Suppressed`] is the filter saying nothing matches, with nothing sent;
    /// [`FilteredPut::Sent`] is what [`Self::put_plain_declared`] answered `Some`;
    /// [`FilteredPut::NotPlain`] is its `None`, and nothing has been sent.
    ///
    /// A DEBUG build always asks the filter the long way round
    /// ([`Self::write_filter_active`] checks its kept answer against the registries'), so
    /// every test that runs with real faces still tests the counters.
    ///
    /// A session that holds a group (open-debt item 913) answers [`FilteredPut::NotPlain`]
    /// unless the filter holds the put back ([`Self::write_filter_holds_back`]): the lane
    /// writes unicast faces only, so the general publish that follows reaches the group.
    /// zenoh-pico writes to a multicast transport whatever its write filter says unless its
    /// multicast declarations are on (`vendor/zenoh-pico/src/api/api.c` @
    /// `session->_tp._type == _Z_TRANSPORT_MULTICAST_TYPE ||`), when the group's answer holds
    /// the put back as a peer's does.
    pub fn put_plain_filtered(
        &self,
        filter: FilterId,
        keyexpr: &str,
        mapping_id: u64,
        payload: &[u8],
        params: &wz_runtime_tokio::session::PlainPutParams,
    ) -> FilteredPut {
        #[cfg(all(target_has_atomic = "64", not(debug_assertions)))]
        {
            let kept = {
                let guard = self.lock();
                let targets = guard.fan_targets();
                // A session with a group takes the long way below, which asks the filter
                // outside this lock.
                if targets.has_groups() {
                    None
                } else {
                    guard
                        .filters
                        .iter()
                        .find(|e| e.id == filter)
                        // A filter that counts the session's own entities has no kept answer
                        // for them; it is asked the long way, which reads them.
                        .filter(|entry| !entry.count_local)
                        .and_then(|entry| {
                            let token = guard.filter_token(entry.plane)?;
                            let kept = entry.cache?;
                            ((kept.generation, kept.epoch_sum) == token)
                                .then_some((kept.inactive, targets))
                        })
                }
            };
            if let Some((inactive, targets)) = kept {
                if inactive {
                    return FilteredPut::Suppressed;
                }
                return self.put_plain_after_filter(&targets, keyexpr, mapping_id, payload, params);
            }
        }
        let targets = self.fan_targets();
        if targets.has_groups() {
            if !targets.has_unasked_groups() && self.write_filter_active(filter) {
                return FilteredPut::Suppressed;
            }
            return FilteredPut::NotPlain;
        }
        if self.write_filter_active(filter) {
            return FilteredPut::Suppressed;
        }
        self.put_plain_after_filter(&targets, keyexpr, mapping_id, payload, params)
    }

    /// The part of [`Self::put_plain_declared`] that follows the filter, on faces already read.
    fn put_plain_after_filter(
        &self,
        targets: &FanTargets,
        keyexpr: &str,
        mapping_id: u64,
        payload: &[u8],
        params: &wz_runtime_tokio::session::PlainPutParams,
    ) -> FilteredPut {
        if params.destination.allows_local() && self.local.has_local_delivery_for(keyexpr) {
            return FilteredPut::NotPlain;
        }
        match self.put_plain_to(targets, keyexpr, mapping_id, payload, params) {
            Some(sent) => FilteredPut::Sent(sent),
            None => FilteredPut::NotPlain,
        }
    }

    /// The wire legs of [`Self::put_plain_declared`], on faces already read: `None` when one
    /// of them stamps what it sends, or when the session holds a group (open-debt item 913),
    /// which only the general publish reaches.
    fn put_plain_to(
        &self,
        targets: &FanTargets,
        keyexpr: &str,
        mapping_id: u64,
        payload: &[u8],
        params: &wz_runtime_tokio::session::PlainPutParams,
    ) -> Option<Result<usize, FanoutError>> {
        if targets.has_groups() {
            return None;
        }
        let sessions = &targets.faces;
        // A node that states a traffic policy sends through the general publish: this lane writes
        // the frame without building the message a verdict reads, so the policy's egress half
        // (an ACL deny, a size cap, a rate) would never be asked. Every caller of the lane goes
        // through here, which is why the test is here and not in each of them. (The session
        // refuses the lane too, for a caller that did not ask: `Session::publish_plain_declared`.)
        if self.has_policy() {
            return None;
        }
        if params.destination.allows_remote() {
            if sessions.iter().any(|session| session.stamps_publishes()) {
                return None;
            }
            for session in sessions.iter() {
                if session.peer_wants_no_put_on(keyexpr) {
                    continue;
                }
                match session.publish_plain_declared(mapping_id, payload, params) {
                    Ok(()) => {}
                    // Per-face and transient, as in the general fan-out: the surviving faces
                    // still receive the sample.
                    Err(PublishError::TransportUnavailable) => {}
                    Err(_) => return Some(Err(FanoutError::ExceedsCapacity)),
                }
            }
        }
        // The loopback leg ran for nobody (nothing here wants the put), as the general
        // publish's would have found.
        Some(Ok(0))
    }

    /// A snapshot of every connected face's session PAIRED with its re-arm
    /// signal — what [`Self::fan_query`] iterates.
    ///
    /// Paired rather than looked up per face afterwards because the two must
    /// come from the same snapshot: a face that leaves the registry between the
    /// two reads would otherwise have its query issued and its wake never
    /// notified.
    pub fn face_sessions_with_wake(&self) -> Vec<(TokioSession, Arc<Notify>)> {
        Self::faces_with_wake(&self.lock())
    }

    /// The fan-out every get shares, the query half of the publish fan-out: the wire leg
    /// to each face, then to each group the session joined, then the local leg ONCE on
    /// the local plane (`Self::local`), each only where `destination` admits it.
    ///
    /// A C session's queryable is declared on every face AND on the plane, so an `Any`
    /// get handed to each face would run its one handler once per face, and at zero
    /// faces there would be no local leg at all. Both ABIs issued their gets through
    /// their own copy of this loop, and the pico copy had exactly that defect (open-debt
    /// item 914): it is one function so the two cannot disagree again.
    ///
    /// `issue` makes the one call a leg is, through the [`QueryLeg`] it is handed, and
    /// answers the leg's request id when it issued one. Each issued leg is recorded
    /// against `fan`; a token cancelled mid-fan stops the loop at that leg (its own undo
    /// has then already run) and no later leg is issued. Each face's drive loop, and each
    /// group's sweep, is woken after its leg, issued or not, so it re-arms on the deadline
    /// just registered: without it a silent session sweeps the get only at its next wake.
    /// The plane's drain is woken after the local leg, for what a local queryable's
    /// handler stages on it; the loopback replies and the final are finalised inside
    /// `Session::query`.
    pub fn fan_query(
        &self,
        destination: Locality,
        fan: Option<&CancellableFan>,
        mut issue: impl FnMut(QueryLeg<'_>) -> Option<u64>,
    ) {
        // `false` when the token cancelled while the fan was running.
        let mut issue_recorded = |leg: QueryLeg<'_>| -> bool {
            match (issue(leg), fan) {
                (Some(rid), Some(fan)) => fan.record(leg.canceller(rid)),
                _ => true,
            }
        };
        if destination.allows_remote() {
            let targets = self.query_targets();
            for (session, revised) in targets.faces {
                if !issue_recorded(QueryLeg::Face(&session)) {
                    return;
                }
                revised.notify_one();
            }
            #[cfg(feature = "multicast-transport")]
            for group in targets.groups.iter() {
                if !issue_recorded(QueryLeg::Group(&group.session)) {
                    return;
                }
                group.revised.notify_one();
            }
        }
        if destination.allows_local() {
            // The local leg is cancellable like a face's; nothing follows it, so a cancel
            // that raced it has nothing further to stop.
            let _ = issue_recorded(QueryLeg::Local(&self.local));
            self.local_wake.notify_one();
        }
    }

    /// The faces and the groups a get's wire legs go to, read in ONE step of the registry:
    /// a face or a group that leaves between two reads would otherwise have its leg issued
    /// and its wake never notified.
    fn query_targets(&self) -> QueryTargets {
        let guard = self.lock();
        QueryTargets {
            faces: Self::faces_with_wake(&guard),
            #[cfg(feature = "multicast-transport")]
            groups: guard.mcast_set.clone(),
        }
    }

    /// Every face's session with its re-arm signal, from the registry as `guard` holds it.
    fn faces_with_wake(guard: &Inner) -> Vec<(TokioSession, Arc<Notify>)> {
        guard
            .faces
            .values()
            .map(|face| (face.session.clone(), face.revised.clone()))
            .collect()
    }

    /// Face `id`'s drive-loop re-arm signal (see `FaceEntry::revised`).
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
        self.lock().take_entity_id()
    }

    /// The session's own clock in whole milliseconds, monotonic: the one its periodic jobs run on.
    pub fn now_ms(&self) -> u64 {
        use wz_runtime_core::TimeSource as _;
        self.clock.now_monotonic_ms()
    }

    /// Run `tick` every `period_ms` in a task of the `net` runtime, on the session's clock, until
    /// it answers `false` or [`Self::stop_ticker`] is called with the id returned.
    #[cfg(feature = "advanced")]
    pub fn start_ticker(&self, period_ms: u64, tick: wz_capi_port::Tick) -> u64 {
        let id = self.next_entity_id();
        let task = wz_runtime_tokio::periodic::spawn_periodic_ms(
            Arc::clone(self.local.clock()),
            period_ms,
            tick,
        );
        self.tickers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id, task);
        id
    }

    /// End the periodic job `id`: its task is aborted, outside the table's lock.
    #[cfg(feature = "advanced")]
    pub fn stop_ticker(&self, id: u64) {
        let task = self
            .tickers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&id);
        drop(task);
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
        let id = guard.take_entity_id();

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
        // Every listener that counts the session's own entities reads it again, whatever origin
        // this one accepts: a listener of upstream's rule counts it either way.
        let local_key = Some(keyexpr.clone());
        let entry = SubEntry {
            id,
            keyexpr,
            allowed_origin,
            wire,
            retraction,
            sink,
        };
        // Open-debt item 913 — and on every group the session joined, by the literal.
        #[cfg(feature = "multicast-transport")]
        Self::subscribe_on_groups(&mut guard, &entry);
        guard.subs.push(entry);
        drop(guard);
        // A subscriber the session's own traffic reaches is a match for every listener
        // that counts the session's own subscribers.
        if let Some(key) = local_key {
            self.refresh_local_matches(FilterPlane::Subscribers, &key);
        }
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
        self.declare_plane_matching_listener(FilterPlane::Subscribers, keyexpr, sink, false)
    }

    /// The matching listener of everything else: it counts what a write filter on `plane`
    /// counts — the subscribers, or the queryables (only complete ones when `plane` requires
    /// it) — and, with `count_local`, the session's own too: zenoh-pico's matching status
    /// with its local switch on, for an entity whose locality admits session-local traffic.
    /// pico's matching listener is its entity's write filter's callback
    /// (`vendor/zenoh-pico/src/net/filtering.c` @ `_z_write_filter_ctx_update_state`), so it
    /// counts what that filter counts. The plane is recorded on the registry's entry, so a
    /// face that comes up later installs the same watch (`MatchEntry::plane`).
    ///
    /// A listener that counts the session's own entities is given their verdict once its
    /// faces are installed, and again after every local declaration that could move it
    /// (`refresh_local_matches`).
    pub fn declare_plane_matching_listener(
        &self,
        plane: FilterPlane,
        keyexpr: String,
        sink: MatchingSink,
        count_local: bool,
    ) -> MatchId {
        // What the peers declare always counts for this form of the call, and the session's own
        // entities when `count_local` says so, by the origin each accepts.
        self.declare_matching_listener_counting(
            plane,
            keyexpr,
            sink,
            if count_local {
                Locality::Any
            } else {
                Locality::Remote
            },
            false,
        )
    }

    /// The matching listener of an entity whose `locality` says whose declarations count:
    /// the peers' (`Remote`), the session's own (`SessionLocal`) or both (`Any`), which is what
    /// upstream's matching status asks of an entity by the destination it was declared with.
    /// A listener of the session's own entities alone installs no watch on any face.
    pub fn declare_matching_listener_in(
        &self,
        plane: FilterPlane,
        keyexpr: String,
        sink: MatchingSink,
        locality: Locality,
    ) -> MatchId {
        self.declare_matching_listener_counting(plane, keyexpr, sink, locality, true)
    }

    /// The listener of [`Self::declare_matching_listener_in`] and of
    /// [`Self::declare_plane_matching_listener`], which differ in whether the session's own
    /// entities count whatever origin each accepts and a peer's queryable only by inclusion
    /// (`upstream_rule`, zenoh's Rust session) or by the origin and by intersection (zenoh-pico's).
    fn declare_matching_listener_counting(
        &self,
        plane: FilterPlane,
        keyexpr: String,
        sink: MatchingSink,
        locality: Locality,
        upstream_rule: bool,
    ) -> MatchId {
        let (count_local, count_remote) = (locality.allows_local(), locality.allows_remote());
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
                .filter(|_| count_remote)
                .map(|(fid, face)| (*fid, face.session.clone()))
                .collect();
            guard.matches.push(MatchEntry {
                id,
                keyexpr: keyexpr.clone(),
                state: state.clone(),
                plane,
                count_local,
                count_remote,
                upstream_rule,
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
                if let Some(listener) =
                    install_matching_watch(plane, &session, &keyexpr, upstream_rule, callback)
                {
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
        // Phase 4 — the session's own entities, for a listener that counts them. No lock
        // is held here, as the matching lock order requires.
        if count_local {
            self.fold_local_match(&state, plane, &keyexpr, upstream_rule);
        }
        id
    }

    /// Fold the session's own verdict for one matching listener into its aggregate, and
    /// deliver it to C when the session verdict flips.
    ///
    /// The verdict is worked out INSIDE the fold, under the aggregate's lock: the registry
    /// lock is taken after the aggregate's, which is the one order the matching lock order
    /// allows ([`deliver_matching_flip`]), and two folds racing a declaration each read the
    /// declarations as they stand when they hold the aggregate, so the last fold delivered
    /// is the current answer.
    fn fold_local_match(
        &self,
        state: &StdMutex<MatchAggregate>,
        plane: FilterPlane,
        keyexpr: &str,
        any_origin: bool,
    ) {
        deliver_matching_flip(state, |agg| {
            let matching = self.lock().local_entity_matches(plane, keyexpr, any_origin);
            agg.apply(LOCAL_PLANE_MEMBER, matching)
        });
    }

    /// Give every matching listener that counts the session's own entities of `plane`'s
    /// kind, and whose key meets `keyexpr`, the verdict after a local declaration or
    /// retraction on `keyexpr` — pico's `_z_write_filter_notify_subscriber` /
    /// `_z_write_filter_notify_queryable` (`vendor/zenoh-pico/src/net/filtering.c`), which
    /// run inside the declare or undeclare, on its thread. Each listener reads the verdict
    /// on its own plane, so one that counts only complete queryables is told whether one is.
    ///
    /// Called with no lock held. The listeners are read under the registry lock and folded
    /// after it is released, by the matching lock order.
    fn refresh_local_matches(&self, plane: FilterPlane, keyexpr: &str) {
        let affected: Vec<(Arc<StdMutex<MatchAggregate>>, FilterPlane, String, bool)> = {
            let guard = self.lock();
            guard
                .matches
                .iter()
                .filter(|entry| {
                    entry.count_local
                        && entry.plane.same_kind(plane)
                        && keyexpr_intersects_text(&entry.keyexpr, keyexpr)
                })
                .map(|entry| {
                    (
                        entry.state.clone(),
                        entry.plane,
                        entry.keyexpr.clone(),
                        entry.upstream_rule,
                    )
                })
                .collect()
        };
        for (state, plane, key, any_origin) in affected {
            self.fold_local_match(&state, plane, &key, any_origin);
        }
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
    /// `deliver_matching_flip` serialisation — is shared with the publisher
    /// path by construction: the only difference is which declaration the
    /// per-face watch is installed on.
    ///
    /// `complete_required` is a querier whose target is `ALL_COMPLETE`: only a complete
    /// queryable matches it, as zenoh's querier asks
    /// (`zenoh/src/api/querier.rs` @ `self.target == QueryTarget::AllComplete,`).
    pub fn declare_querier_matching_listener(
        &self,
        keyexpr: String,
        sink: MatchingSink,
        complete_required: bool,
    ) -> MatchId {
        self.declare_plane_matching_listener(
            FilterPlane::Queryables { complete_required },
            keyexpr,
            sink,
            false,
        )
    }

    /// The SESSION's matching verdict for a QUERIER's `keyexpr` (pico
    /// `z_querier_get_matching_status`): `true` when any connected peer has a
    /// matching QUERYABLE, or this session itself declared one — a complete one
    /// when `complete_required`, as [`Self::declare_querier_matching_listener`]
    /// counts. The publisher twin is [`Self::has_matching`].
    ///
    /// R2579 — over [`Self::matching_planes`], not `face_sessions`: the doc on
    /// that method carries the measurement, and the clause this sentence used to
    /// open with ("ANY connected peer") was the defect written down.
    pub fn has_matching_queryable(&self, keyexpr: &str, complete_required: bool) -> bool {
        self.matching_planes().into_iter().any(|session| {
            session
                .declare_querier(keyexpr.to_owned(), querier_watching(complete_required))
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
    /// `declare_plane_matching_listener` still installs per FACE, so a
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

    /// Whether anything `plane` counts matches `keyexpr`, from the declarations `locality` admits:
    /// the session's own (`SessionLocal`), the peers' (`Remote`), or either (`Any`). The one-shot
    /// twin of [`Self::declare_matching_listener_in`], read fresh from the registries and so
    /// never at odds with what a listener of the same locality last said.
    ///
    /// The sessions are snapshotted out of the lock before they are consulted, as everywhere here.
    pub fn matching_verdict(&self, plane: FilterPlane, keyexpr: &str, locality: Locality) -> bool {
        if locality.allows_local() && self.lock().local_entity_matches(plane, keyexpr, true) {
            return true;
        }
        if !locality.allows_remote() {
            return false;
        }
        self.face_sessions().iter().any(|session| match plane {
            FilterPlane::Subscribers => session.remote_subscribers_match(keyexpr, Locality::Remote),
            FilterPlane::Queryables { complete_required } => session.remote_queryables_match_by(
                keyexpr,
                Locality::Remote,
                complete_required,
                true,
            ),
        })
    }

    /// Declare a WRITE FILTER — zenoh-pico's `_z_write_filter_create`, which a
    /// publisher or querier does once, at declare.
    ///
    /// `ask` is how every peer is asked what the filter counts, or `None` to ask
    /// none of them (a pico peer with no router among its peers asks nobody); the
    /// entry is replayed onto every
    /// face that comes up later, as each other declaration here is. The filter
    /// reads what peers DECLARE, so it needs no callback: [`Self::write_filter_active`]
    /// answers from the registries, and keeps the answer only together with the
    /// counters that say whether those registries have changed since, which is
    /// why it cannot drift from what the peers said.
    ///
    /// The local plane is not asked. The session's own entities count when
    /// `count_local` says so, which is zenoh-pico's local subscriber or queryable switch
    /// with an entity whose locality admits session-local traffic; its default build
    /// counts none (`Z_FEATURE_LOCAL_SUBSCRIBER` is 0). They are read off the
    /// declarations when the filter is asked, never cached.
    ///
    /// Open-debt item 913 — the filter's Interest takes the session's next entity id, asked
    /// or not, as zenoh-pico's `_z_add_interest` takes it before it decides whether to send
    /// (`vendor/zenoh-pico/src/net/primitives.c` @ `intr._id = _z_get_entity_id(zn);`), and
    /// every group a filter asks ([`crate::drive::GroupDeclarations::asks_for_filters`]) is
    /// asked by that id for its members' declarations on `wire`, the key as the peers were
    /// told it. A group that comes up later is not asked: zenoh-pico opens its one transport
    /// before any entity, so it has no such moment.
    pub fn declare_write_filter(
        &self,
        plane: FilterPlane,
        keyexpr: String,
        wire: &WireKey,
        ask: Option<InterestForm>,
        count_local: bool,
    ) -> FilterId {
        let mut guard = self.lock();
        guard.next_filter_id = guard.next_filter_id.wrapping_add(1);
        let id = guard.next_filter_id;
        let interest_id = guard.take_entity_id();
        #[cfg(feature = "multicast-transport")]
        Self::ask_filter_on_groups(&mut guard, id, interest_id, plane, &keyexpr, wire);
        #[cfg(not(feature = "multicast-transport"))]
        let _ = (interest_id, wire);
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
            count_local,
            #[cfg(target_has_atomic = "64")]
            cache: None,
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
            #[cfg(feature = "multicast-transport")]
            Self::end_filter_on_groups(&mut guard, id);
        }
        drop(dropped);
    }

    /// Whether write filter `id` keeps a put, a delete or a get from being sent: it says
    /// nothing matches ([`Self::write_filter_active`]) and the session holds no group the
    /// filter does not ask.
    ///
    /// Open-debt item 913 — zenoh-pico sends on a multicast transport whatever its filter
    /// says unless its `Z_FEATURE_MULTICAST_DECLARATIONS` is on
    /// (`vendor/zenoh-pico/src/api/api.c` @
    /// `session->_tp._type == _Z_TRANSPORT_MULTICAST_TYPE ||`): without it a multicast
    /// session sends its group no Interest, so the filter has no answer to wait for there,
    /// and with it the group's answer is counted as a peer's
    /// ([`crate::drive::GroupDeclarations::asks_for_filters`]). The filter's own answer,
    /// which a matching status reports, is unchanged.
    pub fn write_filter_holds_back(&self, id: FilterId) -> bool {
        !self.fan_targets().has_unasked_groups() && self.write_filter_active(id)
    }

    /// Whether the filter says NOTHING matches — zenoh-pico's
    /// `_z_write_filter_active`, and the reason a put, delete or get is not
    /// sent, unless the session holds a group ([`Self::write_filter_holds_back`]).
    /// `true` until a peer has declared something the filter counts, which
    /// is the state a filter is CREATED in (`ctx->state = WRITE_FILTER_ACTIVE`),
    /// so a publisher with no peer yet suppresses, as upstream's does.
    ///
    /// An unknown id answers `false`: not filtered. A handle that outlived its
    /// filter should send rather than drop silently.
    ///
    /// The registries are read OUTSIDE the registry lock: a face's observer
    /// mutex is taken to answer, and holding this one across it would invert
    /// their order against the drive thread.
    ///
    /// The answer is kept with what it was worked out from: the set of faces and the
    /// counters their sessions move after every change to what a peer has declared
    /// ([`TokioSession::remote_declaration_epochs`]). The counters are read BEFORE the
    /// answer is worked out and a change moves its counter AFTER the table changes, so a
    /// kept answer whose counters have not moved is still the answer, and a put that finds
    /// it costs a lock and a few loads instead of the registries' walk. A stale pairing
    /// can only err towards working the answer out again.
    ///
    /// A DEBUG build checks every kept answer it uses against the answer worked out the
    /// long way, unless a change landed while it was checking: every test that runs with
    /// real faces is then a test of the counters.
    pub fn write_filter_active(&self, id: FilterId) -> bool {
        #[cfg(target_has_atomic = "64")]
        let mut seen: Option<(u64, u64)> = None;
        #[cfg(all(target_has_atomic = "64", debug_assertions))]
        let mut kept_answer: Option<bool> = None;
        let (plane, keyexpr, sessions) = {
            let guard = self.lock();
            let Some(entry) = guard.filters.iter().find(|e| e.id == id) else {
                return false;
            };
            // The session's own entity is a match whatever the peers say, and it is
            // read here rather than kept: no peer's counter moves when it comes or goes.
            if entry.count_local && guard.local_entity_matches(entry.plane, &entry.keyexpr, false) {
                return false;
            }
            #[cfg(target_has_atomic = "64")]
            if let Some(token) = guard.filter_token(entry.plane) {
                if let Some(kept) = entry.cache {
                    if (kept.generation, kept.epoch_sum) == token {
                        #[cfg(not(debug_assertions))]
                        return kept.inactive;
                        #[cfg(debug_assertions)]
                        {
                            kept_answer = Some(kept.inactive);
                        }
                    }
                }
                seen = Some(token);
            }
            (entry.plane, entry.keyexpr.clone(), guard.fan_targets())
        };
        // `Remote`: only what a peer declared counts. See `declare_write_filter`.
        let matching = sessions.faces.iter().any(|session| match plane {
            FilterPlane::Subscribers => {
                session.remote_subscribers_match(&keyexpr, Locality::Remote)
            }
            FilterPlane::Queryables { complete_required } => {
                session.remote_queryables_match(&keyexpr, Locality::Remote, complete_required)
            }
        });
        // Open-debt item 913 — and what the members of each group the filter asks declared.
        #[cfg(feature = "multicast-transport")]
        let matching = matching
            || sessions
                .groups
                .iter()
                .filter(|group| group.declarations.asks_for_filters())
                .any(|group| match plane {
                    FilterPlane::Subscribers => group
                        .session
                        .remote_subscribers_match(&keyexpr, Locality::Remote),
                    FilterPlane::Queryables { complete_required } => group
                        .session
                        .remote_queryables_match(&keyexpr, Locality::Remote, complete_required),
                });
        #[cfg(target_has_atomic = "64")]
        if let Some((generation, epoch_sum)) = seen {
            let mut guard = self.lock();
            #[cfg(debug_assertions)]
            if let Some(kept) = kept_answer {
                // Nothing moved while the long way was walked: then the kept answer and
                // the answer worked out are the answer of the same world.
                if guard
                    .filters
                    .iter()
                    .find(|e| e.id == id)
                    .map(|e| e.plane)
                    .and_then(|p| guard.filter_token(p))
                    == Some((generation, epoch_sum))
                {
                    assert_eq!(
                        kept, !matching,
                        "write filter {id}: the kept answer disagrees with the registries' \
                         at counters ({generation}, {epoch_sum})"
                    );
                }
                return kept;
            }
            if let Some(entry) = guard.filters.iter_mut().find(|e| e.id == id) {
                entry.cache = Some(FilterCache {
                    generation,
                    epoch_sum,
                    inactive: !matching,
                });
            }
        }
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
        #[cfg(feature = "multicast-transport")]
        let dropped_groups;
        {
            let mut guard = self.lock();
            // Open-debt item 913 — the group faces' copies, into the same out-of-lock
            // drop as the unicast faces'.
            #[cfg(feature = "multicast-transport")]
            {
                dropped_groups = Self::unsubscribe_on_groups(&mut guard, id);
            }
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
        // A subscriber the session's own traffic reached is a match no more.
        let local_key = dropped_entry.as_ref().map(|entry| entry.keyexpr.clone());
        drop(dropped);
        #[cfg(feature = "multicast-transport")]
        drop(dropped_groups);
        drop(dropped_entry);
        drop(dropped_live);
        drop(dropped_live_entry);
        if let Some(key) = local_key {
            self.refresh_local_matches(FilterPlane::Subscribers, &key);
        }
    }
}

impl SharedSession {
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
    #[cfg(feature = "group")]
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
    #[cfg(feature = "group")]
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
        let id = guard.take_entity_id();

        // R311y557 — the LOCAL PLANE is in this walk, which is what an
        // in-process `z_get` reaches. The sink factory receives each target's
        // OWN session for the reason it always did: an escaped query owes its
        // deferred replies and its `ResponseFinal` to the session the query
        // arrived on, and for a local query that session is the plane's.
        for face in guard.declaration_targets() {
            let callback = sink(&TokioQueryHolder::Unicast(face.session.clone()));
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
        let local_key = Some(keyexpr.clone());
        let entry = QblEntry {
            id,
            keyexpr,
            complete,
            allowed_origin,
            wire,
            retraction,
            sink,
        };
        // Open-debt item 913 — and on every group the session joined: a member's query
        // reaches it, and its replies leave on the group.
        #[cfg(all(feature = "multicast-transport", feature = "queryable"))]
        Self::answer_on_groups(&mut guard, &entry);
        guard.qbls.push(entry);
        drop(guard);
        // A queryable the session's own gets reach is a match for every listener that
        // counts the session's own queryables.
        if let Some(key) = local_key {
            self.refresh_local_matches(
                FilterPlane::Queryables {
                    complete_required: false,
                },
                &key,
            );
        }
        id
    }

    /// Drop a C queryable: remove it from the SSOT so no future face replays
    /// it, and drop every face's wz queryable for it (each emitting its wire
    /// `Declare(UndeclQueryable)`). Mirror of [`Self::undeclare_subscriber`],
    /// including the drop-outside-the-lock discipline.
    pub fn undeclare_queryable(&self, id: QblId) {
        let mut dropped = Vec::new();
        let mut dropped_entry = None;
        #[cfg(all(feature = "multicast-transport", feature = "queryable"))]
        let dropped_groups;
        {
            let mut guard = self.lock();
            // Open-debt item 913 — the group faces' copies, dropped with the rest.
            #[cfg(all(feature = "multicast-transport", feature = "queryable"))]
            {
                dropped_groups = Self::unanswer_on_groups(&mut guard, id);
            }
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
        // A queryable the session's own gets reached is a match no more.
        let local_key = dropped_entry.as_ref().map(|entry| entry.keyexpr.clone());
        // Drop OUTSIDE the lock — see `undeclare_subscriber`: the last
        // `Arc<CQueryClosure>` release runs the C `drop(context)`.
        drop(dropped);
        #[cfg(all(feature = "multicast-transport", feature = "queryable"))]
        drop(dropped_groups);
        drop(dropped_entry);
        if let Some(key) = local_key {
            self.refresh_local_matches(
                FilterPlane::Queryables {
                    complete_required: false,
                },
                &key,
            );
        }
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
/// into C. (R3069: for zenoh-c's ABI that is no longer the goal -- the real
/// library runs the handler on the calling thread, and its open chooses
/// [`LocalDeliveryDrain::Caller`] for the plane -- but the hazard named here is
/// what zenoh-pico's choice still answers.) Worth stating plainly, because the pin was ALSO the only thing
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
#[cfg(feature = "peer")]
pub struct CApiForwarder {
    shared: Arc<SharedSession>,
    /// R3076 -- added to every face id this forwarder is handed, so the faces of the session's
    /// several listeners stay apart in the registry: each accept loop numbers the faces it
    /// accepts from zero. `0` for the one listener a session had until then.
    base: u64,
}

/// R3076 -- how far apart the face ids of two listeners of one session are. An accept loop's own
/// ids are small and it counts them upward; `1 << 40` of room is more faces than a listener will
/// ever accept, and 2^22 listeners fit below [`DIAL_FACE_ID`].
#[cfg(feature = "peer")]
const LISTENER_FACE_STRIDE: u64 = 1 << 40;

#[cfg(feature = "peer")]
impl CApiForwarder {
    /// The forwarder of the session's FIRST (and, for most sessions, only) listener.
    pub fn new(shared: Arc<SharedSession>) -> Self {
        Self::listening(shared, 0)
    }

    /// The forwarder of the session's listener number `index`, in the order they were bound: its
    /// faces are numbered in a range of their own.
    pub fn listening(shared: Arc<SharedSession>, index: u64) -> Self {
        Self {
            shared,
            base: index * LISTENER_FACE_STRIDE,
        }
    }
}

#[cfg(feature = "peer")]
impl FaceForwarder for CApiForwarder {
    fn register(&self, id: FaceId, actions: &Arc<SessionLinkActions>) {
        // Admitted already: the loop asked `holds_peer` before it got here, and it
        // is a single task, so nothing came up between the question and this call
        // that the loop did not see. A refusal here would be a face the loop holds
        // and the registry does not, which is why the question is asked there.
        let admitted = self.shared.face_up(id.0 + self.base, actions, false);
        debug_assert!(
            admitted,
            "the accept loop admitted a face the registry refuses"
        );
    }

    /// One face per remote node, across BOTH roles: see [`SharedSession::face_up`].
    fn dedups_faces_by_zid(&self) -> bool {
        true
    }

    /// What the node's config asks of the peers its listener accepts.
    #[cfg(any(feature = "access-extauth-usrpwd", feature = "access-extauth-pubkey"))]
    fn session_auth(&self) -> Option<wz_runtime_tokio::accept_loop::SessionAuth> {
        self.shared
            .node_auth()
            .map(crate::node_auth::NodeAuth::session_auth)
    }

    /// The prefix the node's keys carry on the wire, for the sessions its listener accepts.
    #[cfg(feature = "routing-namespace")]
    fn session_namespace(&self) -> Option<wz_session_core::keyexpr_prefix::OwnedNonWildKeyExpr> {
        self.shared.node_namespace().cloned()
    }

    /// A node a face that stays already links this session to: the dial role's, unless the
    /// inbound link is the one to keep ([`SharedSession::face_up`] states the rule).
    fn holds_peer(&self, zid: &[u8]) -> bool {
        self.shared.refuses_inbound_from(zid)
    }

    fn deregister(&self, id: FaceId) {
        self.shared.face_down(id.0 + self.base);
    }

    fn forward(&self, id: FaceId, event: IterationEvent<'_>) {
        self.shared.dispatch(id.0 + self.base, event);
    }

    /// This face's ingress admission: the node's policy applied to the frame before the
    /// subscribers see it. See [`SharedSession::ingress`].
    fn ingress(&self, id: FaceId, outcome: &mut DriverLoopOutcome) {
        self.shared.ingress(id.0 + self.base, outcome);
    }

    /// Arm this face's drive loop on its earliest pending `z_get` deadline, so
    /// [`SharedSession::dispatch`]'s sweep runs when a get is actually due.
    ///
    /// Without this the accepted faces would sweep only on the keepalive wake
    /// (~3333 ms for this crate's 10 s lease), because a query timing out is by
    /// definition traffic-free — so nothing else would wake the loop and a
    /// `timeout_ms = 100` get would report its final 33x late.
    fn next_extra_deadline_ms(&self, id: FaceId) -> Option<u64> {
        self.shared.next_reply_deadline_ms(id.0 + self.base)
    }

    /// Let a C-thread `z_get` wake this face's drive loop so it re-arms on the
    /// new pending query's deadline. Without it the deadline above would only
    /// be re-read at the loop's next wake — the keepalive one, ~3333 ms away —
    /// and every get issued into an idle session would be that late.
    fn deadline_revised(&self, id: FaceId) -> Option<Arc<tokio::sync::Notify>> {
        self.shared.deadline_revised(id.0 + self.base)
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
        let publisher = shared.declare_write_filter(
            FilterPlane::Subscribers,
            "wz/wf/pub".to_owned(),
            &WireKey::literal(),
            None,
            false,
        );
        let querier = shared.declare_write_filter(
            FilterPlane::Queryables {
                complete_required: true,
            },
            "wz/wf/qry".to_owned(),
            &WireKey::literal(),
            None,
            false,
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

    /// zenoh-pico with its local subscriber switch on: a write filter and a matching
    /// listener that count the session's own entities see a subscriber whose locality
    /// admits session-local traffic, and stop seeing it when it is retracted; one whose
    /// locality is remote-only, and a filter that does not count local entities, see
    /// nothing. The matching listener hears both flips, inside the declare and the
    /// undeclare, as pico's write filter calls its listeners there.
    #[test]
    fn the_sessions_own_subscriber_counts_where_the_filter_counts_local_entities() {
        let shared = SharedSession::new(TokioTime::new(), test_zid()).expect("test host entropy");
        let counting = shared.declare_write_filter(
            FilterPlane::Subscribers,
            "wz/local/**".to_owned(),
            &WireKey::literal(),
            None,
            true,
        );
        let remote_only = shared.declare_write_filter(
            FilterPlane::Subscribers,
            "wz/local/**".to_owned(),
            &WireKey::literal(),
            None,
            false,
        );
        let heard = Arc::new(StdMutex::new(Vec::new()));
        let log = heard.clone();
        let sink: MatchingSink = Arc::new(move |matching| log.lock().unwrap().push(matching));
        shared.declare_plane_matching_listener(
            FilterPlane::Subscribers,
            "wz/local/a".to_owned(),
            sink,
            true,
        );
        let no_op: SubscriberSink = Arc::new(|| Box::new(|_sample: &dyn SampleView| {}));

        // A remote-only subscriber is no session-local match.
        let remote_sub =
            shared.declare_subscriber("wz/local/a".to_owned(), Locality::Remote, no_op.clone());
        assert!(shared.write_filter_active(counting));
        assert!(heard.lock().unwrap().is_empty());

        let local_sub = shared.declare_subscriber("wz/local/a".to_owned(), Locality::Any, no_op);
        assert!(
            !shared.write_filter_active(counting),
            "the session's own subscriber opens a filter that counts it"
        );
        assert!(
            shared.write_filter_active(remote_only),
            "and not one that does not"
        );
        assert_eq!(*heard.lock().unwrap(), vec![true]);

        shared.undeclare_subscriber(local_sub);
        assert!(shared.write_filter_active(counting));
        assert_eq!(*heard.lock().unwrap(), vec![true, false]);
        shared.undeclare_subscriber(remote_sub);
    }

    /// The port's periodic job on this engine: a task of the `net` runtime that runs every period
    /// until it is stopped, and `stop_ticker` ends it for good. The count after the stop, and
    /// again a few periods later, is what says it ended and did not merely pause.
    #[cfg(feature = "advanced")]
    #[test]
    fn a_periodic_job_runs_until_it_is_stopped() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use wz_capi_port::SessionEngine;

        let shared = SharedSession::new(TokioTime::new(), test_zid()).expect("test host entropy");
        let runs = Arc::new(AtomicUsize::new(0));
        let count = runs.clone();
        let id = SessionEngine::start_ticker(
            &shared,
            10,
            Arc::new(move || {
                count.fetch_add(1, Ordering::SeqCst);
                true
            }),
        )
        .expect("this engine runs periodic jobs");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while runs.load(Ordering::SeqCst) < 3 {
            assert!(std::time::Instant::now() < deadline, "no third run in 5 s");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        SessionEngine::stop_ticker(&shared, id);
        SessionEngine::stop_ticker(&shared, id);
        std::thread::sleep(std::time::Duration::from_millis(30));
        let after = runs.load(Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(80));
        assert_eq!(
            runs.load(Ordering::SeqCst),
            after,
            "eight periods after the stop it had run no more"
        );
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

    /// A get's legs at zero faces: one local leg, on the plane, exactly when its
    /// destination admits session-local traffic, and never a remote one. The pico
    /// ABI's own copy of this loop issued every leg on a face, so a session with no
    /// peer never reached its own queryable (open-debt item 914).
    #[test]
    fn a_faceless_get_issues_one_local_leg_where_its_destination_admits_one() {
        let shared = SharedSession::new(TokioTime::new(), test_zid()).expect("test host entropy");
        for (destination, expected) in [
            (Locality::Any, vec![Locality::SessionLocal]),
            (Locality::SessionLocal, vec![Locality::SessionLocal]),
            (Locality::Remote, vec![]),
        ] {
            let mut legs = Vec::new();
            shared.fan_query(destination, None, |leg| {
                legs.push(leg.locality());
                None
            });
            assert_eq!(legs, expected, "legs of a {destination:?} get with no face");
        }
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

    /// The plain-put parameters of `options` in a build that sends plain puts, and `None` in one
    /// that does not, after asserting that this is what the build says of itself
    /// (`SENDS_PLAIN_PUTS`: a build that counts or rewrites the owned message, or has no Push
    /// codec, has no plain lane). A test of the lane has nothing to run in the second kind of
    /// build, and what it holds there is this assertion: the build answers that it has none.
    fn plain_params(
        options: &PublishOptions,
    ) -> Option<wz_session_core::publish_options::PlainPutParams> {
        let params = options.plain_put_params();
        assert_eq!(
            params.is_some(),
            wz_session_core::publish_options::SENDS_PLAIN_PUTS,
            "the build's answer for a plain Put is the build's one answer"
        );
        params
    }

    /// The plain lane of a declared key answers for a put that nothing in this node wants (it
    /// is sent to the faces, here none, and delivers to nobody), and STEPS ASIDE for one that
    /// this node's own subscriber wants, sending nothing, so that the general publish keeps
    /// the loopback leg that only it carries out. A put whose destination leaves the node out
    /// is plain whatever subscribes here.
    #[test]
    fn a_plain_put_on_a_declared_key_steps_aside_for_a_local_subscriber() {
        let shared = SharedSession::new(TokioTime::new(), test_zid()).expect("test host entropy");
        let mapping = shared
            .declare_keyexpr("wz/plain/target".to_owned())
            .expect("the first alias id is not exhausted");
        if !wz_session_core::publish_options::SENDS_PLAIN_PUTS {
            // No plain lane in this build: what the test holds here is that the build says so.
            assert!(plain_params(&PublishOptions::put()).is_none());
            return;
        }
        let params =
            plain_params(&PublishOptions::put()).expect("a build with the lane sends plain puts");

        // Nobody here wants it: the lane answers, and the answer is the general publish's.
        assert!(
            matches!(
                shared.put_plain_declared("wz/plain/target", mapping, b"x", &params),
                Some(Ok(0))
            ),
            "no subscriber, no face: sent to nobody"
        );

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
        shared.declare_subscriber("wz/plain/target".to_owned(), Locality::Any, sink);

        // A subscriber of this node wants it: the lane steps aside and delivers nothing...
        assert!(
            shared
                .put_plain_declared("wz/plain/target", mapping, b"y", &params)
                .is_none(),
            "a local subscriber wants it: the general publish owns the loopback leg"
        );
        assert_eq!(
            shared.drain_local_plane(),
            0,
            "stepping aside staged nothing"
        );
        // ...and the general publish, which the caller then takes, delivers it.
        let delivered = shared
            .publish_declared_all(
                "wz/plain/target",
                mapping,
                b"y",
                &PublishOptions::put().with_locality(Locality::Any),
            )
            .expect("a faceless declared publish is not an error");
        assert_eq!(delivered, 1);
        assert_eq!(shared.drain_local_plane(), 1);
        assert_eq!(
            seen.lock().expect("test mutex").as_slice(),
            &[b"y".to_vec()]
        );

        // A destination that leaves this node out is plain whatever subscribes here.
        let remote_only = plain_params(&PublishOptions::put().with_locality(Locality::Remote))
            .expect("a build that sends a plain put sends this one");
        assert!(matches!(
            shared.put_plain_declared("wz/plain/target", mapping, b"z", &remote_only),
            Some(Ok(0))
        ));
        assert_eq!(shared.drain_local_plane(), 0);
    }

    /// The plain lane is the node's to give up, and only the node that states a traffic policy
    /// gives it up. In a build that CAN enforce a policy a node without one still takes the lane
    /// (the same destination that answers `Some` above), and a node with one is answered `None`
    /// for the identical put, so the general publish judges it. Both halves are asserted on one
    /// put: a build that dropped the lane for everyone would fail the first, and one that kept
    /// it for everyone would fail the second.
    #[cfg(feature = "interceptors")]
    #[test]
    fn only_a_node_that_states_a_policy_gives_up_the_plain_lane() {
        use wz_runtime_tokio::zenoh_config::ZenohNodeConfig;

        let put = |policy: crate::node_policy::NodePolicy| {
            let shared = SharedSession::new_with_resources(
                TokioTime::new(),
                test_zid(),
                SessionResources {
                    policy,
                    ..SessionResources::default()
                },
            )
            .expect("test host entropy");
            let mapping = shared
                .declare_keyexpr("wz/plain/target".to_owned())
                .expect("the first alias id is not exhausted");
            let params = plain_params(&PublishOptions::put())
                .expect("a build that can enforce still sends plain puts");
            shared.put_plain_declared("wz/plain/target", mapping, b"x", &params)
        };
        if !wz_session_core::publish_options::SENDS_PLAIN_PUTS {
            // No plain lane in this build, for the node with a policy and the node without one.
            assert!(PublishOptions::put().plain_put_params().is_none());
            return;
        }
        let stated = ZenohNodeConfig::from_json5(
            r#"{ low_pass_filter: [ { messages: ["put"], key_exprs: ["wz/**"], size_limit: 4 } ] }"#,
        )
        .expect("a document a real zenohd starts on")
        .config;

        assert!(
            matches!(put(crate::node_policy::NodePolicy::default()), Some(Ok(0))),
            "a node with no policy keeps the lane"
        );
        assert!(
            put(crate::node_policy::NodePolicy::from_node_config(&stated).expect("compiles"))
                .is_none(),
            "a node with a policy sends through the general publish, which judges the put"
        );
    }

    /// The plain lane behind a write filter answers as the filter and the lane answer one
    /// after the other: a filter nothing matches suppresses the put (every time, the first
    /// from the registries and the later ones from the kept answer), a put with no filter of
    /// that id goes on to the lane, and a put this node's own subscriber wants steps aside.
    #[test]
    fn a_plain_put_behind_a_write_filter_answers_as_the_filter_and_the_lane_do() {
        let shared = SharedSession::new(TokioTime::new(), test_zid()).expect("test host entropy");
        let mapping = shared
            .declare_keyexpr("wz/plain/filtered".to_owned())
            .expect("the first alias id is not exhausted");
        let options = PublishOptions::put().with_locality(Locality::Remote);
        if !wz_session_core::publish_options::SENDS_PLAIN_PUTS {
            // No plain lane in this build: what the test holds here is that the build says so.
            assert!(plain_params(&options).is_none());
            return;
        }
        let params = plain_params(&options).expect("a build with the lane sends plain puts");
        let filter = shared.declare_write_filter(
            FilterPlane::Subscribers,
            "wz/plain/filtered".to_owned(),
            &WireKey::literal(),
            None,
            false,
        );

        // No face has said it matches: suppressed, and the same on every later put.
        for _ in 0..3 {
            assert_eq!(
                shared.put_plain_filtered(filter, "wz/plain/filtered", mapping, b"x", &params),
                FilteredPut::Suppressed
            );
        }
        assert!(shared.write_filter_active(filter));

        // A filter the registry does not hold filters nothing: the lane answers.
        assert_eq!(
            shared.put_plain_filtered(
                filter.wrapping_add(1000),
                "wz/plain/filtered",
                mapping,
                b"x",
                &params
            ),
            FilteredPut::Sent(Ok(0))
        );

        // A filter that is gone is a filter that is not held.
        shared.undeclare_write_filter(filter);
        assert_eq!(
            shared.put_plain_filtered(filter, "wz/plain/filtered", mapping, b"x", &params),
            FilteredPut::Sent(Ok(0))
        );

        // A put this node's own subscriber wants steps aside, sending nothing.
        let sink: SubscriberSink = Arc::new(|| Box::new(move |_sample: &dyn SampleView| {}));
        shared.declare_subscriber("wz/plain/filtered".to_owned(), Locality::Any, sink);
        let local = plain_params(&PublishOptions::put().with_locality(Locality::Any))
            .expect("a build that sends a plain put sends this one");
        assert_eq!(
            shared.put_plain_filtered(
                filter.wrapping_add(1000),
                "wz/plain/filtered",
                mapping,
                b"x",
                &local
            ),
            FilteredPut::NotPlain
        );
        assert_eq!(
            shared.drain_local_plane(),
            0,
            "stepping aside staged nothing"
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

    /// Whether a session tells its own liveliness subscribers of its own tokens is its ABI's
    /// choice ([`SessionResources::liveliness_to_self`]): zenoh's does, with the put when a
    /// token is declared, the delete when it is retracted, and the replay a history asks for;
    /// zenoh-pico's tells of its peers' tokens alone. The get is answered the same way.
    #[test]
    fn a_session_tells_its_own_liveliness_subscribers_of_its_own_tokens_when_its_abi_says_so() {
        let heard = |to_self: bool| {
            let shared = SharedSession::new_with_resources(
                TokioTime::new(),
                test_zid(),
                SessionResources {
                    liveliness_to_self: to_self,
                    ..SessionResources::default()
                },
            )
            .expect("test host entropy");
            let told = Arc::new(StdMutex::new(Vec::new()));
            let sink = |told: &Arc<StdMutex<Vec<String>>>| -> LivelinessSink {
                let told = told.clone();
                Arc::new(move || {
                    let told = told.clone();
                    Box::new(move |sample: LivelinessSample<'_>| {
                        told.lock()
                            .unwrap()
                            .push(format!("{} {:?}", sample.keyexpr, sample.kind));
                    })
                })
            };
            shared.declare_liveliness_subscriber(
                "wz/live/**".to_owned(),
                LivelinessSubscriberOptions::default(),
                sink(&told),
            );
            let token = shared
                .declare_liveliness_token("wz/live/a".to_owned())
                .expect("declares");
            let _apart = shared
                .declare_liveliness_token("wz/other".to_owned())
                .expect("declares");
            let replayed = Arc::new(StdMutex::new(Vec::new()));
            shared.declare_liveliness_subscriber(
                "wz/live/*".to_owned(),
                LivelinessSubscriberOptions::default().with_history(true),
                sink(&replayed),
            );
            let mut found = Vec::new();
            let answered = shared.answer_liveliness_get_locally("wz/live/*", |view| {
                found.push(view.keyexpr().to_owned());
            });
            assert_eq!(answered, found.len());
            shared.undeclare_liveliness_token(token);
            let told = told.lock().unwrap().clone();
            let replayed = replayed.lock().unwrap().clone();
            (told, replayed, found)
        };

        let (told, replayed, found) = heard(true);
        assert_eq!(told, ["wz/live/a Put", "wz/live/a Delete"]);
        assert_eq!(
            replayed,
            ["wz/live/a Put", "wz/live/a Delete"],
            "the history lists the token, and the retraction follows"
        );
        assert_eq!(found, ["wz/live/a"]);

        let (told, replayed, found) = heard(false);
        assert!(
            told.is_empty(),
            "zenoh-pico tells of its peers' tokens alone"
        );
        assert!(replayed.is_empty());
        assert!(found.is_empty());
    }
}

/// The registry's decision for a face that comes up to a node it may already hold
/// ([`admission_of`], which [`SharedSession::face_up`] and
/// [`SharedSession::refuses_inbound_from`] both read). The rule itself is
/// `wz_session_core::link_admission`'s and is held there; these hold that this registry hands it
/// the right facts: which face is held, in which direction, and the node's zid however spelled.
#[cfg(test)]
mod admission_tests {
    use super::*;

    const LOW: [u8; 1] = [0x10];
    const HIGH: [u8; 1] = [0xa0];
    const NODE: [u8; 1] = [0x42];

    /// The decision for face `1` to `NODE`, against `held`: `(id, zid, dialled)` rows.
    fn decide(
        local: &[u8],
        held: &[(u64, Option<&[u8]>, bool)],
        zid: Option<&[u8]>,
        dialled: bool,
    ) -> Admission {
        admission_of(local, held.iter().copied(), 1, zid, dialled)
    }

    #[test]
    fn a_face_to_a_node_no_face_holds_is_admitted() {
        assert_eq!(decide(&LOW, &[], Some(&NODE), true), Admission::Admit);
        assert_eq!(
            decide(&LOW, &[(2, Some(&[0x77]), true)], Some(&NODE), true),
            Admission::Admit,
            "a face to another node is no reason to refuse this one"
        );
    }

    #[test]
    fn a_face_that_names_no_node_cannot_be_matched_and_is_held() {
        assert_eq!(
            decide(&LOW, &[(2, Some(&NODE), true)], None, true),
            Admission::Admit
        );
        assert_eq!(
            decide(&LOW, &[(2, None, true)], Some(&NODE), true),
            Admission::Admit,
            "a held face with no zid is not a face to this node"
        );
    }

    #[test]
    fn a_second_link_that_went_the_same_way_is_refused_whatever_the_zids() {
        for dialled in [true, false] {
            for local in [&LOW, &HIGH] {
                assert_eq!(
                    decide(local, &[(2, Some(&NODE), dialled)], Some(&NODE), dialled),
                    Admission::Refuse,
                    "the first up stays (dialled: {dialled})"
                );
            }
        }
    }

    #[test]
    fn of_two_links_that_went_opposite_ways_the_one_the_lower_zid_dialled_is_kept() {
        // This session's zid is the lower one: the link IT dialled wins.
        assert_eq!(
            decide(&LOW, &[(2, Some(&HIGH), false)], Some(&HIGH), true),
            Admission::Replace(2),
            "the new link was dialled by the lower zid, which is this session"
        );
        assert_eq!(
            decide(&LOW, &[(2, Some(&HIGH), true)], Some(&HIGH), false),
            Admission::Refuse,
            "the held link was dialled by the lower zid, so it stays"
        );
        // The node's zid is the lower one: the link IT dialled wins.
        assert_eq!(
            decide(&HIGH, &[(2, Some(&LOW), true)], Some(&LOW), false),
            Admission::Replace(2),
            "the new link was dialled by the lower zid, which is the node"
        );
        assert_eq!(
            decide(&HIGH, &[(2, Some(&LOW), false)], Some(&LOW), true),
            Admission::Refuse,
            "the held link was dialled by the lower zid, so it stays"
        );
    }

    #[test]
    fn the_node_is_matched_by_the_id_and_not_by_its_spelling() {
        // The wire form trims a zid's trailing zero bytes and a handshake keeps the bytes it
        // was given: `[0x42]` and `[0x42, 0x00]` are one node.
        assert_eq!(
            decide(&LOW, &[(2, Some(&[0x42, 0x00]), true)], Some(&[0x42]), true),
            Admission::Refuse
        );
    }

    #[test]
    fn the_face_being_decided_is_not_its_own_rival() {
        // A face id the registry already holds is the face being brought up again: it is not
        // a second link to its own node.
        assert_eq!(
            decide(&LOW, &[(1, Some(&NODE), true)], Some(&NODE), true),
            Admission::Admit
        );
    }
}
