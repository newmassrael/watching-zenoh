// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! [`CoopEngine`]: one session the program steps, behind the C ABI's engine port.
//!
//! ## One lock, and callbacks outside it (decision D8)
//!
//! The session's state is the session shell's: a cooperative task set, `Rc` handles, `RefCell`
//! cells, none of it `Send`. It lives in [`Core`], and every access to it is made under ONE lock,
//! so the engine can be shared between the C session handle and every entity declared on it and
//! called from any thread, as zenoh-pico's multi-threaded arm allows.
//!
//! A C callback never runs under that lock. What the session delivers while it is stepped (a
//! sample for a subscriber, a change of a matching status) is queued as an owned value, and the
//! queue is handed out after the lock is released, so a callback may call back into its session:
//! publish, declare, undeclare itself. zenoh-pico does the same, copying what it delivers out of
//! its session mutex before it calls (`vendor/zenoh-pico/src/session/subscription.c` @
//! `_z_trigger_subscriptions_impl`). The C program's `drop(context)` is reached the same way: an
//! undeclaration takes the callback out under the lock and drops it after.
//!
//! ## A session outlives its link
//!
//! The session is the C program's; a link is one connection of it to a router. When the link is
//! lost, whatever ended it, the session dials its endpoints again, at once and then every
//! [`CoopConfig::redial_ms`] while none answers, and declares over the new link what it holds
//! under the ids it holds it by, as zenoh-pico's client reopens its session
//! (`Z_FEATURE_AUTO_RECONNECT`). What the lost peer declared goes with the link. The dial is
//! stepped like everything else: a step moves the handshake on and returns, so a program that
//! steps its session, or its read task, is what brings the link back.

use alloc::borrow::Cow;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::sync::{Arc, Weak};
use core::any::Any;
use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, Ordering};
// A 64-bit atomic where the target has one, and a critical section where it does not (a
// Cortex-M7 has 32-bit atomics only).
use portable_atomic::{AtomicU64, AtomicUsize};

#[allow(unused_imports)]
use crate::prelude::*;

// The operating system the engine runs on: its mutex, its threads and its sleep are `std`'s on a
// host and the kernel's on an MCU (`docs/upstream-parity.md` section 5a, E1).
#[cfg(feature = "listen")]
use crate::admission_gate::{AdmissionGate, Admitted};
use wz_capi_port::os::{self, JoinHandle, Mutex, MutexGuard, ThreadId};
use wz_capi_port::sync::Lock;
use wz_capi_port::{
    CalledFromReadTask, FanoutError, FilterId, FilterPlane, FilteredPut, MatchId, MatchingSink,
    SessionClosed, SessionDrive, SessionEngine, StatementNotHonoured, SubId, SubscriberSink,
    WireKey,
};
#[cfg(feature = "ticker")]
use wz_capi_port::{Tick, TickerId};
use wz_runtime_coop::session_drive::{
    spawn_session, wait_any, LinkReadiness, LinkWritability, OpenedLink, SessionDatagramLink,
    SessionDriveConfig, SessionLinks, SessionRole,
};
#[cfg(feature = "listen")]
use wz_runtime_coop::session_drive::{LinkListener, LinkOpenError};
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime};
use wz_session_core::close_reason::CloseReason;
use wz_session_core::declare::matching::BoxedMatchingSink;
use wz_session_core::declare::queryable::QuerierCriterion;
use wz_session_core::declare::subscriber::PublisherCriterion;
use wz_session_core::declare_form::{InterestForm, RetractionKey};
use wz_session_core::driver_loop::DriverOutcome;
use wz_session_core::entropy::{EntropySource, EntropyUnavailable};
use wz_session_core::interest_build::InterestKinds;
use wz_session_core::limits::SessionLimits;
#[cfg(feature = "listen")]
use wz_session_core::link_admission::{LinkAdmission, LinkRegistry};
use wz_session_core::locality::Locality;
use wz_session_core::network_message::NetworkMessage;
#[cfg(not(feature = "shared-key-ids"))]
use wz_session_core::policy::KeyWireForm;
use wz_session_core::policy::{SessionPolicy, SnResolution};
use wz_session_core::publish_options::{PlainPutParams, PublishError, PublishOptions};
use wz_session_core::pubsub::SubscriptionId;
use wz_session_core::push_build;
use wz_session_core::qos::CongestionControl;
use wz_session_core::sample::{QosLevel, Sample, SampleKind};
use wz_session_core::send_wire_error::SendWireError;
use wz_session_core::session_init_params::{
    HeldDrop, KeepAliveConf, LinkRxConf, SessionInitParams, SessionZid, TxQueueConf, ZidError,
};
use wz_session_core::session_timeouts::SessionTimeouts;
#[cfg(feature = "shared-key-ids")]
use wz_session_core::shared_key_ids::{KeyIdsAtOpen, KeyIdsRefused, LinkKeyForms, SharedKeyIds};
use wz_session_core::signing_key::SigningKey;
use wz_session_core::sink::{BoxedSink, SampleView};
use wz_session_core::wire_id::{next_u32_id, u32_id_taken, EntityId, ExprId};
use wz_session_core::wireexpr_resolve::{OwnMappingSpace, SharedOwnMappingSpace};
#[cfg(feature = "listen")]
use wz_session_core::zid_hex::same_zid;
use wz_session_core::WhatAmI;
#[cfg(feature = "listen")]
use wz_session_mcu::dial::parse_listen_locator;
use wz_session_mcu::dial::{parse_locator, McuActions};
#[cfg(feature = "queryable")]
use {
    query::{CoopHolder, QueryPlane},
    wz_capi_port::{QblId, QueryCallback, QueryableSink},
    wz_session_core::query::QueryableId,
    wz_session_core::query_sink::BoxedQuerySink,
    wz_session_core::reply_stage::ReplyStage,
    wz_session_core::response_sink::ResponseSink,
};

#[cfg(feature = "queryable")]
mod query;

#[cfg(feature = "group")]
mod group;
#[cfg(feature = "group")]
use {
    group::{GroupEntity, GroupFace, GroupJoining, GroupPut},
    wz_capi_port::group::GroupJoin,
    wz_session_core::declare_form::GroupDeclaration,
};

mod registry;
#[cfg(feature = "local-queryable")]
use registry::LOCAL_FACE;
use registry::{FaceId, Registry, DIAL_FACE};

mod replay;
use replay::{Kind, Replay, TurnEnd};

#[cfg(feature = "ticker")]
mod ticker;
#[cfg(feature = "ticker")]
use ticker::Tickers;
use wz_session_core::replay_pacing::ReplayPacing;

#[cfg(feature = "connectivity")]
mod faces;
#[cfg(feature = "connectivity")]
use faces::FacePlane;
#[cfg(feature = "connectivity")]
use wz_session_core::face::FaceEventSink;
use wz_session_core::face::{FaceEventKind, FaceSnapshot};
#[cfg(feature = "local-queryable")]
use wz_session_core::query::QueryEnvelope;

#[cfg(feature = "liveliness-get")]
use wz_session_core::query_options::DEFAULT_QUERY_TIMEOUT_MS;

#[cfg(feature = "liveliness")]
mod liveliness;
#[cfg(feature = "liveliness")]
use {
    liveliness::{LiveSubEntry, LivelinessCallback, LivelinessQueue, TokenEntry},
    wz_capi_port::{LivelinessSink, TokenId},
};

#[cfg(feature = "query")]
mod get;
#[cfg(feature = "query")]
use {
    get::{GetEvent, GetKind, GetPlane, PendingGet},
    wz_capi_port::{cancellation::CancellableFan, ReplyCallback},
    wz_session_core::query_options::QueryOptions,
    wz_session_core::reply_acceptance::ReplyAcceptance,
    wz_session_core::reply_sink::ConsolidatingSink,
};

/// How a session is opened: what the ABI's config says, which the engine turns into the
/// session's parameters.
pub struct CoopConfig {
    /// The endpoints to dial (`tcp/a.b.c.d:port` or `udp/a.b.c.d:port`), in order: the session
    /// is opened to the first that answers, as zenoh-pico's client opens to the first of its
    /// `connect` locators that does.
    pub endpoints: Vec<String>,
    /// The role the session announces.
    pub whatami: WhatAmI,
    /// The session's zid as the config states it, up to sixteen bytes; `None` mints sixteen
    /// random ones.
    pub zid: Option<Vec<u8>>,
    /// The batch size the session advertises.
    pub batch_size: u16,
    /// The lease the session advertises, in milliseconds.
    pub lease_ms: u64,
    /// How often the session's keepalive speaks on an idle link.
    pub keep_alive: KeepAliveConf,
    /// The width of the sequence numbers the session advertises at its handshake.
    pub sn_resolution: SnResolution,
    /// What the session rejoins from fragments: a chain a fragment would take past its
    /// `max_message_size` is dropped.
    pub link_rx: LinkRxConf,
    /// The transmit model of the ABI the session stands for.
    pub tx_queue: TxQueueConf,
    /// The handshake's deadlines.
    pub timeouts: SessionTimeouts,
    /// How long one endpoint is given to complete the handshake, in milliseconds.
    pub open_timeout_ms: u64,
    /// How long a session whose link was lost waits to dial its endpoints again after a round of
    /// them failed, in milliseconds; the first round is dialled as soon as the loss is seen.
    /// `None` for a session that ends with its link.
    pub redial_ms: Option<u64>,
    /// The longest a read waits for its link to have something to read before it steps the
    /// session, in milliseconds; a read returns as soon as something is there. The wait is made
    /// with nothing of the session held, on a link whose network stack lets its owner wait
    /// (`SessionDatagramLink::readiness`); a link whose stack does not waits in its own loop.
    pub idle_wait_ms: u32,
    /// The endpoints to listen on (`tcp/a.b.c.d:port`; port 0 has the stack choose one, read back
    /// with `CoopEngine::listening`), which the session takes inbound links from for as long as
    /// it lives, each as a face of its own. A session that lists none and dials at least one is
    /// the dial role alone; one that lists some and dials none is only a listener, and is open as
    /// soon as it is bound (`listen`).
    pub listen: Vec<String>,
    /// How many inbound links may be in their handshake at once; one that arrives past it is
    /// closed unread. `transport/unicast/accept_pending` of zenoh, [`DEFAULT_ACCEPT_PENDING`]
    /// by default (`listen`). How long a handshake may take is `timeouts.accepting_inactivity_ms`.
    pub accept_pending: usize,
    /// How many faces the session holds besides the dial role's; an inbound link that arrives
    /// past it is closed unread. `transport/unicast/max_sessions` of zenoh,
    /// [`DEFAULT_MAX_FACES`] by default (`listen`).
    pub max_faces: usize,
    /// The multicast groups the session joins, each a face of its own beside its links, joined
    /// before anything is dialled: what each advertises and what the session tells it of its
    /// declarations is the ABI's (`wz_capi_port::group`). A session that dials nothing and joins
    /// a group is open once the group is joined (`group`; a build without it refuses a group
    /// with [`OpenError::Group`]).
    pub groups: Vec<wz_capi_port::group::GroupJoin>,
    /// What tells a read that the session's clock moved on, for a clock the program moves (a time
    /// base it supplies): a read that waits for its next dial waits on it, and one that waits on
    /// its links waits on it beside them, so the program's word ends the wait. `None` for a clock
    /// that moves by itself, whose waits the wall bounds. Always `None` in a build without
    /// `time-base`, whose [`ClockMovesWord`] has no value.
    pub clock_moves: Option<ClockMovesWord>,
}

/// The program's word that a clock it moves has moved on, as a read of this engine waits on it
/// ([`CoopConfig::clock_moves`]).
#[cfg(feature = "time-base")]
pub trait ClockMoves: Send + Sync {
    /// A wait that is ready once the clock has moved on after this call.
    fn moved(&self) -> Arc<dyn LinkReadiness>;
}

/// What [`CoopConfig::clock_moves`] holds: the program's word that a clock it moves has moved on
/// (`time-base`).
#[cfg(feature = "time-base")]
pub type ClockMovesWord = Arc<dyn ClockMoves>;

/// What [`CoopConfig::clock_moves`] holds in a build without `time-base`: no program moves the
/// clock, so the type has no value and the field is `None`. Uninhabited rather than left out, so a
/// config written for one build is written for the other and the wait the word would end, and the
/// drop of a word, are not in the text.
#[cfg(not(feature = "time-base"))]
pub enum ClockMovesWord {}

/// `wait`, ended also by the program's word that the clock moved on when `moves` gives one: a
/// sleep becomes a wait on the word, and a wait on links waits on it too. With no word, or no
/// wait, it is `wait` as it was.
#[cfg(feature = "time-base")]
fn ended_by_clock_moves(wait: IdleWait, moves: Option<&ClockMovesWord>) -> IdleWait {
    let Some(moves) = moves else {
        return wait;
    };
    match wait {
        IdleWait::None => IdleWait::None,
        IdleWait::Sleep(ms) => IdleWait::Input(vec![moves.moved()], ms),
        IdleWait::Input(mut waits, ms) => {
            waits.push(moves.moved());
            IdleWait::Input(waits, ms)
        }
    }
}

/// `wait` as it was: a build without `time-base` has no word to end it with.
#[cfg(not(feature = "time-base"))]
fn ended_by_clock_moves(wait: IdleWait, moves: Option<&ClockMovesWord>) -> IdleWait {
    if let Some(word) = moves {
        match *word {}
    }
    wait
}

/// Inbound links in their handshake at once, when the config states none: zenoh's
/// `transport/unicast/accept_pending`.
pub const DEFAULT_ACCEPT_PENDING: usize = 100;

/// Faces the session holds besides the dial role's, when the config states none: zenoh's
/// `transport/unicast/max_sessions`.
pub const DEFAULT_MAX_FACES: usize = 1000;

/// The policies a session [`CoopEngine::open`] opens from `config` runs under: the one place that
/// open decides them. The build defaults: the config is what the ABI read from its own keys and
/// values, not a zenoh document with a `wz` member, and it has no field for a policy yet; the
/// ABI's door for one is a key of its own.
fn resolve_policy(_config: &CoopConfig) -> SessionPolicy {
    SessionPolicy::defaults()
}

/// The session limits a session [`CoopEngine::open`] opens from `config` holds its tables to: the
/// one place that open decides them. The build's, for the reason [`resolve_policy`] gives: the
/// config has no field for a limit yet.
fn resolve_limits(_config: &CoopConfig) -> SessionLimits {
    SessionLimits::defaults()
}

/// Why no session was opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// The configuration names no endpoint.
    NoEndpoint,
    /// An endpoint to listen on could not be listened on: it does not parse, the network opens no
    /// listener for its protocol, or the port is taken. The endpoint and the reason; a build
    /// without `listen` answers every listen endpoint this way.
    Listen(String),
    /// A group to join could not be: the network joins no group for its endpoint, or the group's
    /// link did not open. The endpoint and the reason; a build without `group` answers every
    /// group this way.
    Group(String),
    /// No endpoint could be dialled: each was refused, unreachable or did not complete the
    /// handshake in time. The last endpoint's reason.
    Unreachable(String),
    /// The platform gave no entropy for the session's zid or its cookie key.
    EntropyUnavailable,
    /// The configured zid is not one: it is not one to sixteen bytes, or its bytes are all zero.
    InvalidZid(ZidError),
    /// The session states no zid and its `zid-derivation` is `address-ports`, and its `listen`
    /// endpoints give the node no address a zid can be built on.
    ZidDerivation(wz_session_core::zid_derivation::ZidDerivationError),
    /// The session's `key-wire-form` cannot be honoured: see [`KeyWireFormRefused`].
    KeyWireForm(KeyWireFormRefused),
}

/// Why the `key-wire-form` a session was opened under cannot be honoured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyWireFormRefused {
    /// The form is not `declared`, and the build has no key ids every node shares to name a key
    /// by (the `shared-key-ids` feature).
    NotInBuild,
    /// The form is `shared`, for the session or for a link, and the open was given no
    /// dictionary.
    NoDictionary,
    /// The form of one endpoint is stated twice.
    LinkStatedTwice,
}

/// The key ids every node of a deployment shares that an open hands the session, and the
/// endpoints whose key-wire form is stated apart from the session's
/// ([`CoopEngine::open_with_key_ids`]). A build without `shared-key-ids` hands none, and an ABI
/// that opens in either build says so with [`Self::none`].
#[derive(Clone, Default)]
pub struct OpenKeyIds {
    #[cfg(feature = "shared-key-ids")]
    at_open: KeyIdsAtOpen,
}

impl OpenKeyIds {
    /// No dictionary and no endpoint stated apart: the session reads and names its keys as its
    /// key-wire form says, which may not be `shared`.
    pub fn none() -> Self {
        Self::default()
    }

    /// The dictionary `ids`, and no endpoint stated apart.
    #[cfg(feature = "shared-key-ids")]
    pub fn shared(ids: SharedKeyIds) -> Self {
        Self::new(KeyIdsAtOpen {
            ids: Some(ids),
            links: Vec::new(),
        })
    }

    /// What `at_open` states: the dictionary, when there is one, and the endpoints' own forms.
    #[cfg(feature = "shared-key-ids")]
    pub fn new(at_open: KeyIdsAtOpen) -> Self {
        Self { at_open }
    }

    /// The forms of the session's links under `policy`'s key-wire form: `shared`, for the
    /// session or an endpoint, needs a dictionary, and an endpoint is stated once.
    #[cfg(feature = "shared-key-ids")]
    fn admit(&self, policy: &SessionPolicy) -> Result<LinkKeyForms, OpenError> {
        self.at_open
            .forms(policy.key_wire_form())
            .map_err(|refused| {
                OpenError::KeyWireForm(match refused {
                    KeyIdsRefused::DuplicateLink { .. } => KeyWireFormRefused::LinkStatedTwice,
                    _ => KeyWireFormRefused::NoDictionary,
                })
            })
    }

    /// Whether a session may open under `policy`'s key-wire form: only `declared`, which names a
    /// key as upstream does, in a build that has no other. A comparison the open makes in line,
    /// and nothing at all where the build's domain of the policy is that one value.
    #[cfg(not(feature = "shared-key-ids"))]
    #[inline(always)]
    fn admit(&self, policy: &SessionPolicy) -> Result<(), OpenError> {
        match policy.key_wire_form() {
            KeyWireForm::Declared => Ok(()),
            _ => Err(OpenError::KeyWireForm(KeyWireFormRefused::NotInBuild)),
        }
    }
}

/// The zid's wire form: the bytes up to the last non-zero one, as zenoh writes an id. Refused
/// when the configured bytes are not one to sixteen or are all zero, here and once, so the
/// session it opens holds a zid.
pub(crate) fn wire_zid(zid: &[u8]) -> Result<SessionZid, OpenError> {
    let stated = SessionZid::new(zid).map_err(OpenError::InvalidZid)?;
    let len = stated.iter().rposition(|b| *b != 0).map_or(0, |at| at + 1);
    SessionZid::new(&stated[..len]).map_err(OpenError::InvalidZid)
}

/// The session's entropy source, which every draw of the session goes through: its zid, the
/// cookie key of each dial and, in a listening session, the cookie nonce of each handshake it
/// accepts. A board has one source and it is not copied, so the users of it hold the one source
/// behind a lock and draw from it in turn; each accepted session owns a handle of its own, as
/// the session-core's accept path requires of a source (`install_cookie_entropy`).
#[derive(Clone)]
struct SharedEntropy(Arc<Lock<Box<dyn EntropySource + Send>>>);

impl SharedEntropy {
    fn new(source: impl EntropySource + Send + 'static) -> Self {
        Self(Arc::new(Lock::new(Box::new(source))))
    }
}

impl EntropySource for SharedEntropy {
    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
        self.0.with(|source| source.try_fill_bytes(buf))
    }
}

/// Sixteen random bytes, not all zero (an id of zero bytes names nothing).
fn fresh_zid(entropy: &mut dyn EntropySource) -> Result<SessionZid, OpenError> {
    let mut zid = [0u8; 16];
    entropy
        .try_fill_bytes(&mut zid)
        .map_err(|_| OpenError::EntropyUnavailable)?;
    if zid.iter().all(|b| *b == 0) {
        return Err(OpenError::EntropyUnavailable);
    }
    wire_zid(&zid)
}

/// The zid `zid-derivation = address-ports` derives from the `listen` endpoints and eight bytes
/// of `entropy` (see `wz_session_core::zid_derivation`), in its wire form.
pub(crate) fn derived_zid(
    listen: &[String],
    entropy: &mut dyn EntropySource,
) -> Result<SessionZid, OpenError> {
    use wz_runtime_coop::session_drive::LinkProto;
    use wz_session_core::zid_derivation::{ListenerFacts, ListenerTransport, RANDOM_BYTES};
    let mut random = [0u8; RANDOM_BYTES];
    entropy
        .try_fill_bytes(&mut random)
        .map_err(|_| OpenError::EntropyUnavailable)?;
    // The listeners are read with the engine's own locator reader, the one its listens bind
    // through, not the session core's full one: that reader parses every option a locator may
    // carry (TLS material, socket options, numbers in floating point), none of which names an
    // address or a port, and linking it put some thirty kilobytes into every cooperative build.
    let mut facts = ListenerFacts::new();
    for endpoint in listen {
        let Ok(at) = wz_session_mcu::dial::parse_listen_locator(endpoint) else {
            continue;
        };
        let transport = match at.proto {
            LinkProto::Tcp => ListenerTransport::Tcp,
            LinkProto::Udp => ListenerTransport::Udp,
            LinkProto::Tls => continue,
        };
        if let core::net::SocketAddr::V4(address) = at.at {
            if !address.ip().is_multicast() {
                facts.listener(transport, address.ip().octets(), address.port());
            }
        }
    }
    let zid = facts
        .derive(None, random)
        .map_err(OpenError::ZidDerivation)?;
    wire_zid(&zid)
}

/// One session the program steps; see the module doc.
pub struct CoopEngine<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> {
    core: Mutex<Confined<Core<L, C>>>,
    /// The waits for room of the links that are up, asked by a publish that may be dropped while
    /// another holds the session ([`Self::live_to_publish`]), how long it waits
    /// (`congestion_control/drop/wait_before_drop`), and whether the queue profile has it ask at
    /// all (`TxQueueConf::held_drop`).
    rooms: Arc<LinkRooms>,
    wait_before_drop_us: u64,
    held_drop: HeldDrop,
    /// The publishes sending on the session now ([`Sending`]): what holds the session for a
    /// send, which pico's profile drops a droppable publish behind, as against a read step, a
    /// timer or the drive, which it waits for.
    sending: AtomicUsize,
    /// The droppable publishes dropped before they reached a link: behind a held session, for
    /// want of room or by the profile's drop at once ([`Self::live_to_publish`]). Charged to the
    /// transport's drops in [`Self::transport_stats`], where a link's session charges its own.
    #[cfg(feature = "transport-stats")]
    unsent_drops: AtomicU64,
    /// What the session delivered under the lock, handed out after it: the samples for its
    /// subscribers, in the order they arrived, and the changes of its matching statuses. Two
    /// queues and not one of an enum, so a sample is queued as it was built and a matching flip
    /// does not take a sample's room.
    samples: Arc<Mutex<VecDeque<(SubId, Sample)>>>,
    matching: Arc<Mutex<VecDeque<(MatchId, bool)>>>,
    /// The callbacks deliveries go to, by the id of the entity that owns them. Kept outside
    /// [`Core`] so a delivery takes no session state, and a callback that undeclares another
    /// entity finds its target gone rather than the lock held.
    targets: Mutex<Vec<(TargetKey, Target)>>,
    /// The queries waiting for their callbacks and the Finals held for them (`query`).
    #[cfg(feature = "queryable")]
    plane: Arc<QueryPlane>,
    /// What the session's gets queued for their callbacks (`get`).
    #[cfg(feature = "query")]
    gets: Arc<GetPlane>,
    /// What the session's watchers of its faces are owed, and who they are (`connectivity`).
    #[cfg(feature = "connectivity")]
    faces: Arc<FacePlane>,
    /// What the liveliness subscribers' sinks queued for their callbacks (`liveliness`).
    #[cfg(feature = "liveliness")]
    live_samples: LivelinessQueue,
    zid: SessionZid,
    closed: AtomicBool,
    /// The entity ids the session's declarations and Interests take, from 1: `u32`, upstream's
    /// `EntityId`, and refused once spent rather than wrapped (`SessionEngine::next_entity_id`).
    next_entity: AtomicU64,
    /// The ids of what the session holds for the program and never names to a peer: the legs
    /// of its gets and its periodic jobs. A space of their own, so they are not refused when the
    /// entity ids are spent; the table of callbacks tells a leg from an entity by its kind
    /// ([`TargetKey`]).
    #[cfg(any(feature = "query", feature = "ticker"))]
    next_local: AtomicU64,
    reader: Mutex<Option<ReadTask>>,
    /// The threads handing deliveries out for this engine now ([`Delivering`]): a callback that
    /// steps its session again from one of them queues what it delivers for the outer delivery.
    delivering: Lock<Vec<ThreadId>>,
    this: Weak<Self>,
}

/// The session state no other thread may touch while one does; see the module doc.
struct Confined<T>(T);

/// The waits for room of the session's links that are up, kept outside [`Core`] so that a publish
/// that finds the session held asks them with nothing of it held. Each wait belongs to its link's
/// [`Wire`]; this holds it weakly, so a link that has gone drops out with its wire.
#[derive(Default)]
pub(crate) struct LinkRooms(Mutex<Vec<Weak<dyn LinkWritability>>>);

/// What the links that are up answered a publish that asked them for room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Room {
    /// Every link asked takes bytes: whoever holds the session is not waiting on one of them.
    Free,
    /// A link took none within the wait.
    Congested,
    /// No link that is up gives a wait to ask.
    Unasked,
    /// Nothing was asked: the session is held by another publish sending on it, and the queue
    /// profile drops a message behind it at once and reports it to the caller, as pico's
    /// try-lock drop does.
    Held,
}

/// A publish sending on the session, counted for as long as this lives ([`CoopEngine`]'s
/// `sending`): what tells a droppable publish that finds the session held whether a send holds
/// it, as pico's transmit lock is held by a send, or something that is not one (a read step, a
/// timer, the drive), which lets go once its step is done.
struct Sending<'a>(&'a AtomicUsize);

impl<'a> Sending<'a> {
    fn enter(count: &'a AtomicUsize) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self(count)
    }
}

impl Drop for Sending<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl LinkRooms {
    /// Hold `wait` while its link lives, letting go of the waits of links that have gone.
    pub(crate) fn hold(&self, wait: &Arc<dyn LinkWritability>) {
        let mut waits = lock(&self.0);
        waits.retain(|held| held.strong_count() > 0);
        waits.push(Arc::downgrade(wait));
    }

    /// What a droppable publish that found the session held is told, by the queue profile's
    /// `held_drop`: zenoh's asks the links for room within `wait_us` ([`Self::within`]). Pico's
    /// asks nothing: behind another publish `sending` on the session it is dropped at once
    /// ([`Room::Held`]), as pico's try-lock fails on a transmit lock another send holds, and
    /// behind a holder that is not one it waits for the session ([`Room::Free`]).
    pub(crate) fn for_held(&self, held_drop: HeldDrop, sending: bool, wait_us: u64) -> Room {
        match held_drop {
            HeldDrop::WaitForRoom => self.within(wait_us),
            HeldDrop::DropAtOnce if sending => Room::Held,
            HeldDrop::DropAtOnce => Room::Free,
        }
    }

    /// Ask each link that is up for room, for at most `wait_us` each; one that takes none within
    /// it ends the asking. The waits are taken out of the lock first: a wait blocks, and a link
    /// coming up must not wait behind it.
    pub(crate) fn within(&self, wait_us: u64) -> Room {
        let waits: Vec<Arc<dyn LinkWritability>> =
            lock(&self.0).iter().filter_map(Weak::upgrade).collect();
        if waits.is_empty() {
            Room::Unasked
        } else if waits.iter().all(|wait| wait.wait_writable(wait_us)) {
            Room::Free
        } else {
            Room::Congested
        }
    }
}

// SAFETY: a `Confined` is reached only through the `Mutex` that holds it in `CoopEngine`, so one
// thread at a time uses it. Its `Rc` handles and `RefCell` cells are all owned by the `Core`
// inside it: no clone of any of them is ever handed out of the lock (deliveries leave as owned
// `Sample`s and `bool`s, see `CoopEngine::samples`), so every handle of each `Rc` moves with the
// `Core` when another thread takes the lock, and none is used by two threads at once.
unsafe impl<T> Send for Confined<T> {}

/// The id space of one link: the key expressions this session declared to it, read through the
/// link's `actions` (which keep what they sent), lent to the tables of the face the link serves.
/// A peer that was told an id names it instead of the literal when it sends something for the
/// session (a router does for a subscriber it routes to), and the tables resolve it against this.
struct LinkOwnSpace<C: ClockSource + 'static>(Rc<McuActions<C>>);

impl<C: ClockSource + 'static> OwnMappingSpace for LinkOwnSpace<C> {
    fn resolve_own_mapping(&self, id: ExprId) -> Option<String> {
        OwnMappingSpace::resolve_own_mapping(&*self.0, id)
    }
}

// SAFETY: as `Confined`. A `LinkOwnSpace` is stored only in the tables of a face, which `Core`
// owns inside the lock of `CoopEngine`, and it is read only by the dispatch of that face's
// frames, which runs under the same lock; no clone of its `Rc` leaves the lock. The marker
// traits are what the shared handle of a host build names (`SharedOwnMappingSpace` is an `Arc` of
// a `Send + Sync` object where the target has atomic pointers).
unsafe impl<C: ClockSource + 'static> Send for LinkOwnSpace<C> {}
unsafe impl<C: ClockSource + 'static> Sync for LinkOwnSpace<C> {}

/// One thread's delivery for one engine, from `enter` to drop. The engine keeps the threads
/// delivering for it ([`CoopEngine::delivering`]); a set held per engine and keyed by thread is
/// what a thread-local set keyed by engine was, without a thread-local, which an MCU kernel does
/// not give a Rust image.
struct Delivering<'a> {
    set: &'a Lock<Vec<ThreadId>>,
    thread: ThreadId,
}

impl<'a> Delivering<'a> {
    /// `None` when this thread is already delivering for the engine whose set this is.
    fn enter(set: &'a Lock<Vec<ThreadId>>) -> Option<Self> {
        let thread = os::current();
        set.with(|threads| {
            if threads.contains(&thread) {
                return None;
            }
            threads.push(thread);
            Some(Self { set, thread })
        })
    }
}

impl Drop for Delivering<'_> {
    fn drop(&mut self) {
        let thread = self.thread;
        self.set.with(|threads| threads.retain(|t| *t != thread));
    }
}

/// A subscriber's callback, as the ABI's sink minted it. Locked while it runs, so a delivery
/// from the read task and one from the program's own `zp_read` never overlap.
type SubscriberCallback = Arc<Mutex<Box<dyn FnMut(&dyn SampleView) + Send + 'static>>>;

/// A queryable's callback, locked while it runs as a subscriber's is.
#[cfg(feature = "queryable")]
type QueryableCallback = Arc<Mutex<QueryCallback>>;

/// The session's state, held: what [`CoopEngine::live`] hands a caller that may act on it.
type LiveCore<'a, L, C> = MutexGuard<'a, Confined<Core<L, C>>>;

/// Where a delivery goes.
enum Target {
    Subscriber(SubscriberCallback),
    Matching(MatchingSink),
    #[cfg(feature = "queryable")]
    Queryable(QueryableCallback),
    /// One leg of a get, locked while it runs.
    #[cfg(feature = "query")]
    Reply(Arc<Mutex<ReplyCallback>>),
    #[cfg(feature = "liveliness")]
    Liveliness(LivelinessCallback),
}

/// Whose callback a [`Target`] is: the kind of what owns it, and that owner's id. The kinds are
/// numbered from spaces of their own (the entity ids, the matching listeners', the legs of the
/// gets), so an id alone would find a callback of another kind that holds the same number.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetKey {
    Subscriber(SubId),
    Matching(MatchId),
    #[cfg(feature = "queryable")]
    Queryable(QblId),
    #[cfg(feature = "query")]
    Reply(u64),
    #[cfg(feature = "liveliness")]
    Liveliness(SubId),
}

/// The read task: a thread that steps the session until it is told to stop.
struct ReadTask {
    stop: Arc<AtomicBool>,
    thread: JoinHandle,
    id: ThreadId,
}

struct Core<L: SessionLinks + 'static, C: ClockSource + 'static> {
    local: CoopLocalSet<C>,
    runtime: CoopRuntime<C>,
    clock: C,
    /// What the application holds and what the peer declared. It is the session's, so it
    /// outlives each link: a new link is dispatched to the same registry.
    registry: Rc<RefCell<Registry>>,
    /// The session's faces: the dial role's first, which is never removed, then the others in the
    /// order they came. What is declared is declared over each of them, and a get is asked of
    /// each.
    faces: Vec<Face<C>>,
    /// Where each link that comes up leaves its wait for room, for the publishes that find the
    /// session held ([`CoopEngine::live_to_publish`]).
    rooms: Arc<LinkRooms>,
    /// The face an accepted or attached link takes next, beneath the dial role's.
    next_face: FaceId,
    /// Where a face coming up or going down is reported (`connectivity`).
    #[cfg(feature = "connectivity")]
    watchers: Arc<FacePlane>,
    /// The network the session's links are opened on; it outlives them.
    links: L,
    /// The ports the session takes inbound links from (`listen`).
    #[cfg(feature = "listen")]
    listeners: Vec<Listening<L::Pump>>,
    /// The multicast groups the session joined, each a face of its own (`group`).
    #[cfg(feature = "group")]
    groups: Vec<GroupFace>,
    /// Each handshake's cookie key and nonce come from here.
    entropy: SharedEntropy,
    config: CoopConfig,
    /// The policies the session runs under, as its open was handed them: every link's session
    /// is given them, and the replay and the admission of a second link follow them.
    policy: SessionPolicy,
    /// The zid in its wire form, which every handshake of the session announces.
    wire_zid: SessionZid,
    /// The session's say on a link to a node it holds a link to, asked while the link's handshake
    /// runs (`install_link_admission`, `listen`).
    #[cfg(feature = "listen")]
    admission: Arc<dyn LinkAdmission>,
    subscribers: Vec<SubEntry>,
    keyexprs: Vec<KexprEntry>,
    next_mapping: ExprId,
    /// The key ids every node of the deployment shares, which the session was opened with: each
    /// link it opens is handed them, its key expressions are declared under ids past theirs, and
    /// a key goes on the wire as the session's key-wire form says (`shared-key-ids`).
    #[cfg(feature = "shared-key-ids")]
    key_ids: Option<SharedKeyIds>,
    /// The key-wire form of each link the session opens: the session's, and the one stated for an
    /// endpoint apart from it (`shared-key-ids`).
    #[cfg(feature = "shared-key-ids")]
    key_forms: LinkKeyForms,
    /// The next request id of a get's leg to the session's own queryables, counted apart from
    /// the ids the links hand out (`local-queryable`).
    #[cfg(feature = "local-queryable")]
    next_local_request: wz_session_core::wire_id::RequestId,
    filters: Vec<FilterEntry>,
    next_filter: FilterId,
    interests: Vec<InterestHold>,
    matches: Vec<MatchEntry>,
    next_match: MatchId,
    #[cfg(feature = "queryable")]
    queryables: Vec<QblEntry>,
    #[cfg(feature = "queryable")]
    plane: Arc<QueryPlane>,
    /// The legs of the session's gets still pending on its link.
    #[cfg(feature = "query")]
    pending_gets: Vec<PendingGet>,
    #[cfg(feature = "query")]
    gets: Arc<GetPlane>,
    /// The tokens the session holds, and its liveliness subscribers (`liveliness`).
    #[cfg(feature = "liveliness")]
    tokens: Vec<TokenEntry>,
    #[cfg(feature = "liveliness")]
    live_subs: Vec<LiveSubEntry>,
    /// The periodic jobs the program started on the session ([`SessionEngine::start_ticker`]).
    #[cfg(feature = "ticker")]
    tickers: Tickers,
}

/// A port the session listens on, and the wait for a connection on it.
#[cfg(feature = "listen")]
struct Listening<P> {
    listener: Box<dyn LinkListener<P>>,
    readiness: Option<Arc<dyn LinkReadiness>>,
    /// The endpoint as the config names it, which the key-wire form of a link it takes is stated
    /// for (`shared-key-ids`).
    #[cfg(feature = "shared-key-ids")]
    endpoint: String,
}

/// One face of the session: the link it holds, and where the telling of the session's
/// declarations to that link's peer stands (`replay`).
struct Face<C: ClockSource + 'static> {
    id: FaceId,
    link: Link<C>,
    replay: Replay,
}

/// A face's link: up, in its handshake, waiting to be dialled, or (with `listen`) standing by.
enum Link<C: ClockSource + 'static> {
    /// Established: the session's sends go through it.
    Up(Wire<C>),
    /// A handshake under way, given up at `deadline_us`. The dial role's face has dialled the
    /// endpoint before `next` and goes on to the one after; another face holds a link it
    /// dialled once or took off a port, and is removed when the handshake fails.
    Opening {
        wire: Wire<C>,
        next: usize,
        deadline_us: u64,
    },
    /// Lost, or no endpoint answered: the endpoints are dialled again at `at_us`.
    Waiting { at_us: u64 },
    /// The dial role's face, whose link reached the node `zid` while another face holds that node
    /// or has a link to it in the making: the session keeps one face for each remote zid, so this
    /// one stands by and the endpoints are dialled again when no other face has the node
    /// (`Core::node_is_held`, read at each step). Dialled at once it would be refused again, and
    /// the handshake is paid each time.
    #[cfg(feature = "listen")]
    Held { zid: Vec<u8> },
}

/// One link's half of the session: the actions that send over it, the task that runs it, the
/// link the task reads, and the wait its owner makes for that link's input.
struct Wire<C: ClockSource + 'static> {
    actions: Rc<McuActions<C>>,
    task: CoopLocalJoinHandle<DriverOutcome>,
    link: Rc<dyn SessionDatagramLink>,
    readiness: Option<Arc<dyn LinkReadiness>>,
    /// The wait for room on the link, held for as long as the wire is: the session's
    /// [`LinkRooms`] holds it weakly once the face is up.
    writability: Option<Arc<dyn LinkWritability>>,
    /// Opened when the face is brought up (`bring_up`); until then the link gives the session
    /// nothing past its handshake, so the watchers hear the face come up before anything its link
    /// carried.
    #[cfg(feature = "listen")]
    admitted: Admitted,
    /// The link's generation, which the queries it carries are answered under (`query`).
    #[cfg(feature = "queryable")]
    generation: u64,
}

/// What a read waits for before it steps the session, with nothing of the session held.
enum IdleWait {
    /// Nothing: the link holds input already, or its own loop waits for it.
    None,
    /// The next input of any of these links, or the next connection on any of these ports, for
    /// at most this many milliseconds. Each wait is held for as long as the wait is, so the
    /// descriptor it names stays the link's.
    Input(Vec<Arc<dyn LinkReadiness>>, u32),
    /// Nothing to wait on: the next dial, or the next look at a port that gives no wait, for at
    /// most this many milliseconds.
    Sleep(u32),
}

impl IdleWait {
    fn wait(self) {
        match self {
            IdleWait::None => {}
            IdleWait::Input(waits, ms) => wait_any(&waits, ms),
            IdleWait::Sleep(ms) => os::sleep_ms(ms.into()),
        }
    }
}

struct SubEntry {
    id: SubId,
    registration: SubscriptionId,
    retraction: Option<RetractionKey>,
    keyexpr: String,
    /// The key the declaration names, kept to declare it again over a new link; holding it also
    /// keeps alive what it holds.
    wire: WireKey,
}

impl SubEntry {
    /// Declare this subscriber over `actions`: whether the link took it.
    fn declare<C: ClockSource + 'static>(&self, actions: &McuActions<C>) -> bool {
        let wire = on_link(actions, &self.keyexpr, &self.wire);
        if wire.is_literal() {
            actions.send_declare_subscriber(self.id, 0, Some(&self.keyexpr))
        } else {
            actions.send_declare_subscriber(self.id, wire.mapping_id, wire.suffix.as_deref())
        }
        .is_ok()
    }
}

/// `wire` as the link of `actions` names the key `keyexpr`: the link's key-wire form decides,
/// and the declared form keeps `wire` as the ABI made it (`shared-key-ids`).
#[cfg(feature = "shared-key-ids")]
fn on_link<'w, C: ClockSource + 'static>(
    actions: &McuActions<C>,
    keyexpr: &str,
    wire: &'w WireKey,
) -> Cow<'w, WireKey> {
    match wz_capi_port::wire_on_link(actions.key_wire_on_link(keyexpr)) {
        Some(linked) => Cow::Owned(linked),
        None => Cow::Borrowed(wire),
    }
}

/// A build without the shared key ids names every key on every link as the ABI made it.
#[cfg(not(feature = "shared-key-ids"))]
#[inline(always)]
fn on_link<'w, C: ClockSource + 'static>(
    _actions: &McuActions<C>,
    _keyexpr: &str,
    wire: &'w WireKey,
) -> Cow<'w, WireKey> {
    Cow::Borrowed(wire)
}

/// `form`, an Interest about the key `keyexpr`, as the link of `actions` names that key: by the
/// link's key-wire form, as `on_link` names the key of a put or a declaration, the declared
/// form keeping `form` as the ABI made it (`shared-key-ids`).
#[cfg(feature = "shared-key-ids")]
fn interest_on_link<'f, C: ClockSource + 'static>(
    actions: &McuActions<C>,
    keyexpr: &str,
    form: &'f InterestForm,
) -> Cow<'f, InterestForm> {
    match wz_capi_port::interest_on_link(actions.key_wire_on_link(keyexpr), keyexpr, form) {
        Some(linked) => Cow::Owned(linked),
        None => Cow::Borrowed(form),
    }
}

/// A build without the shared key ids names the key of every Interest as the ABI made it.
#[cfg(not(feature = "shared-key-ids"))]
#[inline(always)]
fn interest_on_link<'f, C: ClockSource + 'static>(
    _actions: &McuActions<C>,
    _keyexpr: &str,
    form: &'f InterestForm,
) -> Cow<'f, InterestForm> {
    Cow::Borrowed(form)
}

/// One queryable: its registration with the observer and what its declaration says on the wire.
#[cfg(feature = "queryable")]
struct QblEntry {
    id: QblId,
    registration: QueryableId,
    retraction: Option<RetractionKey>,
    keyexpr: String,
    wire: WireKey,
    complete: bool,
}

#[cfg(feature = "queryable")]
impl QblEntry {
    /// Declare this queryable over `actions`: whether the link took it.
    fn declare<C: ClockSource + 'static>(&self, actions: &McuActions<C>) -> bool {
        let wire = on_link(actions, &self.keyexpr, &self.wire);
        if wire.is_literal() {
            actions.send_declare_queryable(self.id, 0, Some(&self.keyexpr), self.complete)
        } else {
            actions.send_declare_queryable(
                self.id,
                wire.mapping_id,
                wire.suffix.as_deref(),
                self.complete,
            )
        }
        .is_ok()
    }

    /// Retract this queryable over `actions`, naming its key when its declaration asked to.
    fn retract<C: ClockSource + 'static>(&self, actions: &McuActions<C>) {
        match &self.retraction {
            Some(key) => actions.send_undeclare_queryable_naming(
                u64::from(self.id),
                key.mapping_id,
                &key.suffix,
            ),
            None => actions.send_undeclare_queryable(u64::from(self.id)),
        }
    }
}

struct KexprEntry {
    id: ExprId,
    keyexpr: String,
    holds: usize,
}

struct FilterEntry {
    id: FilterId,
    plane: FilterPlane,
    keyexpr: String,
    asked: bool,
    /// Whether the session's own entities count toward the filter (`local-subscriber`).
    count_local: bool,
}

/// One Interest the session holds open, and how many hold it.
struct InterestHold {
    plane: FilterPlane,
    keyexpr: String,
    interest_id: u64,
    form: InterestForm,
    holds: usize,
}

impl InterestHold {
    /// Send this Interest over `actions`, for what is declared now and what is declared later,
    /// naming its key as the link's key-wire form says: whether the link took it.
    fn send<C: ClockSource + 'static>(&self, actions: &McuActions<C>) -> bool {
        let form = interest_on_link(actions, &self.keyexpr, &self.form);
        actions
            .send_interest_kinds(
                self.interest_id,
                kinds(self.plane),
                /* current */ true,
                /* future */ true,
                form.aggregate,
                form.mapping_id,
                form.suffix.as_deref(),
            )
            .is_ok()
    }
}

struct MatchEntry {
    id: MatchId,
    /// What the listener counts, as a write filter names it: which registry `watch` is in.
    plane: FilterPlane,
    watch: u64,
    keyexpr: String,
}

/// The locality a matching criterion carries: what the entity counts. The session's own
/// entities of `plane`'s kind count (`Any`) only for one that asked them to and in a build that
/// delivers to them locally.
fn counted(plane: FilterPlane, count_local: bool) -> Locality {
    let delivers_locally = match plane {
        FilterPlane::Subscribers => cfg!(feature = "local-subscriber"),
        FilterPlane::Queryables { .. } => cfg!(feature = "local-queryable"),
    };
    if delivers_locally && count_local {
        Locality::Any
    } else {
        Locality::Remote
    }
}

/// The engine's mutex, held until the guard drops; one poisoned by a panic is recovered, since
/// every critical section here leaves its value consistent ([`os::Mutex::lock`]).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock()
}

/// The two planes' Interest kinds, an Interest held per plane and key.
fn kinds(plane: FilterPlane) -> InterestKinds {
    match plane {
        FilterPlane::Subscribers => InterestKinds::SUBSCRIBERS,
        FilterPlane::Queryables { .. } => InterestKinds::QUERYABLES,
    }
}

/// What one send's failure means for a publish: a link that is down skips it, anything else is
/// a message no link could have carried.
fn leg(result: Result<(), SendWireError>) -> Result<usize, FanoutError> {
    match result.map_err(PublishError::from) {
        Ok(()) => Ok(0),
        Err(PublishError::TransportUnavailable | PublishError::RequiresUnicast) => Ok(0),
        // The link's queue profile dropped the put behind a held conduit and says so: the other
        // links are still sent it, and the publish is answered as dropped.
        Err(PublishError::HeldConduit) => Err(FanoutError::HeldConduit),
        Err(_) => Err(FanoutError::ExceedsCapacity),
    }
}

/// The `on_event` of a link whose session answers queries outside its lock: the registry's
/// dispatch, with the `ResponseFinal`s it owes held back for the queries a callback is still to
/// answer (`query`). Everything else the dispatch staged (the replies of a queryable that answers
/// in place, declare replies, get prunes) goes out at once, as [`dispatch_all`] sends it.
#[cfg(feature = "queryable")]
fn dispatch_holding_finals<C: ClockSource + 'static>(
    registry: Rc<RefCell<Registry>>,
    face: FaceId,
    actions: Rc<McuActions<C>>,
    plane: Arc<QueryPlane>,
    generation: u64,
) -> impl FnMut(wz_session_core::driver_loop::IterationEvent<'_, '_>) + 'static {
    move |event| {
        let mut registry = registry.borrow_mut();
        // The queries this frame carries arrive on this face's link, whichever was dialled last.
        plane.arriving.store(generation, Ordering::Release);
        // The application's queryables serve every face, so this face's session states its own
        // answer to a query it cannot resolve before its frame is dispatched.
        registry
            .app
            .set_unanswerable_final(actions.params.policy.query_unanswerable_final());
        // A query by an id of the shared dictionary is kept, so its replies mirror its key form.
        #[cfg(feature = "shared-key-ids")]
        actions.note_requests(&event);
        registry.dispatch_event(face, event);
        registry.flush_pending_replies(face, &*actions);
        for (rid, qos) in registry.take_pending_final_rids(face) {
            if lock(&plane.holds).owe(generation, rid, qos) {
                actions.send_response_final(rid, qos);
            }
        }
    }
}

/// The `on_event` of a link whose session has no queryable: the registry's dispatch, with
/// everything it staged sent at once.
#[cfg(not(feature = "queryable"))]
fn dispatch_all<C: ClockSource + 'static>(
    registry: Rc<RefCell<Registry>>,
    face: FaceId,
    actions: Rc<McuActions<C>>,
) -> impl FnMut(wz_session_core::driver_loop::IterationEvent<'_, '_>) + 'static {
    move |event| registry.borrow_mut().dispatch(face, event, &*actions)
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> Core<L, C> {
    /// The dial role's face, which the session holds for its whole life.
    fn dial(&self) -> &Face<C> {
        &self.faces[0]
    }

    /// The actions of every face whose link is up, which is what the session sends through. A
    /// face whose link is dialled or waits to be is not among them: what is declared then is
    /// declared when it comes up.
    fn ups(&self) -> impl Iterator<Item = &Rc<McuActions<C>>> {
        self.faces.iter().filter_map(|face| match &face.link {
            Link::Up(wire) => Some(&wire.actions),
            _ => None,
        })
    }

    /// The faces whose links are up, which is what a get is asked of.
    #[cfg(feature = "query")]
    fn up_faces(&self) -> Vec<FaceId> {
        self.faces
            .iter()
            .filter(|face| matches!(face.link, Link::Up(_)))
            .map(|face| face.id)
            .collect()
    }

    /// The actions of face `id` while its link is up.
    #[cfg(feature = "query")]
    fn up_actions(&self, id: FaceId) -> Option<&Rc<McuActions<C>>> {
        self.faces.iter().find_map(|face| match &face.link {
            Link::Up(wire) if face.id == id => Some(&wire.actions),
            _ => None,
        })
    }

    /// Where an answer to a query that came in under `generation` goes: the link of that
    /// generation while it is up, or the group the query came on while its session runs
    /// (`group`). Either is the sink a reply and a Final are sent through.
    #[cfg(feature = "queryable")]
    fn answer_route(&self, generation: u64) -> Option<&dyn ResponseSink> {
        #[cfg(feature = "group")]
        if let Some(group) = self
            .groups
            .iter()
            .find(|group| group.answers_as(generation))
        {
            return Some(group.replies() as &dyn ResponseSink);
        }
        self.faces.iter().find_map(|face| match &face.link {
            Link::Up(wire) if wire.generation == generation => {
                Some(&*wire.actions as &dyn ResponseSink)
            }
            _ => None,
        })
    }

    /// Dial `endpoint` as face `face`: a link opened to it and run as the initiator
    /// ([`Self::open_wire`]). [`OpenError::Unreachable`] when the endpoint does not parse or the
    /// network opens no link to it, [`OpenError::EntropyUnavailable`] when the platform gives no
    /// cookie key for the attempt.
    fn dial_endpoint(&mut self, face: FaceId, endpoint: &str) -> Result<Wire<C>, OpenError> {
        let to = parse_locator(endpoint)
            .map_err(|refused| OpenError::Unreachable(format!("{endpoint}: {refused:?}")))?;
        let opened = self
            .links
            .open_initiator(to)
            .map_err(|refused| OpenError::Unreachable(format!("{endpoint}: {refused:?}")))?;
        self.open_wire(face, opened, SessionRole::Initiator, Some(endpoint))
    }

    /// Run a session over `opened` as face `face`, in `role`: the handshake begun, its task
    /// spawned on the session's local set and stepped once so that an initiator's InitSyn is sent
    /// now and not after the wait of the next read. The link is the same whichever end opened
    /// it; the role is the handshake's alone. [`OpenError::EntropyUnavailable`] when the platform
    /// gives no cookie key for the attempt.
    fn open_wire(
        &mut self,
        face: FaceId,
        opened: OpenedLink<L::Pump>,
        role: SessionRole,
        endpoint: Option<&str>,
    ) -> Result<Wire<C>, OpenError> {
        let OpenedLink { sink, pump } = opened;
        // The parameters the tokio engine gives a session (`wz-capi-core`'s `init_params`), with a
        // cookie key of its own per attempt.
        let params = SessionInitParams {
            whatami: self.config.whatami,
            zid: self.wire_zid,
            seq_num_res: self.config.sn_resolution.wire_code(),
            req_id_res: 2,
            batch_size: self.config.batch_size,
            lease_ms: self.config.lease_ms,
            keep_alive: self.config.keep_alive,
            initial_sn: 0,
            cookie: Vec::new(),
            tx_queue: self.config.tx_queue,
            link_rx: self.config.link_rx,
            policy: self.policy,
            cookie_signing_key: SigningKey::from_entropy(&mut self.entropy)
                .map_err(|_| OpenError::EntropyUnavailable)?,
        };
        let actions = McuActions::<C>::new_generic(sink, params, CoopTime::new(&self.runtime));
        // The link has its place in the session's admission before the handshake runs, which asks
        // it once the remote's zid is known: a second link to a node the session holds is refused
        // there, with nothing declared over it by either end, and not closed after it came up.
        #[cfg(feature = "listen")]
        actions.install_link_admission(
            Arc::clone(&self.admission),
            matches!(role, SessionRole::Initiator),
        );
        // An acceptor mints a cookie at each InitAck from a nonce it draws, and one with no source
        // to draw from refuses every handshake (fail closed): it is given the session's, and a
        // source that is dry now is not a link to accept.
        #[cfg(feature = "listen")]
        if matches!(role, SessionRole::Acceptor) {
            actions.install_cookie_entropy(Box::new(self.entropy.clone()));
            if !actions.draw_cookie_nonce() {
                return Err(OpenError::EntropyUnavailable);
            }
        }
        // The id space of this link, for the tables of the face it serves: what the peer names by
        // an id the session declared to it resolves against the link's own declarations. Each link
        // has its own, so it is installed whenever one is made, a redialled face's included.
        #[cfg(target_has_atomic = "ptr")]
        let own_space: SharedOwnMappingSpace = Arc::new(LinkOwnSpace(actions.clone()));
        #[cfg(not(target_has_atomic = "ptr"))]
        let own_space: SharedOwnMappingSpace = Rc::new(LinkOwnSpace(actions.clone()));
        self.registry
            .borrow_mut()
            .install_own_mapping_space(face, own_space);
        // The key ids every node shares, on both sides of the link before it carries anything:
        // the link's actions, with the key-wire form stated for the endpoint it was dialled to or
        // taken on, so what is sent over it names its keys in that form, and the face's tables,
        // so an id of the dictionary the peer sends is read.
        #[cfg(feature = "shared-key-ids")]
        {
            actions.install_link_keys(wz_session_core::shared_key_ids::LinkKeys::new(
                self.key_ids.clone(),
                self.key_forms.form_of(endpoint),
            ));
            if let Some(ids) = &self.key_ids {
                self.registry
                    .borrow_mut()
                    .install_shared_key_ids(face, ids.clone());
            }
        }
        #[cfg(not(feature = "shared-key-ids"))]
        let _ = endpoint;
        let readiness = pump.readiness().map(Arc::from);
        let writability = pump.writability().map(Arc::from);
        // The link gives the session nothing between its handshake and the face table's decision
        // (`admit`), so a link that is refused has put nothing in the tables.
        #[cfg(feature = "listen")]
        let admitted = Admitted::default();
        #[cfg(feature = "listen")]
        let link: Rc<dyn SessionDatagramLink> =
            Rc::new(AdmissionGate::new(pump, actions.clone(), admitted.clone()));
        #[cfg(not(feature = "listen"))]
        let link = Rc::new(pump);
        #[cfg(feature = "queryable")]
        let generation = self.plane.generation.fetch_add(1, Ordering::AcqRel) + 1;
        #[cfg(feature = "queryable")]
        let dispatch = dispatch_holding_finals(
            self.registry.clone(),
            face,
            actions.clone(),
            self.plane.clone(),
            generation,
        );
        #[cfg(not(feature = "queryable"))]
        let dispatch = dispatch_all(self.registry.clone(), face, actions.clone());
        let task = spawn_session(
            &self.local,
            link.clone(),
            actions.clone(),
            CoopTime::new(&self.runtime),
            SessionDriveConfig {
                timeouts: self.config.timeouts,
                role,
                max_iters: None,
            },
            dispatch,
        );
        self.local.run_until_idle();
        Ok(Wire {
            actions,
            task,
            link,
            readiness,
            writability,
            #[cfg(feature = "listen")]
            admitted,
            #[cfg(feature = "queryable")]
            generation,
        })
    }

    /// When a handshake begun now is given up, in microseconds on the session's clock.
    fn open_deadline_us(&self) -> u64 {
        self.clock
            .now_us()
            .saturating_add(self.config.open_timeout_ms.saturating_mul(1000))
    }

    /// Start a handshake with the first endpoint, from index `from` on, that a link opens to, as
    /// the dial role's face. `Err` with the reason the last endpoint tried gave (`last` when none
    /// is), or with [`OpenError::EntropyUnavailable`] when the platform gives no cookie key for
    /// the attempt.
    fn dial_from(&mut self, from: usize, mut last: OpenError) -> Result<Link<C>, OpenError> {
        for at in from..self.config.endpoints.len() {
            let endpoint = self.config.endpoints[at].clone();
            match self.dial_endpoint(DIAL_FACE, &endpoint) {
                Ok(wire) => {
                    return Ok(Link::Opening {
                        wire,
                        next: at + 1,
                        deadline_us: self.open_deadline_us(),
                    });
                }
                Err(OpenError::EntropyUnavailable) => return Err(OpenError::EntropyUnavailable),
                Err(refused) => last = refused,
            }
        }
        Err(last)
    }

    /// Dial from endpoint `from` on; when none answers, wait `redial_ms` to dial them all again,
    /// or end with the last endpoint's reason when the session redials none.
    fn dial_or_wait(
        &mut self,
        from: usize,
        last: OpenError,
        now_us: u64,
        redial_ms: Option<u64>,
    ) -> Result<Link<C>, OpenError> {
        match (self.dial_from(from, last), redial_ms) {
            (Ok(link), _) => Ok(link),
            (Err(OpenError::EntropyUnavailable), _) => Err(OpenError::EntropyUnavailable),
            (Err(last), None) => Err(last),
            (Err(_), Some(ms)) => Ok(Link::Waiting {
                at_us: now_us.saturating_add(ms.saturating_mul(1000)),
            }),
        }
    }

    /// Move every face's link on, after the session was stepped; see [`Self::poll_face`]. `Err`
    /// when the session ends, which only the dial role's face can bring about.
    fn poll_links(&mut self, redial_ms: Option<u64>) -> Result<(), OpenError> {
        // The connections that arrived come first, so their handshakes are moved on in this pass.
        #[cfg(feature = "listen")]
        self.accept_links();
        // A group whose link was lost is let go of, and joined again when its time comes.
        #[cfg(feature = "group")]
        self.poll_groups(redial_ms);
        // From the last face to the first: a face that is gone is removed, which moves none of the
        // ones before it.
        for at in (0..self.faces.len()).rev() {
            self.poll_face(at, redial_ms)?;
        }
        Ok(())
    }

    /// Move the link of the face at `at` on. A handshake that completed brings the link up and
    /// begins to declare over it what the session holds, and a link that is up goes on with the
    /// telling when a turn of it is due (`replay`), or ends when the replay is given up on a send
    /// the link refused, and is then lost as any other link is. The dial role's face is kept: a
    /// link that ended or ran out of time gives way to the next endpoint, and a lost link takes
    /// what its peer declared with it and is dialled again. Any other face is not dialled again:
    /// its lost or failed link takes the face with it. `Err` when the session ends: the dial
    /// role's link was lost, or no endpoint answered, and `redial_ms` is `None`; or the platform
    /// gave no entropy.
    fn poll_face(&mut self, at: usize, redial_ms: Option<u64>) -> Result<(), OpenError> {
        let now_us = self.clock.now_us();
        let now_ms = now_us / 1000;
        let id = self.faces[at].id;
        let link = core::mem::replace(&mut self.faces[at].link, Link::Waiting { at_us: now_us });
        // A link that is up goes on telling its peer what the session holds, when a turn is due.
        // A turn the replay is given up on (a refused send, at once without a pace or when the
        // pace says so) ends the link here, with no Close, as
        // zenoh-pico clears a transport its reopen could not send its declarations over
        // (`vendor/zenoh-pico/src/net/session.c` @ `_z_transport_clear(&s->_tp);`); the arm for a
        // lost link below then takes it as lost, so the dial role's face dials again and tells
        // everything over the next link, and any other face goes.
        if let Link::Up(wire) = &link {
            if !wire.task.is_finished()
                && self.replay_turn(at, &wire.actions, now_ms) == TurnEnd::EndsLink
            {
                wire.task.abort();
                self.local.run_until_idle();
            }
        }
        let polled = match link {
            // zenoh-pico's client reopens whatever ended its link: a lease that ran out, a read
            // that failed, a Close from the router (`vendor/zenoh-pico/src/transport/unicast/read.c` @
            // `return _zp_unicast_failed_result(ztu, executor);`).
            Link::Up(wire) if wire.task.is_finished() => {
                // The face is read before the wire goes: what it was is what a watcher is told.
                let snapshot = self.face_of(&wire.actions);
                drop(wire);
                self.lose_link(id);
                self.report_face(FaceEventKind::Down, snapshot);
                if id != DIAL_FACE {
                    self.remove_face(at);
                    return Ok(());
                }
                if redial_ms.is_none() {
                    return Err(OpenError::Unreachable(String::from("the link was lost")));
                }
                self.dial_or_wait(0, OpenError::NoEndpoint, now_us, redial_ms)?
            }
            Link::Opening {
                wire,
                next,
                deadline_us,
            } => {
                if wire.actions.is_established() {
                    // The face table decides whether the node is held already, and installs the
                    // link itself.
                    self.admit(at, wire, now_us);
                    return Ok(());
                } else if wire.task.is_finished() || now_us >= deadline_us {
                    let why = match (wire.actions.close_reason(), wire.task.is_finished()) {
                        (Some(reason), _) => format!("the handshake ended: {reason:?}"),
                        (None, true) => String::from("the handshake ended"),
                        (None, false) => String::from("no answer in time"),
                    };
                    #[cfg(feature = "listen")]
                    let node = Self::node_of(&wire.actions);
                    wire.task.abort();
                    self.local.run_until_idle();
                    drop(wire);
                    if id != DIAL_FACE {
                        self.remove_face(at);
                        return Ok(());
                    }
                    // The dial role's link reached a node another face holds or is bringing up:
                    // the node refused it (`install_link_admission`). It stands by, and dials
                    // again when no other face has the node, where dialling at once would be
                    // refused again and the handshake paid each time.
                    #[cfg(feature = "listen")]
                    if let Some(zid) = node.filter(|zid| self.node_is_held(zid, id)) {
                        self.faces[at].link = Link::Held { zid };
                        return Ok(());
                    }
                    let last = OpenError::Unreachable(format!(
                        "{}: {why}",
                        self.config.endpoints[next - 1]
                    ));
                    self.dial_or_wait(next, last, now_us, redial_ms)?
                } else {
                    Link::Opening {
                        wire,
                        next,
                        deadline_us,
                    }
                }
            }
            Link::Waiting { at_us } if now_us >= at_us => {
                self.dial_or_wait(0, OpenError::NoEndpoint, now_us, redial_ms)?
            }
            // The face that held the node is gone, and so is any link in the making to it: the
            // node is dialled again. Read from the face table each step and not told by the face
            // that goes, so a link that dies in its handshake frees the node as well.
            #[cfg(feature = "listen")]
            Link::Held { zid } if !self.node_is_held(&zid, id) => {
                self.dial_or_wait(0, OpenError::NoEndpoint, now_us, redial_ms)?
            }
            link => link,
        };
        self.faces[at].link = polled;
        Ok(())
    }

    /// The node a link reaches, as far as the link knows it: the zid its peer announced, or the
    /// one its admission was asked about when the link was refused before it took the Init that
    /// carried it (`SessionLinkActions::link_admission_node`).
    #[cfg(feature = "listen")]
    fn node_of(actions: &McuActions<C>) -> Option<Vec<u8>> {
        actions.peer_zid().or_else(|| actions.link_admission_node())
    }

    /// Whether a face other than `id` holds the node `zid` or is bringing a link to it up: its
    /// link is up or in its handshake, and reaches that node.
    #[cfg(feature = "listen")]
    fn node_is_held(&self, zid: &[u8], id: FaceId) -> bool {
        self.faces.iter().any(|face| {
            if face.id == id {
                return false;
            }
            let (Link::Up(wire) | Link::Opening { wire, .. }) = &face.link else {
                return false;
            };
            Self::node_of(&wire.actions).is_some_and(|node| same_zid(&node, zid))
        })
    }

    /// Bring up the face at `at`, whose handshake `wire` completed. The link was admitted in its
    /// handshake (`install_link_admission`), so a link that got this far is the session's link to
    /// its node, and no other link to the node is kept beside it.
    fn admit(&mut self, at: usize, wire: Wire<C>, now_us: u64) {
        self.bring_up(at, wire, now_us);
    }

    /// Tell the peer of every face whose link is up everything the session holds again, as a link
    /// that has just come up is told (`begin_replay`), at the session's pace; the count of faces.
    /// What the application asks for when it holds that a peer lost declarations the session made.
    /// A face whose first turn the replay is given up on is not counted: its link ends, and the
    /// next pass over the faces takes it as lost (`poll_face`).
    fn redeclare(&mut self) -> usize {
        let now_ms = self.clock.now_us() / 1000;
        let mut told = 0;
        for at in 0..self.faces.len() {
            let actions = match &self.faces[at].link {
                Link::Up(wire) => Rc::clone(&wire.actions),
                _ => continue,
            };
            match self.begin_replay(at, &actions, now_ms) {
                TurnEnd::Kept => told += 1,
                TurnEnd::EndsLink => {
                    if let Link::Up(wire) = &self.faces[at].link {
                        wire.task.abort();
                    }
                }
            }
        }
        told
    }

    /// The link of the face at `at` is `wire`, up: what the session holds is declared over it from
    /// here on, and the watchers of the faces are told it came up. A first turn the replay is
    /// given up on ends the link at once, and the next pass over the faces takes it as lost
    /// (`poll_face`).
    fn bring_up(&mut self, at: usize, wire: Wire<C>, now_us: u64) {
        #[cfg(feature = "listen")]
        wire.admitted.grant();
        // A publish goes to the links that are up, so theirs are the rooms it asks.
        if let Some(wait) = &wire.writability {
            self.rooms.hold(wait);
        }
        if self.begin_replay(at, &wire.actions, now_us / 1000) == TurnEnd::EndsLink {
            wire.task.abort();
        }
        let snapshot = self.face_of(&wire.actions);
        self.faces[at].link = Link::Up(wire);
        self.report_face(FaceEventKind::Up, snapshot);
    }

    /// Whether the dial role's face has what an open waits for: its link is up, or the node it
    /// reached is held by another face (`Link::Held`, with `listen`).
    fn dial_settled(&self) -> bool {
        match self.dial().link {
            Link::Up(_) => true,
            #[cfg(feature = "listen")]
            Link::Held { .. } => true,
            _ => false,
        }
    }

    /// Whether the session listens on any port.
    fn listens(&self) -> bool {
        #[cfg(feature = "listen")]
        {
            !self.listeners.is_empty()
        }
        #[cfg(not(feature = "listen"))]
        {
            false
        }
    }

    /// Listen on every endpoint the config lists. [`OpenError::Listen`] for the first that does
    /// not parse, that the network opens no listener for, or whose port is taken; a build without
    /// `listen` answers every endpoint so.
    fn listen_on_config(&mut self) -> Result<(), OpenError> {
        #[cfg(feature = "listen")]
        for endpoint in self.config.listen.clone() {
            let refused =
                |why: &dyn core::fmt::Debug| OpenError::Listen(format!("{endpoint}: {why:?}"));
            let at = parse_listen_locator(&endpoint).map_err(|why| refused(&why))?;
            let listener = self.links.open_listener(at).map_err(|why| refused(&why))?;
            let readiness = listener.readiness().map(Arc::from);
            self.listeners.push(Listening {
                listener,
                readiness,
                #[cfg(feature = "shared-key-ids")]
                endpoint: endpoint.clone(),
            });
        }
        #[cfg(not(feature = "listen"))]
        if let Some(endpoint) = self.config.listen.first() {
            return Err(OpenError::Listen(format!(
                "{endpoint}: listening is not built"
            )));
        }
        Ok(())
    }

    /// Join every group the config lists, each a face of its own whose session is a task of the
    /// session's local set, stepped once here so that its first JOIN leaves now.
    /// [`OpenError::Group`] for the first the network joins no group for, or whose session ended
    /// at its first step (its link did not open); a build without `group` answers every group so.
    fn join_groups(&mut self) -> Result<(), OpenError> {
        #[cfg(feature = "group")]
        for join in self.config.groups.clone() {
            let id = self.next_face;
            // The tables first: the group's task dispatches to them from its first step. They are
            // the face's for as long as the session holds the group, across its joins.
            self.registry.borrow_mut().add_face(id);
            // An id of the key ids every node shares is read on the group as on a link.
            #[cfg(feature = "shared-key-ids")]
            if let Some(ids) = &self.key_ids {
                self.registry
                    .borrow_mut()
                    .install_shared_key_ids(id, ids.clone());
            }
            match self.join_group(id, join) {
                Ok(face) => {
                    self.next_face += 1;
                    self.groups.push(face);
                }
                Err(refused) => {
                    self.registry.borrow_mut().remove_face(id);
                    return Err(refused);
                }
            }
        }
        #[cfg(not(feature = "group"))]
        if let Some(join) = self.config.groups.first() {
            return Err(OpenError::Group(format!(
                "{}: joining a group is not built",
                join.endpoint
            )));
        }
        Ok(())
    }

    /// Join the group `join` names as face `id`, whose tables the registry holds: the stack joins
    /// the group, and its session, with a fresh dispatcher, is spawned on the session's local set
    /// and stepped once. [`OpenError::Group`] when the stack joins no such group or the session
    /// ended at its first step (its link did not open).
    #[cfg(feature = "group")]
    fn join_group(&mut self, id: FaceId, join: GroupJoin) -> Result<GroupFace, OpenError> {
        let transport = self
            .links
            .open_group(&join.endpoint)
            .map_err(|why| OpenError::Group(format!("{}: {why:?}", join.endpoint)))?;
        let endpoint = join.endpoint.clone();
        let params = join.profile.params(
            self.config.whatami,
            self.wire_zid,
            self.config.tx_queue,
            self.config.link_rx,
            self.policy,
        );
        // A member's query is held, and answered, under the group's own generation, as a link's
        // is under its; each join of the group is a generation of its own.
        #[cfg(feature = "queryable")]
        let generation = self.plane.generation.fetch_add(1, Ordering::AcqRel) + 1;
        #[cfg(feature = "queryable")]
        let dispatch = group::dispatch(
            self.registry.clone(),
            id,
            self.policy,
            self.plane.clone(),
            generation,
        );
        #[cfg(not(feature = "queryable"))]
        let dispatch = group::dispatch(self.registry.clone(), id);
        let face = GroupFace::join(
            &self.local,
            GroupJoining {
                id,
                join,
                transport,
                params,
                policy: self.policy,
                // A message the session puts on the group waits for room by running the session's
                // tasks, the group's among them, on the session's clock.
                pace: Rc::new(group::SessionPace {
                    local: self.local.clone(),
                    clock: self.clock.clone(),
                }),
                #[cfg(feature = "queryable")]
                generation,
                #[cfg(feature = "connectivity")]
                watchers: Arc::clone(&self.watchers),
            },
            dispatch,
        );
        self.local.run_until_idle();
        if face.has_ended() {
            return Err(OpenError::Group(format!(
                "{endpoint}: the group's link did not open"
            )));
        }
        // A droppable publish that finds the session held asks the group's socket for room as it
        // asks a link's, and its wait goes with the face.
        if let Some(wait) = face.room() {
            self.rooms.hold(wait);
        }
        Ok(face)
    }

    /// Tell each group the session joined of an entity it declared, as each group's declarations
    /// say (`group`).
    #[cfg(feature = "group")]
    fn announce_to_groups(&self, entity: GroupEntity<'_>) {
        for group in &self.groups {
            group.announce(entity);
        }
    }

    /// Tell each group the session joined that the entity `entity` it was told of is retracted
    /// (`group`).
    #[cfg(feature = "group")]
    fn retract_from_groups(&self, entity: EntityId) {
        for group in &self.groups {
            group.retract(entity);
        }
    }

    /// Move each group on. A group whose session ended on its own (its link was lost) takes with
    /// it what its members declared and the gets asked of them, as a lost link does, and is
    /// joined again `redial_ms` later, and again after each attempt that fails, as zenoh-pico's
    /// reopen task rejoins a lost multicast transport on the period it redials a lost link. Which
    /// ends are worth a new join is the session core's rule
    /// (`MulticastOutcome::warrants_rejoin`); a session that redials nothing joins nothing again.
    #[cfg(feature = "group")]
    fn poll_groups(&mut self, redial_ms: Option<u64>) {
        let now_us = self.clock.now_us();
        let again_at = |ms: u64| now_us.saturating_add(ms.saturating_mul(1000));
        for at in 0..self.groups.len() {
            let id = self.groups[at].id();
            if let Some(outcome) = self.groups[at].take_outcome(&self.local) {
                self.lose_link(id);
                if let (true, Some(ms)) = (outcome.warrants_rejoin(), redial_ms) {
                    self.groups[at].wait_to_rejoin(again_at(ms));
                }
                continue;
            }
            if self.groups[at].rejoin_due(now_us) {
                let join = self.groups[at].group_join().clone();
                match self.join_group(id, join) {
                    Ok(face) => {
                        // The liveliness subscribers ask the group again, as they would have
                        // had it been there when they were declared, as the tokio engine's
                        // group asks again when it comes up. What the session announced is
                        // not told again: neither upstream tells a group that comes up of
                        // the entities a session already holds.
                        #[cfg(feature = "liveliness")]
                        for entry in &self.live_subs {
                            face.ask_liveliness(
                                entry.id,
                                &entry.keyexpr,
                                &entry.wire,
                                entry.history,
                            );
                        }
                        self.groups[at] = face;
                    }
                    Err(_) => {
                        if let Some(ms) = redial_ms {
                            self.groups[at].wait_to_rejoin(again_at(ms));
                        }
                    }
                }
            }
        }
    }

    /// Take the connections waiting on every port the session listens on, each as a face of its
    /// own whose handshake is run as the acceptor's. A port the platform has no descriptor or
    /// buffer for just now is looked at again on the next step, and one that is broken for good
    /// is let go of.
    #[cfg(feature = "listen")]
    fn accept_links(&mut self) {
        let mut at = 0;
        while at < self.listeners.len() {
            let broken = loop {
                match self.listeners[at].listener.accept() {
                    Ok(Some(opened)) => {
                        // The link is the listener's: its key-wire form is the one stated for
                        // the endpoint the config listens on (`shared-key-ids`).
                        #[cfg(feature = "shared-key-ids")]
                        let endpoint = Some(self.listeners[at].endpoint.clone());
                        #[cfg(not(feature = "shared-key-ids"))]
                        let endpoint: Option<String> = None;
                        self.accept_face(opened, endpoint.as_deref());
                    }
                    Ok(None) | Err(LinkOpenError::Exhausted) => break false,
                    Err(_) => break true,
                }
            };
            if broken {
                self.listeners.remove(at);
            } else {
                at += 1;
            }
        }
    }

    /// Give a link taken off a port a face, and run its session as the acceptor. A link that
    /// arrives when the session holds as many faces as `max_faces`, or has as many handshakes
    /// under way as `accept_pending`, is closed unread: its peer learns the node is full from the
    /// close, where one left queued would wait for a handshake that never starts.
    #[cfg(feature = "listen")]
    fn accept_face(&mut self, opened: OpenedLink<L::Pump>, endpoint: Option<&str>) {
        let pending = self
            .faces
            .iter()
            .filter(|face| face.id != DIAL_FACE && matches!(face.link, Link::Opening { .. }))
            .count();
        if self.faces.len() > self.config.max_faces || pending >= self.config.accept_pending {
            return;
        }
        let id = self.next_face;
        // The tables first: the link's task dispatches to them from its first step.
        self.registry.borrow_mut().add_face(id);
        let Ok(wire) = self.open_wire(id, opened, SessionRole::Acceptor, endpoint) else {
            self.registry.borrow_mut().remove_face(id);
            return;
        };
        self.next_face += 1;
        // The handshake is the acceptor's whole-handshake bound; the session's own timer in the
        // state machine is the same bound and ends the task, so whichever is first removes the face.
        let deadline_us = self.clock.now_us().saturating_add(
            self.config
                .timeouts
                .accepting_inactivity_ms
                .saturating_mul(1000),
        );
        self.push_opening(id, wire, deadline_us);
    }

    /// Add a face that holds `wire`, whose handshake is given up at `deadline_us`. It is told the
    /// session's declarations at the pace the dial role's face is.
    fn push_opening(&mut self, id: FaceId, wire: Wire<C>, deadline_us: u64) {
        let pacing = self.dial().replay.pacing();
        self.faces.push(Face {
            id,
            link: Link::Opening {
                wire,
                next: 0,
                deadline_us,
            },
            replay: Replay::with_pacing(pacing),
        });
    }

    /// Take the face at `at` out of the session, with its tables. The dial role's face is never
    /// taken out.
    fn remove_face(&mut self, at: usize) {
        if self.faces[at].id == DIAL_FACE {
            return;
        }
        let face = self.faces.remove(at);
        self.registry.borrow_mut().remove_face(face.id);
    }

    /// The face a link's `actions` are the end of, when something watches the faces (an event is
    /// the snapshot it carries) and the handshake has told who the peer is. A build without the
    /// connectivity plane watches nothing, and its snapshot is not linked.
    fn face_of(&self, actions: &McuActions<C>) -> Option<FaceSnapshot> {
        #[cfg(feature = "connectivity")]
        {
            if !self.watchers.watched() {
                return None;
            }
            FaceSnapshot::of_actions(actions)
        }
        #[cfg(not(feature = "connectivity"))]
        {
            let _ = actions;
            None
        }
    }

    /// Tell the watchers of the faces that `face` came up or went, with the session's other
    /// deliveries (`face_of` says whether there is anything to tell).
    fn report_face(&self, kind: FaceEventKind, face: Option<FaceSnapshot>) {
        #[cfg(feature = "connectivity")]
        if let Some(face) = face {
            self.watchers.happened(kind, face);
        }
        #[cfg(not(feature = "connectivity"))]
        let _ = (kind, face);
    }

    /// The faces that stand: those whose links have completed their handshakes.
    #[cfg(feature = "connectivity")]
    fn standing_faces(&self) -> Vec<FaceSnapshot> {
        let links = self.faces.iter().filter_map(|face| match &face.link {
            Link::Up(wire) if wire.actions.is_established() => {
                FaceSnapshot::of_actions(&*wire.actions)
            }
            _ => None,
        });
        // And each member of a group the session joined, a transport of its own as both
        // upstreams report it (`group`).
        #[cfg(feature = "group")]
        let links = links.chain(self.groups.iter().flat_map(GroupFace::member_snapshots));
        links.collect()
    }

    /// What a lost link takes with it: every subscriber and queryable its peer declared, so a
    /// matching status or a write filter that counted on one reads the session as it now is.
    /// zenoh-pico drops a peer's targets from every write filter when its connection drops
    /// (`vendor/zenoh-pico/src/net/filtering.c` @ `case _Z_INTEREST_MSG_TYPE_CONNECTION_DROPPED: {`).
    fn lose_link(&mut self, id: FaceId) {
        // What the lost link's peer was told went with it: the next link's peer holds nothing.
        if let Some(face) = self.faces.iter_mut().find(|face| face.id == id) {
            face.replay.discard();
        }
        let mut registry = self.registry.borrow_mut();
        registry.flush_declarations_on_link_loss(id);
        registry.flush_liveliness_on_link_loss(id);
        // The gets asked of the face went with its link: the peer that owed their Finals is gone,
        // so each pending entry is dropped, which ends its leg (`get`).
        #[cfg(feature = "query")]
        {
            let mut at = 0;
            while at < self.pending_gets.len() {
                if self.pending_gets[at].face == id {
                    self.pending_gets.remove(at).unregister(&mut registry);
                } else {
                    at += 1;
                }
            }
        }
    }

    /// When the earliest pending get is due: a query's or a liveliness snapshot's, on any face.
    #[cfg(feature = "query")]
    fn next_get_deadline_ms(&self) -> Option<u64> {
        let registry = self.registry.borrow();
        registry
            .all_gets()
            .flat_map(|gets| {
                let due = gets.replies.next_deadline_ms();
                #[cfg(feature = "liveliness-get")]
                let due = [due, gets.liveliness_gets.next_deadline_ms()]
                    .into_iter()
                    .flatten()
                    .min();
                due
            })
            .min()
    }

    /// `most` milliseconds, or the whole milliseconds left until `due_ms` (rounded up, so a wait
    /// never ends a clock reading before the time it waits for), whichever is less.
    fn wait_until(&self, most: u32, due_ms: u64) -> u32 {
        let left_us = due_ms
            .saturating_mul(1000)
            .saturating_sub(self.clock.now_us());
        u32::try_from(left_us.div_ceil(1000)).map_or(most, |left| left.min(most))
    }

    /// What a read waits for before it steps the session: the link's next input, for at most
    /// [`CoopConfig::idle_wait_ms`], unless the link already holds some or waits in its own loop;
    /// and while no link is open, the next dial, for no longer either. zenoh-pico's read waits
    /// the same way, on a socket whose receive timeout is that long (`Z_CONFIG_SOCKET_TIMEOUT`).
    fn idle_wait(&self) -> IdleWait {
        let most = self.config.idle_wait_ms;
        // A get whose deadline comes first is swept when it is due, not up to a whole wait late.
        #[cfg(feature = "query")]
        let most = match self.next_get_deadline_ms() {
            Some(due_ms) => self.wait_until(most, due_ms),
            None => most,
        };
        // And so is the next turn of a replay a link owes its peer, which is not due by input.
        let most = match self
            .faces
            .iter()
            .filter_map(|face| face.replay.next_turn_ms())
            .min()
        {
            Some(due_ms) => self.wait_until(most, due_ms),
            None => most,
        };
        // And so is a periodic job the program started, which no input brings about either.
        #[cfg(feature = "ticker")]
        let most = match self.tickers.next_due_ms() {
            Some(due_ms) => self.wait_until(most, due_ms),
            None => most,
        };
        // And so is a group's turn: its task looks at its beacon, its lease sweep and what its
        // members sent each time the session is stepped, and takes one datagram a step, so a group
        // that took one is stepped again at once and one that took none within a tick.
        #[cfg(feature = "group")]
        let most = if self.groups.is_empty() {
            most
        } else if self.groups.iter().any(GroupFace::took_input) {
            0
        } else {
            most.min(group::GROUP_TICK_MS)
        };
        if most == 0 {
            return IdleWait::None;
        }
        // What the read waits on: the readiness of every link that holds no input already, and of
        // every port that gives one. A link that holds input is stepped at once, and one that
        // waits in its own loop has nothing to wait on here.
        let mut holds = false;
        let mut waits: Vec<Arc<dyn LinkReadiness>> = Vec::new();
        // Something the read cannot wait on that must still be looked at: a link that waits in its
        // own loop, beside links that do not, and a port that gives no wait.
        let mut own_loop = false;
        let mut dial_left_ms = None;
        for face in &self.faces {
            match &face.link {
                Link::Up(wire) | Link::Opening { wire, .. } => {
                    if wire.link.holds_input() {
                        holds = true;
                    } else if let Some(ready) = &wire.readiness {
                        waits.push(ready.clone());
                    } else {
                        own_loop = true;
                    }
                }
                Link::Waiting { at_us } => {
                    dial_left_ms = Some(at_us.saturating_sub(self.clock.now_us()) / 1000);
                }
                // Nothing to wait for until the face that holds the node is lost, which is
                // another face's link.
                #[cfg(feature = "listen")]
                Link::Held { .. } => {}
            }
        }
        if holds {
            return IdleWait::None;
        }
        #[cfg(feature = "listen")]
        let mut unwaited_port = false;
        #[cfg(feature = "listen")]
        for listening in &self.listeners {
            match &listening.readiness {
                Some(ready) => waits.push(ready.clone()),
                None => unwaited_port = true,
            }
        }
        let most = match dial_left_ms {
            Some(left) => u32::try_from(left).map_or(most, |left| left.min(most)),
            None => most,
        };
        #[cfg(feature = "listen")]
        let look_again = unwaited_port;
        #[cfg(not(feature = "listen"))]
        let look_again = false;
        let wait = match (waits.is_empty(), look_again) {
            // A port that gives no wait is looked at again after a bounded sleep.
            (true, true) if most > 0 => IdleWait::Sleep(most.min(1)),
            (true, _) => match dial_left_ms {
                Some(_) if most > 0 => IdleWait::Sleep(most),
                _ => IdleWait::None,
            },
            // The links that give a wait are waited on together, for no longer than a look when
            // something beside them cannot be waited on.
            (false, _) if most > 0 => {
                let most = if own_loop || look_again {
                    most.min(1)
                } else {
                    most
                };
                IdleWait::Input(waits, most)
            }
            _ => IdleWait::None,
        };
        // The bounds above are the clock's time read as the wall's, which a clock the program
        // moves is not: its word that the time moved on ends the wait as well.
        ended_by_clock_moves(wait, self.config.clock_moves.as_ref())
    }

    /// End every face's link, whatever it is doing, telling an established peer so. The dial
    /// role's face stays, with no link and no redial; the others go.
    fn end_links(&mut self) {
        // The ports are let go of first, so no connection is taken while the faces are ended.
        #[cfg(feature = "listen")]
        self.listeners.clear();
        // Each group's session is asked to stop, and its next step, taken here, tells the group it
        // leaves and lets the group's link go; its tables go with it.
        #[cfg(feature = "group")]
        if !self.groups.is_empty() {
            for group in &self.groups {
                group.stop();
            }
            self.local.run_until_idle();
            let mut registry = self.registry.borrow_mut();
            for group in self.groups.drain(..) {
                registry.remove_face(group.id());
            }
        }
        for face in &mut self.faces {
            face.replay.discard();
            let link = core::mem::replace(&mut face.link, Link::Waiting { at_us: u64::MAX });
            if let Link::Up(wire) | Link::Opening { wire, .. } = link {
                if wire.actions.is_established() {
                    wire.actions.send_close_with_reason(CloseReason::Generic);
                }
                wire.task.abort();
            }
        }
        drop(self.faces.split_off(1));
        self.registry.borrow_mut().remove_accepted_faces();
        self.local.run_until_idle();
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
    /// Open a session over `links` to the first endpoint of `config` that completes the
    /// handshake, stepping it on this thread until it does. `entropy` mints the zid the config
    /// does not state and each attempt's cookie key, for this open and every redial after it.
    /// An open that no endpoint answers fails: the session redials only a link it had.
    ///
    /// The session runs under the snapshot this open resolves from `config` (`resolve_policy`);
    /// an ABI that has resolved its own opens with [`Self::open_with_policy`].
    pub fn open(
        links: L,
        clock: C,
        entropy: impl EntropySource + Send + 'static,
        config: CoopConfig,
    ) -> Result<Arc<Self>, OpenError> {
        let policy = resolve_policy(&config);
        Self::open_with_policy(links, clock, entropy, config, policy)
    }

    /// [`Self::open`], the session running under `policy`, the snapshot its creator resolved:
    /// every link's session is handed it, a link's declarations are replayed at the pace it
    /// states, and two links to one node are told apart by its `link-tie-order`.
    #[inline]
    pub fn open_with_policy(
        links: L,
        clock: C,
        entropy: impl EntropySource + Send + 'static,
        config: CoopConfig,
        policy: SessionPolicy,
    ) -> Result<Arc<Self>, OpenError> {
        Self::open_with_key_ids(links, clock, entropy, config, policy, OpenKeyIds::none())
    }

    /// [`Self::open_with_policy`], the session holding `key_ids`, the key ids every node of the
    /// deployment shares (`shared-key-ids`): every link of it reads an id only the dictionary
    /// names, the session declares no key expression under one of its ids, and a key goes on the
    /// wire as the policy's `key-wire-form` says. The form is judged first, so a session that
    /// cannot honour it dials and binds nothing: `shared` with no dictionary, or any form but
    /// `declared` in a build without the feature, is [`OpenError::KeyWireForm`].
    pub fn open_with_key_ids(
        links: L,
        clock: C,
        entropy: impl EntropySource + Send + 'static,
        config: CoopConfig,
        policy: SessionPolicy,
        key_ids: OpenKeyIds,
    ) -> Result<Arc<Self>, OpenError> {
        #[cfg(feature = "shared-key-ids")]
        let key_forms = key_ids.admit(&policy)?;
        #[cfg(not(feature = "shared-key-ids"))]
        key_ids.admit(&policy)?;
        let mut entropy = SharedEntropy::new(entropy);
        let wire = match (&config.zid, policy.zid_derivation()) {
            (Some(zid), _) => wire_zid(zid)?,
            (None, wz_session_core::policy::ZidDerivation::Random) => fresh_zid(&mut entropy)?,
            (None, wz_session_core::policy::ZidDerivation::AddressPorts) => {
                derived_zid(&config.listen, &mut entropy)?
            }
        };
        let runtime = CoopRuntime::new(clock.clone());
        let local = CoopLocalSet::new(&runtime);
        let mut core = Core {
            local,
            runtime,
            clock,
            registry: Rc::new(RefCell::new(Registry::new(&resolve_limits(&config)))),
            faces: vec![Face {
                id: DIAL_FACE,
                link: Link::Waiting { at_us: u64::MAX },
                replay: Replay::with_pacing(ReplayPacing::of_policy(&policy)),
            }],
            rooms: Arc::new(LinkRooms::default()),
            next_face: 1,
            #[cfg(feature = "connectivity")]
            watchers: Arc::new(FacePlane::default()),
            links,
            #[cfg(feature = "listen")]
            listeners: Vec::new(),
            #[cfg(feature = "group")]
            groups: Vec::new(),
            entropy,
            config,
            policy,
            #[cfg(feature = "listen")]
            admission: Arc::new(LinkRegistry::<CoopRuntime<C>>::with_order(
                &wire,
                policy.link_tie_order(),
            )),
            wire_zid: wire,
            subscribers: Vec::new(),
            keyexprs: Vec::new(),
            next_mapping: 1,
            #[cfg(feature = "shared-key-ids")]
            key_ids: key_ids.at_open.ids,
            #[cfg(feature = "shared-key-ids")]
            key_forms,
            #[cfg(feature = "local-queryable")]
            next_local_request: 0,
            filters: Vec::new(),
            next_filter: 1,
            interests: Vec::new(),
            matches: Vec::new(),
            next_match: 1,
            #[cfg(feature = "queryable")]
            queryables: Vec::new(),
            #[cfg(feature = "queryable")]
            plane: Arc::new(QueryPlane::default()),
            #[cfg(feature = "query")]
            pending_gets: Vec::new(),
            #[cfg(feature = "query")]
            gets: Arc::new(GetPlane::default()),
            #[cfg(feature = "liveliness")]
            tokens: Vec::new(),
            #[cfg(feature = "liveliness")]
            live_subs: Vec::new(),
            #[cfg(feature = "ticker")]
            tickers: Tickers::default(),
        };
        #[cfg(feature = "queryable")]
        let plane = core.plane.clone();
        #[cfg(feature = "query")]
        let gets = core.gets.clone();
        #[cfg(feature = "connectivity")]
        let faces = core.watchers.clone();
        let rooms = core.rooms.clone();
        let wait_before_drop_us = core.config.tx_queue.wait_before_drop_us;
        let held_drop = core.config.tx_queue.held_drop;
        // The ports are bound and the groups joined before anything is dialled: a session that
        // cannot listen, or join a group, where it was told to does not open.
        core.listen_on_config()?;
        core.join_groups()?;
        // A session that only listens, or only joins groups, is open once it is bound and joined;
        // one that dials is open once a link completes its handshake.
        if !(core.config.endpoints.is_empty() && (core.listens() || !core.config.groups.is_empty()))
        {
            core.faces[0].link = core.dial_from(0, OpenError::NoEndpoint)?;
            // Open once the dial's link is up, or once the node it reached is held by a face that
            // came first (a peer that listens and dials its own listener's peer).
            while !core.dial_settled() {
                core.idle_wait().wait();
                core.local.run_until_idle();
                core.poll_links(None)?;
            }
        }
        Ok(Arc::new_cyclic(|this| Self {
            core: Mutex::new(Confined(core)),
            rooms,
            wait_before_drop_us,
            held_drop,
            sending: AtomicUsize::new(0),
            #[cfg(feature = "transport-stats")]
            unsent_drops: AtomicU64::new(0),
            samples: Arc::new(Mutex::new(VecDeque::new())),
            matching: Arc::new(Mutex::new(VecDeque::new())),
            targets: Mutex::new(Vec::new()),
            #[cfg(feature = "queryable")]
            plane,
            #[cfg(feature = "query")]
            gets,
            #[cfg(feature = "connectivity")]
            faces,
            #[cfg(feature = "liveliness")]
            live_samples: Arc::new(Mutex::new(VecDeque::new())),
            zid: wire,
            closed: AtomicBool::new(false),
            next_entity: AtomicU64::new(1),
            #[cfg(any(feature = "query", feature = "ticker"))]
            next_local: AtomicU64::new(1),
            reader: Mutex::new(None),
            delivering: Lock::new(Vec::new()),
            this: this.clone(),
        }))
    }

    /// Dial `endpoint` as a face of its own, beside the dial role's, and return the id it is
    /// known by. What the session declares is declared over it once its handshake completes (the
    /// session steps it as it does the first face's), what is declared after goes to it too, a
    /// publish and a get reach its peer, and what its peer declares counts with the others'. It
    /// is dialled once: a link that is lost or never completes takes the face with it, where the
    /// dial role's face is dialled again. [`OpenError::Unreachable`] when the session is closed
    /// or the endpoint is not reached.
    pub fn attach_face(&self, endpoint: &str) -> Result<u64, OpenError> {
        let Some(mut guard) = self.live() else {
            return Err(OpenError::Unreachable(String::from(
                "the session is closed",
            )));
        };
        let core = &mut guard.0;
        let id = core.next_face;
        // The tables first: the link's task dispatches to them from its first step.
        core.registry.borrow_mut().add_face(id);
        let wire = match core.dial_endpoint(id, endpoint) {
            Ok(wire) => wire,
            Err(refused) => {
                core.registry.borrow_mut().remove_face(id);
                return Err(refused);
            }
        };
        core.next_face += 1;
        let deadline_us = core.open_deadline_us();
        core.push_opening(id, wire, deadline_us);
        Ok(id)
    }

    /// The waits for room a publish that finds the session held asks. Compiled where its
    /// readers are: the group tests over the program's transport (`tests::group`).
    #[cfg(all(test, feature = "group", feature = "app-transport"))]
    pub(crate) fn rooms(&self) -> &LinkRooms {
        &self.rooms
    }

    /// How many messages of `priority` the session put on its groups were dropped for want of
    /// room on the group's stage. Compiled where its readers are, as [`Self::rooms`] is.
    #[cfg(all(test, feature = "group", feature = "app-transport"))]
    pub(crate) fn group_congestion_drops(&self, priority: wz_session_core::qos::Priority) -> u32 {
        self.live().map_or(0, |core| {
            core.0
                .groups
                .iter()
                .map(|group| group.congestion_drops(priority))
                .sum()
        })
    }

    /// The endpoints the session listens on, as bound: a port the config named as 0 is the one
    /// the stack chose. Empty once the session is closed (`listen`).
    #[cfg(feature = "listen")]
    pub fn listening(&self) -> Vec<String> {
        self.live().map_or_else(Vec::new, |core| {
            core.0
                .listeners
                .iter()
                .map(|listening| listening.listener.local().to_string())
                .collect()
        })
    }

    /// How many faces have a link that is up, whose handshake has completed.
    pub fn faces_up(&self) -> usize {
        self.live().map_or(0, |core| {
            core.0
                .ups()
                .filter(|actions| actions.is_established())
                .count()
        })
    }

    /// State how the declarations of a link go out, for a caller that wants a pace regardless of
    /// the session's policies (a test, or a program whose image is built for another policy); the
    /// snapshot the session opened under states it otherwise (`ReplayPacing::of_policy`). `Some`
    /// sends a burst of declarations a step and waits at least the interval before the next burst;
    /// `None` sends them all in one.
    pub fn set_replay_pacing(&self, pacing: Option<ReplayPacing>) {
        if let Some(mut core) = self.live() {
            for face in &mut core.0.faces {
                face.replay.set_pacing(pacing);
            }
        }
    }

    /// How the dial role's face replays its declarations now, and the snapshot the session opened
    /// under: what a test reads to tell the session's policies from the build's. Compiled where
    /// its readers are: the tests module is a host's (`all(test, feature = "std")`).
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn policy_in_force(&self) -> Option<(Option<ReplayPacing>, SessionPolicy)> {
        self.live()
            .map(|core| (core.0.dial().replay.pacing(), core.0.policy))
    }

    /// Whether the peer of every established link has been told every declaration the session
    /// holds. A session with no link established owes nothing yet, so it is synced, as the slot
    /// node's is before a client has come: synced is a statement about established sessions, not
    /// about whether a session exists.
    pub fn declarations_synced(&self) -> bool {
        self.live().map_or(true, |core| {
            core.0.faces.iter().all(|face| face.replay.finished())
        })
    }

    /// The session's state, for one operation. `None` once the session is closed.
    fn live(&self) -> Option<LiveCore<'_, L, C>> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        let guard = lock(&self.core);
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        Some(guard)
    }

    /// The session's state for a publish's leg to its links. A publish that may not be dropped
    /// waits for it ([`Self::live`]). One that may is not held behind a send that holds the
    /// session while it waits for room on a link, up to `wait_before_close` for a blocking one:
    /// zenoh bounds a droppable message's wait by `wait_before_drop`
    /// (`commons/zenoh-config/src/defaults.rs` @ `wait_before_drop: 1000,`), where its own pipeline
    /// would queue it behind the blocking one on the stage that one holds
    /// (`io/zenoh-transport/src/common/pipeline.rs` @ `let mut queue = zlock!(self.stage_in[idx]);`).
    /// So it takes the session when it is free, and while it is held asks the links that are up
    /// for room with nothing of the session held. No room within `wait_before_drop` is the
    /// congestion drop, which zenoh answers the put with success; room means the holder is not
    /// waiting on a link, and the session is tried again. A session whose links give no wait to
    /// ask is waited for. `Ok(None)` once the session is closed, or when the publish was dropped
    /// for want of room. Under the pico profile a held session drops the publish at once, with
    /// nothing asked ([`LinkRooms::for_held`]), and the caller is told
    /// ([`FanoutError::HeldConduit`]), as pico's put fails when its held transmit lock drops it.
    fn live_to_publish(&self, droppable: bool) -> Result<Option<LiveCore<'_, L, C>>, FanoutError> {
        if !droppable {
            return Ok(self.live());
        }
        loop {
            if self.closed.load(Ordering::Acquire) {
                return Ok(None);
            }
            if let Some(guard) = self.core.try_lock() {
                // A close that took the session first is seen under it, as `live` sees it.
                if self.closed.load(Ordering::Acquire) {
                    return Ok(None);
                }
                return Ok(Some(guard));
            }
            let sending = self.sending.load(Ordering::SeqCst) > 0;
            match self
                .rooms
                .for_held(self.held_drop, sending, self.wait_before_drop_us)
            {
                Room::Free => core::hint::spin_loop(),
                Room::Congested => {
                    #[cfg(feature = "transport-stats")]
                    self.unsent_drops.fetch_add(1, Ordering::Relaxed);
                    return Ok(None);
                }
                Room::Unasked => return Ok(self.live()),
                Room::Held => {
                    #[cfg(feature = "transport-stats")]
                    self.unsent_drops.fetch_add(1, Ordering::Relaxed);
                    return Err(FanoutError::HeldConduit);
                }
            }
        }
    }

    /// What the session's transports counted (`transport-stats`), in the report a tokio session
    /// gives (`OpenedSession::stats`): the counters of each link that is up, summed, and in
    /// `tx.n_dropped`, where a link's session charges the messages it dropped for congestion,
    /// the droppable publishes this engine dropped before they reached a link (one each,
    /// whatever the number of links). A link's counters leave with it, as a tokio session's
    /// leave with that session; a closed session reports the engine's drops alone.
    #[cfg(feature = "transport-stats")]
    pub fn transport_stats(&self) -> wz_session_core::stats::TransportStatsReport {
        let mut report = wz_session_core::stats::TransportStatsReport::default();
        if let Some(core) = self.live() {
            for actions in core.0.ups() {
                report.absorb(&actions.stats_report());
            }
            // A group charges what its queue dropped for congestion where the tokio engine's
            // group charges it, the transport's dropped messages; it leaves with the group's join.
            #[cfg(feature = "group")]
            for group in &core.0.groups {
                report.tx.n_dropped = report.tx.n_dropped.saturating_add(
                    usize::try_from(group.congestion_drops_total()).unwrap_or(usize::MAX),
                );
            }
        }
        let unsent = self.unsent_drops.load(Ordering::Relaxed);
        report.tx.n_dropped = report
            .tx
            .n_dropped
            .saturating_add(usize::try_from(unsent).unwrap_or(usize::MAX));
        report
    }

    /// Run the periodic jobs that are due, with no lock held: what a job does (a beacon is a
    /// publish) takes the session's lock itself. One is taken at a time, so a job that stops
    /// another finds it not yet started, and each is put back a period after its run ended. What
    /// is due is read against the time this call began, so a job that takes longer than its own
    /// period runs once per call and does not keep the caller here.
    #[cfg(feature = "ticker")]
    fn run_due_tickers(&self) {
        let Some(started_ms) = self.live().map(|core| core.0.clock.now_us() / 1000) else {
            return;
        };
        loop {
            let next = self
                .live()
                .and_then(|mut core| core.0.tickers.take_next_due(started_ms));
            let Some((id, tick)) = next else {
                return;
            };
            let goes_on = tick();
            if let Some(mut core) = self.live() {
                let now_ms = core.0.clock.now_us() / 1000;
                core.0.tickers.rearm(id, goes_on, now_ms);
            }
        }
    }

    /// Hand out what the session delivered, with no lock held.
    ///
    /// A callback may step its session again (`zp_read` from inside a subscriber), and that step
    /// delivers nothing itself: the delivery this thread is already making goes on to hand out
    /// what the inner step queued, in order. Delivering from the inner call would run a callback
    /// inside itself, waiting on its own lock.
    fn deliver(&self) {
        let Some(_delivering) = Delivering::enter(&self.delivering) else {
            return;
        };
        // Each popped under its queue's lock alone, which is released before the callback runs:
        // the pop is its own statement, since a guard in a `while let` condition would live
        // through the body and a callback that steps the session again would wait on it.
        loop {
            let next = lock(&self.samples).pop_front();
            let Some((id, sample)) = next else {
                break;
            };
            let callback = lock(&self.targets)
                .iter()
                .find_map(|(t, target)| match target {
                    Target::Subscriber(cb) if *t == TargetKey::Subscriber(id) => Some(cb.clone()),
                    _ => None,
                });
            if let Some(callback) = callback {
                (lock(&callback))(&sample);
            }
        }
        #[cfg(feature = "liveliness")]
        loop {
            let next = lock(&self.live_samples).pop_front();
            let Some((id, sample)) = next else {
                break;
            };
            let callback = lock(&self.targets)
                .iter()
                .find_map(|(t, target)| match target {
                    Target::Liveliness(cb) if *t == TargetKey::Liveliness(id) => Some(cb.clone()),
                    _ => None,
                });
            if let Some(callback) = callback {
                (lock(&callback))(sample.as_sample());
            }
        }
        // A face that came up or went down, told to each watcher as it stands now: the list is
        // cloned out of its lock, so a sink that undeclares a watcher does not wait on it.
        #[cfg(feature = "connectivity")]
        while let Some((kind, face)) = self.faces.next_event() {
            for sink in self.faces.sinks() {
                sink(kind, &face);
            }
        }
        loop {
            let next = lock(&self.matching).pop_front();
            let Some((id, matching)) = next else {
                break;
            };
            let sink = lock(&self.targets)
                .iter()
                .find_map(|(t, target)| match target {
                    Target::Matching(sink) if *t == TargetKey::Matching(id) => Some(sink.clone()),
                    _ => None,
                });
            if let Some(sink) = sink {
                sink(matching);
            }
        }
        #[cfg(feature = "queryable")]
        loop {
            let next = lock(&self.plane.queries).pop_front();
            let Some((id, query, generation)) = next else {
                break;
            };
            let callback = lock(&self.targets)
                .iter()
                .find_map(|(t, target)| match target {
                    Target::Queryable(cb) if *t == TargetKey::Queryable(id) => Some(cb.clone()),
                    _ => None,
                });
            let mut replies = ReplyStage::new();
            if let Some(callback) = callback {
                let _answering =
                    query::Answering::enter(self as *const Self as usize, generation, query.rid());
                let mut responder = query.responder(&mut replies);
                (lock(&callback))(&query, &mut responder);
            }
            // The callback's replies go out, then its hold on the Final is let go; a queryable
            // undeclared before its query was delivered lets go of the hold all the same.
            self.answer(generation, query.rid(), replies, true);
        }
        #[cfg(feature = "query")]
        loop {
            let next = lock(&self.gets.events).pop_front();
            match next {
                None => break,
                Some(GetEvent::Reply(leg, reply)) => {
                    let callback =
                        lock(&self.targets)
                            .iter()
                            .find_map(|(t, target)| match target {
                                Target::Reply(cb) if *t == TargetKey::Reply(leg) => {
                                    Some(cb.clone())
                                }
                                _ => None,
                            });
                    if let Some(callback) = callback {
                        (lock(&callback))(&reply);
                    }
                }
                // The leg is over: its callback is dropped here, with no lock held, which is
                // how the C program learns it (the reply closure's `drop(context)`).
                Some(GetEvent::End(leg)) => {
                    if let Some(mut core) = self.live() {
                        core.0.pending_gets.retain(|pending| pending.leg != leg);
                    }
                    drop(self.take_target(TargetKey::Reply(leg)));
                }
            }
        }
    }

    /// A publish's leg to the peer the link reaches, when its destination admits the wire. A link
    /// that is down skips it, as a send over it would.
    fn publish_to_link(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        if !opts.allowed_destination.allows_remote() {
            return Ok(0);
        }
        let meta = opts.push_metadata();
        let reliable = opts.reliable_bool();
        // zenoh's `is_droppable`: a best-effort message, or one whose congestion control is `Drop`
        // (`commons/zenoh-protocol/src/network/mod.rs` @ `!self.is_reliable() || self.congestion_control() == CongestionControl::Drop`).
        // A message with no QoS of its own is sent with the default's, as the send reads it.
        let congestion = meta.qos.unwrap_or(QosLevel::DEFAULT).congestion();
        let droppable = !reliable || congestion == CongestionControl::Drop;
        let Some(core) = self.live_to_publish(droppable)? else {
            return Ok(0);
        };
        // Declared after the session's guard, so it is let go first: a publish that then finds
        // the session held finds a holder that is not sending, and waits for it.
        let _sending = Sending::enter(&self.sending);
        let express = meta.is_express();
        let priority = opts.priority_band();
        // Each face is sent the put, and one a face's link could not have carried is the one that
        // is reported; a face whose link is down is skipped, as a send over it would.
        let mut outcome = Ok(0);
        for actions in core.0.ups() {
            // Each link names the key as its own key-wire form says.
            let wire = on_link(actions, keyexpr, wire);
            let suffix = wire.suffix.as_deref();
            // A plain Put is sent from the borrowed bytes, as the tokio engine sends it, unless
            // the session rewrites what it originates, which leaves it to the owned send below.
            let plain = if opts.kind == SampleKind::Put && meta.is_plain_apart_from_qos() {
                let (mapping_id, suffix) = if wire.is_literal() {
                    (0, Some(keyexpr))
                } else {
                    (wire.mapping_id, suffix)
                };
                actions.send_plain_put_qos(
                    mapping_id, suffix, payload, meta.qos, reliable, express, priority,
                )
            } else {
                None
            };
            let sent = if let Some(plain) = plain {
                leg(plain)
            } else {
                let push = match (opts.kind, wire.mapping_id) {
                    (SampleKind::Put, 0) => {
                        push_build::build_push_literal_with_meta(keyexpr, payload, &meta)
                    }
                    (SampleKind::Del, 0) => {
                        push_build::build_push_del_literal_with_meta(keyexpr, &meta)
                    }
                    (SampleKind::Put, mapping_id) => {
                        push_build::build_push_aliased_with_meta(mapping_id, suffix, payload, &meta)
                    }
                    (SampleKind::Del, mapping_id) => {
                        push_build::build_push_del_aliased_with_meta(mapping_id, suffix, &meta)
                    }
                };
                match push {
                    Ok(push) => leg(actions.send_network_message_qos(
                        NetworkMessage::Push(Box::new(push)),
                        reliable,
                        express,
                        priority,
                    )),
                    Err(_) => Err(FanoutError::ExceedsCapacity),
                }
            };
            if sent.is_err() {
                outcome = sent;
            }
        }
        // And each group the session joined, which its task frames and sends.
        #[cfg(feature = "group")]
        for group in &core.0.groups {
            let sent = group.publish(GroupPut {
                keyexpr,
                wire,
                payload,
                kind: opts.kind,
                meta: &meta,
                reliable,
                priority,
            });
            if sent.is_err() {
                outcome = sent;
            }
        }
        outcome
    }

    /// A publish's leg to the session's own subscribers, when its destination admits them: the
    /// sample goes through the registry's loopback, which fires the subscribers whose origin
    /// admits it, and what they queued is handed out here with no lock held, so a callback runs
    /// inside the put as zenoh-pico's does. The number of subscribers it reached.
    #[cfg(feature = "local-subscriber")]
    fn publish_to_subscribers(
        &self,
        keyexpr: &str,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> usize {
        if !opts.allowed_destination.allows_local() {
            return 0;
        }
        let Some(core) = self.live() else {
            return 0;
        };
        let sample = opts.loopback_sample(keyexpr, payload);
        let reached = core
            .0
            .registry
            .borrow_mut()
            .app
            .subscribers
            .local_publish(&sample);
        drop(core);
        self.deliver();
        reached
    }

    /// Tell `fan`, when the get can be cancelled, how to undo leg `leg`: a token cancelled while
    /// the leg is issued undoes it at once (`record` runs it). Whether the legs may go on being
    /// issued: `false` once the token cancelled.
    #[cfg(feature = "query")]
    fn cancelling(&self, fan: Option<&CancellableFan>, leg: u64) -> bool {
        let Some(fan) = fan else {
            return true;
        };
        let engine = self.this.clone();
        fan.record(move || {
            if let Some(engine) = engine.upgrade() {
                engine.cancel_get(leg);
            }
        })
    }

    /// Cancel leg `leg` (its get's cancellation token was cancelled): its pending entry is
    /// dropped, and its callback with it, here, with no lock held, so a `cancel` that waits for
    /// the leg's callback to be dropped returns whether or not the session is stepped.
    #[cfg(feature = "query")]
    fn cancel_get(&self, leg: u64) {
        if let Some(mut core) = self.live() {
            let core = &mut core.0;
            if let Some(at) = core.pending_gets.iter().position(|p| p.leg == leg) {
                let pending = core.pending_gets.remove(at);
                pending.unregister(&mut core.registry.borrow_mut());
            }
        }
        drop(self.take_target(TargetKey::Reply(leg)));
    }

    /// Hold `callback` as what the replies of leg `leg` are handed to, until the leg ends.
    #[cfg(feature = "query")]
    fn hold_leg(&self, leg: u64, callback: ReplyCallback) {
        lock(&self.targets).push((
            TargetKey::Reply(leg),
            Target::Reply(Arc::new(Mutex::new(callback))),
        ));
    }

    /// Send `replies` to the query `rid` on the link of `generation` and, with `release`, let go
    /// of one hold on its Final, sending the Final when it was owed and this was the last hold.
    /// Nothing is sent on a link that is no longer the session's.
    #[cfg(feature = "queryable")]
    fn answer(
        &self,
        generation: u64,
        rid: wz_session_core::wire_id::RequestId,
        replies: ReplyStage,
        release: bool,
    ) {
        let Some(core) = self.live() else {
            return;
        };
        // The session's own get is answered to its pending entry, which is the registry's.
        #[cfg(feature = "local-queryable")]
        if generation == query::LOCAL_QUERY {
            let mut registry = core.0.registry.borrow_mut();
            let gets = &mut registry.local;
            for reply in replies {
                gets.replies.deliver_local_reply(&reply.into());
            }
            if release && lock(&self.plane.holds).release(generation, rid).is_some() {
                gets.replies.deliver_local_final(rid);
            }
            drop(registry);
            drop(core);
            self.deliver();
            return;
        }
        let route = core.0.answer_route(generation);
        if let Some(route) = route {
            for reply in replies {
                if let Ok(response) = reply.into_response() {
                    route.send_response(response);
                }
            }
        }
        if release {
            let due = lock(&self.plane.holds).release(generation, rid);
            if let (Some(qos), Some(route)) = (due, route) {
                route.send_response_final(rid, qos);
            }
        }
    }

    /// Take the callback `key` names out of the targets; the caller drops it with no lock held.
    fn take_target(&self, key: TargetKey) -> Option<Target> {
        let mut targets = lock(&self.targets);
        let at = targets.iter().position(|(t, _)| *t == key)?;
        Some(targets.remove(at).1)
    }

    /// Step the session until it has nothing more to do, move its link on, and notice a session
    /// that ended.
    fn step(&self, core: &mut Core<L, C>) -> bool {
        core.local.run_until_idle();
        // A get whose deadline has passed ends with zenoh's timeout reply and its Final, here,
        // because this is what runs on every step and the entries are the registry's.
        #[cfg(feature = "query")]
        {
            let now_ms = core.clock.now_us() / 1000;
            let mut registry = core.registry.borrow_mut();
            for gets in registry.all_gets_mut() {
                gets.replies.sweep_timed_out(now_ms);
                // A liveliness snapshot that expired ends the same way. Its terminated ids are
                // staged for a reconnect cache this engine does not keep (it declares again from
                // its own entries), so they are drained and dropped: staged ones would pile up.
                #[cfg(feature = "liveliness-get")]
                {
                    gets.liveliness_gets.sweep_timed_out(now_ms);
                    drop(gets.liveliness_gets.take_finalized());
                }
            }
        }
        let redial_ms = core.config.redial_ms;
        if core.poll_links(redial_ms).is_err() {
            self.closed.store(true, Ordering::Release);
            return false;
        }
        // A group told the session's keyexprs that came up, at the open or joined again, asks
        // for its members' with the session's next entity id, as the tokio engine's group asks
        // when it comes up. Best effort: a member's own declarations reach the group later all
        // the same, so a session with no entity id left does not ask.
        #[cfg(feature = "group")]
        for group in &core.groups {
            if group.owes_keyexpr_ask() {
                if let Some(interest_id) = self.next_entity_id() {
                    group.ask_keyexprs(u64::from(interest_id));
                }
            }
        }
        true
    }

    /// Hold the Interest for `keyexpr` on `plane`, sending it in `form` for its first holder:
    /// `false`, with nothing held or sent, when a first holder finds the session with no entity
    /// id left for it.
    fn acquire_interest(
        &self,
        core: &mut Core<L, C>,
        plane: FilterPlane,
        keyexpr: &str,
        form: &InterestForm,
    ) -> bool {
        if let Some(hold) = core
            .interests
            .iter_mut()
            .find(|h| h.plane.same_kind(plane) && h.keyexpr == keyexpr)
        {
            hold.holds += 1;
            return true;
        }
        // zenoh-pico's Interest takes the session's next entity id
        // (`vendor/zenoh-pico/src/net/primitives.c` @ `intr._id = _z_get_entity_id(zn);`).
        let Some(interest_id) = self.next_entity_id() else {
            return false;
        };
        let hold = InterestHold {
            plane,
            keyexpr: keyexpr.to_owned(),
            interest_id: u64::from(interest_id),
            form: form.clone(),
            holds: 1,
        };
        core.announce(Kind::Interest, |actions| hold.send(actions));
        core.interests.push(hold);
        true
    }

    /// The id of something the session holds and never names to a peer (`next_local`).
    #[cfg(any(feature = "query", feature = "ticker"))]
    fn next_local_id(&self) -> u64 {
        self.next_local.fetch_add(1, Ordering::Relaxed)
    }

    /// Spend every interest id of the session of each face whose link is up, as a session that
    /// has asked `u32::MAX` Interests has.
    #[cfg(all(test, feature = "liveliness-get"))]
    pub(crate) fn spend_interest_ids(&self) {
        let Some(guard) = self.live() else {
            return;
        };
        let core = &guard.0;
        for face in core.up_faces() {
            if let Some(actions) = core.up_actions(face) {
                actions
                    .next_outbound_interest_id
                    .store(u64::from(u32::MAX) + 1, Ordering::Relaxed);
            }
        }
    }

    /// Let go of one hold on the Interest for `keyexpr` on `plane`; the last one ends it.
    fn release_interest(core: &mut Core<L, C>, plane: FilterPlane, keyexpr: &str) {
        let Some(at) = core
            .interests
            .iter()
            .position(|h| h.plane.same_kind(plane) && h.keyexpr == keyexpr)
        else {
            return;
        };
        core.interests[at].holds -= 1;
        if core.interests[at].holds == 0 {
            let links = core.retract(Kind::Interest, at);
            let hold = core.interests.remove(at);
            for actions in links {
                actions.send_interest_final(hold.interest_id);
            }
        }
    }

    /// Whether a peer declared what `plane` counts on `keyexpr`.
    fn peer_matches(core: &Core<L, C>, plane: FilterPlane, keyexpr: &str) -> bool {
        let registry = core.registry.borrow();
        let subscribers = PublisherCriterion::new(keyexpr, Locality::Remote);
        // Any face's peer: a write filter holds a write back only when none of them wants it.
        let matched = registry.faces().any(|face| match plane {
            FilterPlane::Subscribers => face.peer.remote_subscribers.has_matching_for(&subscribers),
            FilterPlane::Queryables { complete_required } => face
                .peer
                .remote_queryables
                .has_matching_for(&QuerierCriterion::new(
                    keyexpr,
                    Locality::Remote,
                    complete_required,
                )),
        });
        matched
    }

    /// Whether the session's own entities of `plane`'s kind match `keyexpr`: a subscriber of its
    /// own that a local put reaches (`local-subscriber`). The session answers nothing else
    /// locally, as zenoh-pico's default build does not.
    fn local_matches(core: &Core<L, C>, plane: FilterPlane, keyexpr: &str) -> bool {
        #[cfg(feature = "local-subscriber")]
        if matches!(plane, FilterPlane::Subscribers) {
            return core
                .registry
                .borrow()
                .app
                .subscribers
                .has_local_matching(keyexpr);
        }
        #[cfg(feature = "local-queryable")]
        if let FilterPlane::Queryables { complete_required } = plane {
            return core
                .registry
                .borrow()
                .app
                .queryables
                .has_local_matching(keyexpr, complete_required);
        }
        let _ = (core, plane, keyexpr);
        false
    }

    /// Hand a get of this session to the session's own queryables, as zenoh-pico's
    /// `_z_session_deliver_query_locally` does after the query went out: each queryable that
    /// matches holds the get's Final and answers when its callback runs, and the Final is owed
    /// now, so it reaches the get once the last of them has answered.
    #[cfg(feature = "local-queryable")]
    fn ask_own_queryables(
        &self,
        core: &mut Core<L, C>,
        rid: wz_session_core::wire_id::RequestId,
        keyexpr: &str,
        opts: &QueryOptions,
    ) {
        let qos = opts.qos.unwrap_or(QosLevel::DEFAULT);
        let envelope = QueryEnvelope {
            rid,
            target: opts.effective_target(),
            qos,
        };
        let query = opts.loopback_query();
        let mut staged = ReplyStage::new();
        let mut registry = core.registry.borrow_mut();
        self.plane.asking_locally(|| {
            registry.app.queryables.local_query_with_value(
                envelope,
                keyexpr,
                &query,
                None,
                &mut staged,
            )
        });
        let gets = &mut registry.local;
        for reply in staged {
            gets.replies.deliver_local_reply(&reply.into());
        }
        if lock(&self.plane.holds).owe(query::LOCAL_QUERY, rid, qos) {
            gets.replies.deliver_local_final(rid);
        }
    }

    /// The queryables' plane's counterpart of [`Self::reevaluate_subscriber_matching`].
    #[cfg(feature = "local-queryable")]
    fn reevaluate_queryable_matching(core: &Core<L, C>) {
        core.registry.borrow_mut().reevaluate_querier_watches();
    }

    /// What a write filter or a matching listener on `plane` reads: a peer's declaration, or with
    /// `count_local` one of the session's own.
    fn plane_matches(
        core: &Core<L, C>,
        plane: FilterPlane,
        keyexpr: &str,
        count_local: bool,
    ) -> bool {
        Self::peer_matches(core, plane, keyexpr)
            || (count_local && Self::local_matches(core, plane, keyexpr))
    }

    /// Tell every matching listener on the subscribers' plane that counts the session's own
    /// subscribers whether it now matches, after one was declared or retracted here: the
    /// registry reads the remote half off its own membership and asks this for the local half.
    #[cfg(feature = "local-subscriber")]
    fn reevaluate_subscriber_matching(core: &Core<L, C>) {
        core.registry.borrow_mut().reevaluate_publisher_watches();
    }

    /// Stop the read task, from a thread that is not it.
    fn stop_reader(&self) -> Result<(), CalledFromReadTask> {
        let task = {
            let mut reader = lock(&self.reader);
            match reader.as_ref() {
                None => return Ok(()),
                Some(task) if task.id == os::current() => return Err(CalledFromReadTask),
                Some(_) => reader.take(),
            }
        };
        if let Some(task) = task {
            task.stop.store(true, Ordering::Release);
            task.thread.join();
        }
        Ok(())
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> SessionEngine
    for CoopEngine<L, C>
{
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn session_zid(&self) -> SessionZid {
        self.zid
    }

    fn now_ms(&self) -> u64 {
        // The session's own clock, which is what its deadlines and its jobs run on. Read under the
        // session's lock, which nothing here holds while a callback runs.
        lock(&self.core).0.clock.now_us() / 1000
    }

    fn next_entity_id(&self) -> Option<EntityId> {
        u32_id_taken(self.next_entity.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            next_u32_id,
        ))
    }

    #[cfg(feature = "ticker")]
    fn start_ticker(&self, period_ms: u64, tick: Tick) -> Option<TickerId> {
        let mut core = self.live()?;
        let id = self.next_local_id();
        let now_ms = core.0.clock.now_us() / 1000;
        core.0.tickers.start(id, period_ms, tick, now_ms);
        Some(id)
    }

    #[cfg(feature = "ticker")]
    fn stop_ticker(&self, id: TickerId) {
        if let Some(mut core) = self.live() {
            core.0.tickers.stop(id);
        }
    }

    fn peer_identities(&self) -> Vec<(Vec<u8>, u8)> {
        let Some(core) = self.live() else {
            return Vec::new();
        };
        // A group's members are not listed here, as the tokio engine lists none:
        // `group_member_zids` answers them, whatever role they announced.
        core.0
            .ups()
            .filter(|actions| actions.is_established())
            .filter_map(
                |actions| match (actions.peer_zid(), actions.peer_whatami_wire()) {
                    (Some(zid), Some(role)) => Some((zid, role)),
                    _ => None,
                },
            )
            .collect()
    }

    #[cfg(feature = "group")]
    fn group_member_zids(&self) -> Vec<Vec<u8>> {
        let Some(core) = self.live() else {
            return Vec::new();
        };
        core.0
            .groups
            .iter()
            .flat_map(GroupFace::member_zids)
            .collect()
    }

    /// Each group's session sends its JOIN at its next step, which this call takes, as the tokio
    /// engine's group sends one at once.
    #[cfg(feature = "group")]
    fn send_join_on_groups(&self) -> usize {
        let Some(mut guard) = self.live() else {
            return 0;
        };
        let core = &mut guard.0;
        let asked = core.groups.iter().filter(|group| group.ask_join()).count();
        if asked == 0 {
            return 0;
        }
        core.local.run_until_idle();
        drop(guard);
        // What the step took from a group is handed out outside the lock, as a read's is.
        self.deliver();
        asked
    }

    #[cfg(feature = "connectivity")]
    fn face_snapshots(&self) -> Vec<FaceSnapshot> {
        self.live()
            .map_or_else(Vec::new, |core| core.0.standing_faces())
    }

    #[cfg(feature = "connectivity")]
    fn watch_faces(&self, sink: FaceEventSink) -> u64 {
        self.faces.watch(sink)
    }

    #[cfg(feature = "connectivity")]
    fn unwatch_faces(&self, id: u64) -> bool {
        self.faces.unwatch(id)
    }

    fn has_router_peer(&self) -> bool {
        self.live().is_some_and(|core| {
            core.0
                .ups()
                .any(|actions| actions.peer_whatami_wire() == Some(0))
        })
    }

    #[cfg(feature = "shared-key-ids")]
    fn names_keys_by_link(&self) -> bool {
        self.live().is_some_and(|core| {
            core.0.key_ids.is_some() || core.0.key_forms.departs_from_declared()
        })
    }

    fn redeclare(&self) -> Result<usize, wz_capi_port::RedeclareRefusal> {
        let mut core = self.live().ok_or(wz_capi_port::RedeclareRefusal::Closed)?;
        Ok(core.0.redeclare())
    }

    fn publish_on_wire_all(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        // This engine numbers none of its links, offers no frame without waiting and reserves
        // none, so a publish that states a set of links, a retry or the all-or-none form is
        // refused by name before anything is sent, to a link or to a subscriber of the session.
        StatementNotHonoured::of_publish(opts)?;
        // The link first, then the session's own subscribers, as zenoh-pico's `_z_write` does,
        // and nothing local when the link refused it.
        let sent = self.publish_to_link(keyexpr, wire, payload, opts)?;
        #[cfg(feature = "local-subscriber")]
        let sent = sent + self.publish_to_subscribers(keyexpr, payload, opts);
        Ok(sent)
    }

    fn declare_subscriber_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        allowed_origin: Locality,
        retraction: Option<RetractionKey>,
        sink: SubscriberSink,
    ) -> Option<SubId> {
        let id = self.next_entity_id()?;
        let Some(mut guard) = self.live() else {
            return Some(id);
        };
        let core = &mut guard.0;
        let queue = self.samples.clone();
        let registration = core.registry.borrow_mut().app.subscribers.register_sink(
            &keyexpr,
            allowed_origin,
            BoxedSink::new(move |sample: &dyn SampleView| {
                lock(&queue).push_back((id, Sample::from_view(sample)));
            }),
        );
        let Ok(registration) = registration else {
            return Some(id);
        };
        lock(&self.targets).push((
            TargetKey::Subscriber(id),
            Target::Subscriber(Arc::new(Mutex::new(sink()))),
        ));
        let entry = SubEntry {
            id,
            registration,
            retraction,
            keyexpr,
            wire,
        };
        core.announce(Kind::Subscriber, |actions| entry.declare(actions));
        #[cfg(feature = "group")]
        core.announce_to_groups(GroupEntity {
            what: GroupDeclaration::Subscriber,
            entity: id,
            keyexpr: &entry.keyexpr,
            wire: &entry.wire,
            retraction: entry.retraction.as_ref(),
            allowed_origin,
        });
        core.subscribers.push(entry);
        // A matching listener that counts the session's own subscribers may now match: it is
        // told, outside the lock.
        #[cfg(feature = "local-subscriber")]
        {
            Self::reevaluate_subscriber_matching(core);
            drop(guard);
            self.deliver();
        }
        Some(id)
    }

    fn undeclare_subscriber(&self, id: SubId) {
        // A liveliness subscriber's id is one of these too (the port's one id space): its
        // registration goes and its Interest ends.
        #[cfg(feature = "liveliness")]
        let live = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let at = core.live_subs.iter().position(|s| s.id == id)?;
            let links = core.retract(Kind::LiveSub, at);
            let entry = core.live_subs.remove(at);
            // The groups asked for it are told the asking ended.
            #[cfg(feature = "group")]
            for group in &core.groups {
                group.end_liveliness_ask(id);
            }
            core.registry
                .borrow_mut()
                .app
                .liveliness_subscribers
                .unregister(u64::from(id));
            for actions in links {
                actions.send_interest_final(u64::from(id));
            }
            Some(entry)
        });
        #[cfg(feature = "liveliness")]
        if live.is_some() {
            let callback = self.take_target(TargetKey::Liveliness(id));
            drop((live, callback));
            return;
        }
        let entry = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let at = core.subscribers.iter().position(|s| s.id == id)?;
            let links = core.retract(Kind::Subscriber, at);
            let entry = core.subscribers.remove(at);
            #[cfg(feature = "group")]
            core.retract_from_groups(id);
            core.registry
                .borrow_mut()
                .app
                .subscribers
                .unregister(entry.registration);
            for actions in links {
                match &entry.retraction {
                    Some(key) => actions.send_undeclare_subscriber_naming(
                        u64::from(id),
                        key.mapping_id,
                        &key.suffix,
                    ),
                    None => actions.send_undeclare_subscriber(u64::from(id)),
                }
            }
            // One that counted it may now match no more.
            #[cfg(feature = "local-subscriber")]
            Self::reevaluate_subscriber_matching(core);
            Some(entry)
        });
        let callback = self.take_target(TargetKey::Subscriber(id));
        drop((entry, callback));
        #[cfg(feature = "local-subscriber")]
        self.deliver();
    }

    fn acquire_keyexpr(&self, keyexpr: String) -> Option<ExprId> {
        let mut core = self.live()?;
        let core = &mut core.0;
        if let Some(entry) = core.keyexprs.iter_mut().find(|e| e.keyexpr == keyexpr) {
            entry.holds += 1;
            return Some(entry.id);
        }
        // The id space is the wire's `ExprId`; once it is spent the counter rests at 0, the
        // literal's id, and every further declaration is refused rather than re-issuing a live
        // id.
        let id = core.next_mapping;
        // An id of the shared dictionary names its key in this session's space too, so no key
        // expression is declared under one: the next id past them, or none when none is left.
        #[cfg(feature = "shared-key-ids")]
        let id = match &core.key_ids {
            Some(ids) => ids.next_free_id(id).unwrap_or(0),
            None => id,
        };
        if id == 0 {
            return None;
        }
        // A declaration a link refuses is not made, and the links that took it take it back; one
        // made while a link is down, or that a replay has not reached, is sent in its turn.
        let taken = core.announce_or_undo(
            Kind::Keyexpr,
            |actions| actions.send_declare_keyexpr(id, &keyexpr).is_ok(),
            |actions| actions.send_undeclare_kexpr(id),
        );
        if !taken {
            return None;
        }
        // And each group told the session's keyexprs, as a link is.
        #[cfg(feature = "group")]
        for group in &core.groups {
            group.announce_keyexpr(id, &keyexpr);
        }
        core.next_mapping = id.wrapping_add(1);
        core.keyexprs.push(KexprEntry {
            id,
            keyexpr,
            holds: 1,
        });
        Some(id)
    }

    fn release_keyexpr(&self, mapping_id: ExprId) {
        let Some(mut core) = self.live() else {
            return;
        };
        let core = &mut core.0;
        let Some(at) = core.keyexprs.iter().position(|e| e.id == mapping_id) else {
            return;
        };
        core.keyexprs[at].holds -= 1;
        if core.keyexprs[at].holds == 0 {
            let links = core.retract(Kind::Keyexpr, at);
            core.keyexprs.remove(at);
            for actions in links {
                actions.send_undeclare_kexpr(mapping_id);
            }
            #[cfg(feature = "group")]
            for group in &core.groups {
                group.retract_keyexpr(mapping_id);
            }
        }
    }

    fn keyexpr_declarations(&self) -> Vec<(ExprId, String)> {
        self.live()
            .map(|core| {
                core.0
                    .keyexprs
                    .iter()
                    .map(|e| (e.id, e.keyexpr.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn declare_matching_listener(
        &self,
        plane: FilterPlane,
        keyexpr: String,
        sink: MatchingSink,
        // The session's own subscribers count with `local-subscriber` and its own queryables with
        // `local-queryable`, and nothing of its own does otherwise: zenoh-pico's default build
        // (`Z_FEATURE_LOCAL_SUBSCRIBER` and `Z_FEATURE_LOCAL_QUERYABLE` 0) delivers nothing
        // locally.
        count_local: bool,
    ) -> MatchId {
        let Some(mut guard) = self.live() else {
            return 0;
        };
        let core = &mut guard.0;
        // A listener whose Interest the session has no id left for is not declared, as a closed
        // session declares none: it would never hear a peer.
        if !self.acquire_interest(
            core,
            plane,
            &keyexpr,
            &InterestForm {
                mapping_id: 0,
                suffix: Some(keyexpr.clone()),
                aggregate: false,
            },
        ) {
            return 0;
        }
        let id = core.next_match;
        core.next_match += 1;
        let local = count_local && Self::local_matches(core, plane, &keyexpr);
        let now = Self::peer_matches(core, plane, &keyexpr) || local;
        let queue = self.matching.clone();
        let report = BoxedMatchingSink::new(move |matching| {
            lock(&queue).push_back((id, matching));
        });
        // The watch is in the registry of what `plane` counts, with the criterion its write
        // filter reads ([`Self::plane_matches`]), so the listener and the filter cannot differ.
        let watch = {
            let mut registry = core.registry.borrow_mut();
            match plane {
                FilterPlane::Subscribers => registry.watch_publishers(
                    PublisherCriterion::new(&keyexpr, counted(plane, count_local)),
                    local,
                    report,
                ),
                FilterPlane::Queryables { complete_required } => registry.watch_queriers(
                    QuerierCriterion::new(&keyexpr, counted(plane, count_local), complete_required),
                    local,
                    report,
                ),
            }
        };
        lock(&self.targets).push((TargetKey::Matching(id), Target::Matching(sink)));
        // An already-matching registration is told so at once, as zenoh-pico tells it
        // (`vendor/zenoh-pico/src/net/filtering.c` @ `_z_write_filter_ctx_add_callback`).
        if now {
            lock(&self.matching).push_back((id, true));
        }
        core.matches.push(MatchEntry {
            id,
            plane,
            watch,
            keyexpr,
        });
        drop(guard);
        self.deliver();
        id
    }

    fn undeclare_matching_listener(&self, id: MatchId) {
        if let Some(mut core) = self.live() {
            let core = &mut core.0;
            if let Some(at) = core.matches.iter().position(|m| m.id == id) {
                let entry = core.matches.remove(at);
                {
                    let mut registry = core.registry.borrow_mut();
                    match entry.plane {
                        FilterPlane::Subscribers => registry
                            .app
                            .remote_subscribers
                            .undeclare_matching_listener(entry.watch),
                        FilterPlane::Queryables { .. } => registry
                            .app
                            .remote_queryables
                            .undeclare_matching_listener(entry.watch),
                    };
                }
                Self::release_interest(core, entry.plane, &entry.keyexpr);
            }
        }
        drop(self.take_target(TargetKey::Matching(id)));
    }

    fn declare_write_filter(
        &self,
        plane: FilterPlane,
        keyexpr: String,
        wire: &WireKey,
        ask: Option<InterestForm>,
        // See `declare_matching_listener`: the session's own subscribers count with
        // `local-subscriber`.
        count_local: bool,
    ) -> Option<FilterId> {
        let Some(mut core) = self.live() else {
            return Some(0);
        };
        let core = &mut core.0;
        // The id this filter spent of its own, when it spent one: its Interest's, when it is the
        // first to hold it, or the one taken for a filter that sends none.
        let mut spent = None;
        let held = match &ask {
            Some(form) => {
                let before = core.interests.len();
                let held = self.acquire_interest(core, plane, &keyexpr, form);
                if held && core.interests.len() > before {
                    spent = core.interests.last().map(|hold| hold.interest_id);
                }
                held
            }
            // The entity id is taken whether the Interest is sent or not, as zenoh-pico's
            // `_z_add_interest` takes it before it decides.
            None => match self.next_entity_id() {
                Some(taken) => {
                    spent = Some(u64::from(taken));
                    true
                }
                None => false,
            },
        };
        // A session with no id left refuses the filter, and spends no filter id on it.
        if !held {
            return None;
        }
        let id = core.next_filter;
        core.next_filter += 1;
        // Each group a write filter asks (`asks_for_filters`) is asked for its members'
        // declarations by an id of the filter's own, as the tokio engine's group is: the one the
        // filter spent, or a fresh one when its Interest was held already.
        #[cfg(feature = "group")]
        if core
            .groups
            .iter()
            .any(|group| group.declarations().asks_for_filters())
        {
            if let Some(interest_id) = spent.or_else(|| self.next_entity_id().map(u64::from)) {
                for group in &core.groups {
                    group.ask_filter(id, interest_id, plane, &keyexpr, wire);
                }
            }
        }
        #[cfg(not(feature = "group"))]
        let _ = (spent, wire);
        core.filters.push(FilterEntry {
            id,
            plane,
            keyexpr,
            asked: ask.is_some(),
            count_local,
        });
        Some(id)
    }

    fn write_filter_active(&self, id: FilterId) -> bool {
        let Some(core) = self.live() else {
            return false;
        };
        let core = &core.0;
        // A filter is created suppressing, until a peer declares what it counts, or the session
        // itself does when it counts its own (`vendor/zenoh-pico/src/net/filtering.c` @
        // `ctx->state = WRITE_FILTER_ACTIVE`).
        core.filters
            .iter()
            .find(|f| f.id == id)
            .is_some_and(|f| !Self::plane_matches(core, f.plane, &f.keyexpr, f.count_local))
    }

    fn write_filter_holds_back(&self, id: FilterId) -> bool {
        // A group the filter does not ask is sent a write whatever the filter says, as the tokio
        // engine sends one (`GroupDeclarations::asks_for_filters`): on such a group zenoh-pico
        // sends what its filter would hold back. Without a group no write must reach anyone
        // regardless.
        #[cfg(feature = "group")]
        if self.live().is_some_and(|core| {
            core.0
                .groups
                .iter()
                .any(|group| !group.declarations().asks_for_filters())
        }) {
            return false;
        }
        self.write_filter_active(id)
    }

    fn undeclare_write_filter(&self, id: FilterId) {
        let Some(mut core) = self.live() else {
            return;
        };
        let core = &mut core.0;
        let Some(at) = core.filters.iter().position(|f| f.id == id) else {
            return;
        };
        let entry = core.filters.remove(at);
        if entry.asked {
            Self::release_interest(core, entry.plane, &entry.keyexpr);
        }
        // The groups it asked are told the asking ended.
        #[cfg(feature = "group")]
        for group in &core.groups {
            group.end_filter(id);
        }
    }

    fn put_plain_filtered(
        &self,
        filter: FilterId,
        keyexpr: &str,
        mapping_id: ExprId,
        payload: &[u8],
        params: &PlainPutParams,
    ) -> FilteredPut {
        if self.write_filter_holds_back(filter) {
            return FilteredPut::Suppressed;
        }
        // A put one of the session's own subscribers wants is not plain: the general publish
        // sends it and delivers it there.
        #[cfg(feature = "local-subscriber")]
        if params.destination.allows_local() {
            let wanted = self.live().is_some_and(|core| {
                core.0
                    .registry
                    .borrow()
                    .app
                    .subscribers
                    .has_local_matching(keyexpr)
            });
            if wanted {
                return FilteredPut::NotPlain;
            }
        }
        if !params.destination.allows_remote() {
            return FilteredPut::Sent(Ok(0));
        }
        let Some(core) = self.live() else {
            return FilteredPut::Sent(Ok(0));
        };
        // A group is sent a put by the general publish, which pushes it onto the group's stage.
        #[cfg(feature = "group")]
        if !core.0.groups.is_empty() {
            return FilteredPut::NotPlain;
        }
        // Asked of every link before any is sent to, so the put goes plain to all of them or to
        // none: a link that rewrites what it originates (a routing namespace) takes the general
        // publish for the whole of it. Its namespace is installed before the session sends
        // anything, so no link answers otherwise below.
        if core
            .0
            .ups()
            .any(|actions| actions.rewrites_originated_keys())
        {
            return FilteredPut::NotPlain;
        }
        let suffix = (mapping_id == 0).then_some(keyexpr);
        let mut outcome = Ok(0);
        for actions in core.0.ups() {
            let sent = leg(actions
                .send_plain_put_qos(
                    mapping_id,
                    suffix,
                    payload,
                    params.qos,
                    params.reliable,
                    params.express,
                    params.priority,
                )
                .unwrap_or(Err(SendWireError::FeatureDisabled)));
            if sent.is_err() {
                outcome = sent;
            }
        }
        FilteredPut::Sent(outcome)
    }

    fn batch_start_all(&self) -> usize {
        self.live().map_or(0, |core| {
            core.0
                .ups()
                .filter(|actions| actions.batch_start().is_ok())
                .count()
        })
    }

    fn batch_flush_all(&self) -> usize {
        self.live().map_or(0, |core| {
            core.0
                .ups()
                .filter(|actions| actions.batch_flush().is_ok())
                .count()
        })
    }

    fn batch_stop_all(&self) -> usize {
        self.live().map_or(0, |core| {
            core.0
                .ups()
                .filter(|actions| actions.batch_stop().is_ok())
                .count()
        })
    }

    #[cfg(feature = "queryable")]
    fn declare_queryable_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        complete: bool,
        allowed_origin: Locality,
        retraction: Option<RetractionKey>,
        sink: QueryableSink,
    ) -> Option<QblId> {
        let id = self.next_entity_id()?;
        let mut guard = self.live()?;
        let core = &mut guard.0;
        // The registry's queryable only copies a query out and holds its Final; the callback
        // `sink` mints runs when the deliveries are handed out (`query`).
        let plane = self.plane.clone();
        let registration = core
            .registry
            .borrow_mut()
            .app
            .queryables
            .register_sink(
                &keyexpr,
                allowed_origin,
                complete,
                BoxedQuerySink::new(move |query, _in_place| plane.arrive(id, query)),
            )
            .ok()?;
        let holder = Arc::new(CoopHolder {
            engine: self.this.clone(),
        });
        lock(&self.targets).push((
            TargetKey::Queryable(id),
            Target::Queryable(Arc::new(Mutex::new(sink(holder)))),
        ));
        let entry = QblEntry {
            id,
            registration,
            retraction,
            keyexpr,
            wire,
            complete,
        };
        core.announce(Kind::Queryable, |actions| entry.declare(actions));
        #[cfg(feature = "group")]
        core.announce_to_groups(GroupEntity {
            what: GroupDeclaration::Queryable {
                complete: entry.complete,
            },
            entity: id,
            keyexpr: &entry.keyexpr,
            wire: &entry.wire,
            retraction: entry.retraction.as_ref(),
            allowed_origin,
        });
        core.queryables.push(entry);
        // A matching listener that counts the session's own queryables may now match: it is told,
        // outside the lock.
        #[cfg(feature = "local-queryable")]
        {
            Self::reevaluate_queryable_matching(core);
            drop(guard);
            self.deliver();
        }
        Some(id)
    }

    #[cfg(feature = "query")]
    fn get_on_wire(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        opts: &QueryOptions,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Option<usize> {
        // One leg for each face whose link is up, when the destination admits a peer, and one to
        // the session's own queryables, when it admits the session and the build has them
        // (`local-queryable`: zenoh-pico's default build asks none, `Z_FEATURE_LOCAL_QUERYABLE`
        // 0). A get that reaches nobody, because its destination admits neither or because no
        // link is up, is over at once. Each leg is issued under the session's lock and no lock is
        // held between two of them.
        //
        // A get limited to some links or addressed to one node is asked of none: this engine
        // reads neither, and asking every link would widen it. `get_stated` is the door that
        // refuses it by name.
        if StatementNotHonoured::of_query(opts).is_err() {
            return Some(0);
        }
        let faces = {
            let Some(guard) = self.live() else {
                return Some(0);
            };
            if opts.allowed_destination.allows_remote() {
                guard.0.up_faces()
            } else {
                Vec::new()
            }
        };
        let mut issued = 0;
        for face in faces {
            let leg_id = self.next_local_id();
            let Some(mut guard) = self.live() else {
                return Some(issued);
            };
            let core = &mut guard.0;
            let Some(actions) = core.up_actions(face).cloned() else {
                continue;
            };
            // A request id the face's actions allocate, so its peer's answer names it.
            let rid = actions.alloc_next_request_id();
            let timeout_ms = opts.effective_timeout_ms();
            // Rounded up, so a get whose deadline the sweep reads in whole milliseconds never
            // ends before its timeout.
            let deadline_ms = (timeout_ms > 0)
                .then(|| core.clock.now_us().div_ceil(1000) + u64::from(timeout_ms));
            let sink = ConsolidatingSink::new(
                opts.resolved_consolidation(),
                get::reply_sink(leg_id, &self.gets),
            );
            // One Final: the face's peer's. Registered before the request goes out, so no answer
            // can arrive before its entry.
            let registered = core
                .registry
                .borrow_mut()
                .face_mut(face)
                .map(|tables| {
                    tables.gets.replies.register_sink(
                        rid,
                        1,
                        deadline_ms,
                        ReplyAcceptance::for_query(keyexpr, opts.effective_accept_replies()),
                        sink,
                    )
                })
                .is_some_and(|registered| registered.is_ok());
            if !registered {
                continue;
            }
            self.hold_leg(leg_id, leg());
            // The link names the key as its own key-wire form says.
            let wire = on_link(&actions, keyexpr, wire);
            let (mapping_id, suffix) = if wire.is_literal() {
                (0, Some(keyexpr))
            } else {
                (wire.mapping_id, wire.suffix.as_deref())
            };
            if actions
                .send_request_query_with_meta(rid, mapping_id, suffix, &opts.query_metadata())
                .is_err()
            {
                // Nothing went out: the entry and the leg go, and the leg is over.
                if let Some(tables) = core.registry.borrow_mut().face_mut(face) {
                    tables.gets.replies.unregister(rid);
                }
                drop(guard);
                drop(self.take_target(TargetKey::Reply(leg_id)));
                continue;
            }
            core.pending_gets.push(PendingGet {
                face,
                leg: leg_id,
                kind: GetKind::Query(rid),
            });
            drop(guard);
            issued += 1;
            // A fan cancelled while the legs are issued stops the issuing.
            if !self.cancelling(fan, leg_id) {
                return Some(issued);
            }
        }
        // And one leg for each group the session asks queries of
        // (`GroupDeclarations::asks_queries`), owed a Final by each member it holds when the get
        // is asked: the shared count (`QueryOptions::remote_finals`) over the members the
        // group's JOINs admitted, as the tokio engine's group counts them. A member that leaves
        // before its Final is not taken off the count, there as here: the leg ends at its
        // deadline.
        #[cfg(feature = "group")]
        let groups: Vec<FaceId> = match self.live() {
            Some(guard) if opts.allowed_destination.allows_remote() => guard
                .0
                .groups
                .iter()
                .filter(|group| group.declarations().asks_queries())
                .map(GroupFace::id)
                .collect(),
            _ => Vec::new(),
        };
        #[cfg(feature = "group")]
        for face in groups {
            let leg_id = self.next_local_id();
            let Some(mut guard) = self.live() else {
                return Some(issued);
            };
            let core = &mut guard.0;
            let Some(group) = core.groups.iter().find(|group| group.id() == face) else {
                continue;
            };
            let finals = opts.remote_finals(group.member_count());
            // A group that holds no member reaches nobody, as zenoh-pico's get with no peer does.
            if finals == 0 {
                continue;
            }
            // A request id the group allocates, so a member's answer names it on this face.
            let rid = group.alloc_request_id();
            let timeout_ms = opts.effective_timeout_ms();
            let deadline_ms = (timeout_ms > 0)
                .then(|| core.clock.now_us().div_ceil(1000) + u64::from(timeout_ms));
            let sink = ConsolidatingSink::new(
                opts.resolved_consolidation(),
                get::reply_sink(leg_id, &self.gets),
            );
            // Registered before the query is queued, as a link's leg is before it is sent.
            let registered = core
                .registry
                .borrow_mut()
                .face_mut(face)
                .map(|tables| {
                    tables.gets.replies.register_sink(
                        rid,
                        finals,
                        deadline_ms,
                        ReplyAcceptance::for_query(keyexpr, opts.effective_accept_replies()),
                        sink,
                    )
                })
                .is_some_and(|registered| registered.is_ok());
            if !registered {
                continue;
            }
            self.hold_leg(leg_id, leg());
            if !group.ask(rid, keyexpr, wire, &opts.query_metadata()) {
                // Nothing was queued: the entry and the leg go, and the leg is over.
                if let Some(tables) = core.registry.borrow_mut().face_mut(face) {
                    tables.gets.replies.unregister(rid);
                }
                drop(guard);
                drop(self.take_target(TargetKey::Reply(leg_id)));
                continue;
            }
            core.pending_gets.push(PendingGet {
                face,
                leg: leg_id,
                kind: GetKind::Query(rid),
            });
            drop(guard);
            issued += 1;
            if !self.cancelling(fan, leg_id) {
                return Some(issued);
            }
        }
        #[cfg(feature = "local-queryable")]
        if opts.allowed_destination.allows_local() {
            let leg_id = self.next_local_id();
            let Some(mut guard) = self.live() else {
                return Some(issued);
            };
            let core = &mut guard.0;
            // The session's own request ids are a space of their own: the leg is registered in
            // the session's own pending gets (`Registry::local`) and answered under the local
            // generation (`query::LOCAL_QUERY`), so no table a link's ids reach holds it, and
            // the two counters never meet.
            let rid = core.next_local_request;
            core.next_local_request = rid.wrapping_add(1);
            let timeout_ms = opts.effective_timeout_ms();
            let deadline_ms = (timeout_ms > 0)
                .then(|| core.clock.now_us().div_ceil(1000) + u64::from(timeout_ms));
            let sink = ConsolidatingSink::new(
                opts.resolved_consolidation(),
                get::reply_sink(leg_id, &self.gets),
            );
            let registered = core.registry.borrow_mut().local.replies.register_sink(
                rid,
                1,
                deadline_ms,
                ReplyAcceptance::for_query(keyexpr, opts.effective_accept_replies()),
                sink,
            );
            if registered.is_ok() {
                self.hold_leg(leg_id, leg());
                core.pending_gets.push(PendingGet {
                    face: LOCAL_FACE,
                    leg: leg_id,
                    kind: GetKind::Query(rid),
                });
                // Asked once the legs to the peers were, as zenoh-pico asks it only once the send
                // succeeded.
                self.ask_own_queryables(core, rid, keyexpr, opts);
                drop(guard);
                issued += 1;
                let _ = self.cancelling(fan, leg_id);
                // What the session's own queryables were handed runs inside the get, outside the
                // lock, as zenoh-pico's `_z_session_deliver_query_locally` does on the caller's
                // thread.
                self.deliver();
            }
        }
        Some(issued)
    }

    #[cfg(feature = "liveliness-get")]
    fn liveliness_get_on_wire(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        timeout_ms: u32,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Option<usize> {
        // One leg for each face whose link is up; a session with no link up reaches nobody, and
        // the snapshot is over at once.
        let faces = {
            let Some(guard) = self.live() else {
                return Some(0);
            };
            guard.0.up_faces()
        };
        // `0` is the platform default and never no deadline, as pico's `z_liveliness_get`
        // rewrites it (`vendor/zenoh-pico/src/api/liveliness.c` @
        // `if (opt.timeout_ms == 0) {`); rounded up as a query's deadline is.
        let timeout_ms = match timeout_ms {
            0 => DEFAULT_QUERY_TIMEOUT_MS,
            set => set,
        };
        let mut issued = 0;
        for face in faces {
            let leg_id = self.next_local_id();
            let Some(mut guard) = self.live() else {
                return Some(issued);
            };
            let core = &mut guard.0;
            let Some(actions) = core.up_actions(face).cloned() else {
                continue;
            };
            // A face whose session has no interest id left is not asked, as one that could not
            // hold the entry.
            let Some(interest_id) = actions.alloc_next_interest_id() else {
                continue;
            };
            let interest_id = u64::from(interest_id);
            let deadline_ms = Some(core.clock.now_us().div_ceil(1000) + u64::from(timeout_ms));
            // One DeclFinal: the face's peer's. Registered before the Interest goes out, so no
            // answer can arrive before its entry.
            let registered = core
                .registry
                .borrow_mut()
                .face_mut(face)
                .map(|tables| {
                    tables.gets.liveliness_gets.register(
                        interest_id,
                        deadline_ms,
                        get::reply_sink(leg_id, &self.gets),
                    )
                })
                .is_some_and(|registered| matches!(registered, Ok(true)));
            if !registered {
                continue;
            }
            self.hold_leg(leg_id, leg());
            // The Interest names the key as the link's own key-wire form says, as a query does.
            let wire = on_link(&actions, keyexpr, wire);
            let (mapping_id, suffix) = if wire.is_literal() {
                (0, Some(keyexpr))
            } else {
                (wire.mapping_id, wire.suffix.as_deref())
            };
            if actions
                .send_interest_liveliness_get(interest_id, mapping_id, suffix)
                .is_err()
            {
                // Nothing went out: the entry and the leg go, and the leg is over.
                if let Some(tables) = core.registry.borrow_mut().face_mut(face) {
                    tables.gets.liveliness_gets.unregister(interest_id);
                }
                drop(guard);
                drop(self.take_target(TargetKey::Reply(leg_id)));
                continue;
            }
            core.pending_gets.push(PendingGet {
                face,
                leg: leg_id,
                kind: GetKind::Liveliness(interest_id),
            });
            drop(guard);
            issued += 1;
            // A fan cancelled while the legs are issued stops the issuing.
            if !self.cancelling(fan, leg_id) {
                return Some(issued);
            }
        }
        Some(issued)
    }

    #[cfg(feature = "queryable")]
    fn undeclare_queryable(&self, id: QblId) {
        let entry = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let at = core.queryables.iter().position(|q| q.id == id)?;
            let links = core.retract(Kind::Queryable, at);
            let entry = core.queryables.remove(at);
            #[cfg(feature = "group")]
            core.retract_from_groups(id);
            core.registry
                .borrow_mut()
                .app
                .queryables
                .unregister(entry.registration);
            for actions in links {
                entry.retract(&actions);
            }
            // One that counted it may now match no more.
            #[cfg(feature = "local-queryable")]
            Self::reevaluate_queryable_matching(core);
            Some(entry)
        });
        let callback = self.take_target(TargetKey::Queryable(id));
        drop((entry, callback));
        #[cfg(feature = "local-queryable")]
        self.deliver();
    }

    #[cfg(feature = "liveliness")]
    fn declare_liveliness_token_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        retraction: Option<RetractionKey>,
    ) -> Option<TokenId> {
        // zenoh-pico's token takes the session's next entity id
        // (`vendor/zenoh-pico/src/net/liveliness.c` @ `uint32_t id = _z_get_entity_id(_Z_RC_IN_VAL(zn));`).
        let id = self.next_entity_id()?;
        let mut core = self.live()?;
        let core = &mut core.0;
        core.registry
            .borrow_mut()
            .app
            .local_tokens
            .register(u64::from(id), &keyexpr)
            .ok()?;
        let entry = TokenEntry {
            id,
            keyexpr,
            wire,
            retraction,
        };
        core.announce(Kind::Token, |actions| entry.declare(actions));
        // A token takes no traffic of its own, so every group that is told tokens is told it. It is
        // held before it is announced (the registration above, in the tables a group's
        // dispatch answers a member's Interest from), so a member that asks right after it
        // hears the announcement finds it held: the tokio engine's group holds it the same way.
        #[cfg(feature = "group")]
        core.announce_to_groups(GroupEntity {
            what: GroupDeclaration::Token,
            entity: id,
            keyexpr: &entry.keyexpr,
            wire: &entry.wire,
            retraction: entry.retraction.as_ref(),
            allowed_origin: Locality::Any,
        });
        core.tokens.push(entry);
        Some(id)
    }

    #[cfg(feature = "liveliness")]
    fn undeclare_liveliness_token(&self, id: TokenId) {
        let entry = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let at = core.tokens.iter().position(|t| t.id == id)?;
            let links = core.retract(Kind::Token, at);
            let entry = core.tokens.remove(at);
            #[cfg(feature = "group")]
            core.retract_from_groups(id);
            core.registry
                .borrow_mut()
                .app
                .local_tokens
                .unregister(u64::from(id));
            for actions in links {
                entry.retract(&actions);
            }
            Some(entry)
        });
        // Its key may hold a declaration whose release reaches the session: after the lock.
        drop(entry);
    }

    #[cfg(feature = "liveliness")]
    fn declare_liveliness_subscriber_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        history: bool,
        sink: LivelinessSink,
    ) -> Option<SubId> {
        let id = self.next_entity_id()?;
        let Some(mut guard) = self.live() else {
            return Some(id);
        };
        let core = &mut guard.0;
        lock(&self.targets).push((
            TargetKey::Liveliness(id),
            Target::Liveliness(Arc::new(Mutex::new(sink()))),
        ));
        // With `history`, the registration hands the sink the tokens the session already knows,
        // before the peer answers with the rest, as zenoh-pico's does
        // (`vendor/zenoh-pico/src/net/liveliness.c` @ `_z_liveliness_subscription_trigger_history`).
        let registered = core.registry.borrow_mut().register_liveliness_subscriber(
            u64::from(id),
            &keyexpr,
            history,
            liveliness::sample_sink(id, &self.live_samples),
        );
        if registered.is_err() {
            drop(guard);
            drop(self.take_target(TargetKey::Liveliness(id)));
            return Some(id);
        }
        let entry = LiveSubEntry {
            id,
            keyexpr,
            wire,
            history,
        };
        core.announce(Kind::LiveSub, |actions| entry.ask(actions));
        // And each group the session joined is asked, as its declarations say.
        #[cfg(feature = "group")]
        for group in &core.groups {
            group.ask_liveliness(id, &entry.keyexpr, &entry.wire, entry.history);
        }
        core.live_subs.push(entry);
        drop(guard);
        self.deliver();
        Some(id)
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> SessionDrive
    for CoopEngine<L, C>
{
    fn engine(&self) -> Arc<dyn SessionEngine> {
        self.this
            .upgrade()
            .expect("a live engine is held by an Arc")
    }

    fn engine_ref(&self) -> &dyn SessionEngine {
        self
    }

    fn close(&self) {
        // The read task stops first, so the close is the last thing the session does. A close
        // from the read task itself stops nothing and leaves the thread to see the session
        // closed.
        let _ = self.stop_reader();
        let mut guard = lock(&self.core);
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let core = &mut guard.0;
        core.end_links();
        let subscribers: Vec<TargetKey> = core
            .subscribers
            .drain(..)
            .map(|s| TargetKey::Subscriber(s.id))
            .collect();
        let matches: Vec<TargetKey> = core
            .matches
            .drain(..)
            .map(|m| TargetKey::Matching(m.id))
            .collect();
        #[cfg(feature = "queryable")]
        let queryables: Vec<TargetKey> = core
            .queryables
            .drain(..)
            .map(|q| TargetKey::Queryable(q.id))
            .collect();
        #[cfg(not(feature = "queryable"))]
        let queryables: Vec<TargetKey> = Vec::new();
        // A get still pending ends with its session: its entry and its leg's callback go.
        #[cfg(feature = "query")]
        let gets: Vec<TargetKey> = {
            let mut registry = core.registry.borrow_mut();
            core.pending_gets
                .drain(..)
                .map(|pending| {
                    pending.unregister(&mut registry);
                    TargetKey::Reply(pending.leg)
                })
                .collect()
        };
        #[cfg(not(feature = "query"))]
        let gets: Vec<TargetKey> = Vec::new();
        // The session's tokens end with its link; its liveliness subscribers' callbacks go.
        #[cfg(feature = "liveliness")]
        let live_subs: Vec<TargetKey> = {
            core.tokens.clear();
            core.live_subs
                .drain(..)
                .map(|s| TargetKey::Liveliness(s.id))
                .collect()
        };
        #[cfg(not(feature = "liveliness"))]
        let live_subs: Vec<TargetKey> = Vec::new();
        drop(guard);
        #[cfg(feature = "liveliness")]
        drop(core::mem::take(&mut *lock(&self.live_samples)));
        #[cfg(feature = "query")]
        drop(core::mem::take(&mut *lock(&self.gets.events)));
        // The queries no callback will now answer, and the callbacks' C contexts, are dropped
        // with no lock held.
        #[cfg(feature = "queryable")]
        drop(core::mem::take(&mut *lock(&self.plane.queries)));
        let taken: Vec<_> = subscribers
            .into_iter()
            .chain(matches)
            .chain(queryables)
            .chain(gets)
            .chain(live_subs)
            .filter_map(|id| self.take_target(id))
            .collect();
        drop(taken);
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn start_read_task(&self) -> Result<(), CalledFromReadTask> {
        let mut reader = lock(&self.reader);
        if let Some(task) = reader.as_ref() {
            if task.id == os::current() {
                return Err(CalledFromReadTask);
            }
            return Ok(());
        }
        let Some(engine) = self.this.upgrade() else {
            return Ok(());
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let Some((thread, id)) =
            os::spawn(
                move || {
                    while !stopped.load(Ordering::Acquire) && engine.read(false).is_ok() {}
                },
            )
        else {
            // What `std::thread::spawn` did when the system gave no thread, kept as it was: the
            // ABI's guard answers the C call with an error. The port's start has no answer for
            // "no thread" yet (zenoh-pico's `_Z_ERR_SYSTEM_TASK_FAILED`), which is where this
            // belongs.
            panic!("the system gave no thread for the read task");
        };
        *reader = Some(ReadTask { stop, thread, id });
        Ok(())
    }

    fn stop_read_task(&self) -> Result<(), CalledFromReadTask> {
        self.stop_reader()
    }

    fn read_task_is_running(&self) -> bool {
        lock(&self.reader)
            .as_ref()
            .is_some_and(|task| !task.thread.is_finished())
    }

    fn read(&self, _single: bool) -> Result<(), SessionClosed> {
        // The wait comes first and holds nothing of the session, so what arrives during it is
        // read by this call and a publisher on another thread is not held up by it.
        let wait = self
            .live()
            .map_or(IdleWait::None, |core| core.0.idle_wait());
        wait.wait();
        // One pass of the session's task reads what its link holds, a batch at a time, and does
        // what is due: `single` asks for one message, and a pass is the least this engine reads.
        let stepped = match self.live() {
            Some(mut core) => self.step(&mut core.0),
            None => false,
        };
        self.deliver();
        #[cfg(feature = "ticker")]
        self.run_due_tickers();
        if stepped {
            Ok(())
        } else {
            Err(SessionClosed)
        }
    }

    fn send_keep_alive(&self) -> Result<(), SessionClosed> {
        let core = self.live().ok_or(SessionClosed)?;
        // A link that is down has no lease to keep; the session is not closed.
        for actions in core.0.ups() {
            actions.send_keep_alive();
        }
        Ok(())
    }

    fn spin_once(&self) -> bool {
        self.read(false).is_ok()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
    /// This session as the C handle's drive. Made HERE (out of line), so the session's drop glue
    /// is this crate's and not a second copy in the ABI crate that holds the handle, as the tokio
    /// engine's `SessionState::into_drive` is.
    #[inline(never)]
    pub fn into_drive(self: Arc<Self>) -> Box<dyn SessionDrive> {
        Box::new(Drive(self))
    }
}

/// The C handle's hold on an engine: the engine is shared with the entities declared on it and
/// with its read task, so the handle holds it as one of its `Arc`s.
struct Drive<L: SessionLinks + 'static, C: ClockSource + Clone + 'static>(Arc<CoopEngine<L, C>>);

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> SessionDrive for Drive<L, C> {
    fn engine(&self) -> Arc<dyn SessionEngine> {
        self.0.clone()
    }

    fn engine_ref(&self) -> &dyn SessionEngine {
        &*self.0
    }

    fn close(&self) {
        SessionDrive::close(&*self.0)
    }

    fn is_closed(&self) -> bool {
        SessionDrive::is_closed(&*self.0)
    }

    fn start_read_task(&self) -> Result<(), CalledFromReadTask> {
        self.0.start_read_task()
    }

    fn stop_read_task(&self) -> Result<(), CalledFromReadTask> {
        self.0.stop_read_task()
    }

    fn read_task_is_running(&self) -> bool {
        self.0.read_task_is_running()
    }

    fn read(&self, single: bool) -> Result<(), SessionClosed> {
        self.0.read(single)
    }

    fn send_keep_alive(&self) -> Result<(), SessionClosed> {
        self.0.send_keep_alive()
    }

    fn spin_once(&self) -> bool {
        self.0.spin_once()
    }

    fn as_any(&self) -> &dyn Any {
        &*self.0
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> Drop for Drive<L, C> {
    /// The C program let go of its session (zenoh-pico's `z_session_drop`), which closes it: the
    /// read task, which holds the engine too, is stopped and joined, and an entity declared on the
    /// session that outlives it finds it closed.
    fn drop(&mut self) {
        SessionDrive::close(&*self.0);
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> Drop for CoopEngine<L, C> {
    fn drop(&mut self) {
        // The last handle is gone, so no read task holds one: it has stopped, or is about to
        // drop the handle it held. A session never closed is closed now; a closed one has no
        // link left to end.
        self.core.get_mut().0.end_links();
    }
}

#[cfg(all(test, feature = "std", feature = "time-base"))]
mod clock_moves_tests {
    use super::*;
    use std::sync::{Condvar, Mutex as StdMutex};
    use std::time::{Duration, Instant};

    /// A clock the test moves: a count of its moves and the word that it grew.
    struct Moves {
        count: StdMutex<u64>,
        moved: Condvar,
    }

    /// A wait that ends once the count passes the one it was made at.
    struct Since {
        moves: Arc<Moves>,
        seen: u64,
    }

    impl LinkReadiness for Since {
        fn wait_readable(&self, timeout_ms: u32) {
            let count = self.moves.count.lock().unwrap();
            let bound = Duration::from_millis(timeout_ms.into());
            let moved = &self.moves.moved;
            let _ = moved.wait_timeout_while(count, bound, |count| *count == self.seen);
        }
    }

    struct Word(Arc<Moves>);

    impl ClockMoves for Word {
        fn moved(&self) -> Arc<dyn LinkReadiness> {
            let seen = *self.0.count.lock().unwrap();
            Arc::new(Since {
                moves: self.0.clone(),
                seen,
            })
        }
    }

    fn word() -> (Arc<Moves>, Arc<dyn ClockMoves>) {
        let moves = Arc::new(Moves {
            count: StdMutex::new(0),
            moved: Condvar::new(),
        });
        let word: Arc<dyn ClockMoves> = Arc::new(Word(moves.clone()));
        (moves, word)
    }

    /// A read waiting five seconds for its next dial is let go by the program's word that the
    /// clock moved on, long before its bound of the wall clock.
    #[test]
    fn a_wait_for_the_next_dial_ends_at_the_word_that_the_clock_moved() {
        let (moves, word) = word();
        let wait = ended_by_clock_moves(IdleWait::Sleep(5_000), Some(&word));
        let waiting = std::thread::spawn(move || {
            let started = Instant::now();
            wait.wait();
            started.elapsed()
        });
        std::thread::sleep(Duration::from_millis(100));
        *moves.count.lock().unwrap() += 1;
        moves.moved.notify_all();
        let took = waiting.join().expect("the waiting thread");
        assert!(
            took < Duration::from_millis(2_500),
            "the read waited out its bound instead of the word ({took:?})"
        );
    }

    /// A wait on links waits on the word beside them; no wait stays none; and a clock that moves
    /// by itself leaves every wait as it was.
    #[test]
    fn the_word_joins_a_wait_and_makes_none_where_there_was_none() {
        let (_moves, word) = word();
        match ended_by_clock_moves(IdleWait::Input(Vec::new(), 9), Some(&word)) {
            IdleWait::Input(waits, 9) => assert_eq!(waits.len(), 1),
            _ => panic!("a wait on links keeps its bound and gains the word"),
        }
        assert!(matches!(
            ended_by_clock_moves(IdleWait::None, Some(&word)),
            IdleWait::None
        ));
        assert!(matches!(
            ended_by_clock_moves(IdleWait::Sleep(7), None),
            IdleWait::Sleep(7)
        ));
    }
}
