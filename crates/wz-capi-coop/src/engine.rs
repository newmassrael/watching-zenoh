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
//! sample for a subscriber, a change of a matching status) is queued as an owned value, or owed
//! in its row, and handed out after the lock is released, so a callback may call back into its
//! session: publish, declare, undeclare itself. zenoh-pico does the same, copying what it delivers
//! out of its session mutex before it calls (`vendor/zenoh-pico/src/session/subscription.c` @
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

use alloc::rc::Rc;
use alloc::sync::{Arc, Weak};
use core::any::Any;
use core::cell::RefCell;
use core::num::NonZeroU32;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};
// A 64-bit atomic where the target has one, and a critical section where it does not (a
// Cortex-M7 has 32-bit atomics only).
use portable_atomic::AtomicU64;

#[allow(unused_imports)]
use crate::prelude::*;

#[cfg(feature = "advanced-cache")]
use crate::arena::CacheSpan;
#[cfg(any(feature = "listen", feature = "group"))]
use crate::arena::HandedTable;
use crate::arena::{
    AllocatorMemory, ArenaMemory, ArenaPlan, ArenaRefused, ClaimedPlaces, DroppedOn, EntityKind,
    EntityPlace, EntityPlaces, HandlePlace, HeldPlaces, LinkCells, OpenStorage, PlaceTables,
    SessionArena, SessionRows, TransportTables,
};
use crate::round::{Round, RoundCounts, RoundGate, RoundRows};
use wz_session_core::bounded::{KeyBacking, KeyMaker, KeyUnkept, Lent, TableLender};
use wz_session_core::caps;
#[cfg(feature = "liveliness")]
use wz_session_core::key_arena::KeyRef;
use wz_session_core::key_arena::{KeySpace, LentKeys};
#[cfg(feature = "query")]
use wz_session_core::reply_hold::HeldReplies;
use wz_session_core::row_callback::{CallLatch, RowCallback};
#[cfg(feature = "local-queryable")]
use wz_session_core::session_state::LocalRequests;
use wz_session_core::session_state::{MatchingRead, SessionParts};
use wz_session_core::session_tables::{
    kind, DeclaredRow, DeclaredTable, InterestHandle, InterestKind, InterestName, InterestRow,
    KeyexprHandle, MatchingListenerHandle, Plane, Refused, Retraction, RowCallbacks, SessionTables,
    SubscriberHandle, Watching, WriteFilterHandle,
};
use wz_session_core::slot_map::Handle;
use wz_session_core::slot_observer::ObserverRows;

// The operating system the engine runs on: its mutex, its threads and its sleep are `std`'s on a
// host and the kernel's on an MCU (`docs/upstream-parity.md` section 5a, E1).
#[cfg(feature = "listen")]
use crate::admission_gate::AdmissionGate;
use wz_capi_port::os::{self, JoinHandle, Mutex, MutexGuard, ThreadId};
use wz_capi_port::{
    BatchStep, CalledFromReadTask, FanoutError, FilterId, FilterPlane, FilteredPut, HeldKey,
    KeyAsk, KeyNotHeld, MatchId, MatchingSink, PeerIdentity, PlaceLender, ReadTaskStartRefused,
    SessionClosed, SessionDrive, SessionEngine, SessionKeys, StatementNotHonoured, SubId,
    SubscriberSink, WireHolds, WireKey,
};
// The port's refusal of a declaration, named apart from this crate's refusal of an endpoint.
use wz_capi_port::Refusal as Declined;
#[cfg(feature = "ticker")]
use wz_capi_port::{Tick, TickerId};
use wz_runtime_coop::executor::SpawnRefusal;
use wz_runtime_coop::face_life::{FaceEffect, Next};
use wz_runtime_coop::face_send::{self, Behind, FaceSend, Pass, PublishRun, Then, FIRST_FACE};
#[cfg(feature = "listen")]
use wz_runtime_coop::face_send::{after_probe, AfterProbe, ProbeAnswer};
#[cfg(any(feature = "listen", feature = "group"))]
use wz_runtime_coop::face_send::{DropSet, HandedLimits};
#[cfg(feature = "listen")]
use wz_runtime_coop::faces::OwingWaits;
use wz_runtime_coop::faces::{
    DialEndpoint, EndpointTexts, FaceRecord, FaceSession, IdleWait, Link, LinkSupervisor,
};
use wz_runtime_coop::link_cells::CellRc;
use wz_runtime_coop::reassembly_rx::{
    session_reassembly, SessionChains, SessionReassembly, LENT_CHAINS,
};
#[cfg(feature = "time-base")]
use wz_runtime_coop::session_drive::LinkWait;
#[cfg(feature = "time-base")]
use wz_runtime_coop::session_drive::StackWake;
use wz_runtime_coop::session_drive::{
    router_session_task_bytes, OpenedLink, SessionDatagramLink, SessionLinks, SessionRole,
};
use wz_runtime_coop::session_drive::{LinkOpenError, LinkWaits, WaitOn};
use wz_runtime_coop::session_runtime::{SessionEntropy, SessionHandle};
use wz_runtime_coop::transport::{
    DialWalk, FaceStep, LinkCalls, TransportFaces, TransportRefusal, TransportSession, WireMaking,
};
pub use wz_runtime_coop::transport::{EndpointRefusal, Refusal};
use wz_runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeRows};
#[cfg(any(test, feature = "advanced-cache"))]
use wz_session_core::byte_cells::LentByteCells;
use wz_session_core::close_reason::CloseReason;
use wz_session_core::declare_form::{InterestAsk, InterestForm, RetractionKey};
use wz_session_core::driver_loop::{EventSink, IterationEvent};
use wz_session_core::entropy::EntropySource;
use wz_session_core::interest_build::InterestKinds;
use wz_session_core::lent_push;
use wz_session_core::limits::{MaxKeyexprBytesHeld, SessionLimits};
#[cfg(feature = "listen")]
use wz_session_core::link_admission::LinkRegistry;
use wz_session_core::locality::Locality;

use crate::open_source::{Counted, EndpointList, EndpointWriter, OpenSource};
use wz_runtime_coop::locator_text::parse_listen_locator;
use wz_session_core::metadata::PushMetadata;
use wz_session_core::named_key::NamedKey;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::policy::KeyWireForm;
use wz_session_core::policy::{SessionPolicy, SnResolution};
use wz_session_core::publish_options::{PlainPutParams, PublishError, PublishOptions};
use wz_session_core::push_build;
use wz_session_core::sample::{QosLevel, SampleKind};
use wz_session_core::send_wire_error::SendWireError;
#[cfg(feature = "listen")]
use wz_session_core::session_actions::Probed;
use wz_session_core::session_actions::{LinkState, SessionCore};
use wz_session_core::session_init_params::{
    HeldDrop, KeepAliveConf, LinkRxConf, SessionInitParams, SessionZid, TxQueueConf, ZidError,
};
use wz_session_core::session_timeouts::SessionTimeouts;
#[cfg(feature = "shared-key-ids")]
use wz_session_core::shared_key_ids::{KeyIdsAtOpen, KeyIdsRefused, LinkKeyForms, SharedKeyIds};
use wz_session_core::signing_key::SigningKey;
use wz_session_core::sink::{FanOut, RowAccess, SampleDelivery, SampleView};
use wz_session_core::timestamp_visibility::{exposed_by, HiddenTimestamp};
use wz_session_core::unicast_rx::RouterLend;
use wz_session_core::wire_id::{EntityId, ExprId};
use wz_session_core::WhatAmI;
use wz_session_mcu::dial::McuActions;
#[cfg(feature = "queryable")]
use {
    query::{CoopHolder, Onward, QueryPlane, QueryableRow},
    wz_capi_port::{QblId, QueryableSink},
    wz_session_core::query::QueryResponder,
    wz_session_core::query_sink::ReplyError,
    wz_session_core::query_sink::{ProvenQuery, QueryView},
    wz_session_core::reply_stage::ReplyParts,
    wz_session_core::session_tables::QueryableHandle,
};

#[cfg(feature = "local-queryable")]
use wz_session_core::reply_stage::ReplyStage;

#[cfg(feature = "queryable")]
mod query;
#[cfg(feature = "queryable")]
pub(crate) use query::{FinalHold, QueryableCall, RefusedFinal};

#[cfg(feature = "group")]
mod group;
#[cfg(feature = "group")]
use {
    group::{GroupEntity, GroupFace, GroupJoining, GroupPut},
    wz_capi_port::group::GroupJoin,
    wz_session_core::declare_form::GroupDeclaration,
};

mod deliveries;
use deliveries::Deliveries;

mod registry;
#[cfg(feature = "local-queryable")]
use registry::LOCAL_FACE;
use registry::{FaceId, HeldFace, Registry, DIAL_FACE};
pub(crate) use registry::{FACE_SET_BYTES, HELD_SET_BYTES};

mod replay;
use replay::{Replay, TurnEnd};

#[cfg(feature = "listen")]
mod faces_added;

mod transport;
#[cfg(feature = "group")]
use transport::TellGroups;
use transport::TransportState;

#[cfg(feature = "ticker")]
mod ticker;
#[cfg(feature = "ticker")]
use ticker::Tickers;
use wz_session_core::replay_pacing::ReplayPacing;

#[cfg(any(
    feature = "remote-declaration-watch",
    feature = "declarations-synced-event"
))]
mod decl_watch;
#[cfg(any(
    feature = "remote-declaration-watch",
    feature = "declarations-synced-event"
))]
pub(crate) use decl_watch::WatchCall;
#[cfg(any(
    feature = "remote-declaration-watch",
    feature = "declarations-synced-event"
))]
use {
    decl_watch::DeclWatches,
    wz_capi_port::{DeclPlane, DeclWatchId, DeclWatchSink},
};

/// The watchers of the session's faces and the events queued for them, under the port's mutex
/// (`connectivity`).
#[cfg(feature = "connectivity")]
type FacePlane = wz_session_core::face_plane::FacePlane<CoopLocks>;

/// The rows a session's queue of face events holds between two deliveries, reserved at its open:
/// the build's [`caps::MAX_FACE_WATCH_ROWS`], or fewer for a session whose faces turn over in
/// fewer, each face the config admits beside the dial role's and each member each of its groups
/// holds going and coming back once. A coop face has one link, so one row each way.
#[cfg(feature = "connectivity")]
pub(crate) fn face_event_rows(max_faces: usize, groups: usize) -> usize {
    let members = groups.saturating_mul(caps::MAX_GROUP_MEMBERS);
    let faces = max_faces.saturating_add(1).saturating_add(members);
    faces.saturating_mul(2).min(caps::MAX_FACE_WATCH_ROWS)
}
#[cfg(feature = "connectivity")]
mod told;
use wz_session_core::face::{FaceEventKind, FaceLinkRow};
#[cfg(feature = "connectivity")]
use wz_session_core::face::{FaceEventSink, FaceRowSink, FaceSnapshot};
#[cfg(feature = "local-queryable")]
use wz_session_core::query::QueryEnvelope;
#[cfg(feature = "connectivity")]
use {
    told::FaceTold,
    wz_capi_port::told::{ToldKey, ToldPlane},
};

#[cfg(feature = "liveliness-get")]
use wz_session_core::query_options::DEFAULT_QUERY_TIMEOUT_MS;

#[cfg(feature = "liveliness")]
mod liveliness;
#[cfg(feature = "liveliness")]
pub(crate) use liveliness::{LivelinessCall, LivelinessRow};
#[cfg(feature = "liveliness")]
use {
    liveliness::retract_token,
    registry::HistoryCursor,
    wz_capi_port::{LivelinessSink, TokenId},
    wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleKind},
    wz_session_core::session_tables::LivelinessSubscriberHandle,
};

#[cfg(feature = "query")]
mod get;
/// What a face's table of pending gets holds for each leg ([`get::LegSink`]). A build that asks no
/// query keeps no such table (`registry::Gets`), so it names no leg.
#[cfg(feature = "query")]
pub(crate) use get::{Ended, LegHold, LegId, LegRow, LegSink, PendingGet};
#[cfg(feature = "query")]
use {
    crate::round::LegHolders,
    get::{EndedLegs, GetKind, GetPlane, LegRows},
    wz_capi_port::cancellation::{CancellableFan, FanCanceller, FanKey},
    wz_capi_port::ReplyCallback,
    wz_session_core::query_options::QueryOptionsOf,
    wz_session_core::registry_error::RegisterError,
    wz_session_core::reply_acceptance::ReplyAcceptance,
    wz_session_core::reply_sink::{timeout_reply, ConsolidatingSink},
};

/// How a session is opened: what the ABI's config says, which the engine turns into the
/// session's parameters. Its lists of endpoints (`E`) hold their texts in the host's form, or only
/// how many there are in a source's ([`crate::open_source::Counted`]), which writes the texts into
/// the session's rows itself ([`crate::open_source::OpenSource`]).
pub struct CoopConfig<E = Vec<String>> {
    /// The endpoints to dial (`tcp/a.b.c.d:port` or `udp/a.b.c.d:port`), in order: the session
    /// is opened to the first that answers, as zenoh-pico's client opens to the first of its
    /// `connect` locators that does. At most the build's `MAX_STATIC_CONNECT`, each at most
    /// `MAX_LOCATOR_LEN` bytes: the open writes each into a row of the session's arena and keeps
    /// no copy of the list.
    pub endpoints: E,
    /// The role the session announces.
    pub whatami: WhatAmI,
    /// The session's zid as the config states it, which the session announces up to its last
    /// non-zero byte, as zenoh writes an id; `None` has the open make one as the session's
    /// policy says.
    pub zid: Option<SessionZid>,
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
    /// (`SessionDatagramLink::input_wait`); a link whose stack does not waits in its own loop.
    pub idle_wait_ms: u32,
    /// The endpoints to listen on (`tcp/a.b.c.d:port` or `udp/a.b.c.d:port`; port 0 has the stack
    /// choose one, read back with `CoopEngine::listening`), which the session takes inbound links
    /// from for as long as it lives, each as a face of its own. A session that lists none and
    /// dials at least one is the dial role alone; one that lists some and dials none is only a
    /// listener, and is open as soon as it is bound (`listen`). At most the build's
    /// `MAX_ADMIN_LOCATORS`, each at most `MAX_LOCATOR_LEN` bytes, written into rows as the
    /// endpoints are.
    pub listen: E,
    /// How many inbound links may be in their handshake at once; one that arrives past it is
    /// closed unread. At most the session's `MAX_ACCEPT_PENDING` (zenoh's
    /// `transport/unicast/accept_pending`), which [`crate::arena::admitted_handshakes`] gives;
    /// the open of a session that listens refuses more (`listen`). How long a handshake may take
    /// is `timeouts.accepting_inactivity_ms`.
    pub accept_pending: usize,
    /// How many faces the session holds besides the dial role's, one still in its handshake among
    /// them; an inbound link that arrives past it is closed unread. At most the session's
    /// `MAX_FACES` (zenoh's `transport/unicast/max_sessions`), which
    /// [`crate::arena::admitted_faces`] gives; the open refuses more. Each is lent a set of a
    /// face's tables when the session opens (`listen`).
    pub max_faces: usize,
    /// The multicast groups the session joins, each a face of its own beside its links, joined
    /// before anything is dialled: what each advertises and what the session tells it of its
    /// declarations is the ABI's (`wz_capi_port::group`). A session that dials nothing and joins
    /// a group is open once the group is joined (`group`; a build without it refuses a group
    /// with [`OpenError::Group`]).
    pub groups: Vec<wz_capi_port::group::GroupJoin>,
    /// What tells a read that the session's clock moved on, for a clock the program moves (a time
    /// base it supplies): the open has it wake a wake of the links' stack, which a read waits on
    /// beside its links and in place of a sleep to its next dial, so the program's word ends the
    /// wait. `None` for a clock that moves by itself, whose waits the wall bounds. Always `None`
    /// in a build without `time-base`, whose [`ClockMovesWord`] has no value.
    pub clock_moves: Option<ClockMovesWord>,
    /// The session limits the ABI resolved for the session, which its tables are held to:
    /// `SessionLimits::defaults()` for an ABI that states none.
    pub limits: SessionLimits,
}

impl CoopConfig {
    /// The config in a source's form, its lists counted, and the lists, the host's texts.
    pub(crate) fn counted(self) -> (CoopConfig<Counted>, Vec<String>, Vec<String>) {
        let Self {
            endpoints,
            whatami,
            zid,
            batch_size,
            lease_ms,
            keep_alive,
            sn_resolution,
            link_rx,
            tx_queue,
            timeouts,
            open_timeout_ms,
            redial_ms,
            idle_wait_ms,
            listen,
            accept_pending,
            max_faces,
            groups,
            clock_moves,
            limits,
        } = self;
        let config = CoopConfig {
            endpoints: Counted(endpoints.len()),
            whatami,
            zid,
            batch_size,
            lease_ms,
            keep_alive,
            sn_resolution,
            link_rx,
            tx_queue,
            timeouts,
            open_timeout_ms,
            redial_ms,
            idle_wait_ms,
            listen: Counted(listen.len()),
            accept_pending,
            max_faces,
            groups,
            clock_moves,
            limits,
        };
        (config, endpoints, listen)
    }
}

/// The program's word that a clock it moves has moved on, as a read of this engine waits on it
/// ([`CoopConfig::clock_moves`]).
#[cfg(feature = "time-base")]
pub trait ClockMoves: Send + Sync {
    /// Wake `waker` at each word from now on, for as long as this is held; a later watch takes
    /// the place of an earlier one. The open hands it the waker of its stack's wake.
    fn watch(&self, waker: core::task::Waker);
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

/// What a read of a session waits on beside its links for the program's word that the clock
/// moved on (`moves`), and the longest it then waits of `most`: the stack's wake the word wakes
/// (`wake`), for as long as the links' wait; with no wake the stack could make, a look, after
/// which the step reads the clock again. A clock that moves by itself leaves the wait as it was.
#[cfg(feature = "time-base")]
fn clock_beside(
    most: u32,
    moves: Option<&ClockMovesWord>,
    wake: Option<&StackWake>,
) -> (u32, Option<LinkWait>) {
    match (moves, wake) {
        (None, _) => (most, None),
        (Some(_), Some(wake)) => (most, Some(LinkWait::input(wake.on))),
        (Some(_), None) => (most.min(1), None),
    }
}

/// The policies a session [`CoopEngine::open`] opens from `config` runs under: the one place that
/// open decides them. The build defaults: the config is what the ABI read from its own keys and
/// values, not a zenoh document with a `wz` member, and it has no field for a policy yet; the
/// ABI's door for one is a key of its own.
pub(crate) fn resolve_policy<E>(_config: &CoopConfig<E>) -> SessionPolicy {
    SessionPolicy::defaults()
}

/// The session limits a session [`CoopEngine::open`] opens from `config` holds its tables to: the
/// snapshot the ABI resolved and states in the config ([`CoopConfig::limits`]), as it is, read
/// where the config holds it: only a value that owns limits of its own (a link's parameters, a
/// group's) takes a copy.
pub(crate) fn resolve_limits<E>(config: &CoopConfig<E>) -> &SessionLimits {
    &config.limits
}

/// Why no session was opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// The configuration names no endpoint.
    NoEndpoint,
    /// An endpoint to listen on could not be listened on: it does not parse, the network opens no
    /// listener for its protocol, or the port is taken. The endpoint and the reason; a build
    /// without `listen` answers every listen endpoint this way.
    Listen(EndpointRefusal),
    /// A group to join could not be: the network joins no group for its endpoint, or the group's
    /// link did not open. The endpoint and the reason; a build without `group` answers every
    /// group this way.
    Group(EndpointRefusal),
    /// No endpoint could be dialled: each was refused, unreachable or did not complete the
    /// handshake in time. The last endpoint's reason.
    Unreachable(EndpointRefusal),
    /// The platform gave no entropy for the session's zid or its cookie key.
    EntropyUnavailable,
    /// The configured zid is not one: it is not one to sixteen bytes, or its bytes are all zero.
    InvalidZid(ZidError),
    /// The session states no zid and its `zid-derivation` is `address-ports`, and its `listen`
    /// endpoints give the node no address a zid can be built on.
    ZidDerivation(wz_session_core::zid_derivation::ZidDerivationError),
    /// The session's `key-wire-form` cannot be honoured: see [`KeyWireFormRefused`].
    KeyWireForm(KeyWireFormRefused),
    /// The key ids the open was handed are more entries than the session's `MAX_SHARED_KEY_IDS`
    /// admits (`shared-key-ids`).
    KeyIdsOverLimit {
        /// How many entries the dictionary has.
        stated: usize,
        /// How many the session's limit admits.
        limit: usize,
    },
    /// The session's arena could not be reserved (see [`ArenaRefused`]), so nothing was bound,
    /// joined or dialled.
    Arena(ArenaRefused),
    /// The session's runtime had no task for a link's session or a group's: its task cells are
    /// reserved when the session opens, one for each link and group the config admits and in all
    /// at most the build's `MAX_TASKS`, and every one was taken, or none fits the task. Nothing of
    /// the link or the group stays.
    NoTask(SpawnRefusal),
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

impl From<TransportRefusal> for OpenError {
    fn from(refused: TransportRefusal) -> Self {
        match refused {
            TransportRefusal::NoEndpoint => OpenError::NoEndpoint,
            TransportRefusal::Listen(why) => OpenError::Listen(why),
            TransportRefusal::Group(why) => OpenError::Group(why),
            TransportRefusal::Unreachable(why) => OpenError::Unreachable(why),
            TransportRefusal::EntropyUnavailable => OpenError::EntropyUnavailable,
            TransportRefusal::NoTask(why) => OpenError::NoTask(why),
        }
    }
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
    /// session or an endpoint, needs a dictionary, and an endpoint is stated once. The dictionary
    /// is then held to the session's `MAX_SHARED_KEY_IDS` in `limits`.
    #[cfg(feature = "shared-key-ids")]
    fn admit(
        &self,
        policy: &SessionPolicy,
        limits: &SessionLimits,
    ) -> Result<LinkKeyForms, OpenError> {
        let forms = self
            .at_open
            .forms(policy.key_wire_form())
            .map_err(|refused| {
                OpenError::KeyWireForm(match refused {
                    KeyIdsRefused::DuplicateLink { .. } => KeyWireFormRefused::LinkStatedTwice,
                    _ => KeyWireFormRefused::NoDictionary,
                })
            })?;
        if let Err(KeyIdsRefused::TooMany { stated, limit }) = self.at_open.check_limits(limits) {
            return Err(OpenError::KeyIdsOverLimit { stated, limit });
        }
        Ok(forms)
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

/// What the open lent the engine apart from the session's state ([`CoopEngine::assemble`]): the
/// place of the ABI's handle, the places of the publishes kept for the session's other faces,
/// which a publish reaches with the session held by another, and the ring of the advanced
/// publishers' caches, which the engine locks apart from the state.
struct LentApart {
    handle_place: Option<HandlePlace>,
    #[cfg(any(feature = "listen", feature = "group"))]
    handed: HandedTable,
    #[cfg(feature = "advanced-cache")]
    cache: Option<CacheSpan>,
}

/// What the arena of a session lends it at its open ([`lend_session`]). The arena is the last
/// field, so a value of this let go of whole lets every table lent from it go first.
struct SessionLent {
    /// The transport's tables, held as they were lent: taken apart here, they would be moved
    /// once into the open's frame and once more into this value.
    transport: TransportTables,
    samples: Arc<Round>,
    router: SessionReassembly,
    keys: KeySpace,
    #[cfg(feature = "queryable")]
    plane: Arc<QueryPlane>,
    registry: Registry,
    /// What the session's gets share with their sinks and the round: the ends of their legs, the
    /// replies the gets that consolidate hold, and the legs' callbacks.
    #[cfg(feature = "query")]
    gets: Arc<GetPlane>,
    /// The session's own note of each leg pending, a row for each get its tables hold.
    #[cfg(feature = "query")]
    pending_gets: Rows<PendingGet, { usize::MAX }>,
    handle_place: Option<HandlePlace>,
    places: EntityPlaces,
    /// The links the plan holds buffers for: the rows of the session's link admission.
    #[cfg(feature = "listen")]
    links: usize,
    /// Whether the outbound slots the links share are fewer than the links.
    #[cfg(feature = "listen")]
    tx_pool_short: bool,
    /// The ring the advanced publishers' caches keep their samples in, none for a plan of none.
    #[cfg(feature = "advanced-cache")]
    cache: Option<CacheSpan>,
    arena: SessionArena,
}

/// The plain tables of a session's state, lent by an open's one lender
/// (`SessionRows::lent_from`): the key arena, and the ends of its legs, their callbacks and the
/// session's note of each leg pending.
struct StateTables {
    keys: LentKeys,
    #[cfg(feature = "query")]
    legs: Rows<Ended, { usize::MAX }>,
    #[cfg(feature = "query")]
    leg_rows: Rows<Option<LegRow>, { usize::MAX }>,
    #[cfg(feature = "query")]
    pending_gets: Rows<PendingGet, { usize::MAX }>,
    /// The Finals the queryables' plane holds and the requests a dispatch refused, a row of each
    /// for each query held at once (`query::FinalHolds`).
    #[cfg(feature = "queryable")]
    held_finals: query::HeldFinals,
    #[cfg(feature = "queryable")]
    refused_finals: query::RefusedFinals,
    #[cfg(feature = "advanced-cache")]
    cache: Option<LentByteCells>,
}

impl SessionRows {
    /// The session's plain tables, lent by `lend` in the order the plan laid them out, each key
    /// at most `longest` bytes. A count past the address space is a table the lender refuses.
    fn lent_from(&self, lend: &mut TableLender<'_>, longest: MaxKeyexprBytesHeld) -> StateTables {
        #[cfg(feature = "query")]
        let legs = self.gets().legs().unwrap_or(usize::MAX);
        StateTables {
            keys: lend.keys(self.key_bytes(), longest),
            #[cfg(feature = "query")]
            legs: lend.table(legs),
            #[cfg(feature = "query")]
            leg_rows: lend.table(legs),
            #[cfg(feature = "query")]
            pending_gets: lend.table(legs),
            #[cfg(feature = "queryable")]
            held_finals: lend.table(self.held_queries()),
            #[cfg(feature = "queryable")]
            refused_finals: lend.table(self.held_queries()),
            #[cfg(feature = "advanced-cache")]
            cache: (self.cache_bytes() != 0).then(|| lend.byte_cells(self.cache_bytes(), 1)),
        }
    }
}

/// Lay out the plan of the session opened with `config` under `policy` (`lay_out_open`, each
/// link's cells `cell_bytes` large and the ABI's places `held`), reserve its arena in `memory`
/// and lend from it every table of the session. One lender lends each layer its plain tables
/// from the rows the plan counts for it: the transport's links, cells, reassembly and endpoints, the
/// state's lane, declarations, keys and legs, and the ABI's places; it gives the tables after a
/// refusal no rows and is asked once, after them all. The round's tables and the application's,
/// which their makers lend, ask their own. What was lent before a refusal goes back with the
/// arena. Out of line and generic over nothing: one body for every stack and source the open is
/// made over. The plan is made and read here, so the open's frame never holds or moves it: what
/// the state is sized by is handed back with the tables.
#[inline(never)]
fn lend_session(
    cell_bytes: LinkCells<usize>,
    held: &HeldPlaces,
    memory: &'static dyn ArenaMemory,
    config: &CoopConfig<Counted>,
    policy: &SessionPolicy,
) -> Result<SessionLent, ArenaRefused> {
    let mut plan = ArenaPlan::vacant();
    plan.count(config, resolve_limits(config))?;
    lay_out_open(&mut plan, cell_bytes, held)?;
    let mut arena = SessionArena::reserve(&plan, memory)?;
    let mut lend = arena.lender();
    // Held whole to the end, as the value handed back holds it; the state's tables, which the
    // open moves into what it makes one by one, are taken apart at once instead: a table held as
    // a field of a set partly moved out would need its own drop on each refusal below.
    let transport = plan.transport().lent_from(&mut lend);
    let StateTables {
        keys,
        #[cfg(feature = "query")]
        legs,
        #[cfg(feature = "query")]
        leg_rows,
        #[cfg(feature = "query")]
        pending_gets,
        #[cfg(feature = "queryable")]
        held_finals,
        #[cfg(feature = "queryable")]
        refused_finals,
        #[cfg(feature = "advanced-cache")]
        cache,
    } = plan
        .session()
        .lent_from(&mut lend, config.limits.max_keyexpr_bytes_held());
    let PlaceTables {
        handle,
        entities: places,
    } = plan.places().lent_from(&mut lend, plan.entities());
    let keys = lend.finish_keys(keys).map_err(ArenaRefused::Lend)?;
    let claimed = plan.claim_handle(handle)?;
    #[cfg(feature = "advanced-cache")]
    let cache = cache
        .map(|cells| CacheSpan::claimed(cells, plan.session().cache_bytes()))
        .transpose()?;
    let ClaimedPlaces {
        handle: handle_place,
    } = claimed;
    let router = session_reassembly(
        policy,
        SessionChains::over(&transport.reassembly, LENT_CHAINS),
    );
    let round_rows =
        RoundRows::lent(arena.arena_mut(), plan.round()).map_err(ArenaRefused::Lend)?;
    // The rows the gets that consolidate hold their replies in, lent beside the round's.
    #[cfg(feature = "query")]
    let held_replies = HeldReplies::lent(arena.arena_mut(), plan.session().held_replies())
        .map_err(ArenaRefused::Lend)?;
    // What the gets share: made here, so the round is told whose legs' callbacks its replies'
    // records hold counts of before it is shared.
    #[cfg(feature = "query")]
    let gets = Arc::new(GetPlane::new(
        EndedLegs::over(legs),
        held_replies,
        LegRows::over(leg_rows),
    ));
    let mut samples = Round::shared_over(round_rows);
    // The round is not shared yet: it reads the keys a peer's aliases keep in the session's key
    // arena where they lie.
    if let Some(round) = Arc::get_mut(&mut samples) {
        round.reads_keys_in(keys);
        #[cfg(feature = "query")]
        round.calls_legs_of(gets.clone());
    }
    // The queries the session's queryables are asked wait for their callbacks here, and the
    // Finals of them are held here, in rows the plan counts.
    #[cfg(feature = "queryable")]
    let plane = Arc::new(QueryPlane::over(query::FinalHolds::over(
        held_finals,
        refused_finals,
    )));
    #[cfg(feature = "queryable")]
    let delivery = RoundDelivery::new(samples.clone(), plane.clone());
    #[cfg(not(feature = "queryable"))]
    let delivery = RoundDelivery::new(samples.clone());
    // The application's tables, lent from the rows the plan counts for them: the session's
    // one table set among them, which holds its subscribers and its queryables.
    let registry = Registry::new(
        resolve_limits(config),
        arena.arena_mut(),
        keys,
        // The session's tokens are rows of its one table set, which answers a peer's Interest
        // too, so the observer's own registry of them is lent none.
        ObserverRows {
            tables: plan.tables(),
            local_tokens: 0,
        },
        plan.gets(),
        plan.peers(),
        delivery,
    )
    .map_err(ArenaRefused::Lend)?;
    Ok(SessionLent {
        transport,
        samples,
        router,
        keys,
        #[cfg(feature = "queryable")]
        plane,
        registry,
        #[cfg(feature = "query")]
        gets,
        #[cfg(feature = "query")]
        pending_gets,
        handle_place,
        places,
        #[cfg(feature = "listen")]
        links: plan.links(),
        #[cfg(feature = "listen")]
        tx_pool_short: plan.tx_pool_short(),
        #[cfg(feature = "advanced-cache")]
        cache,
        arena,
    })
}

/// The zid the session opened with `config` announces: the configured one, or one drawn from
/// `entropy`, or one derived from the endpoints it listens on (`endpoints`) and `entropy`, as
/// `policy` says. Out of line and generic over nothing, as [`lend_session`] is.
#[inline(never)]
fn session_zid(
    config: &CoopConfig<Counted>,
    policy: &SessionPolicy,
    endpoints: &EndpointTexts,
    entropy: &mut SessionEntropy,
) -> Result<SessionZid, OpenError> {
    match (&config.zid, policy.zid_derivation()) {
        (Some(zid), _) => Ok(wire_form(*zid)),
        (None, wz_session_core::policy::ZidDerivation::Random) => fresh_zid(entropy),
        (None, wz_session_core::policy::ZidDerivation::AddressPorts) => derived_zid(
            (0..endpoints.listens()).map(|at| endpoints.listen_text(at)),
            entropy,
        ),
    }
}

/// The wire form of the zid `zid` spells ([`wire_form`]), refused when the bytes are not one to
/// sixteen or are all zero, so the session the open makes from them holds a zid.
pub(crate) fn wire_zid(zid: &[u8]) -> Result<SessionZid, OpenError> {
    SessionZid::new(zid)
        .map(wire_form)
        .map_err(OpenError::InvalidZid)
}

/// `zid` up to its last non-zero byte, as zenoh writes an id. A zid has a non-zero byte, so what
/// is kept is a zid as well and the fallback to `zid` itself is never taken.
pub(crate) fn wire_form(zid: SessionZid) -> SessionZid {
    zid.iter()
        .rposition(|byte| *byte != 0)
        .and_then(|last| zid.get(..=last))
        .and_then(|kept| SessionZid::new(kept).ok())
        .unwrap_or(zid)
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
pub(crate) fn derived_zid<T: AsRef<str>>(
    listen: impl IntoIterator<Item = T>,
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
        let Ok(at) = parse_listen_locator(endpoint.as_ref()) else {
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
    core: CoreLock<L, C>,
    /// The waits for room of the faces that are up, asked by a publish that may be dropped while
    /// another holds the session ([`Self::live_to_publish`]), how long it waits
    /// (`congestion_control/drop/wait_before_drop`), and whether the queue profile has it ask at
    /// all (`TxQueueConf::held_drop`).
    rooms: Arc<LinkRooms<L::Waits>>,
    wait_before_drop_us: u64,
    held_drop: HeldDrop,
    /// The place of the face a publish holding the session sends on now, [`NOT_SENDING`] while
    /// none does ([`SendingOn`]): the face pico's profile drops a droppable publish on, as
    /// against the session's other faces, which it is still sent to, and a session held by a read
    /// step, a timer or the drive, which it waits for.
    sending_on: AtomicU64,
    /// The droppable publishes that found the session held and were dropped on the faces its
    /// holder waits on, owed to the session's other faces ([`HandedTable`]), in the order they
    /// were handed. A build of the dial face alone owes a dropped publish to no face, and keeps
    /// no queue.
    #[cfg(any(feature = "listen", feature = "group"))]
    handed: Mutex<HandedTable>,
    /// Whether `handed` holds a leg, written under its lock: a publish that reads it clear takes
    /// no lock for the queue, which is otherwise two lock round trips on every put of a stream for
    /// what is almost always nothing. A publish that reads it stale leaves the leg to the next
    /// holder, as one that took the queue a moment before the leg was handed does; a read step
    /// always looks under the lock ([`Self::send_handed_now`]).
    #[cfg(any(feature = "listen", feature = "group"))]
    owed: AtomicBool,
    /// Whether the last read's step left a link holding input it had already taken from its stack
    /// (a batch behind the one it read, the rest of a datagram the lane had no room for), or a
    /// group with a datagram its next step reads: the next read steps at once, with no wait to
    /// work out under the session's lock, since that wait would be none. Written by the step, under
    /// the lock; a stale `true` costs one step that finds nothing, after which the read waits.
    input_held: AtomicBool,
    /// Where a read waits for another read to hand back the session's buffer of waits.
    hand_back: HandBack,
    /// How many handed legs of each priority are held at most: as many as the session's queue
    /// holds batches of that priority (`TxQueueConf::sizes`), which is as many as a face whose
    /// queue were its own would take before a droppable message found no room on it.
    #[cfg(any(feature = "listen", feature = "group"))]
    handed_limits: HandedLimits,
    /// The droppable publishes dropped before they reached a link: on the faces a held session
    /// waits on, for want of room or by the profile's drop at once ([`Self::live_to_publish`]),
    /// one each whatever the number of those faces. Charged to the transport's drops in
    /// [`Self::transport_stats`], where a link's session charges its own.
    #[cfg(feature = "transport-stats")]
    unsent_drops: AtomicU64,
    /// What the session delivered under the lock, handed out after it: the records for its
    /// callbacks, in the order they arrived, in the session's round of deliveries
    /// (`crate::round`). A change of a matching status takes no record's room: it is owed in the
    /// listener's row (`SessionTables::take_owed_matching`).
    samples: Arc<Round>,
    /// Whether a read of the matching listeners found a change since a walk of their rows last
    /// found none owed, written under the session's lock: a delivery that reads it clear takes no
    /// lock to look for one.
    matching_owed: AtomicBool,
    /// The queries waiting for their callbacks and the Finals held for them (`query`).
    #[cfg(feature = "queryable")]
    plane: Arc<QueryPlane>,
    /// What the session's gets queued for their callbacks (`get`).
    #[cfg(feature = "query")]
    gets: Arc<GetPlane>,
    /// What the session's watchers of its faces are owed, and who they are (`connectivity`).
    #[cfg(feature = "connectivity")]
    faces: Arc<FacePlane>,
    /// The program's watches of what the peers declare and what is owed to them, shared with the
    /// registry whose observers stage it (`decl_watch`).
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    decl_watches: DeclWatches,
    zid: SessionZid,
    closed: AtomicBool,
    /// The ids of what the session holds for the program and never names to a peer: the legs
    /// of its gets and its periodic jobs. A space of their own, so they are not refused when the
    /// entity ids are spent.
    #[cfg(any(feature = "query", feature = "ticker"))]
    next_local: AtomicU64,
    reader: Mutex<Option<ReadTask>>,
    /// The run of read tasks, one past each stop: a read task steps the session while the run is
    /// the one it was started in, so a stop needs no word made for it (`ReaderBody`).
    reader_run: core::sync::atomic::AtomicUsize,
    /// The threads handing deliveries out for this engine now, and the callbacks each runs
    /// ([`Deliveries`]): a callback that steps its session again from one of them queues what it
    /// delivers for the outer delivery, and the session's own put or get tells a callback it can
    /// call at once from one the asking thread is inside of.
    deliveries: Deliveries,
    /// The bytes the open reserved for the session's arena ([`Self::arena_bytes`]).
    arena_bytes: usize,
    /// The place the arena lent the ABI's handle of the session, when the open was asked for one
    /// ([`CoopDrive::handle_place`]).
    handle_place: Option<HandlePlace>,
    /// The ring the session's advanced publishers' caches keep their samples in, under a lock of
    /// its own, which nothing that holds the session's lock takes ([`wz_capi_port::CacheBytes`]).
    #[cfg(feature = "advanced-cache")]
    cache: Mutex<Option<CacheSpan>>,
    /// The takes of the session's locks on a message's paths, which the tests count.
    #[cfg(test)]
    pub(crate) takes: Takes,
    this: Weak<Self>,
}

/// How often the session's lock ([`CoopEngine::live`], and a droppable publish's try of it) and its
/// queue of handed legs were taken: what a test of the cost of one message counts.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct Takes {
    pub(crate) core: core::sync::atomic::AtomicUsize,
    #[cfg(any(feature = "listen", feature = "group"))]
    pub(crate) handed: core::sync::atomic::AtomicUsize,
    /// The turns a droppable publish spun on a held session before it tried the session again.
    pub(crate) spins: core::sync::atomic::AtomicUsize,
    /// The reads whose wait was a wait on the input of the session's links and ports, which
    /// the step's read follows.
    pub(crate) polls: core::sync::atomic::AtomicUsize,
    /// The sends on a face marked as the session's holder's while they were made (`SendingOn`).
    pub(crate) face_marks: core::sync::atomic::AtomicUsize,
    /// The walks of the tables for rows whose last call ended, made only when a call said one
    /// may wait.
    pub(crate) walks: core::sync::atomic::AtomicUsize,
    /// The holds of key expression declarations the session handed out (declared or retained)
    /// less those given back, counted whether the session is open or closed: a hold given back to
    /// a closed session is still one given back, and one never given back stays counted.
    pub(crate) holds: core::sync::atomic::AtomicIsize,
}

#[cfg(test)]
impl Takes {
    /// Count the wait a read is about to make.
    fn wait(&self, wait: &IdleWait) {
        let counter = match wait {
            IdleWait::Input { .. } => &self.polls,
            IdleWait::None | IdleWait::Sleep(_) | IdleWait::Behind(_) => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Where a read that found another read waiting with the session's buffer of waits
/// ([`IdleWait::Behind`]) waits for the buffer to be handed back: woken then, it steps and its
/// next wait is on the links, so a read task behind a program's read does not sleep out its bound
/// while what arrives after that read waits for it.
struct HandBack {
    /// The reads waiting here now: a hand-back with none takes no lock.
    behind: core::sync::atomic::AtomicUsize,
    /// How many times the buffer was handed back to a read waiting here, under the lock its wait
    /// is made with, so that a hand-back before the wait begins ends it at once.
    handed: Mutex<u64>,
    back: os::Condvar,
}

impl HandBack {
    fn new() -> Self {
        Self {
            behind: core::sync::atomic::AtomicUsize::new(0),
            handed: Mutex::new(0),
            back: os::Condvar::new(),
        }
    }

    /// Count in a read that waits here, under the session's lock, which a hand-back is made
    /// under too: the count of hand-backs it waits to see move.
    fn enter(&self) -> u64 {
        self.behind.fetch_add(1, Ordering::SeqCst);
        *lock(&self.handed)
    }

    /// Wait, with nothing of the session held, for a hand-back after `seen`, for at most `ms`
    /// milliseconds. A wake that comes early ends it as well: the read steps, and looks again.
    fn wait(&self, seen: u64, ms: u32) {
        let handed = lock(&self.handed);
        let handed = if *handed == seen {
            self.back.wait_timeout_ms(handed, u64::from(ms)).0
        } else {
            handed
        };
        drop(handed);
        self.behind.fetch_sub(1, Ordering::SeqCst);
    }

    /// The buffer was handed back, under the session's lock: wake every read waiting for it.
    fn handed_back(&self) {
        if self.behind.load(Ordering::SeqCst) == 0 {
            return;
        }
        let mut handed = lock(&self.handed);
        *handed = handed.wrapping_add(1);
        drop(handed);
        self.back.notify_all();
    }
}

/// The session state no other thread may touch while one does; see the module doc.
struct Confined<T>(T);

/// The session's state behind its one lock. Every hold of it goes through here, and tells the
/// session's key arena that the lock is held for as long as it is
/// ([`KeySpace::guard_by_owner_lock`]): the arena's counts are touched only under this lock, so a
/// key let go of after the lock (a row taken out of a table and dropped outside it) fails a debug
/// build at once instead of racing a reader that holds the lock.
struct CoreLock<L: SessionLinks + 'static, C: ClockSource + 'static>(Mutex<Confined<Core<L, C>>>);

impl<L: SessionLinks + 'static, C: ClockSource + 'static> CoreLock<L, C> {
    /// `core` behind the lock, its key arena guarded by it from now on.
    fn new(core: Core<L, C>) -> Self {
        core.session.keys.guard_by_owner_lock();
        Self(Mutex::new(Confined(core)))
    }

    fn lock(&self) -> CoreGuard<'_, L, C> {
        // Marked before the take, so a take on the thread that holds the lock already fails a
        // debug build instead of waiting on itself.
        let held = wz_capi_port::sync::SessionHeld::enter(core::ptr::from_ref(self).cast());
        CoreGuard::taken(self.0.lock(), held)
    }

    fn try_lock(&self) -> Option<CoreGuard<'_, L, C>> {
        let guard = self.0.try_lock()?;
        let held = wz_capi_port::sync::SessionHeld::enter(core::ptr::from_ref(self).cast());
        Some(CoreGuard::taken(guard, held))
    }

    /// The state with no lock, the engine being let go of: the key arena is marked held for the
    /// rest of the engine's drop, which drops every row that keeps a key.
    fn dropping(&mut self) -> &mut Core<L, C> {
        let core = &mut self.0.get_mut().0;
        core.session.keys.owner_lock_taken();
        core
    }
}

/// A hold of [`CoreLock`]: the key arena is marked held from its taking to its drop.
struct CoreGuard<'a, L: SessionLinks + 'static, C: ClockSource + 'static> {
    guard: MutexGuard<'a, Confined<Core<L, C>>>,
    // The thread's mark of the hold, which a debug build reads: a second take of this lock on
    // this thread, or a C ABI's place given back under it, fails there instead of waiting.
    _held: wz_capi_port::sync::SessionHeld,
}

impl<'a, L: SessionLinks + 'static, C: ClockSource + 'static> CoreGuard<'a, L, C> {
    fn taken(
        guard: MutexGuard<'a, Confined<Core<L, C>>>,
        held: wz_capi_port::sync::SessionHeld,
    ) -> Self {
        guard.0.session.keys.owner_lock_taken();
        Self { guard, _held: held }
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + 'static> Deref for CoreGuard<'_, L, C> {
    type Target = Confined<Core<L, C>>;

    fn deref(&self) -> &Confined<Core<L, C>> {
        &self.guard
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + 'static> DerefMut for CoreGuard<'_, L, C> {
    fn deref_mut(&mut self) -> &mut Confined<Core<L, C>> {
        &mut self.guard
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + 'static> Drop for CoreGuard<'_, L, C> {
    // Out of line: every hold of the session is let go through it.
    #[inline(never)]
    fn drop(&mut self) {
        // Before the lock is let go of, which the guard's own drop does after this body.
        self.guard.0.session.keys.owner_lock_released();
    }
}

/// The waits of the session's stack (`W`, [`SessionLinks::waits`]), and what each face that is
/// up names for a wait for its room, kept outside [`Core`] so that a publish that finds the
/// session held asks them with nothing of it held, and a read waits with them with nothing of it
/// held. A face's handle is a value, held from the face's coming up until its link is lost or the
/// face goes; one asked after its link went is a hint, as every answer is. A face's handle lies at
/// the face's place, the one its tables and its link keep, so a publish dropped on a face names it
/// by that place ([`DroppedOn`]) and nothing looks a face up by its id.
pub(crate) struct LinkRooms<W> {
    waits: W,
    rooms: Mutex<RoomTable>,
}

/// What the faces that are up name for a wait for their room, each at its face's place, and the
/// mark of the last face that took a place: a set of places read at one mark names no face that
/// took its place after it.
struct RoomTable {
    places: Vec<Option<RoomPlace>>,
    mark: u64,
}

/// What the face at a place of the table of rooms names.
#[derive(Clone, Copy)]
struct RoomPlace {
    on: WaitOn,
    /// The table's mark when the face took the place.
    #[cfg(any(feature = "listen", feature = "group"))]
    since: u64,
}

/// What a droppable publish that found the session held is told of the faces it would be sent
/// to, the faces that took no bytes named by their places in the table of rooms: what the face's
/// send value reads into what the publish does ([`face_send::Room::behind`]).
pub(crate) type Room = face_send::Room<DroppedOn>;

/// What [`CoopEngine`]'s `sending_on` holds while no publish sends. A send marks the place of
/// the face it sends on, and no session has a place this far up.
const NOT_SENDING: u64 = u64::MAX - 2;

/// The place `at` as a send marks it ([`SendingOn`]) and as a fan-out orders its faces
/// ([`Pass::face_send`]).
fn mark_of_place(at: usize) -> u64 {
    u64::try_from(at).unwrap_or(NOT_SENDING)
}

/// The place a send's mark names ([`mark_of_place`]): one past every place for a mark that names
/// none.
#[cfg(any(feature = "listen", feature = "group"))]
fn place_of_mark(mark: u64) -> usize {
    usize::try_from(mark).unwrap_or(usize::MAX)
}

/// What [`CoopEngine`]'s `sending_on` holds while a publish holds the session and sends on no
/// face: before its first send and between two. No face has the place.
const PUBLISHING: u64 = u64::MAX;

/// What [`CoopEngine`]'s `sending_on` holds while a read holds the session to work out its wait
/// (and lend its one link's buffer to it): no face has the place either.
const WAITING: u64 = u64::MAX - 1;

/// Who holds the session, as a droppable publish that finds it held reads it ([`SendingOn`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Holder {
    /// What is not a publish: a read step, a timer, the drive. It lets go once its step is done.
    Step,
    /// A publish, between its sends.
    Publish,
    /// A read working out its wait: it holds no send, and lets go within its take.
    Waiting,
    /// A send on the face at this place, a publish's or what a read step sends of the legs
    /// handed to it.
    Sending(u64),
}

/// A send on a face, or a publish holding the session ([`PUBLISHING`]), marked for as long as this
/// lives ([`CoopEngine`]'s `sending_on`): what tells a droppable publish that finds the session
/// held which face a send holds, as pico's transmit lock is held by a send, or that a publish holds
/// it between its sends, or that something that is not a publish holds the session (a read step, a
/// timer, the drive), which lets go once its step is done. Only the holder of the session sends,
/// so one mark is in force at a time; a send ends with the mark it found, so a publish is marked
/// as one between its sends.
struct SendingOn<'a> {
    mark: &'a AtomicU64,
    was: u64,
}

impl<'a> SendingOn<'a> {
    fn enter(mark: &'a AtomicU64, place: u64) -> Self {
        let was = mark.swap(place, Ordering::SeqCst);
        Self { mark, was }
    }
}

impl Drop for SendingOn<'_> {
    fn drop(&mut self) {
        self.mark.store(self.was, Ordering::SeqCst);
    }
}

impl<W: LinkWaits> LinkRooms<W> {
    /// The rooms of a session over a stack whose waits are `waits`, a place for each of the
    /// `places` places a face of the session may hold, made now: none grows after.
    pub(crate) fn new(waits: W, places: usize) -> Self {
        let mut table = Vec::with_capacity(places);
        table.resize(places, None);
        Self {
            waits,
            rooms: Mutex::new(RoomTable {
                places: table,
                mark: 0,
            }),
        }
    }

    /// The waits of the session's stack.
    pub(crate) fn waits(&self) -> &W {
        &self.waits
    }

    /// Hold `on`, what a wait for room on the face at place `at` waits on, in place of what the
    /// face named before (a group joined again keeps the mark it took the place at), or as the
    /// face that takes the place now.
    pub(crate) fn hold(&self, at: usize, on: WaitOn) {
        let mut guard = lock(&self.rooms);
        let rooms = &mut *guard;
        let mark = rooms.mark.wrapping_add(1);
        let Some(place) = rooms.places.get_mut(at) else {
            return;
        };
        if let Some(held) = place.as_mut() {
            held.on = on;
            return;
        }
        rooms.mark = mark;
        *place = Some(RoomPlace {
            on,
            #[cfg(any(feature = "listen", feature = "group"))]
            since: mark,
        });
    }

    /// Let go of what the face at place `at` named: its link is lost, or the face has gone. Its
    /// place is free.
    pub(crate) fn forget(&self, at: usize) {
        if let Some(place) = lock(&self.rooms).places.get_mut(at) {
            *place = None;
        }
    }

    /// Let go of what every face named: the faces' links are ended.
    pub(crate) fn forget_all(&self) {
        for place in &mut lock(&self.rooms).places {
            *place = None;
        }
    }

    /// The set of place `at` alone, as the table stands now: every face when no face holds the
    /// place, since a publish dropped on a face no place names is dropped on all.
    #[cfg(any(feature = "listen", feature = "group"))]
    pub(crate) fn dropped_on(&self, at: usize) -> DroppedOn {
        let rooms = lock(&self.rooms);
        let mut set = DroppedOn::none(rooms.mark);
        if rooms.places.get(at).is_some_and(Option::is_some) {
            set.insert(at);
        } else {
            set.insert(usize::MAX);
        }
        set
    }

    /// Whether a publish dropped on `set` passes over the face at place `at`: one of the set, or
    /// one that took its place after the set was read, as a transport that opened after a publish
    /// is not sent it ([`DroppedOn::owes`]). A place that names no wait for its room is sent it:
    /// when its face came is not known, and a droppable publish sent to a face that came after it
    /// costs that face one message it could have missed, where passing it over could lose one the
    /// face was owed.
    #[cfg(any(feature = "listen", feature = "group"))]
    pub(crate) fn skips(&self, set: &DroppedOn, at: usize) -> bool {
        lock(&self.rooms)
            .places
            .get(at)
            .copied()
            .flatten()
            .is_some_and(|place| !set.owes(at, place.since))
    }

    /// What a droppable publish that found the session held is told, by the queue profile's
    /// `held_drop`: zenoh's asks the faces for room within `wait_us` ([`Self::within`]). Pico's
    /// asks nothing: on the face a send holds it is dropped at once ([`Room::Held`]), as pico's
    /// try-lock fails on a transmit lock another send holds; behind a publish between its sends it
    /// tries the session again ([`Room::Free`]); and behind a holder that is not a publish it waits
    /// for the session ([`Room::Stepping`]). Behind a read working out its wait both profiles try
    /// the session again, asking nothing.
    pub(crate) fn for_held(&self, held_drop: HeldDrop, holder: Holder, wait_us: u64) -> Room {
        match (held_drop, holder) {
            // Under either profile: a read working out its wait waits on no face and lets go in a
            // moment, so no link is asked for room and nothing blocks on the session's lock.
            (_, Holder::Waiting) => Room::Free,
            (HeldDrop::WaitForRoom, _) => self.within(wait_us),
            (HeldDrop::DropAtOnce, Holder::Sending(face)) => Room::Held(face),
            (HeldDrop::DropAtOnce, Holder::Publish) => Room::Free,
            (HeldDrop::DropAtOnce, Holder::Step) => Room::Stepping,
        }
    }

    /// The place `at` of the table, read under the lock, which goes before the caller waits on
    /// what it names: `None` past the table, and a free place as `Some(None)`.
    fn room_at(&self, at: usize) -> Option<Option<RoomPlace>> {
        lock(&self.rooms).places.get(at).copied()
    }

    /// The table's mark now.
    fn mark(&self) -> u64 {
        lock(&self.rooms).mark
    }

    /// Ask each face that is up for room, within `wait_us` in all: the first face that takes none
    /// spends the wait, and the faces after it are asked without one, so the publish spends one
    /// deadline whatever the number of faces. Each face's handle is read under the lock and the
    /// lock let go before its wait: a wait blocks, and a face coming up must not wait behind it.
    /// A face that comes up or goes meanwhile may be asked or passed over, a hint as every answer
    /// is; nothing is copied out of the lock but one handle at a time, and the faces that took no
    /// bytes are named by their places, with nothing of the heap.
    pub(crate) fn within(&self, wait_us: u64) -> Room {
        let mut left_us = wait_us;
        let mut congested = DroppedOn::none(self.mark());
        let mut asked = false;
        let mut any = false;
        let mut at = 0usize;
        while let Some(place) = self.room_at(at) {
            let here = at;
            at = at.wrapping_add(1);
            let Some(RoomPlace { on, .. }) = place else {
                continue;
            };
            asked = true;
            if !self.waits.wait_room(on, left_us) {
                congested.insert(here);
                any = true;
                left_us = 0;
            }
        }
        match (asked, any) {
            (false, _) => Room::Unasked,
            (true, false) => Room::Free,
            (true, true) => Room::Congested(congested),
        }
    }
}

/// One publish as its leg to the links sends it ([`CoopEngine::fan_out`]).
struct Publication<'a> {
    keyexpr: &'a str,
    wire: &'a WireKey,
    payload: &'a [u8],
    opts: &'a PublishOptions<'a>,
    meta: &'a PushMetadata<'a>,
}

/// One put as each of the session's links is sent it ([`CoopEngine::send_on_links`]): the key as
/// the session's tables name it, and how it rides.
struct LinkLeg<'a> {
    named: NamedKey<'a>,
    payload: &'a [u8],
    kind: SampleKind,
    meta: &'a PushMetadata<'a>,
    send: wz_session_core::session_actions::SendAs,
}

/// What a publish's leg to the links finds of the session ([`CoopEngine::live_to_publish`]).
enum ToPublish<'a, L: SessionLinks + 'static, C: ClockSource + 'static> {
    /// The session, held for the publish.
    Live(LiveCore<'a, L, C>),
    /// The session is closed.
    Closed,
    /// The publish may be dropped, and found the session held by a send that waits on `faces`:
    /// it is dropped on them, and the caller is told when `told` (the pico profile). A build of
    /// the dial face alone names no face: the one it holds is the one the publish is dropped on.
    DroppedOn {
        #[cfg(any(feature = "listen", feature = "group"))]
        faces: DroppedOn,
        told: bool,
    },
}

// SAFETY: a `Confined` is reached only through the `Mutex` that holds it in `CoopEngine`, so one
// thread at a time uses it. Its `Rc` handles and `RefCell` cells are all owned by the `Core`
// inside it: no clone of any of them is ever handed out of the lock (deliveries leave as bytes
// of the delivery lane and `bool`s, see `CoopEngine::samples`), so every handle of each `Rc`
// moves with the `Core` when another thread takes the lock, and none is used by two threads at
// once. A key of the session's key arena handed out of it to an object of the program
// (`HeldKey`, `SessionKeys`) is shared and let go of only under this lock, and read outside it
// only for its text, which nothing writes while the key is held.
unsafe impl<T> Send for Confined<T> {}

/// What the rows of the session's one table set hold of a program: the engine's whole record of
/// each of its subscribers and queryables. The engine's kinds move onto the tables one at a time
/// (`docs/c-abi-l3-tables.md`, section 6), and a kind not moved yet, or one the build has not, is
/// lent no rows of them.
pub(crate) struct CoopRows;

impl RowCallbacks for CoopRows {
    type Subscriber = SubscriberRow;
    #[cfg(feature = "queryable")]
    type Queryable = QueryableRow;
    #[cfg(not(feature = "queryable"))]
    type Queryable = ();
    #[cfg(feature = "liveliness")]
    type LivelinessSubscriber = LivelinessRow;
    #[cfg(not(feature = "liveliness"))]
    type LivelinessSubscriber = ();
    type Matching = MatchingCall;
    type Reply = ();
    // A session that answers no query keeps no table of queryables.
    #[cfg(feature = "queryable")]
    type QueryablePresence = wz_session_core::session_tables::Present;
    #[cfg(not(feature = "queryable"))]
    type QueryablePresence = wz_session_core::session_tables::Absent;
    // A session without liveliness keeps neither tokens nor liveliness subscribers.
    #[cfg(feature = "liveliness")]
    type LivelinessPresence = wz_session_core::session_tables::Present;
    #[cfg(not(feature = "liveliness"))]
    type LivelinessPresence = wz_session_core::session_tables::Absent;
    // The write filters, the matching listeners and the Interests they hold are rows of the
    // tables; the pending gets are kept in the engine's own core, so the tables keep none.
    type FilterPresence = wz_session_core::session_tables::Present;
    type GetPresence = wz_session_core::session_tables::Absent;
}

/// A matching listener's callback as its row holds it. A change of the listener's status is found
/// under the session's lock and owed in the row; the delivery after the
/// lock takes the callback out of the row, calls it and puts it back, so no call reads the row and
/// the row is let go of as soon as it is undeclared, its callback by the thread that called it when
/// it was out. `None` while it is out for a call.
pub(crate) struct MatchingCall {
    sink: Option<MatchingSink>,
}

impl RowCallback for MatchingCall {
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

    fn drained(&self) -> bool {
        true
    }
}

/// The id the port names a write filter or a matching listener by: the bits of its row's handle,
/// whose generation tells the id of an undeclared row from the row that took its slot since.
fn row_id<K>(handle: Handle<K>) -> u64 {
    u64::from(handle.to_bits().get())
}

/// The row `id` names, as [`row_id`] made it; `None` for an id no handle is made of.
fn row_of<K>(id: u64) -> Option<Handle<K>> {
    Handle::from_bits(NonZeroU32::new(u32::try_from(id).ok()?)?)
}

/// What a write filter or a matching listener on `plane` counts, as the session's tables name it.
fn plane_of(plane: FilterPlane) -> Plane {
    match plane {
        FilterPlane::Subscribers => Plane::Subscribers,
        FilterPlane::Queryables { complete_required } => Plane::Queryables { complete_required },
    }
}

/// The session's one table set, its rows lent from the session's arena: the application's tables
/// (`Registry::app`), read through [`tables`].
pub(crate) type CoopTables = SessionTables<CoopRows, Lent>;

/// The session's one table set, read where the registry keeps it: the application's tables are the
/// session's tables (`Registry::app`), so a declaration and the dispatch that reads it hold one
/// record.
fn tables(registry: &RefCell<Registry>) -> core::cell::Ref<'_, CoopTables> {
    core::cell::Ref::map(registry.borrow(), |registry| &registry.app.tables)
}

/// [`tables`], to write.
fn tables_mut(registry: &RefCell<Registry>) -> core::cell::RefMut<'_, CoopTables> {
    core::cell::RefMut::map(registry.borrow_mut(), |registry| &mut registry.app.tables)
}

/// The session's state, held: what [`CoopEngine::live`] hands a caller that may act on it. As it
/// lets go, the round of deliveries it wrote is sealed (`Round::seal`), so what the session wrote
/// under its lock is handed out by the delivery that follows.
struct LiveCore<'a, L: SessionLinks + 'static, C: ClockSource + 'static> {
    /// Let go in the hold's own drop, after the seal, so that no caller holds a copy of the lock's
    /// release beside the call to it.
    core: core::mem::ManuallyDrop<CoreGuard<'a, L, C>>,
    lane: &'a Round,
}

impl<L: SessionLinks + 'static, C: ClockSource + 'static> Deref for LiveCore<'_, L, C> {
    type Target = Confined<Core<L, C>>;

    fn deref(&self) -> &Confined<Core<L, C>> {
        &self.core
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + 'static> DerefMut for LiveCore<'_, L, C> {
    fn deref_mut(&mut self) -> &mut Confined<Core<L, C>> {
        &mut self.core
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + 'static> Drop for LiveCore<'_, L, C> {
    // Out of line, as `CoopEngine::live` is: every operation lets the session go through it, the
    // round sealed and the lock let go in this one body.
    #[inline(never)]
    fn drop(&mut self) {
        // SAFETY: the session's lock is held: `core` is let go below, after the seal.
        unsafe { self.lane.seal() };
        // SAFETY: this is the hold's drop, so `core` is let go once and nothing reads it after.
        unsafe { core::mem::ManuallyDrop::drop(&mut self.core) };
    }
}

/// The read task: a thread that steps the session until it is told to stop.
struct ReadTask {
    thread: JoinHandle,
    id: ThreadId,
}

/// What the read task's thread runs, handed to whatever makes the thread: a hold of the engine,
/// stepped until the engine's run of read tasks is no longer this one's (`reader_run`). A value
/// of a type that can be named, so the start boxes nothing and makes no word for the stop.
pub(crate) struct ReaderBody<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> {
    engine: Arc<CoopEngine<L, C>>,
    run: usize,
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> ReaderBody<L, C> {
    /// Step the session until the task is told to stop or the session ends.
    pub(crate) fn run(self) {
        // Each step blocks in the read of the session's links, so the loop waits there and spins
        // nowhere; it ends once the engine starts another run or the session's read fails.
        while self.engine.reader_run.load(Ordering::Acquire) == self.run {
            if self.engine.read(false).is_err() {
                break;
            }
        }
    }
}

/// A table of the session's own declarations: rows lent from the session's arena at its open, as
/// many as the limit the open resolved, `N` the build's ceiling. A declaration that finds it full
/// is refused before anything is taken, registered or sent.
#[cfg(feature = "query")]
type Rows<T, const N: usize> = wz_session_core::bounded::BoundedVec<T, N, Lent>;

/// The session's state under its one lock, in the layers that own it: the driver's tasks, clock,
/// policy and arena stay here beside the ABI's places, what the links carry is the transport's
/// ([`TransportState`]) and what the session declared and asked is the session's
/// ([`SessionState`]). Each layer is reached through its own field, so it moves out whole.
struct Core<L: SessionLinks + 'static, C: ClockSource + 'static> {
    /// The session's tasks, and the runtime their cells and timers lie in, which the set holds.
    local: CoopLocalSet<C>,
    clock: C,
    /// What the session's links carry: the links, their cells and reassembly, and what each
    /// handshake announces. Dropped before `session`, so a link is let go of before the tables
    /// and keys its declarations name.
    transport: TransportState<L, C>,
    /// What the session declared and asked, and the round its deliveries go through.
    session: SessionState,
    /// Where each link that comes up leaves its wait for room, for the publishes that find the
    /// session held ([`CoopEngine::live_to_publish`]).
    rooms: Arc<LinkRooms<L::Waits>>,
    /// The wake of the links' stack that the program's word that the clock moved on wakes, which
    /// a read waits on beside its links (`CoopConfig::clock_moves`); none for a clock that moves
    /// by itself, or a stack that makes no wake. Held for the session: a wait names it by value.
    #[cfg(feature = "time-base")]
    clock_wake: Option<StackWake>,
    /// The session's one entropy source, which every draw of the session goes through: its zid,
    /// the cookie key of each dial and, through each link's handshake binding (a handle on it,
    /// cloned per link), the cookie nonce and challenges of each handshake it accepts.
    entropy: SessionEntropy,
    /// The config the session opened with, which counts its endpoints: their texts are the
    /// session's rows (`endpoints`).
    config: CoopConfig<Counted>,
    /// The policies the session runs under, as its open was handed them: every link's session
    /// is given them, and the replay and the admission of a second link follow them.
    policy: SessionPolicy,
    /// How often a read's wait and its step read the session's clock ([`Self::now_us`]), which the
    /// tests count.
    #[cfg(test)]
    clock_reads: core::cell::Cell<usize>,
    /// The periodic jobs the program started on the session ([`wz_capi_port::Tickers::start_ticker`]).
    #[cfg(feature = "ticker")]
    tickers: Tickers,
    /// The time the session measures on: each link's actions and task are given it, so what one
    /// link sets a deadline by and another reads it by (the Router's chains among them) are on one
    /// epoch, whenever each link came up.
    session_time: CoopTime<C>,
    /// The places the ABI keeps its objects of the session's entities in, lent from the arena at
    /// the open ([`HeldPlaces`]) and to the ABI under this lock ([`PlaceLender::claim_place`]).
    places: EntityPlaces,
    /// The memory the open reserved for what the session's limits size (`crate::arena`). Last,
    /// so every table lent from it is dropped before it gives its memory back.
    arena: SessionArena,
}

/// The session's part of [`Core`]: the tables of what it declared and asked, over every link, in
/// the parts this engine keeps ([`CoopSession`]).
type SessionState = wz_session_core::session_state::SessionState<CoopSession>;

/// The parts of the coop engine's session state, each `()` where the build leaves it out.
enum CoopSession {}

impl SessionParts for CoopSession {
    type Registry = Rc<RefCell<Registry>>;
    type Faces = Registry;
    type Callbacks = CoopRows;
    type Storage = Lent;
    /// Where a face coming up or going down is reported (`connectivity`).
    #[cfg(feature = "connectivity")]
    type Watchers = Arc<FacePlane>;
    #[cfg(not(feature = "connectivity"))]
    type Watchers = ();
    /// The tables hold each plane's write filters to its own bound: nothing is kept apart.
    type Entities = ();
    #[cfg(feature = "queryable")]
    type Queryables = Arc<QueryPlane>;
    #[cfg(not(feature = "queryable"))]
    type Queryables = ();
    /// The legs of the session's gets still pending on its links, in rows the session's arena lent.
    #[cfg(feature = "query")]
    type PendingGets = Rows<PendingGet, { usize::MAX }>;
    #[cfg(not(feature = "query"))]
    type PendingGets = ();
    #[cfg(feature = "query")]
    type Gets = Arc<GetPlane>;
    #[cfg(not(feature = "query"))]
    type Gets = ();
    /// Asked by every link's gate before it reads a record (`crate::round::RoundGate`).
    type Lane = Arc<Round>;
    #[cfg(feature = "shared-key-ids")]
    type KeyIds = Option<SharedKeyIds>;
    #[cfg(not(feature = "shared-key-ids"))]
    type KeyIds = ();
    #[cfg(feature = "local-queryable")]
    type LocalRequests = LocalRequests;
    #[cfg(not(feature = "local-queryable"))]
    type LocalRequests = ();

    fn tables(registry: &Self::Registry) -> core::cell::Ref<'_, CoopTables> {
        tables(registry)
    }

    fn tables_mut(registry: &Self::Registry) -> core::cell::RefMut<'_, CoopTables> {
        tables_mut(registry)
    }

    fn faces(registry: &Self::Registry) -> core::cell::Ref<'_, Registry> {
        registry.borrow()
    }

    fn faces_mut(registry: &Self::Registry) -> core::cell::RefMut<'_, Registry> {
        registry.borrow_mut()
    }
}

/// One face of the session: the link it holds, and where the telling of the session's
/// declarations to that link's peer stands (`replay`).
struct Face<C: ClockSource + 'static, L: SessionLinks> {
    id: FaceId,
    link: Link<LinkSession<C>, L::Dial>,
    replay: Replay,
    /// What the connectivity listeners whose history is being replayed were told of the face, and
    /// the tomb of a row of it that went (`told`).
    #[cfg(feature = "connectivity")]
    told: FaceTold,
}

impl<C: ClockSource + 'static, L: SessionLinks> FaceRecord for Face<C, L> {
    type Session = LinkSession<C>;
    type Pump = L::Pump;
    type Dial = L::Dial;

    fn id(&self) -> FaceId {
        self.id
    }

    fn link(&self) -> &Link<LinkSession<C>, L::Dial> {
        &self.link
    }

    fn link_mut(&mut self) -> &mut Link<LinkSession<C>, L::Dial> {
        &mut self.link
    }
}

/// One link's half of the session: the actions that send over it. The task that runs the link,
/// the link itself and its owner's waits for it are the driver's ([`Wire`]).
struct LinkSession<C: ClockSource + 'static> {
    actions: SessionHandle<C>,
    /// The link's gates, whose admission is granted when the face is brought up (`bring_up`);
    /// until then the link gives the session nothing past its handshake, so the watchers hear the
    /// face come up before anything its link carried.
    #[cfg(feature = "listen")]
    gate: CellRc<LinkGate<C>>,
    /// The link's generation, which the queries it carries are answered under (`query`).
    #[cfg(feature = "queryable")]
    generation: u64,
}

impl<C: ClockSource + 'static> FaceSession for LinkSession<C> {
    fn established(&self) -> bool {
        self.actions.is_established()
    }

    /// The zid the link's peer announced, or the one its admission was asked about when the link
    /// was refused before it took the Init that carried it
    /// (`SessionLinkActions::link_admission_node`). A session that does not listen keeps no face
    /// for a node apart from its dial, and asks none.
    fn node(&self) -> Option<SessionZid> {
        #[cfg(feature = "listen")]
        {
            self.actions
                .peer_session_zid()
                .or_else(|| self.actions.link_admission_node())
        }
        #[cfg(not(feature = "listen"))]
        {
            None
        }
    }

    fn end(&self) {
        self.actions.send_close_with_reason(CloseReason::Generic);
    }

    fn close_reason(&self) -> Option<CloseReason> {
        self.actions.close_reason()
    }
}

impl<C: ClockSource + 'static> TransportSession<C> for LinkSession<C> {
    fn actions(&self) -> &SessionHandle<C> {
        &self.actions
    }

    #[cfg(feature = "queryable")]
    fn answers_as(&self, generation: u64) -> bool {
        self.generation == generation
    }
}

/// One link of the session: its session half ([`LinkSession`]) and what the driver holds of it.
type Wire<C> = wz_runtime_coop::faces::Wire<LinkSession<C>>;

/// Sleep `ms` milliseconds: what a read's wait with nothing to wait on does
/// ([`IdleWait::wait`]).
fn sleep_ms(ms: u32) {
    os::sleep_ms(ms.into());
}

/// One of the session's own subscribers, as a row of the session's tables holds it: the row keeps
/// its entity id, the pattern the subscriber matches, the declaration its key is named by, which
/// it holds, and what its retraction names, and this everything else the session knows of it, its
/// callback among it. The subscriber is that one row (`docs/c-abi-architecture.md`, P1), and so
/// is its callback's life (P11): a call is begun on the row's latch with the session held and made
/// after it, and an undeclared row is let go of by whoever sees its last call end.
pub(crate) struct SubscriberRow {
    /// What the ABI's key held besides the declaration the tables' row holds: the declaration the
    /// retraction names and an object of the ABI's, which go with the row, let go of with no lock
    /// of the session held.
    holds: WireHolds,
    /// The program's callback, called where the row lies: the tables lend their rows from the
    /// session's arena and never move one.
    sink: SubscriberSink,
    /// Whether the callback is shown each sample's timestamp (`entity-timestamp-opt-in`).
    expose: bool,
    /// How many calls of the callback run, and whether the subscriber was undeclared.
    latch: CallLatch,
}

/// A row of the session's own declarations whose key holds the session's declarations: taken out
/// of the tables, it is let go of with no lock of the session held, and what its key held comes
/// back from it, to give back to the session (`CoopEngine::give_back`). The holds are bare ids
/// of the session's count, which a dropped row would never give back, so every place a row leaves
/// the tables goes through this.
pub(crate) trait RowHolds {
    /// Let go of the row, its callback with it: what its key held.
    fn into_holds(self) -> WireHolds;
}

impl RowHolds for SubscriberRow {
    fn into_holds(self) -> WireHolds {
        self.holds
    }
}

impl SubscriberRow {
    /// A subscriber keeping `holds`, handing what it hears to `sink`, the timestamp shown when
    /// `expose`.
    // Out of line: measured smaller apart from the declaration that builds the row.
    #[inline(never)]
    pub(crate) fn new(holds: WireHolds, sink: SubscriberSink, expose: bool) -> Self {
        Self {
            holds,
            sink,
            expose,
            latch: CallLatch::new(),
        }
    }

    /// Hand `sample` to the callback, unless the subscriber was undeclared since the call was
    /// begun: the one place a sample is handed to a subscriber's callback.
    fn hand(&self, sample: &dyn SampleView) {
        if self.latch.retired() {
            return;
        }
        if self.expose {
            self.sink.call(sample);
        } else {
            self.sink.call(&HiddenTimestamp(sample));
        }
    }

    /// Declare subscriber `id`, the id its row in the tables holds, on `key`, over `actions`:
    /// whether the link took it.
    fn declare<C: ClockSource + 'static>(
        id: SubId,
        key: NamedKey<'_>,
        actions: &McuActions<C>,
    ) -> bool {
        actions
            .send_declare_subscriber(id, key_on_link(actions, key))
            .is_ok()
    }

    /// Retract subscriber `id` over `actions`, naming its key as `names` says (the declaration's
    /// id and the rest of the key) when its declaration asked to. Read off the row before it is
    /// undeclared: a row a call of which runs is kept out of every lookup until the call ends.
    fn retract<C: ClockSource + 'static>(
        id: SubId,
        names: Option<(ExprId, &str)>,
        actions: &McuActions<C>,
    ) {
        match names {
            Some((mapping, suffix)) => {
                actions.send_undeclare_subscriber_naming(u64::from(id), mapping, suffix)
            }
            None => actions.send_undeclare_subscriber(u64::from(id)),
        }
    }
}

// A call reads its row where it lies, so the rows lie in the session's arena, lent at its open,
// where no table moves them and the dispatch reads them only through a shared borrow.
const _: () = assert!(
    <Lent as wz_session_core::bounded::Storage>::LENT_AT_OPEN,
    "the session's tables lend their rows from its arena and never move one"
);

// A delivery ends a call with no lock of the session held; a target whose latch is ended only with
// the tables held has no atomic read-modify-write of a word, and so no `Arc` this engine is built on.
const _: () = assert!(
    !CallLatch::ENDS_HELD,
    "a call of a subscriber's callback ends with no lock held"
);

/// A call of a subscriber's callback, begun on its row's latch: where the row lies.
pub(crate) struct RowCall(NonNull<SubscriberRow>);

impl RowCallback for SubscriberRow {
    type Call = RowCall;

    const READS_ROW_IN_PLACE: bool = true;

    fn begin(&self) -> Option<RowCall> {
        self.latch.begin().then(|| RowCall(NonNull::from(self)))
    }

    unsafe fn end(call: RowCall) -> bool {
        // SAFETY: the caller's: the row has not moved since the call began and is still in its
        // table, which keeps it until its last call ended.
        unsafe { call.0.as_ref() }.latch.end()
    }

    fn retire(&self) -> bool {
        self.latch.retire()
    }

    fn drained(&self) -> bool {
        self.latch.drained()
    }
}

/// A call of a subscriber's callback the session began under its lock and a delivery makes after
/// it: where its row lies, and nothing else, since the row whose last call it ends is found by its
/// latch and not by a handle. Neither copied nor dropped unended: each is ended once
/// ([`Self::end`]), or its row would keep its slot for good.
#[must_use = "a call is ended, or its row is never let go of"]
pub(crate) struct SubscriberCall {
    call: RowCall,
}

impl SubscriberCall {
    /// `call`, begun on a subscriber's row.
    pub(crate) fn new(call: RowCall) -> Self {
        Self { call }
    }

    /// Hand `sample` to the row's callback.
    pub(crate) fn hand(&self, sample: &dyn SampleView) {
        // SAFETY: the row lies where the call began until its last call ended, and this one has
        // not; nothing writes a row's sink or its timestamp choice after it is declared.
        unsafe { self.call.0.as_ref() }.hand(sample);
    }

    /// End the call: `true` when it was the last call of an undeclared subscriber, whose row the
    /// session's walk of its tables then lets go of (`SessionTables::release_drained_subscriber`).
    pub(crate) fn end(self) -> bool {
        // SAFETY: the row lies where the call began (the tables never move a row, asserted above)
        // and keeps its slot until its last call ended, which this one is not yet; a call ends with
        // no lock held (asserted above).
        unsafe { <SubscriberRow as RowCallback>::end(self.call) }
    }
}

/// What the session's dispatch hands what a row of its tables matched to: a sample, the round of
/// deliveries, which holds a call begun on a subscriber's row until a delivery makes it with no
/// lock held; a query, the queryables' plane, which holds a call begun on a queryable's row until
/// the query is handed to its callback. The registry holds it and hands it to each dispatch, so no
/// row keeps a reference to either.
pub(crate) struct RoundDelivery {
    round: Arc<Round>,
    #[cfg(feature = "queryable")]
    plane: Arc<QueryPlane>,
}

impl RoundDelivery {
    /// Deliveries into `round`.
    #[cfg(not(feature = "queryable"))]
    fn new(round: Arc<Round>) -> Self {
        Self { round }
    }

    /// Deliveries into `round`, and queries into `plane`, which only the engine reaches.
    #[cfg(feature = "queryable")]
    fn new(round: Arc<Round>, plane: Arc<QueryPlane>) -> Self {
        Self { round, plane }
    }
}

impl SampleDelivery<SubscriberRow, SubscriberHandle> for RoundDelivery {
    fn deliver(
        &mut self,
        _id: SubscriberHandle,
        row: RowAccess<'_, SubscriberRow>,
        sample: &dyn SampleView,
        turn: FanOut,
    ) {
        // The row is read where it lies, shared with the calls of it a delivery makes on another
        // thread. One past the most calls one latch counts is handed nothing; an undeclared one is
        // in no lookup, so no dispatch reaches it.
        let Some(call) = RowCallback::begin(row.row()) else {
            return;
        };
        // SAFETY: the session's tables are dispatched under the session's lock, which only `Core`
        // holds, as the round's writer must.
        unsafe {
            self.round
                .offer_sample(SubscriberCall::new(call), sample, turn.is_first())
        };
    }
}

// The delivery traits are the rows': each names the context its row is told through, here the
// session's round of deliveries and its query plane.
#[cfg(feature = "liveliness")]
impl
    wz_session_core::declare::liveliness_subscriber::LivelinessDelivered<
        RoundDelivery,
        LivelinessSubscriberHandle,
    > for LivelinessRow
{
    fn tell(
        cx: &mut RoundDelivery,
        id: LivelinessSubscriberHandle,
        row: RowAccess<'_, LivelinessRow>,
        sample: LivelinessSample<'_>,
    ) {
        Self::tell_held(cx, id, row, sample, None);
    }

    fn tell_held(
        cx: &mut RoundDelivery,
        _id: LivelinessSubscriberHandle,
        row: RowAccess<'_, LivelinessRow>,
        sample: LivelinessSample<'_>,
        held: Option<&KeyRef>,
    ) {
        // As a subscriber's sample: the row is read where it lies, and one past the most calls
        // its latch counts is handed nothing.
        let Some(call) = RowCallback::begin(row.row()) else {
            return;
        };
        // SAFETY: the session's tables are dispatched under the session's lock, which only `Core`
        // holds, as the round's writer must.
        unsafe {
            cx.round
                .offer_liveliness(LivelinessCall::new(call), &sample, held)
        };
    }
}

#[cfg(feature = "queryable")]
impl wz_session_core::query::QueryDelivered<RoundDelivery, QueryableHandle> for QueryableRow {
    fn ask(
        cx: &mut RoundDelivery,
        _id: QueryableHandle,
        row: RowAccess<'_, QueryableRow>,
        query: &ProvenQuery<'_>,
        _responder: &mut QueryResponder<'_>,
    ) {
        // The callback is the program's and never runs under the session's lock: the query is
        // held for it with a call begun on its row, read where it lies, and the replies it makes
        // go out through a responder of the plane's own.
        // SAFETY: the session's tables are dispatched under the session's lock, which only `Core`
        // holds, as the plane's arrival asks.
        unsafe {
            cx.plane
                .arrive(&cx.round, || QueryableCall::begin(row.row()), query)
        };
    }
}

/// `wire` as the link of `actions` names the key `keyexpr`: the link's key-wire form decides,
/// and the declared form keeps `wire` as the ABI made it (`shared-key-ids`). Only a get and a
/// liveliness subscriber's Interest name their key by the ABI's form still.
#[cfg(all(
    feature = "shared-key-ids",
    any(feature = "query", feature = "liveliness", feature = "liveliness-get")
))]
fn on_link<'w, C: ClockSource + 'static>(
    actions: &McuActions<C>,
    keyexpr: &str,
    wire: &'w WireKey,
) -> wz_capi_port::LinkKey<'w> {
    match wz_capi_port::wire_on_link(actions.key_wire_on_link(keyexpr)) {
        Some(linked) => wz_capi_port::LinkKey::Made(linked),
        None => wz_capi_port::LinkKey::Lent(wire),
    }
}

/// `key` as the link of `actions` names it: the link's key-wire form decides, and the declared
/// form keeps `key` as the session names it (`shared-key-ids`).
#[cfg(feature = "shared-key-ids")]
fn key_on_link<'k, C: ClockSource + 'static>(
    actions: &McuActions<C>,
    key: NamedKey<'k>,
) -> NamedKey<'k> {
    actions.named_on_link(key)
}

/// A build without the shared key ids names every key on every link as the session names it.
#[cfg(not(feature = "shared-key-ids"))]
#[inline(always)]
fn key_on_link<'k, C: ClockSource + 'static>(
    _actions: &McuActions<C>,
    key: NamedKey<'k>,
) -> NamedKey<'k> {
    key
}

/// A build without the shared key ids names every key on every link as the ABI made it.
#[cfg(all(
    not(feature = "shared-key-ids"),
    any(feature = "query", feature = "liveliness", feature = "liveliness-get")
))]
#[inline(always)]
fn on_link<'w, C: ClockSource + 'static>(
    _actions: &McuActions<C>,
    _keyexpr: &str,
    wire: &'w WireKey,
) -> wz_capi_port::LinkKey<'w> {
    wz_capi_port::LinkKey::Lent(wire)
}

/// How the link of `actions` names the key `keyexpr` of an Interest that asks aggregated as
/// `aggregate` says: by the link's key-wire form, as `on_link` names the key of a put or a
/// declaration; `None` for a link of the declared form, which names it as the Interest's row does
/// (`shared-key-ids`).
#[cfg(feature = "shared-key-ids")]
fn interest_on_link<C: ClockSource + 'static>(
    actions: &McuActions<C>,
    keyexpr: &str,
    aggregate: bool,
) -> Option<InterestForm> {
    // The link's form reads only whether the Interest aggregates; the rest is the link's own.
    let asked = InterestForm {
        mapping_id: 0,
        suffix: None,
        aggregate,
    };
    wz_capi_port::interest_on_link(actions.key_wire_on_link(keyexpr), keyexpr, &asked)
}

/// A build without the shared key ids names the key of every Interest as its row does.
#[cfg(not(feature = "shared-key-ids"))]
#[inline(always)]
fn interest_on_link<C: ClockSource + 'static>(
    _actions: &McuActions<C>,
    _keyexpr: &str,
    _aggregate: bool,
) -> Option<InterestForm> {
    None
}

/// Send the Interest `row` holds open over `actions`, for what is declared now and what is
/// declared later, naming its key as the link's key-wire form says: whether the link took it.
fn send_interest<K: KeyBacking, C: ClockSource + 'static>(
    row: &InterestRow<K>,
    actions: &McuActions<C>,
) -> bool {
    let linked = interest_on_link(actions, row.key(), row.aggregate());
    let (mapping_id, suffix) = match &linked {
        Some(form) => (form.mapping_id, form.suffix.as_deref()),
        None => (row.mapping_id(), row.suffix()),
    };
    actions
        .send_interest_kinds(
            u64::from(row.id()),
            wz_session_core::session_actions::InterestAsk {
                kinds: kinds(row.kind()),
                current: true,
                future: true,
                aggregate: row.aggregate(),
            },
            mapping_id,
            suffix,
        )
        .is_ok()
}

/// Where the Interest `handle` names lies among the Interests the replay tells, in the table's slot
/// order: read while it stands, for its Final's place once it is let go of.
fn interest_rank(tables: &CoopTables, handle: Option<InterestHandle>) -> Option<usize> {
    tables.interests().rank_of(handle?)
}

/// Take the write filter `handle` names out of `tables`, with the listeners declared on it, let go
/// of there: the id of the Interest it held last, `None` when no filter is there. Every caller
/// passes this one closure, so the tables' walk is built once.
fn unwatch_filter(tables: &mut CoopTables, handle: WriteFilterHandle) -> Option<Option<EntityId>> {
    tables
        .undeclare_write_filter(handle, |_, _| {})
        .map(|unwatched| unwatched.interest_final)
}

/// Whether the session's own entities of `plane`'s kind count for a write filter or a matching
/// listener: only for one that asked them to, and in a build that delivers to them locally.
fn counts_own(plane: FilterPlane, count_local: bool) -> bool {
    let delivers_locally = match plane {
        FilterPlane::Subscribers => cfg!(feature = "local-subscriber"),
        FilterPlane::Queryables { .. } => cfg!(feature = "local-queryable"),
    };
    delivers_locally && count_local
}

/// What tells a link that the key expression declaration `mapping_id` is retracted: one closure type
/// for every caller that sends it, so its body and its call through `&dyn TellTo` are made once.
/// Whether the batch window of the link of `actions` took `step`. Out of line, so the walk over
/// the links that asks each is one loop: with the step's match inlined in it, the compiler writes
/// the walk out once per step.
#[inline(never)]
fn batch_link<C: ClockSource + 'static>(actions: &McuActions<C>, step: BatchStep) -> bool {
    match step {
        BatchStep::Start => actions.batch_start(),
        BatchStep::Flush => actions.batch_flush(),
        BatchStep::Stop => actions.batch_stop(),
    }
    .is_ok()
}

fn undeclare_kexpr<C: ClockSource + 'static>(mapping_id: ExprId) -> impl Fn(&McuActions<C>) {
    move |actions| actions.send_undeclare_kexpr(mapping_id)
}

/// What tells a link that the Interest `id` ends, one closure type for every caller as
/// [`undeclare_kexpr`] is.
fn interest_final<C: ClockSource + 'static>(id: u64) -> impl Fn(&McuActions<C>) {
    move |actions| actions.send_interest_final(id)
}

/// What a get answers when its session closes while its legs are issued: the legs issued so far,
/// which the close has ended, or the close itself when it came before the first.
#[cfg(any(feature = "query", feature = "liveliness-get"))]
fn issued_so_far(issued: usize) -> Result<usize, Declined> {
    if issued == 0 {
        Err(Declined::Closed)
    } else {
        Ok(issued)
    }
}

/// The deadline of a leg asked at `now_us` that waits `timeout_ms`, in milliseconds on the
/// session's clock, rounded up so a sweep that reads whole milliseconds never ends the leg before
/// its timeout. A clock of microseconds read in milliseconds leaves room past it for any timeout a
/// `u32` states, so the sum does not saturate.
#[cfg(any(feature = "query", feature = "liveliness-get"))]
fn leg_deadline_ms(now_us: u64, timeout_ms: u32) -> u64 {
    now_us.div_ceil(1000).saturating_add(u64::from(timeout_ms))
}

/// What every leg of one get is held pending with (`CoopEngine::hold_leg`): the key it was asked
/// under, its options, whether its callbacks show a reply's timestamp, and the mint of each leg's
/// callback.
#[cfg(feature = "query")]
struct LegAsk<'a, 'o> {
    keyexpr: &'a str,
    opts: &'a QueryOptionsOf<'o>,
    expose: bool,
    mint: &'a mut dyn FnMut() -> ReplyCallback,
}

/// What came of holding a leg of a get pending (`CoopEngine::hold_leg`).
#[cfg(feature = "query")]
enum LegHeld {
    /// Held, owed its Finals: its request may go out.
    Held,
    /// The table is no longer the session's: the leg is asked of nobody.
    Gone,
    /// No row of the table, or of the plane's callbacks, was free: no callback was minted.
    NoRoom,
    /// The table refused the registration, `table_full` when for want of a row: the leg's minted
    /// callback is to be let go of with no lock held.
    Refused { table_full: bool },
}

/// A group member's key (`SessionEngine::next_group_member`): its group's place in the session's
/// groups in the high half, its place in the group's member table in the low one, so the keys
/// order by group first. Each half is a `u32`, so the two never overlap.
#[cfg(feature = "group")]
fn member_key(group: u32, member: u32) -> u64 {
    let [g0, g1, g2, g3] = group.to_be_bytes();
    let [m0, m1, m2, m3] = member.to_be_bytes();
    u64::from_be_bytes([g0, g1, g2, g3, m0, m1, m2, m3])
}

/// The group's place and the member's place a key is made of (`member_key`).
#[cfg(feature = "group")]
fn member_places(key: u64) -> (u32, u32) {
    let [g0, g1, g2, g3, m0, m1, m2, m3] = key.to_be_bytes();
    (
        u32::from_be_bytes([g0, g1, g2, g3]),
        u32::from_be_bytes([m0, m1, m2, m3]),
    )
}

/// The engine's mutex, held until the guard drops; one poisoned by a panic is recovered, since
/// every critical section here leaves its value consistent ([`os::Mutex::lock`]).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock()
}

/// The port's mutex, as the lock the session core's planes keep their state under and the queues
/// the deliveries drain sit behind: the query plane's (every build, `PlaneCalls::Queues`), the
/// faces' watchers (`connectivity`) and the gets' queues (`query`).
pub(crate) enum CoopLocks {}

impl wz_session_core::plane_lock::LockFamily for CoopLocks {
    type Lock<T> = Mutex<T>;

    fn new<T>(value: T) -> Mutex<T> {
        Mutex::new(value)
    }

    fn with<T, R>(lock: &Mutex<T>, f: impl FnOnce(&mut T) -> R) -> R {
        f(&mut lock.lock())
    }
}

/// Whether this build holds what a matching listener or a write filter of `plane` counts: the
/// subscribers a peer declares in every build, and the queryables with a querier or a queryable
/// (`query`, `queryable`). One of a plane the build does not hold is refused before anything is
/// asked, as one the session has no row for is: there is no table to count it with.
const fn counts(plane: FilterPlane) -> bool {
    match plane {
        FilterPlane::Subscribers => true,
        FilterPlane::Queryables { .. } => cfg!(any(feature = "query", feature = "queryable")),
    }
}

/// What an Interest of `kind` asks the peer about, an Interest held per kind and key.
fn kinds(kind: InterestKind) -> InterestKinds {
    match kind {
        InterestKind::Subscribers => InterestKinds::SUBSCRIBERS,
        InterestKind::Queryables => InterestKinds::QUERYABLES,
    }
}

/// What one send's failure means for a publish: a link that is down skips it, anything else is
/// a message no link could have carried.
fn leg_outcome(result: Result<(), SendWireError>) -> Result<usize, FanoutError> {
    match result.map_err(PublishError::from) {
        Ok(()) => Ok(0),
        Err(PublishError::TransportUnavailable | PublishError::RequiresUnicast) => Ok(0),
        // The link's queue profile dropped the put behind a held conduit and says so: the other
        // links are still sent it, and the publish is answered as dropped.
        Err(PublishError::HeldConduit) => Err(FanoutError::HeldConduit),
        Err(_) => Err(FanoutError::ExceedsCapacity),
    }
}

/// The lane told, while a link's record is dispatched, that what is offered waited for room
/// ([`Round::offering_gated`]), and told otherwise again when the dispatch is done, or
/// unwinds. Only a debug build checks the gate's bound by it; it is told without the lane's lock,
/// so a debug build's dispatch takes the lock as often as a release build's.
#[cfg(debug_assertions)]
struct Gated<'a>(&'a Round);

#[cfg(debug_assertions)]
impl<'a> Gated<'a> {
    fn over(lane: &'a Round) -> Self {
        lane.offering_gated(true);
        Self(lane)
    }
}

#[cfg(debug_assertions)]
impl Drop for Gated<'_> {
    fn drop(&mut self) {
        self.0.offering_gated(false);
    }
}

/// Whether `event` is a Push lent where its frame lies: what the subscribers' plane alone reads, so
/// a link's dispatch hands it there and to no other plane (`Registry::dispatch_push`).
fn lent_push(event: &wz_session_core::driver_loop::IterationEvent<'_, '_>) -> bool {
    matches!(
        event,
        wz_session_core::driver_loop::IterationEvent::InPlace(record) if record.push().is_some()
    )
}

/// The `on_event` of a link's session: the registry's dispatch for the face the link serves. A
/// value of a type that can be named, so the task the link's session runs as can be
/// (`RouterSessionTask`), and the runtime reserves its cells at the open in the bytes that task
/// takes (`link_task_bytes`).
///
/// With `queryable` the session answers queries outside its lock: the `ResponseFinal`s the
/// dispatch owes are held back for the queries a callback is still to answer, and everything else
/// it staged (the replies of a queryable that answers in place, declare replies, get prunes) goes
/// out at once. Without it everything the dispatch staged goes out at once.
pub(crate) struct FaceDispatch<C: ClockSource + 'static> {
    registry: Rc<RefCell<Registry>>,
    /// The face the link serves, its set found by its place for every frame and not looked for.
    face: HeldFace,
    actions: SessionHandle<C>,
    #[cfg(feature = "queryable")]
    plane: Arc<QueryPlane>,
    /// The link's generation, which the queries it carries are answered under.
    #[cfg(feature = "queryable")]
    generation: u64,
    /// The session's round of deliveries: told where a rejoined message lies while its records are
    /// dispatched, and, in a debug build, that what is offered waited for room (`Gated`).
    lane: Arc<Round>,
}

impl<C: ClockSource + 'static> EventSink for FaceDispatch<C> {
    #[cfg(feature = "queryable")]
    fn event(&mut self, event: IterationEvent<'_, '_>) {
        #[cfg(debug_assertions)]
        let _gated = Gated::over(&self.lane);
        let face = self.face;
        let actions = &*self.actions;
        let mut registry = self.registry.borrow_mut();
        // A Push is no query and no declaration: it is handed to the subscribers alone, and what
        // follows every record (the drains, the Finals owed) under the one lookup of the face.
        let owed = if lent_push(&event) {
            registry.dispatch_push(face, event, actions)
        } else {
            // The queries this frame carries arrive on this face's link, whichever was dialled
            // last.
            self.plane.set_arriving(self.generation);
            // A query by an id of the shared dictionary is kept, so its replies mirror its key
            // form.
            #[cfg(feature = "shared-key-ids")]
            actions.note_requests(&event);
            // What the declaration watches are told of this frame is this link's peer's.
            #[cfg(any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ))]
            registry.hear_decl_link(|| actions.peer_session_zid());
            registry.dispatch_event(face, event);
            registry.flush_pending_replies(face, actions);
            registry.take_pending_final_rids(face)
        };
        for (rid, qos) in owed {
            if self
                .plane
                .with_holds(|holds| holds.owe(self.generation, rid, qos))
            {
                actions.send_response_final(rid, qos);
            }
        }
    }

    #[cfg(not(feature = "queryable"))]
    fn event(&mut self, event: IterationEvent<'_, '_>) {
        #[cfg(debug_assertions)]
        let _gated = Gated::over(&self.lane);
        let face = self.face;
        let actions = &*self.actions;
        let mut registry = self.registry.borrow_mut();
        // A Push is no query and no declaration: it is handed to the subscribers alone.
        if lent_push(&event) {
            registry.dispatch_push(face, event, actions);
            return;
        }
        // What the declaration watches are told of this frame is this link's peer's.
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        registry.hear_decl_link(|| actions.peer_session_zid());
        registry.dispatch(face, event, actions);
    }

    /// A rejoined message's records are read where its chain's buffer lies, which the round keeps
    /// for as long as it holds them.
    fn lend_rejoined(&mut self, message: &wz_session_core::byte_cells::KeptBytes) {
        // SAFETY: a link's records are dispatched by the session's step, under the session's lock.
        unsafe { self.lane.lend_rejoined(message) };
    }

    fn end_rejoined(&mut self, message: wz_session_core::byte_cells::KeptBytes) {
        // SAFETY: as `lend_rejoined`.
        unsafe { self.lane.end_rejoined(message) };
    }
}

/// The gates a link's pump runs behind on this engine, for a session on the clock `C`, which the
/// session places in the link's cell of its table (`TransportState::gate_cells`): the round's, and with
/// `listen` the admission's under it, which carries the clock.
trait LinkGates {
    /// The gates.
    type Gate;
}

impl<C: ClockSource + 'static> LinkGates for C {
    #[cfg(feature = "listen")]
    type Gate = RoundGate<AdmissionGate<CellRc<dyn SessionDatagramLink>, C>>;
    #[cfg(not(feature = "listen"))]
    type Gate = RoundGate<CellRc<dyn SessionDatagramLink>>;
}

/// The gates of a link of a session on the clock `C` ([`LinkGates`]).
type LinkGate<C> = <C as LinkGates>::Gate;

/// The two halves the actions of a link of a session on the clock `C` hold, which the session
/// places together in the link's cell of its table (`TransportState::halves_cells`): the link's
/// own state and the session's kernel.
type LinkHalves<C> = (
    LinkState<CoopRuntime<C>>,
    SessionCore<CoopRuntime<C>, CoopTime<C>>,
);

/// The bytes of each link's cells a session over `links` on the clock `C` lays out: a cell for
/// each link's driver as large as the largest the links open, one for its gates, one for its
/// actions and one for the two halves they hold.
pub(crate) fn link_cells<C: ClockSource + 'static>(links: &impl SessionLinks) -> LinkCells<usize> {
    LinkCells {
        driver: links.link_cell_bytes(),
        gate: CellRc::<LinkGate<C>>::cell_bytes(),
        actions: CellRc::<McuActions<C>>::cell_bytes(),
        halves: CellRc::<LinkHalves<C>>::cell_bytes(),
    }
}

/// Lay out on `plan`, the rows an open's limits size ([`ArenaPlan::count`]), the cells `cells` sizes
/// for each link and then the ABI's places `held` names, after every other row: the one plan an
/// open reserves by. Laid out where the plan lies, which `lend_session` reads in its own frame: a
/// plan handed back by value would be moved again, twice, by the open that reads it.
pub(crate) fn lay_out_open(
    plan: &mut ArenaPlan,
    cells: LinkCells<usize>,
    held: &HeldPlaces,
) -> Result<(), ArenaRefused> {
    plan.holding_cells(cells)?;
    plan.holding(held)
}

/// The bytes of the task a link's session runs as on this engine: `RouterSessionTask` over the
/// link's gates, the place the session lends its one reassembly Router in and `FaceDispatch`.
/// What each cell the open reserves for a link holds, so a link's session is never refused a cell
/// for its size.
pub(crate) const fn link_task_bytes<C: ClockSource + 'static>() -> usize {
    router_session_task_bytes::<
        C,
        CellRc<dyn SessionDatagramLink>,
        RouterLend<SessionReassembly>,
        RouterLend<SessionReassembly>,
        FaceDispatch<C>,
    >()
}

/// The waits a read of a session `config` opens makes at once, reserved at its open so that none
/// grows after it: the link of each face the session may hold (the dial role's and each one
/// `max_faces` admits, accepted or attached after the open), each port, each group, and the
/// clock's word waited on beside them.
pub(crate) fn read_wait_room(config: &CoopConfig<impl EndpointList>) -> usize {
    config
        .max_faces
        .saturating_add(2)
        .saturating_add(config.listen.count())
        .saturating_add(config.groups.len())
}

/// What a session's runtime reserves when the session opens (`Self::runtime`), from the build's
/// limits and the faces its config admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeTables {
    /// Reserved at once: a task cell for each face the session may hold at once (the dial role's
    /// when it dials, and each `max_faces` admits, a link in its handshake among them: a link
    /// taken off a port past them is closed before it has a task), in the bytes a link's session task takes
    /// (`link_task_bytes`), and `MAX_TIMERS` deadlines.
    pub(crate) rows: RuntimeRows,
    /// The cells the open may add, one for each group it joins: a group's task is a future no
    /// type names, so its cell takes the bytes the task has when the open spawns it.
    pub(crate) groups: usize,
}

impl RuntimeTables {
    /// The tables of a session `config` opens, its task cells together at most the build's
    /// `MAX_TASKS`: the groups' first, as a session that cannot join a group it was told to does
    /// not open, then the links', so a face past them is refused as one past `max_faces` is.
    pub(crate) fn of<C: ClockSource + 'static>(config: &CoopConfig<impl EndpointList>) -> Self {
        let groups = config.groups.len().min(caps::MAX_TASKS);
        let links = usize::from(crate::arena::dials(config))
            .saturating_add(config.max_faces)
            .min(caps::MAX_TASKS.saturating_sub(groups));
        Self {
            rows: RuntimeRows {
                tasks: links,
                task_bytes: link_task_bytes::<C>(),
                timers: caps::MAX_TIMERS,
            },
            groups,
        }
    }

    /// The runtime these tables are reserved for. A build that joins groups reserves the links'
    /// cells and holds a bare cell for each group, given the bytes the group's task needs when the
    /// open spawns it, and sealed once the open is over (`open_links`). A build that joins none
    /// reserves every cell for a link, and its runtime takes no memory after it is made: a config
    /// that names a group is refused by name there, so the groups' cells are none.
    pub(crate) fn runtime<C: ClockSource>(self, clock: C) -> CoopRuntime<C> {
        #[cfg(feature = "group")]
        {
            CoopRuntime::opening(clock, self.rows, self.groups)
        }
        #[cfg(not(feature = "group"))]
        {
            CoopRuntime::reserved(
                clock,
                RuntimeRows {
                    tasks: self.rows.tasks.saturating_add(self.groups),
                    ..self.rows
                },
            )
        }
    }
}

/// The session's part in the making of each of its links' sessions (`LinkCalls`): what its tables
/// are told of a link, the gates it puts the link behind, and what the link's task hands its reads
/// to.
struct LinkMaking<'a> {
    session: &'a SessionState,
    /// The limits the session was opened with.
    limits: &'a SessionLimits,
}

impl<C: ClockSource + 'static> LinkCalls<C> for LinkMaking<'_> {
    type Gate = LinkGate<C>;
    type Dispatch = FaceDispatch<C>;
    type Session = LinkSession<C>;

    fn link_made(&self, face: FaceId, actions: &SessionHandle<C>, key_form: Option<KeyWireForm>) {
        // The session keeps its declarations in its one table set and names each key it sends
        // itself, so the link keeps none and reads none; what the peer sends by the session's
        // ids is read from the same tables, which the dispatch of every face reads.
        actions.keep_no_keyexprs();
        // The answer the face's session gives a query of its peer whose key it cannot resolve:
        // the session's policy, stated for each link the face is opened over.
        self.session
            .registry
            .borrow_mut()
            .set_unanswerable_final(face, actions.params.policy.query_unanswerable_final());
        // The key ids every node shares, on both sides of the link before it carries anything:
        // the link's actions, with the key-wire form stated for the endpoint it was dialled to or
        // taken on, so what is sent over it names its keys in that form, and the face's tables,
        // so an id of the dictionary the peer sends is read.
        #[cfg(feature = "shared-key-ids")]
        if let Some(key_form) = key_form {
            actions.install_link_keys(wz_session_core::shared_key_ids::LinkKeys::new(
                self.session.key_ids.clone(),
                key_form,
                self.limits.link_noted_requests(),
            ));
            if let Some(ids) = &self.session.key_ids {
                self.session
                    .registry
                    .borrow_mut()
                    .install_shared_key_ids(face, ids.clone());
            }
        }
        #[cfg(not(feature = "shared-key-ids"))]
        let _ = key_form;
    }

    fn gate(
        &self,
        pump: CellRc<dyn SessionDatagramLink>,
        actions: &SessionHandle<C>,
    ) -> LinkGate<C> {
        // The session is handed a record of a link only while its round of deliveries has the room
        // one record can take (decision Q4), and with `listen` only once the engine admitted it:
        // the link gives the session nothing between its handshake and the face table's decision
        // (`admit`), so a link that is refused has put nothing in the tables.
        let record_room = crate::round::read_room::<
            { caps::MAX_SUBSCRIPTIONS },
            { caps::MAX_LIVELINESS_SUBSCRIPTIONS },
        >(self.limits);
        #[cfg(feature = "listen")]
        {
            // SAFETY: a link is made under the session's lock, and its gate asked by the step
            // alone.
            unsafe {
                RoundGate::new(
                    AdmissionGate::new(pump, actions.clone()),
                    self.session.lane.clone(),
                    record_room,
                )
            }
        }
        #[cfg(not(feature = "listen"))]
        {
            let _ = actions;
            // SAFETY: a link is made under the session's lock, and its gate asked by the step
            // alone.
            unsafe { RoundGate::new(pump, self.session.lane.clone(), record_room) }
        }
    }

    fn wire_parts(
        &self,
        face: FaceId,
        actions: SessionHandle<C>,
        gate: &CellRc<LinkGate<C>>,
    ) -> (FaceDispatch<C>, LinkSession<C>) {
        #[cfg(feature = "queryable")]
        let generation = self.session.plane.next_generation();
        let dispatch = FaceDispatch {
            registry: self.session.registry.clone(),
            // The registry holds the face before its link is made (`Registry::add_face`).
            face: self.session.registry.borrow().held(face),
            actions: actions.clone(),
            #[cfg(feature = "queryable")]
            plane: self.session.plane.clone(),
            #[cfg(feature = "queryable")]
            generation,
            lane: self.session.lane.clone(),
        };
        // The wire keeps a handle on the gates to admit the link through them.
        #[cfg(not(feature = "listen"))]
        let _ = gate;
        (
            dispatch,
            LinkSession {
                actions,
                #[cfg(feature = "listen")]
                gate: gate.clone(),
                #[cfg(feature = "queryable")]
                generation,
            },
        )
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> Core<L, C> {
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
        endpoint: Option<&DialEndpoint>,
    ) -> Result<Wire<C>, OpenError> {
        let wire = self.start_wire(face, opened, role, endpoint)?;
        self.run_tasks();
        Ok(wire)
    }

    /// [`Self::open_wire`] up to the first step of the task: the link's session, its gates and its
    /// task made, and the task spawned. Never inlined, for the stack: what is built here (the
    /// session's parameters moved into its actions, the gates over the link, the task's closure)
    /// lies in this frame alone, which has returned before the task first runs, so the frame of
    /// the caller the session's first steps run under (a dial, a face's poll) holds only the wire
    /// handed back.
    #[inline(never)]
    fn start_wire(
        &mut self,
        face: FaceId,
        opened: OpenedLink<L::Pump>,
        role: SessionRole,
        endpoint: Option<&DialEndpoint>,
    ) -> Result<Wire<C>, OpenError> {
        // The cookie key of the attempt is drawn before the parameters are read off the config:
        // drawn among them, its refusal would leave every field read before it in a temporary
        // of its own, moved again into the parameters once the key is there.
        let cookie_signing_key = SigningKey::from_entropy(&mut self.entropy)
            .map_err(|_| OpenError::EntropyUnavailable)?;
        // The parameters the tokio engine gives a session (`wz-capi-core`'s `init_params`), with a
        // cookie key of its own per attempt.
        let params = SessionInitParams {
            whatami: self.config.whatami,
            zid: self.transport.wire_zid,
            seq_num_res: self.config.sn_resolution.wire_code(),
            req_id_res: 2,
            batch_size: self.config.batch_size,
            lease_ms: self.config.lease_ms,
            keep_alive: self.config.keep_alive,
            initial_sn: 0,
            cookie: Default::default(),
            tx_queue: self.config.tx_queue,
            link_rx: self.config.link_rx,
            policy: self.policy,
            // The snapshot the registry's tables were held to: the open decides it from the
            // config alone.
            limits: *resolve_limits(&self.config),
            cookie_signing_key,
            region: None,
        };
        // The link's session is the transport's to make; what the session's tables keep of the
        // link, its gates and what its task hands its reads to are the session's (`LinkMaking`).
        let calls = LinkMaking {
            session: &self.session,
            limits: resolve_limits(&self.config),
        };
        self.transport
            .make_wire(
                &calls,
                face,
                opened,
                role,
                endpoint,
                WireMaking {
                    params,
                    local: &self.local,
                    entropy: &mut self.entropy,
                    clock: &self.session_time,
                    timeouts: self.config.timeouts,
                },
            )
            .map_err(OpenError::from)
    }

    /// When a handshake begun now is given up, in microseconds on the session's clock.
    fn open_deadline_us(&self) -> u64 {
        self.clock
            .now_us()
            .saturating_add(self.config.open_timeout_ms.saturating_mul(1000))
    }

    /// Start a handshake with the first endpoint, from index `from` on, that a link opens to, as
    /// the dial role's face, at `at` in the face table, which holds the link from then on. `Err`
    /// with the reason the last endpoint tried gave (`last` when none is), or with
    /// [`OpenError::EntropyUnavailable`] when the platform gives no cookie key for the attempt;
    /// the face keeps the link it held then.
    ///
    /// A dial the network has not answered yet is left under way (`Link::Dialing`), and the steps
    /// that follow ask it (`Self::dial_answered`), so no dial is waited for while the session is
    /// held; one answered at once runs its handshake here. The dial names its endpoint by its
    /// row of the session's endpoint texts, which holds the text.
    ///
    /// The link is put in its face where it is made, and not handed back: the link is the
    /// largest value of the dial, and each caller that put it would move it once more.
    fn dial_from(
        &mut self,
        at: usize,
        mut from: usize,
        mut last: OpenError,
    ) -> Result<(), OpenError> {
        // Which row is dialled next is the transport's walk to say; each turn moves `from` past
        // the row it handed back, so the walk ends.
        loop {
            let walked = self.transport.walk_dials(from, &mut last);
            let deadline_us = self.open_deadline_us();
            match walked {
                DialWalk::Dialing { dial, next } => {
                    self.transport.links.put_link(
                        at,
                        Link::Dialing {
                            dial,
                            next,
                            deadline_us,
                        },
                    );
                    return Ok(());
                }
                DialWalk::Answered {
                    endpoint,
                    next,
                    answer,
                } => {
                    match self.dial_answered(
                        at,
                        DIAL_FACE,
                        Some(&endpoint),
                        next,
                        deadline_us,
                        answer,
                    ) {
                        Ok(()) => return Ok(()),
                        // Neither is the endpoint's: the next one would be refused the same.
                        Err(refused @ (OpenError::EntropyUnavailable | OpenError::NoTask(_))) => {
                            return Err(refused)
                        }
                        Err(refused) => {
                            last = refused;
                            from = next;
                        }
                    }
                }
                DialWalk::Ended => return Err(last),
            }
        }
    }

    /// The dial of `endpoint` that face `face`, at `at` in the face table, made answered: its
    /// link's handshake begun and put in the face, given up at `deadline_us` as the dial was, the
    /// dial role's going on from endpoint `next` after it. [`OpenError::Unreachable`] when the
    /// dial was refused, [`OpenError::EntropyUnavailable`] when the platform gives no cookie key
    /// for the attempt; the face keeps the link it held then.
    fn dial_answered(
        &mut self,
        at: usize,
        face: FaceId,
        endpoint: Option<&DialEndpoint>,
        next: usize,
        deadline_us: u64,
        answer: Result<OpenedLink<L::Pump>, LinkOpenError>,
    ) -> Result<(), OpenError> {
        let opened = self.transport.dialled(endpoint, answer)?;
        let wire = self.open_wire(face, opened, SessionRole::Initiator, endpoint)?;
        self.transport.links.put_link(
            at,
            Link::Opening {
                wire,
                next,
                deadline_us,
            },
        );
        Ok(())
    }

    /// Dial from endpoint `from` on; when none answers, wait `redial_ms` to dial them all again,
    /// or end with the last endpoint's reason when the session redials none.
    ///
    /// The wait is counted from the end of the dials, read from the clock after them. A dial
    /// blocks the read step, which holds the session, and a host may refuse one only after
    /// retries of its own (a refused loopback connect takes about two seconds on Windows): a wait
    /// counted from before the dials would then already be over, the next read would dial again at
    /// once, and the session would be held through dial after dial with no room for a publish or
    /// a close to take it.
    /// The face at `at` holds the dial's link, or the wait; it keeps the link it held when the
    /// session ends instead.
    /// Out of line: four arms of `poll_face` dial or wait, and one body serves them.
    #[inline(never)]
    fn dial_or_wait(
        &mut self,
        at: usize,
        from: usize,
        last: OpenError,
        redial_ms: Option<u64>,
    ) -> Result<(), OpenError> {
        match (self.dial_from(at, from, last), redial_ms) {
            (Ok(()), _) => Ok(()),
            (Err(OpenError::EntropyUnavailable), _) => Err(OpenError::EntropyUnavailable),
            (Err(last), None) => Err(last),
            (Err(_), Some(ms)) => {
                let ended_us = self.now_us();
                self.transport.links.put_link(
                    at,
                    Link::Waiting {
                        at_us: ended_us.saturating_add(ms.saturating_mul(1000)),
                    },
                );
                Ok(())
            }
        }
    }

    /// Move every face's link on, after the session was stepped, against the step's reading of the
    /// clock, `now_us`; see [`Self::poll_face`]. `Err` when the session ends, which only the dial
    /// role's face can bring about.
    fn poll_links(&mut self, redial_ms: Option<u64>, now_us: u64) -> Result<(), OpenError> {
        // The connections that arrived come first, so their handshakes are moved on in this pass.
        #[cfg(feature = "listen")]
        self.accept_links();
        // A group whose link was lost is let go of, and joined again when its time comes.
        #[cfg(feature = "group")]
        self.poll_groups(redial_ms);
        // From the last face to the first: a face that is gone is removed, which moves none of the
        // ones before it.
        for at in (0..self.transport.links.places()).rev() {
            self.poll_face(at, redial_ms, now_us)?;
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
    ///
    /// What became of the link, and what the session does about it, is the face's value to say
    /// (`wz_runtime_coop::face_life`); the link stays in its face while that is done here.
    fn poll_face(
        &mut self,
        at: usize,
        redial_ms: Option<u64>,
        now_us: u64,
    ) -> Result<(), OpenError> {
        let now_ms = now_us / 1000;
        let Some(face) = self.transport.links.face(at) else {
            return Ok(());
        };
        let id = face.id;
        // A link that is up goes on telling its peer what the session holds, when a turn is due.
        // A turn the replay is given up on (a refused send, at once without a pace or when the
        // pace says so) ends the link here, with no Close, as
        // zenoh-pico clears a transport its reopen could not send its declarations over
        // (`vendor/zenoh-pico/src/net/session.c` @ `_z_transport_clear(&s->_tp);`); the driver
        // then finds it lost, so the dial role's face dials again and tells everything over the
        // next link, and any other face goes.
        let up = match &face.link {
            Link::Up(wire) if !wire.finished() => Some(wire.actions.clone()),
            _ => None,
        };
        if let Some(actions) = up {
            if self.replay_turn(at, &actions, now_ms) == TurnEnd::EndsLink {
                self.transport.links.abort_link(at);
                self.run_tasks();
            }
        }
        // What became of the link is the face's value's to say (`FaceLife`), from what the
        // transport reads of the link here, the face's role among it; carrying it out is the
        // session's.
        let step = self
            .transport
            .face_step(at, id, redial_ms.is_some(), now_us);
        self.carry_out(at, step, redial_ms, now_us)
    }

    /// Carry out what the face at `at` does at a step (`step`): what its value decided, with the
    /// answer of its dial when one was asked and the endpoint of a dial that is over, read where
    /// the step holds it. The session's part of its value's decision. `Err` when the session
    /// ends: the dial role's link was lost, or no endpoint answered, and `redial_ms` is `None`;
    /// or the platform gave no entropy.
    fn carry_out(
        &mut self,
        at: usize,
        step: FaceStep<L::Pump>,
        redial_ms: Option<u64>,
        now_us: u64,
    ) -> Result<(), OpenError> {
        let FaceStep {
            life,
            effect,
            answer,
            endpoint,
        } = step;
        let id = life.id();
        // Every arm that does not end here names what follows and the reason the last endpoint
        // gave, and one call carries them out.
        let (then, last) = match effect {
            FaceEffect::Stay => return Ok(()),
            // The face table decides whether the node is held already, and installs the link
            // itself.
            FaceEffect::BringUp => {
                self.bring_up(at, now_us);
                return Ok(());
            }
            // zenoh-pico's client reopens whatever ended its link: a lease that ran out, a read
            // that failed, a Close from the router
            // (`vendor/zenoh-pico/src/transport/unicast/read.c` @
            // `return _zp_unicast_failed_result(ztu, executor);`).
            FaceEffect::Lose { then } => {
                self.lose_face_link(at, id, now_us);
                let last = if then == Next::EndSession {
                    OpenError::Unreachable(EndpointRefusal::new("", Refusal::LinkLost))
                } else {
                    OpenError::NoEndpoint
                };
                (then, last)
            }
            // The link's task, told to stop, ends in the pass of the tasks before its link goes.
            FaceEffect::Fail { then } => {
                let why = self.transport.end_handshake(at);
                self.run_tasks();
                let last = OpenError::from(self.transport.handshake_failed(at, &then, why, now_us));
                (then, last)
            }
            // The dial under way was asked, never waited for: its link's handshake begins once
            // it is made. Refused, or not answered by its deadline, the dial role's face dials the
            // next endpoint, and any other face goes, as one whose handshake fails does.
            FaceEffect::Handshake { next, deadline_us } => {
                let answered = match answer {
                    Some(answer) => {
                        self.dial_answered(at, id, endpoint.as_ref(), next, deadline_us, answer)
                    }
                    None => Err(OpenError::Unreachable(EndpointRefusal::new(
                        self.transport.endpoint_text(endpoint.as_ref()),
                        Refusal::NoAnswerInTime,
                    ))),
                };
                match answered {
                    Ok(()) => return Ok(()),
                    Err(OpenError::EntropyUnavailable) => {
                        return Err(OpenError::EntropyUnavailable)
                    }
                    Err(last) => (life.after_failure(next), last),
                }
            }
            FaceEffect::DialFailed { then } => {
                let why = match answer {
                    Some(Err(refused)) => Refusal::Link(refused),
                    _ => Refusal::NoAnswerInTime,
                };
                let last = OpenError::Unreachable(EndpointRefusal::new(
                    self.transport.endpoint_text(endpoint.as_ref()),
                    why,
                ));
                (then, last)
            }
            // A face whose wait is over, or whose node no other face holds now (with `listen`):
            // the face that held the node is gone, and so is any link in the making to it. Read
            // from the face table each step and not told by the face that goes, so a link that
            // dies in its handshake frees the node as well.
            FaceEffect::Dial { from } => (Next::DialFrom { from }, OpenError::NoEndpoint),
        };
        self.follow(at, then, last, redial_ms)
    }

    /// What follows a link of the face at `at` that failed or was lost (`then`), `last` the
    /// reason of the last endpoint tried: the face goes, the session ends with `last`, the face
    /// dials from an endpoint (and waits `redial_ms` to dial them all again when none answers),
    /// or it stands by for a node another face holds.
    fn follow(
        &mut self,
        at: usize,
        then: Next,
        last: OpenError,
        redial_ms: Option<u64>,
    ) -> Result<(), OpenError> {
        match then {
            Next::Remove => {
                self.remove_face(at);
                Ok(())
            }
            Next::EndSession => Err(last),
            Next::DialFrom { from } => self.dial_or_wait(at, from, last, redial_ms),
            // The dial role's link reached a node another face holds or is bringing up: the node
            // refused it (`install_link_admission`). It stands by, and dials again when no other
            // face has the node, where dialling at once would be refused again and the handshake
            // paid each time.
            Next::StandBy { node } => {
                self.transport.links.put_link(at, Link::Held { zid: node });
                Ok(())
            }
        }
    }

    /// What a lost link of the face at `at`, numbered `id`, takes with it at `now_us`: its
    /// peer's chains, its room, what its peer declared, and the face's watchers are told it went.
    fn lose_face_link(&mut self, at: usize, id: FaceId, now_us: u64) {
        // The face is read before the wire goes: what it was is what a watcher is told, its rows
        // queued now and handed out once the session is let go of.
        let lost = self
            .transport
            .links
            .face(at)
            .and_then(|face| face.link.wire());
        if let Some(wire) = lost.filter(|_| self.session.faces_watched()) {
            FaceLinkRow::each_of_actions(&*wire.actions, |row| {
                self.session.report_face_row(FaceEventKind::Down, row);
            });
        }
        self.transport.end_peer_chains(at);
        // What a replaying listener was told of the face is read while its link is held.
        #[cfg(feature = "connectivity")]
        self.face_went(at);
        self.transport
            .links
            .put_link(at, Link::Waiting { at_us: now_us });
        // What the lost link's peer was told went with it: the next link's peer holds nothing.
        if let Some(face) = self.transport.links.face_mut(at) {
            face.replay.discard();
        }
        self.rooms.forget(at);
        self.lose_link(id);
    }

    /// Tell the peer of every face whose link is up everything the session holds again, as a link
    /// that has just come up is told (`begin_replay`), at the session's pace; the count of faces.
    /// What the application asks for when it holds that a peer lost declarations the session made.
    /// A face whose first turn the replay is given up on is not counted: its link ends, and the
    /// next pass over the faces takes it as lost (`poll_face`).
    fn redeclare(&mut self) -> usize {
        let now_ms = self.clock.now_us() / 1000;
        let places = self.transport.links.places();
        (0..places)
            .filter(|&at| self.redeclare_on(at, now_ms))
            .count()
    }

    /// Tell the peer of the face at `at` everything the session holds again (`redeclare`):
    /// whether it was told, which a place with no face, or a face whose link is not up, is not.
    fn redeclare_on(&mut self, at: usize, now_ms: u64) -> bool {
        let actions = match self.transport.links.face(at).map(|face| &face.link) {
            Some(Link::Up(wire)) => wire.actions.clone(),
            _ => return false,
        };
        match self.begin_replay(at, &actions, now_ms) {
            TurnEnd::Kept => true,
            TurnEnd::EndsLink => {
                if let Some(Link::Up(wire)) = self.transport.links.face(at).map(|face| &face.link) {
                    wire.abort();
                }
                false
            }
        }
    }

    /// The face at `at`, whose handshake completed, holds its link up: what the session holds is
    /// declared over it from here on, and the watchers of the faces are told it came up. The link
    /// was admitted in its handshake (`install_link_admission`), so a link that got this far is
    /// the session's link to its node, and no other link to the node is kept beside it. A first
    /// turn the replay is given up on ends the link at once, and the next pass over the faces
    /// takes it as lost (`poll_face`).
    fn bring_up(&mut self, at: usize, now_us: u64) {
        let Some(face) = self.transport.links.face(at) else {
            return;
        };
        let Some(wire) = face.link.wire() else {
            return;
        };
        #[cfg(feature = "listen")]
        wire.gate.pump().grant();
        // A publish goes to the links that are up, so theirs are the rooms it asks.
        if let Some(on) = wire.room_wait() {
            self.rooms.hold(at, on);
        }
        let actions = wire.actions.clone();
        if self.begin_replay(at, &actions, now_us / 1000) == TurnEnd::EndsLink {
            self.transport.links.abort_link(at);
        }
        self.transport.links.establish(at);
        if self.session.faces_watched() {
            FaceLinkRow::each_of_actions(&*actions, |row| {
                self.session.report_face_row(FaceEventKind::Up, row);
            });
        }
    }

    /// Join every group the config lists, each a face of its own whose session is a task of the
    /// session's local set, stepped once here so that its first JOIN leaves now.
    /// [`OpenError::Group`] for the first the network joins no group for, or whose session ended
    /// at its first step (its link did not open); a build without `group` answers every group so.
    fn join_groups(&mut self) -> Result<(), OpenError> {
        #[cfg(feature = "group")]
        for join in self.config.groups.clone() {
            let id = self.transport.links.next_face_id();
            // The tables first: the group's task dispatches to them from its first step. They are
            // the face's for as long as the session holds the group, across its joins, and answer
            // a query whose key they cannot resolve by the session's policy. The open lent a set
            // for each group the task cells hold, so a group past them is refused as its spawn
            // would be: no task cell is left for it.
            let Ok(held) = self.session.registry.borrow_mut().add_face(id) else {
                return Err(OpenError::NoTask(SpawnRefusal::NoTaskCell));
            };
            self.session
                .registry
                .borrow_mut()
                .set_unanswerable_final(id, self.policy.query_unanswerable_final());
            // An id of the key ids every node shares is read on the group as on a link.
            #[cfg(feature = "shared-key-ids")]
            if let Some(ids) = &self.session.key_ids {
                self.session
                    .registry
                    .borrow_mut()
                    .install_shared_key_ids(id, ids.clone());
            }
            match self.join_group(held, join) {
                Ok(face) => self.transport.add_group(face),
                Err(refused) => {
                    self.session.registry.borrow_mut().remove_face(held);
                    return Err(refused);
                }
            }
        }
        #[cfg(not(feature = "group"))]
        if let Some(join) = self.config.groups.first() {
            return Err(OpenError::Group(EndpointRefusal::new(
                &join.endpoint,
                Refusal::GroupsNotBuilt,
            )));
        }
        Ok(())
    }

    /// Join the group `join` names as the face `face` names, whose tables the registry holds at
    /// its place: the stack joins the group, and its session, with a fresh dispatcher, is spawned
    /// on the session's local set and stepped once. [`OpenError::Group`] when the stack joins no
    /// such group or the session ended at its first step (its link did not open).
    #[cfg(feature = "group")]
    fn join_group(
        &mut self,
        face: HeldFace,
        join: GroupJoin,
    ) -> Result<GroupFace<L::Waits>, OpenError> {
        let transport = self.transport.open_group(&join.endpoint)?;
        let endpoint = join.endpoint.clone();
        let params = join.profile.params(
            self.config.whatami,
            self.transport.wire_zid,
            self.config.tx_queue,
            self.config.link_rx,
            self.policy,
            *resolve_limits(&self.config),
        );
        // A member's query is held, and answered, under the group's own generation, as a link's
        // is under its; each join of the group is a generation of its own.
        #[cfg(feature = "queryable")]
        let generation = self.session.plane.next_generation();
        #[cfg(feature = "queryable")]
        let dispatch = group::dispatch(
            self.session.registry.clone(),
            face,
            self.session.plane.clone(),
            generation,
        );
        #[cfg(not(feature = "queryable"))]
        let dispatch = group::dispatch(self.session.registry.clone(), face);
        // The group is handed a record of its datagrams only while the round of deliveries has the
        // room one record of the group's batch can take (decision Q4), as a link is.
        let record_room = crate::round::read_room::<
            { caps::MAX_SUBSCRIPTIONS },
            { caps::MAX_LIVELINESS_SUBSCRIPTIONS },
        >(resolve_limits(&self.config));
        // SAFETY: a group's transport is driven by the session's step alone, under its lock.
        let input_gate = wz_session_mcu::group_drive::GroupInputGate::new(unsafe {
            crate::round::takes_a_group_read(self.session.lane.clone(), record_room)
        });
        let group = GroupFace::join(
            &self.local,
            GroupJoining {
                face,
                join,
                transport,
                input_gate,
                lane: self.session.lane.clone(),
                params,
                policy: self.policy,
                limits: *resolve_limits(&self.config),
                // A message the session puts on the group waits for room by running the session's
                // tasks, the group's among them, on the session's clock.
                pace: Rc::new(group::SessionPace {
                    local: self.local.clone(),
                    clock: self.clock.clone(),
                }),
                #[cfg(feature = "queryable")]
                generation,
                #[cfg(feature = "connectivity")]
                watchers: Arc::clone(&self.session.watchers),
            },
            dispatch,
            self.rooms.waits().clone(),
        )
        .map_err(OpenError::NoTask)?;
        self.run_tasks();
        if group.has_ended() {
            return Err(OpenError::Group(EndpointRefusal::new(
                &endpoint,
                Refusal::GroupLinkDidNotOpen,
            )));
        }
        // A droppable publish that finds the session held asks the group's socket for room as it
        // asks a link's, and its wait goes with the face, at the face's place.
        if let Some(on) = group.room() {
            self.rooms.hold(face.at(), on);
        }
        Ok(group)
    }

    /// The place in the replay's order of the declaration `prefix` names, when the entity going is
    /// the last that holds it: read while the rows stand. `None` when the entity's key is named by
    /// no declaration, or another entity holds it too. The one reading of a last hold for every
    /// kind of entity and for the key's own release.
    #[inline(never)]
    fn prefix_retraction(&self, prefix: Option<KeyexprHandle>) -> Option<usize> {
        let prefix = prefix.filter(|&prefix| {
            tables(&self.session.registry)
                .keyexprs()
                .get(prefix)
                .is_some_and(|row| row.holds() <= 1)
        })?;
        Some(self.place_of(DeclaredRow::of(prefix)))
    }

    /// Tell the links whose peers were told of it, and each group the session joined, that the
    /// declaration `mapping_id`, which lay at `place` in the replay's order, is retracted, once the
    /// tables let it go: what its last holder's going sends, after the rows went, so a send never
    /// finds the tables borrowed.
    #[inline(never)]
    fn retract_keyexpr(&mut self, place: Option<usize>, mapping_id: Option<ExprId>) {
        let (Some(place), Some(mapping_id)) = (place, mapping_id) else {
            return;
        };
        self.retract_at(place, &undeclare_kexpr::<C>(mapping_id));
        #[cfg(feature = "group")]
        for group in &self.transport.groups {
            group.retract_keyexpr(mapping_id);
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
        for at in 0..self.transport.groups.len() {
            let Some(group) = self.transport.groups.get_mut(at) else {
                continue;
            };
            let id = group.id();
            let face = HeldFace::new(group.at(), id);
            if let Some(outcome) = group.take_outcome(&self.local) {
                self.lose_link(id);
                if let (true, Some(ms)) = (outcome.warrants_rejoin(), redial_ms) {
                    self.rejoin_group_at(at, again_at(ms));
                }
                continue;
            }
            let due = self
                .transport
                .groups
                .get(at)
                .filter(|group| group.rejoin_due(now_us))
                .map(|group| group.group_join().clone());
            if let Some(join) = due {
                match self.join_group(face, join) {
                    Ok(face) => {
                        // The liveliness subscribers ask the group again, as they would have
                        // had it been there when they were declared, as the tokio engine's
                        // group asks again when it comes up. What the session announced is
                        // not told again: neither upstream tells a group that comes up of
                        // the entities a session already holds.
                        #[cfg(feature = "liveliness")]
                        {
                            let tables = tables(&self.session.registry);
                            for (_, row) in tables.liveliness_subscribers().iter() {
                                face.ask_liveliness(
                                    row.id(),
                                    row.key().as_str(),
                                    &group::wire_key_of(tables.wire_of(row.key())),
                                    row.history(),
                                );
                            }
                        }
                        if let Some(ended) = self.transport.groups.get_mut(at) {
                            // A departure owed to a replaying listener outlives the join that
                            // ended.
                            #[cfg(feature = "connectivity")]
                            face.keep_tombs_of(ended);
                            *ended = face;
                        }
                    }
                    Err(_) => {
                        if let Some(ms) = redial_ms {
                            self.rejoin_group_at(at, again_at(ms));
                        }
                    }
                }
            }
        }
    }

    /// Join the group at place `at` again at `at_us`, on the session's clock; a place no group
    /// stands at waits for nothing.
    #[cfg(feature = "group")]
    fn rejoin_group_at(&mut self, at: usize, at_us: u64) {
        if let Some(group) = self.transport.groups.get_mut(at) {
            group.wait_to_rejoin(at_us);
        }
    }

    /// Take the connections that wait on the ports the session listens on, each as a face of its
    /// own. A port that had no socket or buffer for one just now is looked at again on the next
    /// step, and one that is broken for good is let go of.
    #[cfg(feature = "listen")]
    fn accept_links(&mut self) {
        let mut at = 0;
        while let Some((opened, endpoint)) = self.transport.next_accepted(&mut at) {
            self.accept_face(opened, endpoint);
        }
    }

    /// Take the face at `at` out of the session, with its tables. The dial role's face is never
    /// taken out.
    fn remove_face(&mut self, at: usize) {
        // A face whose departure a replaying listener is owed keeps its place for its tomb.
        #[cfg(feature = "connectivity")]
        if self.keep_departed(at) {
            return;
        }
        if let Some(face) = self.transport.links.take_face(at) {
            self.session
                .registry
                .borrow_mut()
                .remove_face(HeldFace::new(at, face.id));
        }
    }

    /// What a lost link of face `id` takes with it: what the session holds of it
    /// (`SessionState::lose_face`). What the peer was told is the caller's, which holds the face's
    /// place: a group keeps no replay.
    /// Out of line: a lost face and a group that ended each take what the peer declared.
    #[inline(never)]
    fn lose_link(&mut self, id: FaceId) {
        self.session.lose_face(id);
        #[cfg(feature = "liveliness")]
        self.retract_owed();
    }

    /// Retract the tokens the peers of lost links declared, as many as the round of deliveries
    /// takes now (`SessionState::retract_owed`). Each `Delete` is a record of a token for every
    /// liveliness subscriber the session's limits admit.
    #[cfg(feature = "liveliness")]
    fn retract_owed(&mut self) {
        // A token's record owes a callback to each liveliness subscriber the session admits.
        let callbacks = crate::round::session_liveliness::<{ caps::MAX_LIVELINESS_SUBSCRIPTIONS }>(
            resolve_limits(&self.config),
        )
        .max(1);
        // SAFETY: `Core` is reached under the session's lock alone, the round writer's lock.
        unsafe {
            self.session
                .retract_owed(crate::round::ReadRoom { callbacks })
        };
    }

    /// Hold in the round what the declaration watches are owed and it has room for now
    /// (`DeclWatches::tell_owed`): each new watch's catch-up from the peers of the links up now,
    /// each declaration named as its link's peer, and the events a watch lost.
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    fn tell_decl_watches_owed(&self) {
        let registry = self.session.registry.borrow();
        let tables = &*registry;
        let links = &self.transport.links;
        let faces = move || {
            links.faces().filter_map(move |face| {
                let (Link::Up(wire) | Link::Opening { wire, .. }) = &face.link else {
                    return None;
                };
                let peer = decl_watch::named(|| wire.actions.peer_session_zid());
                Some((tables.tables_of(face.id)?, peer))
            })
        };
        // SAFETY: `Core` is reached under the session's lock alone, the round writer's lock.
        unsafe { registry.decl_watches.tell_owed(faces) };
    }

    /// `most` milliseconds, or the whole milliseconds left at `now_us` until `due_ms` (rounded up,
    /// so a wait never ends a clock reading before the time it waits for), whichever is less.
    fn wait_until(most: u32, due_ms: u64, now_us: u64) -> u32 {
        let left_us = due_ms.saturating_mul(1000).saturating_sub(now_us);
        u32::try_from(left_us.div_ceil(1000)).map_or(most, |left| left.min(most))
    }

    /// The session's clock, read: what a read's wait is worked out from and what its step moves
    /// the links, sweeps the gets and looks for a due job against, each read once.
    fn now_us(&self) -> u64 {
        #[cfg(test)]
        self.clock_reads.set(self.clock_reads.get() + 1);
        self.clock.now_us()
    }

    /// The milliseconds of `now_us`, a step's reading of the clock, when a periodic job is due
    /// by it: what the read runs its jobs against once its delivery is done.
    #[cfg(feature = "ticker")]
    fn jobs_due_at(&self, now_us: u64) -> Option<u64> {
        let now_ms = now_us / 1000;
        self.tickers
            .next_due_ms()
            .is_some_and(|due_ms| due_ms <= now_ms)
            .then_some(now_ms)
    }

    /// A build without periodic jobs has none due.
    #[cfg(not(feature = "ticker"))]
    fn jobs_due_at(&self, _now_us: u64) -> Option<u64> {
        None
    }

    /// What a read waits for before it steps the session: the link's next input, for at most
    /// [`CoopConfig::idle_wait_ms`], unless the link already holds some or waits in its own loop;
    /// and while no link is open, the next dial, for no longer either. zenoh-pico's read waits
    /// the same way, on a socket whose receive timeout is that long (`Z_CONFIG_SOCKET_TIMEOUT`).
    fn idle_wait(&mut self) -> IdleWait {
        // What is due other than input, the earliest of it in milliseconds of the session's clock:
        // a get whose deadline comes first is swept when it is due, not up to a whole wait late,
        // and so is the next turn of a replay a link owes its peer, a periodic job the program
        // started, and a group's session when it is next due with nothing arriving (its beacon,
        // its sweep, what the session pushed onto it, its join again). A group that took a
        // datagram is stepped again at once, its task taking one a step, so its own time is not
        // asked.
        #[cfg(feature = "group")]
        let group_took = self.transport.group_took_input();
        let due_ms = [
            #[cfg(feature = "query")]
            self.session.next_get_deadline_ms(),
            self.transport
                .links
                .faces()
                .filter_map(|face| face.replay.next_turn_ms())
                .min(),
            #[cfg(feature = "ticker")]
            self.tickers.next_due_ms(),
            #[cfg(feature = "group")]
            if group_took {
                None
            } else {
                self.transport.groups_due_ms()
            },
        ]
        .into_iter()
        .flatten()
        .min();
        // The clock is read when something is due, and that reading serves every bound after it:
        // a wait with nothing due reads it not at all.
        let mut clock_now: Option<u64> = None;
        let most = match due_ms {
            Some(due_ms) => Self::wait_until(
                self.config.idle_wait_ms,
                due_ms,
                *clock_now.get_or_insert_with(|| self.now_us()),
            ),
            None => self.config.idle_wait_ms,
        };
        // A group whose stack gives no wait for its input is looked at on its tick.
        #[cfg(feature = "group")]
        let most = if group_took {
            0
        } else if self.transport.group_unwaited() {
            most.min(group::GROUP_TICK_MS)
        } else {
            most
        };
        if most == 0 {
            return IdleWait::None;
        }
        // What the read waits on is the driver's to make (`LinkSupervisor::idle_wait`): the input
        // of every link and port, and each group's after them, since a wait over several is made
        // by the first and a link's names a group's socket to the platform beside its own.
        let clock = &self.clock;
        #[cfg(test)]
        let clock_reads = &self.clock_reads;
        let mut now_us = || {
            *clock_now.get_or_insert_with(|| {
                #[cfg(test)]
                clock_reads.set(clock_reads.get() + 1);
                clock.now_us()
            })
        };
        // The bounds above are the clock's time read as the wall's, which a clock the program
        // moves is not: its word that the time moved on ends the wait as well.
        #[cfg(feature = "time-base")]
        let (most, beside) = clock_beside(
            most,
            self.config.clock_moves.as_ref(),
            self.clock_wake.as_ref(),
        );
        #[cfg(not(feature = "time-base"))]
        let beside = None;
        self.transport.idle_wait(most, &mut now_us, beside)
    }

    /// Run the session's tasks until none is ready, the session's one reassembly Router lent to
    /// its links' receives for as long ([`RouterLend::lend_for`]). Every pass of the session's
    /// own is made here, so a link's receive finds its Router lent whenever its task runs; a pass
    /// a group's wait makes lends nothing, and a link's receive takes no input in it.
    /// Out of line: nine places step the session's tasks, the lend around them one body.
    #[inline(never)]
    fn run_tasks(&mut self) {
        let Self {
            local,
            transport: TransportState { router, lend, .. },
            ..
        } = self;
        lend.lend_for(router, || local.run_until_idle());
    }

    /// End every face's link, whatever it is doing, telling an established peer so. The dial
    /// role's face stays, with no link and no redial; the others go.
    fn end_links(&mut self) {
        // A dial under way is let go of: its connection is not made. The ports are let go of
        // first, so no connection is taken while the faces are ended.
        self.transport.links.end_dials_and_ports();
        // Each group's session is asked to stop, and its next step, taken here, tells the group it
        // leaves and lets the group's link go; its tables go with the other faces' below.
        #[cfg(feature = "group")]
        if self.transport.stop_groups() {
            self.run_tasks();
            self.transport.groups.clear();
        }
        self.transport.links.end_faces(|face| face.replay.discard());
        self.rooms.forget_all();
        self.session.registry.borrow_mut().remove_accepted_faces();
        self.run_tasks();
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
    /// `declared` in a build without the feature, is [`OpenError::KeyWireForm`], and a
    /// dictionary of more entries than the config's limits admit is
    /// [`OpenError::KeyIdsOverLimit`].
    ///
    /// The session's arena is the allocator's ([`AllocatorMemory`]); an ABI that reserves it
    /// elsewhere opens with [`Self::open_in`].
    #[inline]
    pub fn open_with_key_ids(
        links: L,
        clock: C,
        entropy: impl EntropySource + Send + 'static,
        config: CoopConfig,
        policy: SessionPolicy,
        key_ids: OpenKeyIds,
    ) -> Result<Arc<Self>, OpenError> {
        Self::open_in(
            links,
            clock,
            entropy,
            config,
            policy,
            key_ids,
            &AllocatorMemory,
        )
    }

    /// [`Self::open_with_key_ids`], the session's arena reserved from `memory`. The arena is
    /// reserved once the key-wire form is judged and before anything else, as the limits the open
    /// resolved lay it out ([`ArenaPlan`]): a session whose memory cannot be given binds no port,
    /// joins no group and dials no endpoint, and is [`OpenError::Arena`]. The links' buffers are
    /// lent from it to `links` before anything is bound or dialled
    /// (`SessionLinks::lend_buffers`), so a link the session opens reads and encodes in the arena.
    pub fn open_in(
        links: L,
        clock: C,
        entropy: impl EntropySource + Send + 'static,
        config: CoopConfig,
        policy: SessionPolicy,
        key_ids: OpenKeyIds,
        memory: &'static dyn ArenaMemory,
    ) -> Result<Arc<Self>, OpenError> {
        Self::open_made_in(
            links,
            clock,
            entropy,
            || config,
            policy,
            key_ids,
            OpenStorage {
                memory,
                held: HeldPlaces::NONE,
            },
        )
    }

    /// [`Self::open_in`], its config read from `source` inside the open, once, before anything
    /// else: an ABI that builds the config from its own values hands the source (a maker of the
    /// config is one), so the config is never a value of its frame, which the open's handshake runs
    /// under. The source writes the endpoints' texts into the rows the open lends for them, and is
    /// let go of before anything is bound or dialled ([`OpenSource`]).
    ///
    /// The open is two frames that never lie on the stack together. The first builds the engine
    /// where it is kept (the session's state and its arena's tables, in the engine's own
    /// allocation), and returns; the second binds the ports, joins the groups and dials over the
    /// engine it built, holding only a handle to it. So no part of the engine, and no copy of the
    /// config, is under the session's first steps. An open that fails once the engine is built
    /// ends what it began as a dropped session does (`end_links`): the ports it bound are let
    /// go of and a group it joined is told it leaves.
    ///
    /// The arena also holds the places `storage.held` names, lent after every table
    /// ([`ArenaPlan::holding`]): a place for the ABI's own handle of the session
    /// ([`CoopDrive::handle_place`]) and places for its objects of the session's entities
    /// ([`PlaceLender::claim_place`]). They are reserved with the session, and an open whose arena cannot
    /// hold them opens nothing.
    pub fn open_made_in(
        links: L,
        clock: C,
        entropy: impl EntropySource + Send + 'static,
        source: impl OpenSource,
        policy: SessionPolicy,
        key_ids: OpenKeyIds,
        storage: OpenStorage,
    ) -> Result<Arc<Self>, OpenError> {
        let engine = Self::assemble(links, clock, entropy, source, policy, key_ids, storage)?;
        engine.open_links()?;
        Ok(engine)
    }

    /// The engine [`Self::open_made_in`] opens, built where it is kept and not yet bound, joined
    /// or dialled: the config made, the key-wire form judged, the arena reserved and its tables
    /// lent, the zid decided; then the links lent their buffers and cells, the task and timer
    /// tables reserved, the dial role's face and every table in place. Never inlined, for the
    /// stack: the frame has returned before the first link is opened.
    ///
    /// One frame from the config to the state: the links, the config, the entropy and what the
    /// arena lent are each borrowed while the open decides, and a value borrowed once is copied
    /// when it is handed on by value. Made here, each is moved only into the state, which is moved
    /// once, into the engine's allocation ([`Self::engine_of`]).
    #[inline(never)]
    fn assemble(
        mut links: L,
        clock: C,
        entropy: impl EntropySource + Send + 'static,
        source: impl OpenSource,
        policy: SessionPolicy,
        key_ids: OpenKeyIds,
        storage: OpenStorage,
    ) -> Result<Arc<Self>, OpenError> {
        let OpenStorage { memory, held } = storage;
        let (config, write_endpoints) = source.into_parts();
        #[cfg(feature = "shared-key-ids")]
        let key_forms = key_ids.admit(&policy, resolve_limits(&config))?;
        #[cfg(not(feature = "shared-key-ids"))]
        key_ids.admit(&policy)?;
        let mut lent = lend_session(link_cells::<C>(&links), &held, memory, &config, &policy)
            .map_err(OpenError::Arena)?;
        // The texts of the endpoints, each written once by the source into the row the plan laid
        // out for it: the session names an endpoint by its row from here, and what the source
        // held goes with its writer, here, before anything is bound or dialled.
        write_endpoints(&mut EndpointWriter::over(&mut lent.transport.endpoints))?;
        let mut entropy = SessionEntropy::new(entropy);
        let wire = session_zid(&config, &policy, &lent.transport.endpoints, &mut entropy)?;
        links.lend_buffers(lent.transport.links);
        #[cfg(feature = "listen")]
        links.lend_port_rows(lent.transport.port_rows);
        if let Some(driver_cells) = lent.transport.cells.driver {
            links.lend_cells(driver_cells);
        }
        // The task and timer tables, reserved here once: no spawn and no sleep of the session
        // takes memory after its open (`open_links` seals them).
        let runtime = RuntimeTables::of::<C>(&config).runtime(clock.clone());
        let local = CoopLocalSet::new(&runtime);
        let session_time = CoopTime::new(&runtime);
        let wait_room = read_wait_room(&config);
        #[cfg(feature = "time-base")]
        let clock_wake = config.clock_moves.as_ref().and_then(|moves| {
            let wake = links.waits().wake()?;
            moves.watch(wake.waker.clone());
            Some(wake)
        });
        #[cfg(feature = "connectivity")]
        let face_rows = face_event_rows(config.max_faces, config.groups.len());
        // The faces' links keep the places the registry lends their tables at: one table of them.
        let places = lent.registry.places();
        // Each field is made in the order its makers need: the rooms ask the links' waits before the
        // supervisor takes the links, and the config and policy are read before they are moved.
        let core = Core {
            local,
            clock,
            // A handle at each place a face may hold, the dial role's and each group's among them.
            rooms: Arc::new(LinkRooms::new(links.waits(), places)),
            transport: TransportState {
                #[cfg(feature = "listen")]
                tx_pool_short: lent.tx_pool_short,
                // A place for each face the registry lent a set for, each face with its dial, and
                // the waits a read makes at once, reserved here: none grows after.
                links: LinkSupervisor::new(
                    links,
                    Face {
                        id: DIAL_FACE,
                        link: Link::Waiting { at_us: u64::MAX },
                        replay: Replay::idle(),
                        #[cfg(feature = "connectivity")]
                        told: FaceTold::default(),
                    },
                    places,
                    wait_room,
                ),
                endpoints: lent.transport.endpoints,
                #[cfg(feature = "group")]
                groups: Vec::new(),
                #[cfg(feature = "listen")]
                // A row for each link the plan holds buffers for, reserved here: a link the
                // session takes after its open is admitted in place.
                admission: Arc::new(LinkRegistry::<CoopRuntime<C>>::with_order(
                    &wire,
                    policy.link_tie_order(),
                    lent.links,
                )),
                wire_zid: wire,
                gate_cells: lent.transport.cells.gate,
                actions_cells: lent.transport.cells.actions,
                halves_cells: lent.transport.cells.halves,
                #[cfg(feature = "shared-key-ids")]
                key_forms,
                router: lent.router,
                lend: RouterLend::new(),
            },
            session: SessionState {
                registry: Rc::new(RefCell::new(lent.registry)),
                // No watcher yet: the queue's rows are reserved now, so a program that watches
                // after the open is told its faces with nothing allocated.
                #[cfg(feature = "connectivity")]
                watchers: Arc::new(FacePlane::with_room(face_rows)),
                #[cfg(not(feature = "connectivity"))]
                watchers: (),
                entities: (),
                keys: lent.keys,
                #[cfg(feature = "shared-key-ids")]
                key_ids: key_ids.at_open.ids,
                #[cfg(not(feature = "shared-key-ids"))]
                key_ids: (),
                // From 0, and `()` without `local-queryable`.
                local_requests: Default::default(),
                matching: MatchingRead::default(),
                replay_pacing: ReplayPacing::of_snapshot(&policy, resolve_limits(&config)),
                #[cfg(feature = "queryable")]
                plane: lent.plane,
                #[cfg(not(feature = "queryable"))]
                plane: (),
                #[cfg(feature = "query")]
                pending_gets: lent.pending_gets,
                #[cfg(not(feature = "query"))]
                pending_gets: (),
                #[cfg(feature = "query")]
                gets: lent.gets,
                #[cfg(not(feature = "query"))]
                gets: (),
                lane: lent.samples,
            },
            #[cfg(feature = "time-base")]
            clock_wake,
            entropy,
            config,
            policy,
            #[cfg(test)]
            clock_reads: core::cell::Cell::new(0),
            #[cfg(feature = "ticker")]
            tickers: Tickers::reserved(caps::MAX_TICKERS),
            session_time,
            places: lent.places,
            arena: lent.arena,
        };
        let apart = LentApart {
            handle_place: lent.handle_place,
            #[cfg(any(feature = "listen", feature = "group"))]
            handed: lent.transport.handed,
            #[cfg(feature = "advanced-cache")]
            cache: lent.cache,
        };
        Ok(Self::engine_of(core, apart))
    }

    /// The engine over `core`, held where its own handle (`this`) reaches it, with what the open
    /// lent apart from the state (`apart`). Out of line, so the open's measure shows it apart.
    #[inline(never)]
    fn engine_of(core: Core<L, C>, apart: LentApart) -> Arc<Self> {
        let LentApart {
            handle_place,
            #[cfg(any(feature = "listen", feature = "group"))]
            handed,
            #[cfg(feature = "advanced-cache")]
            cache,
        } = apart;
        let samples = core.session.lane.clone();
        let wire = core.transport.wire_zid;
        #[cfg(feature = "queryable")]
        let plane = core.session.plane.clone();
        #[cfg(feature = "query")]
        let gets = core.session.gets.clone();
        #[cfg(feature = "connectivity")]
        let faces = core.session.watchers.clone();
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        let decl_watches = core.session.registry.borrow().decl_watches.clone();
        let rooms = core.rooms.clone();
        let wait_before_drop_us = core.config.tx_queue.wait_before_drop_us;
        let held_drop = core.config.tx_queue.held_drop;
        #[cfg(any(feature = "listen", feature = "group"))]
        let handed_limits = HandedLimits::new(core.config.tx_queue.sizes);
        let arena_bytes = core.arena.bytes();
        // The handle's type is named: the engine's handle coerced for the round would otherwise be
        // what infers it.
        Arc::new_cyclic(|this: &Weak<Self>| {
            // The round hands the queries it holds to their queryables through the engine, which
            // sends what they answer.
            #[cfg(feature = "queryable")]
            {
                let answering: Weak<dyn crate::round::AnswersQueries<crate::round::CoopCalls>> =
                    Weak::<Self>::clone(this);
                samples.answer_queries_with(answering);
            }
            Self {
                core: CoreLock::new(core),
                rooms,
                wait_before_drop_us,
                held_drop,
                sending_on: AtomicU64::new(NOT_SENDING),
                #[cfg(any(feature = "listen", feature = "group"))]
                handed: Mutex::new(handed),
                #[cfg(any(feature = "listen", feature = "group"))]
                owed: AtomicBool::new(false),
                input_held: AtomicBool::new(false),
                hand_back: HandBack::new(),
                #[cfg(any(feature = "listen", feature = "group"))]
                handed_limits,
                #[cfg(feature = "transport-stats")]
                unsent_drops: AtomicU64::new(0),
                samples,
                matching_owed: AtomicBool::new(false),
                #[cfg(feature = "queryable")]
                plane,
                #[cfg(feature = "query")]
                gets,
                #[cfg(feature = "connectivity")]
                faces,
                #[cfg(any(
                    feature = "remote-declaration-watch",
                    feature = "declarations-synced-event"
                ))]
                decl_watches,
                zid: wire,
                closed: AtomicBool::new(false),
                #[cfg(any(feature = "query", feature = "ticker"))]
                next_local: AtomicU64::new(1),
                reader: Mutex::new(None),
                reader_run: core::sync::atomic::AtomicUsize::new(0),
                deliveries: Deliveries::new(),
                arena_bytes,
                handle_place,
                #[cfg(feature = "advanced-cache")]
                cache: Mutex::new(cache),
                #[cfg(test)]
                takes: Takes::default(),
                this: this.clone(),
            }
        })
    }

    /// Open the links of the engine [`Self::assemble`] built: the ports bound and the groups
    /// joined before anything is dialled, so a session that cannot listen, or join a group, where
    /// it was told to does not open; then the first endpoint dialled and the session stepped on
    /// this thread until the dial settles. A session that only listens, or only joins groups, is
    /// open once it is bound and joined; one that dials is open once a link completes its
    /// handshake. Never inlined: what it holds under the session's first steps is the guard of the
    /// engine's state, which nothing else can take before the open returns the engine.
    #[inline(never)]
    fn open_links(&self) -> Result<(), OpenError> {
        let mut held = self.core.lock();
        let core = &mut held.0;
        core.transport.listen_on_config()?;
        core.join_groups()?;
        // Asked as the arena asked it, so the dial role's face dials exactly when its plan lent
        // it a link.
        if crate::arena::dials_of(
            core.transport.endpoints.dials(),
            core.transport.endpoints.listens(),
            core.config.groups.len(),
        ) {
            core.dial_from(0, 0, OpenError::NoEndpoint)?;
            // Open once the dial's link is up, or once the node it reached is held by a face that
            // came first (a peer that listens and dials its own listener's peer).
            while !core.transport.dial_settled() {
                let mut wait = core.idle_wait();
                wait.wait(core.rooms.waits(), sleep_ms);
                core.transport.links.waited(wait);
                core.run_tasks();
                let now_us = core.now_us();
                core.poll_links(None, now_us)?;
            }
        }
        // What the open spawned has its cells: from here a spawn finds a free cell or is refused.
        #[cfg(feature = "group")]
        core.local.runtime().seal();
        Ok(())
    }

    /// How many cells of the session's table of links' halves hold a link's halves now: `None`
    /// for a session whose plan laid out no such table.
    #[cfg(test)]
    pub(crate) fn link_halves_in_use(&self) -> Option<usize> {
        self.core
            .lock()
            .0
            .transport
            .halves_cells
            .as_ref()
            .map(LentByteCells::in_use)
    }

    /// The plane the session's faces are told through, for a test that tells it rows itself.
    #[cfg(all(test, feature = "connectivity"))]
    pub(crate) fn face_plane(&self) -> &FacePlane {
        &self.faces
    }

    /// The session's say on a second link to a node, the one its links' handshakes ask, for a
    /// test that asks it as they do.
    #[cfg(all(test, feature = "listen"))]
    pub(crate) fn link_admission(&self) -> Arc<dyn wz_session_core::link_admission::LinkAdmission> {
        Arc::clone(&self.core.lock().0.transport.admission)
    }

    /// How many places of `kind` the ABI holds now, and how many the session's arena lends at
    /// most.
    #[cfg(test)]
    pub(crate) fn place_counts(&self, kind: EntityKind) -> (usize, usize) {
        self.core.lock().0.places.counts(kind)
    }

    /// Run `f` while this thread holds the session's lock, as a drop made under it would.
    #[cfg(test)]
    pub(crate) fn under_the_lock<R>(&self, f: impl FnOnce() -> R) -> R {
        let _held = self.core.lock();
        f()
    }

    /// The bytes the session's open reserved for its arena: the sum of its plan's spans
    /// ([`ArenaPlan::reserved_bytes`]).
    pub fn arena_bytes(&self) -> usize {
        self.arena_bytes
    }

    /// What the session's key arena holds now, closed or not.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn key_counts(&self) -> wz_session_core::key_arena::KeyCounts {
        self.core.lock().0.session.keys.counts()
    }

    /// What the session's round of deliveries did not hand a callback, by why (`crate::round`).
    pub fn round_counts(&self) -> RoundCounts {
        self.samples.counts()
    }

    /// What the in-place receive cost the peers of the faces the session holds now
    /// ([`InPlaceFallbacks`](wz_session_core::pubsub::InPlaceFallbacks)): a message whose key,
    /// composed from the peer's declaration and the message's suffix, is past the row a face
    /// composes keys in is refused where it lies and counted there. A face's counts leave with it;
    /// a closed session reports none.
    pub fn in_place_fallbacks(&self) -> wz_session_core::pubsub::InPlaceFallbacks {
        self.live().map_or_else(Default::default, |core| {
            let registry = core.0.session.registry.borrow();
            registry.in_place_fallbacks()
        })
    }

    /// The waits for room a publish that finds the session held asks. Compiled where its
    /// readers are: the group tests over the program's transport (`tests::group`).
    #[cfg(all(test, feature = "group", feature = "app-transport"))]
    pub(crate) fn rooms(&self) -> &LinkRooms<L::Waits> {
        &self.rooms
    }

    /// How many messages of `priority` the session put on its groups were dropped for want of
    /// room on the group's stage. Compiled where its readers are, as [`Self::rooms`] is.
    #[cfg(all(test, feature = "group", feature = "app-transport"))]
    pub(crate) fn group_congestion_drops(&self, priority: wz_session_core::qos::Priority) -> u32 {
        self.live().map_or(0, |core| {
            core.0
                .transport
                .groups
                .iter()
                .map(|group| group.congestion_drops(priority))
                .sum()
        })
    }

    /// Stage `count` replies that `reply` makes on each group the session joined, as a group's
    /// dispatch stages what a member asked for, with no step of the session between them. Compiled
    /// where its readers are: the tests of a group's drops (`tests::group`, `transport-stats`).
    #[cfg(all(
        test,
        feature = "group",
        feature = "app-transport",
        feature = "transport-stats"
    ))]
    pub(crate) fn stage_group_replies(
        &self,
        count: usize,
        reply: impl Fn() -> wz_session_core::multicast_tx::MulticastTxItem,
    ) {
        use wz_session_core::multicast_reply_sink::MulticastReplyEnqueue;
        if let Some(core) = self.live() {
            for group in &core.0.transport.groups {
                for _ in 0..count {
                    group.reply_stage().enqueue(reply());
                }
            }
        }
    }

    /// The endpoints the session listens on, as bound: a port the config named as 0 is the one
    /// the stack chose. Empty once the session is closed (`listen`).
    #[cfg(feature = "listen")]
    pub fn listening(&self) -> Vec<String> {
        self.live().map_or_else(Vec::new, |core| {
            core.0
                .transport
                .links
                .listening()
                .map(|at| at.to_string())
                .collect()
        })
    }

    /// How many faces have a link that is up, whose handshake has completed.
    pub fn faces_up(&self) -> usize {
        self.live().map_or(0, |core| {
            core.0
                .transport
                .ups()
                .filter(|actions| actions.is_established())
                .count()
        })
    }

    /// How many of the session's links owe their stack the rest of a frame it took only in part,
    /// each holding an outbound slot for it. Compiled where its readers are (`tests::tx_pool`).
    #[cfg(all(test, feature = "std", feature = "listen"))]
    pub(crate) fn links_owing(&self) -> usize {
        self.live().map_or(0, |core| {
            core.0
                .transport
                .links
                .faces()
                .filter(|face| match &face.link {
                    Link::Up(wire) | Link::Opening { wire, .. } => wire.owes_write(),
                    _ => false,
                })
                .count()
        })
    }

    /// Where the frames of the session's first link that is up were written, the batch frames and
    /// the frames sent whole: in a slot its link lent, or on the heap. Compiled where its readers
    /// are (`tests::arena`).
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn lend_counts(
        &self,
    ) -> Option<(
        wz_session_core::session_actions::BatchLendCounts,
        wz_session_core::session_actions::FrameLendCounts,
    )> {
        self.live().and_then(|core| {
            core.0
                .transport
                .ups()
                .next()
                .map(|actions| (actions.batch_lend_counts(), actions.frame_lend_counts()))
        })
    }

    /// State how the declarations of a link go out, for a caller that wants a pace regardless of
    /// the session's policies (a test, or a program whose image is built for another policy); the
    /// snapshots the session opened under state it otherwise (`ReplayPacing::of_snapshot`). `Some`
    /// sends a burst of declarations a step and waits at least the interval before the next burst;
    /// `None` sends them all in one.
    pub fn set_replay_pacing(&self, pacing: Option<ReplayPacing>) {
        if let Some(mut core) = self.live() {
            core.0.session.replay_pacing = pacing;
        }
    }

    /// How the dial role's face replays its declarations now, and the snapshot the session opened
    /// under: what a test reads to tell the session's policies from the build's. Compiled where
    /// its readers are: the tests module is a host's (`all(test, feature = "std")`).
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn policy_in_force(&self) -> Option<(Option<ReplayPacing>, SessionPolicy)> {
        self.live()
            .map(|core| (core.0.session.replay_pacing, core.0.policy))
    }

    /// How often the session's read path read its clock since the open ([`Core::now_us`]): what a
    /// test of the cost of one read step counts. Read under the lock, uncounted as a take.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn clock_reads(&self) -> usize {
        self.core.lock().0.clock_reads.get()
    }

    /// Run `f` on the session's one reassembly Router with the time now on the epoch its chains
    /// are staged on: what a test of the chains the session's step ends stages its chain in and
    /// reads them by. Under the lock, uncounted as a take and as a reading of the session's clock.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn with_chain_router<T>(
        &self,
        f: impl FnOnce(&mut SessionReassembly, u64) -> T,
    ) -> T {
        let mut core = self.core.lock();
        let now_ms = core.0.session_time.ms_at(core.0.clock.now_us());
        f(&mut core.0.transport.router, now_ms)
    }

    /// How many subscribers the session core's table holds, each one row: what a test of a
    /// subscriber's ends reads. Read under the lock, uncounted as a take.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn subscriber_rows(&self) -> usize {
        tables(&self.core.lock().0.session.registry)
            .subscribers()
            .len()
    }

    /// The key expression declarations the session holds, `(id, keyexpr)` in declaration order:
    /// what a test reads of the session's tables.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn keyexpr_declarations(&self) -> Vec<(ExprId, String)> {
        self.live()
            .map(|core| {
                tables(&core.0.session.registry)
                    .keyexprs()
                    .iter()
                    .map(|(_, row)| (row.id(), String::from(row.key())))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// How many rounds of deliveries were handed out since the open: what a test of the cost of
    /// one received sample counts.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn rounds_handed(&self) -> usize {
        self.samples.tally().rounds()
    }

    /// How many samples the rounds handed to their callbacks where their datagram lies since the
    /// open: what a test of the cost of one received sample counts.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn samples_lent(&self) -> usize {
        self.samples.tally().lent()
    }

    /// How often the list of the threads delivering beside the first was taken since the open
    /// ([`Deliveries`]): what a test of the cost of one received sample counts.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn delivery_list_takes(&self) -> usize {
        self.deliveries.others_taken()
    }

    /// The lent Pushes the session's links handed to the subscribers' plane alone, the face
    /// lookups those dispatches made with the drains after them, and the lent Pushes the fan over
    /// every plane was handed (`Registry::dispatch_push`): what a test of the cost of one received
    /// sample counts.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn push_dispatches(&self) -> (usize, usize, usize) {
        self.core
            .lock()
            .0
            .session
            .registry
            .borrow()
            .push_dispatches()
    }

    /// Whether the peer of every established link has been told every declaration the session
    /// holds. A session with no link established owes nothing yet, so it is synced, as the slot
    /// node's is before a client has come: synced is a statement about established sessions, not
    /// about whether a session exists.
    pub fn declarations_synced(&self) -> bool {
        self.live().is_none_or(|core| {
            core.0
                .transport
                .links
                .faces()
                .all(|face| face.replay.finished())
        })
    }

    /// The session's state, for one operation. `None` once the session is closed.
    // Out of line: every entry point of the engine takes the session through it, each a copy
    // inlined.
    #[inline(never)]
    fn live(&self) -> Option<LiveCore<'_, L, C>> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        let guard = self.core.lock();
        #[cfg(test)]
        self.takes.core.fetch_add(1, Ordering::Relaxed);
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        Some(LiveCore {
            core: core::mem::ManuallyDrop::new(guard),
            lane: self.samples.as_ref(),
        })
    }

    /// The session's state for a publish's leg to its links. A publish that may not be dropped
    /// waits for it ([`Self::live`]). One that may is not held behind a send that holds the
    /// session while it waits for room on a link, up to `wait_before_close` for a blocking one:
    /// zenoh bounds a droppable message's wait by `wait_before_drop`
    /// (`commons/zenoh-config/src/defaults.rs` @ `wait_before_drop: 1000,`), where its own pipeline
    /// would queue it behind the blocking one on the stage that one holds
    /// (`io/zenoh-transport/src/common/pipeline.rs` @ `let mut queue = zlock!(self.stage_in[idx]);`).
    /// So it takes the session when it is free, and while it is held asks the faces that are up
    /// for room with nothing of the session held. A face with no room within `wait_before_drop`
    /// is the congestion drop, which zenoh answers the put with success; room on every face means
    /// the holder is not waiting on one, and the session is tried again. A session whose faces
    /// give no wait to ask is waited for. Under the pico profile the publish is dropped at once on
    /// the face another publish is sending on, with nothing asked ([`LinkRooms::for_held`]), and
    /// the caller is told ([`FanoutError::HeldConduit`]), as pico's put fails when its held
    /// transmit lock drops it; behind a publish between its sends it tries the session again, and
    /// behind what is not a publish it waits for the session, blocked, since that holder holds no
    /// send and lets go once its step is done. Either drop is the faces' it names alone, as each
    /// of zenoh's transports drops on its own queue: the publish is still owed to the others
    /// ([`ToPublish::DroppedOn`], [`Self::hand_off`]).
    // Out of line: the loop that asks the faces for room is taken only when the session is held.
    #[inline(never)]
    fn live_to_publish(&self, droppable: bool) -> ToPublish<'_, L, C> {
        if !droppable {
            return self.live().map_or(ToPublish::Closed, ToPublish::Live);
        }
        loop {
            if self.closed.load(Ordering::Acquire) {
                return ToPublish::Closed;
            }
            if let Some(guard) = self.core.try_lock() {
                #[cfg(test)]
                self.takes.core.fetch_add(1, Ordering::Relaxed);
                // A close that took the session first is seen under it, as `live` sees it.
                if self.closed.load(Ordering::Acquire) {
                    return ToPublish::Closed;
                }
                return ToPublish::Live(LiveCore {
                    core: core::mem::ManuallyDrop::new(guard),
                    lane: self.samples.as_ref(),
                });
            }
            let room = self
                .rooms
                .for_held(self.held_drop, self.holder(), self.wait_before_drop_us);
            let dropped = match room.behind() {
                Behind::TryAgain => {
                    #[cfg(test)]
                    self.takes.spins.fetch_add(1, Ordering::Relaxed);
                    core::hint::spin_loop();
                    continue;
                }
                Behind::WaitForSession => {
                    return self.live().map_or(ToPublish::Closed, ToPublish::Live)
                }
                #[cfg(any(feature = "listen", feature = "group"))]
                Behind::Dropped { on, told } => ToPublish::DroppedOn {
                    faces: match on {
                        DropSet::Faces(faces) => faces,
                        DropSet::Face(place) => self.rooms.dropped_on(place_of_mark(place)),
                    },
                    told,
                },
                // The dial face alone: the face congested, or held by another publish's send, is
                // that face, and there is no other to owe the publish to.
                #[cfg(not(any(feature = "listen", feature = "group")))]
                Behind::Dropped { told, .. } => ToPublish::DroppedOn { told },
            };
            #[cfg(feature = "transport-stats")]
            self.unsent_drops.fetch_add(1, Ordering::Relaxed);
            return dropped;
        }
    }

    /// Who holds the session now, as its holder marked itself ([`SendingOn`]).
    fn holder(&self) -> Holder {
        match self.sending_on.load(Ordering::SeqCst) {
            NOT_SENDING => Holder::Step,
            PUBLISHING => Holder::Publish,
            WAITING => Holder::Waiting,
            place => Holder::Sending(place),
        }
    }

    /// Run `held` while holding the session as a read step holds it: what a test of a publish that
    /// finds the session held by what is not a publish runs beside one.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn holding_as_a_step(&self, held: impl FnOnce()) {
        let _core = self.live();
        held();
    }

    /// Run `held` while holding the session as a read working out its wait holds it.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn holding_as_a_read_wait(&self, held: impl FnOnce()) {
        let _core = self.live();
        let _waiting = SendingOn::enter(&self.sending_on, WAITING);
        held();
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
            for actions in core.0.transport.ups() {
                report.absorb(&actions.stats_report());
            }
            // A group charges what its queue dropped, for want of room or past the reply limit,
            // where the tokio engine's group charges it, the transport's dropped messages; it
            // leaves with the group's join.
            #[cfg(feature = "group")]
            for group in &core.0.transport.groups {
                report.tx.n_dropped = report
                    .tx
                    .n_dropped
                    .saturating_add(usize::try_from(group.drops_total()).unwrap_or(usize::MAX));
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
    /// is due is read against `started_ms`, the reading of the clock the read's step made, so a
    /// job that takes longer than its own period runs once per call and does not keep the caller
    /// here.
    ///
    /// A read calls this only when its step found a job due by that reading, so a read with
    /// nothing due takes the lock for its jobs not at all. The first due job is taken under one
    /// take, and a job that ran is put back and the next taken under one more.
    #[cfg(feature = "ticker")]
    fn run_due_tickers(&self, started_ms: u64) {
        let mut next = match self.live() {
            Some(mut core) => core.0.tickers.take_next_due(started_ms),
            None => return,
        };
        while let Some((id, tick)) = next {
            let goes_on = tick();
            next = self.live().and_then(|mut core| {
                let now_ms = core.0.clock.now_us() / 1000;
                core.0.tickers.rearm(id, goes_on, now_ms);
                core.0.tickers.take_next_due(started_ms)
            });
        }
    }

    /// A build without periodic jobs has none due ([`Core::jobs_due_at`]).
    #[cfg(not(feature = "ticker"))]
    fn run_due_tickers(&self, _started_ms: u64) {}

    /// Hand out what the session delivered, with no lock held.
    ///
    /// A callback may step its session again (`zp_read` from inside a subscriber), and that step
    /// delivers nothing itself: the delivery this thread is already making goes on to hand out
    /// what the inner step queued, in order. Delivering from the inner call would run a callback
    /// inside itself, waiting on its own lock.
    fn deliver(&self) {
        self.deliveries.within(|entered| {
            if entered {
                self.hand_out_entered();
            }
        });
    }

    /// Everything [`Self::deliver`] hands out, inside the delivery it entered.
    fn hand_out_entered(&self) {
        // A callback can queue more for this delivery than the pass that ran it has already passed
        // over (a queryable's answer to the session's own get lies in the next round): the passes
        // go on until one hands nothing, so a get its own queryables answer inside the call ends
        // there.
        while self.hand_out() {}
        // The subscribers undeclared while a call of theirs ran, whose last call has ended now.
        self.let_go_of_released();
        // What the declaration watches are owed and the round had no room for when it came (the
        // catch-up of a watch declared while a round was handed out, the events a watch lost),
        // held now the round is handed out, each round sealed as the session is let go of and
        // handed out in turn.
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        while self.decl_watches.owes() {
            let Some(core) = self.live() else {
                break;
            };
            core.0.tell_decl_watches_owed();
            drop(core);
            if !self.hand_out() {
                break;
            }
        }
        // The tokens of a lost link the round had no room for, retracted now the round is handed
        // out, each round sealed as the session is let go of and handed out in turn.
        #[cfg(feature = "liveliness")]
        while self.samples.owes() {
            let Some(mut core) = self.live() else {
                break;
            };
            core.0.retract_owed();
            drop(core);
            if !self.hand_out() {
                break;
            }
        }
        // The legs that are over, after every reply queued before their ends: each callback is
        // dropped here, with no lock held, which is how the C program learns it (the reply
        // closure's `drop(context)`). A round another delivery still hands out may hold a reply
        // of one of them: that delivery tells the ends once it is through.
        #[cfg(feature = "query")]
        while self.gets.ends_pending() && self.samples.is_idle() {
            let Some(ended) = self.gets.take_end() else {
                break;
            };
            if let Some(mut core) = self.live() {
                core.0
                    .session
                    .pending_gets
                    .retain(|pending| pending.leg != ended.leg());
            }
            // The callback the end holds is let go of after what it was owed, with no lock held.
            self.hand_held(ended);
        }
    }

    /// Hand the callback of the leg that `ended` what its entry held to its end, with no lock held:
    /// the replies its consolidation made due, each taken out of its row, then those held whole,
    /// each taken out of the plane's held table, then the timeout that ended it, as upstream's
    /// querier hands them.
    #[cfg(feature = "query")]
    fn hand_held(&self, ended: Ended) {
        let (leg, row) = (ended.leg(), ended.row());
        while let Some(reply) = self.gets.take_due(leg) {
            self.gets.call(row, &reply);
        }
        while let Some(reply) = self.gets.take_held(leg) {
            self.gets.call(row, &reply);
        }
        if let Some(rid) = ended.timed_out() {
            self.gets.call(row, &timeout_reply(rid));
        }
        // The end's count of the row, given back last: the callback goes with it unless a record
        // of a round another delivery hands out holds it still, whose end lets it go.
        drop(self.gets.release(row));
    }

    /// One pass over what the session queued for the program's callbacks, under the delivery
    /// [`Self::deliver`] entered. Whether anything was handed out. The round, the matching changes
    /// and the queries each say without their locks whether they hold anything, so a pass that
    /// finds nothing, which every delivery's last pass is, takes none of their locks.
    fn hand_out(&self) -> bool {
        // The round the session wrote under its lock, in the order it was written.
        let mut handed = self.samples.deliver();
        // A face that came up or went down, a row at a time, told to each watcher as it stands
        // now, each taken out of its lock alone, so a sink that undeclares a watcher does not
        // wait on it.
        #[cfg(feature = "connectivity")]
        while self.faces.hand_out_next() {
            handed = true;
        }
        // Each listener owed its verdict, one at a time: its callback is taken out of its row
        // under the session's lock and called after it, and put back under the lock that looks
        // for the next. A callback out for a call is not taken again, so two calls of one never
        // overlap, and the thread that put it back finds the verdict it is owed since. A listener
        // undeclared since its verdict changed is handed nothing.
        if self.matching_owed.load(Ordering::Acquire) {
            // Each callback is moved into the walk that puts it back, so the pass itself lets
            // none go: `Self::owed_matching` is where one is.
            let mut called = None;
            while let Some((handle, matching, sink)) = self.owed_matching(called) {
                handed = true;
                sink.call(matching);
                called = Some((handle, sink));
            }
        }
        handed
    }

    /// Put `called`'s callback back in its row and take the next one owed its verdict out of its
    /// row, under the session's lock, with the verdict it is owed. A callback with no row to go
    /// back to, its row gone during the call or the session closed, is let go of here, after the
    /// lock: the one place a pass lets one go.
    fn owed_matching(
        &self,
        called: Option<(MatchingListenerHandle, MatchingSink)>,
    ) -> Option<(MatchingListenerHandle, bool, MatchingSink)> {
        let (gone, next) = match self.live() {
            Some(core) => {
                let mut tables = tables_mut(&core.0.session.registry);
                // Put back in its row, or let go of below, with no lock held, when the row went
                // during the call (an undeclare from inside it): the handle's generation tells a
                // row that took the slot since from the listener's. A row holds no callback while
                // its own is out, so what the put back replaces is none.
                let gone = called.and_then(|(handle, sink)| {
                    match tables.matching_listener_callback_mut(handle) {
                        Some(call) => call.sink.replace(sink),
                        None => Some(sink),
                    }
                });
                let next = tables.take_owed_matching(&mut 0, |call| call.sink.take());
                // Cleared under the lock a read sets it under, so a change found after this walk
                // keeps its word.
                if next.is_none() {
                    self.matching_owed.store(false, Ordering::Release);
                }
                (gone, next)
            }
            // The session closed during the call: the callback goes with no row to go to.
            None => (called.map(|(_, sink)| sink), None),
        };
        drop(gone);
        next
    }

    /// Run the callback `call` was begun for on `query`, which arrived on the link of
    /// `generation`, and send what it answered: its replies go out, then the hold its arrival took
    /// on the Final is let go. A queryable undeclared since lets go of the hold all the same. The
    /// caller ends the call.
    #[cfg(feature = "queryable")]
    fn run_queryable(&self, call: &QueryableCall, query: &dyn QueryView, generation: u64) {
        let mut onward = Onward::to(self, generation);
        if !call.retired() {
            let _answering =
                query::Answering::enter(self as *const Self as usize, generation, query.rid());
            let mut responder = query::responder_for(
                query.rid(),
                query.keyexpr(),
                query.parameters(),
                query.qos(),
                &mut onward,
            );
            // The queries the callback keeps are held through the session, as the face's holder.
            let holder = CoopHolder {
                engine: self.this.clone(),
            };
            call.ask(query, &mut responder, &holder);
        }
        self.answer(generation, query.rid(), query::Release::Hold);
    }

    /// A publish's leg to the peers the session's faces reach, when its destination admits the
    /// wire. A link that is down skips it, as a send over it would.
    // Out of line: the publish that calls it measured smaller with its link leg apart, the
    // held-session paths of the leg (`live_to_publish`, `hand_off`) then apart of it too.
    #[inline(never)]
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
        // zenoh's `is_droppable` (`face_send::droppable`). A message with no QoS of its own is sent
        // with the default's, as the send reads it.
        let congestion = meta.qos.unwrap_or(QosLevel::DEFAULT).congestion();
        let droppable = face_send::droppable(opts.reliable_bool(), congestion);
        let core = match self.live_to_publish(droppable) {
            ToPublish::Live(core) => core,
            ToPublish::Closed => return Ok(0),
            ToPublish::DroppedOn {
                #[cfg(any(feature = "listen", feature = "group"))]
                faces,
                told,
            } => {
                #[cfg(any(feature = "listen", feature = "group"))]
                self.hand_off(keyexpr, payload, opts, faces);
                return if told {
                    Err(FanoutError::HeldConduit)
                } else {
                    Ok(0)
                };
            }
        };
        // Marked as the holder for as long as it holds the session: a droppable publish that
        // finds it held between this one's sends tries the session again, where one behind what
        // is not a publish waits for it.
        let publishing = SendingOn::enter(&self.sending_on, PUBLISHING);
        // A publish that may not be dropped, on a session whose links share fewer outbound slots
        // than they are, may find every slot held by another link's frame its stream has not
        // finished. It then waits for one with nothing of the session held, as zenoh-pico's
        // blocking put waits for its transmit lock, within its `wait_before_close`
        // (`Self::wait_for_slots`). The run's order is the face send value's (`PublishRun`).
        #[cfg(feature = "listen")]
        let probe = !droppable && core.0.transport.tx_pool_short;
        #[cfg(not(feature = "listen"))]
        let probe = false;
        let mut run = PublishRun::new(
            cfg!(any(feature = "listen", feature = "group")),
            probe,
            core.0.config.tx_queue.wait_before_close_us,
            // The faces are sent in the order of their places, the dial role's the first.
            FIRST_FACE,
        );
        let begin = run.begin();
        // What was handed to the session before this publish leaves before it, and what was
        // handed while this publish held the session leaves after it.
        #[cfg(any(feature = "listen", feature = "group"))]
        if begin.hand_before {
            self.send_handed(&core.0);
        }
        let put = Publication {
            keyexpr,
            wire,
            payload,
            opts,
            meta: &meta,
        };
        let (outcome, stuck) = self.fan_out_in(&core.0, &put, None, begin.pass);
        // The clock is read only for a fan-out that stopped at a face, whose wait it bounds.
        let fanned = run.fanned(stuck, || core.0.now_us());
        #[cfg(feature = "listen")]
        let waits = match fanned.then {
            Then::WaitForSlots { .. } => core.0.transport.links.owing_waits(),
            Then::Done => OwingWaits::new_static(),
        };
        #[cfg(any(feature = "listen", feature = "group"))]
        if fanned.hand_after {
            self.send_handed(&core.0);
        }
        drop(publishing);
        drop(core);
        match fanned.then {
            Then::Done => outcome,
            #[cfg(feature = "listen")]
            Then::WaitForSlots { left_us, .. } => {
                self.wait_for_slots(&put, run, waits, left_us, outcome)
            }
            // Only a fan-out whose sends wait for no slot stops at a face, which a build that
            // listens on nothing never makes.
            #[cfg(not(feature = "listen"))]
            Then::WaitForSlots { .. } => outcome,
        }
    }

    /// Send `put` on from the face whose link found every outbound slot of the session held, and
    /// the faces after it, waiting each time with nothing of the session held until a link that
    /// holds a slot for a frame its stream has not finished has room or input
    /// (`LinkSupervisor::owing_waits`, the wait its own step makes for its room): its stack then
    /// takes what it owes, written by its step or by this publish, which has every link write what
    /// it owes before it tries again, so the slot is back. The faces before were sent it already, and are not again. Past the
    /// deadline, or with no link whose room can be waited on, the put is sent as any blocking send
    /// past its wait is.
    #[cfg(feature = "listen")]
    fn wait_for_slots(
        &self,
        put: &Publication<'_>,
        mut run: PublishRun,
        mut waits: OwingWaits,
        mut left_us: u64,
        mut outcome: Result<usize, FanoutError>,
    ) -> Result<usize, FanoutError> {
        loop {
            let waited = !waits.is_empty();
            if waited {
                self.rooms.waits().wait(
                    &waits,
                    u32::try_from(left_us.div_ceil(1_000)).unwrap_or(u32::MAX),
                );
            }
            let Some(core) = self.live() else {
                return outcome;
            };
            let publishing = SendingOn::enter(&self.sending_on, PUBLISHING);
            let now_us = core.0.now_us();
            core.0.transport.links.write_owed_now();
            let pass = run.waited(waited, now_us);
            let (more, again) = self.fan_out_in(&core.0, put, None, pass);
            if more.is_err() {
                outcome = more;
            }
            let fanned = run.fanned(again, || now_us);
            waits = match fanned.then {
                Then::WaitForSlots { .. } => core.0.transport.links.owing_waits(),
                Then::Done => OwingWaits::new_static(),
            };
            if fanned.hand_after {
                self.send_handed(&core.0);
            }
            drop(publishing);
            drop(core);
            match fanned.then {
                Then::Done => return outcome,
                Then::WaitForSlots { left_us: left, .. } => left_us = left,
            }
        }
    }

    /// Send `put` to each face whose link is up and to each group the session joined, but the
    /// faces in `skip`. Each face is sent the put, and one a face's link could not have carried is
    /// the one that is reported; a face whose link is down is skipped, as a send over it would.
    /// The face being sent to is marked as the one this publish holds ([`SendingOn`]) for as long
    /// as its send takes. What a handed leg is sent by, so a build that hands none has none.
    #[cfg(any(feature = "listen", feature = "group"))]
    fn fan_out(
        &self,
        core: &Core<L, C>,
        put: &Publication<'_>,
        skip: Option<&DroppedOn>,
    ) -> Result<usize, FanoutError> {
        self.fan_out_in(core, put, skip, Pass::EVERY_FACE).0
    }

    /// [`Self::fan_out`] by `pass`: with `listen`, to the faces from the one whose place is
    /// `pass.from` on ([`mark_of_place`]), with a send that does not wait for a slot when
    /// `pass.probe`. The faces are sent the put in order until one's link finds no outbound slot
    /// for it, which is answered beside the outcome and is sent nothing, nor are the faces after
    /// it, nor the groups.
    fn fan_out_in(
        &self,
        core: &Core<L, C>,
        put: &Publication<'_>,
        skip: Option<&DroppedOn>,
        pass: Pass,
    ) -> (Result<usize, FanoutError>, Option<u64>) {
        let Publication {
            keyexpr,
            wire,
            payload,
            opts,
            meta,
        } = *put;
        // The key as the session's tables name it: by the declaration the ABI named it by while
        // that declaration stands, and whole otherwise. An empty key names nothing a link carries.
        let Some(named) = tables(&core.session.registry).named_by(keyexpr, wire.mapping_id) else {
            return (Err(FanoutError::ExceedsCapacity), None);
        };
        let send = wz_session_core::session_actions::SendAs {
            reliable: opts.reliable_bool(),
            express: meta.is_express(),
            priority: opts.priority_band(),
        };
        let link_leg = LinkLeg {
            named,
            payload,
            kind: opts.kind,
            meta,
            send,
        };
        let (outcome, stuck) = self.send_on_links(core, &link_leg, skip, pass);
        if stuck.is_some() {
            return (outcome, stuck);
        }
        // And each group the session joined, which its task frames and sends.
        #[cfg(feature = "group")]
        let mut outcome = outcome;
        #[cfg(feature = "group")]
        for group in &core.transport.groups {
            if skip.is_some_and(|dropped| self.rooms.skips(dropped, group.at())) {
                continue;
            }
            let _sending = SendingOn::enter(&self.sending_on, mark_of_place(group.at()));
            let sent = group.publish(GroupPut {
                keyexpr,
                wire,
                payload,
                kind: opts.kind,
                meta,
                reliable: send.reliable,
                priority: send.priority,
            });
            if sent.is_err() {
                outcome = sent;
            }
        }
        (outcome, None)
    }

    /// Send `leg` to the session's links by `pass` (`Self::fan_out_in`), each face marked as the
    /// session's holder's send on it while it is sent (`SendingOn`), as every put the session
    /// sends to its links is, a plain one through a write filter (`Self::put_plain_in`) among
    /// them. A link that does not take the plain form (one that rewrites the keys the session
    /// originates) is sent the owned message in its place, so each link answers for itself.
    // Out of line: the publish and the put through a write filter send through this one body.
    #[inline(never)]
    fn send_on_links(
        &self,
        core: &Core<L, C>,
        leg: &LinkLeg<'_>,
        skip: Option<&DroppedOn>,
        pass: Pass,
    ) -> (Result<usize, FanoutError>, Option<u64>) {
        let LinkLeg {
            named,
            payload,
            kind,
            meta,
            send,
        } = *leg;
        let wz_session_core::session_actions::SendAs {
            reliable,
            express,
            priority,
        } = send;
        let mut outcome = Ok(0);
        #[cfg(not(any(feature = "listen", feature = "group")))]
        let _ = skip;
        for (at, _, actions) in core.transport.ups_at() {
            #[cfg(any(feature = "listen", feature = "group"))]
            let dropped_on = skip.is_some_and(|dropped| self.rooms.skips(dropped, at));
            #[cfg(not(any(feature = "listen", feature = "group")))]
            let dropped_on = false;
            // How the face is sent the publish is the face send value's (`Pass::face_send`): the
            // faces go in the order of their places, so a pass that stopped at one goes on from it.
            let place = mark_of_place(at);
            let how = pass.face_send(place, dropped_on);
            if how == FaceSend::Skip {
                continue;
            }
            let _sending = SendingOn::enter(&self.sending_on, place);
            #[cfg(test)]
            self.takes.face_marks.fetch_add(1, Ordering::Relaxed);
            // Each link names the key as its own key-wire form says. A publication is written from
            // the borrowed key, bytes and metadata into the slot its link lends, a plain Put by its
            // own shorter writer, unless the session or the build leaves it to the owned send below.
            let key = key_on_link(actions, named);
            let plain = kind == SampleKind::Put && meta.is_plain_apart_from_qos();
            // A send that may not wait is told apart from one whose link has room: one with none
            // ends the fan-out at this face, and a chain of fragments, which such a send does not
            // begin, is sent as the caller's own send.
            #[cfg(feature = "listen")]
            if how == FaceSend::Probe {
                let probed = if plain {
                    actions.try_send_plain_put_qos(
                        key,
                        payload,
                        meta.qos,
                        wz_session_core::session_actions::SendAs {
                            reliable,
                            express,
                            priority,
                        },
                    )
                } else {
                    actions.try_send_publication_qos(
                        key,
                        kind,
                        payload,
                        meta,
                        wz_session_core::session_actions::SendAs {
                            reliable,
                            express,
                            priority,
                        },
                    )
                };
                let answer = match probed {
                    Some(Ok(Probed::NoRoom)) => ProbeAnswer::NoRoom,
                    Some(Ok(Probed::Sent)) => ProbeAnswer::Sent,
                    Some(Err(error)) => {
                        let sent = leg_outcome(Err(error));
                        if sent.is_err() {
                            outcome = sent;
                        }
                        ProbeAnswer::Failed
                    }
                    Some(Ok(Probed::Chain)) | None => ProbeAnswer::Chain,
                };
                match after_probe(answer) {
                    AfterProbe::StopHere => return (outcome, Some(place)),
                    AfterProbe::Next => continue,
                    AfterProbe::SendAsOwn => {}
                }
            }
            let lent = if plain {
                actions.send_plain_put_qos(
                    key,
                    payload,
                    meta.qos,
                    wz_session_core::session_actions::SendAs {
                        reliable,
                        express,
                        priority,
                    },
                )
            } else {
                actions.send_publication_qos(
                    key,
                    kind,
                    payload,
                    meta,
                    wz_session_core::session_actions::SendAs {
                        reliable,
                        express,
                        priority,
                    },
                )
            };
            let sent = if let Some(lent) = lent {
                leg_outcome(lent)
            } else if !lent_push::LENT_PUBLICATION_MAY_DECLINE {
                // No send of this build declines one, so the owned builders are not linked.
                Err(FanoutError::ExceedsCapacity)
            } else {
                let suffix = key.wire().suffix();
                let push = match (kind, key.wire().id()) {
                    (SampleKind::Put, 0) => {
                        push_build::build_push_literal_with_meta(key.text(), payload, meta)
                    }
                    (SampleKind::Del, 0) => {
                        push_build::build_push_del_literal_with_meta(key.text(), meta)
                    }
                    (SampleKind::Put, mapping_id) => {
                        push_build::build_push_aliased_with_meta(mapping_id, suffix, payload, meta)
                    }
                    (SampleKind::Del, mapping_id) => {
                        push_build::build_push_del_aliased_with_meta(mapping_id, suffix, meta)
                    }
                };
                match push {
                    Ok(push) => leg_outcome(actions.send_network_message_qos(
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
        (outcome, None)
    }

    /// Owe the publish of `payload` on `keyexpr` with `opts` to the session's faces it was not
    /// dropped on (`dropped_on`): it is kept in a place the session took at open and sent by
    /// whoever next holds the session for a publish or a read, ahead of what that holder sends, and
    /// here at once when the session is free by now. Past the publishes of its priority the session
    /// keeps at most, or with no place for it, it is dropped on the other faces too, as a message
    /// that finds its queue full is, and counted as the one drop it already is.
    // Out of line: the copy of a dropped publish is taken only when a holder drops it.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[inline(never)]
    fn hand_off(
        &self,
        keyexpr: &str,
        payload: &[u8],
        opts: &PublishOptions<'_>,
        dropped_on: DroppedOn,
    ) {
        let priority = opts.priority_band();
        {
            let mut handed = self.handed();
            let room = self.handed_limits.keeps(priority, handed.held_at(priority));
            if room && handed.keep(keyexpr, payload, opts, dropped_on) {
                self.owed.store(true, Ordering::SeqCst);
            }
        }
        // The holder may have let go of the session since the publish found it held, with
        // nobody left to send what was handed.
        if let Some(core) = self.core.try_lock() {
            if !self.closed.load(Ordering::Acquire) {
                self.send_handed(&core.0);
            }
        }
    }

    /// Send what was handed to the session ([`Self::hand_off`]), in the order it was handed, each
    /// publish to the faces it was not dropped on.
    // Out of line: four sends of a publish and of its hand-off ask it, each a copy inlined.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[inline(never)]
    fn send_handed(&self, core: &Core<L, C>) {
        if self.owed.load(Ordering::SeqCst) {
            self.send_handed_now(core);
        }
    }

    /// [`Self::send_handed`], looking at the table under its lock whatever `owed` says: what a
    /// read step sends, so a publish a holder passed over on a stale reading leaves on the next
    /// step. Each publish is taken out under the table's lock, sent with the lock let go, since a
    /// send may wait for room and a publish that finds the session held must not wait behind it,
    /// and given back under the lock, so its place is free for the next. It is sent by its whole
    /// key, which holds no declaration the session might retract meanwhile.
    #[cfg(any(feature = "listen", feature = "group"))]
    fn send_handed_now(&self, core: &Core<L, C>) {
        let whole = WireKey::literal();
        loop {
            let taken = {
                let mut handed = self.handed();
                let leg = handed.take_first();
                if leg.is_none() {
                    self.owed.store(false, Ordering::SeqCst);
                }
                leg
            };
            let Some(leg) = taken else {
                return;
            };
            {
                let opts = leg.options();
                let meta = opts.push_metadata();
                // The caller was answered when the publish was kept.
                let _ = self.fan_out(
                    core,
                    &Publication {
                        keyexpr: leg.keyexpr(),
                        wire: &whole,
                        payload: leg.payload(),
                        opts: &opts,
                        meta: &meta,
                    },
                    Some(leg.dropped_on()),
                );
            }
            self.handed().give_back(leg);
        }
    }

    /// The table of handed publishes, held.
    #[cfg(any(feature = "listen", feature = "group"))]
    fn handed(&self) -> MutexGuard<'_, HandedTable> {
        #[cfg(test)]
        self.takes.handed.fetch_add(1, Ordering::Relaxed);
        lock(&self.handed)
    }

    /// A publish's leg to the session's own subscribers, when its destination admits them: the
    /// subscribers whose origin admits it, as the registry's loopback finds them, are each handed
    /// it here, with no lock of the session held, inside the put as zenoh-pico's does
    /// (`vendor/zenoh-pico/src/session/subscription.c` @ `_z_trigger_subscriptions_impl`), by a
    /// call begun on each one's row under the session's lock ([`SubscriberCall`]). A callback is
    /// called through a shared borrow: one running on another thread is called beside it, and one
    /// the putting thread is inside of is called again from inside itself, as pico's is, so a put a
    /// callback makes on its own subscriber's key reaches it at once, at any depth.
    /// The number of subscribers reached.
    #[cfg(feature = "local-subscriber")]
    fn publish_to_subscribers(
        &self,
        keyexpr: &str,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        if !opts.allowed_destination.allows_local() {
            return Ok(0);
        }
        let Some(core) = self.live() else {
            return Ok(0);
        };
        let sample = opts.loopback_sample(keyexpr, payload);
        // SAFETY: the session's lock is held (`core`).
        unsafe { self.samples.capture() };
        core.0.session.registry.borrow_mut().local_publish(&sample);
        // SAFETY: as above.
        let mut reached = unsafe { self.samples.captured() };
        drop(core);
        let count = reached.len();
        // A callback that steps the session from inside the put hands out nothing itself, as one
        // inside a delivery does; nor does an undeclare inside it wait for this call.
        self.deliveries.within(|_| {
            for call in reached.iter() {
                call.hand(&sample);
            }
        });
        // Each call is ended; a row whose last call this was, its subscriber undeclared meanwhile,
        // is let go of by the delivery below, its drop perhaps the program's own, with no lock held.
        while let Some(call) = reached.pop() {
            self.samples.end_call(call);
        }
        self.deliver();
        Ok(count)
    }

    /// Attach this engine to `fan` as what ends the legs it tags with the fan's key, before a leg
    /// is issued: the key, `None` for a get no token can cancel, or [`FanCancelled`] for a fan
    /// cancelled already, whose get issues no leg. Nothing is kept for a leg but its tag.
    #[cfg(feature = "query")]
    fn tag_of(&self, fan: Option<&CancellableFan>) -> Result<Option<FanKey>, FanCancelled> {
        let Some(fan) = fan else {
            return Ok(None);
        };
        let canceller: Weak<dyn FanCanceller> = Weak::<Self>::clone(&self.this);
        if fan.attach(&canceller) {
            Ok(Some(fan.key()))
        } else {
            Err(FanCancelled)
        }
    }

    /// Whether `fan` was cancelled while its legs were being issued: none further is issued, and
    /// the legs tagged `tag` are ended here, since the cancel may have run before the last of
    /// them was pending.
    #[cfg(feature = "query")]
    fn cut_short(&self, fan: Option<&CancellableFan>, tag: Option<FanKey>) -> bool {
        match (fan, tag) {
            (Some(fan), Some(key)) if fan.is_cancelled() => {
                self.cancel_fan(key);
                true
            }
            _ => false,
        }
    }

    /// Give back to the session what a key held of its declarations (`RowHolds`), with no lock
    /// of the session held: a release may retract a declaration, which takes the lock.
    // Out of line: every undeclaration, refused declaration and close gives holds back, and each
    // would otherwise carry the releases and the drop of what the key kept.
    #[inline(never)]
    fn give_back(&self, holds: WireHolds) {
        holds.release(self);
    }

    /// Let go of `wire`, a key no row came to hold, giving back what it held
    /// ([`Self::give_back`]), with no lock of the session held.
    // Out of line: each refusal of a declaration lets its key go, and one body serves them.
    #[inline(never)]
    fn let_go_of_key(&self, wire: WireKey) {
        self.give_back(wire.into_holds());
    }

    /// Let go of each row whose last call ended after it was undeclared, when a call said one may
    /// wait ([`Round::take_marked`]): a walk of each table whose calls the round ends takes them out
    /// one at a time under the session's lock (`SessionTables::release_drained_subscriber` and its
    /// kin) and drops each after it, so a C program's `drop` never runs under the lock.
    fn let_go_of_released(&self) {
        if !self.samples.take_marked() {
            return;
        }
        #[cfg(test)]
        self.takes.walks.fetch_add(1, Ordering::Relaxed);
        self.let_go_of_drained(|tables, cursor| {
            tables
                .release_drained_subscriber(cursor)
                .map(|row| row.into_callback())
        });
        #[cfg(feature = "liveliness")]
        self.let_go_of_drained(|tables, cursor| {
            tables
                .release_drained_liveliness_subscriber(cursor)
                .map(|row| row.into_callback())
        });
        #[cfg(feature = "queryable")]
        self.let_go_of_drained(|tables, cursor| {
            tables
                .release_drained_queryable(cursor)
                .map(|row| row.into_callback())
        });
    }

    /// Walk one table with `take`, which takes out the next row at or after its cursor whose last
    /// call ended: each row is taken under the session's lock, its drop counted as under way from
    /// there, and dropped after the lock.
    fn let_go_of_drained<R: RowHolds>(
        &self,
        mut take: impl FnMut(&mut CoopTables, &mut usize) -> Option<R>,
    ) {
        let mut cursor = 0;
        loop {
            let taken = {
                let guard = self.core.lock();
                let mut tables = tables_mut(&guard.0.session.registry);
                take(&mut tables, &mut cursor).map(|row| (row, self.samples.releasing()))
            };
            let Some((row, releasing)) = taken else {
                break;
            };
            self.give_back(row.into_holds());
            // Only now is the row's drop over, which a waiting undeclaration reads.
            drop(releasing);
        }
    }

    /// Return once subscriber `handle`, undeclared while a call of it ran, is let go of: after
    /// its last call has returned and its row, with the program's callback, was dropped (P11).
    /// A thread that delivers now returns at once: the call that runs may be its own, below it on
    /// its stack (a callback that undeclares its own subscriber), whose end lets the row go as the
    /// delivery it is inside of ends.
    fn wait_for_release(&self, handle: SubscriberHandle) {
        self.wait_until_let_go(
            |tables| tables.subscribers().holds_slot(handle),
            || self.samples.released_settled(),
        );
    }

    /// [`Self::wait_for_release`] for liveliness subscriber `handle`, whose calls the round of
    /// deliveries ends as a subscriber's.
    #[cfg(feature = "liveliness")]
    fn wait_for_liveliness_release(&self, handle: LivelinessSubscriberHandle) {
        self.wait_until_let_go(
            |tables| tables.liveliness_subscribers().holds_slot(handle),
            || self.samples.released_settled(),
        );
    }

    /// [`Self::wait_for_release`] for queryable `handle`: a query queued for it holds a call of it
    /// until a delivery hands the query out, which hands the undeclared queryable nothing.
    #[cfg(feature = "queryable")]
    fn wait_for_queryable_release(&self, handle: QueryableHandle) {
        self.wait_until_let_go(
            |tables| tables.queryables().holds_slot(handle),
            || self.samples.released_settled(),
        );
    }

    /// Return once a row of the session's tables undeclared while a call of it ran is let go of:
    /// `held` reads whether its table still holds it, `settled` whether no drop of a row taken
    /// out of its table is under way. At once on a thread that delivers now (see
    /// [`Self::wait_for_release`]).
    fn wait_until_let_go(&self, held: impl Fn(&CoopTables) -> bool, settled: impl Fn() -> bool) {
        if self.deliveries.delivers_here() {
            return;
        }
        loop {
            // A round sealed and handed out by no delivery yet, or a query queued, may owe the row
            // a call: handed out here, the call hands nothing to an undeclared entity and is
            // ended, and the rows whose last call ended are let go of.
            self.deliver();
            let still_held = {
                let guard = self.core.lock();
                let tables = tables(&guard.0.session.registry);
                held(&tables)
            };
            // Out of its table, the row is dropped by whoever took it, after the lock: settled,
            // no drop is under way.
            if !still_held && settled() {
                return;
            }
            sleep_ms(1);
        }
    }

    /// Let go of the rows of the session's own declarations, which its close emptied: each row is
    /// taken out under the session's lock, and the row let go of after the lock, one at a time, so
    /// the last holder of a callback, a C program's `drop`, never runs under it. A subscriber a
    /// call of which runs is let go of once the call ends ([`Self::wait_for_release`]).
    fn let_go_of_rows(&self) {
        loop {
            let undeclared = {
                let guard = self.core.lock();
                let mut tables = tables_mut(&guard.0.session.registry);
                let Some((handle, _)) = tables.subscribers().iter().next() else {
                    break;
                };
                tables
                    .undeclare_subscriber(handle)
                    .map(|undeclared| (handle, undeclared.taken))
            };
            match undeclared {
                Some((_, Some(row))) => self.give_back(row.into_holds()),
                Some((handle, None)) => self.wait_for_release(handle),
                None => {}
            }
        }
        loop {
            let row = {
                let guard = self.core.lock();
                let mut tables = tables_mut(&guard.0.session.registry);
                let Some((handle, _)) = tables.matching_listeners().iter().next() else {
                    break;
                };
                tables
                    .undeclare_matching_listener(handle)
                    .and_then(|unwatched| unwatched.row)
            };
            drop(row);
        }
        #[cfg(feature = "queryable")]
        loop {
            let undeclared = {
                let guard = self.core.lock();
                let mut tables = tables_mut(&guard.0.session.registry);
                let Some((handle, _)) = tables.queryables().iter().next() else {
                    break;
                };
                tables
                    .undeclare_queryable(handle)
                    .map(|undeclared| (handle, undeclared.taken))
            };
            match undeclared {
                Some((_, Some(row))) => self.give_back(row.into_holds()),
                Some((handle, None)) => self.wait_for_queryable_release(handle),
                None => {}
            }
        }
        #[cfg(feature = "liveliness")]
        loop {
            let undeclared = {
                let guard = self.core.lock();
                let mut tables = tables_mut(&guard.0.session.registry);
                let Some((handle, _)) = tables.liveliness_subscribers().iter().next() else {
                    break;
                };
                tables
                    .undeclare_liveliness_subscriber(handle)
                    .map(|undeclared| (handle, undeclared.taken))
            };
            match undeclared {
                Some((_, Some(row))) => self.give_back(row.into_holds()),
                Some((handle, None)) => self.wait_for_liveliness_release(handle),
                None => {}
            }
        }
    }

    /// Drop leg `leg`'s callback here, its end decided by the session itself (cancelled, or never
    /// sent), and leave no end of it waiting for a delivery.
    #[cfg(feature = "query")]
    fn end_leg_now(&self, leg: u64) {
        let ended = self.gets.forget_end(leg);
        self.gets.forget_due(leg);
        while self.gets.take_held(leg).is_some() {}
        if let Some(ended) = ended {
            drop(self.gets.release(ended.row()));
        }
    }

    /// Hold one leg of a get pending in the table of `face` (a link's, a group's, or the
    /// session's own, `LOCAL_FACE`) under `rid`, owed `finals` Finals: the leg's callback minted
    /// in a row of the plane's, and its sink registered with the deadline and the accepted key the
    /// get states. Out of line where a get issues more than one kind of leg (to groups, or to the
    /// session itself, besides its links), so those legs are held by one body and not by a copy
    /// each; a build whose get asks its links alone has one caller, which keeps it inline.
    #[cfg(feature = "query")]
    #[cfg_attr(any(feature = "group", feature = "local-queryable"), inline(never))]
    fn hold_leg(
        &self,
        core: &Core<L, C>,
        ask: &mut LegAsk<'_, '_>,
        face: FaceId,
        leg_id: u64,
        rid: wz_session_core::wire_id::RequestId,
        finals: u32,
    ) -> LegHeld {
        let timeout_ms = ask.opts.effective_timeout_ms();
        // Rounded up, so a get whose deadline the sweep reads in whole milliseconds never ends
        // before its timeout.
        let deadline_ms =
            (timeout_ms > 0).then(|| leg_deadline_ms(core.clock.now_us(), timeout_ms));
        // A get no row holds is refused before its leg's callback is minted.
        match core
            .session
            .registry
            .borrow_mut()
            .gets_mut(face)
            .map(|gets| gets.replies.has_room())
        {
            Some(true) => {}
            Some(false) => return LegHeld::NoRoom,
            None => return LegHeld::Gone,
        }
        // The leg's callback, in a row of the plane's the entry's sink holds.
        let Some(row) = self.gets.open_leg(&mut *ask.mint, ask.expose) else {
            return LegHeld::NoRoom;
        };
        // SAFETY: the sink goes into a table of pending gets, which the session
        // reaches under its lock alone, and is handed its replies there.
        let leg_sink = unsafe { get::LegSink::new(leg_id, row, &self.gets, &self.samples) };
        let sink = ConsolidatingSink::with_hold(
            ask.opts.resolved_consolidation(),
            leg_sink,
            get::LegHold::new(leg_id, &self.gets),
        );
        let accept = ReplyAcceptance::for_query(ask.keyexpr, ask.opts.effective_accept_replies());
        let registered = core
            .session
            .registry
            .borrow_mut()
            .gets_mut(face)
            .map(|gets| {
                gets.replies
                    .register_sink(rid, finals, deadline_ms, accept, sink)
            });
        match registered {
            Some(Ok(_)) => LegHeld::Held,
            Some(Err(RegisterError::TableFull)) => LegHeld::Refused { table_full: true },
            Some(Err(_)) | None => LegHeld::Refused { table_full: false },
        }
    }

    /// One reply to the query that came in under `generation`, as its queryable makes it: onto
    /// the query's link, written into the link's transmit slot under the session's lock, or to the
    /// session's own get. Refused, sending nothing, when its payload or its attachment is longer
    /// than the session's `MAX_REPLY_PAYLOAD_BYTES`; dropped, as a lost link drops it, when the
    /// session is closed or the query's link is no longer the session's.
    #[cfg(feature = "queryable")]
    fn send_reply(&self, generation: u64, parts: ReplyParts<'_>) -> Result<(), ReplyError> {
        let Some(core) = self.live() else {
            return Ok(());
        };
        let (payload, attachment) = parts.bounded_lengths();
        let most = core.0.config.limits.max_reply_payload_bytes();
        if !most.admits(payload) || !most.admits(attachment) {
            return Err(ReplyError::PayloadTooLarge);
        }
        // The session's own get is answered to its pending entry, which is the registry's: what
        // the entry's consolidation forwards at once is handed to the leg's callback by this
        // thread, once it lets go of the session, and what it holds is handed out when the answer
        // ends (`Self::answer`).
        #[cfg(feature = "local-queryable")]
        if generation == query::LOCAL_QUERY {
            let reply: wz_session_core::reply::InboundReply =
                wz_session_core::query::QueryReply::from_parts(&parts).into();
            self.gets.capture();
            core.0
                .session
                .registry
                .borrow_mut()
                .local
                .replies
                .deliver_local_reply(&reply);
            let reached = self.gets.captured();
            drop(core);
            if let Some(leg) = reached {
                // A callback that steps the session from inside the reply hands out nothing
                // itself, as one inside a delivery does.
                self.deliveries.within(|_| self.gets.call(leg, &reply));
                drop(self.gets.release(leg));
                self.deliver();
            }
            return Ok(());
        }
        if let Some(route) = core.0.transport.answer_route(generation) {
            route.send_reply_parts(parts);
        }
        Ok(())
    }

    /// One turn of the answer to the query `rid` on the link of `generation` has ended, its
    /// replies sent as they were made ([`Self::send_reply`]): with `release`, let go of one hold
    /// on its Final, sending the Final when it was owed and this was the last hold. Nothing is sent
    /// on a link that is no longer the session's. On a group, what the replies staged there is
    /// written by this call, on the calling thread.
    #[cfg(feature = "queryable")]
    fn answer(
        &self,
        generation: u64,
        rid: wz_session_core::wire_id::RequestId,
        release: query::Release,
    ) {
        let Some(core) = self.live() else {
            return;
        };
        let due = match release {
            query::Release::Hold => self
                .plane
                .with_holds(|holds| holds.release(generation, rid)),
            query::Release::Kept => self
                .plane
                .with_holds(|holds| holds.release_kept(generation, rid)),
        };
        // The session's own get is answered to its pending entry, which is the registry's.
        #[cfg(feature = "local-queryable")]
        if generation == query::LOCAL_QUERY {
            if due.is_some() {
                core.0
                    .session
                    .registry
                    .borrow_mut()
                    .local
                    .replies
                    .deliver_local_final(rid);
            }
            drop(core);
            self.deliver();
            return;
        }
        if let (Some(qos), Some(route)) = (due, core.0.transport.answer_route(generation)) {
            route.send_response_final(rid, qos);
        }
        // A group's sink only stages: a kept query answered from the program's own thread would
        // otherwise leave when the read task's wait ends, up to the group's tick a leg.
        #[cfg(feature = "group")]
        core.0.transport.write_answers(generation);
    }

    /// Hand the liveliness subscriber `handle` names the tokens the session already knows, which
    /// its declaration with history is owed, on this thread with no lock held while each is handed:
    /// a call is begun on its row, under the session's lock the next token's key is copied into a
    /// buffer on this stack ([`Registry::next_history_token`]), the lock is let go, the callback is
    /// called, and the next is looked for from where the last stood. A session closed meanwhile, or
    /// the subscriber undeclared, hands no more; the call is ended as the history is.
    #[cfg(feature = "liveliness")]
    fn hand_history(&self, handle: LivelinessSubscriberHandle) {
        // A callback that steps the session from inside its history hands out nothing itself, as
        // one inside a delivery does.
        self.deliveries.within(|_| self.tell_history(handle));
    }

    /// The history [`Self::hand_history`] hands, inside the delivery it entered.
    #[cfg(feature = "liveliness")]
    fn tell_history(&self, handle: LivelinessSubscriberHandle) {
        let begun = self.live().and_then(|core| {
            let tables = tables(&core.0.session.registry);
            let id = tables.liveliness_subscribers().get(handle)?.id();
            let call = tables.begin_liveliness_subscriber(handle)?;
            Some((id, LivelinessCall::new(call)))
        });
        let Some((id, call)) = begun else {
            return;
        };
        let mut cursor = HistoryCursor::default();
        let mut key = [0u8; caps::MAX_KEYEXPR_BYTES];
        loop {
            let next = {
                let Some(core) = self.live() else {
                    break;
                };
                let registry = core.0.session.registry.borrow();
                let found = registry.next_history_token(u64::from(id), cursor).and_then(
                    |(at, token, text)| {
                        let bytes = text.as_bytes();
                        key.get_mut(..bytes.len())?.copy_from_slice(bytes);
                        Some((at, token, bytes.len()))
                    },
                );
                found
            };
            let Some((at, token_id, len)) = next else {
                break;
            };
            cursor = at;
            // The key was a `&str` the registry held, copied whole.
            let Some(keyexpr) = key
                .get(..len)
                .and_then(|bytes| core::str::from_utf8(bytes).ok())
            else {
                break;
            };
            call.hand(LivelinessSample {
                kind: LivelinessSampleKind::Put,
                keyexpr,
                token_id,
            });
        }
        // A row whose last call this was, its subscriber undeclared from inside its history, is
        // let go of by the delivery the declaration ends with.
        self.samples.end_liveliness_call(call);
    }

    /// Step the session until it has nothing more to do, move its link on, and notice a session
    /// that ended. The step reads the clock once, after its tasks ran, and measures everything it
    /// does by that reading, which it returns; `None` once the session ended.
    fn step(&self, core: &mut Core<L, C>) -> Option<u64> {
        // What a lost link's peer is still owed comes before anything the links bring now.
        #[cfg(feature = "liveliness")]
        if self.samples.owes() {
            core.retract_owed();
        }
        core.run_tasks();
        let now_us = core.now_us();
        // A link's receive sweeps nothing, so the session ends the chains of its one reassembly
        // Router past their deadline here, once a step and by its reading, whichever link's task
        // ran; on the epoch its links staged them on, which is not the clock's own.
        let chain_ms = core.session_time.ms_at(now_us);
        core.transport.router.sweep(chain_ms);
        // A get whose deadline has passed ends with zenoh's timeout reply and its Final, here,
        // because this is what runs on every step and the entries are the registry's.
        #[cfg(feature = "query")]
        {
            let now_ms = now_us / 1000;
            let mut registry = core.session.registry.borrow_mut();
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
        if core.poll_links(redial_ms, now_us).is_err() {
            self.closed.store(true, Ordering::Release);
            return None;
        }
        // A group told the session's keyexprs that came up, at the open or joined again, asks
        // for its members' with the session's next entity id, as the tokio engine's group asks
        // when it comes up. Best effort: a member's own declarations reach the group later all
        // the same, so a session with no entity id left does not ask.
        #[cfg(feature = "group")]
        for group in &core.transport.groups {
            if group.owes_keyexpr_ask() {
                if let Some(interest_id) = core.session.take_entity_id() {
                    group.ask_keyexprs(u64::from(interest_id));
                }
            }
        }
        // What the peers declared moved only where a face's tables were written since the
        // listeners were last read.
        let written = core.session.registry.borrow().faces_written();
        if core.session.matching.moved(written) {
            self.read_matching(core);
        }
        Some(now_us)
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
        let mut asked = None;
        while let Some(face) = core.transport.next_up_face(true, asked) {
            asked = Some(face);
            if let Some(actions) = core.transport.up_actions(face) {
                actions
                    .next_outbound_interest_id
                    .store(u64::from(u32::MAX) + 1, Ordering::Relaxed);
            }
        }
    }

    /// The end of a matching listener's declaration the tables answered under `guard`: its new
    /// Interest asked of each link and its first verdict delivered once the lock is let go, or the
    /// refusal, its callback let go of with no lock held.
    fn matching_declared(
        &self,
        mut guard: LiveCore<'_, L, C>,
        declared: Result<Watching<kind::MatchingListener>, Refused<MatchingCall>>,
    ) -> Result<MatchId, Declined> {
        let core = &mut guard.0;
        let watching = match declared {
            Ok(watching) => watching,
            Err(refused) => {
                drop(guard);
                let why = Declined::from(refused.why);
                drop(refused.callback);
                return Err(why);
            }
        };
        // A new Interest is asked of each link from its row; one held already was asked.
        if let Some(opened) = watching.interest {
            core.announce(DeclaredRow::of(opened.handle));
        }
        // A listener that matches already is told so as it is declared, as zenoh-pico tells it
        // (`vendor/zenoh-pico/src/net/filtering.c` @ `_z_write_filter_ctx_add_callback`).
        self.read_matching(core);
        drop(guard);
        self.deliver();
        Ok(row_id(watching.handle))
    }

    /// Read the verdict of every matching listener off what the peers and the session itself
    /// declare now, each one that changed owed to its callback in its row, which the delivery
    /// after the lock hands it: after a step that wrote the faces' tables, and after each
    /// declaration of the session's own that may move a verdict.
    fn read_matching(&self, core: &Core<L, C>) {
        let registry = core.session.registry.borrow();
        core.session.matching.read_at(registry.faces_written());
        let mut cursor = 0;
        while registry
            .app
            .tables
            .next_matching_change(&mut cursor, &*registry)
            .is_some()
        {
            self.matching_owed.store(true, Ordering::Release);
        }
    }

    /// Ask the session's own queryables a get of this session, as zenoh-pico's
    /// `_z_session_deliver_query_locally` does after the query went out: each queryable that
    /// matches holds the get's Final, the Final is owed now and the row `own` took for it is let
    /// go, so it reaches the get once the last of them has answered, at once when none matched.
    /// The queryables it matched, which the get hands its query itself ([`Self::hand_own_get`]).
    #[cfg(feature = "local-queryable")]
    fn ask_own_queryables(
        &self,
        core: &mut Core<L, C>,
        own: query::OwnFinalHold<'_>,
        keyexpr: &str,
        opts: &QueryOptionsOf<'_>,
    ) -> query::Asked {
        let rid = own.rid();
        let qos = opts.qos.unwrap_or(QosLevel::DEFAULT);
        let envelope = QueryEnvelope {
            rid,
            target: opts.effective_target(),
            qos,
        };
        // A body the codec refuses is one no link could carry either: no queryable is asked, and
        // the Final is owed as one that matched none.
        let query = opts.loopback_query().ok();
        // The session's queryables only begin a call and hold the query's Final
        // (`QueryPlane::arrive`), so none stages a reply here: the stage they are handed has no
        // room.
        let mut staged = ReplyStage::<Lent>::default();
        let mut registry = core.session.registry.borrow_mut();
        if let Some(query) = &query {
            self.plane.asking_locally(|| {
                registry.ask_own_queryables(envelope, keyexpr, query, &mut staged)
            });
        }
        let gets = &mut registry.local;
        self.plane
            .with_holds(|holds| holds.owe(query::LOCAL_QUERY, rid, qos));
        if own.release().is_some() {
            gets.replies.deliver_local_final(rid);
        }
        self.plane.take_asked()
    }

    /// Hand the session's own get to each of its queryables it was asked of, inside the get and
    /// with no lock held, then hand out what they answered. Each is called at once on the caller's
    /// thread, one whose callback this thread is inside of as well, as zenoh-pico's
    /// `_z_session_deliver_query_locally` hands it to `_z_trigger_queryables`, which calls each
    /// callback where it stands (`vendor/zenoh-pico/src/session/queryable.c` @
    /// `qle_info->_callback(&query, qle_info->_arg);`): a callback is called through a shared
    /// borrow, from inside itself too, so nothing of the query is kept or copied.
    #[cfg(feature = "local-queryable")]
    fn hand_own_get(&self, asked: query::Asked, get: &query::OwnGet<'_>) {
        // A callback that steps the session or asks a get from inside one of these hands out
        // nothing itself, as one inside a delivery does.
        self.deliveries.within(|_| {
            for call in asked {
                self.run_queryable(&call, get, query::LOCAL_QUERY);
                self.samples.end_query_call(call);
            }
        });
        // A row whose last call one of these was, its queryable undeclared meanwhile, is let go
        // of by the delivery's walk, its drop perhaps the program's own, with no lock held.
        self.deliver();
    }

    /// Whether write filter `id` holds what it filters back: a filter is created suppressing,
    /// until a peer declares what it counts, or the session itself does when it counts its own
    /// (`vendor/zenoh-pico/src/net/filtering.c` @ `ctx->state = WRITE_FILTER_ACTIVE`). A filter
    /// the session does not hold holds nothing back.
    fn filter_active_in(core: &Core<L, C>, id: FilterId) -> bool {
        let Some(handle) = row_of(id) else {
            return false;
        };
        let registry = core.session.registry.borrow();
        // What the peers answered is kept by the filter's row until a face's tables are written.
        let open = registry.app.tables.write_filter_open(handle, &*registry);
        open.is_some_and(|open| !open)
    }

    /// A plain Put on `mapping_id` (the literal `keyexpr` when it is `0`) sent from `params` to
    /// every link, once the write filter let it through, as a publish is sent
    /// ([`Self::send_on_links`]): `NotPlain`, with nothing sent, when a subscriber of the session or
    /// a group wants it the general way, or the key names nothing a link carries.
    fn put_plain_in(
        &self,
        core: &Core<L, C>,
        keyexpr: &str,
        mapping_id: ExprId,
        payload: &[u8],
        params: &PlainPutParams,
    ) -> FilteredPut {
        // A put one of the session's own subscribers wants is not plain: the general publish
        // sends it and delivers it there.
        #[cfg(feature = "local-subscriber")]
        if params.destination.allows_local()
            && wz_session_core::pubsub::LocalSubscribers::has_local_matching(
                &*tables(&core.session.registry),
                keyexpr,
            )
        {
            return FilteredPut::NotPlain;
        }
        if !params.destination.allows_remote() {
            return FilteredPut::Sent(Ok(0));
        }
        // A group is sent a put by the general publish, which pushes it onto the group's stage.
        #[cfg(feature = "group")]
        if !core.transport.groups.is_empty() {
            return FilteredPut::NotPlain;
        }
        // The key as the session's tables name it, and each link as its key-wire form says.
        let Some(named) = tables(&core.session.registry).named_by(keyexpr, mapping_id) else {
            return FilteredPut::NotPlain;
        };
        // A plain put carries its QoS and nothing else of a publication's.
        let meta = PushMetadata {
            qos: params.qos,
            ..PushMetadata::default()
        };
        let leg = LinkLeg {
            named,
            payload,
            kind: SampleKind::Put,
            meta: &meta,
            send: wz_session_core::session_actions::SendAs {
                reliable: params.reliable,
                express: params.express,
                priority: params.priority,
            },
        };
        // Marked as a publish for as long as it holds the session, as the general publish is.
        let _publishing = SendingOn::enter(&self.sending_on, PUBLISHING);
        let (outcome, _) = self.send_on_links(core, &leg, None, Pass::EVERY_FACE);
        FilteredPut::Sent(outcome)
    }

    /// [`Self::filter_active_in`], except on a session that holds a group the filter does not
    /// ask: such a group is sent a write whatever the filter says, as the tokio engine sends one
    /// (`GroupDeclarations::asks_for_filters`), since on it zenoh-pico sends what its filter would
    /// hold back. Without a group no write must reach anyone regardless.
    fn holds_back_in(core: &Core<L, C>, id: FilterId) -> bool {
        #[cfg(feature = "group")]
        if core
            .transport
            .groups
            .iter()
            .any(|group| !group.declarations().asks_for_filters())
        {
            return false;
        }
        Self::filter_active_in(core, id)
    }

    /// How often what the peers declared was searched since the open: what a test of the cost of
    /// a filtered put counts. Read under the lock, uncounted as a take.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn peer_looks(&self) -> usize {
        self.core.lock().0.session.registry.borrow().peer_looks()
    }

    /// Hand out entity ids from `next` on, none with `None`: how a test reaches the end of the
    /// id space without spending it.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn entity_ids_from(&self, next: Option<EntityId>) {
        tables_mut(&self.core.lock().0.session.registry).entity_ids_from(next);
    }

    /// Start the read task on the thread `spawn` makes; idempotent. A system that gives no thread
    /// is answered (`NoThread`), and the task is left not running, so a later start tries again:
    /// zenoh-pico's start answers its task creation's error the same way, and a panic here would
    /// leave the C caller nothing to read on a build that aborts on one.
    pub(crate) fn start_reader(
        &self,
        spawn: impl FnOnce(ReaderBody<L, C>) -> Option<(JoinHandle, ThreadId)>,
    ) -> Result<(), ReadTaskStartRefused> {
        let mut reader = lock(&self.reader);
        if let Some(task) = reader.as_ref() {
            if task.id == os::current() {
                return Err(ReadTaskStartRefused::CalledFromReadTask);
            }
            return Ok(());
        }
        let Some(engine) = self.this.upgrade() else {
            return Ok(());
        };
        // Read under the reader's lock, which every stop moves the run under too.
        let run = self.reader_run.load(Ordering::Acquire);
        let (thread, id) =
            spawn(ReaderBody { engine, run }).ok_or(ReadTaskStartRefused::NoThread)?;
        *reader = Some(ReadTask { thread, id });
        Ok(())
    }

    /// Stop the read task, from a thread that is not it.
    fn stop_reader(&self) -> Result<(), CalledFromReadTask> {
        let task = {
            let mut reader = lock(&self.reader);
            match reader.as_ref() {
                None => return Ok(()),
                Some(task) if task.id == os::current() => return Err(CalledFromReadTask),
                Some(_) => {
                    // The task's run is over: it ends after the step it is in.
                    self.reader_run.fetch_add(1, Ordering::AcqRel);
                    reader.take()
                }
            }
        };
        if let Some(task) = task {
            task.thread.join();
        }
        Ok(())
    }
}

// A key's hold and a periodic job's handle name the session by these alone, so the doors that
// reach the engine as its own type make no table of all of its operations for them.
impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> wz_capi_port::KeyHolds
    for CoopEngine<L, C>
{
    #[inline(never)]
    fn release_keyexpr(&self, mapping_id: ExprId) {
        #[cfg(test)]
        self.takes.holds.fetch_sub(1, Ordering::Relaxed);
        let Some(mut core) = self.live() else {
            return;
        };
        let core = &mut core.0;
        let Some(handle) = tables(&core.session.registry).keyexpr_by_id(mapping_id) else {
            return;
        };
        let place = core.prefix_retraction(Some(handle));
        let retracted = tables_mut(&core.session.registry).undeclare_keyexpr(handle);
        // The row went before the links are told: a send never finds the table borrowed.
        core.retract_keyexpr(place, retracted);
    }

    #[inline(never)]
    fn retain_keyexpr(&self, mapping_id: ExprId) {
        #[cfg(test)]
        self.takes.holds.fetch_add(1, Ordering::Relaxed);
        let Some(core) = self.live() else {
            return;
        };
        // One more hold of the row in the session's one table set; nothing goes on the wire.
        let mut tables = tables_mut(&core.0.session.registry);
        if let Some(handle) = tables.keyexpr_by_id(mapping_id) {
            tables.retain_keyexpr(handle);
        }
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> wz_capi_port::Tickers
    for CoopEngine<L, C>
{
    #[cfg(feature = "ticker")]
    fn start_ticker(&self, period_ms: u64, tick: Tick) -> Result<TickerId, Declined> {
        let mut core = self.live().ok_or(Declined::Closed)?;
        let id = self.next_local_id();
        let now_ms = core.0.clock.now_us() / 1000;
        // A table of the build's `MAX_TICKERS` rows, reserved at the open: a start past them is
        // refused as a full table.
        if core.0.tickers.start(id, period_ms, tick, now_ms) {
            Ok(id)
        } else {
            Err(Declined::TableFull)
        }
    }

    #[cfg(feature = "ticker")]
    fn stop_ticker(&self, id: TickerId) {
        if let Some(mut core) = self.live() {
            core.0.tickers.stop(id);
        }
    }
}

// The operations a door of a C ABI calls on the session's tables are out of line: the engine is
// one type per build, so each is one body the doors call, counted as the engine's, and not a
// copy inside each door.
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
        self.core.lock().0.clock.now_us() / 1000
    }

    fn next_entity_id(&self) -> Option<EntityId> {
        // The session's tables number every entity, open or closed: an id is taken under the lock.
        self.core.lock().0.session.take_entity_id()
    }

    #[inline(never)]
    fn next_peer(&self, from: u64) -> Option<(u64, PeerIdentity)> {
        let core = self.live()?;
        // A face's id is its key: faces are numbered as they come and keep their id while they
        // stand. A group's members are not listed here, as the tokio engine lists none:
        // `next_group_member` answers them, whatever role they announced.
        core.0
            .transport
            .ups_at()
            .filter(|(_, id, actions)| *id >= from && actions.is_established())
            .filter_map(|(_, id, actions)| {
                Some((
                    id,
                    PeerIdentity {
                        zid: actions.peer_session_zid()?,
                        whatami: actions.peer_whatami_wire()?,
                    },
                ))
            })
            .min_by_key(|(id, _)| *id)
    }

    /// A member's key is its group's place in the session's groups above its own place in the
    /// group's member table.
    #[cfg(feature = "group")]
    #[inline(never)]
    fn next_group_member(&self, from: u64) -> Option<(u64, SessionZid)> {
        let core = self.live()?;
        let (first_group, first_member) = member_places(from);
        core.0
            .transport
            .groups
            .iter()
            .enumerate()
            .skip(usize::try_from(first_group).ok()?)
            .find_map(|(at, group)| {
                // A group, or a member, whose place does not fit its half of a key has no key,
                // and so is not listed.
                let place = u32::try_from(at).ok()?;
                let from_member = if place == first_group {
                    first_member
                } else {
                    0
                };
                let (member, zid) = group.member_zid_from(usize::try_from(from_member).ok()?)?;
                Some((member_key(place, u32::try_from(member).ok()?), zid))
            })
    }

    /// Each group's session sends its JOIN at its next step, which this call takes, as the tokio
    /// engine's group sends one at once.
    #[cfg(feature = "group")]
    fn send_join_on_groups(&self) -> Result<usize, Declined> {
        let mut guard = self.live().ok_or(Declined::Closed)?;
        let core = &mut guard.0;
        let asked = core
            .transport
            .groups
            .iter()
            .filter(|group| group.ask_join())
            .count();
        if asked == 0 {
            return Ok(0);
        }
        core.run_tasks();
        drop(guard);
        // What the step took from a group is handed out outside the lock, as a read's is.
        self.deliver();
        Ok(asked)
    }

    #[cfg(feature = "connectivity")]
    fn face_snapshots(&self) -> Vec<FaceSnapshot> {
        self.live()
            .map_or_else(Vec::new, |core| core.0.transport.standing_faces())
    }

    #[cfg(feature = "connectivity")]
    fn face_link_at(&self, at: usize) -> Option<FaceLinkRow> {
        self.live()
            .and_then(|core| core.0.transport.face_link_at(at))
    }

    // The told bits live on the session's own face rows (`told`), not in a ledger.
    #[cfg(feature = "connectivity")]
    fn tell_came(&self, plane: ToldPlane, listener: usize, key: &ToldKey) -> bool {
        self.live()
            .is_some_and(|mut core| core.0.tell_came(plane, listener, key))
    }

    #[cfg(feature = "connectivity")]
    fn tell_went(&self, plane: ToldPlane, listener: usize, key: &ToldKey) -> bool {
        self.live()
            .is_some_and(|mut core| core.0.tell_went(plane, listener, key))
    }

    #[cfg(feature = "connectivity")]
    fn first_told_gone(&self, plane: ToldPlane, listener: usize) -> Option<FaceLinkRow> {
        self.live()
            .and_then(|core| core.0.first_told_gone(plane, listener))
    }

    #[cfg(feature = "connectivity")]
    fn forget_told(&self, plane: ToldPlane, listener: usize) {
        if let Some(mut core) = self.live() {
            core.0.forget_told(plane, listener);
        }
    }

    // The faces are told a row at a time, as they are written in place: a watcher of snapshots is
    // told each face its rows gather into.
    #[cfg(feature = "connectivity")]
    fn watch_faces(&self, sink: FaceEventSink) -> Result<u64, Declined> {
        SessionEngine::watch_face_rows(self, wz_capi_port::face_rows::snapshots_of_rows(sink))
    }

    #[cfg(feature = "connectivity")]
    fn watch_face_rows(&self, sink: FaceRowSink) -> Result<u64, Declined> {
        if SessionEngine::is_closed(self) {
            return Err(Declined::Closed);
        }
        Ok(self.faces.watch(sink))
    }

    #[cfg(feature = "connectivity")]
    fn unwatch_faces(&self, id: u64) -> bool {
        self.faces.unwatch(id)
    }

    /// The watch is told first what each link's peer holds now, then what the links' dispatch
    /// holds for it from here on (`decl_watch`): at once when the round takes the catch-up, or by
    /// the next round when it is handed out now, as it is to a watch declared from inside a
    /// callback. A refused sink is let go of with no lock held.
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    fn declare_decl_watch(
        &self,
        plane: DeclPlane,
        sink: DeclWatchSink,
    ) -> Result<DeclWatchId, Declined> {
        if !decl_watch::hears(plane) {
            return Err(Declined::NotBuilt);
        }
        let Some(guard) = self.live() else {
            return Err(Declined::Closed);
        };
        let core = &guard.0;
        let added = self
            .decl_watches
            .add(&mut core.session.registry.borrow_mut().app, plane, sink);
        let id = match added {
            Ok(id) => id,
            Err((refused, sink)) => {
                drop(guard);
                drop(sink);
                return Err(refused);
            }
        };
        core.tell_decl_watches_owed();
        Ok(id)
    }

    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    fn undeclare_decl_watch(&self, id: DeclWatchId) -> bool {
        // A closed session let go of every watch at its close.
        let sink = match self.live() {
            Some(core) => {
                let mut registry = core.0.session.registry.borrow_mut();
                self.decl_watches.undeclare(&mut registry.app, id)
            }
            None => None,
        };
        let found = sink.is_some();
        drop(sink);
        found
    }

    fn has_transport(&self) -> bool {
        self.live()
            .is_some_and(|core| core.0.transport.holds_transport())
    }

    #[inline(never)]
    fn has_router_peer(&self) -> bool {
        self.live().is_some_and(|core| {
            core.0
                .transport
                .ups()
                .any(|actions| actions.peer_whatami_wire() == Some(0))
        })
    }

    #[cfg(feature = "shared-key-ids")]
    fn names_keys_by_link(&self) -> bool {
        self.live().is_some_and(|core| {
            core.0.session.key_ids.is_some() || core.0.transport.key_forms.departs_from_declared()
        })
    }

    fn redeclare(&self) -> Result<usize, wz_capi_port::RedeclareRefusal> {
        let mut core = self.live().ok_or(wz_capi_port::RedeclareRefusal::Closed)?;
        Ok(core.0.redeclare())
    }

    #[inline(never)]
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
        let sent = sent.saturating_add(self.publish_to_subscribers(keyexpr, payload, opts)?);
        Ok(sent)
    }

    #[inline(never)]
    fn declare_subscriber_on_wire(
        &self,
        keyexpr: &str,
        wire: WireKey,
        allowed_origin: Locality,
        retraction: Option<RetractionKey>,
        sink: SubscriberSink,
    ) -> Result<SubId, Declined> {
        // A closed session declares nothing, and takes no id for what it does not declare; what
        // the key holds goes back with the refusal.
        let Some(mut guard) = self.live() else {
            self.let_go_of_key(wire);
            return Err(Declined::Closed);
        };
        let core = &mut guard.0;
        // The subscriber is one row of the session's tables, numbered by the id they hand out
        // next: a full table, a key the session cannot hold or no id left refuses it before
        // anything is sent, and the sink goes with the refusal. The row holds the key expression
        // declaration its key is named by for as long as it stands.
        let next = tables(&core.session.registry).next_entity_id();
        let Some(id) = next else {
            drop(guard);
            self.let_go_of_key(wire);
            return Err(Declined::NoEntityId);
        };
        let form = core.session.key_form(
            wire.mapping_id,
            retraction.map_or(Retraction::ById, Retraction::Named),
        );
        // The tables' row holds the declaration the key is named by, so the key's own hold of it
        // is given back once the row stands, and the entity holds it once; the row keeps what
        // else the key held.
        let mut holds = wire.into_holds();
        let named = holds.take_named();
        // The declaration states no choice about the timestamp, so it takes the session's
        // `entity-timestamp-opt-in`, as the policy the session was opened under resolves it.
        let row = SubscriberRow::new(holds, sink, exposed_by(&core.policy));
        let declared = tables_mut(&core.session.registry).declare_subscriber(
            keyexpr,
            allowed_origin,
            form,
            row,
        );
        let declared = match declared {
            Ok(declared) => declared,
            Err(refused) => {
                // The program's callback goes with the refusal, let go of with no lock held, and
                // what the key held goes back.
                drop(guard);
                let why = Declined::from(refused.why);
                if let Some(named) = named {
                    named.release(self);
                }
                self.give_back(refused.callback.into_holds());
                return Err(why);
            }
        };
        debug_assert_eq!(
            declared.id, id,
            "the tables number a row as they said they would"
        );
        // Each link is told it from the row, which names the key as the tables keep it.
        core.announce(DeclaredRow::of(declared.handle));
        // So is each group.
        #[cfg(feature = "group")]
        {
            let tables = tables(&core.session.registry);
            if let Some(row) = tables.subscribers().get(declared.handle) {
                let wire = group::wire_key_of(tables.wire_of(row.key()));
                let retraction = tables.retraction_of(row.key());
                core.transport.announce_to_groups(GroupEntity {
                    what: GroupDeclaration::Subscriber,
                    entity: id,
                    keyexpr: row.key().as_str(),
                    wire: &wire,
                    retraction: retraction.as_ref(),
                    allowed_origin,
                });
            }
        }
        // A matching listener that counts the session's own subscribers may now match: it is
        // told, outside the lock.
        #[cfg(feature = "local-subscriber")]
        self.read_matching(core);
        drop(guard);
        if let Some(named) = named {
            named.release(self);
        }
        #[cfg(feature = "local-subscriber")]
        self.deliver();
        Ok(id)
    }

    #[inline(never)]
    fn undeclare_subscriber(&self, id: SubId) {
        // A liveliness subscriber's id is one of these too (the port's one id space): its row goes
        // and its Interest ends.
        #[cfg(feature = "liveliness")]
        let live = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let (rank, handle, prefix) = tables(&core.session.registry)
                .liveliness_subscribers()
                .iter()
                .enumerate()
                .find(|(_, (_, row))| row.id() == id)
                .map(|(rank, (handle, row))| (rank, handle, row.key().prefix()))?;
            // The links are asked while the rows stand, which are their places in the replay's
            // order: the subscriber's, ranked by the walk that found it, then the declaration's
            // its key is named by.
            let place = core.place(DeclaredTable::LivelinessSubscribers, rank);
            let keyexpr_place = core.prefix_retraction(prefix);
            // The groups asked for it are told the asking ended.
            #[cfg(feature = "group")]
            for group in &core.transport.groups {
                group.end_liveliness_ask(id);
            }
            let undeclared =
                tables_mut(&core.session.registry).undeclare_liveliness_subscriber(handle)?;
            // The rows went before the links are told: a send never finds the tables borrowed.
            core.retract_at(place, &interest_final::<C>(u64::from(id)));
            core.retract_keyexpr(keyexpr_place, undeclared.keyexpr);
            Some((handle, undeclared.taken))
        });
        // The row, and its callback with it, is let go of here with no lock held; one a call of
        // which runs is let go of by the call that ends last.
        #[cfg(feature = "liveliness")]
        if let Some(undeclared) = live {
            match undeclared {
                (_, Some(row)) => self.give_back(row.into_holds()),
                (handle, None) => self.wait_for_liveliness_release(handle),
            }
            return;
        }
        // The row is taken out of the tables under the lock and let go of after it: its key may hold
        // a declaration whose release reaches the session (`WireKey`). One a call of which runs is
        // let go of once that call ends (`Self::wait_for_release`).
        let undeclared = self.live().and_then(|mut core| {
            let core = &mut core.0;
            // The declaration its key is named by goes with it when it is the last that holds it;
            // what the links are told is read while the row stands.
            let found = {
                let tables = tables(&core.session.registry);
                let found = tables
                    .subscribers()
                    .iter()
                    .enumerate()
                    .find(|(_, (_, row))| row.id() == id)
                    .map(|(rank, (handle, row))| {
                        (
                            rank,
                            handle,
                            row.key().prefix(),
                            // Read against the key, held past the row.
                            tables
                                .retraction_of(row.key())
                                .map(|names| (names, row.key().backing().clone())),
                        )
                    });
                found
            };
            let (rank, handle, prefix, retraction) = found?;
            // The links are asked while the rows stand, which are their places in the replay's
            // order: the subscriber's, ranked by the walk that found it, then the declaration's,
            // which comes before every subscriber.
            let place = core.place(DeclaredTable::Subscribers, rank);
            let keyexpr_place = core.prefix_retraction(prefix);
            #[cfg(feature = "group")]
            core.transport.retract_from_groups(id);
            let undeclared = tables_mut(&core.session.registry).undeclare_subscriber(handle)?;
            let row = undeclared.taken;
            // The rows went before the links are told: a send never finds the tables borrowed.
            core.retract_at(place, &|actions: &McuActions<C>| {
                let names = retraction.as_ref().map(|(names, key)| names.names(key));
                SubscriberRow::retract(id, names, actions);
            });
            core.retract_keyexpr(keyexpr_place, undeclared.keyexpr);
            // One that counted it may now match no more.
            #[cfg(feature = "local-subscriber")]
            self.read_matching(core);
            Some((handle, row))
        });
        // The row, and its callback with it, is let go of here, with no lock held; one a call of
        // which runs is let go of by the call that ends last.
        match undeclared {
            Some((_, Some(row))) => self.give_back(row.into_holds()),
            Some((handle, None)) => self.wait_for_release(handle),
            None => {}
        }
        #[cfg(feature = "local-subscriber")]
        self.deliver();
    }

    #[inline(never)]
    fn acquire_keyexpr(&self, keyexpr: &str) -> Result<ExprId, Declined> {
        let mut core = self.live().ok_or(Declined::Closed)?;
        let core = &mut core.0;
        // A key the session declared already is held once more; any other takes a row and an id.
        // The table refuses it, before an id is taken or anything is sent, when it is full, when
        // the key cannot be held, or when every id is taken. An id of the shared dictionary names
        // its key in this session's space too, so no key expression is declared under one.
        // One declaration, whatever ids the session shares: the table's declaration is one body
        // for both.
        #[cfg(feature = "shared-key-ids")]
        let shared = core.session.key_ids.as_ref();
        let usable = |id: ExprId| -> bool {
            #[cfg(feature = "shared-key-ids")]
            {
                shared.is_none_or(|ids| ids.next_free_id(id) == Some(id))
            }
            #[cfg(not(feature = "shared-key-ids"))]
            {
                let _ = id;
                true
            }
        };
        let declared =
            tables_mut(&core.session.registry).declare_keyexpr_where(keyexpr, false, usable)?;
        let id = declared.id;
        if !declared.new {
            #[cfg(test)]
            self.takes.holds.fetch_add(1, Ordering::Relaxed);
            return Ok(id);
        }
        // A declaration a link refuses is not made, and the links that took it take it back; one
        // made while a link is down, or that a replay has not reached, is sent in its turn. A link
        // refuses one it cannot carry.
        let place = core.place_of(DeclaredRow::of(declared.handle));
        let taken = core.announce_or_undo_at(
            place,
            &|actions: &McuActions<C>| actions.send_declare_keyexpr(id, keyexpr).is_ok(),
            &undeclare_kexpr::<C>(id),
        );
        if !taken {
            tables_mut(&core.session.registry).undeclare_keyexpr(declared.handle);
            return Err(Declined::ExceedsCapacity);
        }
        // And each group told the session's keyexprs, as a link is.
        #[cfg(feature = "group")]
        for group in &core.transport.groups {
            group.announce_keyexpr(id, keyexpr);
        }
        #[cfg(test)]
        self.takes.holds.fetch_add(1, Ordering::Relaxed);
        Ok(id)
    }

    fn key_arena(&self) -> Option<&dyn SessionKeys> {
        Some(self)
    }

    fn place_lender(&self) -> Option<&dyn PlaceLender> {
        Some(self)
    }

    #[cfg(feature = "advanced-cache")]
    fn cache_bytes(&self) -> Option<&dyn wz_capi_port::CacheBytes> {
        Some(self)
    }

    fn declare_matching_listener(
        &self,
        plane: FilterPlane,
        keyexpr: &str,
        sink: MatchingSink,
        // The session's own subscribers count with `local-subscriber` and its own queryables with
        // `local-queryable`, and nothing of its own does otherwise: zenoh-pico's default build
        // (`Z_FEATURE_LOCAL_SUBSCRIBER` and `Z_FEATURE_LOCAL_QUERYABLE` 0) delivers nothing
        // locally.
        count_local: bool,
    ) -> Result<MatchId, Declined> {
        // A plane the build does not hold is refused first, with nothing taken. Every refusal
        // lets `sink` go as it returns, before the caller hears of it.
        if !counts(plane) {
            return Err(Declined::NotBuilt);
        }
        let guard = self.live().ok_or(Declined::Closed)?;
        // The listener is a row of the session's tables holding an Interest of its own: a full
        // table, a key the session cannot hold or an Interest it cannot hold or number refuses it
        // before anything is asked, as a listener that could ask no peer would never hear one.
        let declared = tables_mut(&guard.0.session.registry).declare_matching_listener_on(
            plane_of(plane),
            keyexpr,
            counts_own(plane, count_local),
            MatchingCall { sink: Some(sink) },
        );
        self.matching_declared(guard, declared)
    }

    #[inline(never)]
    fn declare_filter_matching_listener(
        &self,
        filter: FilterId,
        sink: MatchingSink,
    ) -> Result<MatchId, Declined> {
        let handle = row_of(filter).ok_or(Declined::Closed)?;
        let guard = self.live().ok_or(Declined::Closed)?;
        // The filter's row holds the plane and the count of the session's own it was declared
        // with, as `declare_matching_listener` would make them, so the listener is that one's.
        let declared = tables_mut(&guard.0.session.registry)
            .declare_matching_listener_of(handle, MatchingCall { sink: Some(sink) });
        self.matching_declared(guard, declared)
    }

    fn undeclare_matching_listener(&self, id: MatchId) {
        let gone = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let handle = row_of(id)?;
            let place = {
                let tables = tables(&core.session.registry);
                let interest = tables.matching_listeners().get(handle)?.interest();
                interest_rank(&tables, interest)
            };
            let unwatched =
                tables_mut(&core.session.registry).undeclare_matching_listener(handle)?;
            // The row went before the links are told: a send never finds the tables borrowed.
            core.end_interest(unwatched.interest_final, place);
            unwatched.row
        });
        // Nothing it was owed is handed, its row being gone; its callback is let go of here, with
        // no lock held.
        drop(gone);
    }

    #[inline(never)]
    fn declare_write_filter(
        &self,
        plane: FilterPlane,
        keyexpr: &str,
        wire: &WireKey,
        ask: Option<InterestAsk<'_>>,
        // See `declare_matching_listener`: the session's own subscribers count with
        // `local-subscriber`.
        count_local: bool,
    ) -> Result<FilterId, Declined> {
        if !counts(plane) {
            return Err(Declined::NotBuilt);
        }
        let mut core = self.live().ok_or(Declined::Closed)?;
        let core = &mut core.0;
        // A full table, a plane at its own bound (a publisher's MAX_PUBLISHERS, a querier's
        // MAX_QUERIERS, in the one table lent for both), a key the session cannot hold, or an
        // Interest it cannot hold or number refuses the filter, with nothing held, asked or
        // numbered.
        let name = ask.map(|form| InterestName {
            mapping_id: form.mapping_id,
            suffix: form.suffix,
            aggregate: form.aggregate,
        });
        let watching = tables_mut(&core.session.registry)
            .declare_write_filter_as(
                plane_of(plane),
                keyexpr,
                counts_own(plane, count_local),
                name,
            )
            .map_err(Declined::from)?;
        let id = row_id(watching.handle);
        // The id this filter spent of its own, when it spent one: its Interest's, when it is the
        // first to hold it, or the one taken for a filter that sends none.
        let spent = if ask.is_some() {
            if let Some(opened) = watching.interest {
                core.announce(DeclaredRow::of(opened.handle));
            }
            watching.interest.map(|opened| u64::from(opened.id))
        } else {
            // The entity id is taken whether the Interest is sent or not, as zenoh-pico's
            // `_z_add_interest` takes it before it decides: a filter that finds none left is
            // refused, its row given back.
            let Some(taken) = core.session.take_entity_id() else {
                let _ = unwatch_filter(&mut tables_mut(&core.session.registry), watching.handle);
                return Err(Declined::NoEntityId);
            };
            Some(u64::from(taken))
        };
        // Each group a write filter asks (`asks_for_filters`) is asked for its members'
        // declarations by an id of the filter's own, as the tokio engine's group is: the one the
        // filter spent, or a fresh one when its Interest was held already.
        #[cfg(feature = "group")]
        if core
            .transport
            .groups
            .iter()
            .any(|group| group.declarations().asks_for_filters())
        {
            if let Some(interest_id) =
                spent.or_else(|| core.session.take_entity_id().map(u64::from))
            {
                for group in &core.transport.groups {
                    group.ask_filter(id, interest_id, plane, keyexpr, wire);
                }
            }
        }
        #[cfg(not(feature = "group"))]
        let _ = (spent, wire);
        Ok(id)
    }

    fn write_filter_active(&self, id: FilterId) -> bool {
        let Some(core) = self.live() else {
            return false;
        };
        Self::filter_active_in(&core.0, id)
    }

    fn write_filter_holds_back(&self, id: FilterId) -> bool {
        let Some(core) = self.live() else {
            return false;
        };
        Self::holds_back_in(&core.0, id)
    }

    #[inline(never)]
    fn undeclare_write_filter(&self, id: FilterId) {
        let Some(handle) = row_of(id) else {
            return;
        };
        let Some(mut core) = self.live() else {
            return;
        };
        let core = &mut core.0;
        let place = {
            let tables = tables(&core.session.registry);
            let Some(row) = tables.write_filters().get(handle) else {
                return;
            };
            interest_rank(&tables, row.interest())
        };
        let Some(last_held) = unwatch_filter(&mut tables_mut(&core.session.registry), handle)
        else {
            return;
        };
        // The row went before the links are told: a send never finds the tables borrowed.
        core.end_interest(last_held, place);
        // The groups it asked are told the asking ended.
        #[cfg(feature = "group")]
        for group in &core.transport.groups {
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
        self.put_through_filter(filter, keyexpr, payload, Some((mapping_id, *params)))
    }

    #[inline(never)]
    fn keep_write_filter_plain(&self, filter: FilterId, plain: Option<(PlainPutParams, ExprId)>) {
        let Some(core) = self.live() else {
            return;
        };
        let tables = tables(&core.0.session.registry);
        if let Some(row) = row_of(filter).and_then(|handle| tables.write_filters().get(handle)) {
            row.keep_plain(plain);
        }
    }

    #[inline(never)]
    fn publish_filtered(
        &self,
        filter: FilterId,
        keyexpr: &str,
        wire: &WireKey,
        payload: &[u8],
        opts: Option<&PublishOptions>,
    ) -> FilteredPut {
        if let Some(opts) = opts {
            if self.write_filter_holds_back(filter) {
                return FilteredPut::Suppressed;
            }
            return FilteredPut::Sent(self.publish_on_wire_all(keyexpr, wire, payload, opts));
        }
        // A write that brings nothing of its own goes in the plain form its filter's row keeps.
        self.put_through_filter(filter, keyexpr, payload, None)
    }

    /// Each group the session joined takes the step too, and is counted as a link is: a group's
    /// window holds what the session sends on the group, as pico's batch holds what it sends on
    /// its multicast transport, and is written by a flush or a stop on the caller's thread, as a
    /// link's is.
    fn batch_all(&self, step: BatchStep) -> usize {
        self.live().map_or(0, |core| {
            let links = core
                .0
                .transport
                .ups()
                .filter(|&actions| batch_link(actions, step))
                .count();
            #[cfg(feature = "group")]
            let groups = core
                .0
                .transport
                .groups
                .iter()
                .filter(|group| match step {
                    BatchStep::Start => group.batch_start(),
                    BatchStep::Flush => group.batch_flush(),
                    BatchStep::Stop => group.batch_stop(),
                })
                .count();
            #[cfg(not(feature = "group"))]
            let groups = 0;
            links.saturating_add(groups)
        })
    }

    #[cfg(feature = "queryable")]
    fn declare_queryable_on_wire(
        &self,
        keyexpr: &str,
        wire: WireKey,
        complete: bool,
        allowed_origin: Locality,
        retraction: Option<RetractionKey>,
        sink: QueryableSink,
    ) -> Result<QblId, Declined> {
        let Some(mut guard) = self.live() else {
            self.let_go_of_key(wire);
            return Err(Declined::Closed);
        };
        let core = &mut guard.0;
        // The queryable is one row of the session's tables, numbered by the id they hand out
        // next: a full table, a key the session cannot hold or no id left refuses it before
        // anything is sent, and before its callback is minted. The row holds the key expression
        // declaration its key is named by for as long as it stands.
        let next = tables(&core.session.registry).next_entity_id();
        let Some(id) = next else {
            drop(guard);
            self.let_go_of_key(wire);
            return Err(Declined::NoEntityId);
        };
        let form = core.session.key_form(
            wire.mapping_id,
            retraction.map_or(Retraction::ById, Retraction::Named),
        );
        // The tables' row holds the declaration the key is named by, so the key's own hold of it
        // is given back once the row stands, and the entity holds it once; the row keeps what
        // else the key held.
        let mut holds = wire.into_holds();
        let named = holds.take_named();
        let row = QueryableRow::new(holds, sink);
        let declared = tables_mut(&core.session.registry).declare_queryable(
            keyexpr,
            allowed_origin,
            complete,
            form,
            row,
        );
        let declared = match declared {
            Ok(declared) => declared,
            Err(refused) => {
                // The row goes with the refusal, let go of with no lock held, and what its key
                // held goes back.
                drop(guard);
                let why = Declined::from(refused.why);
                if let Some(named) = named {
                    named.release(self);
                }
                self.give_back(refused.callback.into_holds());
                return Err(why);
            }
        };
        debug_assert_eq!(
            declared.id, id,
            "the tables number a row as they said they would"
        );
        // Each link is told it from the row, which names the key as the tables keep it.
        core.announce(DeclaredRow::of(declared.handle));
        // So is each group.
        #[cfg(feature = "group")]
        {
            let tables = tables(&core.session.registry);
            if let Some(row) = tables.queryables().get(declared.handle) {
                let wire = group::wire_key_of(tables.wire_of(row.key()));
                let retraction = tables.retraction_of(row.key());
                core.transport.announce_to_groups(GroupEntity {
                    what: GroupDeclaration::Queryable {
                        complete: row.complete(),
                    },
                    entity: id,
                    keyexpr: row.key().as_str(),
                    wire: &wire,
                    retraction: retraction.as_ref(),
                    allowed_origin,
                });
            }
        }
        // A matching listener that counts the session's own queryables may now match: it is told,
        // outside the lock.
        #[cfg(feature = "local-queryable")]
        self.read_matching(core);
        drop(guard);
        if let Some(named) = named {
            named.release(self);
        }
        #[cfg(feature = "local-queryable")]
        self.deliver();
        Ok(id)
    }

    #[cfg(feature = "query")]
    fn get_on_wire(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        opts: &QueryOptionsOf<'_>,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Result<usize, Declined> {
        // One leg for each face whose link is up, when the destination admits a peer, and one to
        // the session's own queryables, when it admits the session and the build has them
        // (`local-queryable`: zenoh-pico's default build asks none, `Z_FEATURE_LOCAL_QUERYABLE`
        // 0). A get that reaches nobody, because its destination admits neither or because no
        // link is up, is over at once. Each leg is issued under the session's lock and no lock is
        // held between two of them.
        //
        // A get limited to some links or addressed to one node is refused by that statement:
        // this engine reads neither, and asking every link would widen it.
        StatementNotHonoured::of_query(opts)?;
        // A fan cancelled before a leg is issued issues none: the get reached nobody.
        let Ok(tag) = self.tag_of(fan) else {
            return Ok(0);
        };
        // The session's own queryables are asked all or none, under a row of the plane's held
        // Finals taken before any leg is issued: a session with none free refuses the get whole,
        // with nothing sent and no queryable asked, where zenoh-pico refuses a get whose delivery
        // to its own queryables failed (`vendor/zenoh-pico/src/net/primitives.c` @
        // `_Z_CLEAN_RETURN_IF_ERR(ret, _z_unregister_pending_query(zn, qid));`).
        #[cfg(feature = "local-queryable")]
        let own = if opts.allowed_destination.allows_local() {
            let mut guard = self.live().ok_or(Declined::Closed)?;
            // The session's own request ids are a space of their own: the leg is registered in
            // the session's own pending gets (`Registry::local`) and answered under the local
            // generation (`query::LOCAL_QUERY`), so no table a link's ids reach holds it, and
            // the two counters never meet.
            let rid = guard.0.session.local_requests.take();
            Some(query::OwnFinalHold::take(&self.plane, rid).ok_or(Declined::TableFull)?)
        } else {
            None
        };
        let expose = {
            let guard = self.live().ok_or(Declined::Closed)?;
            // `entity-timestamp-opt-in`: the query's choice, or the session's policy when it
            // states none, applied to every leg's callback, after its replies are consolidated.
            opts.expose_timestamp_by(&guard.0.policy)
        };
        // What every leg of this get is held with, the mint of each leg's callback among it.
        let mut ask = LegAsk {
            keyexpr,
            opts,
            expose,
            mint: leg,
        };
        let remote = opts.allowed_destination.allows_remote();
        let mut issued: usize = 0;
        // The legs refused for want of a row in their face's table of pending gets: a get that
        // issued none, and found no room for one, is refused whole.
        let mut unheld = 0usize;
        // The faces whose links are up, each asked once in the order of their ids: the walk keeps
        // the last face it asked and takes the session's lock for each, holding no list of them.
        let mut asked = None;
        loop {
            let Some(mut guard) = self.live() else {
                return issued_so_far(issued);
            };
            let core = &mut guard.0;
            let Some(face) = core.transport.next_up_face(remote, asked) else {
                break;
            };
            asked = Some(face);
            let leg_id = self.next_local_id();
            let Some(actions) = core.transport.up_actions(face).cloned() else {
                continue;
            };
            // A request id the face's actions allocate, so its peer's answer names it.
            let rid = actions.alloc_next_request_id();
            // One Final: the face's peer's. Held before the request goes out, so no answer can
            // arrive before its entry.
            match self.hold_leg(core, &mut ask, face, leg_id, rid, 1) {
                LegHeld::Held => {}
                LegHeld::Gone => continue,
                LegHeld::NoRoom => {
                    unheld = unheld.saturating_add(1);
                    continue;
                }
                LegHeld::Refused { table_full } => {
                    unheld = unheld.saturating_add(usize::from(table_full));
                    // A leg no table holds is let go of with no lock held.
                    drop(guard);
                    self.end_leg_now(leg_id);
                    continue;
                }
            }
            // The link names the key as its own key-wire form says.
            let wire = on_link(&actions, keyexpr, wire);
            let (mapping_id, suffix) = if wire.is_literal() {
                (0, Some(keyexpr))
            } else {
                wire.names_in(keyexpr)
            };
            // The query is written from the options where they lie, with nothing copied.
            let sent = match wz_session_core::wire_key::WireKey::from_parts(mapping_id, suffix) {
                Some(key) => actions
                    .send_get_parts(wz_session_core::query_parts::GetParts {
                        rid,
                        key,
                        query: opts.query_parts(),
                    })
                    .is_ok(),
                None => false,
            };
            if !sent {
                // Nothing went out: the entry and the leg go, and the leg is over.
                if let Some(tables) = core.session.registry.borrow_mut().face_mut(face) {
                    tables.gets.replies.unregister(rid);
                }
                drop(guard);
                self.end_leg_now(leg_id);
                continue;
            }
            if !core.session.note_pending(PendingGet {
                face,
                leg: leg_id,
                kind: GetKind::Query(rid),
                fan: tag,
            }) {
                unheld = unheld.saturating_add(1);
                continue;
            }
            drop(guard);
            issued = issued.saturating_add(1);
            // A fan cancelled while the legs are issued stops the issuing.
            if self.cut_short(fan, tag) {
                return Ok(issued);
            }
        }
        // And one leg for each group the session asks queries of
        // (`GroupDeclarations::asks_queries`), owed a Final by each member it holds when the get
        // is asked: the shared count (`QueryOptions::remote_finals`) over the members the
        // group's JOINs admitted, as the tokio engine's group counts them. A member that leaves
        // before its Final is not taken off the count, there as here: the leg ends at its
        // deadline.
        #[cfg(feature = "group")]
        let mut asked = None;
        #[cfg(feature = "group")]
        loop {
            let Some(mut guard) = self.live() else {
                return issued_so_far(issued);
            };
            let core = &mut guard.0;
            let Some(face) = core.transport.next_group_to_ask(remote, asked) else {
                break;
            };
            asked = Some(face);
            let leg_id = self.next_local_id();
            let Some(group) = core
                .transport
                .groups
                .iter()
                .find(|group| group.id() == face)
            else {
                continue;
            };
            let finals = opts.remote_finals(group.member_count());
            // A group that holds no member reaches nobody, as zenoh-pico's get with no peer does.
            if finals == 0 {
                continue;
            }
            // A request id the group allocates, so a member's answer names it on this face.
            let rid = group.alloc_request_id();
            // Held before the query is queued, as a link's leg is before it is sent.
            match self.hold_leg(core, &mut ask, face, leg_id, rid, finals) {
                LegHeld::Held => {}
                LegHeld::Gone => continue,
                LegHeld::NoRoom => {
                    unheld = unheld.saturating_add(1);
                    continue;
                }
                LegHeld::Refused { table_full } => {
                    unheld = unheld.saturating_add(usize::from(table_full));
                    drop(guard);
                    self.end_leg_now(leg_id);
                    continue;
                }
            }
            if !group.ask(rid, keyexpr, wire, opts.query_parts()) {
                // Nothing was queued: the entry and the leg go, and the leg is over.
                if let Some(tables) = core.session.registry.borrow_mut().face_mut(face) {
                    tables.gets.replies.unregister(rid);
                }
                drop(guard);
                self.end_leg_now(leg_id);
                continue;
            }
            if !core.session.note_pending(PendingGet {
                face,
                leg: leg_id,
                kind: GetKind::Query(rid),
                fan: tag,
            }) {
                unheld = unheld.saturating_add(1);
                continue;
            }
            drop(guard);
            issued = issued.saturating_add(1);
            if self.cut_short(fan, tag) {
                return Ok(issued);
            }
        }
        #[cfg(feature = "local-queryable")]
        if let Some(own) = own {
            let leg_id = self.next_local_id();
            let Some(mut guard) = self.live() else {
                return issued_so_far(issued);
            };
            let core = &mut guard.0;
            let rid = own.rid();
            match self.hold_leg(core, &mut ask, LOCAL_FACE, leg_id, rid, 1) {
                LegHeld::Held => {
                    if !core.session.note_pending(PendingGet {
                        face: LOCAL_FACE,
                        leg: leg_id,
                        kind: GetKind::Query(rid),
                        fan: tag,
                    }) {
                        unheld = unheld.saturating_add(1);
                    } else {
                        // Asked once the legs to the peers were, as zenoh-pico asks it only once
                        // the send succeeded.
                        let asked = self.ask_own_queryables(core, own, keyexpr, opts);
                        drop(guard);
                        issued = issued.saturating_add(1);
                        let _ = self.cut_short(fan, tag);
                        self.hand_own_get(asked, &query::OwnGet::of(keyexpr, opts, rid));
                    }
                }
                // A leg the session's own table refused is let go of with no lock held.
                LegHeld::Refused { .. } => {
                    drop(guard);
                    self.end_leg_now(leg_id);
                }
                LegHeld::NoRoom | LegHeld::Gone => unheld = unheld.saturating_add(1),
            }
        }
        // Asked of someone and held by none, with nothing sent: refused whole.
        if issued == 0 && unheld > 0 {
            return Err(Declined::TableFull);
        }
        Ok(issued)
    }

    #[cfg(feature = "liveliness-get")]
    fn liveliness_get_on_wire(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        timeout_ms: u32,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Result<usize, Declined> {
        // One leg for each face whose link is up; a session with no link up reaches nobody, and
        // the snapshot is over at once. A closed session asks nothing.
        if self.live().is_none() {
            return Err(Declined::Closed);
        }
        let Ok(tag) = self.tag_of(fan) else {
            return Ok(0);
        };
        // `0` is the platform default and never no deadline, as pico's `z_liveliness_get`
        // rewrites it (`vendor/zenoh-pico/src/api/liveliness.c` @
        // `if (opt.timeout_ms == 0) {`); rounded up as a query's deadline is.
        let timeout_ms = match timeout_ms {
            0 => DEFAULT_QUERY_TIMEOUT_MS,
            set => set,
        };
        let mut issued: usize = 0;
        // The faces whose links are up, each asked once, as a query's are.
        let mut asked = None;
        loop {
            let Some(mut guard) = self.live() else {
                return issued_so_far(issued);
            };
            let core = &mut guard.0;
            let Some(face) = core.transport.next_up_face(true, asked) else {
                break;
            };
            asked = Some(face);
            let leg_id = self.next_local_id();
            let Some(actions) = core.transport.up_actions(face).cloned() else {
                continue;
            };
            // A face whose session has no interest id left is not asked, as one that could not
            // hold the entry.
            let Some(interest_id) = actions.alloc_next_interest_id() else {
                continue;
            };
            let interest_id = u64::from(interest_id);
            let deadline_ms = Some(leg_deadline_ms(core.clock.now_us(), timeout_ms));
            // A snapshot no row holds is refused before its leg's callback is minted.
            if !core
                .session
                .registry
                .borrow_mut()
                .face_mut(face)
                .is_some_and(|tables| tables.gets.liveliness_gets.has_room())
            {
                continue;
            }
            // A snapshot's replies are tokens, shown as they came.
            let Some(row) = self.gets.open_leg(leg, true) else {
                continue;
            };
            // SAFETY: the sink goes into a table of pending gets, which the session
            // reaches under its lock alone, and is handed its replies there.
            let leg_sink = unsafe { get::LegSink::new(leg_id, row, &self.gets, &self.samples) };
            // One DeclFinal: the face's peer's. Registered before the Interest goes out, so no
            // answer can arrive before its entry.
            let registered = core
                .session
                .registry
                .borrow_mut()
                .face_mut(face)
                .map(|tables| {
                    tables
                        .gets
                        .liveliness_gets
                        .register(interest_id, deadline_ms, leg_sink)
                })
                .is_some_and(|registered| matches!(registered, Ok(true)));
            if !registered {
                drop(guard);
                self.end_leg_now(leg_id);
                continue;
            }
            // The Interest names the key as the link's own key-wire form says, as a query does.
            let wire = on_link(&actions, keyexpr, wire);
            let (mapping_id, suffix) = if wire.is_literal() {
                (0, Some(keyexpr))
            } else {
                wire.names_in(keyexpr)
            };
            if actions
                .send_interest_liveliness_get(interest_id, mapping_id, suffix)
                .is_err()
            {
                // Nothing went out: the entry and the leg go, and the leg is over.
                if let Some(tables) = core.session.registry.borrow_mut().face_mut(face) {
                    tables.gets.liveliness_gets.unregister(interest_id);
                }
                drop(guard);
                self.end_leg_now(leg_id);
                continue;
            }
            if !core.session.note_pending(PendingGet {
                face,
                leg: leg_id,
                kind: GetKind::Liveliness(interest_id),
                fan: tag,
            }) {
                continue;
            }
            drop(guard);
            issued = issued.saturating_add(1);
            // A fan cancelled while the legs are issued stops the issuing.
            if self.cut_short(fan, tag) {
                return Ok(issued);
            }
        }
        Ok(issued)
    }

    #[cfg(feature = "queryable")]
    fn reply_held(
        &self,
        id: wz_capi_port::HeldQueryId,
        key: &str,
        answer: &mut dyn FnMut(&mut dyn wz_session_core::query_sink::ReplyOut),
    ) {
        self.reply_kept(id, key, answer);
    }

    #[cfg(feature = "queryable")]
    fn release_held(&self, id: wz_capi_port::HeldQueryId) {
        self.answer(id.generation, id.rid, query::Release::Kept);
    }
    #[cfg(feature = "queryable")]
    fn undeclare_queryable(&self, id: QblId) {
        // The row is taken out of the tables under the lock and let go of after it: its key may hold
        // a declaration whose release reaches the session (`WireKey`). One a call of which is owed,
        // a query queued for it or handed to its callback now, is let go of once that call ends
        // (`Self::wait_for_queryable_release`), and a query queued before is answered by nothing.
        let undeclared = self.live().and_then(|mut core| {
            let core = &mut core.0;
            // The declaration its key is named by goes with it when it is the last that holds it;
            // what the links are told is read while the row stands.
            let found = {
                let tables = tables(&core.session.registry);
                let found = tables
                    .queryables()
                    .iter()
                    .enumerate()
                    .find(|(_, (_, row))| row.id() == id)
                    .map(|(rank, (handle, row))| {
                        (
                            rank,
                            handle,
                            row.key().prefix(),
                            // Read against the key, held past the row.
                            tables
                                .retraction_of(row.key())
                                .map(|names| (names, row.key().backing().clone())),
                        )
                    });
                found
            };
            let (rank, handle, prefix, retraction) = found?;
            // The links are asked while the rows stand, which are their places in the replay's
            // order: the queryable's, ranked by the walk that found it, then the declaration's,
            // which comes before every queryable.
            let place = core.place(DeclaredTable::Queryables, rank);
            let keyexpr_place = core.prefix_retraction(prefix);
            #[cfg(feature = "group")]
            core.transport.retract_from_groups(id);
            let undeclared = tables_mut(&core.session.registry).undeclare_queryable(handle)?;
            let row = undeclared.taken;
            // The rows went before the links are told: a send never finds the tables borrowed.
            core.retract_at(place, &|actions: &McuActions<C>| {
                let names = retraction.as_ref().map(|(names, key)| names.names(key));
                QueryableRow::retract(id, names, actions);
            });
            core.retract_keyexpr(keyexpr_place, undeclared.keyexpr);
            // One that counted it may now match no more.
            #[cfg(feature = "local-queryable")]
            self.read_matching(core);
            Some((handle, row))
        });
        // The row, and its callback with it, is let go of here, with no lock held; one a call of
        // which is owed is let go of by the call that ends last.
        match undeclared {
            Some((_, Some(row))) => self.give_back(row.into_holds()),
            Some((handle, None)) => self.wait_for_queryable_release(handle),
            None => {}
        }
        #[cfg(feature = "local-queryable")]
        self.deliver();
    }

    #[cfg(feature = "liveliness")]
    fn declare_liveliness_token_on_wire(
        &self,
        keyexpr: &str,
        wire: WireKey,
        retraction: Option<RetractionKey>,
    ) -> Result<TokenId, Declined> {
        // zenoh-pico's token takes the session's next entity id
        // (`vendor/zenoh-pico/src/net/liveliness.c` @ `uint32_t id = _z_get_entity_id(_Z_RC_IN_VAL(zn));`).
        let declared = self.live().ok_or(Declined::Closed).and_then(|mut core| {
            let core = &mut core.0;
            // The token is a row of the session's tables, which takes its id: a full table, a key
            // the session cannot hold or no id left refuses it before anything is registered or
            // sent. It holds the key expression declaration its key is named by for as long as it
            // stands.
            // A token's retraction names its key as its announcement does.
            let named = if retraction.is_some() {
                Retraction::AsAnnounced
            } else {
                Retraction::ById
            };
            let form = core.session.key_form(wire.mapping_id, named);
            let declared = tables_mut(&core.session.registry).declare_token(keyexpr, form)?;
            core.announce(DeclaredRow::of(declared.handle));
            // A token takes no traffic of its own, so every group that is told tokens is told it.
            // It is held before it is announced (its row, which a peer's and a group member's
            // Interest are answered from), so a member that asks right after it hears the
            // announcement finds it held: the tokio engine's group holds it the same way.
            #[cfg(feature = "group")]
            core.announce_token_to_groups(declared.handle);
            Ok(declared.id)
        });
        // The row holds the declaration its key is named by, so the key the ABI named it by is
        // not kept: what it held goes back, declared or refused, with no lock held.
        self.let_go_of_key(wire);
        declared
    }

    #[cfg(feature = "liveliness")]
    fn undeclare_liveliness_token(&self, id: TokenId) {
        let Some(mut core) = self.live() else {
            return;
        };
        let core = &mut core.0;
        let retracted = {
            let tables = tables(&core.session.registry);
            let found =
                tables
                    .tokens()
                    .iter()
                    .find(|(_, row)| row.id() == id)
                    .map(|(handle, row)| {
                        // What its retraction names, read while the declaration stands.
                        let names = tables.retraction_of(row.key());
                        (handle, names, row.key().prefix())
                    });
            found
        };
        let Some((handle, names, prefix)) = retracted else {
            return;
        };
        // The links are asked while the rows stand, which are their places in the replay's order:
        // the token's, then the declaration's, which comes before every token.
        let token_place = core.place_of(DeclaredRow::of(handle));
        let keyexpr_place = core.prefix_retraction(prefix);
        let Some(undeclared) = tables_mut(&core.session.registry).undeclare_token(handle) else {
            return;
        };
        #[cfg(feature = "group")]
        core.transport.retract_from_groups(id);
        // The rows went before the links are told: a send never finds the tables borrowed.
        let key = undeclared.taken.as_ref().map(|row| row.key().as_str());
        core.retract_at(token_place, &|actions: &McuActions<C>| {
            if let Some(key) = key {
                retract_token(actions, id, names.map(|names| names.names(key)));
            }
        });
        core.retract_keyexpr(keyexpr_place, undeclared.keyexpr);
    }

    #[cfg(feature = "liveliness")]
    fn declare_liveliness_subscriber_on_wire(
        &self,
        keyexpr: &str,
        wire: WireKey,
        history: bool,
        sink: LivelinessSink,
    ) -> Result<SubId, Declined> {
        // A closed session declares nothing, and takes no id for what it does not declare; what
        // the key holds goes back with the refusal.
        let Some(mut guard) = self.live() else {
            self.let_go_of_key(wire);
            return Err(Declined::Closed);
        };
        let core = &mut guard.0;
        // The subscriber is one row of the session's tables, numbered by the id they hand out
        // next, which its Interest carries: a full table, a key the session cannot hold or no id
        // left refuses it before anything is asked, and the sink goes with the refusal. The row
        // holds the key expression declaration its Interest names the key by for as long as it
        // stands, so the key's own hold of it is given back once the row stands.
        let next = tables(&core.session.registry).next_entity_id();
        let Some(id) = next else {
            drop(guard);
            self.let_go_of_key(wire);
            return Err(Declined::NoEntityId);
        };
        let form = core.session.key_form(wire.mapping_id, Retraction::ById);
        let mut holds = wire.into_holds();
        let mut named = holds.take_named();
        let declared = tables_mut(&core.session.registry).declare_liveliness_subscriber(
            keyexpr,
            history,
            form,
            LivelinessRow::new(holds, sink),
        );
        let declared = match declared {
            Ok(declared) => declared,
            Err(refused) => {
                // The program's callback goes with the refusal, let go of with no lock held, and
                // what the key held goes back.
                drop(guard);
                let why = Declined::from(refused.why);
                if let Some(named) = named {
                    named.release(self);
                }
                self.give_back(refused.callback.into_holds());
                return Err(why);
            }
        };
        debug_assert_eq!(
            declared.id, id,
            "the tables number a row as they said they would"
        );
        // With `history`, the subscriber is handed the tokens the session already knows before
        // the peers are asked for the rest, as zenoh-pico's is
        // (`vendor/zenoh-pico/src/net/liveliness.c` @ `_z_liveliness_subscription_trigger_history`):
        // on this thread, one at a time, with the session let go of while each is handed. A token
        // a peer's answer repeats is not handed again: the first declaration of an id wins.
        if history {
            drop(guard);
            if let Some(named) = named.take() {
                named.release(self);
            }
            self.hand_history(declared.handle);
            guard = match self.live() {
                Some(guard) => guard,
                None => return Err(Declined::Closed),
            };
        }
        let core = &mut guard.0;
        // A subscriber its own history's callback undeclared asks nothing: its row is gone, and so
        // is its place in the replay's order.
        let stands = tables(&core.session.registry)
            .liveliness_subscribers()
            .get(declared.handle)
            .is_some();
        if stands {
            // Each link is asked from the row, as it stands now.
            core.announce(DeclaredRow::of(declared.handle));
            // And each group the session joined is asked, as its declarations say.
            #[cfg(feature = "group")]
            {
                let tables = tables(&core.session.registry);
                if let Some(row) = tables.liveliness_subscribers().get(declared.handle) {
                    let wire = group::wire_key_of(tables.wire_of(row.key()));
                    for group in &core.transport.groups {
                        group.ask_liveliness(id, row.key().as_str(), &wire, row.history());
                    }
                }
            }
        }
        drop(guard);
        if let Some(named) = named {
            named.release(self);
        }
        self.deliver();
        Ok(id)
    }
}

/// The places the session's arena laid out at its open for the ABI's objects of its entities
/// ([`HeldPlaces::with_entity`]), one for each row the session keeps of a kind, lent and given
/// back under the session's lock, as every table of its arena is.
impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> PlaceLender for CoopEngine<L, C> {
    /// Closed or not: a place is the session's memory and not its state, and the declaration the
    /// place is taken for answers a closed session itself, as it would with a place to spare.
    fn claim_place(&self, kind: EntityKind) -> Option<EntityPlace> {
        self.core.lock().0.places.claim(kind)
    }

    /// Closed or not: the arena the place lies in is the session's until the engine is let go,
    /// which the ABI's object of the entity holds off.
    fn give_back_place(&self, place: EntityPlace) -> Result<(), EntityPlace> {
        self.core.lock().0.places.give_back(place)
    }
}

/// The ring the session's arena laid out at its open for its advanced publishers' caches
/// ([`CacheSpan`]), lent under a lock of its own: a cache's put and its queryable's answer take
/// it, from whatever thread, and neither takes the session's lock with it.
#[cfg(feature = "advanced-cache")]
impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> wz_capi_port::CacheBytes
    for CoopEngine<L, C>
{
    /// Closed or not: the ring is the session's memory and not its state, and stands until the
    /// engine is let go, which the caches that hold the engine hold off. A plan of no ring lends
    /// an empty span.
    fn with_cache_bytes(&self, with: &mut dyn FnMut(&mut [u8])) {
        let held = self.cache.lock();
        match *held {
            // SAFETY: the span is the arena's, lent to this lock alone, which is held for the call,
            // and the arena stands while the engine does.
            Some(span) => with(unsafe { span.bytes() }),
            None => with(&mut []),
        }
    }
}

/// The keys the C ABI's objects hold, in the session's key arena, all through one body. A closed
/// session makes no key and gives no block back: its close emptied the record, and its arena is
/// given back whole when the engine goes, which a holder's hold on the engine keeps from happening
/// first. So a key shared or let go of after the close takes no lock, and a holder the close itself
/// lets go of, under the lock, does not wait on it.
impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> SessionKeys for CoopEngine<L, C> {
    #[inline(never)]
    fn key(&self, ask: KeyAsk<'_>) -> Result<Option<HeldKey>, KeyNotHeld> {
        let Some(core) = self.live() else {
            return match ask {
                KeyAsk::Hold(_) => Err(KeyNotHeld::Closed),
                // SAFETY: the session is closed, so its arena makes no key and gives no block
                // back, and a release after the close hands nothing to the arena (below).
                KeyAsk::Share(key) => Ok(Some(unsafe { key.uncounted() })),
                KeyAsk::Release(_) => Ok(None),
            };
        };
        let core = &core.0;
        match ask {
            // A text the arena keeps already, whoever holds it, is that block shared, so a key the
            // session's declarations and the program's objects name alike takes one block.
            KeyAsk::Hold(text) => match LentKeys::from(core.session.keys).shared(text) {
                Ok(key) => Ok(Some(HeldKey::of(key))),
                Err(KeyUnkept::TooLong) => Err(KeyNotHeld::TooLong),
                Err(KeyUnkept::NoRoom) => Err(KeyNotHeld::NoRoom),
            },
            // SAFETY: the session's lock is held (`core`), and the key is its arena's.
            KeyAsk::Share(key) => Ok(Some(unsafe { key.share(&core.session.keys) })),
            KeyAsk::Release(key) => {
                // SAFETY: as a share.
                unsafe { key.release(&core.session.keys) };
                Ok(None)
            }
        }
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> SessionDrive
    for CoopEngine<L, C>
{
    fn zid(&self) -> [u8; 16] {
        SessionEngine::zid(self)
    }

    fn close(&self) {
        // The read task stops first, so the close is the last thing the session does. A close
        // from the read task itself stops nothing and leaves the thread to see the session
        // closed.
        let _ = self.stop_reader();
        let mut guard = self.core.lock();
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let core = &mut guard.0;
        core.end_links();
        // The rows of the session's own declarations, and the callbacks they hold, go after the
        // lock is let go of, one row at a time (`Self::let_go_of_rows`).
        // A get still pending ends with its session: its entry goes here, its leg's callback with
        // the table.
        #[cfg(feature = "query")]
        {
            let mut registry = core.session.registry.borrow_mut();
            while let Some(pending) = core.session.pending_gets.pop() {
                pending.unregister(&mut *registry);
            }
        }
        // The session's tokens end with its link: the rows of its tables go, each with its hold of the
        // declaration its key is named by.
        #[cfg(feature = "liveliness")]
        {
            let mut tables = tables_mut(&core.session.registry);
            loop {
                let Some(handle) = tables.tokens().iter().next().map(|(handle, _)| handle) else {
                    break;
                };
                let _ = tables.undeclare_token(handle);
            }
        }
        // The watches end with the session; their sinks, and the C contexts they hold, are let go
        // of with no lock held.
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        let watches = self.decl_watches.close();
        // A closed session runs no periodic job, so each ends with it, and what it holds (a place
        // of the session's, which goes back under this lock) is let go of with no lock held.
        #[cfg(feature = "ticker")]
        let jobs = core.tickers.take_all();
        drop(guard);
        #[cfg(feature = "ticker")]
        drop(jobs);
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        drop(watches);
        // What publishes handed to the session and it never sent goes with it, let go of with no
        // lock held, as a sent leg is.
        #[cfg(any(feature = "listen", feature = "group"))]
        {
            let handed = {
                let mut handed = self.handed();
                self.owed.store(false, Ordering::SeqCst);
                core::mem::take(&mut *handed)
            };
            drop(handed);
        }
        #[cfg(feature = "query")]
        {
            // Each end gives back its count of its leg's row, and the callback goes there when no
            // record of the round still holds it, with no lock held.
            while let Some(ended) = self.gets.take_end() {
                self.gets.forget_due(ended.leg());
                drop(self.gets.release(ended.row()));
            }
            drop(self.gets.take_all_held());
        }
        // A round sealed and handed out by no delivery is emptied unhanded, its calls ended: no
        // callback of the session is called after its close. The rows whose last call that was
        // go first, then every row the close emptied.
        self.samples.discard();
        self.let_go_of_released();
        self.let_go_of_rows();
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn start_read_task(&self) -> Result<(), ReadTaskStartRefused> {
        self.start_reader(|body| os::spawn(move || body.run()))
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
        // read by this call and a publisher on another thread is not held up by it. Input the last
        // step left held makes it none, which it is then without the session taken to say so:
        // under a stream of batches each read takes the session once, for its step.
        // A read behind another's wait counts itself in under the session's lock, which the
        // hand-back it waits for is made under too.
        let mut seen = None;
        let mut wait = if self.input_held.swap(false, Ordering::Relaxed) {
            IdleWait::None
        } else {
            // Marked as a holder that holds no send, so a droppable publish that finds the session
            // held for the wait tries it again at once (`LinkRooms::for_held`): the mark is let go
            // before the session is.
            self.live().map_or(IdleWait::None, |mut core| {
                let _waiting = SendingOn::enter(&self.sending_on, WAITING);
                let wait = core.0.idle_wait();
                if matches!(wait, IdleWait::Behind(_)) {
                    seen = Some(self.hand_back.enter());
                }
                wait
            })
        };
        #[cfg(test)]
        self.takes.wait(&wait);
        match (&wait, seen) {
            (IdleWait::Behind(ms), Some(seen)) => self.hand_back.wait(seen, *ms),
            _ => wait.wait(self.rooms.waits(), sleep_ms),
        }
        // One pass of the session's task reads what its link holds, a batch at a time, and does
        // what is due: `single` asks for one message, and a pass is the least this engine reads.
        // One take of the session for the step: its links, what publishes handed to it, and
        // whether a periodic job is due by the clock reading the step made.
        // What publishes handed to the session while it was held leaves on this step too, so a
        // program that only reads its session sends it; let go of once the session is.
        let (stepped, jobs_due_ms) = match self.live() {
            Some(mut core) => {
                let handed = matches!(wait, IdleWait::Input { .. });
                core.0.transport.links.waited(wait);
                if handed {
                    self.hand_back.handed_back();
                }
                let stepped = self.step(&mut core.0);
                self.input_held.store(
                    stepped.is_some() && core.0.transport.holds_input(),
                    Ordering::Relaxed,
                );
                let jobs_due_ms = stepped.and_then(|now_us| core.0.jobs_due_at(now_us));
                #[cfg(any(feature = "listen", feature = "group"))]
                self.send_handed_now(&core.0);
                (stepped.is_some(), jobs_due_ms)
            }
            None => (false, None),
        };
        self.deliver();
        if let Some(started_ms) = jobs_due_ms {
            self.run_due_tickers(started_ms);
        }
        if stepped {
            Ok(())
        } else {
            Err(SessionClosed)
        }
    }

    fn send_keep_alive(&self) -> Result<(), SessionClosed> {
        let core = self.live().ok_or(SessionClosed)?;
        // A link that is down has no lease to keep; the session is not closed.
        for actions in core.0.transport.ups() {
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

/// A get's fan cancelled before the engine issued a leg of it ([`CoopEngine::tag_of`]).
#[cfg(feature = "query")]
struct FanCancelled;

/// The legs a cancelled fan tagged are ended one at a time: each pending entry is taken out under
/// the session's lock and its callback dropped after it, with no lock held, so a token's `cancel`
/// that waits for the callbacks returns whether or not the session is stepped.
#[cfg(feature = "query")]
impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> FanCanceller
    for CoopEngine<L, C>
{
    fn cancel_fan(&self, key: FanKey) {
        loop {
            let leg = self.live().and_then(|mut core| {
                let core = &mut core.0;
                let at = core
                    .session
                    .pending_gets
                    .iter()
                    .position(|pending| pending.fan == Some(key))?;
                let pending = core.session.pending_gets.remove(at);
                pending.unregister(&mut *core.session.registry.borrow_mut());
                Some(pending.leg)
            });
            let Some(leg) = leg else {
                break;
            };
            self.end_leg_now(leg);
        }
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
    /// The one body of a plain put through write filter `filter`: the filter's answer, the plain
    /// form (`given`, or the one the filter's row keeps when none is given) and the sends, under
    /// one take of the session, as zenoh-pico's put reads its filter's state and takes only its
    /// transmit lock (`vendor/zenoh-pico/src/api/api.c` @ `!_z_write_filter_active(&pub->_filter)`).
    #[inline(never)]
    fn put_through_filter(
        &self,
        filter: FilterId,
        keyexpr: &str,
        payload: &[u8],
        given: Option<(ExprId, PlainPutParams)>,
    ) -> FilteredPut {
        let Some(core) = self.live() else {
            return FilteredPut::Sent(Ok(0));
        };
        let core = &core.0;
        if Self::holds_back_in(core, filter) {
            return FilteredPut::Suppressed;
        }
        let (mapping_id, params) = match given {
            Some(given) => given,
            None => {
                let plain = row_of(filter).and_then(|handle| {
                    tables(&core.session.registry)
                        .write_filters()
                        .get(handle)
                        .and_then(|row| row.plain())
                });
                let Some((params, mapping_id)) = plain else {
                    return FilteredPut::NotPlain;
                };
                // A link that names keys its own way is sent the general way, which names the key
                // as its form says: no declared id goes to every link at once.
                #[cfg(feature = "shared-key-ids")]
                if core.session.key_ids.is_some()
                    || core.transport.key_forms.departs_from_declared()
                {
                    return FilteredPut::NotPlain;
                }
                (mapping_id, params)
            }
        };
        self.put_plain_in(core, keyexpr, mapping_id, payload, &params)
    }

    /// This session as the C handle's drive: the engine's own allocation, which the handle holds
    /// as one of its `Arc`s, so the open makes nothing more for it.
    pub fn into_drive(self: Arc<Self>) -> CoopDrive<L, C> {
        let handle_place = self.handle_place;
        CoopDrive {
            engine: self,
            handle_place,
        }
    }
}

/// The C handle's hold on a session of this engine, kept by value in the handle: the engine is
/// shared with the entities declared on it and with its read task, so the handle holds one of its
/// `Arc`s. Its operations are the port's [`SessionDrive`] of this engine, called by name, so an
/// ABI built over one kind of links reaches its session through no table of functions, and the
/// engine it hands out is the engine's own type.
pub struct CoopDrive<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> {
    engine: Arc<CoopEngine<L, C>>,
    handle_place: Option<HandlePlace>,
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> CoopDrive<L, C> {
    /// The engine the session's entities keep.
    pub fn engine(&self) -> Arc<CoopEngine<L, C>> {
        self.engine.clone()
    }

    /// The engine, borrowed for the length of one call.
    pub fn engine_ref(&self) -> &CoopEngine<L, C> {
        &self.engine
    }

    /// The session's own hold of the engine, borrowed for the length of one call: a caller that
    /// keeps the engine clones it where it keeps it, and one that only reaches it counts nothing.
    pub fn engine_hold(&self) -> &Arc<CoopEngine<L, C>> {
        &self.engine
    }

    /// The place the session's arena lent the ABI's handle (`open_made_in`'s `handle`), `None`
    /// for a session opened without one. It stands while the engine does.
    pub fn handle_place(&self) -> Option<HandlePlace> {
        self.handle_place
    }

    /// The session's own zid, zero-padded to 16 bytes ([`SessionEngine::zid`]).
    pub fn zid(&self) -> [u8; 16] {
        SessionEngine::zid(self.engine_ref())
    }

    /// [`SessionDrive::close`].
    pub fn close(&self) {
        SessionDrive::close(self.engine_ref())
    }

    /// [`SessionDrive::is_closed`].
    pub fn is_closed(&self) -> bool {
        SessionDrive::is_closed(self.engine_ref())
    }

    /// [`SessionDrive::start_read_task`].
    pub fn start_read_task(&self) -> Result<(), ReadTaskStartRefused> {
        SessionDrive::start_read_task(self.engine_ref())
    }

    /// [`SessionDrive::stop_read_task`].
    pub fn stop_read_task(&self) -> Result<(), CalledFromReadTask> {
        SessionDrive::stop_read_task(self.engine_ref())
    }

    /// [`SessionDrive::read_task_is_running`].
    pub fn read_task_is_running(&self) -> bool {
        SessionDrive::read_task_is_running(self.engine_ref())
    }

    /// [`SessionDrive::read`].
    pub fn read(&self, single: bool) -> Result<(), SessionClosed> {
        SessionDrive::read(self.engine_ref(), single)
    }

    /// [`SessionDrive::send_keep_alive`].
    pub fn send_keep_alive(&self) -> Result<(), SessionClosed> {
        SessionDrive::send_keep_alive(self.engine_ref())
    }

    /// [`SessionDrive::spin_once`].
    pub fn spin_once(&self) -> bool {
        SessionDrive::spin_once(self.engine_ref())
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> Drop for CoopDrive<L, C> {
    /// The C program let go of its session (zenoh-pico's `z_session_drop`), which closes it: the
    /// read task, which holds the engine too, is stopped and joined, and an entity declared on the
    /// session that outlives it finds it closed.
    fn drop(&mut self) {
        SessionDrive::close(self.engine_ref());
    }
}

/// What the builders of [`IpLinks`](wz_runtime_coop::ip_stack::IpLinks) turn links into: the links
/// `with_tls` makes over a secure channel `S`, and those `with_groups` makes joining groups by
/// `J`. An ABI names with it the links it opens its sessions over, and so the engine's type,
/// whatever its build adds to the host's.
pub trait ComposedLinks {
    /// The links `with_tls` makes.
    type WithTls<S>;
    /// The links `with_groups` makes.
    type WithGroups<J>;
}

impl<U, D, L, G> ComposedLinks for wz_runtime_coop::ip_stack::IpLinks<U, D, L, G> {
    type WithTls<S> = wz_runtime_coop::ip_stack::IpLinks<U, D, S, G>;
    type WithGroups<J> = wz_runtime_coop::ip_stack::IpLinks<U, D, L, J>;
}

#[cfg(feature = "queryable")]
impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static>
    crate::round::AnswersQueries<crate::round::CoopCalls> for CoopEngine<L, C>
{
    fn answer_query(&self, call: &QueryableCall, query: &dyn QueryView, generation: u64) {
        self.run_queryable(call, query, generation);
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> Drop for CoopEngine<L, C> {
    fn drop(&mut self) {
        // The last handle is gone, so no read task holds one: it has stopped, or is about to
        // drop the handle it held. A session never closed is closed now; a closed one has no
        // link left to end.
        self.core.dropping().end_links();
        // The kept publishes' places lie in the session's arena, which the state's drop gives
        // back: they are given back first.
        #[cfg(any(feature = "listen", feature = "group"))]
        lock(&self.handed).clear();
        // The round's tables lie in the session's arena, which the state's drop gives back: they
        // are let go of first, with the callbacks their records owe, each call ended before the
        // row it reads is dropped with the tables.
        // SAFETY: the last handle is gone, so no delivery runs or starts.
        unsafe { self.samples.let_go() };
        // The legs' rows and ends lie in the arena too. A session never closed still holds the
        // entries of its pending gets: they go first, each saying its end, and the plane lets go
        // of the ends and the rows after, the callbacks still held among them.
        #[cfg(feature = "query")]
        {
            let core = self.core.dropping();
            let mut registry = core.session.registry.borrow_mut();
            while let Some(pending) = core.session.pending_gets.pop() {
                pending.unregister(&mut *registry);
            }
            drop(registry);
            self.gets.let_go();
        }
        // The held Finals' rows lie in the arena too; the round's calls were ended above.
        #[cfg(feature = "queryable")]
        self.plane.let_go();
    }
}

#[cfg(all(test, feature = "std", feature = "time-base", unix))]
mod clock_moves_tests {
    use super::*;
    use core::task::Waker;
    use std::sync::Mutex as StdMutex;
    use std::time::{Duration, Instant};
    use wz_runtime_posix::net::PosixWaits;

    /// A program's word as a test tells it: the waker the open watched with, woken by `tell`.
    #[derive(Default)]
    struct Word(StdMutex<Option<Waker>>);

    impl Word {
        fn tell(&self) {
            if let Some(waker) = self.0.lock().unwrap().as_ref() {
                waker.wake_by_ref();
            }
        }
    }

    impl ClockMoves for Word {
        fn watch(&self, waker: Waker) {
            *self.0.lock().unwrap() = Some(waker);
        }
    }

    /// A read on a moved clock that sleeps five seconds to its next dial waits on the stack's
    /// wake in place of the sleep, and the program's word, told from another thread, ends it long
    /// before its bound. Turned red by a sleep the word cannot end, or a wake the word does not
    /// wake.
    #[test]
    fn a_wait_for_the_next_dial_ends_at_the_word_that_the_clock_moved() {
        let word = Arc::new(Word::default());
        let moves: ClockMovesWord = word.clone();
        let wake = PosixWaits.wake().expect("the host makes a wake");
        moves.watch(wake.waker.clone());
        let (most, beside) = clock_beside(5_000, Some(&moves), Some(&wake));
        let mut wait = IdleWait::Input {
            on: beside.into_iter().collect(),
            ms: most,
        };
        let telling = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            word.tell();
        });
        let started = Instant::now();
        wait.wait(&PosixWaits, |_| panic!("the word made the sleep a wait"));
        let took = started.elapsed();
        telling.join().expect("the thread that tells the word");
        assert!(
            took < Duration::from_millis(2_500),
            "the read waited out its bound instead of the word ({took:?})"
        );
    }

    /// A moved clock's word joins a read's wait as the stack's wake, for the whole bound; a stack
    /// that makes no wake bounds the wait at a look; a clock that moves by itself leaves the wait
    /// as it was. Turned red by a word left out of the wait, or one with no wake that waits on.
    #[test]
    fn the_word_joins_a_wait_as_the_stacks_wake_or_bounds_it_at_a_look() {
        let moves: ClockMovesWord = Arc::new(Word::default());
        let wake = PosixWaits.wake().expect("the host makes a wake");
        assert_eq!(
            clock_beside(9, Some(&moves), Some(&wake)),
            (9, Some(LinkWait::input(wake.on)))
        );
        assert_eq!(clock_beside(9, Some(&moves), None), (1, None), "no wake");
        assert_eq!(
            clock_beside(7, None, Some(&wake)),
            (7, None),
            "CONTROL: a clock that moves by itself"
        );
    }
}

#[cfg(test)]
mod row_id_tests {
    //! How the port's ids of write filters and matching listeners name their rows.
    use super::{counts_own, plane_of, row_id, row_of};
    use core::num::NonZeroU32;
    use wz_capi_port::FilterPlane;
    use wz_session_core::session_tables::{kind, Plane, WriteFilterHandle};

    /// A row's id is its handle's bits and names that handle back; an id no handle is made of
    /// names none: zero, and one past a handle's width, whose low bits alone would name a row.
    #[test]
    fn a_rows_id_names_its_handle_and_no_other() {
        let bits = NonZeroU32::new(0x0003_0005).expect("not zero");
        let handle = WriteFilterHandle::from_bits(bits).expect("an index");
        let id = row_id(handle);
        assert_eq!(id, 0x0003_0005);
        assert_eq!(row_of::<kind::WriteFilter>(id), Some(handle));
        assert_eq!(row_of::<kind::WriteFilter>(0), None);
        assert_eq!(row_of::<kind::WriteFilter>(id + (1 << 32)), None);
        // The same slot at another generation is another row.
        assert_ne!(row_of::<kind::WriteFilter>(0x0004_0005), Some(handle));
    }

    /// A plane of the port is the tables' plane of the same kind, a querier's need of complete
    /// queryables kept.
    #[test]
    fn a_ports_plane_is_the_tables_plane_of_its_kind() {
        assert_eq!(plane_of(FilterPlane::Subscribers), Plane::Subscribers);
        for complete_required in [false, true] {
            assert_eq!(
                plane_of(FilterPlane::Queryables { complete_required }),
                Plane::Queryables { complete_required }
            );
        }
    }

    /// The session's own entities count only for a filter or a listener that asked them to, and
    /// only in a build that delivers to them locally; never for one that did not ask.
    #[test]
    fn the_sessions_own_entities_count_only_where_asked_and_built() {
        let querier = FilterPlane::Queryables {
            complete_required: false,
        };
        assert!(!counts_own(FilterPlane::Subscribers, false));
        assert!(!counts_own(querier, false));
        assert_eq!(
            counts_own(FilterPlane::Subscribers, true),
            cfg!(feature = "local-subscriber")
        );
        assert_eq!(counts_own(querier, true), cfg!(feature = "local-queryable"));
    }
}

#[cfg(all(test, any(feature = "query", feature = "liveliness-get")))]
mod leg_deadline_tests {
    //! Where a get's leg ends on the session's clock.
    use super::leg_deadline_ms;

    /// A leg's deadline is its timeout past the asking millisecond rounded up, at the clock's
    /// last microsecond too.
    ///
    /// # Control
    ///
    /// Reading the clock as `now_us / 1000`, rounded down, reds the first assertion.
    #[test]
    fn a_legs_deadline_rounds_up_at_every_reading_of_the_clock() {
        assert_eq!(leg_deadline_ms(1_001, 5), 7, "1.001 ms rounds up to 2");
        assert_eq!(leg_deadline_ms(2_000, 0), 2, "a whole millisecond stays");
        assert_eq!(
            leg_deadline_ms(u64::MAX, u32::MAX),
            18_446_744_073_709_552 + 4_294_967_295
        );
    }
}

#[cfg(all(test, feature = "group"))]
mod member_key_tests {
    //! How a group member's key names its group and its place in the group's member table.
    use super::{member_key, member_places};

    /// A member's key holds its group's place above its own, and gives both back; the key past a
    /// group's last place is the next group's first.
    ///
    /// # Control
    ///
    /// Swapping the halves in `member_key` reds the first assertion.
    #[test]
    fn a_members_key_holds_its_group_above_its_place() {
        assert_eq!(member_key(1, 2), 0x0000_0001_0000_0002);
        assert_eq!(member_places(0x0000_0001_0000_0002), (1, 2));
        assert_eq!(member_key(u32::MAX, u32::MAX), u64::MAX);
        assert_eq!(member_places(u64::MAX), (u32::MAX, u32::MAX));
        assert_eq!(member_places(member_key(3, u32::MAX) + 1), (4, 0));
    }
}

#[cfg(all(test, feature = "std"))]
mod hand_back_tests {
    use super::{lock, HandBack};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// A read waiting for another read's buffer wakes when the buffer is handed back, well
    /// before its bound, and is counted out after. Turned red by a hand-back that wakes no one,
    /// which leaves a read task asleep for its whole bound behind a program's read.
    #[test]
    fn a_read_waiting_for_the_buffer_wakes_when_it_is_handed_back() {
        let back = Arc::new(HandBack::new());
        let seen = back.enter();
        let handing = {
            let back = back.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                back.handed_back();
            })
        };
        let started = Instant::now();
        back.wait(seen, 5_000);
        let took = started.elapsed();
        handing
            .join()
            .expect("the thread that hands the buffer back");
        assert!(
            took < Duration::from_millis(2_500),
            "the read slept out its bound ({took:?})"
        );
        assert_eq!(back.behind.load(core::sync::atomic::Ordering::SeqCst), 0);
    }

    /// A hand-back made after a read counted itself in and before its wait began ends that wait
    /// at once. Turned red by a wait that looks for a notification alone, which this one missed.
    #[test]
    fn a_hand_back_before_the_wait_begins_ends_it_at_once() {
        let back = HandBack::new();
        let seen = back.enter();
        back.handed_back();
        let started = Instant::now();
        back.wait(seen, 5_000);
        assert!(started.elapsed() < Duration::from_millis(2_500));
    }

    /// A hand-back with no read waiting takes no lock and moves no count. Turned red by one
    /// that counts a hand-back no read waits for.
    #[test]
    fn a_hand_back_with_no_read_waiting_counts_nothing() {
        let back = HandBack::new();
        back.handed_back();
        assert_eq!(*lock(&back.handed), 0);
    }
}
