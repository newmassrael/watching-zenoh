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
use core::cell::{Cell, RefCell};
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};
// A 64-bit atomic where the target has one, and a critical section where it does not (a
// Cortex-M7 has 32-bit atomics only).
use portable_atomic::AtomicU64;

#[allow(unused_imports)]
use crate::prelude::*;

use crate::arena::{
    AllocatorMemory, ArenaMemory, ArenaPlan, ArenaRefused, EntityKind, EntityPlace, EntityPlaces,
    EntityRows, HandlePlace, HeldPlaces, SessionArena,
};
use crate::lane::{LaneCounts, LaneGate, LaneItem, MatchFlips, SharedLane};
use wz_session_core::bounded::{BoundedVec, Lent};
use wz_session_core::caps;
use wz_session_core::key_arena::{KeyRef, KeySpace};
use wz_session_core::slot_observer::ObserverRows;

// The operating system the engine runs on: its mutex, its threads and its sleep are `std`'s on a
// host and the kernel's on an MCU (`docs/upstream-parity.md` section 5a, E1).
#[cfg(feature = "listen")]
use crate::admission_gate::{AdmissionGate, Admitted};
use wz_capi_port::os::{self, JoinHandle, Mutex, MutexGuard, ThreadId};
use wz_capi_port::sync::Lock;
use wz_capi_port::{
    BatchStep, CalledFromReadTask, FanoutError, FilterId, FilterPlane, FilteredPut, HeldKey,
    KeyAsk, KeyNotHeld, MatchId, MatchingSink, PeerIdentity, PlaceLender, ReadTaskStartRefused,
    SessionClosed, SessionDrive, SessionEngine, SessionKeys, StatementNotHonoured, SubId,
    SubscriberSink, WireKey,
};
// The port's refusal of a declaration, named apart from this crate's refusal of an endpoint.
use wz_capi_port::Refusal as Declined;
#[cfg(feature = "ticker")]
use wz_capi_port::{Tick, TickerId};
use wz_runtime_coop::executor::SpawnRefusal;
#[cfg(feature = "listen")]
use wz_runtime_coop::faces::Accepted;
use wz_runtime_coop::faces::{
    Dial, DialEndpoint, EndpointTexts, FaceRecord, FaceSession, IdleWait, Link, LinkSupervisor,
    Moved,
};
use wz_runtime_coop::link_cells::CellRc;
use wz_runtime_coop::reassembly_rx::{
    session_reassembly, SessionChains, SessionReassembly, LENT_CHAINS,
};
#[cfg(feature = "listen")]
use wz_runtime_coop::session_drive::wait_any;
use wz_runtime_coop::session_drive::LinkOpenError;
#[cfg(any(feature = "time-base", feature = "listen"))]
use wz_runtime_coop::session_drive::LinkReadiness;
use wz_runtime_coop::session_drive::{
    router_session_task_bytes, spawn_session_with_router, LinkWritability, OpenedLink, PendingDial,
    SessionDatagramLink, SessionDriveConfig, SessionLinks, SessionRole,
};
use wz_runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeRows};
use wz_session_core::byte_cells::LentByteCells;
use wz_session_core::close_reason::CloseReason;
#[cfg(any(feature = "query", feature = "queryable"))]
use wz_session_core::declare::queryable::QuerierCriterion;
use wz_session_core::declare::subscriber::PublisherCriterion;
use wz_session_core::declare_form::{InterestAsk, InterestForm, RetractionKey};
use wz_session_core::driver_loop::{EventSink, IterationEvent};
use wz_session_core::entropy::{EntropySource, EntropyUnavailable};
use wz_session_core::interest_build::InterestKinds;
use wz_session_core::lent_push;
use wz_session_core::limits::SessionLimits;
#[cfg(feature = "listen")]
use wz_session_core::link_admission::{LinkAdmission, LinkRegistry};
use wz_session_core::locality::Locality;
use wz_session_core::locator_directory::LocatorText;

use crate::open_source::{Counted, EndpointList, EndpointWriter, OpenSource};
use wz_session_core::metadata::PushMetadata;
use wz_session_core::network_message::NetworkMessage;
#[cfg(not(feature = "shared-key-ids"))]
use wz_session_core::policy::KeyWireForm;
use wz_session_core::policy::{SessionPolicy, SnResolution};
use wz_session_core::publish_options::{PlainPutParams, PublishError, PublishOptions};
use wz_session_core::push_build;
use wz_session_core::qos::{CongestionControl, Priority};
use wz_session_core::sample::{QosLevel, SampleKind};
use wz_session_core::send_wire_error::SendWireError;
#[cfg(feature = "listen")]
use wz_session_core::session_actions::Probed;
use wz_session_core::session_init_params::{
    HeldDrop, KeepAliveConf, LinkRxConf, SessionInitParams, SessionZid, TxQueueConf, ZidError,
};
use wz_session_core::session_timeouts::SessionTimeouts;
#[cfg(feature = "shared-key-ids")]
use wz_session_core::shared_key_ids::{KeyIdsAtOpen, KeyIdsRefused, LinkKeyForms, SharedKeyIds};
use wz_session_core::signing_key::SigningKey;
use wz_session_core::sink::{SampleSink, SampleView};
use wz_session_core::timestamp_visibility::{exposed_by, HiddenTimestamp};
use wz_session_core::unicast_rx::RouterLend;
use wz_session_core::wire_id::{next_u32_id, u32_id_taken, EntityId, ExprId};
use wz_session_core::wireexpr_resolve::{OwnMappingSpace, SharedOwnMappingSpace};
use wz_session_core::WhatAmI;
#[cfg(feature = "listen")]
use wz_session_mcu::dial::parse_listen_locator;
use wz_session_mcu::dial::{parse_locator, McuActions};
#[cfg(feature = "queryable")]
use {
    query::{CoopHolder, Onward, QueryPlane},
    wz_capi_port::{QblId, QueryCallback, QueryableSink},
    wz_session_core::query::QueryableId,
    wz_session_core::query_sink::ReplyError,
    wz_session_core::query_sink::{BoxedQuerySink, QueryView},
    wz_session_core::reply_stage::ReplyParts,
    wz_session_core::response_sink::ResponseSink,
};

#[cfg(feature = "local-queryable")]
use wz_session_core::reply_stage::ReplyStage;

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

mod deliveries;
use deliveries::Deliveries;
mod queued;
use queued::Queued;

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

#[cfg(any(
    feature = "remote-declaration-watch",
    feature = "declarations-synced-event"
))]
mod decl_watch;
#[cfg(any(
    feature = "remote-declaration-watch",
    feature = "declarations-synced-event"
))]
use {
    decl_watch::DeclWatches,
    wz_capi_port::{DeclPlane, DeclWatchId, DeclWatchSink},
};

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
    liveliness::{LiveSubEntry, LivelinessCallback, TokenEntry},
    wz_capi_port::{LivelinessSink, TokenId},
};

#[cfg(feature = "query")]
mod get;
#[cfg(feature = "query")]
use {
    get::{EndedLegs, GetKind, GetPlane, PendingGet},
    wz_capi_port::{cancellation::CancellableFan, ReplyCallback},
    wz_session_core::query_options::QueryOptions,
    wz_session_core::registry_error::RegisterError,
    wz_session_core::reply_acceptance::ReplyAcceptance,
    wz_session_core::reply_sink::{ConsolidatingSink, ReplyView},
    wz_session_core::timestamp_visibility::HiddenReplyTimestamp,
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
    /// base it supplies): a read that waits for its next dial waits on it, and one that waits on
    /// its links waits on it beside them, so the program's word ends the wait. `None` for a clock
    /// that moves by itself, whose waits the wall bounds. Always `None` in a build without
    /// `time-base`, whose [`ClockMovesWord`] has no value.
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
        // Made only for a session whose clock moves by itself (`LinkSupervisor::idle_wait`): a
        // read the link waits in cannot be ended by the word.
        read @ IdleWait::Read(..) => read,
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

/// The policies a session [`CoopEngine::open`] opens from `config` runs under: the one place that
/// open decides them. The build defaults: the config is what the ABI read from its own keys and
/// values, not a zenoh document with a `wz` member, and it has no field for a policy yet; the
/// ABI's door for one is a key of its own.
fn resolve_policy<E>(_config: &CoopConfig<E>) -> SessionPolicy {
    SessionPolicy::defaults()
}

/// The session limits a session [`CoopEngine::open`] opens from `config` holds its tables to: the
/// one place that open decides them. The snapshot the ABI resolved and states in the config
/// ([`CoopConfig::limits`]), its delivery lane long enough for what one record the session is
/// handed can put in it (`lane::holding_a_read`).
pub(crate) fn resolve_limits<E>(config: &CoopConfig<E>) -> SessionLimits {
    crate::lane::holding_a_read::<
        { caps::PICO_UNICAST_BATCH_BYTES },
        { caps::PICO_FRAG_MAX_BYTES },
        { caps::MAX_KEYEXPR_BYTES },
        { caps::MAX_SUBSCRIPTIONS },
        { caps::MAX_LIVELINESS_SUBSCRIPTIONS },
    >(config.limits)
}

/// An endpoint a session could not use, at its open or at a later dial: the endpoint as it was
/// given, and why.
// Typed and not a text: the C ABIs answer a refusal with a code and never read its words, so the
// formatter is linked only into a program that prints one (`Display`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRefusal {
    /// The endpoint, as the config or the caller states it, at most `MAX_LOCATOR_LEN` bytes of
    /// it; empty when the refusal is the session's and names no endpoint ([`Refusal::LinkLost`]).
    pub endpoint: LocatorText,
    /// Why it could not be used.
    pub why: Refusal,
}

impl EndpointRefusal {
    /// The refusal of `endpoint` for `why`. A refusal is made after the open too (a dial again
    /// that fails), so it keeps the endpoint in a row's length and no memory of the heap: a text
    /// longer than that is kept up to the last whole character that fits.
    pub(crate) fn new(endpoint: &str, why: Refusal) -> Self {
        let mut cut = endpoint.len().min(caps::MAX_LOCATOR_LEN);
        while !endpoint.is_char_boundary(cut) {
            cut = cut.saturating_sub(1);
        }
        let mut kept = LocatorText::new();
        // The cut is at most a row's length, so the text before it fits whole.
        let _ = kept.push_str(endpoint.get(..cut).unwrap_or_default());
        Self {
            endpoint: kept,
            why,
        }
    }
}

/// Why an endpoint could not be used ([`EndpointRefusal`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The endpoint does not parse as a locator this build can dial or listen on.
    Locator(wz_session_mcu::connect_manager::DialRefused),
    /// The network opened no link, listener or group for it.
    Link(LinkOpenError),
    /// The handshake ended with a close reason.
    HandshakeClosed(CloseReason),
    /// The handshake ended with no close reason.
    HandshakeEnded,
    /// Nothing answered by the deadline.
    NoAnswerInTime,
    /// The link was lost and the session dials no endpoint again.
    LinkLost,
    /// The endpoint is one to listen on, and this build does not listen.
    ListeningNotBuilt,
    /// The endpoint is a group to join, and this build joins no group.
    GroupsNotBuilt,
    /// The group was joined and its link did not open.
    GroupLinkDidNotOpen,
    /// The session is closed.
    SessionClosed,
    /// The session holds as many faces as `max_faces` admits.
    FacesFull,
    /// The endpoint's text is longer than a row of the session's endpoints, `MAX_LOCATOR_LEN`
    /// bytes.
    TextTooLong,
}

impl core::fmt::Display for EndpointRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if !self.endpoint.is_empty() {
            write!(f, "{}: ", self.endpoint)?;
        }
        match self.why {
            Refusal::Locator(why) => write!(f, "{why:?}"),
            Refusal::Link(why) => write!(f, "{why:?}"),
            Refusal::HandshakeClosed(reason) => write!(f, "the handshake ended: {reason:?}"),
            Refusal::HandshakeEnded => f.write_str("the handshake ended"),
            Refusal::NoAnswerInTime => f.write_str("no answer in time"),
            Refusal::LinkLost => f.write_str("the link was lost"),
            Refusal::ListeningNotBuilt => f.write_str("listening is not built"),
            Refusal::GroupsNotBuilt => f.write_str("joining a group is not built"),
            Refusal::GroupLinkDidNotOpen => f.write_str("the group's link did not open"),
            Refusal::SessionClosed => f.write_str("the session is closed"),
            Refusal::FacesFull => {
                f.write_str("the session holds as many faces as max_faces admits")
            }
            Refusal::TextTooLong => f.write_str("the endpoint is longer than MAX_LOCATOR_LEN"),
        }
    }
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
        let Ok(at) = wz_session_mcu::dial::parse_listen_locator(endpoint.as_ref()) else {
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
    rooms: Arc<LinkRooms>,
    wait_before_drop_us: u64,
    held_drop: HeldDrop,
    /// The face a publish holding the session sends on now, [`NOT_SENDING`] while none does
    /// ([`SendingOn`]): the face pico's profile drops a droppable publish on, as against the
    /// session's other faces, which it is still sent to, and a session held by a read step, a
    /// timer or the drive, which it waits for.
    sending_on: AtomicU64,
    /// The droppable publishes that found the session held and were dropped on the faces its
    /// holder waits on, owed to the session's other faces ([`HandedLeg`]), in the order they
    /// were handed.
    handed: Mutex<VecDeque<HandedLeg>>,
    /// Whether `handed` holds a leg, written under its lock: a publish that reads it clear takes
    /// no lock for the queue, which is otherwise two lock round trips on every put of a stream for
    /// what is almost always nothing. A publish that reads it stale leaves the leg to the next
    /// holder, as one that took the queue a moment before the leg was handed does; a read step
    /// always looks under the lock ([`Self::send_handed_now`]).
    owed: AtomicBool,
    /// Whether the last read's step left a link holding input it had already taken from its stack
    /// (a batch behind the one it read, the rest of a datagram the lane had no room for), or a
    /// group with a datagram its next step reads: the next read steps at once, with no wait to
    /// work out under the session's lock, since that wait would be none. Written by the step, under
    /// the lock; a stale `true` costs one step that finds nothing, after which the read waits.
    input_held: AtomicBool,
    /// How many handed legs of each priority are held at most: as many as the session's queue
    /// holds batches of that priority (`TxQueueConf::sizes`), which is as many as a face whose
    /// queue were its own would take before a droppable message found no room on it.
    handed_at_most: [usize; Priority::NUM],
    /// The droppable publishes dropped before they reached a link: on the faces a held session
    /// waits on, for want of room or by the profile's drop at once ([`Self::live_to_publish`]),
    /// one each whatever the number of those faces. Charged to the transport's drops in
    /// [`Self::transport_stats`], where a link's session charges its own.
    #[cfg(feature = "transport-stats")]
    unsent_drops: AtomicU64,
    /// What the session delivered under the lock, handed out after it: the samples for its
    /// subscribers, in the order they arrived, in the session's delivery lane (`crate::lane`),
    /// and the changes of its matching statuses. Apart, so a matching flip does not take a
    /// sample's room.
    samples: Arc<SharedLane>,
    matching: Arc<Queued<MatchFlips>>,
    /// The callbacks deliveries go to, by the id of the entity that owns them. Kept outside
    /// [`Core`] so a delivery takes no session state, and a callback that undeclares another
    /// entity finds its target gone rather than the lock held.
    targets: Mutex<Vec<(TargetKey, Target)>>,
    /// How many callbacks were taken out of `targets`, counted under its lock: a delivery that found
    /// a subscriber's callback while the count was what it reads now hands that callback the next
    /// sample without looking it up again ([`Resolved`]).
    removed: AtomicU64,
    /// The callbacks kept from one delivery to the next ([`Resolved`]), only ever tried, with no
    /// lock: a delivery that finds them held by another keeps a set of its own for its pass, and a
    /// removal that finds them held leaves them to the delivery that holds them.
    resolved: TryCell<Resolved>,
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
    decl_watches: Arc<DeclWatches>,
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
    /// The takes of the session's locks on a message's paths, which the tests count.
    #[cfg(test)]
    pub(crate) takes: Takes,
    this: Weak<Self>,
}

/// How often the session's lock ([`CoopEngine::live`], and a droppable publish's try of it) and its
/// queue of handed legs were taken, and a subscriber's callback was looked up in the table of
/// them: what a test of the cost of one message counts.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct Takes {
    pub(crate) core: core::sync::atomic::AtomicUsize,
    pub(crate) handed: core::sync::atomic::AtomicUsize,
    pub(crate) callbacks: core::sync::atomic::AtomicUsize,
    /// The turns a droppable publish spun on a held session before it tried the session again.
    pub(crate) spins: core::sync::atomic::AtomicUsize,
    /// The reads whose wait was a wait on the readiness of the session's links and ports, which
    /// the step's read follows.
    pub(crate) polls: core::sync::atomic::AtomicUsize,
    /// The reads whose wait was made in the read of the one link's buffer ([`IdleWait::Read`]).
    pub(crate) owner_reads: core::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl Takes {
    /// Count the wait a read is about to make.
    fn wait(&self, wait: &IdleWait) {
        let counter = match wait {
            IdleWait::Input(..) => &self.polls,
            IdleWait::Read(..) => &self.owner_reads,
            IdleWait::None | IdleWait::Sleep(_) => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
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
        core.keys.guard_by_owner_lock();
        Self(Mutex::new(Confined(core)))
    }

    fn lock(&self) -> CoreGuard<'_, L, C> {
        CoreGuard::taken(self.0.lock())
    }

    fn try_lock(&self) -> Option<CoreGuard<'_, L, C>> {
        self.0.try_lock().map(CoreGuard::taken)
    }

    /// The state with no lock, the engine being let go of: the key arena is marked held for the
    /// rest of the engine's drop, which drops every row that keeps a key.
    fn dropping(&mut self) -> &mut Core<L, C> {
        let core = &mut self.0.get_mut().0;
        core.keys.owner_lock_taken();
        core
    }
}

/// A hold of [`CoreLock`]: the key arena is marked held from its taking to its drop.
struct CoreGuard<'a, L: SessionLinks + 'static, C: ClockSource + 'static> {
    guard: MutexGuard<'a, Confined<Core<L, C>>>,
}

impl<'a, L: SessionLinks + 'static, C: ClockSource + 'static> CoreGuard<'a, L, C> {
    fn taken(guard: MutexGuard<'a, Confined<Core<L, C>>>) -> Self {
        guard.0.keys.owner_lock_taken();
        Self { guard }
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
    fn drop(&mut self) {
        // Before the lock is let go of, which the guard's own drop does after this body.
        self.guard.0.keys.owner_lock_released();
    }
}

/// The waits for room of the session's faces that are up, each with its face, kept outside
/// [`Core`] so that a publish that finds the session held asks them with nothing of it held. Each
/// wait belongs to its link's [`Wire`] or to its group; this holds it weakly, so a face that has
/// gone drops out with it.
#[derive(Default)]
pub(crate) struct LinkRooms(Mutex<Vec<(FaceId, Weak<dyn LinkWritability>)>>);

/// What a droppable publish that found the session held is told of the faces it would be sent
/// to. Each face is a transport of its own, as each of zenoh's is: the publish is dropped on the
/// faces its holder waits on and still sent to the others ([`CoopEngine::live_to_publish`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Room {
    /// Every face asked takes bytes, or the holder is a publish between its sends or a read
    /// working out its wait: whoever holds the session is not waiting on a face, and the session
    /// is tried again.
    Free,
    /// Nothing was asked: what holds the session is not a publish (a read step, a timer, the
    /// drive), which lets go of it once its step is done, and the queue profile drops a message
    /// only behind a send. The publish waits for the session, blocked, as a send's lock that the
    /// holder does not hold would not stop pico's put.
    Stepping,
    /// These faces took no bytes within the wait.
    Congested(Vec<FaceId>),
    /// No face that is up gives a wait to ask.
    Unasked,
    /// Nothing was asked: this face is held by another publish sending on it, and the queue
    /// profile drops a message behind it at once and reports it to the caller, as pico's
    /// try-lock drop does.
    Held(FaceId),
}

/// Where a fan-out begins and whether its sends wait for no slot ([`CoopEngine::fan_out_in`]): a
/// build that listens holds many links over pools of buffers they share, whose blocking publish
/// may wait for a slot and go on where it stopped.
#[cfg(feature = "listen")]
#[derive(Clone, Copy)]
struct Pass {
    /// The order of the first face sent to ([`order_key`]).
    from: u64,
    /// Whether a send that finds no slot of its pool is left unsent and the fan-out stops there.
    probe: bool,
}

/// A fan-out in a build that only dials: to every face, each send as the caller's own.
#[cfg(not(feature = "listen"))]
#[derive(Clone, Copy)]
struct Pass;

/// The pass of a fan-out to every face, each send as the caller's own.
#[cfg(feature = "listen")]
const EVERY_FACE: Pass = Pass {
    from: FIRST_FACE,
    probe: false,
};
/// The pass of a fan-out to every face, each send as the caller's own.
#[cfg(not(feature = "listen"))]
const EVERY_FACE: Pass = Pass;

/// The order of the first of a session's faces ([`order_key`]): a fan-out from it reaches every
/// face.
#[cfg(feature = "listen")]
const FIRST_FACE: u64 = 0;

/// Where a face stands in the order a fan-out sends in, which is the order of the session's faces:
/// the dial role's first, then the others by id, as each takes the next id when it comes
/// (`LinkSupervisor::next_face_id`). A fan-out that stopped at a face goes on from it by this,
/// whatever faces went meanwhile.
#[cfg(feature = "listen")]
fn order_key(face: FaceId) -> u64 {
    if face == DIAL_FACE {
        0
    } else {
        face
    }
}

/// What [`CoopEngine`]'s `sending_on` holds while no publish sends: no face has the id 0, since
/// the session numbers its faces from 1 (`LinkSupervisor::next_face_id`).
const NOT_SENDING: FaceId = 0;

/// What [`CoopEngine`]'s `sending_on` holds while a publish holds the session and sends on no
/// face: before its first send and between two. No face has the id, the session numbering its
/// faces up from 1 one at a time.
const PUBLISHING: FaceId = FaceId::MAX;

/// What [`CoopEngine`]'s `sending_on` holds while a read holds the session to work out its wait
/// (and lend its one link's buffer to it): no face has the id either.
const WAITING: FaceId = FaceId::MAX - 1;

/// Who holds the session, as a droppable publish that finds it held reads it ([`SendingOn`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Holder {
    /// What is not a publish: a read step, a timer, the drive. It lets go once its step is done.
    Step,
    /// A publish, between its sends.
    Publish,
    /// A read working out its wait: it holds no send, and lets go within its take.
    Waiting,
    /// A send on this face, a publish's or what a read step sends of the legs handed to it.
    Sending(FaceId),
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
    was: FaceId,
}

impl<'a> SendingOn<'a> {
    fn enter(mark: &'a AtomicU64, face: FaceId) -> Self {
        let was = mark.swap(face, Ordering::SeqCst);
        Self { mark, was }
    }
}

impl Drop for SendingOn<'_> {
    fn drop(&mut self) {
        self.mark.store(self.was, Ordering::SeqCst);
    }
}

impl LinkRooms {
    /// Hold the wait of `face` while it lives, letting go of the waits of faces that have gone.
    pub(crate) fn hold(&self, face: FaceId, wait: &Arc<dyn LinkWritability>) {
        let mut waits = lock(&self.0);
        waits.retain(|(_, held)| held.strong_count() > 0);
        waits.push((face, Arc::downgrade(wait)));
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

    /// Ask each face that is up for room, within `wait_us` in all: the first face that takes none
    /// spends the wait, and the faces after it are asked without one, so the publish spends one
    /// deadline whatever the number of faces. The waits are taken out of the lock first: a wait
    /// blocks, and a face coming up must not wait behind it.
    pub(crate) fn within(&self, wait_us: u64) -> Room {
        let waits: Vec<(FaceId, Arc<dyn LinkWritability>)> = lock(&self.0)
            .iter()
            .filter_map(|(face, wait)| Some((*face, wait.upgrade()?)))
            .collect();
        if waits.is_empty() {
            return Room::Unasked;
        }
        let mut left_us = wait_us;
        let mut congested = Vec::new();
        for (face, wait) in waits {
            if !wait.wait_writable(left_us) {
                congested.push(face);
                left_us = 0;
            }
        }
        if congested.is_empty() {
            Room::Free
        } else {
            Room::Congested(congested)
        }
    }
}

/// A droppable publish that found the session held, dropped on the faces its holder waits on
/// (`dropped_on`) and owed to the session's other faces: what zenoh's transports, each with a
/// queue of its own, would still take, where this engine has one lock for every face (D8). Owned,
/// since its caller has returned by the time it is sent ([`CoopEngine::send_handed`]).
struct HandedLeg {
    keyexpr: String,
    wire: WireKey,
    payload: Vec<u8>,
    /// The options without the attachment they borrowed, which the leg keeps beside them.
    opts: PublishOptions<'static>,
    attachment: Option<Vec<u8>>,
    dropped_on: Vec<FaceId>,
}

/// One publish as its leg to the links sends it ([`CoopEngine::fan_out`]).
struct Publication<'a> {
    keyexpr: &'a str,
    wire: &'a WireKey,
    payload: &'a [u8],
    opts: &'a PublishOptions<'a>,
    meta: &'a PushMetadata<'a>,
}

/// What a publish's leg to the links finds of the session ([`CoopEngine::live_to_publish`]).
enum ToPublish<'a, L: SessionLinks + 'static, C: ClockSource + 'static> {
    /// The session, held for the publish.
    Live(LiveCore<'a, L, C>),
    /// The session is closed.
    Closed,
    /// The publish may be dropped, and found the session held by a send that waits on `faces`:
    /// it is dropped on them, and the caller is told when `told` (the pico profile).
    DroppedOn { faces: Vec<FaceId>, told: bool },
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

/// The key expressions the session declared, one table for all its links (`Core::keyexprs`).
type KeyexprRows = Rows<KexprEntry, { caps::MAX_DECLARED_KEYEXPRS }>;

/// The session's own id space, read from its one table of declared key expressions: what a link
/// sends names a key by the id the session gave it, and what a peer sends for the session may
/// name one too (a router does for a subscriber it routes to). Every link is told the same
/// declarations under the same ids, so each link and the tables of each face hold this handle
/// and none keeps a copy: a declaration grows nothing on a link. The table is held weakly: the
/// session owns it and drops it before the arena its keys lie in, and a handle left after that
/// reads nothing.
struct SessionKeyexprs(alloc::rc::Weak<RefCell<KeyexprRows>>);

impl OwnMappingSpace for SessionKeyexprs {
    fn resolve_own_mapping(&self, id: ExprId) -> Option<String> {
        let table = self.0.upgrade()?;
        let rows = table.borrow();
        rows.iter()
            .find(|row| row.id == id)
            .map(|row| String::from(row.keyexpr.as_str()))
    }

    // The literal goes from the session's row straight into the resolver's buffer: the provided
    // form would make a `String` of it first, an allocation for every message that names an id
    // of this session's.
    fn append_own_mapping(
        &self,
        id: ExprId,
        out: &mut wz_session_core::wireexpr_resolve::KeyexprBuf,
    ) -> Option<Result<(), wz_session_core::bounded::CapacityFull<()>>> {
        let table = self.0.upgrade()?;
        let rows = table.borrow();
        rows.iter()
            .find(|row| row.id == id)
            .map(|row| out.push_str(row.keyexpr.as_str()))
    }
}

// SAFETY: as `Confined`. A `SessionKeyexprs` is stored only in the tables of a face and in the
// actions of a link, which `Core` owns inside the lock of `CoopEngine`, and it is read only by
// the dispatch of a face's frames and by a link's sends, which run under the same lock; no clone
// of its `Weak` leaves the lock. The marker traits are what the shared handle of a host build
// names (`SharedOwnMappingSpace` is an `Arc` of a `Send + Sync` object where the target has
// atomic pointers).
unsafe impl Send for SessionKeyexprs {}
unsafe impl Sync for SessionKeyexprs {}

/// What a subscriber's sink mints: the callback a sample is handed to.
type SubscriberCallbackFn = Box<dyn FnMut(&dyn SampleView) + Send + 'static>;

/// A subscriber's callback, as the ABI's sink minted it: locked while it runs, so a delivery from
/// the read task and one from the program's own `zp_read` never overlap, and retired when its
/// subscriber is undeclared or its session closed, so a delivery that copied it out of the
/// subscriber's row before hands it nothing more.
pub(crate) struct LiveCallback {
    live: AtomicBool,
    call: Mutex<SubscriberCallbackFn>,
}

impl LiveCallback {
    pub(crate) fn new(call: SubscriberCallbackFn) -> Self {
        Self {
            live: AtomicBool::new(true),
            call: Mutex::new(call),
        }
    }

    /// Hand `sample` to the callback, unless it was retired.
    pub(crate) fn hand(&self, sample: &dyn SampleView) {
        if self.live.load(Ordering::Acquire) {
            (lock(&self.call))(sample);
        }
    }

    /// Hand nothing more: its subscriber is gone.
    fn retire(&self) {
        self.live.store(false, Ordering::Release);
    }
}

/// A subscriber's callback, shared by its row, the table of callbacks and the deliveries that
/// copied it out of the row.
pub(crate) type SubscriberCallback = Arc<LiveCallback>;

/// How many subscribers of one sample a delivery keeps the callbacks of ([`Resolved`]): a sample
/// for more is handed to the ones past these by a look in the table each.
const RESOLVED_SUBSCRIBERS: usize = 4;

/// The callbacks the deliveries found for the subscribers of the sample handed last, by their
/// place in the sample's list, and the count of removals from the table of callbacks they were
/// found at ([`CoopEngine::removed`]). The next sample, in this delivery or the next step's, is
/// almost always for the same subscribers: it is handed the same callbacks with no lock of the
/// table, no search of it and no count taken on the callback, while nothing has been taken out of
/// the table since. What was kept from before a removal is let go of by the removal, or, when a
/// delivery holds the set then, by that delivery as it ends.
struct Resolved {
    removed: u64,
    callbacks: [Option<(SubId, SubscriberCallback)>; RESOLVED_SUBSCRIBERS],
}

impl Resolved {
    fn new() -> Self {
        Self {
            removed: 0,
            callbacks: [const { None }; RESOLVED_SUBSCRIBERS],
        }
    }

    /// What this kept from before the removals counted up to `removed`, taken out for the caller
    /// to let go of with no lock held; nothing when it kept nothing older.
    fn take_stale(
        &mut self,
        removed: u64,
    ) -> [Option<(SubId, SubscriberCallback)>; RESOLVED_SUBSCRIBERS] {
        if self.removed == removed {
            return [const { None }; RESOLVED_SUBSCRIBERS];
        }
        self.removed = removed;
        core::mem::replace(&mut self.callbacks, [const { None }; RESOLVED_SUBSCRIBERS])
    }
}

/// A value one holder at a time reaches, taken by a compare-exchange and never waited for: a
/// holder that finds it taken goes without, as `Mutex::try_lock` would have it go, with no lock of
/// the kernel taken or given. What the deliveries keep across samples ([`Resolved`]) is held so.
struct TryCell<T> {
    taken: portable_atomic::AtomicBool,
    value: core::cell::UnsafeCell<T>,
}

// SAFETY: the value is reached by the one holder of `taken` alone, from the exchange that took it
// (acquire) to the store that gives it back (release), so each holder sees what the one before
// it left, and the value moves between threads only as a `Send` value does.
unsafe impl<T: Send> Sync for TryCell<T> {}

impl<T> TryCell<T> {
    fn new(value: T) -> Self {
        Self {
            taken: portable_atomic::AtomicBool::new(false),
            value: core::cell::UnsafeCell::new(value),
        }
    }

    /// The value, held until the guard drops; `None` while another holds it.
    fn try_take(&self) -> Option<TryHeld<'_, T>> {
        self.taken
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| TryHeld { cell: self })
    }
}

/// A [`TryCell`]'s value, held.
struct TryHeld<'a, T> {
    cell: &'a TryCell<T>,
}

impl<T> Deref for TryHeld<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: this guard holds the cell (`TryCell::try_take`).
        unsafe { &*self.cell.value.get() }
    }
}

impl<T> DerefMut for TryHeld<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as `deref`.
        unsafe { &mut *self.cell.value.get() }
    }
}

impl<T> Drop for TryHeld<'_, T> {
    fn drop(&mut self) {
        self.cell.taken.store(false, Ordering::Release);
    }
}

/// A queryable's callback, locked while it runs as a subscriber's is.
#[cfg(feature = "queryable")]
type QueryableCallback = Arc<Mutex<QueryCallback>>;

/// The session's state, held: what [`CoopEngine::live`] hands a caller that may act on it. As it
/// lets go, the sample the delivery lane holds open for more subscribers is published and what the
/// lane published is handed on to the deliveries (`SharedLane`), so nothing the session wrote
/// under its lock waits for another hold to be handed out.
struct LiveCore<'a, L: SessionLinks + 'static, C: ClockSource + 'static> {
    core: CoreGuard<'a, L, C>,
    lane: &'a SharedLane,
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
    fn drop(&mut self) {
        // SAFETY: the session's lock is held: `core` is let go after this body.
        unsafe { self.lane.held() }.seal_all();
    }
}

/// Where a delivery goes. Each kind is a shared handle, cloned out of the table so a delivery runs
/// it with the table's lock let go (`CoopEngine::target`).
#[derive(Clone)]
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

/// What the read task's thread runs, handed to whatever makes the thread.
pub(crate) type ReaderBody = Box<dyn FnOnce() + Send + 'static>;

/// A table of the session's own declarations: rows lent from the session's arena at its open, as
/// many as the limit the open resolved, `N` the build's ceiling. A declaration that finds it full
/// is refused before anything is taken, registered or sent.
type Rows<T, const N: usize> = BoundedVec<T, N, Lent>;

/// The bytes of one row of each table the engine keeps of the session's own declarations, as the
/// session's arena lays them out (`crate::arena::ArenaPlan`).
pub(crate) struct EntryBytes;

impl EntryBytes {
    /// A queryable's row.
    #[cfg(feature = "queryable")]
    pub(crate) const QUERYABLE: usize = core::mem::size_of::<QblEntry>();
    /// A liveliness token's row.
    #[cfg(feature = "liveliness")]
    pub(crate) const TOKEN: usize = core::mem::size_of::<TokenEntry>();
    /// A liveliness subscriber's row.
    #[cfg(feature = "liveliness")]
    pub(crate) const LIVELINESS_SUBSCRIBER: usize = core::mem::size_of::<LiveSubEntry>();
    /// A declared key expression's row.
    pub(crate) const KEYEXPR: usize = core::mem::size_of::<KexprEntry>();
    /// A write filter's row.
    pub(crate) const FILTER: usize = core::mem::size_of::<FilterEntry>();
    /// A matching listener's row.
    pub(crate) const MATCH: usize = core::mem::size_of::<MatchEntry>();
    /// An Interest's row.
    pub(crate) const INTEREST: usize = core::mem::size_of::<InterestHold>();
}

/// Keep `row` in `table`, whose room its declaration found free under the lock it still holds,
/// before it took an id or sent anything.
fn keep<T, const N: usize>(table: &mut Rows<T, N>, row: T) {
    let kept = table.push(row).is_ok();
    debug_assert!(kept, "the table had the row its declaration found free");
}

/// A key as a row of the session's own declarations keeps it: a block of the session's key arena
/// (`KEY_ARENA_BYTES`) as long as the key, which the row holds by its place, and which is given
/// back when the row goes.
pub(super) type RowKey = KeyRef;

/// The write filters' table, sized by the build: a publisher's and a querier's each.
type FilterRows = Rows<FilterEntry, { caps::MAX_PUBLISHERS + caps::MAX_QUERIERS }>;

/// The Interests' table, sized by the build: one for each write filter and matching listener at
/// most.
type InterestRows = Rows<
    InterestHold,
    { caps::MAX_PUBLISHERS + caps::MAX_QUERIERS + caps::MAX_MATCHING_LISTENERS },
>;

struct Core<L: SessionLinks + 'static, C: ClockSource + 'static> {
    /// The session's tasks, and the runtime their cells and timers lie in, which the set holds.
    local: CoopLocalSet<C>,
    clock: C,
    /// What the application holds and what the peer declared. It is the session's, so it
    /// outlives each link: a new link is dispatched to the same registry.
    registry: Rc<RefCell<Registry>>,
    /// Whether the links' pool of outbound slots is smaller than the links (`TX_POOL_SLOTS`), so
    /// that a link may find every slot held by another link's frame its stream has not finished:
    /// a publish that may not be dropped then waits for a slot with nothing of the session held
    /// ([`CoopEngine::publish_to_link`]).
    #[cfg(feature = "listen")]
    tx_pool_short: bool,
    /// Where each link that comes up leaves its wait for room, for the publishes that find the
    /// session held ([`CoopEngine::live_to_publish`]).
    rooms: Arc<LinkRooms>,
    /// Where a face coming up or going down is reported (`connectivity`).
    #[cfg(feature = "connectivity")]
    watchers: Arc<FacePlane>,
    /// The session's faces, the dial role's first, which is never removed, then the others in the
    /// order they came, over the network their links are opened on: the faces' links, the dials
    /// under way, the ports listened on and a read's waits are the driver's
    /// (`wz_runtime_coop::faces`). What is declared is declared over each face, and a get is
    /// asked of each.
    links: LinkSupervisor<L, Face<C, L>>,
    /// The texts of the endpoints the session dials and listens on, written once when it opened
    /// into rows of its arena: a dial and a port name their endpoint by its row, and the config's
    /// copies went with the open.
    endpoints: EndpointTexts,
    /// The multicast groups the session joined, each a face of its own (`group`).
    #[cfg(feature = "group")]
    groups: Vec<GroupFace>,
    /// Each handshake's cookie key and nonce come from here.
    entropy: SharedEntropy,
    /// The config the session opened with, which counts its endpoints: their texts are the
    /// session's rows (`endpoints`).
    config: CoopConfig<Counted>,
    /// The policies the session runs under, as its open was handed them: every link's session
    /// is given them, and the replay and the admission of a second link follow them.
    policy: SessionPolicy,
    /// The zid in its wire form, which every handshake of the session announces.
    wire_zid: SessionZid,
    /// The session's say on a link to a node it holds a link to, asked while the link's handshake
    /// runs (`install_link_admission`, `listen`).
    #[cfg(feature = "listen")]
    admission: Arc<dyn LinkAdmission>,
    /// How many rows each table of the session's own declarations was lent: what a write filter
    /// of each plane is held to, the filters sharing one table.
    entities: EntityRows,
    /// The key arena the rows of those tables keep their keys in, lent from `arena` with them.
    keys: KeySpace,
    /// The key expressions the session declared: shared only with the weak handles its links and
    /// the tables of its faces read them through (`SessionKeyexprs`), so it is dropped here, before
    /// the arena its keys lie in.
    keyexprs: Rc<RefCell<KeyexprRows>>,
    /// The session's id space as its links and its faces' tables read it, a weak handle on
    /// `keyexprs`: one for the session, which each link it makes is handed a clone of.
    own_space: SharedOwnMappingSpace,
    /// The cells each link's gates are placed in when the session makes the link (`LinkGate`),
    /// lent from the arena; none for a plan that laid out none.
    gate_cells: Option<LentByteCells>,
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
    filters: FilterRows,
    next_filter: FilterId,
    interests: InterestRows,
    /// How often a read's wait and its step read the session's clock ([`Self::now_us`]), which the
    /// tests count.
    #[cfg(test)]
    clock_reads: core::cell::Cell<usize>,
    matches: Rows<MatchEntry, { caps::MAX_MATCHING_LISTENERS }>,
    next_match: MatchId,
    #[cfg(feature = "queryable")]
    queryables: Rows<QblEntry, { caps::MAX_QUERYABLES }>,
    #[cfg(feature = "queryable")]
    plane: Arc<QueryPlane>,
    /// The legs of the session's gets still pending on its link.
    #[cfg(feature = "query")]
    pending_gets: Vec<PendingGet>,
    #[cfg(feature = "query")]
    gets: Arc<GetPlane>,
    /// The tokens the session holds, and its liveliness subscribers (`liveliness`).
    #[cfg(feature = "liveliness")]
    tokens: Rows<TokenEntry, { caps::MAX_LOCAL_TOKENS }>,
    #[cfg(feature = "liveliness")]
    live_subs: Rows<LiveSubEntry, { caps::MAX_LIVELINESS_SUBSCRIPTIONS }>,
    /// The periodic jobs the program started on the session ([`SessionEngine::start_ticker`]).
    #[cfg(feature = "ticker")]
    tickers: Tickers,
    /// The session's delivery lane, which every link's gate asks before it reads a batch
    /// (`crate::lane::LaneGate`).
    lane: Arc<SharedLane>,
    /// The one reassembly Router of the session, which its links share: its chains are keyed by
    /// their peers, and staged in the session's buffers for them, each claimed by a chain while it
    /// is open, lent from the arena (`ArenaPlan::reassembly`). The session sweeps it and ends a
    /// lost peer's chains; its links' receives reach it only while [`Core::run_tasks`] lends it.
    router: SessionReassembly,
    /// Where the session lends its Router to its links' receives, each link's task holding the
    /// place: lent for the length of a pass of the tasks and at no other time.
    lend: RouterLend<SessionReassembly>,
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

/// One face of the session: the link it holds, and where the telling of the session's
/// declarations to that link's peer stands (`replay`).
struct Face<C: ClockSource + 'static, L: SessionLinks> {
    id: FaceId,
    link: Link<LinkSession<C>, L::Dial>,
    replay: Replay,
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
    actions: Rc<McuActions<C>>,
    /// Opened when the face is brought up (`bring_up`); until then the link gives the session
    /// nothing past its handshake, so the watchers hear the face come up before anything its link
    /// carried.
    #[cfg(feature = "listen")]
    admitted: Admitted,
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
    fn node(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "listen")]
        {
            self.actions
                .peer_zid()
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
}

/// One link of the session: its session half ([`LinkSession`]) and what the driver holds of it.
type Wire<C> = wz_runtime_coop::faces::Wire<LinkSession<C>>;

/// Sleep `ms` milliseconds: what a read's wait with nothing to wait on does
/// ([`IdleWait::wait`]).
fn sleep_ms(ms: u32) {
    os::sleep_ms(ms.into());
}

/// One of the session's own subscribers, as a row of the session core's subscriber table holds
/// it: the row keeps the pattern the subscriber matches, and this, its sink, everything else the
/// session knows of it. The subscriber is that one row (`docs/c-abi-architecture.md`, P1).
pub(crate) struct SubscriberRow {
    id: SubId,
    retraction: Option<RetractionKey>,
    /// The key the declaration names, kept to declare it again over a new link; holding it also
    /// keeps alive what it holds, so a row is let go of with no lock of the session held.
    wire: WireKey,
    /// Where a sample the row matches is offered, under the subscriber's id.
    lane: Arc<SharedLane>,
    /// The callback the samples the row matches are handed to, copied out of the row with each
    /// of them. Set once the row is registered, so a refused registration mints none.
    callback: Option<SubscriberCallback>,
}

impl SubscriberRow {
    /// Declare this subscriber, which matches `keyexpr`, over `actions`: whether the link took
    /// it.
    fn declare<C: ClockSource + 'static>(&self, keyexpr: &str, actions: &McuActions<C>) -> bool {
        let wire = on_link(actions, keyexpr, &self.wire);
        if wire.is_literal() {
            actions.send_declare_subscriber(self.id, 0, Some(keyexpr))
        } else {
            actions.send_declare_subscriber(self.id, wire.mapping_id, wire.suffix.as_deref())
        }
        .is_ok()
    }

    /// Retract this subscriber over `actions`, naming its key when its declaration asked to.
    fn retract<C: ClockSource + 'static>(&self, actions: &McuActions<C>) {
        match &self.retraction {
            Some(key) => actions.send_undeclare_subscriber_naming(
                u64::from(self.id),
                key.mapping_id,
                &key.suffix,
            ),
            None => actions.send_undeclare_subscriber(u64::from(self.id)),
        }
    }
}

impl SampleSink for SubscriberRow {
    fn deliver(&mut self, sample: &dyn SampleView) {
        // SAFETY: the session core's table hands its sinks a sample under the session's lock: it
        // is the registry's, which only `Core` holds.
        unsafe { self.lane.offer_to(self.id, self.callback.as_ref(), sample) }
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
    keyexpr: RowKey,
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
    keyexpr: RowKey,
    holds: usize,
}

struct FilterEntry {
    id: FilterId,
    plane: FilterPlane,
    keyexpr: RowKey,
    asked: bool,
    /// Whether the session's own entities count toward the filter (`local-subscriber`).
    count_local: bool,
    /// What the peers' declarations answered for the filter, with the registry's count of writes
    /// it was read at (`Registry::faces_written`): kept for the puts after it until a face's
    /// tables are written, as zenoh-pico's filter keeps its state between the declarations that
    /// move it (`vendor/zenoh-pico/include/zenoh-pico/net/filtering.h` @
    /// `return ctx->state == WRITE_FILTER_ACTIVE;`).
    peers: Cell<Option<(u64, bool)>>,
    /// How a write of the filter's entity that brings nothing of its own goes the plain way: the
    /// facts it is sent from and the declaration that names its key, stated once by the entity
    /// that declared the filter (`keep_write_filter_plain`). `None` sends it the general way.
    plain: Cell<Option<(PlainPutParams, ExprId)>>,
}

/// One Interest the session holds open, and how many hold it.
struct InterestHold {
    plane: FilterPlane,
    keyexpr: RowKey,
    interest_id: u64,
    /// How the Interest names its key. The rest of the key it names is no copy of its own when it
    /// is a tail of `keyexpr` (`suffix_at`), which it is for every form the ABI asks with.
    form: InterestForm,
    /// Where in `keyexpr` the rest of the key the form names begins: the whole key for a form that
    /// names no declaration, what follows the declared prefix for one that does. `None` when the
    /// form keeps a rest of its own, or names none.
    suffix_at: Option<usize>,
    holds: usize,
}

impl InterestHold {
    /// The rest of the key the form names.
    fn suffix(&self) -> Option<&str> {
        match self.suffix_at {
            Some(at) => self.keyexpr.get(at..),
            None => self.form.suffix.as_deref(),
        }
    }

    /// Send this Interest over `actions`, for what is declared now and what is declared later,
    /// naming its key as the link's key-wire form says: whether the link took it.
    fn send<C: ClockSource + 'static>(&self, actions: &McuActions<C>) -> bool {
        let linked = interest_on_link(actions, &self.keyexpr, &self.form);
        let (aggregate, mapping_id, suffix) = match &linked {
            Cow::Borrowed(form) => (form.aggregate, form.mapping_id, self.suffix()),
            Cow::Owned(form) => (form.aggregate, form.mapping_id, form.suffix.as_deref()),
        };
        actions
            .send_interest_kinds(
                self.interest_id,
                kinds(self.plane),
                /* current */ true,
                /* future */ true,
                aggregate,
                mapping_id,
                suffix,
            )
            .is_ok()
    }
}

/// Where in `keyexpr` a form's rest of the key, `suffix`, begins, when it is a tail of it.
fn suffix_place(keyexpr: &str, suffix: Option<&str>) -> Option<usize> {
    let suffix = suffix?;
    let at = keyexpr.len().checked_sub(suffix.len())?;
    keyexpr.ends_with(suffix).then_some(at)
}

struct MatchEntry {
    id: MatchId,
    /// What the listener counts, as a write filter names it: which registry `watch` is in.
    plane: FilterPlane,
    watch: u64,
    keyexpr: RowKey,
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

/// The engine's mutex, held until the guard drops; one poisoned by a panic is recovered, since
/// every critical section here leaves its value consistent ([`os::Mutex::lock`]).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock()
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

/// What a matching listener watches: the criterion of the plane it counts, made only for a plane
/// the build holds ([`counts`]). A listener on any other plane is refused where this is made,
/// before anything is taken, so the registry is never handed a plane it has no table for.
enum Watched {
    Publishers(PublisherCriterion),
    #[cfg(any(feature = "query", feature = "queryable"))]
    Queriers(QuerierCriterion),
}

impl Watched {
    /// The criterion a listener on `plane` over `keyexpr` counts with, the session's own
    /// entities among it with `count_local` as its write filter's are (`counted`); `None` for a
    /// plane this build does not hold.
    fn of(plane: FilterPlane, keyexpr: &str, count_local: bool) -> Option<Self> {
        let locality = counted(plane, count_local);
        match plane {
            FilterPlane::Subscribers => {
                Some(Self::Publishers(PublisherCriterion::new(keyexpr, locality)))
            }
            #[cfg(any(feature = "query", feature = "queryable"))]
            FilterPlane::Queryables { complete_required } => Some(Self::Queriers(
                QuerierCriterion::new(keyexpr, locality, complete_required),
            )),
            #[cfg(not(any(feature = "query", feature = "queryable")))]
            FilterPlane::Queryables { .. } => None,
        }
    }
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

/// The lane told, while a link's record is dispatched, that what is offered waited for room
/// ([`SharedLane::offering_gated`]), and told otherwise again when the dispatch is done, or
/// unwinds. Only a debug build checks the gate's bound by it; it is told without the lane's lock,
/// so a debug build's dispatch takes the lock as often as a release build's.
#[cfg(debug_assertions)]
struct Gated<'a>(&'a SharedLane);

#[cfg(debug_assertions)]
impl<'a> Gated<'a> {
    fn over(lane: &'a SharedLane) -> Self {
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

/// A subscriber's `callback`, shown each sample's timestamp when `expose` and none otherwise
/// (`entity-timestamp-opt-in`): the one place a sample is handed to a subscriber's callback.
fn sample_shown(expose: bool, mut callback: SubscriberCallbackFn) -> SubscriberCallbackFn {
    if expose {
        return callback;
    }
    Box::new(move |sample: &dyn SampleView| callback(&HiddenTimestamp(sample)))
}

/// A get's leg `callback`, shown each reply's timestamp when `expose` and none otherwise
/// (`entity-timestamp-opt-in`): the one place a reply is handed to a get's callback.
#[cfg(feature = "query")]
fn reply_shown(expose: bool, mut callback: ReplyCallback) -> ReplyCallback {
    if expose {
        return callback;
    }
    Box::new(move |reply: &dyn ReplyView| callback(&HiddenReplyTimestamp(reply)))
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
    face: FaceId,
    actions: Rc<McuActions<C>>,
    #[cfg(feature = "queryable")]
    plane: Arc<QueryPlane>,
    /// The link's generation, which the queries it carries are answered under.
    #[cfg(feature = "queryable")]
    generation: u64,
    /// What a debug build tells, while a record is dispatched, that what is offered waited for
    /// room (`Gated`).
    #[cfg(debug_assertions)]
    lane: Arc<SharedLane>,
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
            self.plane
                .arriving
                .store(self.generation, Ordering::Release);
            // A query by an id of the shared dictionary is kept, so its replies mirror its key
            // form.
            #[cfg(feature = "shared-key-ids")]
            actions.note_requests(&event);
            registry.dispatch_event(face, event);
            #[cfg(any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ))]
            registry.settle_decl_events(|| actions.peer_zid());
            registry.flush_pending_replies(face, actions);
            registry.take_pending_final_rids(face)
        };
        for (rid, qos) in owed {
            if lock(&self.plane.holds).owe(self.generation, rid, qos) {
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
        registry.dispatch(face, event, actions);
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        registry.settle_decl_events(|| actions.peer_zid());
    }
}

/// The gates a link's pump runs behind on this engine, for a session on the clock `C`, which the
/// session places in the link's cell of its table (`Core::gate_cells`): the delivery lane's, and
/// with `listen` the admission's under it, which carries the clock.
trait LinkGates {
    /// The gates.
    type Gate;
}

impl<C: ClockSource + 'static> LinkGates for C {
    #[cfg(feature = "listen")]
    type Gate = LaneGate<AdmissionGate<CellRc<dyn SessionDatagramLink>, C>>;
    #[cfg(not(feature = "listen"))]
    type Gate = LaneGate<CellRc<dyn SessionDatagramLink>>;
}

/// The gates of a link of a session on the clock `C` ([`LinkGates`]).
type LinkGate<C> = <C as LinkGates>::Gate;

/// The arena a session over `links` opens `config` with: the rows its limits size, a cell for
/// each link's driver as large as the largest the links open, and a cell for each link's gates.
/// The one plan an open reserves by.
pub(crate) fn arena_plan<C: ClockSource + 'static, E: EndpointList>(
    links: &impl SessionLinks,
    config: &CoopConfig<E>,
) -> Result<ArenaPlan, ArenaRefused> {
    ArenaPlan::of(config, &resolve_limits(config)).and_then(|plan| {
        plan.holding_cells(links.link_cell_bytes(), CellRc::<LinkGate<C>>::cell_bytes())
    })
}

/// The session's id space over `keyexprs`, as its links and its faces' tables read it: a weak
/// handle, so the table goes with the session whatever holds the space.
fn session_space(keyexprs: &Rc<RefCell<KeyexprRows>>) -> SharedOwnMappingSpace {
    let space = SessionKeyexprs(Rc::downgrade(keyexprs));
    #[cfg(target_has_atomic = "ptr")]
    {
        Arc::new(space)
    }
    #[cfg(not(target_has_atomic = "ptr"))]
    {
        Rc::new(space)
    }
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
            .min(caps::MAX_TASKS - groups);
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

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> Core<L, C> {
    /// `keyexpr` as a row keeps it, in the session's key arena; `None` past the session's
    /// `MAX_KEYEXPR_BYTES` the arena was lent with, or when the key arena has no room for it: a
    /// key the session cannot hold is refused, never cut short, and the declaration with it,
    /// before an id is taken or anything is sent. A text the arena keeps already, whoever holds it
    /// (a row of the session's record, a table of the registry, an object of the program), is that
    /// block shared ([`KeySpace::kept`]), so a key the session's declarations and the program's
    /// objects name alike takes one block, whichever of them came first.
    fn row_key(&self, keyexpr: &str) -> Option<RowKey> {
        if !self.keys.holds_key(keyexpr.len()) {
            return None;
        }
        self.keys
            .kept(keyexpr)
            .or_else(|| self.keys.key(keyexpr).ok())
    }

    /// Why [`Self::row_key`] refused `keyexpr`: longer than a row holds, or no room for it left in
    /// the key arena.
    fn key_refusal(&self, keyexpr: &str) -> Declined {
        if self.keys.holds_key(keyexpr.len()) {
            Declined::TableFull
        } else {
            Declined::KeyTooLong
        }
    }

    /// The dial role's face, which the session holds for its whole life.
    fn dial(&self) -> &Face<C, L> {
        &self.links.faces()[0]
    }

    /// The actions of every face whose link is up, which is what the session sends through. A
    /// face whose link is dialled or waits to be is not among them: what is declared then is
    /// declared when it comes up.
    fn ups(&self) -> impl Iterator<Item = &Rc<McuActions<C>>> {
        self.links
            .faces()
            .iter()
            .filter_map(|face| match &face.link {
                Link::Up(wire) => Some(&wire.actions),
                _ => None,
            })
    }

    /// [`Self::ups`], each with the id of its face.
    fn ups_by_id(&self) -> impl Iterator<Item = (FaceId, &Rc<McuActions<C>>)> {
        self.links
            .faces()
            .iter()
            .filter_map(|face| match &face.link {
                Link::Up(wire) => Some((face.id, &wire.actions)),
                _ => None,
            })
    }

    /// The faces whose links are up, which is what a get is asked of.
    #[cfg(feature = "query")]
    fn up_faces(&self) -> Vec<FaceId> {
        self.links
            .faces()
            .iter()
            .filter(|face| matches!(face.link, Link::Up(_)))
            .map(|face| face.id)
            .collect()
    }

    /// The actions of face `id` while its link is up.
    #[cfg(feature = "query")]
    fn up_actions(&self, id: FaceId) -> Option<&Rc<McuActions<C>>> {
        self.links.faces().iter().find_map(|face| match &face.link {
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
        self.links.faces().iter().find_map(|face| match &face.link {
            Link::Up(wire) if wire.generation == generation => {
                Some(&*wire.actions as &dyn ResponseSink)
            }
            _ => None,
        })
    }

    /// Write on its group what the answers to a query that came in under `generation` put on the
    /// group's stage, on this thread, as a put on the group is written by the thread that puts it.
    /// Nothing is done for a query that came in on a link.
    #[cfg(all(feature = "queryable", feature = "group"))]
    fn write_answers(&self, generation: u64) {
        if let Some(group) = self
            .groups
            .iter()
            .find(|group| group.answers_as(generation))
        {
            group.write_staged();
        }
    }

    /// Begin face `face`'s dial of `endpoint`, which the network answers later
    /// (`SessionLinks::begin_initiator`). [`OpenError::Unreachable`] when the endpoint does not
    /// parse or the network refuses the dial at once.
    fn begin_dial(&self, face: FaceId, endpoint: &str) -> Result<L::Dial, OpenError> {
        let to = parse_locator(endpoint).map_err(|refused| {
            OpenError::Unreachable(EndpointRefusal::new(endpoint, Refusal::Locator(refused)))
        })?;
        // The face's last link holds its buffers in the session's arena until the last thing that
        // holds the link lets it go, and that is the id space the face's tables keep until a link
        // replaces it: let go of here, so the dial begun next finds the buffers the last one held.
        self.registry.borrow_mut().forget_own_mapping_space(face);
        self.links.begin_dial(to).map_err(|refused| {
            OpenError::Unreachable(EndpointRefusal::new(endpoint, Refusal::Link(refused)))
        })
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
            cookie: Default::default(),
            tx_queue: self.config.tx_queue,
            link_rx: self.config.link_rx,
            policy: self.policy,
            // The snapshot the registry's tables were held to: the open decides it from the
            // config alone.
            limits: resolve_limits(&self.config),
            cookie_signing_key: SigningKey::from_entropy(&mut self.entropy)
                .map_err(|_| OpenError::EntropyUnavailable)?,
        };
        let actions = McuActions::<C>::new_generic(sink, params, self.session_time.clone());
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
        // The session's id space, read from its one table of declarations by the link (what it
        // sends names a key by its id) and by the tables of the face it serves (what the peer
        // sends may name one): installed whenever a link is made, a redialled face's included.
        #[cfg(target_has_atomic = "ptr")]
        actions.install_session_keyexprs(Arc::clone(&self.own_space));
        self.registry
            .borrow_mut()
            .install_own_mapping_space(face, self.own_space.clone());
        // The answer the face's session gives a query of its peer whose key it cannot resolve:
        // the session's policy, stated for each link the face is opened over.
        self.registry
            .borrow_mut()
            .set_unanswerable_final(face, actions.params.policy.query_unanswerable_final());
        // The key ids every node shares, on both sides of the link before it carries anything:
        // the link's actions, with the key-wire form stated for the endpoint it was dialled to or
        // taken on, so what is sent over it names its keys in that form, and the face's tables,
        // so an id of the dictionary the peer sends is read.
        #[cfg(feature = "shared-key-ids")]
        {
            actions.install_link_keys(wz_session_core::shared_key_ids::LinkKeys::new(
                self.key_ids.clone(),
                self.key_forms
                    .form_of(endpoint.map(|endpoint| endpoint.text(&self.endpoints))),
                resolve_limits(&self.config).link_noted_requests(),
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
        // One handle to the link, which its gates and a read's wait, lent its buffer, share: a
        // stack whose pump is a shared handle already gives that one (`SessionLinks::share_pump`).
        let pump = L::share_pump(pump);
        let ungated = pump.clone();
        // The link gives the session nothing between its handshake and the face table's decision
        // (`admit`), so a link that is refused has put nothing in the tables.
        #[cfg(feature = "listen")]
        let admitted = Admitted::default();
        // The session is handed a record of a link only while its delivery lane has the room one
        // record can take (decision Q4), and with `listen` only once the engine admitted it.
        let room = crate::lane::read_room::<
            { caps::PICO_FRAG_MAX_BYTES },
            { caps::MAX_KEYEXPR_BYTES },
            { caps::MAX_SUBSCRIPTIONS },
            { caps::MAX_LIVELINESS_SUBSCRIPTIONS },
        >(
            usize::from(self.config.batch_size),
            &resolve_limits(&self.config),
        );
        #[cfg(feature = "listen")]
        // SAFETY: a link is made under the session's lock, and its gate asked by the step alone.
        let gate: LinkGate<C> = unsafe {
            LaneGate::new(
                AdmissionGate::new(pump, actions.clone(), admitted.clone()),
                self.lane.clone(),
                room,
            )
        };
        #[cfg(not(feature = "listen"))]
        // SAFETY: a link is made under the session's lock, and its gate asked by the step alone.
        let gate: LinkGate<C> = unsafe { LaneGate::new(pump, self.lane.clone(), room) };
        // The gates go in the link's cell of the session's table, as the link's driver goes in
        // one of the stack's: a link past the cells is refused as one past the buffers is.
        let link = match &self.gate_cells {
            Some(cells) => CellRc::place(cells, gate).map_err(|_| {
                OpenError::Unreachable(EndpointRefusal::new(
                    self.endpoint_text(endpoint),
                    Refusal::Link(LinkOpenError::Exhausted),
                ))
            })?,
            None => CellRc::boxed(gate),
        }
        .into_link();
        #[cfg(feature = "queryable")]
        let generation = self.plane.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let dispatch = FaceDispatch {
            registry: self.registry.clone(),
            face,
            actions: actions.clone(),
            #[cfg(feature = "queryable")]
            plane: self.plane.clone(),
            #[cfg(feature = "queryable")]
            generation,
            #[cfg(debug_assertions)]
            lane: self.lane.clone(),
        };
        // The link's fragmented messages are staged by the session's one Router, which its links
        // share, keyed by their peers, in buffers of the session's one table: a chain claims one
        // when its first fragment arrives and gives it back when it ends, and a chain that finds
        // none free is refused and counted. The link's task holds the place it is lent in.
        let spawned = spawn_session_with_router(
            &self.local,
            link.clone(),
            actions.clone(),
            self.session_time.clone(),
            SessionDriveConfig {
                timeouts: self.config.timeouts,
                role,
                max_iters: None,
            },
            self.lend.clone(),
            dispatch,
        );
        // The runtime's cells were reserved at the open, one for each link the config admits: a
        // link past them has no task to run its session, and what it installed in the face's
        // tables goes with it.
        let task = match spawned {
            Ok(task) => task,
            Err(why) => {
                self.registry.borrow_mut().forget_own_mapping_space(face);
                return Err(OpenError::NoTask(why));
            }
        };
        Ok(wz_runtime_coop::faces::Wire::new(
            LinkSession {
                actions,
                #[cfg(feature = "listen")]
                admitted,
                #[cfg(feature = "queryable")]
                generation,
            },
            task,
            link,
            ungated,
            readiness,
            writability,
        ))
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
    ///
    /// A dial the network has not answered yet is left under way (`Link::Dialing`), and the steps
    /// that follow ask it (`Self::dial_answered`), so no dial is waited for while the session is
    /// held; one answered at once runs its handshake here. The dial names its endpoint by its
    /// row of the session's endpoint texts, which holds the text.
    fn dial_from(
        &mut self,
        from: usize,
        mut last: OpenError,
    ) -> Result<Link<LinkSession<C>, L::Dial>, OpenError> {
        for at in from..self.endpoints.dials() {
            let mut pending = match self.begin_dial(DIAL_FACE, self.endpoints.dial_text(at)) {
                Ok(pending) => pending,
                Err(refused) => {
                    last = refused;
                    continue;
                }
            };
            let next = at + 1;
            let deadline_us = self.open_deadline_us();
            match pending.poll() {
                None => {
                    return Ok(Link::Dialing {
                        dial: Dial::new(DialEndpoint::Listed(at), pending),
                        next,
                        deadline_us,
                    });
                }
                Some(answer) => {
                    let endpoint = DialEndpoint::Listed(at);
                    match self.dial_answered(DIAL_FACE, Some(&endpoint), next, deadline_us, answer)
                    {
                        Ok(link) => return Ok(link),
                        // Neither is the endpoint's: the next one would be refused the same.
                        Err(refused @ (OpenError::EntropyUnavailable | OpenError::NoTask(_))) => {
                            return Err(refused)
                        }
                        Err(refused) => last = refused,
                    }
                }
            }
        }
        Err(last)
    }

    /// The dial of `endpoint` that face `face` made answered: its link's handshake begun, given
    /// up at `deadline_us` as the dial was, the dial role's going on from endpoint `next` after
    /// it. [`OpenError::Unreachable`] when the dial was refused, [`OpenError::EntropyUnavailable`]
    /// when the platform gives no cookie key for the attempt.
    fn dial_answered(
        &mut self,
        face: FaceId,
        endpoint: Option<&DialEndpoint>,
        next: usize,
        deadline_us: u64,
        answer: Result<OpenedLink<L::Pump>, LinkOpenError>,
    ) -> Result<Link<LinkSession<C>, L::Dial>, OpenError> {
        let opened = answer.map_err(|refused| {
            OpenError::Unreachable(EndpointRefusal::new(
                self.endpoint_text(endpoint),
                Refusal::Link(refused),
            ))
        })?;
        let wire = self.open_wire(face, opened, SessionRole::Initiator, endpoint)?;
        Ok(Link::Opening {
            wire,
            next,
            deadline_us,
        })
    }

    /// The text of the endpoint a dial reaches: the session's, by its row, or the one the dial
    /// named; empty for none.
    fn endpoint_text<'a>(&'a self, endpoint: Option<&'a DialEndpoint>) -> &'a str {
        endpoint.map_or("", |endpoint| endpoint.text(&self.endpoints))
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
    fn dial_or_wait(
        &mut self,
        from: usize,
        last: OpenError,
        redial_ms: Option<u64>,
    ) -> Result<Link<LinkSession<C>, L::Dial>, OpenError> {
        match (self.dial_from(from, last), redial_ms) {
            (Ok(link), _) => Ok(link),
            (Err(OpenError::EntropyUnavailable), _) => Err(OpenError::EntropyUnavailable),
            (Err(last), None) => Err(last),
            (Err(_), Some(ms)) => {
                let ended_us = self.now_us();
                Ok(Link::Waiting {
                    at_us: ended_us.saturating_add(ms.saturating_mul(1000)),
                })
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
        for at in (0..self.links.faces().len()).rev() {
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
    /// What became of the link is the driver's to say (`LinkSupervisor::advance`), and the link
    /// stays in its face while what it means for the session is done here.
    fn poll_face(
        &mut self,
        at: usize,
        redial_ms: Option<u64>,
        now_us: u64,
    ) -> Result<(), OpenError> {
        let now_ms = now_us / 1000;
        let Some(face) = self.links.faces().get(at) else {
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
            Link::Up(wire) if !wire.finished() => Some(Rc::clone(&wire.actions)),
            _ => None,
        };
        if let Some(actions) = up {
            if self.replay_turn(at, &actions, now_ms) == TurnEnd::EndsLink {
                self.abort_link(at);
                self.run_tasks();
            }
        }
        let polled = match self.links.advance(at, now_us) {
            Moved::Stays => return Ok(()),
            // zenoh-pico's client reopens whatever ended its link: a lease that ran out, a read
            // that failed, a Close from the router
            // (`vendor/zenoh-pico/src/transport/unicast/read.c` @
            // `return _zp_unicast_failed_result(ztu, executor);`).
            Moved::Lost => {
                // The face is read before the wire goes: what it was is what a watcher is told.
                let lost = self.links.faces()[at].link.wire();
                let snapshot = lost.and_then(|wire| self.face_of(&wire.actions));
                // The peer's chains end with its link: the Router the session's links share would
                // otherwise splice its next link's fragments onto them.
                if let Some(zid) = lost.and_then(|wire| wire.actions.peer_zid()) {
                    self.router.abort_peer(&zid);
                }
                self.links.put_link(at, Link::Waiting { at_us: now_us });
                self.lose_link(id);
                self.report_face(FaceEventKind::Down, snapshot);
                if id != DIAL_FACE {
                    self.remove_face(at);
                    return Ok(());
                }
                if redial_ms.is_none() {
                    return Err(OpenError::Unreachable(EndpointRefusal::new(
                        "",
                        Refusal::LinkLost,
                    )));
                }
                self.dial_or_wait(0, OpenError::NoEndpoint, redial_ms)?
            }
            // The face table decides whether the node is held already, and installs the link
            // itself.
            Moved::Established => {
                self.bring_up(at, now_us);
                return Ok(());
            }
            Moved::HandshakeOver { next } => {
                let why = match self.links.faces()[at].link.wire() {
                    Some(wire) => match (wire.actions.close_reason(), wire.finished()) {
                        (Some(reason), _) => Refusal::HandshakeClosed(reason),
                        (None, true) => Refusal::HandshakeEnded,
                        (None, false) => Refusal::NoAnswerInTime,
                    },
                    None => Refusal::HandshakeEnded,
                };
                #[cfg(feature = "listen")]
                let node = self.links.faces()[at]
                    .link
                    .wire()
                    .and_then(|wire| wire.node());
                self.abort_link(at);
                self.run_tasks();
                self.links.put_link(at, Link::Waiting { at_us: now_us });
                if id != DIAL_FACE {
                    self.remove_face(at);
                    return Ok(());
                }
                // The dial role's link reached a node another face holds or is bringing up:
                // the node refused it (`install_link_admission`). It stands by, and dials
                // again when no other face has the node, where dialling at once would be
                // refused again and the handshake paid each time.
                #[cfg(feature = "listen")]
                if let Some(zid) = node.filter(|zid| self.links.node_is_held(zid, id)) {
                    self.links.put_link(at, Link::Held { zid });
                    return Ok(());
                }
                let last = OpenError::Unreachable(EndpointRefusal::new(
                    self.endpoints.dial_text(next - 1),
                    why,
                ));
                self.dial_or_wait(next, last, redial_ms)?
            }
            // The dial under way was asked, never waited for: its link's handshake begins once it
            // is made. Refused, or not answered by its deadline, the dial role's face dials the
            // next endpoint, and any other face goes, as one whose handshake fails does.
            Moved::DialOver {
                answer,
                endpoint,
                next,
                deadline_us,
            } => {
                let answered = match answer {
                    Some(answer) => {
                        self.dial_answered(id, Some(&endpoint), next, deadline_us, answer)
                    }
                    None => Err(OpenError::Unreachable(EndpointRefusal::new(
                        self.endpoint_text(Some(&endpoint)),
                        Refusal::NoAnswerInTime,
                    ))),
                };
                match answered {
                    Ok(link) => link,
                    Err(OpenError::EntropyUnavailable) => {
                        return Err(OpenError::EntropyUnavailable)
                    }
                    Err(_) if id != DIAL_FACE => {
                        self.remove_face(at);
                        return Ok(());
                    }
                    Err(last) => self.dial_or_wait(next, last, redial_ms)?,
                }
            }
            // A face whose wait is over, or whose node no other face holds now (with `listen`):
            // the face that held the node is gone, and so is any link in the making to it. Read
            // from the face table each step and not told by the face that goes, so a link that
            // dies in its handshake frees the node as well.
            Moved::Due => self.dial_or_wait(0, OpenError::NoEndpoint, redial_ms)?,
        };
        self.links.put_link(at, polled);
        Ok(())
    }

    /// End the task of the link of the face at `at`, if it holds one.
    fn abort_link(&self, at: usize) {
        if let Some(wire) = self.links.faces().get(at).and_then(|face| face.link.wire()) {
            wire.abort();
        }
    }

    /// Tell the peer of every face whose link is up everything the session holds again, as a link
    /// that has just come up is told (`begin_replay`), at the session's pace; the count of faces.
    /// What the application asks for when it holds that a peer lost declarations the session made.
    /// A face whose first turn the replay is given up on is not counted: its link ends, and the
    /// next pass over the faces takes it as lost (`poll_face`).
    fn redeclare(&mut self) -> usize {
        let now_ms = self.clock.now_us() / 1000;
        let mut told = 0;
        for at in 0..self.links.faces().len() {
            let actions = match &self.links.faces()[at].link {
                Link::Up(wire) => Rc::clone(&wire.actions),
                _ => continue,
            };
            match self.begin_replay(at, &actions, now_ms) {
                TurnEnd::Kept => told += 1,
                TurnEnd::EndsLink => {
                    if let Link::Up(wire) = &self.links.faces()[at].link {
                        wire.abort();
                    }
                }
            }
        }
        told
    }

    /// The face at `at`, whose handshake completed, holds its link up: what the session holds is
    /// declared over it from here on, and the watchers of the faces are told it came up. The link
    /// was admitted in its handshake (`install_link_admission`), so a link that got this far is
    /// the session's link to its node, and no other link to the node is kept beside it. A first
    /// turn the replay is given up on ends the link at once, and the next pass over the faces
    /// takes it as lost (`poll_face`).
    fn bring_up(&mut self, at: usize, now_us: u64) {
        let Some(face) = self.links.faces().get(at) else {
            return;
        };
        let Some(wire) = face.link.wire() else {
            return;
        };
        #[cfg(feature = "listen")]
        wire.admitted.grant();
        // A publish goes to the links that are up, so theirs are the rooms it asks.
        if let Some(wait) = wire.writability() {
            self.rooms.hold(face.id, wait);
        }
        let actions = Rc::clone(&wire.actions);
        if self.begin_replay(at, &actions, now_us / 1000) == TurnEnd::EndsLink {
            self.abort_link(at);
        }
        let snapshot = self.face_of(&actions);
        self.links.establish(at);
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

    /// Whether the session holds a transport, as zenoh-pico's `_z_transport_get_common` finds
    /// one: a link that is up, a port it listens on (a peer's unicast transport stands before any
    /// peer comes), or a group it joined. A client whose router went away holds none until a dial
    /// of it succeeds again.
    fn holds_transport(&self) -> bool {
        #[cfg(feature = "group")]
        if !self.groups.is_empty() {
            return true;
        }
        self.ups().next().is_some() || self.listens()
    }

    /// Whether the session listens on any port.
    fn listens(&self) -> bool {
        self.links.listens()
    }

    /// Listen on every endpoint the config lists. [`OpenError::Listen`] for the first that does
    /// not parse, that the network opens no listener for, or whose port is taken; a build without
    /// `listen` answers every endpoint so.
    fn listen_on_config(&mut self) -> Result<(), OpenError> {
        #[cfg(feature = "listen")]
        for row in 0..self.endpoints.listens() {
            let endpoint = self.endpoints.listen_text(row);
            let refused = |why| OpenError::Listen(EndpointRefusal::new(endpoint, why));
            let at =
                parse_listen_locator(endpoint).map_err(|why| refused(Refusal::Locator(why)))?;
            // The key-wire form of a link taken on the port is the one stated for its endpoint
            // (`shared-key-ids`), which the port names by its row.
            #[cfg(feature = "shared-key-ids")]
            let named = Some(row);
            #[cfg(not(feature = "shared-key-ids"))]
            let named = None;
            self.links
                .listen(at, named)
                .map_err(|why| refused(Refusal::Link(why)))?;
        }
        #[cfg(not(feature = "listen"))]
        if self.endpoints.listens() > 0 {
            return Err(OpenError::Listen(EndpointRefusal::new(
                self.endpoints.listen_text(0),
                Refusal::ListeningNotBuilt,
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
            let id = self.links.next_face_id();
            // The tables first: the group's task dispatches to them from its first step. They are
            // the face's for as long as the session holds the group, across its joins, and answer
            // a query whose key they cannot resolve by the session's policy.
            self.registry.borrow_mut().add_face(id);
            self.registry
                .borrow_mut()
                .set_unanswerable_final(id, self.policy.query_unanswerable_final());
            // An id of the key ids every node shares is read on the group as on a link.
            #[cfg(feature = "shared-key-ids")]
            if let Some(ids) = &self.key_ids {
                self.registry
                    .borrow_mut()
                    .install_shared_key_ids(id, ids.clone());
            }
            match self.join_group(id, join) {
                Ok(face) => {
                    self.links.advance_face_id();
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
            return Err(OpenError::Group(EndpointRefusal::new(
                &join.endpoint,
                Refusal::GroupsNotBuilt,
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
            .links()
            .open_group(&join.endpoint)
            .map_err(|why| {
                OpenError::Group(EndpointRefusal::new(&join.endpoint, Refusal::Link(why)))
            })?;
        let endpoint = join.endpoint.clone();
        let params = join.profile.params(
            self.config.whatami,
            self.wire_zid,
            self.config.tx_queue,
            self.config.link_rx,
            self.policy,
            resolve_limits(&self.config),
        );
        // A member's query is held, and answered, under the group's own generation, as a link's
        // is under its; each join of the group is a generation of its own.
        #[cfg(feature = "queryable")]
        let generation = self.plane.generation.fetch_add(1, Ordering::AcqRel) + 1;
        #[cfg(feature = "queryable")]
        let dispatch = group::dispatch(self.registry.clone(), id, self.plane.clone(), generation);
        #[cfg(not(feature = "queryable"))]
        let dispatch = group::dispatch(self.registry.clone(), id);
        // The group is handed a record of its datagrams only while the delivery lane has the room
        // one record of the group's batch can take (decision Q4), as a link is.
        let room = crate::lane::read_room::<
            { caps::PICO_FRAG_MAX_BYTES },
            { caps::MAX_KEYEXPR_BYTES },
            { caps::MAX_SUBSCRIPTIONS },
            { caps::MAX_LIVELINESS_SUBSCRIPTIONS },
        >(
            usize::from(params.batch_size),
            &resolve_limits(&self.config),
        );
        // SAFETY: a group's transport is driven by the session's step alone, under its lock.
        let input_gate = wz_session_mcu::group_drive::GroupInputGate::new(unsafe {
            crate::lane::takes_a_group_read(self.lane.clone(), room)
        });
        let face = GroupFace::join(
            &self.local,
            GroupJoining {
                id,
                join,
                transport,
                input_gate,
                params,
                policy: self.policy,
                limits: resolve_limits(&self.config),
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
        )
        .map_err(OpenError::NoTask)?;
        self.run_tasks();
        if face.has_ended() {
            return Err(OpenError::Group(EndpointRefusal::new(
                &endpoint,
                Refusal::GroupLinkDidNotOpen,
            )));
        }
        // A droppable publish that finds the session held asks the group's socket for room as it
        // asks a link's, and its wait goes with the face.
        if let Some(wait) = face.room() {
            self.rooms.hold(id, wait);
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
                        for entry in self.live_subs.iter() {
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

    /// Take the connections that wait on the ports the session listens on, each as a face of its
    /// own. A port that had no socket or buffer for one just now is looked at again on the next
    /// step, and one that is broken for good is let go of.
    #[cfg(feature = "listen")]
    fn accept_links(&mut self) {
        let mut at = 0;
        while let Some(accepted) = self.links.accept_at(at) {
            match accepted {
                Accepted::Link(opened, endpoint) => self.accept_face(opened, endpoint),
                Accepted::Idle => at += 1,
                // The port was let go of, and the one after it is at `at` now.
                Accepted::Broken => {}
            }
        }
    }

    /// Give a link taken off a port a face, and run its session as the acceptor. A link that
    /// arrives when the session holds as many faces as `max_faces`, or has as many handshakes
    /// under way as `accept_pending`, is closed unread: its peer learns the node is full from the
    /// close, where one left queued would wait for a handshake that never starts.
    #[cfg(feature = "listen")]
    fn accept_face(&mut self, opened: OpenedLink<L::Pump>, endpoint: Option<DialEndpoint>) {
        let pending = self
            .links
            .faces()
            .iter()
            .filter(|face| face.id != DIAL_FACE && matches!(face.link, Link::Opening { .. }))
            .count();
        if self.links.faces().len() > self.config.max_faces || pending >= self.config.accept_pending
        {
            return;
        }
        let id = self.links.next_face_id();
        // The tables first: the link's task dispatches to them from its first step.
        self.registry.borrow_mut().add_face(id);
        let Ok(wire) = self.open_wire(id, opened, SessionRole::Acceptor, endpoint.as_ref()) else {
            self.registry.borrow_mut().remove_face(id);
            return;
        };
        self.links.advance_face_id();
        // The handshake is the acceptor's whole-handshake bound; the session's own timer in the
        // state machine is the same bound and ends the task, so whichever is first removes the face.
        let deadline_us = self.clock.now_us().saturating_add(
            self.config
                .timeouts
                .accepting_inactivity_ms
                .saturating_mul(1000),
        );
        self.push_face(
            id,
            Link::Opening {
                wire,
                next: 0,
                deadline_us,
            },
        );
    }

    /// Add a face whose link is `link`: a dial under way or a handshake. It is told the session's
    /// declarations at the pace the dial role's face is. Every face the open admits has its place
    /// in the table; one past them, which the callers refuse before they make it, is let go of
    /// with its tables.
    fn push_face(&mut self, id: FaceId, link: Link<LinkSession<C>, L::Dial>) {
        let pacing = self.dial().replay.pacing();
        let face = Face {
            id,
            link,
            replay: Replay::with_pacing(pacing),
        };
        if let Err(face) = self.links.push_face(face) {
            if let Some(wire) = face.link.wire() {
                wire.abort();
            }
            self.registry.borrow_mut().remove_face(face.id);
        }
    }

    /// Take the face at `at` out of the session, with its tables. The dial role's face is never
    /// taken out.
    fn remove_face(&mut self, at: usize) {
        if let Some(face) = self.links.remove_face(at) {
            self.registry.borrow_mut().remove_face(face.id);
        }
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
        let links = self
            .links
            .faces()
            .iter()
            .filter_map(|face| match &face.link {
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
        if let Some(face) = self.links.faces_mut().iter_mut().find(|face| face.id == id) {
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

    /// Whether a link of the session holds input it has already taken from its stack, or a group
    /// took a datagram its next step reads: what makes a read's wait none ([`Self::idle_wait`]).
    fn holds_input(&self) -> bool {
        #[cfg(feature = "group")]
        if self.groups.iter().any(GroupFace::took_input) {
            return true;
        }
        self.links.holds_input()
    }

    /// What a read waits for before it steps the session: the link's next input, for at most
    /// [`CoopConfig::idle_wait_ms`], unless the link already holds some or waits in its own loop;
    /// and while no link is open, the next dial, for no longer either. zenoh-pico's read waits
    /// the same way, on a socket whose receive timeout is that long (`Z_CONFIG_SOCKET_TIMEOUT`).
    fn idle_wait(&mut self) -> IdleWait {
        let most = self.config.idle_wait_ms;
        // The clock is read the first time a deadline asks for it, and that reading serves every
        // deadline after it: a wait with nothing due reads it not at all.
        let mut clock_now: Option<u64> = None;
        // A get whose deadline comes first is swept when it is due, not up to a whole wait late.
        #[cfg(feature = "query")]
        let most = match self.next_get_deadline_ms() {
            Some(due_ms) => Self::wait_until(
                most,
                due_ms,
                *clock_now.get_or_insert_with(|| self.now_us()),
            ),
            None => most,
        };
        // And so is the next turn of a replay a link owes its peer, which is not due by input.
        let most = match self
            .links
            .faces()
            .iter()
            .filter_map(|face| face.replay.next_turn_ms())
            .min()
        {
            Some(due_ms) => Self::wait_until(
                most,
                due_ms,
                *clock_now.get_or_insert_with(|| self.now_us()),
            ),
            None => most,
        };
        // And so is a periodic job the program started, which no input brings about either.
        #[cfg(feature = "ticker")]
        let most = match self.tickers.next_due_ms() {
            Some(due_ms) => Self::wait_until(
                most,
                due_ms,
                *clock_now.get_or_insert_with(|| self.now_us()),
            ),
            None => most,
        };
        // And so is a group's turn: its task takes one datagram a step, so a group that took one
        // is stepped again at once; one that took none is stepped when its next datagram comes,
        // which the read waits on below, or when its session is next due with nothing arriving
        // (its beacon, its sweep, what the session pushed onto it, its join again). A group whose
        // stack gives no wait for its input is looked at on its tick.
        #[cfg(feature = "group")]
        let most = if self.groups.iter().any(GroupFace::took_input) {
            0
        } else {
            let most = match self.groups.iter().filter_map(GroupFace::due_us).min() {
                Some(due_us) => Self::wait_until(
                    most,
                    due_us.div_ceil(1_000),
                    *clock_now.get_or_insert_with(|| self.now_us()),
                ),
                None => most,
            };
            if self.groups.iter().any(GroupFace::unwaited) {
                most.min(group::GROUP_TICK_MS)
            } else {
                most
            }
        };
        if most == 0 {
            return IdleWait::None;
        }
        // What the read waits on is the driver's to make (`LinkSupervisor::idle_wait`): the input
        // of every link and port, and each group's after them, since a wait over several is made
        // by the first and a link's names a group's socket to the platform beside its own. The one
        // link waited on is read in place of the wait unless a sample lies in a datagram a link
        // lent (`SharedLane::lends_a_datagram`), which the lend would move, or the program moves
        // the session's clock, whose word must end the wait and cannot end a read.
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
        let (clock_moves, lane) = (&self.config.clock_moves, &self.lane);
        let may_lend = || clock_moves.is_none() && !lane.lends_a_datagram();
        #[cfg(feature = "group")]
        let others = self.groups.iter().filter_map(GroupFace::input).cloned();
        #[cfg(not(feature = "group"))]
        let others = core::iter::empty();
        let wait = self.links.idle_wait(most, &mut now_us, may_lend, others);
        // The bounds above are the clock's time read as the wall's, which a clock the program
        // moves is not: its word that the time moved on ends the wait as well.
        ended_by_clock_moves(wait, self.config.clock_moves.as_ref())
    }

    /// Run the session's tasks until none is ready, the session's one reassembly Router lent to
    /// its links' receives for as long ([`RouterLend::lend_for`]). Every pass of the session's
    /// own is made here, so a link's receive finds its Router lent whenever its task runs; a pass
    /// a group's wait makes lends nothing, and a link's receive takes no input in it.
    fn run_tasks(&mut self) {
        let Self {
            local,
            router,
            lend,
            ..
        } = self;
        lend.lend_for(router, || local.run_until_idle());
    }

    /// End every face's link, whatever it is doing, telling an established peer so. The dial
    /// role's face stays, with no link and no redial; the others go.
    fn end_links(&mut self) {
        // A dial under way is let go of: its connection is not made. The ports are let go of
        // first, so no connection is taken while the faces are ended.
        self.links.end_dials_and_ports();
        // Each group's session is asked to stop, and its next step, taken here, tells the group it
        // leaves and lets the group's link go; its tables go with it.
        #[cfg(feature = "group")]
        if !self.groups.is_empty() {
            for group in &self.groups {
                group.stop();
            }
            self.run_tasks();
            let mut registry = self.registry.borrow_mut();
            for group in self.groups.drain(..) {
                registry.remove_face(group.id());
            }
        }
        self.links.end_faces(|face| face.replay.discard());
        self.registry.borrow_mut().remove_accepted_faces();
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
            memory,
            HeldPlaces::NONE,
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
    /// The arena also holds the places `held` names, lent after every table
    /// ([`ArenaPlan::holding`]): a place for the ABI's own handle of the session
    /// ([`CoopDrive::handle_place`]) and places for its objects of the session's entities
    /// ([`PlaceLender::claim_place`]). They are reserved with the session, and an open whose arena cannot
    /// hold them opens nothing.
    #[allow(clippy::too_many_arguments)]
    pub fn open_made_in(
        links: L,
        clock: C,
        entropy: impl EntropySource + Send + 'static,
        source: impl OpenSource,
        policy: SessionPolicy,
        key_ids: OpenKeyIds,
        memory: &'static dyn ArenaMemory,
        held: HeldPlaces,
    ) -> Result<Arc<Self>, OpenError> {
        let engine = Self::assemble(links, clock, entropy, source, policy, key_ids, memory, held)?;
        engine.open_links()?;
        Ok(engine)
    }

    /// The engine [`Self::open_made_in`] opens, built where it is kept and not yet bound, joined
    /// or dialled: the config made, the key-wire form judged, the arena reserved and its tables
    /// lent, the zid decided. Never inlined, for the stack: the session's state is put together in
    /// this frame and moved into the engine's allocation, and the frame has returned before the
    /// first link is opened.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn assemble(
        mut links: L,
        clock: C,
        entropy: impl EntropySource + Send + 'static,
        source: impl OpenSource,
        policy: SessionPolicy,
        key_ids: OpenKeyIds,
        memory: &'static dyn ArenaMemory,
        held: HeldPlaces,
    ) -> Result<Arc<Self>, OpenError> {
        let (config, write_endpoints) = source.into_parts();
        #[cfg(feature = "shared-key-ids")]
        let key_forms = key_ids.admit(&policy, &resolve_limits(&config))?;
        #[cfg(not(feature = "shared-key-ids"))]
        key_ids.admit(&policy)?;
        let plan = arena_plan::<C, _>(&links, &config)
            .and_then(|plan| plan.holding(&held))
            .map_err(OpenError::Arena)?;
        let mut arena = SessionArena::reserve(&plan, memory).map_err(OpenError::Arena)?;
        links.lend_buffers(arena.lend_links(&plan).map_err(OpenError::Arena)?);
        let (link_cells, gate_cells) = arena.lend_cells(&plan).map_err(OpenError::Arena)?;
        if let Some(cells) = link_cells {
            links.lend_cells(cells);
        }
        let (lane_area, lane_bytes) = arena.lend_lane(&plan).map_err(OpenError::Arena)?;
        let reassembly = arena.lend_reassembly(&plan).map_err(OpenError::Arena)?;
        let router = session_reassembly(&policy, SessionChains::over(&reassembly, LENT_CHAINS));
        // The texts of the endpoints, each written once by the source into the row the plan laid
        // out for it: the session names an endpoint by its row from here, and what the source
        // held goes with its writer, here, before anything is bound or dialled.
        let mut endpoints = arena.lend_endpoints(&plan).map_err(OpenError::Arena)?;
        write_endpoints(&mut EndpointWriter::over(&mut endpoints))?;
        // SAFETY: the area is the arena's, lent to the lane alone, and the arena is the session's
        // and given back only when the session is let go, after its last delivery.
        let samples =
            unsafe { SharedLane::shared_over(lane_area, lane_bytes, &resolve_limits(&config)) };
        let mut entropy = SharedEntropy::new(entropy);
        let wire = match (&config.zid, policy.zid_derivation()) {
            (Some(zid), _) => wire_zid(zid)?,
            (None, wz_session_core::policy::ZidDerivation::Random) => fresh_zid(&mut entropy)?,
            (None, wz_session_core::policy::ZidDerivation::AddressPorts) => derived_zid(
                (0..endpoints.listens()).map(|at| endpoints.listen_text(at)),
                &mut entropy,
            )?,
        };
        // The tables of the session's own declarations, lent from the arena as the plan counts
        // them. Declared after the arena, so a refusal before `core` holds them drops them first.
        let entities = plan.entities();
        let keyexprs = arena.lend(entities.keyexprs).map_err(OpenError::Arena)?;
        let filters = arena
            .lend(
                entities
                    .filters()
                    .ok_or(OpenError::Arena(ArenaRefused::TooLarge))?,
            )
            .map_err(OpenError::Arena)?;
        let interests = arena
            .lend(
                entities
                    .interests()
                    .ok_or(OpenError::Arena(ArenaRefused::TooLarge))?,
            )
            .map_err(OpenError::Arena)?;
        let matches = arena
            .lend(entities.matching_listeners)
            .map_err(OpenError::Arena)?;
        #[cfg(feature = "queryable")]
        let queryables = arena.lend(entities.queryables).map_err(OpenError::Arena)?;
        #[cfg(feature = "liveliness")]
        let tokens = arena.lend(entities.tokens).map_err(OpenError::Arena)?;
        #[cfg(feature = "liveliness")]
        let live_subs = arena
            .lend(entities.liveliness_subscribers)
            .map_err(OpenError::Arena)?;
        let keys = arena
            .lend_keys(&plan, config.limits.max_keyexpr_bytes_held())
            .map_err(OpenError::Arena)?;
        // The application's tables, lent from the rows the plan counts for them.
        let registry = Registry::new(
            &resolve_limits(&config),
            arena.arena_mut(),
            keys,
            ObserverRows {
                subscribers: entities.subscribers,
                queryables: entities.queryables,
                local_tokens: entities.tokens,
                liveliness_subscribers: entities.liveliness_subscribers,
            },
            plan.gets(),
            plan.peers(),
        )
        .map_err(|lend| OpenError::Arena(ArenaRefused::Lend(lend)))?;
        // The ends of the session's legs wait in rows the plan counts for them.
        #[cfg(feature = "query")]
        let ended = EndedLegs::over(
            arena
                .lend(
                    plan.gets()
                        .legs()
                        .ok_or(OpenError::Arena(ArenaRefused::TooLarge))?,
                )
                .map_err(OpenError::Arena)?,
        );
        // The ABI's handle's place, the plan's last row.
        let handle_place = arena.lend_handle(&plan).map_err(OpenError::Arena)?;
        // The places of the ABI's objects of the session's entities, the rows after it.
        let places = arena.lend_entity_places(&plan).map_err(OpenError::Arena)?;
        // The task and timer tables, reserved here once: no spawn and no sleep of the session
        // takes memory after its open (`open_links` seals them).
        let runtime = RuntimeTables::of::<C>(&config).runtime(clock.clone());
        let local = CoopLocalSet::new(&runtime);
        let session_time = CoopTime::new(&runtime);
        // The dial role's link, each port, each group and the clock's word: what a session waits on
        // from its open. A face accepted or attached later grows the buffer once.
        let wait_room = 2usize
            .saturating_add(config.listen.count())
            .saturating_add(config.groups.len());
        let limits = resolve_limits(&config);
        let keyexprs = Rc::new(RefCell::new(keyexprs));
        let core = Core {
            local,
            endpoints,
            clock,
            registry: Rc::new(RefCell::new(registry)),
            #[cfg(feature = "listen")]
            tx_pool_short: plan.tx_pool_short(),
            rooms: Arc::new(LinkRooms::default()),
            #[cfg(feature = "connectivity")]
            watchers: Arc::new(FacePlane::default()),
            // A face for each the config admits beside the dial role's, each with its dial, and the
            // waits a read makes at once, reserved here: none grows after.
            links: LinkSupervisor::new(
                links,
                Face {
                    id: DIAL_FACE,
                    link: Link::Waiting { at_us: u64::MAX },
                    replay: Replay::with_pacing(ReplayPacing::of_snapshot(&policy, &limits)),
                },
                config.max_faces.saturating_add(1),
                wait_room,
            ),
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
            entities,
            keys,
            own_space: session_space(&keyexprs),
            keyexprs,
            gate_cells,
            next_mapping: 1,
            #[cfg(feature = "shared-key-ids")]
            key_ids: key_ids.at_open.ids,
            #[cfg(feature = "shared-key-ids")]
            key_forms,
            #[cfg(feature = "local-queryable")]
            next_local_request: 0,
            filters,
            next_filter: 1,
            interests,
            #[cfg(test)]
            clock_reads: core::cell::Cell::new(0),
            matches,
            next_match: 1,
            #[cfg(feature = "queryable")]
            queryables,
            #[cfg(feature = "queryable")]
            plane: Arc::new(QueryPlane::holding(plan.held_queries())),
            #[cfg(feature = "query")]
            pending_gets: Vec::new(),
            #[cfg(feature = "query")]
            gets: Arc::new(GetPlane::new(ended)),
            #[cfg(feature = "liveliness")]
            tokens,
            #[cfg(feature = "liveliness")]
            live_subs,
            #[cfg(feature = "ticker")]
            tickers: Tickers::reserved(caps::MAX_TICKERS),
            lane: samples.clone(),
            router,
            lend: RouterLend::new(),
            session_time,
            places,
            arena,
        };
        #[cfg(feature = "queryable")]
        let plane = core.plane.clone();
        #[cfg(feature = "query")]
        let gets = core.gets.clone();
        #[cfg(feature = "connectivity")]
        let faces = core.watchers.clone();
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        let decl_watches = core.registry.borrow().decl_watches.clone();
        let rooms = core.rooms.clone();
        let wait_before_drop_us = core.config.tx_queue.wait_before_drop_us;
        let held_drop = core.config.tx_queue.held_drop;
        let handed_at_most = core.config.tx_queue.sizes;
        let arena_bytes = core.arena.bytes();
        Ok(Arc::new_cyclic(|this| Self {
            core: CoreLock::new(core),
            rooms,
            wait_before_drop_us,
            held_drop,
            sending_on: AtomicU64::new(NOT_SENDING),
            handed: Mutex::new(VecDeque::new()),
            owed: AtomicBool::new(false),
            input_held: AtomicBool::new(false),
            handed_at_most,
            #[cfg(feature = "transport-stats")]
            unsent_drops: AtomicU64::new(0),
            samples,
            matching: Arc::new(Queued::new(MatchFlips::new())),
            targets: Mutex::new(Vec::new()),
            removed: AtomicU64::new(0),
            resolved: TryCell::new(Resolved::new()),
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
            next_entity: AtomicU64::new(1),
            #[cfg(any(feature = "query", feature = "ticker"))]
            next_local: AtomicU64::new(1),
            reader: Mutex::new(None),
            deliveries: Deliveries::new(),
            arena_bytes,
            handle_place,
            #[cfg(test)]
            takes: Takes::default(),
            this: this.clone(),
        }))
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
        core.listen_on_config()?;
        core.join_groups()?;
        // Asked as the arena asked it, so the dial role's face dials exactly when its plan lent
        // it a link.
        if crate::arena::dials_of(
            core.endpoints.dials(),
            core.endpoints.listens(),
            core.config.groups.len(),
        ) {
            let link = core.dial_from(0, OpenError::NoEndpoint)?;
            core.links.put_link(0, link);
            // Open once the dial's link is up, or once the node it reached is held by a face that
            // came first (a peer that listens and dials its own listener's peer).
            while !core.dial_settled() {
                let mut wait = core.idle_wait();
                wait.wait(sleep_ms);
                core.links.waited(wait);
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

    /// The bytes the session's open reserved for its arena: the sum of its plan's spans
    /// ([`ArenaPlan::reserved_bytes`]).
    pub fn arena_bytes(&self) -> usize {
        self.arena_bytes
    }

    /// What the session's key arena holds now, closed or not.
    #[cfg(test)]
    pub(crate) fn key_counts(&self) -> wz_session_core::key_arena::KeyCounts {
        self.core.lock().0.keys.counts()
    }

    /// The samples the session's delivery lane did not hand a subscriber, by why
    /// (`crate::lane`).
    pub fn lane_counts(&self) -> LaneCounts {
        let _session = self.core.lock();
        // SAFETY: the session's lock is held (`_session`).
        unsafe { self.samples.held() }.counts()
    }

    /// Dial `endpoint` as a face of its own, beside the dial role's, and return the id it is
    /// known by. What the session declares is declared over it once its handshake completes (the
    /// session steps it as it does the first face's), what is declared after goes to it too, a
    /// publish and a get reach its peer, and what its peer declares counts with the others'. It
    /// is dialled once: a link that is lost or never completes takes the face with it, where the
    /// dial role's face is dialled again. [`OpenError::Unreachable`] when the session is closed,
    /// the endpoint's text is longer than `MAX_LOCATOR_LEN`, the session holds as many faces as
    /// `max_faces` admits, or the endpoint is not reached.
    pub fn attach_face(&self, endpoint: &str) -> Result<u64, OpenError> {
        let Some(mut guard) = self.live() else {
            return Err(OpenError::Unreachable(EndpointRefusal::new(
                endpoint,
                Refusal::SessionClosed,
            )));
        };
        let core = &mut guard.0;
        // The dial keeps the endpoint's text as its own, in a row's length, as the open keeps the
        // config's: no memory of the heap after the open.
        let Ok(named) = LocatorText::try_from(endpoint) else {
            return Err(OpenError::Unreachable(EndpointRefusal::new(
                endpoint,
                Refusal::TextTooLong,
            )));
        };
        // A face past `max_faces` would have no buffers: the arena holds the links of as many
        // faces as the config admits, and an accepted link past them is closed unread.
        if core.links.faces().len() > core.config.max_faces {
            return Err(OpenError::Unreachable(EndpointRefusal::new(
                endpoint,
                Refusal::FacesFull,
            )));
        }
        let id = core.links.next_face_id();
        // The dial is begun here and asked at each step, as the dial role's is: the session is
        // held here, and a connection is not waited for while it is.
        let pending = core.begin_dial(id, endpoint)?;
        // The tables first: the link's task dispatches to them from its first step.
        core.registry.borrow_mut().add_face(id);
        core.links.advance_face_id();
        let deadline_us = core.open_deadline_us();
        core.push_face(
            id,
            Link::Dialing {
                dial: Dial::new(DialEndpoint::Named(named), pending),
                next: 0,
                deadline_us,
            },
        );
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
            for group in &core.0.groups {
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
            core.0.links.listening().map(|at| at.to_string()).collect()
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

    /// How many of the session's links owe their stack the rest of a frame it took only in part,
    /// each holding an outbound slot for it. Compiled where its readers are (`tests::tx_pool`).
    #[cfg(all(test, feature = "std", feature = "listen"))]
    pub(crate) fn links_owing(&self) -> usize {
        self.live().map_or(0, |core| {
            core.0
                .links
                .faces()
                .iter()
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
            for face in core.0.links.faces_mut() {
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
        f(&mut core.0.router, now_ms)
    }

    /// How many subscribers the session core's table holds, each one row: what a test of a
    /// subscriber's ends reads. Read under the lock, uncounted as a take.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn subscriber_rows(&self) -> usize {
        self.core.lock().0.registry.borrow().app.subscribers.len()
    }

    /// How many callbacks the table of callbacks holds: what a test of the close reads.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn callbacks_held(&self) -> usize {
        lock(&self.targets).len()
    }

    /// How many samples the session's delivery lane handed on to the deliveries since the open:
    /// what a test of the cost of one received sample counts.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn lane_handed(&self) -> usize {
        self.samples.handed_on() + self.samples.pending_counts().0
    }

    /// How many samples the session's delivery lane handed to their callbacks where their
    /// datagram lies since the open: what a test of the cost of one received sample counts.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn lane_lent(&self) -> usize {
        self.samples.lent_count() + self.samples.pending_counts().1
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
        self.core.lock().0.registry.borrow().push_dispatches()
    }

    /// Whether the peer of every established link has been told every declaration the session
    /// holds. A session with no link established owes nothing yet, so it is synced, as the slot
    /// node's is before a client has come: synced is a statement about established sessions, not
    /// about whether a session exists.
    pub fn declarations_synced(&self) -> bool {
        self.live().map_or(true, |core| {
            core.0
                .links
                .faces()
                .iter()
                .all(|face| face.replay.finished())
        })
    }

    /// The session's state, for one operation. `None` once the session is closed.
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
            core: guard,
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
                    core: guard,
                    lane: self.samples.as_ref(),
                });
            }
            let room = self
                .rooms
                .for_held(self.held_drop, self.holder(), self.wait_before_drop_us);
            let (faces, told) = match room {
                Room::Free => {
                    #[cfg(test)]
                    self.takes.spins.fetch_add(1, Ordering::Relaxed);
                    core::hint::spin_loop();
                    continue;
                }
                Room::Unasked | Room::Stepping => {
                    return self.live().map_or(ToPublish::Closed, ToPublish::Live)
                }
                Room::Congested(faces) => (faces, false),
                Room::Held(face) => (vec![face], true),
            };
            #[cfg(feature = "transport-stats")]
            self.unsent_drops.fetch_add(1, Ordering::Relaxed);
            return ToPublish::DroppedOn { faces, told };
        }
    }

    /// Who holds the session now, as its holder marked itself ([`SendingOn`]).
    fn holder(&self) -> Holder {
        match self.sending_on.load(Ordering::SeqCst) {
            NOT_SENDING => Holder::Step,
            PUBLISHING => Holder::Publish,
            WAITING => Holder::Waiting,
            face => Holder::Sending(face),
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
            for actions in core.0.ups() {
                report.absorb(&actions.stats_report());
            }
            // A group charges what its queue dropped, for want of room or past the reply limit,
            // where the tokio engine's group charges it, the transport's dropped messages; it
            // leaves with the group's join.
            #[cfg(feature = "group")]
            for group in &core.0.groups {
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
        let Some(_delivering) = self.deliveries.enter() else {
            return;
        };
        // A callback can queue more for this delivery than the pass that ran it has already passed
        // over (a queryable's answer to the session's own get lies in the lane behind what was
        // handed): the passes go on until one hands nothing, so a get its own queryables answer
        // inside the call ends there.
        while self.hand_out() {}
        // The legs that are over, after every reply queued before their ends: each callback is
        // dropped here, with no lock held, which is how the C program learns it (the reply
        // closure's `drop(context)`). A lane another delivery still hands out may hold a reply
        // of one of them: that delivery tells the ends once it is through.
        #[cfg(feature = "query")]
        while self.gets.ended.is_pending() && self.samples.is_idle() {
            let next = self.gets.ended.lock().take();
            let Some(leg) = next else {
                break;
            };
            if let Some(mut core) = self.live() {
                core.0.pending_gets.retain(|pending| pending.leg != leg);
            }
            drop(self.take_target(TargetKey::Reply(leg)));
        }
    }

    /// One pass over what the session queued for the program's callbacks, under the delivery
    /// [`Self::deliver`] entered. Whether anything was handed out. The lane, the matching changes
    /// and the queries each say without their locks whether they hold anything, so a pass that
    /// finds nothing, which every delivery's last pass is, takes none of their locks.
    fn hand_out(&self) -> bool {
        // The pending samples came before anything the lane holds (`SharedLane::offer_to`).
        let mut handed = self.hand_out_pending();
        handed |= self.samples.owes_a_delivery() && self.hand_out_lane();
        // A face that came up or went down, told to each watcher as it stands now: the list is
        // cloned out of its lock, so a sink that undeclares a watcher does not wait on it.
        #[cfg(feature = "connectivity")]
        while let Some((kind, face)) = self.faces.next_event() {
            handed = true;
            for sink in self.faces.sinks() {
                sink(kind, &face);
            }
        }
        // What a peer declared or retracted, told to the watch it is owed to.
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        while let Some((sink, told)) = self.decl_watches.next() {
            sink(told.event());
        }
        while self.matching.is_pending() {
            // Popped under the queue's lock alone, which is released before the sink runs.
            let next = self.matching.lock().next();
            let Some((id, matching)) = next else {
                break;
            };
            handed = true;
            if let Some(Target::Matching(sink)) = self.target(TargetKey::Matching(id)) {
                sink(matching);
            }
        }
        let asked = self.hand_queries();
        handed || asked
    }

    /// Hand the samples of the datagram a link lent the last step to the callbacks their rows
    /// matched, each copied out of its row under the session's lock (`lane::Pending`), with no
    /// lock of the library held. Whether anything was handed.
    fn hand_out_pending(&self) -> bool {
        self.samples
            .deliver_pending(|subscriber, callback, sample| {
                #[cfg(feature = "local-subscriber")]
                let _running = self.deliveries.run(TargetKey::Subscriber(subscriber));
                #[cfg(not(feature = "local-subscriber"))]
                let _ = subscriber;
                callback.hand(sample);
            })
    }

    /// Hand what the session's lane holds to the callbacks it is for, the oldest first. Whether
    /// anything was handed. The samples come from the lane's queue with no lock (`SharedLane`),
    /// each given back to the session when its callbacks have returned, or one unwinds; no lock of
    /// the library is held while a callback runs. Another delivery that holds the lane's side
    /// hands out what this one finds, before it lets go: a delivery that finds the side held
    /// leaves it, and one that lets go looks again for what was handed on meanwhile.
    fn hand_out_lane(&self) -> bool {
        let mut handed = false;
        while self.samples.owes_a_delivery() {
            let Some(delivery) = self.samples.deliver() else {
                break;
            };
            // The callbacks found for the samples' subscribers, kept from one sample to the next and
            // from one delivery to the next: the engine's, unless another delivery holds them now,
            // which leaves this one a set of its own for this pass.
            let mut kept = self.resolved.try_take();
            let mut own = None;
            let resolved: &mut Resolved = match kept.as_deref_mut() {
                Some(held) => held,
                None => own.insert(Resolved::new()),
            };
            while let Some((item, head)) = delivery.take() {
                handed = true;
                match item {
                    LaneItem::Sample(sample) => {
                        self.hand_sample(resolved, &sample, sample.subscribers());
                    }
                    // The samples of a lent datagram, one record for all of them: each handed to
                    // its subscribers from a view of its entry, and the datagram given back once,
                    // after the last of them.
                    LaneItem::Batch(batch) => {
                        for sample in batch.samples() {
                            self.hand_sample(resolved, &sample, sample.subscribers());
                        }
                    }
                    #[cfg(feature = "query")]
                    LaneItem::Reply(reply) => {
                        let leg = reply.leg();
                        if let Some(Target::Reply(callback)) = self.target(TargetKey::Reply(leg)) {
                            (lock(&callback))(&reply);
                        }
                    }
                    #[cfg(feature = "liveliness")]
                    LaneItem::Liveliness(sample) => {
                        for id in sample.subscribers() {
                            if let Some(Target::Liveliness(callback)) =
                                self.target(TargetKey::Liveliness(id))
                            {
                                let _running = self.deliveries.run(TargetKey::Liveliness(id));
                                (lock(&callback))(sample.as_sample());
                            }
                        }
                    }
                }
                // The sample goes back to the session now its callbacks have returned.
                drop(head);
            }
            self.let_go_of_resolved(kept);
            drop(own);
            drop(delivery);
        }
        handed
    }

    /// Hand `sample` to the callback of each of `subscribers`, in order, with no lock of the
    /// library held: the first [`RESOLVED_SUBSCRIBERS`] by the callbacks `resolved` keeps, the rest
    /// by a look in the table each. A subscriber undeclared since the sample arrived has no callback
    /// left, and is passed over.
    fn hand_sample(
        &self,
        resolved: &mut Resolved,
        sample: &dyn SampleView,
        subscribers: impl Iterator<Item = SubId>,
    ) {
        let hand = |id: SubId, callback: &SubscriberCallback| {
            #[cfg(feature = "local-subscriber")]
            let _running = self.deliveries.run(TargetKey::Subscriber(id));
            #[cfg(not(feature = "local-subscriber"))]
            let _ = id;
            callback.hand(sample);
        };
        for (at, id) in subscribers.enumerate() {
            if at < RESOLVED_SUBSCRIBERS {
                if let Some(callback) = self.resolved_subscriber_callback(resolved, at, id) {
                    hand(id, callback);
                }
            } else if let Some(callback) = self.subscriber_callback(id) {
                hand(id, &callback);
            }
        }
    }

    /// Hand each query the session queued to its queryable's callback, and send what it answered.
    /// Whether one was handed.
    #[cfg(feature = "queryable")]
    fn hand_queries(&self) -> bool {
        let mut handed = false;
        while self.plane.queries.is_pending() {
            let next = self.plane.queries.lock().pop_front();
            let Some((id, query, generation)) = next else {
                break;
            };
            handed = true;
            self.run_queryable(id, &query, generation);
        }
        handed
    }

    /// Run queryable `id`'s callback on `query`, which arrived on the link of `generation`, and
    /// send what it answered: its replies go out, then the hold its arrival took on the Final is let
    /// go. A queryable undeclared since lets go of the hold all the same.
    #[cfg(feature = "queryable")]
    fn run_queryable(&self, id: QblId, query: &dyn QueryView, generation: u64) {
        let callback = self
            .target(TargetKey::Queryable(id))
            .and_then(|target| match target {
                Target::Queryable(callback) => Some(callback),
                _ => None,
            });
        let mut onward = Onward::to(self, generation);
        if let Some(callback) = callback {
            let _answering =
                query::Answering::enter(self as *const Self as usize, generation, query.rid());
            // A get of the session's own made from inside this callback reads it as running here,
            // and leaves its query for when it returns.
            #[cfg(feature = "local-queryable")]
            let _running = self.deliveries.run(TargetKey::Queryable(id));
            let mut responder = query::responder_for(
                query.rid(),
                query.keyexpr(),
                query.parameters(),
                query.qos(),
                &mut onward,
            );
            (lock(&callback))(query, &mut responder);
        }
        self.answer(generation, query.rid(), true);
    }

    /// A build with no queryable is handed no query.
    #[cfg(not(feature = "queryable"))]
    fn hand_queries(&self) -> bool {
        false
    }

    /// A publish's leg to the peers the session's faces reach, when its destination admits the
    /// wire. A link that is down skips it, as a send over it would.
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
        // zenoh's `is_droppable`: a best-effort message, or one whose congestion control is `Drop`
        // (`commons/zenoh-protocol/src/network/mod.rs` @ `!self.is_reliable() || self.congestion_control() == CongestionControl::Drop`).
        // A message with no QoS of its own is sent with the default's, as the send reads it.
        let congestion = meta.qos.unwrap_or(QosLevel::DEFAULT).congestion();
        let droppable = !opts.reliable_bool() || congestion == CongestionControl::Drop;
        let core = match self.live_to_publish(droppable) {
            ToPublish::Live(core) => core,
            ToPublish::Closed => return Ok(0),
            ToPublish::DroppedOn { faces, told } => {
                let (kept, attachment) = opts.clone().into_owned_parts();
                self.hand_off(HandedLeg {
                    keyexpr: String::from(keyexpr),
                    wire: wire.clone(),
                    payload: payload.to_vec(),
                    opts: kept,
                    attachment: attachment.map(<[u8]>::to_vec),
                    dropped_on: faces,
                });
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
        // What was handed to the session before this publish leaves before it, and what was
        // handed while this publish held the session leaves after it.
        let before = self.send_handed(&core.0);
        let put = Publication {
            keyexpr,
            wire,
            payload,
            opts,
            meta: &meta,
        };
        // A publish that may not be dropped, on a session whose links share fewer outbound slots
        // than they are, may find every slot held by another link's frame its stream has not
        // finished. It then waits for one with nothing of the session held, as zenoh-pico's
        // blocking put waits for its transmit lock, within its `wait_before_close`
        // (`Self::wait_for_slots`).
        #[cfg(feature = "listen")]
        let pass = Pass {
            from: FIRST_FACE,
            probe: !droppable && core.0.tx_pool_short,
        };
        #[cfg(not(feature = "listen"))]
        let pass = EVERY_FACE;
        let (outcome, stuck) = self.fan_out_in(&core.0, &put, &[], pass);
        #[cfg(feature = "listen")]
        let waiting = stuck.map(|face| {
            let wait_us = core.0.config.tx_queue.wait_before_close_us;
            let deadline_us = core.0.now_us().saturating_add(wait_us);
            (face, deadline_us, wait_us, core.0.links.owing_waits())
        });
        #[cfg(not(feature = "listen"))]
        let _ = stuck;
        let after = self.send_handed(&core.0);
        drop(publishing);
        drop(core);
        // Let go of with nothing of the session held: a key a leg names may keep a declaration
        // that is retracted as it drops, which takes the session (`WireKey`).
        drop((before, after));
        #[cfg(feature = "listen")]
        if let Some(waiting) = waiting {
            return self.wait_for_slots(&put, waiting, outcome);
        }
        outcome
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
        (mut stuck, deadline_us, mut left_us, mut waits): (
            FaceId,
            u64,
            u64,
            Vec<Arc<dyn LinkReadiness>>,
        ),
        mut outcome: Result<usize, FanoutError>,
    ) -> Result<usize, FanoutError> {
        loop {
            let waited = !waits.is_empty();
            if waited {
                wait_any(
                    &waits,
                    u32::try_from(left_us.div_ceil(1_000)).unwrap_or(u32::MAX),
                );
            }
            drop(waits);
            let Some(core) = self.live() else {
                return outcome;
            };
            let publishing = SendingOn::enter(&self.sending_on, PUBLISHING);
            let now_us = core.0.now_us();
            core.0.links.write_owed_now();
            let pass = Pass {
                from: order_key(stuck),
                probe: waited && now_us < deadline_us,
            };
            let (more, again) = self.fan_out_in(&core.0, put, &[], pass);
            if more.is_err() {
                outcome = more;
            }
            waits = match again {
                Some(_) => core.0.links.owing_waits(),
                None => Vec::new(),
            };
            let handed = self.send_handed(&core.0);
            drop(publishing);
            drop(core);
            drop(handed);
            match again {
                Some(face) => stuck = face,
                None => return outcome,
            }
            left_us = deadline_us.saturating_sub(now_us);
        }
    }

    /// Send `put` to each face whose link is up and to each group the session joined, but the
    /// faces in `skip`. Each face is sent the put, and one a face's link could not have carried is
    /// the one that is reported; a face whose link is down is skipped, as a send over it would.
    /// The face being sent to is marked as the one this publish holds ([`SendingOn`]) for as long
    /// as its send takes.
    fn fan_out(
        &self,
        core: &Core<L, C>,
        put: &Publication<'_>,
        skip: &[FaceId],
    ) -> Result<usize, FanoutError> {
        self.fan_out_in(core, put, skip, EVERY_FACE).0
    }

    /// [`Self::fan_out`] by `pass`: with `listen`, to the faces from the one whose order is
    /// `pass.from` on ([`order_key`]), with a send that does not wait for a slot when
    /// `pass.probe`. The faces are sent the put in order until one's link finds no outbound slot
    /// for it, which is answered beside the outcome and is sent nothing, nor are the faces after
    /// it, nor the groups.
    fn fan_out_in(
        &self,
        core: &Core<L, C>,
        put: &Publication<'_>,
        skip: &[FaceId],
        pass: Pass,
    ) -> (Result<usize, FanoutError>, Option<FaceId>) {
        let Publication {
            keyexpr,
            wire,
            payload,
            opts,
            meta,
        } = *put;
        let reliable = opts.reliable_bool();
        let express = meta.is_express();
        let priority = opts.priority_band();
        let mut outcome = Ok(0);
        #[cfg(not(feature = "listen"))]
        let _ = pass;
        for (face, actions) in core.ups_by_id() {
            if skip.contains(&face) {
                continue;
            }
            #[cfg(feature = "listen")]
            if order_key(face) < pass.from {
                continue;
            }
            let _sending = SendingOn::enter(&self.sending_on, face);
            // Each link names the key as its own key-wire form says.
            let wire = on_link(actions, keyexpr, wire);
            let suffix = wire.suffix.as_deref();
            // A publication is written from the borrowed key, bytes and metadata into the slot its
            // link lends, a plain Put by its own shorter writer, unless the session or the build
            // leaves it to the owned send below.
            let (mapping_id, lent_suffix) = if wire.is_literal() {
                (0, Some(keyexpr))
            } else {
                (wire.mapping_id, suffix)
            };
            let plain = opts.kind == SampleKind::Put && meta.is_plain_apart_from_qos();
            // A send that may not wait is told apart from one whose link has room: one with none
            // ends the fan-out at this face, and a chain of fragments, which such a send does not
            // begin, is sent as the caller's own send.
            #[cfg(feature = "listen")]
            if pass.probe {
                let probed = if plain {
                    actions.try_send_plain_put_qos(
                        mapping_id,
                        lent_suffix,
                        payload,
                        meta.qos,
                        reliable,
                        express,
                        priority,
                    )
                } else {
                    actions.try_send_publication_qos(
                        mapping_id,
                        lent_suffix,
                        opts.kind,
                        payload,
                        meta,
                        reliable,
                        express,
                        priority,
                    )
                };
                match probed {
                    Some(Ok(Probed::NoRoom)) => return (outcome, Some(face)),
                    Some(Ok(Probed::Sent)) => continue,
                    Some(Err(error)) => {
                        let sent = leg(Err(error));
                        if sent.is_err() {
                            outcome = sent;
                        }
                        continue;
                    }
                    Some(Ok(Probed::Chain)) | None => {}
                }
            }
            let lent = if plain {
                actions.send_plain_put_qos(
                    mapping_id,
                    lent_suffix,
                    payload,
                    meta.qos,
                    reliable,
                    express,
                    priority,
                )
            } else {
                actions.send_publication_qos(
                    mapping_id,
                    lent_suffix,
                    opts.kind,
                    payload,
                    meta,
                    reliable,
                    express,
                    priority,
                )
            };
            let sent = if let Some(lent) = lent {
                leg(lent)
            } else if !lent_push::LENT_PUBLICATION_MAY_DECLINE {
                // No send of this build declines one, so the owned builders are not linked.
                Err(FanoutError::ExceedsCapacity)
            } else {
                let push = match (opts.kind, wire.mapping_id) {
                    (SampleKind::Put, 0) => {
                        push_build::build_push_literal_with_meta(keyexpr, payload, meta)
                    }
                    (SampleKind::Del, 0) => {
                        push_build::build_push_del_literal_with_meta(keyexpr, meta)
                    }
                    (SampleKind::Put, mapping_id) => {
                        push_build::build_push_aliased_with_meta(mapping_id, suffix, payload, meta)
                    }
                    (SampleKind::Del, mapping_id) => {
                        push_build::build_push_del_aliased_with_meta(mapping_id, suffix, meta)
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
        for group in &core.groups {
            if skip.contains(&group.id()) {
                continue;
            }
            let _sending = SendingOn::enter(&self.sending_on, group.id());
            let sent = group.publish(GroupPut {
                keyexpr,
                wire,
                payload,
                kind: opts.kind,
                meta,
                reliable,
                priority,
            });
            if sent.is_err() {
                outcome = sent;
            }
        }
        (outcome, None)
    }

    /// Owe `leg` to the session's faces it was not dropped on: it is sent by whoever next holds
    /// the session for a publish or a read, ahead of what that holder sends, and here at once
    /// when the session is free by now. Past the legs of its priority the session holds at most
    /// it is dropped on the other faces too, as a message that finds its queue full is, and
    /// counted as the one drop it already is.
    fn hand_off(&self, leg: HandedLeg) {
        let priority = leg.opts.priority_band();
        let refused = {
            let mut handed = self.handed();
            let held = handed
                .iter()
                .filter(|owed| owed.opts.priority_band() == priority)
                .count();
            if held < self.handed_at_most[priority as usize] {
                handed.push_back(leg);
                self.owed.store(true, Ordering::SeqCst);
                None
            } else {
                Some(leg)
            }
        };
        // Let go of outside the lock, as a leg that was sent is (`Self::publish_to_link`).
        drop(refused);
        // The holder may have let go of the session since the publish found it held, with
        // nobody left to send what was handed.
        if let Some(core) = self.core.try_lock() {
            if !self.closed.load(Ordering::Acquire) {
                let sent = self.send_handed(&core.0);
                drop(core);
                drop(sent);
            }
        }
    }

    /// Send what was handed to the session ([`Self::hand_off`]), in the order it was handed, each
    /// leg to the faces it was not dropped on. The legs are given back to be let go of once the
    /// session is: a key a leg names may keep a declaration that is retracted as it drops.
    /// The queue is taken whole, not drained into another collection: the legs leave in the order
    /// they were handed either way, and a drain links the queue's drain and drop-guard code into
    /// every cooperative build for nothing it needs (measured 2026-11-21).
    fn send_handed(&self, core: &Core<L, C>) -> VecDeque<HandedLeg> {
        if !self.owed.load(Ordering::SeqCst) {
            return VecDeque::new();
        }
        self.send_handed_now(core)
    }

    /// [`Self::send_handed`], looking at the queue under its lock whatever `owed` says: what a
    /// read step sends, so a leg a publish passed over on a stale reading leaves on the next step.
    fn send_handed_now(&self, core: &Core<L, C>) -> VecDeque<HandedLeg> {
        let legs = {
            let mut handed = self.handed();
            self.owed.store(false, Ordering::SeqCst);
            core::mem::take(&mut *handed)
        };
        for leg in &legs {
            // The options the leg kept, over the attachment it kept beside them.
            let mut opts: PublishOptions<'_> = leg.opts.clone();
            opts.attachment = leg.attachment.as_deref();
            let meta = opts.push_metadata();
            // The caller was answered when the leg was handed.
            let _ = self.fan_out(
                core,
                &Publication {
                    keyexpr: &leg.keyexpr,
                    wire: &leg.wire,
                    payload: &leg.payload,
                    opts: &opts,
                    meta: &meta,
                },
                &leg.dropped_on,
            );
        }
        legs
    }

    /// The queue of handed legs, held.
    fn handed(&self) -> MutexGuard<'_, VecDeque<HandedLeg>> {
        #[cfg(test)]
        self.takes.handed.fetch_add(1, Ordering::Relaxed);
        lock(&self.handed)
    }

    /// The callback of subscriber `id`, while the subscriber is declared.
    fn subscriber_callback(&self, id: SubId) -> Option<SubscriberCallback> {
        #[cfg(test)]
        self.takes.callbacks.fetch_add(1, Ordering::Relaxed);
        match self.target(TargetKey::Subscriber(id))? {
            Target::Subscriber(callback) => Some(callback),
            _ => None,
        }
    }

    /// The callback of subscriber `id`, the `at`th of the sample a delivery hands, `at` under
    /// [`RESOLVED_SUBSCRIBERS`]: the one `resolved` kept for that place when it is `id`'s and
    /// nothing was taken out of the table since it was found, else the table's, kept there for the
    /// samples after. A subscriber undeclared since has none.
    fn resolved_subscriber_callback<'r>(
        &self,
        resolved: &'r mut Resolved,
        at: usize,
        id: SubId,
    ) -> Option<&'r SubscriberCallback> {
        drop(resolved.take_stale(self.removed.load(Ordering::SeqCst)));
        let kept = &mut resolved.callbacks[at];
        if !matches!(kept, Some((held, _)) if *held == id) {
            *kept = self.subscriber_callback(id).map(|callback| (id, callback));
        }
        kept.as_ref().map(|(_, callback)| callback)
    }

    /// A publish's leg to the session's own subscribers, when its destination admits them: the
    /// subscribers whose origin admits it, as the registry's loopback finds them, are each handed
    /// it here, with no lock of the session held, inside the put as zenoh-pico's does. A callback
    /// another thread is running is waited for, as pico's lock is. One the putting thread is
    /// inside of cannot be called again from inside itself, where pico's would be: it is handed
    /// the sample from the delivery lane once it returns, and when the lane has no room for it
    /// the put is refused before any subscriber is handed it. The number of subscribers reached.
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
        // SAFETY (each hold of the lane below): the session's lock is held (`core`).
        unsafe { self.samples.held() }.capture();
        wz_session_core::pubsub::LocalSubscribers::local_publish(
            &mut core.0.registry.borrow_mut().app.subscribers,
            &mut (),
            &sample,
        );
        let reached = unsafe { self.samples.held() }.captured();
        let inside = |id: &SubId| self.deliveries.runs_here(TargetKey::Subscriber(*id));
        let mut later: BoundedVec<
            SubId,
            { caps::MAX_SUBSCRIPTIONS },
            wz_session_core::bounded::Static,
        > = BoundedVec::new_static();
        for id in reached.iter().filter(|id| inside(id)) {
            let kept = later.push(*id);
            debug_assert!(kept.is_ok(), "no more subscribers than were reached");
        }
        // What waits for a callback running on this thread is queued while the session is held,
        // as every writer of the lane queues.
        if !later.is_empty() {
            let mut lane = unsafe { self.samples.held() };
            if !lane.takes_sample(&sample, later.len()) {
                return Err(FanoutError::LocalNoRoom);
            }
            lane.offer_to(&later, &sample);
        }
        drop(core);
        {
            // A callback that steps the session from inside the put hands out nothing itself, as
            // one inside a delivery does: what the lane holds may be for a callback running here.
            let _delivering = self.deliveries.enter();
            for id in reached.iter().filter(|id| !inside(id)) {
                if let Some(callback) = self.subscriber_callback(*id) {
                    let _running = self.deliveries.run(TargetKey::Subscriber(*id));
                    callback.hand(&sample);
                }
            }
        }
        self.deliver();
        Ok(reached.len())
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
        self.end_leg_now(leg);
    }

    /// Drop leg `leg`'s callback here, its end decided by the session itself (cancelled, or never
    /// sent), and leave no end of it waiting for a delivery.
    #[cfg(feature = "query")]
    fn end_leg_now(&self, leg: u64) {
        self.gets.ended.lock().forget(leg);
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
        // The session's own get is answered to its pending entry, which is the registry's, and
        // handed out when the answer ends (`Self::answer`).
        #[cfg(feature = "local-queryable")]
        if generation == query::LOCAL_QUERY {
            let reply = wz_session_core::query::QueryReply::from_parts(&parts);
            core.0
                .registry
                .borrow_mut()
                .local
                .replies
                .deliver_local_reply(&reply.into());
            return Ok(());
        }
        if let Some(route) = core.0.answer_route(generation) {
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
    fn answer(&self, generation: u64, rid: wz_session_core::wire_id::RequestId, release: bool) {
        let Some(core) = self.live() else {
            return;
        };
        // The session's own get is answered to its pending entry, which is the registry's.
        #[cfg(feature = "local-queryable")]
        if generation == query::LOCAL_QUERY {
            if release && lock(&self.plane.holds).release(generation, rid).is_some() {
                core.0
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
        if release {
            let due = lock(&self.plane.holds).release(generation, rid);
            if let (Some(qos), Some(route)) = (due, core.0.answer_route(generation)) {
                route.send_response_final(rid, qos);
            }
        }
        // A group's sink only stages: a kept query answered from the program's own thread would
        // otherwise leave when the read task's wait ends, up to the group's tick a leg.
        #[cfg(feature = "group")]
        core.0.write_answers(generation);
    }

    /// The callback `key` names, while its owner holds it: the one look in the table every
    /// delivery makes, the handle cloned out so the callback runs with the table's lock let go.
    fn target(&self, key: TargetKey) -> Option<Target> {
        lock(&self.targets)
            .iter()
            .find(|(t, _)| *t == key)
            .map(|(_, target)| target.clone())
    }

    /// Take the callback `key` names out of the targets; the caller drops it with no lock held.
    fn take_target(&self, key: TargetKey) -> Option<Target> {
        let taken = {
            let mut targets = lock(&self.targets);
            let at = targets.iter().position(|(t, _)| *t == key)?;
            self.removed.fetch_add(1, Ordering::SeqCst);
            targets.remove(at).1
        };
        // What the deliveries kept goes first, so the caller's drop of the callback is its last.
        self.forget_resolved();
        Some(taken)
    }

    /// Let go of the callbacks the deliveries kept from before the last removal from the table,
    /// when no delivery holds them now; one that does lets go of them as it ends
    /// ([`Self::let_go_of_resolved`]).
    fn forget_resolved(&self) {
        let Some(mut kept) = self.resolved.try_take() else {
            return;
        };
        let stale = kept.take_stale(self.removed.load(Ordering::SeqCst));
        drop(kept);
        drop(stale);
    }

    /// End a delivery's hold on the kept callbacks: what it kept from before a removal is let go
    /// of, with no lock held, and a removal counted after that, which found them held, is seen to.
    fn let_go_of_resolved(&self, kept: Option<TryHeld<'_, Resolved>>) {
        let Some(mut kept) = kept else {
            return;
        };
        let stale = kept.take_stale(self.removed.load(Ordering::SeqCst));
        let seen = kept.removed;
        drop(kept);
        drop(stale);
        if self.removed.load(Ordering::SeqCst) != seen {
            self.forget_resolved();
        }
    }

    /// Step the session until it has nothing more to do, move its link on, and notice a session
    /// that ended. The step reads the clock once, after its tasks ran, and measures everything it
    /// does by that reading, which it returns; `None` once the session ended.
    fn step(&self, core: &mut Core<L, C>) -> Option<u64> {
        core.run_tasks();
        let now_us = core.now_us();
        // A link's receive sweeps nothing, so the session ends the chains of its one reassembly
        // Router past their deadline here, once a step and by its reading, whichever link's task
        // ran; on the epoch its links staged them on, which is not the clock's own.
        let chain_ms = core.session_time.ms_at(now_us);
        core.router.sweep(chain_ms);
        // A get whose deadline has passed ends with zenoh's timeout reply and its Final, here,
        // because this is what runs on every step and the entries are the registry's.
        #[cfg(feature = "query")]
        {
            let now_ms = now_us / 1000;
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
        if core.poll_links(redial_ms, now_us).is_err() {
            self.closed.store(true, Ordering::Release);
            return None;
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
        Some(now_us)
    }

    /// Hold the Interest for `keyexpr` on `plane`, sending it in `form` for its first holder.
    /// Refused, with nothing held or sent, when a first holder finds no row of the Interests'
    /// table free or the session with no entity id left for it.
    fn acquire_interest(
        &self,
        core: &mut Core<L, C>,
        plane: FilterPlane,
        keyexpr: &str,
        form: InterestAsk<'_>,
    ) -> Result<(), Declined> {
        if let Some(hold) = core
            .interests
            .iter_mut()
            .find(|h| h.plane.same_kind(plane) && h.keyexpr == keyexpr)
        {
            hold.holds += 1;
            return Ok(());
        }
        // A first holder takes a row of the Interests' table, which is lent one for each write
        // filter and matching listener: each of them takes a row of its own table first.
        if core.interests.free_slots() == 0 {
            return Err(Declined::TableFull);
        }
        // zenoh-pico's Interest takes the session's next entity id
        // (`vendor/zenoh-pico/src/net/primitives.c` @ `intr._id = _z_get_entity_id(zn);`).
        let Some(key) = core.row_key(keyexpr) else {
            return Err(core.key_refusal(keyexpr));
        };
        let Some(interest_id) = self.next_entity_id() else {
            return Err(Declined::NoEntityId);
        };
        // The rest of the key the form names is read from the row's own key, not copied.
        let suffix_at = suffix_place(keyexpr, form.suffix);
        let hold = InterestHold {
            plane,
            keyexpr: key,
            interest_id: u64::from(interest_id),
            form: InterestForm {
                mapping_id: form.mapping_id,
                suffix: if suffix_at.is_some() {
                    None
                } else {
                    form.suffix.map(String::from)
                },
                aggregate: form.aggregate,
            },
            suffix_at,
            holds: 1,
        };
        core.announce(Kind::Interest, |actions| hold.send(actions));
        // The row was found free above, under the lock still held.
        let held = core.interests.push(hold).is_ok();
        debug_assert!(held, "the Interests' table had the row the check found");
        if held {
            Ok(())
        } else {
            Err(Declined::TableFull)
        }
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
        opts: &QueryOptions,
    ) -> query::Asked {
        let rid = own.rid();
        let qos = opts.qos.unwrap_or(QosLevel::DEFAULT);
        let envelope = QueryEnvelope {
            rid,
            target: opts.effective_target(),
            qos,
        };
        let query = opts.loopback_query();
        // The session's queryables only copy a query out and hold its Final (`QueryPlane::arrive`),
        // so none stages a reply here: the stage the registry is handed has no room.
        let mut staged = ReplyStage::<Lent>::default();
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
        lock(&self.plane.holds).owe(query::LOCAL_QUERY, rid, qos);
        if own.release().is_some() {
            gets.replies.deliver_local_final(rid);
        }
        self.plane.take_asked()
    }

    /// Hand the session's own get to each of its queryables it was asked of, inside the get and
    /// with no lock held, as zenoh-pico's `_z_session_deliver_query_locally` runs them on the
    /// caller's thread, then hand out what they answered. A queryable whose callback this thread is
    /// inside of would wait on itself if called here: its query is kept, copied, for the delivery
    /// that callback returns to.
    #[cfg(feature = "local-queryable")]
    fn hand_own_get(&self, asked: &query::Asked, get: &query::OwnGet<'_>) {
        {
            // A callback that steps the session or asks a get from inside one of these hands out
            // nothing itself, as one inside a delivery does.
            let _delivering = self.deliveries.enter();
            for &id in asked.iter() {
                if self.deliveries.runs_here(TargetKey::Queryable(id)) {
                    self.plane.queries.lock().push_back((
                        id,
                        query::OwnedQuery::of(get),
                        query::LOCAL_QUERY,
                    ));
                } else {
                    self.run_queryable(id, get, query::LOCAL_QUERY);
                }
            }
        }
        self.deliver();
    }

    /// The queryables' plane's counterpart of [`Self::reevaluate_subscriber_matching`].
    #[cfg(feature = "local-queryable")]
    fn reevaluate_queryable_matching(core: &Core<L, C>) {
        core.registry.borrow_mut().reevaluate_querier_watches();
    }

    /// Whether write filter `id` holds what it filters back: a filter is created suppressing,
    /// until a peer declares what it counts, or the session itself does when it counts its own
    /// (`vendor/zenoh-pico/src/net/filtering.c` @ `ctx->state = WRITE_FILTER_ACTIVE`). A filter
    /// the session does not hold holds nothing back.
    fn filter_active_in(core: &Core<L, C>, id: FilterId) -> bool {
        core.filters
            .iter()
            .find(|f| f.id == id)
            .is_some_and(|f| !Self::filter_matches(core, f))
    }

    /// A plain Put on `mapping_id` (the literal `keyexpr` when it is `0`) sent from `params` to
    /// every link, once the write filter let it through: `NotPlain`, with nothing sent, when a
    /// subscriber of the session, a group or a link that rewrites keys wants it the general way.
    fn put_plain_in(
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
            && core
                .registry
                .borrow()
                .app
                .subscribers
                .has_local_matching(keyexpr)
        {
            return FilteredPut::NotPlain;
        }
        if !params.destination.allows_remote() {
            return FilteredPut::Sent(Ok(0));
        }
        // A group is sent a put by the general publish, which pushes it onto the group's stage.
        #[cfg(feature = "group")]
        if !core.groups.is_empty() {
            return FilteredPut::NotPlain;
        }
        // Asked of every link before any is sent to, so the put goes plain to all of them or to
        // none: a link that rewrites what it originates (a routing namespace) takes the general
        // publish for the whole of it. Its namespace is installed before the session sends
        // anything, so no link answers otherwise below.
        if core.ups().any(|actions| actions.rewrites_originated_keys()) {
            return FilteredPut::NotPlain;
        }
        let suffix = (mapping_id == 0).then_some(keyexpr);
        let mut outcome = Ok(0);
        for actions in core.ups() {
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

    /// [`Self::filter_active_in`], except on a session that holds a group the filter does not
    /// ask: such a group is sent a write whatever the filter says, as the tokio engine sends one
    /// (`GroupDeclarations::asks_for_filters`), since on it zenoh-pico sends what its filter would
    /// hold back. Without a group no write must reach anyone regardless.
    fn holds_back_in(core: &Core<L, C>, id: FilterId) -> bool {
        #[cfg(feature = "group")]
        if core
            .groups
            .iter()
            .any(|group| !group.declarations().asks_for_filters())
        {
            return false;
        }
        Self::filter_active_in(core, id)
    }

    /// What write filter `entry` reads: a peer's declaration, or with `count_local` one of the
    /// session's own. The peers' half is the one kept ([`Self::peers_match_kept`]); the session's
    /// own subscribers change by no face and are asked each time.
    fn filter_matches(core: &Core<L, C>, entry: &FilterEntry) -> bool {
        Self::peers_match_kept(core, entry)
            || (entry.count_local && Self::local_matches(core, entry.plane, &entry.keyexpr))
    }

    /// Whether a peer declared what filter `entry` counts: the answer it keeps while no face's
    /// tables were written since it was read, else read again and kept.
    fn peers_match_kept(core: &Core<L, C>, entry: &FilterEntry) -> bool {
        let registry = core.registry.borrow();
        let written = registry.faces_written();
        if let Some((read_at, matched)) = entry.peers.get() {
            if read_at == written {
                return matched;
            }
        }
        let matched = registry.peers_declare(entry.plane, &entry.keyexpr);
        entry.peers.set(Some((written, matched)));
        matched
    }

    /// How often what the peers declared was searched since the open: what a test of the cost of
    /// a filtered put counts. Read under the lock, uncounted as a take.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn peer_looks(&self) -> usize {
        self.core.lock().0.registry.borrow().peer_looks()
    }

    /// Tell every matching listener on the subscribers' plane that counts the session's own
    /// subscribers whether it now matches, after one was declared or retracted here: the
    /// registry reads the remote half off its own membership and asks this for the local half.
    #[cfg(feature = "local-subscriber")]
    fn reevaluate_subscriber_matching(core: &Core<L, C>) {
        core.registry.borrow_mut().reevaluate_publisher_watches();
    }

    /// Start the read task on the thread `spawn` makes; idempotent. A system that gives no thread
    /// is answered (`NoThread`), and the task is left not running, so a later start tries again:
    /// zenoh-pico's start answers its task creation's error the same way, and a panic here would
    /// leave the C caller nothing to read on a build that aborts on one.
    pub(crate) fn start_reader(
        &self,
        spawn: impl FnOnce(ReaderBody) -> Option<(JoinHandle, ThreadId)>,
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
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let body: ReaderBody =
            Box::new(
                move || {
                    while !stopped.load(Ordering::Acquire) && engine.read(false).is_ok() {}
                },
            );
        let (thread, id) = spawn(body).ok_or(ReadTaskStartRefused::NoThread)?;
        *reader = Some(ReadTask { stop, thread, id });
        Ok(())
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
        u32_id_taken(self.next_entity.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            next_u32_id,
        ))
    }

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

    fn next_peer(&self, from: u64) -> Option<(u64, PeerIdentity)> {
        let core = self.live()?;
        // A face's id is its key: faces are numbered as they come and keep their id while they
        // stand. A group's members are not listed here, as the tokio engine lists none:
        // `next_group_member` answers them, whatever role they announced.
        core.0
            .ups_by_id()
            .filter(|(id, actions)| *id >= from && actions.is_established())
            .filter_map(|(id, actions)| {
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
    fn next_group_member(&self, from: u64) -> Option<(u64, SessionZid)> {
        let core = self.live()?;
        let (first_group, first_member) = (from >> 32, from & u64::from(u32::MAX));
        core.0
            .groups
            .iter()
            .enumerate()
            .skip(usize::try_from(first_group).ok()?)
            .find_map(|(at, group)| {
                let from_member = if at as u64 == first_group {
                    first_member
                } else {
                    0
                };
                let (member, zid) = group.member_zid_from(usize::try_from(from_member).ok()?)?;
                Some((((at as u64) << 32) | member as u64, zid))
            })
    }

    /// Each group's session sends its JOIN at its next step, which this call takes, as the tokio
    /// engine's group sends one at once.
    #[cfg(feature = "group")]
    fn send_join_on_groups(&self) -> Result<usize, Declined> {
        let mut guard = self.live().ok_or(Declined::Closed)?;
        let core = &mut guard.0;
        let asked = core.groups.iter().filter(|group| group.ask_join()).count();
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
            .map_or_else(Vec::new, |core| core.0.standing_faces())
    }

    #[cfg(feature = "connectivity")]
    fn watch_faces(&self, sink: FaceEventSink) -> Result<u64, Declined> {
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
    /// stages from here on (`decl_watch`). A refused sink is let go of with no lock held.
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
        let observed = self
            .decl_watches
            .observe(&mut core.registry.borrow_mut().app, plane);
        if let Err(refused) = observed {
            drop(guard);
            drop(sink);
            return Err(refused);
        }
        let id = self.decl_watches.add(plane, sink);
        let registry = core.registry.borrow();
        for face in core.links.faces() {
            let (Link::Up(wire) | Link::Opening { wire, .. }) = &face.link else {
                continue;
            };
            if let Some(tables) = registry.tables_of(face.id) {
                self.decl_watches
                    .tell_held(id, plane, tables, || wire.actions.peer_zid());
            }
        }
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
                let mut registry = core.0.registry.borrow_mut();
                self.decl_watches.undeclare(&mut registry.app, id)
            }
            None => None,
        };
        let found = sink.is_some();
        drop(sink);
        found
    }

    fn has_transport(&self) -> bool {
        self.live().is_some_and(|core| core.0.holds_transport())
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
        let sent = sent + self.publish_to_subscribers(keyexpr, payload, opts)?;
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
        // A closed session declares nothing, and takes no id for what it does not declare.
        let mut guard = self.live().ok_or(Declined::Closed)?;
        let core = &mut guard.0;
        // The subscriber is one row of the session core's table. A full table refuses it before
        // it takes an id, registers or sends anything; the sink goes with the refusal.
        if core.registry.borrow().app.subscribers.is_full() {
            return Err(Declined::TableFull);
        }
        let id = self.next_entity_id().ok_or(Declined::NoEntityId)?;
        // The row goes at the end of the table, where the replay finds it.
        let at = core.registry.borrow().app.subscribers.len();
        let row = SubscriberRow {
            id,
            retraction,
            wire,
            lane: self.samples.clone(),
            callback: None,
        };
        // A registration the table refuses (a key longer than a row holds or with no room in the
        // key arena) is a refused declaration, told as one: an id answered for it would name a
        // subscriber that hears nothing and was never announced.
        let registered =
            core.registry
                .borrow_mut()
                .app
                .subscribers
                .register_sink(keyexpr, allowed_origin, row);
        registered?;
        // The declaration states no choice about the timestamp, so it takes the session's
        // `entity-timestamp-opt-in`, as the policy the session was opened under resolves it.
        let callback: SubscriberCallback = Arc::new(LiveCallback::new(sample_shown(
            exposed_by(&core.policy),
            sink(),
        )));
        if let Some((_, row)) = core.registry.borrow_mut().app.subscribers.row_at_mut(at) {
            row.callback = Some(Arc::clone(&callback));
        }
        lock(&self.targets).push((TargetKey::Subscriber(id), Target::Subscriber(callback)));
        // Each link is told it from the row, which names the key as the table keeps it.
        core.announce_subscriber(at);
        #[cfg(feature = "group")]
        {
            let registry = core.registry.borrow();
            if let Some((keyexpr, row)) = registry.app.subscribers.row_at(at) {
                core.announce_to_groups(GroupEntity {
                    what: GroupDeclaration::Subscriber,
                    entity: id,
                    keyexpr,
                    wire: &row.wire,
                    retraction: row.retraction.as_ref(),
                    allowed_origin,
                });
            }
        }
        // A matching listener that counts the session's own subscribers may now match: it is
        // told, outside the lock.
        #[cfg(feature = "local-subscriber")]
        {
            Self::reevaluate_subscriber_matching(core);
            drop(guard);
            self.deliver();
        }
        Ok(id)
    }

    #[inline(never)]
    fn undeclare_subscriber(&self, id: SubId) {
        // A liveliness subscriber's id is one of these too (the port's one id space): its
        // registration goes and its Interest ends.
        #[cfg(feature = "liveliness")]
        let live = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let at = core.live_subs.iter().position(|s| s.id == id)?;
            let links = core.retract(Kind::LiveSub, at);
            let mut entry = core.live_subs.remove(at);
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
            // Under the lock, as the row is dropped after it (`KeyRef::let_go`).
            entry.keyexpr.let_go();
            Some(entry)
        });
        #[cfg(feature = "liveliness")]
        if live.is_some() {
            let callback = self.take_target(TargetKey::Liveliness(id));
            drop((live, callback));
            return;
        }
        // The row is taken out of the table under the lock and let go of after it: its key may hold
        // a declaration whose release reaches the session (`WireKey`).
        let entry = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let at = core
                .registry
                .borrow()
                .app
                .subscribers
                .position_of(|row| row.id == id)?;
            let links = core.retract(Kind::Subscriber, at);
            #[cfg(feature = "group")]
            core.retract_from_groups(id);
            let row = core.registry.borrow_mut().app.subscribers.take_at(at)?;
            for actions in links {
                row.retract(&actions);
            }
            // One that counted it may now match no more.
            #[cfg(feature = "local-subscriber")]
            Self::reevaluate_subscriber_matching(core);
            Some(row)
        });
        let callback = self.take_target(TargetKey::Subscriber(id));
        // A delivery that copied the callback out of the row before hands it nothing more.
        if let Some(Target::Subscriber(callback)) = &callback {
            callback.retire();
        }
        drop((entry, callback));
        #[cfg(feature = "local-subscriber")]
        self.deliver();
    }

    #[inline(never)]
    fn acquire_keyexpr(&self, keyexpr: &str) -> Result<ExprId, Declined> {
        let mut core = self.live().ok_or(Declined::Closed)?;
        let core = &mut core.0;
        if let Some(entry) = core
            .keyexprs
            .borrow_mut()
            .iter_mut()
            .find(|e| e.keyexpr == keyexpr)
        {
            entry.holds += 1;
            return Ok(entry.id);
        }
        // A key no declaration holds yet takes a row; a full table refuses it before an id is
        // taken or anything is sent, and so does a key the session cannot hold.
        if core.keyexprs.borrow().free_slots() == 0 {
            return Err(Declined::TableFull);
        }
        let Some(key) = core.row_key(keyexpr) else {
            return Err(core.key_refusal(keyexpr));
        };
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
            return Err(Declined::NoEntityId);
        }
        // A declaration a link refuses is not made, and the links that took it take it back; one
        // made while a link is down, or that a replay has not reached, is sent in its turn. A link
        // refuses one it cannot carry.
        let taken = core.announce_or_undo(
            Kind::Keyexpr,
            |actions| actions.send_declare_keyexpr(id, keyexpr).is_ok(),
            |actions| actions.send_undeclare_kexpr(id),
        );
        if !taken {
            return Err(Declined::ExceedsCapacity);
        }
        // And each group told the session's keyexprs, as a link is.
        #[cfg(feature = "group")]
        for group in &core.groups {
            group.announce_keyexpr(id, keyexpr);
        }
        core.next_mapping = id.wrapping_add(1);
        keep(
            &mut *core.keyexprs.borrow_mut(),
            KexprEntry {
                id,
                keyexpr: key,
                holds: 1,
            },
        );
        Ok(id)
    }

    #[inline(never)]
    fn release_keyexpr(&self, mapping_id: ExprId) {
        let Some(mut core) = self.live() else {
            return;
        };
        let core = &mut core.0;
        let (at, held) = {
            let mut keyexprs = core.keyexprs.borrow_mut();
            let Some(at) = keyexprs.iter().position(|e| e.id == mapping_id) else {
                return;
            };
            keyexprs[at].holds -= 1;
            (at, keyexprs[at].holds != 0)
        };
        if !held {
            // The links are asked before the row goes, and the row goes before they are told: a
            // send never finds the table borrowed.
            let links = core.retract(Kind::Keyexpr, at);
            core.keyexprs.borrow_mut().remove(at);
            for actions in links {
                actions.send_undeclare_kexpr(mapping_id);
            }
            #[cfg(feature = "group")]
            for group in &core.groups {
                group.retract_keyexpr(mapping_id);
            }
        }
    }

    #[inline(never)]
    fn retain_keyexpr(&self, mapping_id: ExprId) {
        let Some(core) = self.live() else {
            return;
        };
        let mut keyexprs = core.0.keyexprs.borrow_mut();
        if let Some(entry) = keyexprs.iter_mut().find(|e| e.id == mapping_id) {
            entry.holds = entry.holds.saturating_add(1);
        }
    }

    fn key_arena(&self) -> Option<&dyn SessionKeys> {
        Some(self)
    }

    fn place_lender(&self) -> Option<&dyn PlaceLender> {
        Some(self)
    }

    fn keyexpr_declarations(&self) -> Vec<(ExprId, String)> {
        self.live()
            .map(|core| {
                let keyexprs = core.0.keyexprs.borrow();
                keyexprs
                    .iter()
                    .map(|e| (e.id, String::from(e.keyexpr.as_str())))
                    .collect()
            })
            .unwrap_or_default()
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
        let watched = Watched::of(plane, keyexpr, count_local).ok_or(Declined::NotBuilt)?;
        let mut guard = self.live().ok_or(Declined::Closed)?;
        let core = &mut guard.0;
        // A full table refuses the listener before its Interest is asked.
        if core.matches.free_slots() == 0 {
            return Err(Declined::TableFull);
        }
        // So does a key the session cannot hold.
        let Some(key) = core.row_key(keyexpr) else {
            return Err(core.key_refusal(keyexpr));
        };
        // A listener whose Interest the session cannot hold is not declared, as a closed session
        // declares none: it would never hear a peer.
        self.acquire_interest(
            core,
            plane,
            keyexpr,
            InterestAsk {
                mapping_id: 0,
                suffix: Some(keyexpr),
                aggregate: false,
            },
        )?;
        let id = core.next_match;
        core.next_match += 1;
        let local = count_local && Self::local_matches(core, plane, keyexpr);
        // The sink is in place before the watch is registered: a registration that already
        // matches reports it as it registers, and a delivery on another thread may hand that out
        // before this call reaches its own.
        lock(&self.targets).push((TargetKey::Matching(id), Target::Matching(sink)));
        let report = registry::FlipReport {
            queue: self.matching.clone(),
            id,
        };
        // The watch is in the registry of what `plane` counts, with the criterion its write
        // filter reads ([`Self::filter_matches`]), so the listener and the filter cannot differ.
        // An already-matching registration is told so by the registry as it registers, as
        // zenoh-pico tells it (`vendor/zenoh-pico/src/net/filtering.c` @
        // `_z_write_filter_ctx_add_callback`): that is the one report of it, and a second would
        // take the first back (`MatchFlips::flip`).
        let watch = {
            let mut registry = core.registry.borrow_mut();
            match watched {
                Watched::Publishers(criterion) => {
                    registry.watch_publishers(criterion, local, report)
                }
                #[cfg(any(feature = "query", feature = "queryable"))]
                Watched::Queriers(criterion) => registry.watch_queriers(criterion, local, report),
            }
        };
        keep(
            &mut core.matches,
            MatchEntry {
                id,
                plane,
                watch,
                keyexpr: key,
            },
        );
        drop(guard);
        self.deliver();
        Ok(id)
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
                        #[cfg(any(feature = "query", feature = "queryable"))]
                        FilterPlane::Queryables { .. } => registry
                            .app
                            .remote_queryables
                            .undeclare_matching_listener(entry.watch),
                        // A build that leaves the plane out holds no listener of it (`counts`).
                        #[cfg(not(any(feature = "query", feature = "queryable")))]
                        FilterPlane::Queryables { .. } => false,
                    };
                }
                Self::release_interest(core, entry.plane, &entry.keyexpr);
            }
        }
        self.matching.lock().forget(id);
        drop(self.take_target(TargetKey::Matching(id)));
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
        // A publisher's filter is held to MAX_PUBLISHERS and a querier's to MAX_QUERIERS, in the
        // one table lent for both: one past its plane's count is refused before its Interest is
        // asked or an id taken.
        let most = match plane {
            FilterPlane::Subscribers => core.entities.publishers,
            FilterPlane::Queryables { .. } => core.entities.queriers,
        };
        let held_of_plane = core
            .filters
            .iter()
            .filter(|f| f.plane.same_kind(plane))
            .count();
        if held_of_plane >= most || core.filters.free_slots() == 0 {
            return Err(Declined::TableFull);
        }
        // So is a key the session cannot hold.
        let Some(key) = core.row_key(keyexpr) else {
            return Err(core.key_refusal(keyexpr));
        };
        // The id this filter spent of its own, when it spent one: its Interest's, when it is the
        // first to hold it, or the one taken for a filter that sends none.
        let mut spent = None;
        // A filter whose Interest the session cannot hold, or that finds no id left, is refused
        // and spends no filter id.
        match ask {
            Some(form) => {
                let before = core.interests.len();
                self.acquire_interest(core, plane, keyexpr, form)?;
                if core.interests.len() > before {
                    spent = core.interests.last().map(|hold| hold.interest_id);
                }
            }
            // The entity id is taken whether the Interest is sent or not, as zenoh-pico's
            // `_z_add_interest` takes it before it decides.
            None => {
                let taken = self.next_entity_id().ok_or(Declined::NoEntityId)?;
                spent = Some(u64::from(taken));
            }
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
                    group.ask_filter(id, interest_id, plane, keyexpr, wire);
                }
            }
        }
        #[cfg(not(feature = "group"))]
        let _ = (spent, wire);
        keep(
            &mut core.filters,
            FilterEntry {
                id,
                plane,
                keyexpr: key,
                asked: ask.is_some(),
                count_local,
                peers: Cell::new(None),
                plain: Cell::new(None),
            },
        );
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
        self.put_through_filter(filter, keyexpr, payload, Some((mapping_id, *params)))
    }

    fn keep_write_filter_plain(&self, filter: FilterId, plain: Option<(PlainPutParams, ExprId)>) {
        let Some(core) = self.live() else {
            return;
        };
        if let Some(entry) = core.0.filters.iter().find(|entry| entry.id == filter) {
            entry.plain.set(plain);
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
                let Some((params, mapping_id)) = core
                    .filters
                    .iter()
                    .find(|entry| entry.id == filter)
                    .and_then(|entry| entry.plain.get())
                else {
                    return FilteredPut::NotPlain;
                };
                // A link that names keys its own way is sent the general way, which names the key
                // as its form says: no declared id goes to every link at once.
                #[cfg(feature = "shared-key-ids")]
                if core.key_ids.is_some() || core.key_forms.departs_from_declared() {
                    return FilteredPut::NotPlain;
                }
                (mapping_id, params)
            }
        };
        Self::put_plain_in(core, keyexpr, mapping_id, payload, &params)
    }

    /// Each group the session joined takes the step too, and is counted as a link is: a group's
    /// window holds what the session sends on the group, as pico's batch holds what it sends on
    /// its multicast transport, and is written by a flush or a stop on the caller's thread, as a
    /// link's is.
    fn batch_all(&self, step: BatchStep) -> usize {
        self.live().map_or(0, |core| {
            let links = core
                .0
                .ups()
                .filter(|actions| {
                    match step {
                        BatchStep::Start => actions.batch_start(),
                        BatchStep::Flush => actions.batch_flush(),
                        BatchStep::Stop => actions.batch_stop(),
                    }
                    .is_ok()
                })
                .count();
            #[cfg(feature = "group")]
            let groups = core
                .0
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
            links + groups
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
        let mut guard = self.live().ok_or(Declined::Closed)?;
        let core = &mut guard.0;
        // A full table refuses the queryable before it takes an id, registers or sends anything;
        // the sink goes with the refusal.
        if core.queryables.free_slots() == 0 {
            return Err(Declined::TableFull);
        }
        // So does a key the session cannot hold.
        let Some(key) = core.row_key(keyexpr) else {
            return Err(core.key_refusal(keyexpr));
        };
        let id = self.next_entity_id().ok_or(Declined::NoEntityId)?;
        // The registry's queryable only copies a query out and holds its Final; the callback
        // `sink` mints runs when the deliveries are handed out (`query`).
        let plane = self.plane.clone();
        let registration = core.registry.borrow_mut().app.queryables.register_sink(
            keyexpr,
            allowed_origin,
            complete,
            BoxedQuerySink::new(move |query, _in_place| plane.arrive(id, query)),
        )?;
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
            keyexpr: key,
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
        keep(&mut core.queryables, entry);
        // A matching listener that counts the session's own queryables may now match: it is told,
        // outside the lock.
        #[cfg(feature = "local-queryable")]
        {
            Self::reevaluate_queryable_matching(core);
            drop(guard);
            self.deliver();
        }
        Ok(id)
    }

    #[cfg(feature = "query")]
    fn get_on_wire(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        opts: &QueryOptions,
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
            let rid = guard.0.next_local_request;
            guard.0.next_local_request = rid.wrapping_add(1);
            Some(query::OwnFinalHold::take(&self.plane.holds, rid).ok_or(Declined::TableFull)?)
        } else {
            None
        };
        let (faces, expose) = {
            let guard = self.live().ok_or(Declined::Closed)?;
            // `entity-timestamp-opt-in`: the query's choice, or the session's policy when it
            // states none, applied to every leg's callback, after its replies are consolidated.
            let expose = opts.expose_timestamp_by(&guard.0.policy);
            let faces = if opts.allowed_destination.allows_remote() {
                guard.0.up_faces()
            } else {
                Vec::new()
            };
            (faces, expose)
        };
        let mut leg = || reply_shown(expose, leg());
        let mut issued = 0;
        // The legs refused for want of a row in their face's table of pending gets: a get that
        // issued none, and found no room for one, is refused whole.
        let mut unheld = 0usize;
        for face in faces {
            let leg_id = self.next_local_id();
            let Some(mut guard) = self.live() else {
                return issued_so_far(issued);
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
                get::reply_sink(leg_id, &self.gets, &self.samples),
            );
            // One Final: the face's peer's. Registered before the request goes out, so no answer
            // can arrive before its entry.
            let registered = core.registry.borrow_mut().face_mut(face).map(|tables| {
                tables.gets.replies.register_sink(
                    rid,
                    1,
                    deadline_ms,
                    ReplyAcceptance::for_query(keyexpr, opts.effective_accept_replies()),
                    sink,
                )
            });
            match registered {
                Some(Ok(_)) => {}
                Some(Err(RegisterError::TableFull)) => {
                    unheld += 1;
                    continue;
                }
                _ => continue,
            }
            self.hold_leg(leg_id, leg());
            // The link names the key as its own key-wire form says.
            let wire = on_link(&actions, keyexpr, wire);
            let (mapping_id, suffix) = if wire.is_literal() {
                (0, Some(keyexpr))
            } else {
                (wire.mapping_id, wire.suffix.as_deref())
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
                if let Some(tables) = core.registry.borrow_mut().face_mut(face) {
                    tables.gets.replies.unregister(rid);
                }
                drop(guard);
                self.end_leg_now(leg_id);
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
                return issued_so_far(issued);
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
                get::reply_sink(leg_id, &self.gets, &self.samples),
            );
            // Registered before the query is queued, as a link's leg is before it is sent.
            let registered = core.registry.borrow_mut().face_mut(face).map(|tables| {
                tables.gets.replies.register_sink(
                    rid,
                    finals,
                    deadline_ms,
                    ReplyAcceptance::for_query(keyexpr, opts.effective_accept_replies()),
                    sink,
                )
            });
            match registered {
                Some(Ok(_)) => {}
                Some(Err(RegisterError::TableFull)) => {
                    unheld += 1;
                    continue;
                }
                _ => continue,
            }
            self.hold_leg(leg_id, leg());
            if !group.ask(rid, keyexpr, wire, opts.query_parts()) {
                // Nothing was queued: the entry and the leg go, and the leg is over.
                if let Some(tables) = core.registry.borrow_mut().face_mut(face) {
                    tables.gets.replies.unregister(rid);
                }
                drop(guard);
                self.end_leg_now(leg_id);
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
            let timeout_ms = opts.effective_timeout_ms();
            let deadline_ms = (timeout_ms > 0)
                .then(|| core.clock.now_us().div_ceil(1000) + u64::from(timeout_ms));
            let sink = ConsolidatingSink::new(
                opts.resolved_consolidation(),
                get::reply_sink(leg_id, &self.gets, &self.samples),
            );
            let registered = core.registry.borrow_mut().local.replies.register_sink(
                rid,
                1,
                deadline_ms,
                ReplyAcceptance::for_query(keyexpr, opts.effective_accept_replies()),
                sink,
            );
            if matches!(registered, Err(RegisterError::TableFull)) {
                unheld += 1;
            }
            if registered.is_ok() {
                self.hold_leg(leg_id, leg());
                core.pending_gets.push(PendingGet {
                    face: LOCAL_FACE,
                    leg: leg_id,
                    kind: GetKind::Query(rid),
                });
                // Asked once the legs to the peers were, as zenoh-pico asks it only once the send
                // succeeded.
                let asked = self.ask_own_queryables(core, own, keyexpr, opts);
                drop(guard);
                issued += 1;
                let _ = self.cancelling(fan, leg_id);
                self.hand_own_get(&asked, &query::OwnGet::of(keyexpr, opts, rid));
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
        let faces = self.live().ok_or(Declined::Closed)?.0.up_faces();
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
                return issued_so_far(issued);
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
                        get::reply_sink(leg_id, &self.gets, &self.samples),
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
                self.end_leg_now(leg_id);
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
                return Ok(issued);
            }
        }
        Ok(issued)
    }

    #[cfg(feature = "queryable")]
    fn undeclare_queryable(&self, id: QblId) {
        let entry = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let at = core.queryables.iter().position(|q| q.id == id)?;
            let links = core.retract(Kind::Queryable, at);
            let mut entry = core.queryables.remove(at);
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
            // Under the lock, as the row is dropped after it (`KeyRef::let_go`).
            entry.keyexpr.let_go();
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
        keyexpr: &str,
        wire: WireKey,
        retraction: Option<RetractionKey>,
    ) -> Result<TokenId, Declined> {
        // zenoh-pico's token takes the session's next entity id
        // (`vendor/zenoh-pico/src/net/liveliness.c` @ `uint32_t id = _z_get_entity_id(_Z_RC_IN_VAL(zn));`).
        let mut core = self.live().ok_or(Declined::Closed)?;
        let core = &mut core.0;
        // A full table refuses the token before it takes an id, registers or sends anything.
        if core.tokens.free_slots() == 0 {
            return Err(Declined::TableFull);
        }
        // So does a key the session cannot hold.
        let Some(key) = core.row_key(keyexpr) else {
            return Err(core.key_refusal(keyexpr));
        };
        let id = self.next_entity_id().ok_or(Declined::NoEntityId)?;
        core.registry
            .borrow_mut()
            .app
            .local_tokens
            .register(u64::from(id), keyexpr)?;
        let entry = TokenEntry {
            id,
            keyexpr: key,
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
        keep(&mut core.tokens, entry);
        Ok(id)
    }

    #[cfg(feature = "liveliness")]
    fn undeclare_liveliness_token(&self, id: TokenId) {
        let entry = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let at = core.tokens.iter().position(|t| t.id == id)?;
            let links = core.retract(Kind::Token, at);
            let mut entry = core.tokens.remove(at);
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
            // Under the lock, as the row is dropped after it (`KeyRef::let_go`).
            entry.keyexpr.let_go();
            Some(entry)
        });
        // Its key may hold a declaration whose release reaches the session: after the lock.
        drop(entry);
    }

    #[cfg(feature = "liveliness")]
    fn declare_liveliness_subscriber_on_wire(
        &self,
        keyexpr: &str,
        wire: WireKey,
        history: bool,
        sink: LivelinessSink,
    ) -> Result<SubId, Declined> {
        // A closed session declares nothing, and takes no id for what it does not declare.
        let mut guard = self.live().ok_or(Declined::Closed)?;
        let core = &mut guard.0;
        // A full table refuses the subscriber before it takes an id, registers or asks anything;
        // the sink goes with the refusal.
        if core.live_subs.free_slots() == 0 {
            return Err(Declined::TableFull);
        }
        // So does a key the session cannot hold.
        let Some(key) = core.row_key(keyexpr) else {
            return Err(core.key_refusal(keyexpr));
        };
        let id = self.next_entity_id().ok_or(Declined::NoEntityId)?;
        lock(&self.targets).push((
            TargetKey::Liveliness(id),
            Target::Liveliness(Arc::new(Mutex::new(sink()))),
        ));
        // With `history`, the registration hands the sink the tokens the session already knows,
        // before the peer answers with the rest, as zenoh-pico's does
        // (`vendor/zenoh-pico/src/net/liveliness.c` @ `_z_liveliness_subscription_trigger_history`).
        // They are rehearsed first: the declaration is refused when the lane cannot hold every one
        // of them until they are handed, at the end of this call or, declared from inside a
        // callback, once that callback returns.
        // SAFETY (both holds): the session's lock is held (`core`).
        unsafe { self.samples.held() }.rehearse();
        let registered = core.registry.borrow_mut().register_liveliness_subscriber(
            u64::from(id),
            keyexpr,
            history,
            liveliness::sample_sink(id, &self.samples),
        );
        let held = unsafe { self.samples.held() }.rehearsed();
        if registered.is_ok() && !held {
            core.registry
                .borrow_mut()
                .app
                .liveliness_subscribers
                .unregister(u64::from(id));
        }
        // Refused by the observer, or with no room on the lane for its history, the declaration
        // is refused, as a subscriber's is.
        let refused = match registered {
            Err(refused) => Some(Declined::from(refused)),
            Ok(_) if !held => Some(Declined::TableFull),
            Ok(_) => None,
        };
        if let Some(refused) = refused {
            drop(guard);
            drop(self.take_target(TargetKey::Liveliness(id)));
            return Err(refused);
        }
        if history {
            core.registry
                .borrow_mut()
                .replay_liveliness_tokens(u64::from(id));
        }
        let entry = LiveSubEntry {
            id,
            keyexpr: key,
            wire,
            history,
        };
        core.announce(Kind::LiveSub, |actions| entry.ask(actions));
        // And each group the session joined is asked, as its declarations say.
        #[cfg(feature = "group")]
        for group in &core.groups {
            group.ask_liveliness(id, &entry.keyexpr, &entry.wire, entry.history);
        }
        keep(&mut core.live_subs, entry);
        drop(guard);
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

    fn place_counts(&self, kind: EntityKind) -> (usize, usize) {
        self.core.lock().0.places.counts(kind)
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
            KeyAsk::Hold(text) if !core.keys.holds_key(text.len()) => Err(KeyNotHeld::TooLong),
            KeyAsk::Hold(text) => core
                .row_key(text)
                .map(|key| Some(HeldKey::of(key)))
                .ok_or(KeyNotHeld::NoRoom),
            // SAFETY: the session's lock is held (`core`), and the key is its arena's.
            KeyAsk::Share(key) => Ok(Some(unsafe { key.share(&core.keys) })),
            KeyAsk::Release(key) => {
                // SAFETY: as a share.
                unsafe { key.release(&core.keys) };
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
        // The rows go back to their tables with the session: a table lent from its arena keeps
        // its rows. Their callbacks are the table of callbacks', taken whole below.
        {
            let mut registry = core.registry.borrow_mut();
            let subscribers = &mut registry.app.subscribers;
            while let Some(last) = subscribers.len().checked_sub(1) {
                drop(subscribers.take_at(last));
            }
        }
        core.matches.clear();
        #[cfg(feature = "queryable")]
        core.queryables.clear();
        // A get still pending ends with its session: its entry goes here, its leg's callback with
        // the table.
        #[cfg(feature = "query")]
        {
            let mut registry = core.registry.borrow_mut();
            for pending in core.pending_gets.drain(..) {
                pending.unregister(&mut registry);
            }
        }
        // The session's tokens end with its link, and its liveliness subscribers with it.
        #[cfg(feature = "liveliness")]
        {
            core.tokens.clear();
            core.live_subs.clear();
        }
        // The watches end with the session; their sinks, and the C contexts they hold, are let go
        // of with no lock held.
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        let watches = self.decl_watches.close();
        drop(guard);
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        drop(watches);
        // What publishes handed to the session and it never sent goes with it, let go of with no
        // lock held, as a sent leg is.
        let handed = {
            let mut handed = self.handed();
            self.owed.store(false, Ordering::SeqCst);
            core::mem::take(&mut *handed)
        };
        drop(handed);
        #[cfg(feature = "query")]
        self.gets.ended.lock().clear();
        // The queries no callback will now answer, and the callbacks' C contexts, are dropped
        // with no lock held.
        #[cfg(feature = "queryable")]
        drop(core::mem::take(&mut *self.plane.queries.lock()));
        // Every callback the session held goes with it, in one take of the table: the ones of the
        // rows emptied above, and one whose row went before its callback (a get's leg whose link
        // was lost, its end not handed out yet). The removal is counted under the table's lock,
        // so what the deliveries kept is let go of first, and the rest with no lock held.
        let taken = {
            let mut targets = lock(&self.targets);
            self.removed.fetch_add(1, Ordering::SeqCst);
            core::mem::take(&mut *targets)
        };
        self.forget_resolved();
        for (_, target) in &taken {
            if let Target::Subscriber(callback) = target {
                callback.retire();
            }
        }
        drop(taken);
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn start_read_task(&self) -> Result<(), ReadTaskStartRefused> {
        self.start_reader(os::spawn)
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
        let mut wait = if self.input_held.swap(false, Ordering::Relaxed) {
            IdleWait::None
        } else {
            // Marked as a holder that holds no send, so a droppable publish that finds the session
            // held for the wait tries it again at once (`LinkRooms::for_held`): the mark is let go
            // before the session is.
            self.live().map_or(IdleWait::None, |mut core| {
                let _waiting = SendingOn::enter(&self.sending_on, WAITING);
                core.0.idle_wait()
            })
        };
        #[cfg(test)]
        self.takes.wait(&wait);
        wait.wait(sleep_ms);
        // One pass of the session's task reads what its link holds, a batch at a time, and does
        // what is due: `single` asks for one message, and a pass is the least this engine reads.
        // One take of the session for the step: its links, what publishes handed to it, and
        // whether a periodic job is due by the clock reading the step made.
        let (stepped, handed, jobs_due_ms) = match self.live() {
            Some(mut core) => {
                core.0.links.waited(wait);
                let stepped = self.step(&mut core.0);
                self.input_held
                    .store(stepped.is_some() && core.0.holds_input(), Ordering::Relaxed);
                let jobs_due_ms = stepped.and_then(|now_us| core.0.jobs_due_at(now_us));
                // What publishes handed to the session while it was held leaves on this step too,
                // so a program that only reads its session sends it.
                (
                    stepped.is_some(),
                    self.send_handed_now(&core.0),
                    jobs_due_ms,
                )
            }
            None => (false, VecDeque::new(), None),
        };
        drop(handed);
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

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> Drop for CoopEngine<L, C> {
    fn drop(&mut self) {
        // The last handle is gone, so no read task holds one: it has stopped, or is about to
        // drop the handle it held. A session never closed is closed now; a closed one has no
        // link left to end.
        self.core.dropping().end_links();
    }
}

/// The cell the deliveries keep their callbacks in is taken with no lock and never waited for: a
/// second taker goes without while the first holds it, and finds what it left once it lets go.
#[cfg(test)]
mod try_cell_tests {
    use super::TryCell;

    #[test]
    fn a_held_cell_is_not_taken_again_until_it_is_let_go() {
        let cell = TryCell::new(1u32);
        let mut held = cell.try_take().expect("a free cell is taken");
        *held += 1;
        assert!(cell.try_take().is_none(), "held by the first taker");
        drop(held);
        let again = cell.try_take().expect("let go, it is free again");
        assert_eq!(*again, 2, "the second taker finds what the first left");
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
        let mut wait = ended_by_clock_moves(IdleWait::Sleep(5_000), Some(&word));
        // The wait stays on the thread that made it, as a session's read does (its lent receive
        // lease is no value of another thread's); the word comes from another, as a program's does.
        let telling = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            *moves.count.lock().unwrap() += 1;
            moves.moved.notify_all();
        });
        let started = Instant::now();
        wait.wait(|ms| std::thread::sleep(Duration::from_millis(u64::from(ms))));
        let took = started.elapsed();
        telling.join().expect("the thread that tells the word");
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

#[cfg(test)]
mod interest_form_tests {
    //! Where an Interest's rest of the key lies in the key its row keeps.
    use super::suffix_place;

    /// A form that names no declaration names the whole key, one that names a declared prefix the
    /// rest after it: each a tail of the row's key, found where it begins. A rest that is not a tail,
    /// or none, has no place, and the form keeps its own.
    #[test]
    fn a_forms_rest_of_the_key_is_found_in_the_rows_key() {
        assert_eq!(suffix_place("demo/if/key", Some("demo/if/key")), Some(0));
        assert_eq!(
            suffix_place("demo/if/key", Some("/key")),
            Some("demo/if".len())
        );
        assert_eq!(
            suffix_place("demo/if/key", Some("")),
            Some("demo/if/key".len())
        );
        assert_eq!(suffix_place("demo/if/key", Some("/other")), None);
        assert_eq!(suffix_place("demo", Some("demo/longer")), None);
        assert_eq!(suffix_place("demo/if/key", None), None);
    }
}
