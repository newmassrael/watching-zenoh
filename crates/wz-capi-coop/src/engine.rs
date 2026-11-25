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

#[cfg(feature = "time-base")]
use alloc::sync::Arc;
use core::any::Any;
use core::num::NonZeroU32;
use core::ops::{Deref, DerefMut};
use core::ptr::{addr_of_mut, NonNull};
use core::sync::atomic::{AtomicBool, Ordering};
// A 64-bit atomic where the target has one, and a critical section where it does not (a
// Cortex-M7 has 32-bit atomics only).
use portable_atomic::AtomicU64;

#[allow(unused_imports)]
use crate::prelude::*;

#[cfg(any(feature = "runtime-plan", test))]
use crate::arena::AllocatorMemory;
#[cfg(feature = "advanced-cache")]
use crate::arena::CacheSpan;
#[cfg(any(feature = "listen", feature = "group"))]
use crate::arena::HandedTable;
use crate::arena::{
    ArenaMemory, ArenaPlan, ArenaRefused, ClaimedPlaces, DroppedOn, EnginePlace, EntityKind,
    EntityPlace, EntityPlaces, HandlePlace, HeldPlaces, LinkCells, OpenStorage, PlaceTables,
    PlanFrom, SessionArena, SessionRows, TransportTables,
};
use crate::form::{CoopForm, Latch};
use crate::form::{
    LinkCount, LockForm, SessionLock, SharedCount, StateGuard, StateLock, UnderCoreLock,
};
use crate::lodging::LodgingPlaces;
#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
use crate::round::RoundGate;
#[cfg(all(wz_round, feature = "runtime-plan"))]
use crate::round::RoundRows;
#[cfg(wz_round)]
use crate::round::{Round, RoundCounts};
use crate::RowPolicy;
use wz_runtime_coop::kept::Shared;
#[cfg(feature = "runtime-plan")]
use wz_session_core::bounded::Arena;
use wz_session_core::bounded::{KeyBacking, KeyMaker, KeyUnkept, LendRefused, TableLender};
use wz_session_core::caps;
#[cfg(all(
    feature = "liveliness",
    any(feature = "threads", feature = "listen", feature = "group")
))]
use wz_session_core::key_arena::KeyRef;
use wz_session_core::key_arena::{KeySpace, LentKeys};
use wz_session_core::placed::{Placed, PlacedRef};
#[cfg(all(feature = "query", feature = "runtime-plan"))]
use wz_session_core::reply_hold::HeldReplies;
use wz_session_core::round::RowReleases;
use wz_session_core::row_callback::{RowCallback, ThreadForm};
#[cfg(feature = "local-queryable")]
use wz_session_core::session_state::LocalRequests;
use wz_session_core::session_state::{MatchingRead, SessionParts};
use wz_session_core::session_tables::{
    kind, DeclaredRow, DeclaredTable, InterestHandle, InterestKind, InterestName, InterestRow,
    KeyexprHandle, KeyexprRef, MatchingListenerHandle, Plane, Refused, Retraction, RowCallbacks,
    SessionTables, SubscriberHandle, Watching, WriteFilterHandle,
};
use wz_session_core::slot_map::Handle;
#[cfg(feature = "runtime-plan")]
use wz_session_core::slot_observer::ObserverRows;

// The operating system the engine runs on: its mutex, its threads and its sleep are `std`'s on a
// host and the kernel's on an MCU (`docs/upstream-parity.md` section 5a, E1).
#[cfg(feature = "listen")]
use crate::admission_gate::AdmissionGate;
use wz_capi_port::os::{self, Mutex, MutexGuard};
#[cfg(feature = "threads")]
use wz_capi_port::os::{JoinHandle, ThreadId};
use wz_capi_port::{
    BatchStep, CalledFromReadTask, FanoutError, FilterId, FilterPlane, FilteredPut, HeldKey,
    HoldRefused, KeyAnchor, KeyAsk, KeyHold, KeyNotHeld, MatchId, MatchingSink, PeerIdentity,
    PlaceLender, ReadTaskStartRefused, SessionClosed, SessionDrive, SessionEngine, SessionKeys,
    StatementNotHonoured, SubId, SubscriberSink, WireKey,
};
// The port's refusal of a declaration, named apart from this crate's refusal of an endpoint.
use wz_capi_port::Refusal as Declined;
#[cfg(feature = "ticker")]
use wz_capi_port::{Tick, TickerId};
use wz_runtime_coop::executor::SpawnRefusal;
use wz_runtime_coop::face_send::{self, Behind, FaceSend, Pass, PublishRun, Then, FIRST_FACE};
#[cfg(feature = "listen")]
use wz_runtime_coop::face_send::{after_probe, AfterProbe, ProbeAnswer};
#[cfg(any(feature = "listen", feature = "group"))]
use wz_runtime_coop::face_send::{DropSet, HandedLimits};
#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
use wz_runtime_coop::faces::DialAnswer;
#[cfg(feature = "listen")]
use wz_runtime_coop::faces::OwingWaits;
use wz_runtime_coop::faces::{
    DialEndpoint, EndpointTexts, FaceRecord, FaceSession, IdleWait, Link, LinkSupervisor,
    DIAL_LOOK_MS,
};
use wz_runtime_coop::link_cells::CellRc;
use wz_runtime_coop::reassembly_rx::{
    session_reassembly, SessionChains, SessionReassembly, LENT_CHAINS,
};
#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
use wz_runtime_coop::session_drive::router_session_task_bytes;
#[cfg(feature = "time-base")]
use wz_runtime_coop::session_drive::LinkWait;
#[cfg(feature = "time-base")]
use wz_runtime_coop::session_drive::StackWake;
use wz_runtime_coop::session_drive::{LinkWaits, WaitOn};
use wz_runtime_coop::session_drive::{OpenedLink, SessionDatagramLink, SessionLinks, SessionRole};
use wz_runtime_coop::session_runtime::{SessionEntropy, SessionHandle};
pub use wz_runtime_coop::transport::{EndpointRefusal, Refusal};
use wz_runtime_coop::transport::{
    LinkCalls, TransportFaces, TransportRefusal, TransportSession, WireMaking,
};
use wz_runtime_coop::{
    ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeForm, RuntimePlace, RuntimeRows,
};
#[cfg(any(all(test, feature = "std"), feature = "advanced-cache"))]
use wz_session_core::byte_cells::LentByteCells;
use wz_session_core::close_reason::CloseReason;
use wz_session_core::declare_form::{InterestAsk, InterestForm, RetractionKey};
use wz_session_core::driver_loop::{EventSink, IterationEvent};
use wz_session_core::entropy::EntropySource;
use wz_session_core::interest_build::InterestKinds;
use wz_session_core::lent_push;
use wz_session_core::limits::SessionLimits;
#[cfg(feature = "listen")]
use wz_session_core::link_admission::{LinkAdmission, LinkBook, LinkRegistry};
#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
use wz_session_core::link_life::{Effects, LinkInput, LinkPhase, Refused as HandshakeRefusal};
use wz_session_core::link_life::{LinkRole, LinkTimes, UnicastLink};
use wz_session_core::locality::Locality;

use crate::open_source::{Counted, EndpointList, EndpointWriter, OpenSource};
use wz_runtime_coop::locator_text::parse_listen_locator;
use wz_session_core::metadata::PushMetadata;
use wz_session_core::named_key::NamedKey;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::policy::KeyWireForm;
use wz_session_core::policy::{DeclarationSyncPacing, SessionPolicy, SnResolution};
use wz_session_core::policy_binding::OutsideDomain;
use wz_session_core::publish_options::{PlainPutParams, PublishError, PublishOptions};
use wz_session_core::push_build;
use wz_session_core::sample::{QosLevel, SampleKind};
use wz_session_core::send_wire_error::SendWireError;
#[cfg(feature = "listen")]
use wz_session_core::session_actions::Probed;
use wz_session_core::session_actions::{LinkState, SessionCore, SessionLinkActions};
use wz_session_core::session_init_params::{
    CookieKey, HeldDrop, KeepAliveConf, LinkRxConf, SessionInitParams, SessionZid, TxQueueConf,
    ZidError,
};
use wz_session_core::session_timeouts::SessionTimeouts;
#[cfg(feature = "shared-key-ids")]
use wz_session_core::shared_key_ids::{KeyIdsAtOpen, KeyIdsRefused, LinkKeyForms, SharedKeyIds};
#[cfg(any(
    feature = "threads",
    feature = "listen",
    feature = "group",
    feature = "liveliness",
    feature = "queryable"
))]
use wz_session_core::sink::RowAccess;
use wz_session_core::sink::SampleRef;
#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
use wz_session_core::sink::{FanOut, SampleDelivery, SampleView};
use wz_session_core::sn::sn_resolution_admitted;
use wz_session_core::step_lend::LendCell;
#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
use wz_session_core::step_lend::StepLend;
use wz_session_core::timestamp_visibility::exposed_by;
use wz_session_core::unicast_rx::RouterLend;
use wz_session_core::wire_id::{EntityId, ExprId};
use wz_session_core::WhatAmI;
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

mod hold;
pub use hold::{EngineHandle, EngineHold};
mod reach;
use reach::ReachEngine;
pub use reach::RowClaim;

mod ledger;
use ledger::{Ledger, Seen};

// A build whose session holds one face and no read task beside the program's calls: the read
// steps the one link's session itself (`direct`).
#[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
mod direct;
// The delivery of a lent Push such a read makes, one subscriber at a time (`pinned`).
#[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
mod pinned;
#[cfg(all(
    feature = "query",
    not(any(feature = "threads", feature = "listen", feature = "group"))
))]
mod replies;
// The delivery of a peer's query such a read makes, one queryable at a time (`queries`).
#[cfg(all(
    feature = "queryable",
    not(any(feature = "threads", feature = "listen", feature = "group"))
))]
mod queries;

mod registry;
#[cfg(not(feature = "runtime-plan"))]
use crate::region::{RegionBlock, RegionField, StateRegion};
#[cfg(not(feature = "runtime-plan"))]
pub(crate) use registry::placed::{RegistryRegion, REGISTRY_REGION_LINES};
// The values the state owns and its tasks reach by handles, as fields of the region.
#[cfg(not(feature = "runtime-plan"))]
mod state_places;
#[cfg(feature = "runtime-plan")]
pub(crate) use registry::FACE_SET_BYTES;
#[cfg(any(feature = "listen", feature = "group"))]
pub(crate) use registry::HELD_SET_BYTES;
#[cfg(feature = "local-queryable")]
use registry::LOCAL_FACE;
use registry::{FaceId, HeldFace, Registry, DIAL_FACE};
#[cfg(all(
    any(feature = "query", feature = "queryable"),
    not(feature = "runtime-plan")
))]
use state_places::PlacedTables;
#[cfg(not(feature = "runtime-plan"))]
pub(crate) use state_places::StatePlaces;

/// How the session's state holds its registry: by value where the open lent its tables from the
/// arena, and by the handle of the field of the session's region where the build laid it out
/// (`crate::region`), which drops it in place.
#[cfg(feature = "runtime-plan")]
type RegistryHold = Registry;
#[cfg(not(feature = "runtime-plan"))]
type RegistryHold = RegionField<Registry>;

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
#[cfg(all(
    any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ),
    any(feature = "threads", feature = "listen", feature = "group")
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
use wz_session_core::face::{FaceEventKind, FaceLinkRow, FaceRowSink};
#[cfg(feature = "connectivity")]
use wz_session_core::face::{FaceEventSink, FaceSnapshot};
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
use wz_session_core::round::LegHolders;
#[cfg(feature = "query")]
use {
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

/// The policies a session `CoopEngine::open` opens from `config` runs under: the one place that
/// open decides them. The build defaults: the config is what the ABI read from its own keys and
/// values, not a zenoh document with a `wz` member, and it has no field for a policy yet; the
/// ABI's door for one is a key of its own.
#[cfg(any(feature = "runtime-plan", feature = "listen", feature = "group", test))]
pub(crate) fn resolve_policy<E>(_config: &CoopConfig<E>) -> SessionPolicy {
    SessionPolicy::defaults()
}

/// Whether a session may run the widths of sequence numbers `config` states, its own and each
/// group's: each is held to the build's `sn-resolution` domain
/// (`wz_session_core::sn::sn_resolution_admitted`), the first one refused is the open's refusal.
fn admit_sn_widths<E>(config: &CoopConfig<E>) -> Result<(), OpenError> {
    sn_resolution_admitted(config.sn_resolution).map_err(OpenError::SnResolution)?;
    config.groups.iter().try_for_each(|group| {
        sn_resolution_admitted(group.profile.seq_num_res).map_err(OpenError::SnResolution)
    })
}

/// The session limits a session `CoopEngine::open` opens from `config` holds its tables to: the
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
    /// A width of sequence numbers the config states, the session's or a group's, is one the
    /// build's `sn-resolution` domain leaves out: the build holds no word for its ring. Nothing
    /// was reserved, bound, joined or dialled.
    SnResolution(OutsideDomain<SnResolution>),
    /// Every row of the process's table of engines (the build's `ENGINE_ROWS`, one for each
    /// session open at once, [`RowClaim`]) holds the engine of a session open now.
    /// Nothing was reserved, bound, joined or dialled.
    NoEngineRow,
    /// The heap had no room for a link's shared handle. Nothing of the link stays.
    HeapRefused,
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
            TransportRefusal::HeapRefused => OpenError::HeapRefused,
        }
    }
}

/// The key ids every node of a deployment shares that an open hands the session, and the
/// endpoints whose key-wire form is stated apart from the session's
/// (`CoopEngine::open_with_key_ids`). A build without `shared-key-ids` hands none, and an ABI
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
    /// The Router of the one link the read steps itself (`direct`).
    #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
    router: SessionReassembly,
    /// The place the engine is written at.
    engine: EnginePlace,
    handle_place: Option<HandlePlace>,
    lodgings: LodgingPlaces,
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
    router: SessionReassembly,
    keys: KeySpace,
    registry: RegistryHold,
    /// After the registry, whose dispatch reaches it by a handle that counts nothing.
    #[cfg(feature = "queryable")]
    plane: Placed<QueryPlane>,
    /// What the session's gets share with their sinks and the round: the ends of their legs, the
    /// replies the gets that consolidate hold, and the legs' callbacks.
    #[cfg(feature = "query")]
    gets: Placed<GetPlane>,
    /// The session's own note of each leg pending, a row for each get its tables hold.
    #[cfg(feature = "query")]
    pending_gets: Rows<PendingGet, { usize::MAX }>,
    handle_place: Option<HandlePlace>,
    places: EntityPlaces,
    /// The places for values lodged by counts, each of which keeps the arena's memory while lent.
    lodgings: LodgingPlaces,
    /// The links the plan holds buffers for: the rows of the session's link admission.
    #[cfg(feature = "listen")]
    links: usize,
    /// Whether the outbound slots the links share are fewer than the links.
    #[cfg(feature = "listen")]
    tx_pool_short: bool,
    /// The ring the advanced publishers' caches keep their samples in, none for a plan of none.
    #[cfg(feature = "advanced-cache")]
    cache: Option<CacheSpan>,
    /// The places of the faces' rooms, a row for each set of face tables (`LinkRooms::init_at`).
    room_places: RoomPlaces,
    /// The places the session lends its registry and its Router in for a step, in the arena.
    steps: StepPlaces,
    /// The session's round of deliveries, which lies in the arena: after the registry, which
    /// holds a handle of it, and before the arena. A build that puts nothing in the round
    /// (`wz_round`) places none.
    #[cfg(wz_round)]
    samples: Placed<Round>,
    /// The span the session's runtime is placed in, and the count of the arena it is kept by.
    runtime: RuntimePlace,
    /// The place the session's engine is written at, and the count of the arena it is kept by.
    engine: EnginePlace,
    /// The region the session's registry and its key arena lie in: after the registry's handle,
    /// which drops the registry in place, and every table that keeps a key there.
    #[cfg(not(feature = "runtime-plan"))]
    state: RegionBlock<StateRegion>,
    arena: SessionArena,
}

/// The plain tables of a session's state, lent by an open's one lender
/// (`SessionRows::lent_from`): the ends of its legs, their callbacks and the session's note of
/// each leg pending, and the Finals its queryables hold, where the arena lends them
/// (`runtime-plan`; a region holds them otherwise, `StatePlaces::tables`), and the ring of the
/// advanced publishers' caches.
struct StateTables {
    #[cfg(all(feature = "query", feature = "runtime-plan"))]
    legs: Rows<Ended, { usize::MAX }>,
    #[cfg(all(feature = "query", feature = "runtime-plan"))]
    leg_rows: Rows<Option<LegRow>, { usize::MAX }>,
    #[cfg(all(feature = "query", feature = "runtime-plan"))]
    pending_gets: Rows<PendingGet, { usize::MAX }>,
    /// The Finals the queryables' plane holds and the requests a dispatch refused, a row of each
    /// for each query held at once (`query::FinalHolds`).
    #[cfg(all(feature = "queryable", feature = "runtime-plan"))]
    held_finals: query::HeldFinals,
    #[cfg(all(feature = "queryable", feature = "runtime-plan"))]
    refused_finals: query::RefusedFinals,
    #[cfg(feature = "advanced-cache")]
    cache: Option<LentByteCells>,
}

impl SessionRows {
    /// The session's plain tables, lent by `lend` in the order the plan laid them out, each key
    /// at most `longest` bytes. A count past the address space is a table the lender refuses.
    fn lent_from(&self, lend: &mut TableLender<'_>) -> StateTables {
        // A build that asks and answers no query from the arena and caches no sample lends the
        // state no plain table: its lender is asked nothing.
        #[cfg(not(any(
            all(
                any(feature = "query", feature = "queryable"),
                feature = "runtime-plan"
            ),
            feature = "advanced-cache"
        )))]
        let _ = lend;
        #[cfg(all(feature = "query", feature = "runtime-plan"))]
        let legs = self.gets().legs().unwrap_or(usize::MAX);
        StateTables {
            #[cfg(all(feature = "query", feature = "runtime-plan"))]
            legs: lend.table(legs),
            #[cfg(all(feature = "query", feature = "runtime-plan"))]
            leg_rows: lend.table(legs),
            #[cfg(all(feature = "query", feature = "runtime-plan"))]
            pending_gets: lend.table(legs),
            #[cfg(all(feature = "queryable", feature = "runtime-plan"))]
            held_finals: lend.table(self.held_queries()),
            #[cfg(all(feature = "queryable", feature = "runtime-plan"))]
            refused_finals: lend.table(self.held_queries()),
            #[cfg(feature = "advanced-cache")]
            cache: (self.cache_bytes() != 0).then(|| lend.byte_cells(self.cache_bytes(), 1)),
        }
    }
}

/// Lay out the plan of the session opened with `config` under `policy`, its tables' rows from
/// `from` and after them the rows `holds` names (`lay_out_open`), reserve its arena in
/// `memory` and lend from it every table of the session. One lender lends each layer its plain
/// tables from the rows the plan counts for it: the transport's links, cells, reassembly and
/// endpoints, the state's lane, declarations, keys and legs, and the ABI's places; it gives the
/// tables after a refusal no rows and is asked once, after them all. The round's tables and the application's, which their makers lend, ask their own. What
/// was lent before a refusal goes back with the arena. Out of line and generic over nothing: one
/// body for every stack and source the open is made over. The plan is made and read here, so the
/// open's frame never holds or moves it: what the state is sized by is handed back with the tables.
#[inline(never)]
fn lend_session(
    holds: &OpenHolds<'_>,
    from: PlanFrom,
    memory: &'static dyn ArenaMemory,
    config: &CoopConfig<Counted>,
    policy: &SessionPolicy,
) -> Result<SessionLent, ArenaRefused> {
    let mut plan = ArenaPlan::vacant();
    match from {
        PlanFrom::Region(region) => region.lay_out_on(&mut plan, config)?,
        #[cfg(any(feature = "runtime-plan", test))]
        PlanFrom::Config => plan.count(config, resolve_limits(config))?,
    }
    lay_out_open(&mut plan, holds)?;
    #[cfg(feature = "runtime-plan")]
    let mut arena = SessionArena::reserve(&plan, memory)?;
    // The registry and the key arena lie in the region the build lays out, the head of the one
    // block the open reserves, zeroed, the arena of what it sizes at run time after it: the
    // session's tables are the region's fields, placed over their rows by one walk.
    #[cfg(not(feature = "runtime-plan"))]
    let (mut arena, state) = SessionArena::reserve_after::<StateRegion>(&plan, memory)?;
    // SAFETY: the head is a zeroed `StateRegion` this open alone reaches; the arena gives the
    // block back only after its last holder, and the region's block is dropped before the arena
    // wherever both are held (here, being made after it, then `SessionLent` and `Core`, whose
    // arena is their last field).
    #[cfg(not(feature = "runtime-plan"))]
    let state = unsafe { RegionBlock::<StateRegion>::within(state) };
    let mut lend = arena.lender();
    // Held whole to the end, as the value handed back holds it; the state's tables, which the
    // open moves into what it makes one by one, are taken apart at once instead: a table held as
    // a field of a set partly moved out would need its own drop on each refusal below.
    let transport = plan.transport().lent_from(&mut lend);
    // The key arena is the arena's where the open lends the registry from it, and the region's
    // otherwise, beside the registry whose tables keep their keys there.
    #[cfg(feature = "runtime-plan")]
    let keys = lend.keys(
        plan.session().key_bytes(),
        config.limits.max_keyexpr_bytes_held(),
    );
    let StateTables {
        #[cfg(all(feature = "query", feature = "runtime-plan"))]
        legs,
        #[cfg(all(feature = "query", feature = "runtime-plan"))]
        leg_rows,
        #[cfg(all(feature = "query", feature = "runtime-plan"))]
        pending_gets,
        #[cfg(all(feature = "queryable", feature = "runtime-plan"))]
        held_finals,
        #[cfg(all(feature = "queryable", feature = "runtime-plan"))]
        refused_finals,
        #[cfg(feature = "advanced-cache")]
        cache,
    } = plan.session().lent_from(&mut lend);
    let PlaceTables {
        handle,
        entities: places,
        lodgings,
    } = plan.places().lent_from(&mut lend, plan.entities());
    #[cfg(feature = "runtime-plan")]
    let room_places: RoomPlaces = lend.table(plan.peers().sets());
    #[cfg(feature = "runtime-plan")]
    let keys = lend.finish_keys(keys).map_err(ArenaRefused::Lend)?;
    #[cfg(not(feature = "runtime-plan"))]
    lend.finish().map_err(ArenaRefused::Lend)?;
    // SAFETY: the block is a zeroed `StateRegion` this open alone reaches; it neither moves nor goes
    // back before the registry's handle and every key of it are let go of, being held after them
    // by what this hands back and then by the session's state.
    #[cfg(not(feature = "runtime-plan"))]
    let keys = unsafe { StateRegion::place(state.as_ptr(), resolve_limits(config)) };
    // The plane, the round, the step places, the queryables' plane and the plain tables' rows lie
    // in the region where the build fixes the session's shape, each in a field of it no other
    // owner reaches.
    // SAFETY: the region was placed above, and nothing reaches its places' fields but this open,
    // which writes each once; the block is held after every owner written in it (`SessionLent`,
    // then `Core`), and neither moves nor goes back before them.
    #[cfg(not(feature = "runtime-plan"))]
    let region_places = unsafe { StateRegion::places_at(state.as_ptr()) };
    // SAFETY: as above, for the plain tables' fields: each table is held by the plane or the
    // state it is moved into, both dropped before the block.
    #[cfg(all(
        any(feature = "query", feature = "queryable"),
        not(feature = "runtime-plan")
    ))]
    let PlacedTables {
        #[cfg(feature = "query")]
        legs,
        #[cfg(feature = "query")]
        leg_rows,
        #[cfg(feature = "query")]
        pending_gets,
        #[cfg(feature = "query")]
        held_replies,
        #[cfg(feature = "queryable")]
        held_finals,
        #[cfg(feature = "queryable")]
        refused_finals,
    } = unsafe { StatePlaces::tables(region_places, plan.session()) };
    // SAFETY: as above, for the rooms' places: the table is held by the rooms, which the session's
    // state drops before the block.
    #[cfg(not(feature = "runtime-plan"))]
    let room_places = unsafe { StatePlaces::rooms(region_places, plan.peers().sets()) };
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
    #[cfg(all(wz_round, feature = "runtime-plan"))]
    let round_rows =
        RoundRows::lent(arena.arena_mut(), plan.round()).map_err(ArenaRefused::Lend)?;
    // The rows the gets that consolidate hold their replies in, lent beside the round's.
    #[cfg(all(feature = "query", feature = "runtime-plan"))]
    let held_replies = HeldReplies::lent(arena.arena_mut(), plan.session().held_replies())
        .map_err(ArenaRefused::Lend)?;
    // What the gets share: placed here, so the round is told whose legs' callbacks its replies'
    // records hold counts of before it is shared.
    #[cfg(feature = "query")]
    let (ended, legs) = (EndedLegs::over(legs), LegRows::over(leg_rows));
    // SAFETY: the arena hands a place aligned for the plane and valid for writes of one, where it
    // stays.
    #[cfg(all(feature = "query", feature = "runtime-plan"))]
    let gets = unsafe {
        arena.arena_mut().place_with(|at| {
            GetPlane::init_at(NonNull::new_unchecked(at), ended, held_replies, legs)
        })
    }
    .map_err(ArenaRefused::Lend)?;
    // SAFETY: as for the region's places above, for the gets' field.
    #[cfg(all(feature = "query", not(feature = "runtime-plan")))]
    let gets = unsafe { StatePlaces::gets(region_places, ended, held_replies, legs) };
    // The round lies beside its tables, owned by the session's state and reached by handles that
    // count nothing.
    #[cfg(all(wz_round, feature = "runtime-plan"))]
    let mut samples =
        Round::placed_over(arena.arena_mut(), round_rows).map_err(ArenaRefused::Lend)?;
    // SAFETY: as above, for the round's field and the field of its tables' rows.
    #[cfg(all(wz_round, not(feature = "runtime-plan")))]
    let mut samples = unsafe { StatePlaces::round(region_places, plan.round()) };
    // No handle of the round is taken yet: it reads the keys a peer's aliases keep in the
    // session's key arena where they lie.
    #[cfg(wz_round)]
    {
        let round = samples.get_mut();
        round.reads_keys_in(keys);
        #[cfg(feature = "query")]
        {
            let legs: NonNull<dyn LegHolders<crate::calls::CoopCalls>> = NonNull::from(&*gets);
            // SAFETY: the round reaches the legs until the engine's drop lets it go
            // (`Round::let_go`), before the plane's owner, the session's state, is dropped;
            // until then the plane is held where it was placed, by this value and then by the
            // state.
            unsafe { round.calls_legs_of(legs) };
        }
    }
    #[cfg(feature = "runtime-plan")]
    let steps = StepPlaces::placed_in(arena.arena_mut()).map_err(ArenaRefused::Lend)?;
    // SAFETY: as above, for the step places' fields.
    #[cfg(not(feature = "runtime-plan"))]
    let steps = unsafe { StatePlaces::steps(region_places) };
    // The queries the session's queryables are asked wait for their callbacks here, and the
    // Finals of them are held here, in rows the plan counts.
    #[cfg(feature = "queryable")]
    let final_holds = query::FinalHolds::over(held_finals, refused_finals);
    // SAFETY: as for the gets' plane above.
    #[cfg(all(feature = "queryable", feature = "runtime-plan"))]
    let plane = unsafe {
        arena
            .arena_mut()
            .place_with(|at| QueryPlane::init_at(NonNull::new_unchecked(at), final_holds))
    }
    .map_err(ArenaRefused::Lend)?;
    // SAFETY: as above, for the queryables' field.
    #[cfg(all(feature = "queryable", not(feature = "runtime-plan")))]
    let plane = unsafe { StatePlaces::queries(region_places, final_holds) };
    // SAFETY: the registry holds the handle, and is dropped before the round's owner wherever
    // both are held (`SessionLent`, and the session's state, whose round is its last field); the
    // owner changes the round no more.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    let lane = unsafe { samples.share() };
    // SAFETY: the delivery is held by the registry, dropped before the plane wherever both are
    // held: here, where the registry is made after it, and in `SessionLent` and the session's
    // state, which hold the plane in a field after the registry's.
    #[cfg(feature = "queryable")]
    let asked = unsafe { plane.share() };
    let delivery = RoundDelivery {
        #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
        round: lane,
        #[cfg(feature = "queryable")]
        plane: asked,
    };
    // The application's tables, lent from the rows the plan counts for them: the session's
    // one table set among them, which holds its subscribers and its queryables.
    #[cfg(feature = "runtime-plan")]
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
    // The application's tables are the region's, placed above; the session's one table set holds
    // its tokens as rows, so the observer's own registry of them has none (`RegistryRegion`).
    // SAFETY: the region was written and placed by `StateRegion::place` above and nothing reaches
    // its registry yet; the block is held after the handle (`SessionLent`, then `Core`).
    #[cfg(not(feature = "runtime-plan"))]
    let registry = unsafe {
        RegistryRegion::bind(
            StateRegion::registry_at(state.as_ptr()),
            resolve_limits(config),
            &plan.tables(),
            delivery,
        )
    }
    .map_err(ArenaRefused::Lend)?;
    let runtime = arena
        .runtime_place(holds.runtime)
        .map_err(ArenaRefused::Lend)?;
    let engine = arena
        .engine_place(holds.engine)
        .map_err(ArenaRefused::Lend)?;
    // SAFETY: the span was lent above to the lodging places alone, and `engine.memory` is the count
    // of the memory it lies in, held by the session's engine for as long as the engine lends from
    // the places.
    let lodgings = unsafe { lodgings.kept_by(engine.memory) };
    Ok(SessionLent {
        runtime,
        engine,
        transport,
        room_places,
        steps,
        #[cfg(wz_round)]
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
        lodgings,
        #[cfg(feature = "listen")]
        links: plan.links(),
        #[cfg(feature = "listen")]
        tx_pool_short: plan.tx_pool_short(),
        #[cfg(feature = "advanced-cache")]
        cache,
        #[cfg(not(feature = "runtime-plan"))]
        state,
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
    entropy: &mut SessionEntropy<SharedCount>,
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
    use wz_runtime_coop::session_drive::{LinkProto, Locator};
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
        let Some(at) = parse_listen_locator(endpoint.as_ref())
            .ok()
            .and_then(Locator::as_ip)
        else {
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
pub struct CoopEngine<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> {
    /// The session's one link as the read steps it, apart from the session's state, so that a
    /// callback the link's records reach takes the state while the link lends them
    /// (`direct`). Before `core`: dropped first, as the link's session holds handles of the
    /// state's cells.
    #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
    direct: direct::DirectFace<L, C>,
    core: CoreLock<L, C>,
    /// The waits for room of the faces that are up, asked by a publish that may be dropped while
    /// another holds the session ([`Self::live_to_publish`]), how long it waits
    /// (`congestion_control/drop/wait_before_drop`), and whether the queue profile has it ask at
    /// all (`TxQueueConf::held_drop`). A handle of the rooms `core` owns, dropped after it.
    rooms: PlacedRef<LinkRooms<L::Waits>>,
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
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    input_held: AtomicBool,
    /// Where a read waits for another read to hand back the session's buffer of waits. Only a
    /// build with a read task beside the program's calls has two reads at once.
    #[cfg(feature = "threads")]
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
    /// listener's row (`SessionTables::take_owed_matching`). A handle of the round the session's
    /// state owns, used last in the engine's drop, before `core` is dropped. None in a build that
    /// puts nothing in the round (`wz_round`).
    #[cfg(wz_round)]
    samples: PlacedRef<Round>,
    /// What a walk's end of a call leaves the session to let go of, where nothing is put in the
    /// round: each walk ends its own calls (`pinned`, `queries`) and lets their rows go itself, so
    /// no row is marked and only the drops under way are counted.
    #[cfg(not(wz_round))]
    releases: RowReleases,
    /// Whether a read of the matching listeners found a change since a walk of their rows last
    /// found none owed, written under the session's lock: a delivery that reads it clear takes no
    /// lock to look for one.
    matching_owed: AtomicBool,
    /// The queries waiting for their callbacks and the Finals held for them (`query`).
    #[cfg(feature = "queryable")]
    plane: PlacedRef<QueryPlane>,
    /// What the session's gets queued for their callbacks (`get`).
    #[cfg(feature = "query")]
    gets: PlacedRef<GetPlane>,
    /// What the session's watchers of its faces are owed, and who they are (`connectivity`).
    #[cfg(feature = "connectivity")]
    faces: PlacedRef<FacePlane>,
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
    #[cfg(feature = "threads")]
    reader: Mutex<Option<ReadTask>>,
    /// The run of read tasks, one past each stop: a read task steps the session while the run is
    /// the one it was started in, so a stop needs no word made for it (`ReaderBody`).
    #[cfg(feature = "threads")]
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
    /// The places for values lodged by counts that may outlive the session, the ABI's
    /// ([`PlaceLender::lend_lodging`]) and the engine's own, lent and given back with no lock.
    lodgings: LodgingPlaces,
    /// The ring the session's advanced publishers' caches keep their samples in, under a lock of
    /// its own, which nothing that holds the session's lock takes ([`wz_capi_port::CacheBytes`]).
    #[cfg(feature = "advanced-cache")]
    cache: Mutex<Option<CacheSpan>>,
    /// The takes of the session's locks on a message's paths, which the tests count.
    #[cfg(test)]
    pub(crate) takes: Takes,
    /// The row of the process's table the engine is reached through without being held
    /// ([`EngineHandle`]), taken out at the session's close.
    reach: ReachEngine<Self>,
}

/// What a step of the session came to ([`CoopEngine::step`]).
#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stepped {
    /// The session ended.
    Closed,
    /// The step read records of what a link took from its stack, which holds more of it, and
    /// left the links, the clock and the gets as they stood: the step that reads the last of it
    /// moves them.
    Read,
    /// The step ran to its end at this reading of the session's clock, in microseconds, and moved
    /// the links on by it when they owed a move.
    Moved(u64),
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
    /// The sends on a face of a plain put written from the head its publisher's plain way made.
    pub(crate) planned: core::sync::atomic::AtomicUsize,
    /// The plain puts of a write filter's own way written from its plan, with nothing asked again.
    pub(crate) plans: core::sync::atomic::AtomicUsize,
    /// The keys the session's tables named for a plain put through a write filter.
    pub(crate) namings: core::sync::atomic::AtomicUsize,
    /// The walks of the tables for rows whose last call ended, made only when a call the round
    /// ended said one may wait.
    #[cfg(wz_round)]
    pub(crate) walks: core::sync::atomic::AtomicUsize,
    /// The takes of input by the pump of the one link the read steps itself that read a unit
    /// (`direct`).
    #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
    pub(crate) pump_reads: core::sync::atomic::AtomicUsize,
    /// The received samples a walk handed to its subscribers one row at a time (`pinned`), each
    /// counted once however many rows it reached.
    #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
    pub(crate) pinned_samples: core::sync::atomic::AtomicUsize,
    /// Of the samples handed one row at a time, those read where their frame lies.
    #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
    pub(crate) pinned_lent: core::sync::atomic::AtomicUsize,
    /// The peers' replies the read handed to the get each answers itself (`replies`).
    #[cfg(all(
        feature = "query",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
    pub(crate) pinned_replies: core::sync::atomic::AtomicUsize,
    /// The peers' queries the read handed to a queryable itself (`queries`), one for each
    /// queryable a query reached.
    #[cfg(all(
        feature = "queryable",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
    pub(crate) pinned_queries: core::sync::atomic::AtomicUsize,
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
#[cfg(feature = "threads")]
struct HandBack {
    /// The reads waiting here now: a hand-back with none takes no lock.
    behind: core::sync::atomic::AtomicUsize,
    /// How many times the buffer was handed back to a read waiting here, under the lock its wait
    /// is made with, so that a hand-back before the wait begins ends it at once.
    handed: Mutex<u64>,
    back: os::Condvar,
}

#[cfg(feature = "threads")]
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
struct CoreLock<L: CoopLinks + 'static, C: ClockSource + 'static>(StateLock<Confined<Core<L, C>>>);

impl<L: CoopLinks + 'static, C: ClockSource + 'static> CoreLock<L, C> {
    /// `core` behind the lock, made in `at` with the state written in the lock's own place, its
    /// key arena guarded by it from now on.
    ///
    /// # Safety
    /// As for [`LockForm::init_at`], of a `Self`.
    unsafe fn init_at(at: NonNull<Self>, core: Core<L, C>) {
        core.session.keys.guard_by_owner_lock();
        // SAFETY: the caller's contract, for the one field.
        unsafe {
            <CoopForm as LockForm>::init_at(
                NonNull::new_unchecked(core::ptr::addr_of_mut!((*at.as_ptr()).0)),
                |state| state.write(Confined(core)),
            );
        }
    }

    fn lock(&self) -> CoreGuard<'_, L, C> {
        // Marked before the take, so a take on the thread that holds the lock already fails a
        // debug build instead of waiting on itself.
        let held = wz_capi_port::sync::SessionHeld::enter(core::ptr::from_ref(self).cast());
        CoreGuard::taken(<CoopForm as LockForm>::lock(&self.0), held)
    }

    fn try_lock(&self) -> Option<CoreGuard<'_, L, C>> {
        let guard = <CoopForm as LockForm>::try_lock(&self.0)?;
        let held = wz_capi_port::sync::SessionHeld::enter(core::ptr::from_ref(self).cast());
        Some(CoreGuard::taken(guard, held))
    }

    /// The state with no lock, the engine being let go of: the key arena is marked held for the
    /// rest of the engine's drop, which drops every row that keeps a key.
    fn dropping(&mut self) -> &mut Core<L, C> {
        let core = &mut <CoopForm as LockForm>::get_mut(&mut self.0).0;
        core.session.keys.owner_lock_taken();
        core
    }
}

/// A hold of [`CoreLock`]: the key arena is marked held from its taking to its drop.
struct CoreGuard<'a, L: CoopLinks + 'static, C: ClockSource + 'static> {
    guard: StateGuard<'a, Confined<Core<L, C>>>,
    // The thread's mark of the hold, which a debug build reads: a second take of this lock on
    // this thread, or a C ABI's place given back under it, fails there instead of waiting.
    _held: wz_capi_port::sync::SessionHeld,
}

impl<'a, L: CoopLinks + 'static, C: ClockSource + 'static> CoreGuard<'a, L, C> {
    fn taken(
        guard: StateGuard<'a, Confined<Core<L, C>>>,
        held: wz_capi_port::sync::SessionHeld,
    ) -> Self {
        guard.0.session.keys.owner_lock_taken();
        Self { guard, _held: held }
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + 'static> Deref for CoreGuard<'_, L, C> {
    type Target = Confined<Core<L, C>>;

    fn deref(&self) -> &Confined<Core<L, C>> {
        &self.guard
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + 'static> DerefMut for CoreGuard<'_, L, C> {
    fn deref_mut(&mut self) -> &mut Confined<Core<L, C>> {
        &mut self.guard
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + 'static> Drop for CoreGuard<'_, L, C> {
    // Out of line where the body marks the arena, in a debug build: every hold of the session is
    // let go through it. A release build's body is empty, and a call to it would be all it costs.
    #[cfg_attr(debug_assertions, inline(never))]
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
    places: RoomPlaces,
    mark: u64,
}

/// The places of the table of rooms, one for each set of face tables the open lent
/// (`crate::arena::ArenaPart::RoomPlaces`), lent from the session's arena or laid in its region
/// (`StatePlaces::rooms`), so of the lent policy whichever policy the registry's rows are of.
pub(crate) type RoomPlaces = wz_session_core::bounded::BoundedVec<
    Option<RoomPlace>,
    { crate::arena::MAX_FACE_SETS },
    wz_session_core::bounded::Lent,
>;

/// The bytes of one place of the table of rooms, as the plan lays the places out where the arena
/// lends them.
#[cfg(feature = "runtime-plan")]
pub(crate) const ROOM_PLACE_BYTES: usize = core::mem::size_of::<Option<RoomPlace>>();

/// The bytes of the rooms of a session over `links`, which the open places in the session's
/// arena (`ArenaPlan::holding_rooms`): how large they are is the stack's waits'.
pub(crate) const fn link_rooms_bytes<L: CoopLinks>(_links: &L) -> usize {
    core::mem::size_of::<LinkRooms<L::Waits>>()
}

/// What the face at a place of the table of rooms names.
#[derive(Clone, Copy)]
pub(crate) struct RoomPlace {
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
///
/// The mark has one writer at a time: every mark is made and let go under the session's lock
/// (`CoreLock`), and the holder puts back what it found before it lets go of the lock. So the
/// mark is read and then stored, with no read-modify-write: what the load reads is this thread's
/// own last store or the previous holder's, which the lock's acquire orders before it, and no
/// other thread stores between the two. Its one reader, a droppable publish whose try of the lock
/// just failed (`CoopEngine::holder`), acts on the value alone and reads what it then needs (the
/// table of rooms, the session) under those values' own locks. A sequentially consistent order
/// would matter only if that reader's choice rested on the order of this mark against another
/// atomic, which it does not, and no ordering makes the store seen sooner: a reader that reads a
/// stale mark does what it did before. A release store and an acquire load are enough, and on a
/// host each is a plain move where the swap and the store were each a locked exchange.
struct SendingOn<'a> {
    mark: &'a AtomicU64,
    was: u64,
}

impl<'a> SendingOn<'a> {
    fn enter(mark: &'a AtomicU64, place: u64) -> Self {
        let was = mark.load(Ordering::Relaxed);
        mark.store(place, Ordering::Release);
        Self { mark, was }
    }
}

impl Drop for SendingOn<'_> {
    fn drop(&mut self) {
        self.mark.store(self.was, Ordering::Release);
    }
}

impl<W: LinkWaits> LinkRooms<W> {
    /// The rooms of a session over a stack whose waits are `waits`, a place for each row of
    /// `places`, each free, made in `at` with their lock: none grows after.
    ///
    /// # Safety
    /// `at` is valid for writes of a `Self` and aligned for it, and what it held is overwritten
    /// without being dropped. The rooms are not moved from `at` until they are dropped there.
    pub(crate) unsafe fn init_at(at: NonNull<Self>, waits: W, mut places: RoomPlaces) {
        while places.push(None).is_ok() {}
        let at = at.as_ptr();
        // SAFETY: `at` is valid for writes of a `Self` that stays there (the caller's contract),
        // so each field is too, and each is written once.
        unsafe {
            core::ptr::addr_of_mut!((*at).waits).write(waits);
            os::mutex_in(
                NonNull::new_unchecked(core::ptr::addr_of_mut!((*at).rooms)),
                |rooms| rooms.write(RoomTable { places, mark: 0 }),
            );
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
        lock(&self.rooms).places.fill(None);
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
    /// The write filter of the publisher whose publish this is, whose row keeps the plan its
    /// declare made: a plain put is written from that plan's head on each link that names the key
    /// by the plan's declaration. `None` for a publish no publisher made.
    plan: Option<FilterId>,
}

/// One put as each of the session's links is sent it ([`CoopEngine::send_on_links`]): the key as
/// the session's tables name it, and how it rides.
struct LinkLeg<'a> {
    named: NamedKey<'a>,
    payload: &'a [u8],
    kind: SampleKind,
    meta: &'a PushMetadata<'a>,
    send: wz_session_core::session_actions::SendAs,
    /// The Put's head its publisher's plain way wrote at its declare, which a link that names the
    /// key by that declaration is sent it from: a plain put through a write filter's alone.
    head: Option<wz_session_core::lent_push::PutHead>,
    /// Whether every link names the key as `named` does, by the head's declaration alone, which
    /// a put's plan found at the session's send epoch (`CoopEngine::put_planned`): no link is
    /// asked how it names the key, and each is sent the head.
    planned: bool,
}

/// What a publish's leg to the links finds of the session ([`CoopEngine::live_to_publish`]).
enum ToPublish<'a, L: CoopLinks + 'static, C: ClockSource + 'static> {
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

// SAFETY: a `Confined` is reached only through the lock that holds it in `CoopEngine`
// (`StateLock`), so one thread at a time uses it. Its `Rc` handles and `RefCell` cells are all owned by the `Core`
// inside it: no clone of any of them is ever handed out of the lock (deliveries leave as bytes
// of the delivery lane and `bool`s, see `CoopEngine::samples`), so every handle of each `Rc`
// moves with the `Core` when another thread takes the lock, and none is used by two threads at
// once. A key of the session's key arena handed out of it to an object of the program
// (`HeldKey`, `SessionKeys`) is shared and let go of only under this lock, and read outside it
// only for its text, which nothing writes while the key is held.
unsafe impl<T> Send for Confined<T> {}

/// The network stacks an engine opens its links over: those that serve sessions whose handles are
/// counted as [`SessionLock`] counts a link's parts ([`LinkCount`]), so the form's choice of lock
/// reaches every stack the engine is built over.
pub trait CoopLinks: SessionLinks<LinkCount> {}

impl<L: SessionLinks<LinkCount> + ?Sized> CoopLinks for L {}

/// The runtime a link's session runs on, read under [`SessionLock`].
type LinkRuntime<C> = CoopRuntime<C, dyn wz_session_core::link::BoxedLinkDriver, SessionLock>;

/// The actions of one link's session.
type LinkActions<C> = SessionLinkActions<LinkRuntime<C>, CoopTime<C>>;

/// The handle on the actions of one link's session.
type LinkHandle<C> = SessionHandle<C, dyn wz_session_core::link::BoxedLinkDriver, SessionLock>;

/// What a link's session is lent its values in, where one thread steps the session: the value
/// alone, with no lock of its own. Named so that a runtime of another lock type fails the build
/// here; its leading `_` keeps it out of the dead-code lint.
#[cfg(not(feature = "threads"))]
fn _a_link_session_lends_its_values_unlocked<C: ClockSource>(
    held: <SessionLock as wz_runtime_coop::sync::LockKind>::Mutex<u8>,
    _runtime: core::marker::PhantomData<LinkRuntime<C>>,
) -> wz_runtime_coop::sync::OwnerHeld<u8, UnderCoreLock> {
    held
}

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
pub(crate) type CoopTables = SessionTables<CoopRows, RowPolicy>;

/// The session's one table set, read where the registry keeps it: the application's tables are the
/// session's tables (`Registry::app`), so a declaration and the dispatch that reads it hold one
/// record.
fn tables(registry: &Registry) -> &CoopTables {
    &registry.app.tables
}

/// [`tables`], to write.
fn tables_mut(registry: &mut Registry) -> &mut CoopTables {
    &mut registry.app.tables
}

/// The session's registry as the tasks of its links and groups reach it: lent to them for the
/// length of each pass of the session's tasks ([`Core::run_tasks`], and a group's wait for room in
/// a publish), and the session state's own value between, read and written by `&` and `&mut`.
#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
type RegistryLend = StepLend<Registry, PlacedRef<LendCell<Registry>>>;

/// The handle on the place the session lends its reassembly Router in to its links' receives for
/// the length of each pass of its tasks: a cell in the session's arena (`StepPlaces`).
type RouterPlace = PlacedRef<LendCell<SessionReassembly>>;

/// The bytes of the place the session lends its registry in ([`RegistryLend`]).
#[cfg(all(
    feature = "runtime-plan",
    any(feature = "threads", feature = "listen", feature = "group")
))]
pub(crate) const REGISTRY_LEND_BYTES: usize = core::mem::size_of::<LendCell<Registry>>();

/// The bytes of the place the session lends its reassembly Router in ([`RouterPlace`]).
#[cfg(feature = "runtime-plan")]
pub(crate) const ROUTER_LEND_BYTES: usize = core::mem::size_of::<LendCell<SessionReassembly>>();

/// The places the session lends its registry and its reassembly Router in for a pass of its
/// tasks, each in the session's arena, or in its region where the build fixes its shape
/// (`StatePlaces::steps`), and reached through handles that count nothing: owned by [`Core`],
/// after every holder of a handle of them.
struct StepPlaces {
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    registry: Placed<LendCell<Registry>>,
    router: Placed<LendCell<SessionReassembly>>,
}

impl StepPlaces {
    /// Both places, nothing lent in either, placed in `arena`. Refused past what it has left.
    #[cfg(feature = "runtime-plan")]
    fn placed_in(arena: &mut Arena) -> Result<Self, LendRefused> {
        Ok(Self {
            #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
            registry: arena.place(core::cell::Cell::new(None))?,
            router: arena.place(core::cell::Cell::new(None))?,
        })
    }
}

/// The session's state, held: what [`CoopEngine::live`] hands a caller that may act on it. As it
/// lets go, the round of deliveries it wrote is sealed (`Round::seal`), so what the session wrote
/// under its lock is handed out by the delivery that follows; a build that puts nothing in the
/// round (`wz_round`) seals none.
struct LiveCore<'a, L: CoopLinks + 'static, C: ClockSource + 'static> {
    /// Let go in the hold's own drop, after the seal, so that no caller holds a copy of the lock's
    /// release beside the call to it.
    core: core::mem::ManuallyDrop<CoreGuard<'a, L, C>>,
    #[cfg(wz_round)]
    lane: &'a Round,
}

impl<L: CoopLinks + 'static, C: ClockSource + 'static> Deref for LiveCore<'_, L, C> {
    type Target = Confined<Core<L, C>>;

    fn deref(&self) -> &Confined<Core<L, C>> {
        &self.core
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + 'static> DerefMut for LiveCore<'_, L, C> {
    fn deref_mut(&mut self) -> &mut Confined<Core<L, C>> {
        &mut self.core
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + 'static> Drop for LiveCore<'_, L, C> {
    // Out of line, as `CoopEngine::live` is: every operation lets the session go through it, the
    // round sealed and the lock let go in this one body.
    #[inline(never)]
    fn drop(&mut self) {
        #[cfg(wz_round)]
        // SAFETY: the session's lock is held: `core` is let go below, after the seal.
        unsafe {
            self.lane.seal()
        };
        // SAFETY: this is the hold's drop, so `core` is let go once and nothing reads it after.
        unsafe { core::mem::ManuallyDrop::drop(&mut self.core) };
    }
}

/// The read task: a thread that steps the session until it is told to stop.
#[cfg(feature = "threads")]
struct ReadTask {
    thread: JoinHandle,
    id: ThreadId,
}

/// What the read task's thread runs, handed to whatever makes the thread: a hold of the engine,
/// stepped until the engine's run of read tasks is no longer this one's (`reader_run`). A value
/// of a type that can be named, so the start boxes nothing and makes no word for the stop.
#[cfg(feature = "threads")]
pub(crate) struct ReaderBody<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> {
    engine: EngineHold<CoopEngine<L, C>>,
    run: usize,
}

#[cfg(feature = "threads")]
impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> ReaderBody<L, C> {
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
type Rows<T, const N: usize> =
    wz_session_core::bounded::BoundedVec<T, N, wz_session_core::bounded::Lent>;

/// What a move of the links left settled ([`Core::move_links`]): every face up or waiting for a
/// time, no port to ask and no group. The links are moved again once a face's link ended, a face
/// or a port was changed through the faces' table (`moves`, its count after the move), or a face
/// is due (`due_us`, the earliest of a replay's next turn and a wait to dial again).
#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
#[derive(Clone, Copy)]
struct LinksSettled {
    moves: u32,
    due_us: u64,
}

/// The session's state under its one lock, in the layers that own it: the driver's tasks, clock,
/// policy and arena stay here beside the ABI's places, what the links carry is the transport's
/// ([`TransportState`]) and what the session declared and asked is the session's
/// ([`SessionState`]). Each layer is reached through its own field, so it moves out whole.
struct Core<L: CoopLinks + 'static, C: ClockSource + 'static> {
    /// The session's tasks, and the runtime their cells and timers lie in, which the set holds.
    local: CoopLocalSet<C>,
    clock: C,
    /// What the session's links carry: the links, their cells and reassembly, and what each
    /// handshake announces. Dropped before `session`, so a link is let go of before the tables
    /// and keys its declarations name.
    transport: TransportState<L, C>,
    /// What the session declared and asked, and the round its deliveries go through.
    session: SessionState,
    /// Where the session's registry is lent to the dispatch of its links and groups for the length
    /// of a pass of its tasks: the one way a task reaches it.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    registry_lend: RegistryLend,
    /// Where each link that comes up leaves its wait for room, for the publishes that find the
    /// session held ([`CoopEngine::live_to_publish`]). They lie in the arena, owned here, before
    /// the arena, and reached by the engine through a handle that counts nothing.
    rooms: Placed<LinkRooms<L::Waits>>,
    /// The wake of the links' stack that the program's word that the clock moved on wakes, which
    /// a read waits on beside its links (`CoopConfig::clock_moves`); none for a clock that moves
    /// by itself, or a stack that makes no wake. Held for the session: a wait names it by value.
    #[cfg(feature = "time-base")]
    clock_wake: Option<StackWake>,
    /// The session's one entropy source, which every draw of the session goes through: its zid,
    /// the cookie key of each dial and, through each link's handshake binding (a handle on it,
    /// cloned per link), the cookie nonce and challenges of each handshake it accepts.
    entropy: SessionEntropy<SharedCount>,
    /// The config the session opened with, which counts its endpoints: their texts are the
    /// session's rows (`endpoints`).
    config: CoopConfig<Counted>,
    /// The policies the session runs under, as its open was handed them: every link's session
    /// is given them, and the replay and the admission of a second link follow them.
    policy: SessionPolicy,
    /// Whether the close let go of what the session holds: its row, its links, its tables' rows.
    /// Apart from the session's being closed, which a step that loses the dial role's link says
    /// too, so the close that follows such a step still lets them go, and once.
    released: bool,
    /// The links as the last move left them, when it left them settled ([`Self::move_links`]).
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    links_settled: Option<LinksSettled>,
    /// When the one link the read steps is next due, on the session's clock in microseconds: its
    /// life's next look and its session's own deadlines (`direct`); `u64::MAX` for none.
    #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
    link_due_us: u64,
    /// When the step's bookkeeping is owed next ([`Self::owes_bookkeeping`]).
    ledger: Ledger,
    /// How often the step's bookkeeping ran (`CoopEngine::service`), which the tests count.
    #[cfg(test)]
    services: core::cell::Cell<usize>,
    /// How often a read's wait and its step read the session's clock ([`Self::now_us`]), which the
    /// tests count.
    #[cfg(test)]
    clock_reads: core::cell::Cell<usize>,
    /// How often the links were moved on, which the tests count: each pass over the faces
    /// (`poll_links`), or each look at the life of the one link a read steps itself (`direct`).
    #[cfg(test)]
    link_polls: core::cell::Cell<usize>,
    /// How often the session's links were let go of ([`Self::end_links`]), which the tests count:
    /// once by the close, whatever calls it and from where.
    #[cfg(test)]
    links_let_go: core::cell::Cell<usize>,
    /// How many steps in a row read a group's datagram and moved nothing, up to
    /// the deploy `GROUP_READS_PER_MOVE` limit (`CoopEngine::step`).
    #[cfg(feature = "group")]
    group_reads: usize,
    /// How often a pass of the session's tasks read the clock to wake its timers
    /// ([`Self::run_tasks`]), which the tests count. Kept where the tests that read it build
    /// (`std`): a build whose read steps its one link itself makes no pass to read it otherwise.
    #[cfg(all(test, feature = "std"))]
    task_clock_reads: core::cell::Cell<usize>,
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
    /// The places the session lends its registry and its Router in for a pass of its tasks: after
    /// every holder of a handle of them (the transport, the tasks, `registry_lend`). Held for its
    /// owner's drop alone: the session reaches the places through those handles.
    _steps: StepPlaces,
    /// The admission the session's links ask while their handshakes run, which each link's lease
    /// and the transport reach by handles that count nothing: after the transport, the state and
    /// the tasks, which hold every lease, and before the arena it lies in. Held for its owner's
    /// drop alone.
    #[cfg(feature = "listen")]
    _admission: Placed<Admission<C>>,
    /// The region the session's registry and its key arena lie in (`crate::region`): after the
    /// session's state, whose handle of the registry drops it in place, and every table that keeps
    /// a key in it. Held for its owner's drop alone: the session reaches the region through those
    /// handles.
    #[cfg(not(feature = "runtime-plan"))]
    _state: RegionBlock<StateRegion>,
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
    type Registry = RegistryHold;
    type Faces = Registry;
    type Callbacks = CoopRows;
    type Storage = RowPolicy;
    /// Where a face coming up or going down is reported (`connectivity`).
    #[cfg(feature = "connectivity")]
    type Watchers = Placed<FacePlane>;
    #[cfg(not(feature = "connectivity"))]
    type Watchers = ();
    /// The tables hold each plane's write filters to its own bound: nothing is kept apart.
    type Entities = ();
    #[cfg(feature = "queryable")]
    type Queryables = Placed<QueryPlane>;
    #[cfg(not(feature = "queryable"))]
    type Queryables = ();
    /// The legs of the session's gets still pending on its links, in rows the session's arena lent.
    #[cfg(feature = "query")]
    type PendingGets = Rows<PendingGet, { usize::MAX }>;
    #[cfg(not(feature = "query"))]
    type PendingGets = ();
    #[cfg(feature = "query")]
    type Gets = Placed<GetPlane>;
    #[cfg(not(feature = "query"))]
    type Gets = ();
    /// Asked by every link's gate before it reads a record (`crate::round::RoundGate`): owned
    /// here, in the session's arena, and reached by the gates through handles of it.
    #[cfg(wz_round)]
    type Lane = Placed<Round>;
    /// A build that puts nothing in the round (`wz_round`) places none, and its gates ask none.
    #[cfg(not(wz_round))]
    type Lane = ();
    #[cfg(feature = "shared-key-ids")]
    type KeyIds = Option<SharedKeyIds>;
    #[cfg(not(feature = "shared-key-ids"))]
    type KeyIds = ();
    #[cfg(feature = "local-queryable")]
    type LocalRequests = LocalRequests;
    #[cfg(not(feature = "local-queryable"))]
    type LocalRequests = ();

    fn tables(registry: &RegistryHold) -> &CoopTables {
        tables(registry)
    }

    fn tables_mut(registry: &mut RegistryHold) -> &mut CoopTables {
        tables_mut(registry)
    }

    fn faces(registry: &RegistryHold) -> &Registry {
        registry
    }

    fn faces_mut(registry: &mut RegistryHold) -> &mut Registry {
        registry
    }
}

/// One face of the session: the link it holds, and where the telling of the session's
/// declarations to that link's peer stands (`replay`).
struct Face<C: ClockSource + 'static, L: CoopLinks> {
    id: FaceId,
    link: Link<LinkSession<C>, L::Dial, FaceEnd, LinkCount>,
    /// Where the face's link stands: the one state of it the session keeps.
    life: UnicastLink,
    replay: Replay,
    /// What the connectivity listeners whose history is being replayed were told of the face, and
    /// the tomb of a row of it that went (`told`).
    #[cfg(feature = "connectivity")]
    told: FaceTold,
}

impl<C: ClockSource + 'static, L: CoopLinks> FaceRecord<LinkCount> for Face<C, L> {
    type Session = LinkSession<C>;
    type Pump = L::Pump;
    type Dial = L::Dial;
    type End = FaceEnd;

    fn id(&self) -> FaceId {
        self.id
    }

    fn link(&self) -> &Link<LinkSession<C>, L::Dial, FaceEnd, LinkCount> {
        &self.link
    }

    fn link_mut(&mut self) -> &mut Link<LinkSession<C>, L::Dial, FaceEnd, LinkCount> {
        &mut self.link
    }

    fn life(&self) -> &UnicastLink {
        &self.life
    }

    fn life_mut(&mut self) -> &mut UnicastLink {
        &mut self.life
    }
}

#[cfg(any(feature = "listen", feature = "connectivity"))]
impl<C: ClockSource + 'static, L: CoopLinks> Face<C, L> {
    /// Build the face numbered `id` that holds `link`, its life of `role` over `endpoints`
    /// endpoints counted in `times`, in `place`, the free place of the faces' table it keeps
    /// ([`VacantPlace::fill`]), and lend it: its life, the machine whose engine is the largest
    /// part of a face, is built where it lies, so no frame of the caller holds it and the face is
    /// not moved into its place. A face that listeners are told of starts with nothing told.
    ///
    /// [`VacantPlace::fill`]: wz_runtime_coop::faces::VacantPlace::fill
    fn make_in(
        place: &mut core::mem::MaybeUninit<Self>,
        id: FaceId,
        link: Link<LinkSession<C>, L::Dial, FaceEnd, LinkCount>,
        times: LinkTimes,
        role: LinkRole,
        endpoints: usize,
    ) -> &mut Self {
        let at = place.as_mut_ptr();
        // A field added to the face and not written below would be read uninitialised. This names
        // every field with no `..`, so adding one without naming it here (and so without writing
        // it below) does not compile.
        let _every_field_is_written = |face: &Self| {
            let Self {
                id: _,
                link: _,
                life: _,
                replay: _,
                #[cfg(feature = "connectivity")]
                    told: _,
            } = face;
        };
        // SAFETY: `at` is valid for writes of a `Self`, and each field is written once through a
        // pointer to it, the life by `init_in`, which writes it whole (a `MaybeUninit<T>` has the
        // layout of `T`). The list above names every field, so the face is whole when it is lent,
        // for as long as `place` is.
        unsafe {
            core::ptr::addr_of_mut!((*at).id).write(id);
            core::ptr::addr_of_mut!((*at).link).write(link);
            UnicastLink::init_in(
                &mut *core::ptr::addr_of_mut!((*at).life)
                    .cast::<core::mem::MaybeUninit<UnicastLink>>(),
                times,
                role,
                endpoints,
            );
            core::ptr::addr_of_mut!((*at).replay).write(Replay::idle());
            #[cfg(feature = "connectivity")]
            core::ptr::addr_of_mut!((*at).told).write(FaceTold::default());
            &mut *at
        }
    }
}

/// The times the life of each link of a session opened with `config` is counted in: a dial and
/// its handshake by the open's timeout, an accepted link's handshake by the acceptor's.
fn link_times<E>(config: &CoopConfig<E>) -> LinkTimes {
    LinkTimes {
        open_timeout_ms: config.open_timeout_ms,
        redial_ms: config.redial_ms,
        dial_look_ms: DIAL_LOOK_MS,
        accept_timeout_ms: config.timeouts.accepting_inactivity_ms,
    }
}

/// One link's half of the session: the actions that send over it. The task that runs the link,
/// the link itself and its owner's waits for it are the driver's (`Wire`).
struct LinkSession<C: ClockSource + 'static> {
    actions: LinkHandle<C>,
    /// The link's gates, whose admission is granted when the face is brought up (`bring_up`);
    /// until then the link gives the session nothing past its handshake, so the watchers hear the
    /// face come up before anything its link carried. A session of several links tells them what
    /// each wait found in the link's stack (`input_seen`).
    #[cfg(any(feature = "listen", feature = "group"))]
    gate: CellRc<LinkGate<C>, LinkCount>,
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

    #[cfg(any(feature = "listen", feature = "group"))]
    fn input_seen(&self, ready: bool) {
        self.gate.input_seen(ready);
    }
}

impl<C: ClockSource + 'static> TransportSession<C, SessionLock> for LinkSession<C> {
    fn actions(&self) -> &LinkHandle<C> {
        &self.actions
    }

    #[cfg(feature = "queryable")]
    fn answers_as(&self, generation: u64) -> bool {
        self.generation == generation
    }
}

/// One link of the session: its session half ([`LinkSession`]) and what the driver holds of it.
#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
type Wire<C> = wz_runtime_coop::faces::Wire<LinkSession<C>, FaceEnd, LinkCount>;

/// How the session of a face's link ends: with its task, or, where the read steps the one link
/// itself, as the read's last step of it said (`direct`).
#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
type FaceEnd = wz_runtime_coop::faces::TaskEnd;
/// How the session of a face's link ends: with its task, or, where the read steps the one link
/// itself, as the read's last step of it said (`direct`).
#[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
type FaceEnd = direct::DirectEnd;

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
    /// What the ABI's key kept alive (an object of the ABI's), let go of with the row, with no
    /// lock of the session held: the declarations the key and the retraction name are the tables'
    /// row's to hold.
    _anchor: KeyAnchor,
    /// The program's callback, called where the row lies: the tables lend their rows from the
    /// session's arena and never move one.
    sink: SubscriberSink,
    /// Whether the callback is shown each sample's timestamp (`entity-timestamp-opt-in`).
    expose: bool,
    /// How many calls of the callback run, and whether the subscriber was undeclared.
    latch: Latch,
}

impl SubscriberRow {
    /// A subscriber keeping `anchor`, handing what it hears to `sink`, the timestamp shown when
    /// `expose`.
    // Out of line: measured smaller apart from the declaration that builds the row.
    #[inline(never)]
    pub(crate) fn new(anchor: KeyAnchor, sink: SubscriberSink, expose: bool) -> Self {
        Self {
            _anchor: anchor,
            sink,
            expose,
            latch: Latch::new(),
        }
    }

    /// Hand `sample` to the callback, unless the subscriber was undeclared since the call was
    /// begun: the one place a sample is handed to a subscriber's callback.
    fn hand(&self, sample: &SampleRef<'_>) {
        if self.latch.retired() {
            return;
        }
        let hidden;
        // A sample that carries no timestamp has none to hide: it is handed as it lies, with no
        // copy made of it for each call.
        let sample = if self.expose || sample.timestamp.is_none() {
            sample
        } else {
            hidden = sample.without_timestamp();
            &hidden
        };
        self.sink.call_ref(sample);
    }

    /// Declare subscriber `id`, the id its row in the tables holds, on `key`, over `actions`:
    /// whether the link took it.
    fn declare<C: ClockSource + 'static>(
        id: SubId,
        key: NamedKey<'_>,
        actions: &LinkActions<C>,
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
        actions: &LinkActions<C>,
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
    <RowPolicy as wz_session_core::bounded::Storage>::LENT_AT_OPEN,
    "the session's tables lend their rows from its arena and never move one"
);

// A delivery ends a call with no lock of the session held; a target whose latch is ended only with
// the tables held has no atomic read-modify-write of a word, and so no `Arc` this engine is built on.
const _: () = assert!(
    !Latch::ENDS_HELD,
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
    pub(crate) fn hand(&self, sample: &SampleRef<'_>) {
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
/// The round is held only where a plane tells it through the delivery: where the read runs beside
/// the program's calls, a subscriber's sample, a token, a query and a declaration watch's event.
/// The read that hands each record out as it is read hands each of them out itself, so its delivery
/// holds the queryables' plane alone, for the session's own get, or nothing.
pub(crate) struct RoundDelivery {
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    round: PlacedRef<Round>,
    #[cfg(feature = "queryable")]
    plane: PlacedRef<QueryPlane>,
}

// The read that hands each record out as it is read hands every sample out itself, one subscriber
// at a time (`pinned`): only a build whose read runs beside the program's calls offers the round
// a sample.
#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
impl SampleDelivery<SubscriberRow, SubscriberHandle> for RoundDelivery {
    fn deliver(
        &mut self,
        id: SubscriberHandle,
        row: RowAccess<'_, SubscriberRow>,
        sample: &dyn SampleView,
        turn: FanOut,
    ) {
        self.deliver_ref(id, row, &SampleRef::of(sample), turn);
    }

    fn deliver_ref(
        &mut self,
        _id: SubscriberHandle,
        row: RowAccess<'_, SubscriberRow>,
        sample: &SampleRef<'_>,
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
                .offer_sample_ref(SubscriberCall::new(call), sample, turn.is_first())
        };
    }
}

// The delivery traits are the rows': each names the context its row is told through, here the
// session's round of deliveries and its query plane.
#[cfg(all(
    feature = "liveliness",
    any(feature = "threads", feature = "listen", feature = "group")
))]
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

/// A read that steps its one link itself hands each peer token to the liveliness subscribers it
/// reaches itself, one row at a time with the session let go of (`TakenAhead::tokens`), so no
/// plane tells a row a token: the observer's sinks name a delivery all the same.
#[cfg(all(
    feature = "liveliness",
    not(any(feature = "threads", feature = "listen", feature = "group"))
))]
impl
    wz_session_core::declare::liveliness_subscriber::LivelinessDelivered<
        RoundDelivery,
        LivelinessSubscriberHandle,
    > for LivelinessRow
{
    fn tell(
        _cx: &mut RoundDelivery,
        _id: LivelinessSubscriberHandle,
        _row: RowAccess<'_, LivelinessRow>,
        _sample: LivelinessSample<'_>,
    ) {
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
        #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
        unsafe {
            cx.plane
                .arrive(&cx.round, || QueryableCall::begin(row.row()), query)
        };
        // A read that steps its one link itself hands each query of the link to the queryables
        // (`queries`), so only the session's own get is asked here, which hands the calls its
        // queryables begin its own view.
        #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
        cx.plane
            .arrive_own(|| QueryableCall::begin(row.row()), query);
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
    actions: &LinkActions<C>,
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
    actions: &LinkActions<C>,
    key: NamedKey<'k>,
) -> NamedKey<'k> {
    actions.named_on_link(key)
}

/// A build without the shared key ids names every key on every link as the session names it.
#[cfg(not(feature = "shared-key-ids"))]
#[inline(always)]
fn key_on_link<'k, C: ClockSource + 'static>(
    _actions: &LinkActions<C>,
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
    _actions: &LinkActions<C>,
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
    actions: &LinkActions<C>,
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
    _actions: &LinkActions<C>,
    _keyexpr: &str,
    _aggregate: bool,
) -> Option<InterestForm> {
    None
}

/// Send the Interest `row` holds open over `actions`, for what is declared now and what is
/// declared later, naming its key as the link's key-wire form says: whether the link took it.
fn send_interest<K: KeyBacking, C: ClockSource + 'static>(
    row: &InterestRow<K>,
    actions: &LinkActions<C>,
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
/// order: read while it stands, for its Final's place once it is let go of. `None` when it names
/// none. A build that reaches no pace reads no place (`replay`), so only whether it stands.
fn interest_rank(tables: &CoopTables, handle: Option<InterestHandle>) -> Option<usize> {
    if !ReplayPacing::REACHABLE {
        return tables.interests().get(handle?).map(|_| 0);
    }
    tables.interests().rank_of(handle?)
}

/// Take the write filter `handle` names out of `tables`, with the listeners declared on it, let go
/// of there: the id of the Interest it held last, `None` when no filter is there.
fn unwatch_filter(tables: &mut CoopTables, handle: WriteFilterHandle) -> Option<Option<EntityId>> {
    tables
        .undeclare_write_filter_quietly(handle)
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
fn batch_link<C: ClockSource + 'static>(actions: &LinkActions<C>, step: BatchStep) -> bool {
    match step {
        BatchStep::Start => actions.batch_start(),
        BatchStep::Flush => actions.batch_flush(),
        BatchStep::Stop => actions.batch_stop(),
    }
    .is_ok()
}

fn undeclare_kexpr<C: ClockSource + 'static>(mapping_id: ExprId) -> impl Fn(&LinkActions<C>) {
    move |actions| actions.send_undeclare_kexpr(mapping_id)
}

/// What tells a link that the Interest `id` ends, one closure type for every caller as
/// [`undeclare_kexpr`] is.
fn interest_final<C: ClockSource + 'static>(id: u64) -> impl Fn(&LinkActions<C>) {
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

/// Where one leg of a get is held pending (`CoopEngine::hold_leg`): in the table of `face` (a
/// link's, a group's, or the session's own, `LOCAL_FACE`) under `rid`, the leg's id `leg`, owed
/// `finals` Finals.
#[cfg(feature = "query")]
struct LegEntry {
    face: FaceId,
    leg: u64,
    rid: wz_session_core::wire_id::RequestId,
    finals: u32,
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
/// the deliveries drain sit behind: the planes' of the engine's calls (`PlaneCalls::Queues`, every
/// build that names them, `crate::calls`), the faces' watchers (`connectivity`) and the gets'
/// queues (`query`).
#[cfg(any(
    wz_round,
    feature = "query",
    feature = "queryable",
    feature = "connectivity"
))]
pub(crate) enum CoopLocks {}

#[cfg(any(
    wz_round,
    feature = "query",
    feature = "queryable",
    feature = "connectivity"
))]
impl wz_session_core::plane_lock::LockFamily for CoopLocks {
    type Lock<T> = Mutex<T>;

    unsafe fn init_at<T>(
        place: NonNull<Mutex<T>>,
        make: impl FnOnce(&mut core::mem::MaybeUninit<T>) -> &mut T,
    ) {
        // SAFETY: the caller's contract is `mutex_in`'s.
        unsafe { os::mutex_in(place, make) }
    }

    fn with<T, R>(lock: &Mutex<T>, f: impl FnOnce(&mut T) -> R) -> R {
        f(&mut lock.lock())
    }
}

#[cfg(all(test, feature = "std"))]
mod plane_lock_tests {
    use super::{CoopLocks, Mutex};
    use core::mem::MaybeUninit;
    use core::ptr::NonNull;
    use wz_session_core::plane_lock::LockFamily;

    /// A plane's lock made in a place holds there the value its maker wrote, and is dropped there
    /// once. Where the host's lock takes the value is the host lock's own (`wz-host-sync`: in place
    /// where `std`'s would box, moved once into `std`'s otherwise). Turned red by a family that
    /// writes the lock anywhere but the place it is handed, or loses the value made.
    #[test]
    fn a_planes_lock_made_in_a_place_holds_what_its_maker_wrote() {
        let mut place = MaybeUninit::<Mutex<[u8; 64]>>::uninit();
        // SAFETY: the place is valid for writes of a lock of `[u8; 64]`, the type written, and
        // the lock is dropped there below.
        unsafe {
            CoopLocks::init_at(
                NonNull::from(&mut place).cast::<Mutex<[u8; 64]>>(),
                |value: &mut MaybeUninit<[u8; 64]>| value.write([7; 64]),
            );
        }
        // SAFETY: the lock was made in the place above.
        let lock = unsafe { place.assume_init_ref() };
        assert_eq!(CoopLocks::with(lock, |value| (value[0], value[63])), (7, 7));
        // SAFETY: the lock was made in the place and is dropped once, there.
        unsafe { place.assume_init_drop() };
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
#[cfg(all(
    debug_assertions,
    any(feature = "threads", feature = "listen", feature = "group")
))]
struct Gated<'a>(&'a Round);

#[cfg(all(
    debug_assertions,
    any(feature = "threads", feature = "listen", feature = "group")
))]
impl<'a> Gated<'a> {
    fn over(lane: &'a Round) -> Self {
        lane.offering_gated(true);
        Self(lane)
    }
}

#[cfg(all(
    debug_assertions,
    any(feature = "threads", feature = "listen", feature = "group")
))]
impl Drop for Gated<'_> {
    fn drop(&mut self) {
        self.0.offering_gated(false);
    }
}

/// What a dispatch that finds the session's registry not lent says: every pass of the session's
/// tasks lends it, so a task stepped outside one is a fault of the engine.
#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
const UNLENT: &str = "a task of the session dispatched outside a pass that lends its registry";

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
#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
pub(crate) struct FaceDispatch<C: ClockSource + 'static> {
    /// The session's registry, lent for each pass of the session's tasks.
    registry: RegistryLend,
    /// The face the link serves, its set found by its place for every frame and not looked for.
    face: HeldFace,
    actions: LinkHandle<C>,
    #[cfg(feature = "queryable")]
    plane: PlacedRef<QueryPlane>,
    /// The link's generation, which the queries it carries are answered under.
    #[cfg(feature = "queryable")]
    generation: u64,
    /// The session's round of deliveries: told where a rejoined message lies while its records are
    /// dispatched, and, in a debug build, that what is offered waited for room (`Gated`).
    lane: PlacedRef<Round>,
    /// Whether Pushes were dispatched whose drains are still owed ([`EventSink::end_records`]).
    after_pushes: bool,
}

#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
impl<C: ClockSource + 'static> EventSink for FaceDispatch<C> {
    #[cfg(feature = "queryable")]
    fn event(&mut self, event: IterationEvent<'_, '_>) {
        let face = self.face;
        // A Push is no query and no declaration: it is handed to the subscribers alone, and what
        // follows a record (the drains, the Finals owed) is put off to the end of its run.
        if lent_push(&event) {
            #[cfg(debug_assertions)]
            let _gated = Gated::over(&self.lane);
            let dispatched = self
                .registry
                .with(|registry| registry.dispatch_push(face, event));
            debug_assert!(dispatched.is_some(), "{UNLENT}");
            self.after_pushes = true;
            return;
        }
        // What the Pushes before this record put off is done before it, as it was after each.
        #[cfg(all(test, feature = "std", feature = "queryable"))]
        if self.after_pushes {
            let _ = self
                .registry
                .with(|registry| registry.count_drain_within_frame());
        }
        self.end_records();
        #[cfg(debug_assertions)]
        let _gated = Gated::over(&self.lane);
        let actions = &*self.actions;
        let plane = &self.plane;
        let generation = self.generation;
        let dispatched = self.registry.with(|registry| {
            // The queries this frame carries arrive on this face's link, whichever was
            // dialled last.
            plane.set_arriving(generation);
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
            for (rid, qos) in registry.take_pending_final_rids(face) {
                if plane.with_holds(|holds| holds.owe(generation, rid, qos)) {
                    actions.send_response_final(rid, qos);
                }
            }
        });
        debug_assert!(dispatched.is_some(), "{UNLENT}");
    }

    #[cfg(not(feature = "queryable"))]
    fn event(&mut self, event: IterationEvent<'_, '_>) {
        let face = self.face;
        // A Push is no query and no declaration: it is handed to the subscribers alone, and what
        // follows a record (the drains) is put off to the end of its run.
        if lent_push(&event) {
            #[cfg(debug_assertions)]
            let _gated = Gated::over(&self.lane);
            let dispatched = self
                .registry
                .with(|registry| registry.dispatch_push(face, event));
            debug_assert!(dispatched.is_some(), "{UNLENT}");
            self.after_pushes = true;
            return;
        }
        // What the Pushes before this record put off is done before it, as it was after each.
        #[cfg(all(test, feature = "std", feature = "queryable"))]
        if self.after_pushes {
            let _ = self
                .registry
                .with(|registry| registry.count_drain_within_frame());
        }
        self.end_records();
        #[cfg(debug_assertions)]
        let _gated = Gated::over(&self.lane);
        let actions = &*self.actions;
        let dispatched = self.registry.with(|registry| {
            // What the declaration watches are told of this frame is this link's peer's.
            #[cfg(any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ))]
            registry.hear_decl_link(|| actions.peer_session_zid());
            registry.dispatch(face, event, actions);
        });
        debug_assert!(dispatched.is_some(), "{UNLENT}");
    }

    /// The drains a run of Pushes put off ([`Registry::settle`]), once for the run: at the
    /// end of the frame, or before the first record of it that is not a Push.
    fn end_records(&mut self) {
        if !core::mem::take(&mut self.after_pushes) {
            return;
        }
        let face = self.face;
        let actions = &*self.actions;
        let dispatched = self
            .registry
            .with(|registry| registry.settle(face, actions));
        debug_assert!(dispatched.is_some(), "{UNLENT}");
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
/// `listen` the admission's under it, which carries the clock; where the read hands each record
/// out as it is read, the link alone.
trait LinkGates {
    /// The gates.
    type Gate;
}

impl<C: ClockSource + 'static> LinkGates for C {
    #[cfg(feature = "listen")]
    type Gate =
        RoundGate<AdmissionGate<CellRc<dyn SessionDatagramLink, LinkCount>, C, SessionLock>>;
    #[cfg(all(not(feature = "listen"), any(feature = "threads", feature = "group")))]
    type Gate = RoundGate<CellRc<dyn SessionDatagramLink, LinkCount>>;
    // The read steps the one link itself and hands each record out as it is read, so nothing
    // holds the link back from its session, and it keeps no round to tell where the datagram it
    // lends lies (`direct`): the link is the pump.
    #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
    type Gate = CellRc<dyn SessionDatagramLink, LinkCount>;
}

/// The gates of a link of a session on the clock `C` ([`LinkGates`]).
type LinkGate<C> = <C as LinkGates>::Gate;

/// The two halves the actions of a link of a session on the clock `C` hold, which the session
/// places together in the link's cell of its table (`TransportState::halves_cells`): the link's
/// own state and the session's kernel.
type LinkHalves<C> = (
    LinkState<LinkRuntime<C>>,
    SessionCore<LinkRuntime<C>, CoopTime<C>>,
);

/// The bytes of each link's cells a session over `links` on the clock `C` lays out: a cell for
/// each link's driver as large as the largest the links open, one for its gates, one for its
/// actions and one for the two halves they hold.
pub(crate) fn link_cells<C: ClockSource + 'static>(links: &impl CoopLinks) -> LinkCells<usize> {
    LinkCells {
        driver: links.link_cell_bytes(),
        gate: CellRc::<LinkGate<C>>::cell_bytes(),
        actions: CellRc::<LinkActions<C>>::cell_bytes(),
        halves: CellRc::<LinkHalves<C>>::cell_bytes(),
    }
}

/// What an open lays out after the rows its limits size ([`lay_out_open`]), which the session's
/// config does not count: what its links and its runtime are made of, and the places the ABI holds.
pub(crate) struct OpenHolds<'h> {
    /// The bytes of each link's cells.
    pub(crate) cells: LinkCells<usize>,
    /// The bytes of the faces' rooms.
    pub(crate) rooms: usize,
    /// The ABI's places.
    pub(crate) held: &'h HeldPlaces,
    /// The span the session's runtime is placed in.
    pub(crate) runtime: usize,
    /// The place the session's engine lies in.
    pub(crate) engine: usize,
    /// The places of the planes the session's state owns.
    pub(crate) planes: SessionPlanes,
    /// The place of the admission the links of a session that listens ask ([`Admission`]).
    #[cfg(feature = "listen")]
    pub(crate) admission: usize,
}

/// The admission the links of a session over the clock `C` ask while their handshakes run: owned
/// by the session's state where its arena lent it, and reached by each link's lease through a
/// handle that counts nothing.
#[cfg(feature = "listen")]
pub(crate) type Admission<C> = LinkRegistry<CoopRuntime<C>>;

/// The admission as its links' leases ask it.
#[cfg(feature = "listen")]
fn as_link_admission<C: ClockSource + 'static>(
    admission: &Admission<C>,
) -> &(dyn LinkAdmission + 'static) {
    admission
}

/// The bytes of the place of each plane a session's state owns, which its tasks and its engine
/// reach by handles that count nothing, each where its feature is ([`ArenaPlan::lay_planes`]).
#[derive(Clone, Copy)]
pub(crate) struct SessionPlanes {
    /// The queryables' plane (`QueryPlane`), in the arena where the open lays it out.
    #[cfg(all(feature = "queryable", feature = "runtime-plan"))]
    pub(crate) queries: usize,
    /// The gets' plane (`GetPlane`), in the arena where the open lays it out.
    #[cfg(all(feature = "query", feature = "runtime-plan"))]
    pub(crate) gets: usize,
    /// The plane of the watchers of the faces (`FacePlane`), in the arena where the open lays it out.
    #[cfg(all(feature = "connectivity", feature = "runtime-plan"))]
    pub(crate) faces: usize,
}

impl SessionPlanes {
    /// This build's planes.
    pub(crate) const OF_BUILD: Self = Self {
        #[cfg(all(feature = "queryable", feature = "runtime-plan"))]
        queries: core::mem::size_of::<QueryPlane>(),
        #[cfg(all(feature = "query", feature = "runtime-plan"))]
        gets: core::mem::size_of::<GetPlane>(),
        #[cfg(all(feature = "connectivity", feature = "runtime-plan"))]
        faces: core::mem::size_of::<FacePlane>(),
    };
}

/// Lay out on `plan`, the rows an open's limits size ([`ArenaPlan::count`]), the cells
/// `holds.cells` sizes for each link, the faces' rooms, the ABI's places and then the span the
/// session's runtime is placed in, the place its engine lies in and the places of its planes,
/// after every other row: the one plan an open reserves by. Laid
/// out where the plan lies, which `lend_session` reads in its own frame: a plan handed back by
/// value would be moved again, twice, by the open that reads it.
pub(crate) fn lay_out_open(
    plan: &mut ArenaPlan,
    holds: &OpenHolds<'_>,
) -> Result<(), ArenaRefused> {
    plan.lay_cells(holds.cells);
    plan.lay_rooms(holds.rooms);
    plan.lay_held(holds.held)?;
    plan.lay_runtime(holds.runtime);
    plan.lay_engine(holds.engine);
    plan.lay_planes(holds.planes);
    #[cfg(feature = "listen")]
    plan.lay_admission(holds.admission);
    // Each hold keeps its refusal in the plan, the first one kept, so the plan is asked once,
    // after them all, and answers what the first refused hold would have.
    plan.settled()
}

/// The bytes of the task a link's session runs as on this engine: `RouterSessionTask` over the
/// link's gates, the place the session lends its one reassembly Router in and `FaceDispatch`.
/// What each cell the open reserves for a link holds, so a link's session is never refused a cell
/// for its size.
#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
pub(crate) const fn link_task_bytes<C: ClockSource + 'static>() -> usize {
    router_session_task_bytes::<
        C,
        CellRc<dyn SessionDatagramLink, LinkCount>,
        RouterLend<SessionReassembly, RouterPlace>,
        RouterLend<SessionReassembly, RouterPlace>,
        FaceDispatch<C>,
        SessionLock,
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

/// The deadlines a session's runtime holds at once: the entries of its timer table, which only a
/// task that sleeps or times out on the runtime (`CoopTime`'s `sleep` and `timeout`) places a
/// deadline in. A session keeps its own deadlines (the lease, the keep-alive, the next dial, the idle
/// wait) in places of its own and reads them off the clock at each step, so the table is the
/// build's `MAX_TIMERS` entries only in a build with a feature whose task sleeps on the runtime,
/// and none otherwise, with no making of a table linked.
pub(crate) const RUNTIME_TIMERS: usize = if TASKS_SLEEP { caps::MAX_TIMERS } else { 0 };

/// Whether a feature of the build spawns a task that sleeps or times out on the session's runtime.
/// The `cfg` names every such feature, and no feature of this engine is one: a feature that
/// spawns such a task names itself here.
const TASKS_SLEEP: bool = cfg!(any());

/// What a session's runtime reserves when the session opens (`Self::runtime`), from the build's
/// limits and the faces its config admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeTables {
    /// Reserved at once: a task cell for each face the session may hold at once (the dial role's
    /// when it dials, and each `max_faces` admits, a link in its handshake among them: a link
    /// taken off a port past them is closed before it has a task), in the bytes a link's session task takes
    /// (`link_task_bytes`), and `RUNTIME_TIMERS` deadlines.
    pub(crate) rows: RuntimeRows,
    /// The cells the open may add, one for each group it joins: a group's task is a future no
    /// type names, so its cell takes the bytes the task has when the open spawns it.
    pub(crate) groups: usize,
}

impl RuntimeTables {
    /// The tables of a session `config` opens, its task cells together at most the build's
    /// `MAX_TASKS`: the groups' first, as a session that cannot join a group it was told to does
    /// not open, then the links', so a face past them is refused as one past `max_faces` is.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    pub(crate) fn of<C: ClockSource + 'static>(config: &CoopConfig<impl EndpointList>) -> Self {
        let groups = config.groups.len().min(caps::MAX_TASKS);
        let links = usize::from(crate::arena::dials(config))
            .saturating_add(config.max_faces)
            .min(caps::MAX_TASKS.saturating_sub(groups));
        Self::holding(groups, links, link_task_bytes::<C>())
    }

    /// The tables of a session `config` opens whose one link a read steps itself: that link runs
    /// as no task, and its session lies in the engine (`direct`), so no cell is reserved for it
    /// and the clock's type sizes nothing here.
    #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
    pub(crate) fn of(config: &CoopConfig<impl EndpointList>) -> Self {
        Self::holding(config.groups.len().min(caps::MAX_TASKS), 0, 0)
    }

    /// The tables of `groups` groups' cells and `links` links' cells of `task_bytes` each.
    fn holding(groups: usize, links: usize, task_bytes: usize) -> Self {
        Self {
            rows: RuntimeRows {
                tasks: links,
                task_bytes,
                timers: RUNTIME_TIMERS,
            },
            groups,
        }
    }

    /// The runtime these tables are reserved for. A build that joins groups reserves the links'
    /// cells and holds a bare cell for each group, given the bytes the group's task needs when the
    /// open spawns it, and sealed once the open is over (`open_links`). A build that joins none
    /// reserves every cell for a link, and its runtime takes no memory after it is made: a config
    /// that names a group is refused by name there, so the groups' cells are none. A build that
    /// neither joins groups nor listens takes no face beside its dial role's, so its runtime hosts
    /// that one link's task and is made for one (`CoopRuntime::try_reserved_for_one`), which links no
    /// walk of a table of many cells.
    ///
    /// The runtime is placed in `place`, the span of the session's arena the open lent it
    /// ([`Self::placed_bytes`]), with the session's local set: nothing of them is of the heap.
    /// `None` for a span short of it.
    pub(crate) fn runtime<C: ClockSource>(
        self,
        clock: C,
        place: RuntimePlace,
    ) -> Option<(CoopRuntime<C>, CoopLocalSet<C>)> {
        CoopRuntime::placed(clock, self.rows(), Self::form(self.groups), place)
    }

    /// The bytes of the span of the session's arena [`Self::runtime`] places the runtime in;
    /// `None` past the address space.
    pub(crate) fn placed_bytes<C: ClockSource>(self) -> Option<usize> {
        CoopRuntime::<C>::placed_layout(self.rows(), Self::form(self.groups))
            .map(|span| span.size())
    }

    /// The rows the runtime is made with. The timers are stated as the constant they are, so the
    /// making of the timer table is that of the build's count alone; a build that joins no group
    /// adds no cell while its open lasts, and reserves the groups' with the links' (none, as a
    /// config that names a group is refused by name there).
    fn rows(self) -> RuntimeRows {
        let tasks = if cfg!(feature = "group") {
            self.rows.tasks
        } else {
            self.rows.tasks.saturating_add(self.groups)
        };
        RuntimeRows {
            tasks,
            timers: RUNTIME_TIMERS,
            ..self.rows
        }
    }

    /// The table of the build's runtime, a constant of the build: cells added while the open lasts
    /// for the `groups` it joins (`group`), every cell reserved (`listen`), or the one cell of
    /// the dial role's link.
    const fn form(groups: usize) -> RuntimeForm {
        if cfg!(feature = "group") {
            RuntimeForm::Opening { added: groups }
        } else if cfg!(feature = "listen") {
            RuntimeForm::Reserved
        } else {
            RuntimeForm::ForOne
        }
    }
}

/// The session's part in the making of each of its links' sessions (`LinkCalls`): what its tables
/// are told of a link, the gates it puts the link behind, and what the link's task hands its reads
/// to.
struct LinkMaking<'a> {
    session: &'a mut SessionState,
    /// Where the registry is lent to each link's dispatch (`Core::registry_lend`).
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    registry_lend: &'a RegistryLend,
    /// The limits the session was opened with: what a link's gate and its shared key ids are
    /// sized by.
    #[cfg(any(
        feature = "threads",
        feature = "listen",
        feature = "group",
        feature = "shared-key-ids"
    ))]
    limits: &'a SessionLimits,
}

impl<C: ClockSource + 'static> LinkCalls<C, SessionLock> for LinkMaking<'_> {
    type Gate = LinkGate<C>;
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    type Dispatch = FaceDispatch<C>;
    // What the read hands each step of the link it steps itself (`direct`).
    #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
    type Dispatch = direct::FaceRecords<C>;
    type Session = LinkSession<C>;

    fn link_made(&mut self, face: FaceId, actions: &LinkHandle<C>, key_form: Option<KeyWireForm>) {
        // The session keeps its declarations in its one table set and names each key it sends
        // itself, so the link keeps none and reads none; what the peer sends by the session's
        // ids is read from the same tables, which the dispatch of every face reads.
        actions.keep_no_keyexprs();
        // The answer the face's session gives a query of its peer whose key it cannot resolve:
        // the session's policy, stated for each link the face is opened over.
        self.session
            .registry
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
                    .install_shared_key_ids(face, ids.clone());
            }
        }
        #[cfg(not(feature = "shared-key-ids"))]
        let _ = key_form;
    }

    // Each record is handed out as it is read, so nothing holds the link back: the link is the
    // pump.
    #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
    fn gate(
        &self,
        pump: CellRc<dyn SessionDatagramLink, LinkCount>,
        _actions: &LinkHandle<C>,
    ) -> LinkGate<C> {
        pump
    }

    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    fn gate(
        &self,
        pump: CellRc<dyn SessionDatagramLink, LinkCount>,
        actions: &LinkHandle<C>,
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
            // alone; the gate is held by the link's cells, which the session's transport holds,
            // dropped before its state (`Core`'s fields), whose round's owner changes it no more.
            unsafe {
                RoundGate::new(
                    AdmissionGate::new(pump, actions.clone()),
                    self.session.lane.share(),
                    record_room,
                )
            }
        }
        #[cfg(all(not(feature = "listen"), any(feature = "threads", feature = "group")))]
        {
            let _ = actions;
            // SAFETY: a link is made under the session's lock, and its gate asked by the step
            // alone; the gate is held by the link's cells, which the session's transport holds,
            // dropped before its state (`Core`'s fields), whose round's owner changes it no more.
            unsafe { RoundGate::new(pump, self.session.lane.share(), record_room) }
        }
    }

    fn wire_parts(
        &self,
        face: FaceId,
        actions: LinkHandle<C>,
        gate: &CellRc<LinkGate<C>, LinkCount>,
    ) -> (Self::Dispatch, LinkSession<C>) {
        #[cfg(feature = "queryable")]
        let generation = self.session.plane.next_generation();
        // What the link's records are dispatched with: the registry is lent to a task's dispatch
        // for each pass, and reached by the read that steps the link itself under the session's
        // lock for each record (`direct`).
        #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
        let dispatch = FaceDispatch {
            registry: self.registry_lend.clone(),
            // The registry holds the face before its link is made (`Registry::add_face`).
            face: self.session.registry.held(face),
            actions: actions.clone(),
            // SAFETY: as the round's handle below: the dispatch is held by the link's session,
            // dropped before the session's state, which owns the plane.
            #[cfg(feature = "queryable")]
            plane: unsafe { self.session.plane.share() },
            #[cfg(feature = "queryable")]
            generation,
            // SAFETY: the dispatch is held by the link's session, which the session's transport
            // holds, dropped before its state (`Core`'s fields), whose round's owner changes it no
            // more.
            lane: unsafe { self.session.lane.share() },
            after_pushes: false,
        };
        #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
        let dispatch = direct::FaceRecords {
            // The registry holds the face before its link is made (`Registry::add_face`).
            face: self.session.registry.held(face),
            actions: actions.clone(),
            // SAFETY: the records are held beside the link's session in the engine's face, which
            // lets them go before the session's state, which owns the plane.
            #[cfg(feature = "queryable")]
            plane: unsafe { self.session.plane.share() },
            #[cfg(feature = "queryable")]
            generation,
            after_pushes: false,
        };
        // The read keeps no handle on the link beside its pump's.
        #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
        let _ = gate;
        // The wire keeps a handle on the gates to admit the link through them, and to tell them
        // what each wait found in the link's stack.
        #[cfg(all(feature = "threads", not(any(feature = "listen", feature = "group"))))]
        let _ = gate;
        (
            dispatch,
            LinkSession {
                actions,
                #[cfg(any(feature = "listen", feature = "group"))]
                gate: gate.clone(),
                #[cfg(feature = "queryable")]
                generation,
            },
        )
    }
}

/// The session ends, for the reason the caller's `last` was left holding: what the moves of the
/// links answer (`Core::poll_links`, `Core::carry_out`). The reason holds an endpoint's text, the
/// largest value of a move, so it is written once where the caller keeps it rather than handed
/// back through every call between.
#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
struct SessionEnds;

/// The dial of a face as its step read it: the answer of the dial, kept for the handshake the
/// face's life asks for next, and the endpoint it dialled, which names the reason a refusal
/// leaves. One value, so what a step read is carried through the arms of its life's effects
/// (`Core::carry_out`) whole; a step that read no dial carries [`Self::none`].
#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
struct ReadDial<P> {
    answer: DialAnswer<P, LinkCount>,
    dialled: Option<DialEndpoint>,
}

#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
impl<P> ReadDial<P> {
    /// No dial read: no answer and no endpoint.
    fn none() -> Self {
        Self {
            answer: None,
            dialled: None,
        }
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> Core<L, C> {
    /// Run a session over `opened` as face `face`, in `role`: the handshake begun, its task
    /// spawned on the session's local set and stepped once so that an initiator's InitSyn is sent
    /// now and not after the wait of the next read. The link is the same whichever end opened
    /// it; the role is the handshake's alone. [`OpenError::EntropyUnavailable`] when the platform
    /// gives no cookie key for the attempt.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    fn open_wire(
        &mut self,
        face: FaceId,
        opened: OpenedLink<L::Pump, LinkCount>,
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
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    #[inline(never)]
    fn start_wire(
        &mut self,
        face: FaceId,
        opened: OpenedLink<L::Pump, LinkCount>,
        role: SessionRole,
        endpoint: Option<&DialEndpoint>,
    ) -> Result<Wire<C>, OpenError> {
        let params = self.link_params()?;
        // The link's session is the transport's to make; what the session's tables keep of the
        // link, its gates and what its task hands its reads to are the session's (`LinkMaking`).
        let mut calls = LinkMaking {
            session: &mut self.session,
            registry_lend: &self.registry_lend,
            limits: resolve_limits(&self.config),
        };
        self.transport
            .make_wire(
                &mut calls,
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

    /// The parameters a link's session is opened with, with a cookie key of its own.
    /// [`OpenError::EntropyUnavailable`] when the platform gives no cookie key for the attempt.
    // Always inlined: the parameters are built in the frame of the making of the link.
    #[inline(always)]
    fn link_params(&mut self) -> Result<SessionInitParams, OpenError> {
        // The cookie key of the attempt is drawn before the parameters are read off the config:
        // drawn among them, its refusal would leave every field read before it in a temporary
        // of its own, moved again into the parameters once the key is there. A build whose
        // session machine has no accepting role holds no key, and its draw takes nothing.
        let cookie_signing_key =
            CookieKey::draw(&mut self.entropy).map_err(|_| OpenError::EntropyUnavailable)?;
        // The parameters the tokio engine gives a session (`wz-capi-core`'s `init_params`), with a
        // cookie key of its own per attempt.
        let params = SessionInitParams {
            whatami: self.config.whatami,
            zid: self.transport.wire_zid,
            seq_num_res: self.config.sn_resolution,
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
        Ok(params)
    }

    /// The times the life of each of the session's links is counted in: asked of a face taken
    /// beside the dial role's, and of a departed face's tomb, which only these builds hold.
    #[cfg(any(feature = "listen", feature = "connectivity"))]
    fn link_times(&self) -> LinkTimes {
        link_times(&self.config)
    }

    /// Dial the session's endpoint at `row` for the face at `at`, and say what came of it as the
    /// input of the face's life. A dial the network has not answered yet is left under way in the
    /// face and asked at the steps that follow, so no dial is waited for while the session is
    /// held; one answered at once with a link has it kept in `read`, with its endpoint, for the
    /// handshake the life asks for next. A refusal is kept in `last`. A dial names its endpoint
    /// by its row of the session's endpoint texts, which holds the text.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    fn dial_endpoint(
        &mut self,
        at: usize,
        row: usize,
        read: &mut ReadDial<L::Pump>,
        last: &mut OpenError,
    ) -> LinkInput {
        match self.transport.dial_row(at, row) {
            Err(refused) => {
                *last = OpenError::from(refused);
                LinkInput::DialRefused
            }
            // Put in the face where it was asked (`LinkSupervisor::ask_dial`).
            Ok(None) => LinkInput::DialPending,
            Ok(Some(Ok(opened))) => {
                read.answer = Some(Ok(opened));
                read.dialled = Some(DialEndpoint::Listed(row));
                LinkInput::DialMade
            }
            Ok(Some(Err(refused))) => {
                self.refuse(
                    last,
                    Some(&DialEndpoint::Listed(row)),
                    Refusal::Link(refused),
                );
                LinkInput::DialRefused
            }
        }
    }

    /// Leave in `last` that `endpoint` could not be reached, for `why`: the reason a face's step
    /// goes on with when its dial, its handshake or its link failed. Out of line and cold: each of
    /// those arms of a face's step would otherwise build the refusal, the endpoint's text in it,
    /// and copy it into `last` itself.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    #[cold]
    #[inline(never)]
    fn refuse(&self, last: &mut OpenError, endpoint: Option<&DialEndpoint>, why: Refusal) {
        *last = OpenError::Unreachable(EndpointRefusal::new(
            self.transport.endpoint_text(endpoint),
            why,
        ));
    }

    /// Begin the handshake of the link the dial of the face at `at`, numbered `id`, made: the
    /// link and the endpoint it came from, as `read` holds them. The face holds the link from then on,
    /// and the input of its life says whether the handshake began; why it did not is kept in
    /// `last`. A task refused is not the endpoint's (the next one would be refused the same),
    /// and no cookie key for the attempt is not a reason any endpoint can pass.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    fn begin_handshake(
        &mut self,
        at: usize,
        id: FaceId,
        read: &mut ReadDial<L::Pump>,
        last: &mut OpenError,
    ) -> LinkInput {
        let endpoint = read.dialled.take();
        let Some(answered) = read.answer.take() else {
            return LinkInput::HandshakeRefused(HandshakeRefusal::Endpoint);
        };
        let opened = match self.transport.dialled(endpoint.as_ref(), answered) {
            Ok(opened) => self.open_wire(id, opened, SessionRole::Initiator, endpoint.as_ref()),
            Err(refused) => Err(OpenError::from(refused)),
        };
        match opened {
            Ok(wire) => {
                self.transport.links.put_link(at, Link::Wire(wire));
                LinkInput::HandshakeBegun
            }
            Err(refused) => {
                let why = match refused {
                    OpenError::EntropyUnavailable => HandshakeRefusal::Fatal,
                    OpenError::NoTask(_) => HandshakeRefusal::Task,
                    _ => HandshakeRefusal::Endpoint,
                };
                *last = refused;
                LinkInput::HandshakeRefused(why)
            }
        }
    }

    /// Move the links on as [`Self::poll_links`] does, unless the last move left them settled and
    /// nothing that moves them came since: no face's link ended, no face or port was changed
    /// through the faces' table, and no face is due by `now_us` ([`LinksSettled`]). A session
    /// whose links are all up, and stay so, then looks at each face's task alone, one load a face,
    /// and turns no face's life, replay or dial until one of those comes. `Err` as
    /// [`Self::poll_links`], the reason in `last`.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    fn move_links(
        &mut self,
        redial_ms: Option<u64>,
        now_us: u64,
        last: &mut OpenError,
    ) -> Result<(), SessionEnds> {
        let links = &self.transport.links;
        if self.links_settled.is_some_and(|settled| {
            settled.moves == links.moves()
                && now_us < settled.due_us
                && !links
                    .faces()
                    .any(|face| face.link.wire().is_some_and(|wire| wire.finished()))
        }) {
            return Ok(());
        }
        self.links_settled = None;
        self.poll_links(redial_ms, now_us, last)?;
        self.links_settled = self.links_settle();
        Ok(())
    }

    /// What the links are settled at after a move: `None` while a face dials, is in its
    /// handshake or stands by for a node, while a face's link ended, while a port is to be asked
    /// for a connection, or while the session holds a group, each of which a step moves on by
    /// what it reads and not by a time or a change counted.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    fn links_settle(&self) -> Option<LinksSettled> {
        #[cfg(feature = "group")]
        if !self.transport.groups.is_empty() {
            return None;
        }
        let links = &self.transport.links;
        #[cfg(feature = "listen")]
        if links.ports_to_ask() {
            return None;
        }
        let mut due_us = u64::MAX;
        for face in links.faces() {
            let at_us = match face.life.phase() {
                LinkPhase::Up if face.link.wire().is_some_and(|wire| wire.finished()) => {
                    return None
                }
                LinkPhase::Up => face.replay.next_turn_ms().map(|ms| ms.saturating_mul(1000)),
                LinkPhase::Backoff { until_us } => Some(until_us),
                LinkPhase::Idle | LinkPhase::Closed => None,
                LinkPhase::Dialing { .. } | LinkPhase::Handshaking { .. } | LinkPhase::Held => {
                    return None
                }
            };
            if let Some(at_us) = at_us {
                due_us = due_us.min(at_us);
            }
        }
        Some(LinksSettled {
            moves: links.moves(),
            due_us,
        })
    }

    /// The counts of the changes the step's bookkeeping follows, as they stand.
    fn seen(&self) -> Seen {
        Seen {
            moves: self.transport.links.moves(),
            written: self.session.registry.faces_written(),
        }
    }

    /// Whether the step's bookkeeping has anything to do at `now_us`: the ledger's deadline
    /// passed or a count it follows moved, the Router holds a chain past its deadline, or a face's
    /// link ended. The Router's chains and a link's end come with the input the step's tasks
    /// read, so they are read as they stand and not kept in the ledger.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    fn owes_bookkeeping(&self, now_us: u64) -> bool {
        let links = &self.transport.links;
        self.ledger.owes(now_us, self.seen())
            || self.session_time.ms_at(now_us) >= self.transport.router.due_ms()
            || links
                .faces()
                .any(|face| face.link.wire().is_some_and(|wire| wire.finished()))
    }

    /// Settle the ledger after the bookkeeping ran: due at the earliest of the links' due time
    /// and the gets' deadlines, and owed at once while the links are not settled or a liveliness
    /// snapshot is pending, each of which a step moves on by what it reads.
    fn settle_ledger(&mut self) {
        #[cfg(feature = "query")]
        let gets_due_us = self
            .session
            .next_get_deadline_ms()
            .map_or(u64::MAX, |due_ms| due_ms.saturating_mul(1000));
        #[cfg(not(feature = "query"))]
        let gets_due_us = u64::MAX;
        // A snapshot's replies end it as they come, and the table of ended ones is drained by
        // the sweep, which a pending snapshot so owes at every step.
        #[cfg(all(feature = "query", feature = "liveliness-get"))]
        let snapshots =
            self.session.registry.all_gets().any(|gets| {
                !gets.liveliness_gets.is_empty() || gets.liveliness_gets.has_finalized()
            });
        #[cfg(not(all(feature = "query", feature = "liveliness-get")))]
        let snapshots = false;
        #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
        let (links_due_us, unsettled) = (
            self.links_settled
                .map_or(u64::MAX, |settled| settled.due_us),
            self.links_settled.is_none(),
        );
        // The one link is due by its own deadlines, which the read reads, and by the next turn of
        // the replay it owes its peer, which only the bookkeeping takes (`direct`).
        #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
        let (links_due_us, unsettled) = (
            self.transport
                .links
                .faces()
                .filter_map(|face| face.replay.next_turn_ms())
                .min()
                .map_or(self.link_due_us, |turn_ms| {
                    self.link_due_us.min(turn_ms.saturating_mul(1000))
                }),
            false,
        );
        let seen = self.seen();
        self.ledger.settle(links_due_us.min(gets_due_us), seen);
        if unsettled || snapshots {
            self.ledger.owe();
        }
    }

    /// Move every face's link on, after the session was stepped, against the step's reading of the
    /// clock, `now_us`; see [`Self::poll_face`]. `redial_ms` is the wait of a group whose link
    /// was lost. `Err` when the session ends, which only the dial role's face can bring about,
    /// the reason in `last`.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    fn poll_links(
        &mut self,
        redial_ms: Option<u64>,
        now_us: u64,
        last: &mut OpenError,
    ) -> Result<(), SessionEnds> {
        #[cfg(test)]
        self.link_polls.set(self.link_polls.get() + 1);
        // Each link's stack is read at the next step, whatever a wait found there since the last
        // move: a run of steps without a wait passes over a link no longer than this.
        #[cfg(any(feature = "listen", feature = "group"))]
        self.transport.links.links_moved();
        // The connections that arrived come first, so their handshakes are moved on in this pass.
        #[cfg(feature = "listen")]
        self.accept_links();
        // A group whose link was lost is let go of, and joined again when its time comes.
        #[cfg(feature = "group")]
        self.poll_groups(redial_ms);
        #[cfg(not(feature = "group"))]
        let _ = redial_ms;
        // From the last face to the first: a face that is gone is removed, which moves none of the
        // ones before it.
        for at in (0..self.transport.links.places()).rev() {
            self.poll_face(at, now_us, last)?;
        }
        Ok(())
    }

    /// Move the link of the face at `at` on. A link that is up goes on with the telling when a
    /// turn of it is due (`replay`), or ends when the replay is given up on a send the link
    /// refused, and is then lost as any other link is. What became of the link, and what the
    /// session does about it, is the face's life's to say ([`UnicastLink`]): the transport reads
    /// the link into the life's input, and the session carries out what the life asks for
    /// ([`Self::carry_out`]). `Err` when the session ends, the reason left in `last`.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    fn poll_face(
        &mut self,
        at: usize,
        now_us: u64,
        last: &mut OpenError,
    ) -> Result<(), SessionEnds> {
        let now_ms = now_us / 1000;
        let Some(face) = self.transport.links.face(at) else {
            return Ok(());
        };
        let id = face.id;
        let was = face.life.phase();
        // A link that is up goes on telling its peer what the session holds, when a turn is due.
        // A turn the replay is given up on (a refused send, at once without a pace or when the
        // pace says so) ends the link here, with no Close, as
        // zenoh-pico clears a transport its reopen could not send its declarations over
        // (`vendor/zenoh-pico/src/net/session.c` @ `_z_transport_clear(&s->_tp);`); the driver
        // then finds it lost, so the dial role's face dials again and tells everything over the
        // next link, and any other face goes.
        // A build that reaches no pace told the peer everything when the link came up.
        let up = face
            .up()
            .filter(|wire| ReplayPacing::REACHABLE && !wire.finished())
            .map(|wire| wire.actions.clone());
        if let Some(actions) = up {
            if self.replay_turn(at, &actions, now_ms) == TurnEnd::EndsLink {
                self.transport.links.abort_link(at);
                self.run_tasks();
            }
        }
        let mut read = ReadDial::none();
        let step = self
            .transport
            .face_step(at, id, now_us, &mut read.answer, &mut read.dialled);
        if step.effects.is_empty() {
            return Ok(());
        }
        self.carry_out(at, step.effects, was, &mut read, now_us, last)
    }

    /// Give the life of the face at `at` the input `input` at `now_us`, and carry out what it
    /// asks for ([`Self::carry_out`]). `Err` as [`Self::carry_out`], the reason in `last`.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    fn give_face(
        &mut self,
        at: usize,
        input: LinkInput,
        now_us: u64,
        last: &mut OpenError,
    ) -> Result<(), SessionEnds> {
        let Some(face) = self.transport.links.face_mut(at) else {
            return Ok(());
        };
        let was = face.life.phase();
        let effects = face.life.input(input, now_us);
        self.carry_out(at, effects, was, &mut ReadDial::none(), now_us, last)
    }

    /// Carry out what the life of the face at `at`, which stood at `was`, asks for (`effects`),
    /// in the order [`Effects`] names, reporting the dial or the handshake it asks for back to it
    /// as its next input, read at the clock after the I/O, until it asks for no more. `read` holds
    /// the face's dial as the step read it ([`ReadDial`]). `Err` when the session ends, the
    /// reason the last endpoint tried gave left in `last`, which every arm writes rather than
    /// hands back.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    fn carry_out(
        &mut self,
        at: usize,
        mut effects: Effects,
        was: LinkPhase,
        read: &mut ReadDial<L::Pump>,
        now_us: u64,
        last: &mut OpenError,
    ) -> Result<(), SessionEnds> {
        let Some(id) = self.transport.links.face(at).map(|face| face.id) else {
            return Ok(());
        };
        *last = OpenError::NoEndpoint;
        // The dial the step read the refusal of, and one the life walked past or let go of with
        // no answer read: either is over, and its endpoint names the reason.
        if matches!(read.answer, Some(Err(_))) {
            if let Some(Err(refused)) = read.answer.take() {
                self.refuse(last, read.dialled.as_ref(), Refusal::Link(refused));
            }
        } else if let Some(endpoint) = self.transport.links.end_dial(at) {
            self.refuse(last, Some(&endpoint), Refusal::NoAnswerInTime);
        }
        loop {
            if effects.let_go() {
                self.transport.links.abort_link(at);
                self.transport.links.put_link(at, Link::Idle);
            }
            // The link's task, told to stop, ends in the pass of the tasks before its link goes.
            if effects.end_handshake() {
                let why = self.transport.end_handshake(at);
                self.run_tasks();
                self.transport.links.put_link(at, Link::Idle);
                if let LinkPhase::Handshaking { row, .. } = was {
                    self.refuse(last, Some(&DialEndpoint::Listed(row)), why);
                }
            }
            // zenoh-pico's client reopens whatever ended its link: a lease that ran out, a read
            // that failed, a Close from the router
            // (`vendor/zenoh-pico/src/transport/unicast/read.c` @
            // `return _zp_unicast_failed_result(ztu, executor);`).
            if effects.lose() {
                self.lose_face_link(at, id);
                self.refuse(last, None, Refusal::LinkLost);
            }
            // The face table decides whether the node is held already.
            if effects.bring_up() {
                self.bring_up(at, now_us);
            }
            if effects.ends_session() {
                return Err(SessionEnds);
            }
            // A face taken beside the dial role's goes with its link; a session whose table holds
            // the dial role's face alone has no such face (`FacePlaces::TAKES`).
            #[cfg(feature = "listen")]
            if effects.removes() {
                if self.transport.links.takes_faces() {
                    self.remove_face(at);
                }
                return Ok(());
            }
            let input = if effects.begin_handshake() {
                self.begin_handshake(at, id, read, last)
            } else if let Some(row) = effects.dial() {
                self.dial_endpoint(at, row, read, last)
            } else {
                // A wait to dial again is the life's: its wake (`UnicastLink::wake_at`) brings
                // the face's next step.
                return Ok(());
            };
            let now_us = self.now_us();
            let Some(face) = self.transport.links.face_mut(at) else {
                return Ok(());
            };
            effects = face.life.input(input, now_us);
        }
    }

    /// What a lost link of the face at `at`, numbered `id`, takes with it: its peer's chains,
    /// its room, what its peer declared, and the face's watchers are told it went.
    fn lose_face_link(&mut self, at: usize, id: FaceId) {
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
        // The one link a read steps itself has its chains in the Router beside it, which the read
        // ends itself (`direct`): the transport holds none to end.
        #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
        self.transport.end_peer_chains(at);
        // What a replaying listener was told of the face is read while its link is held.
        #[cfg(feature = "connectivity")]
        self.face_went(at);
        self.transport.links.put_link(at, Link::Idle);
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
        let Some(actions) = self
            .transport
            .links
            .face(at)
            .and_then(|face| face.up())
            .map(|wire| wire.actions.clone())
        else {
            return false;
        };
        match self.begin_replay(at, &actions, now_ms) {
            TurnEnd::Kept => true,
            TurnEnd::EndsLink => {
                if let Some(wire) = self.transport.links.face(at).and_then(|face| face.up()) {
                    wire.abort();
                }
                false
            }
        }
    }

    /// Send each face's peer what the application's declaration or undeclaration of a subscriber
    /// owes its Interests ([`Registry::settle`]) now: the reconcile that stages it otherwise runs
    /// at the next event of the link's session, a record or a keep-alive, up to a keep-alive
    /// interval later, and not at all while the program does not step the session.
    #[cfg(feature = "interest-answer")]
    fn settle_faces(&mut self) {
        for at in 0..self.transport.links.places() {
            let Some(face) = self.transport.links.face(at) else {
                continue;
            };
            if let Some(wire) = face.up() {
                self.session
                    .registry
                    .settle(HeldFace::new(at, face.id), &*wire.actions);
            }
        }
        // A group's stage is written by the thread that put on it outside the group's own step.
        #[cfg(feature = "group")]
        for group in self
            .transport
            .groups
            .iter()
            .filter(|group| !group.has_ended())
        {
            self.session
                .registry
                .settle(HeldFace::new(group.at(), group.id()), group.replies());
            group.write_staged();
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
        // The link is now one the session's sends go through: what was planned over the links
        // before it no longer holds (`LinkSupervisor::generation`).
        self.transport.links.establish(at);
        if self.begin_replay(at, &actions, now_us / 1000) == TurnEnd::EndsLink {
            self.transport.links.abort_link(at);
        }
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
        for (at, join) in self.config.groups.clone().into_iter().enumerate() {
            // The open counts a task cell, a set of tables and a receive buffer for each group the
            // task cells hold (`RuntimeTables::of`), so a group past them is refused as its spawn
            // would be, before it takes a set: a set left beside them is a face's that
            // `max_faces` admits, and no buffer is left for the group's datagrams.
            if at >= caps::MAX_TASKS {
                return Err(OpenError::NoTask(SpawnRefusal::NoTaskCell));
            }
            let id = self.transport.links.next_face_id();
            // The tables first: the group's task dispatches to them from its first step. They are
            // the face's for as long as the session holds the group, across its joins, and answer
            // a query whose key they cannot resolve by the session's policy.
            let Ok(held) = self.session.registry.add_face(id) else {
                return Err(OpenError::NoTask(SpawnRefusal::NoTaskCell));
            };
            self.session
                .registry
                .set_unanswerable_final(id, self.policy.query_unanswerable_final());
            // Each member's keyexprs are its own, and the face holds them all.
            #[cfg(feature = "multicast-declarations")]
            self.session.registry.hold_member_aliases(held);
            // An id of the key ids every node shares is read on the group as on a link.
            #[cfg(feature = "shared-key-ids")]
            if let Some(ids) = &self.session.key_ids {
                self.session
                    .registry
                    .install_shared_key_ids(id, ids.clone());
            }
            match self.join_group(held, join) {
                Ok(face) => self.transport.add_group(face),
                Err(refused) => {
                    self.session.registry.remove_face(held);
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
        // SAFETY: the dispatch is held by the group's task, which the engine's links' end stops
        // and runs to its end (`Core::end_links`) before the session's state, which owns the
        // plane, is dropped.
        let dispatch = group::dispatch(
            self.registry_lend.clone(),
            face,
            unsafe { self.session.plane.share() },
            generation,
        );
        #[cfg(not(feature = "queryable"))]
        let dispatch = group::dispatch(self.registry_lend.clone(), face);
        // The group is handed a record of its datagrams only while the round of deliveries has the
        // room one record of the group's batch can take (decision Q4), as a link is.
        let record_room = crate::round::read_room::<
            { caps::MAX_SUBSCRIPTIONS },
            { caps::MAX_LIVELINESS_SUBSCRIPTIONS },
        >(resolve_limits(&self.config));
        // SAFETY: a group's transport is driven by the session's step alone, under its lock; the
        // gate is held by the group, which the session's tasks hold, all dropped before its state
        // (`Core`'s fields), whose round's owner changes it no more.
        let input_gate = wz_session_mcu::group_drive::GroupInputGate::new(unsafe {
            crate::round::takes_a_group_read(self.session.lane.share(), record_room)
        });
        let group = GroupFace::join(
            &self.local,
            GroupJoining {
                face,
                join,
                transport,
                input_gate,
                // SAFETY: as the input gate's.
                lane: unsafe { self.session.lane.share() },
                params,
                policy: self.policy,
                limits: *resolve_limits(&self.config),
                // A message the session puts on the group waits for room by running the session's
                // tasks, the group's among them, on the session's clock.
                pace: alloc::rc::Rc::new(group::SessionPace {
                    local: self.local.clone(),
                    clock: self.clock.clone(),
                }),
                #[cfg(feature = "queryable")]
                generation,
                // SAFETY: the group's task reads the watchers while it runs, which ends when the
                // engine's links' end stops the group and runs it out (`Core::end_links`), before
                // the session's state, which owns them, is dropped.
                #[cfg(feature = "connectivity")]
                watchers: unsafe { self.session.watchers.share() },
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
    /// taken out, and is the only face of a session that takes none besides it.
    #[cfg(feature = "listen")]
    fn remove_face(&mut self, at: usize) {
        // A face whose departure a replaying listener is owed keeps its place for its tomb.
        #[cfg(feature = "connectivity")]
        if self.keep_departed(at) {
            return;
        }
        // The face's tables go before the face, which is dropped where it lies.
        if let Some(id) = self.transport.links.face(at).map(|face| face.id) {
            self.session.registry.remove_face(HeldFace::new(at, id));
            self.transport.links.drop_face(at);
        }
    }

    /// What a lost link of face `id` takes with it: what the session holds of it
    /// (`SessionState::lose_face`). What the peer was told is the caller's, which holds the face's
    /// place: a group keeps no replay.
    /// Out of line: a lost face and a group that ended each take what the peer declared.
    #[inline(never)]
    fn lose_link(&mut self, id: FaceId) {
        self.session.lose_face(id);
        // A read that steps its one link itself hands the tokens owed after it lets go of the
        // session (`tokens`).
        #[cfg(all(
            feature = "liveliness",
            any(feature = "threads", feature = "listen", feature = "group")
        ))]
        self.retract_owed();
    }

    /// Retract the tokens the peers of lost links declared, as many as the round of deliveries
    /// takes now (`SessionState::retract_owed`). Each `Delete` is a record of a token for every
    /// liveliness subscriber the session's limits admit.
    #[cfg(all(
        feature = "liveliness",
        any(feature = "threads", feature = "listen", feature = "group")
    ))]
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
    #[cfg(all(
        any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ),
        any(feature = "threads", feature = "listen", feature = "group")
    ))]
    fn tell_decl_watches_owed(&self) {
        let registry = &self.session.registry;
        let links = &self.transport.links;
        let faces = move || {
            links.faces().filter_map(move |face| {
                let wire = face.link.wire()?;
                let peer = decl_watch::named(|| wire.actions.peer_session_zid());
                Some((registry.tables_of(face.id)?, peer))
            })
        };
        // SAFETY: `Core` is reached under the session's lock alone, the round writer's lock.
        unsafe { registry.decl_watches.tell_owed(faces) };
    }

    /// The next call a declaration watch is owed (`DeclWatches::next_call`), its event copied
    /// into `told`: what the dispatch of the last record held, the events a watch lost, then each
    /// new watch's catch-up from the peers of the links up now, each declaration named as its
    /// link's peer.
    #[cfg(all(
        any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ),
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
    fn next_decl_watch_call(&self, told: &mut decl_watch::Told) -> Option<decl_watch::WatchCall> {
        let registry = &self.session.registry;
        let links = &self.transport.links;
        let faces = move || {
            links.faces().filter_map(move |face| {
                let (Link::Up(wire) | Link::Opening { wire, .. }) = &face.link else {
                    return None;
                };
                let peer = decl_watch::named(|| wire.actions.peer_session_zid());
                Some((registry.tables_of(face.id)?, peer))
            })
        };
        registry.decl_watches.next_call(faces, told)
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

    /// The session's send epoch: equal at two reads, the links that are up and how each names
    /// what it sends, what the peers declared and the session's own subscribers are as they were,
    /// so a put planned at the one (`WriteFilterRow::planned_put`) is sent as planned at the
    /// other. Each count it adds up moves by one at a time and never back, so the sum moves
    /// whenever any of them does.
    fn send_epoch(&self) -> u64 {
        let registry = &self.session.registry;
        self.transport
            .links
            .generation()
            .wrapping_add(registry.faces_written())
            .wrapping_add(wz_session_core::pubsub::LocalSubscribers::epoch(tables(
                registry,
            )))
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
            // The one link the read steps itself, by its life and its session's deadlines.
            #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
            (self.link_due_us != u64::MAX).then_some(self.link_due_us.div_ceil(1000)),
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
    /// The pass wakes the timers due by the clock, read now ([`Self::run_tasks_at`]).
    /// Out of line: nine places step the session's tasks. A build whose read steps its one link
    /// itself runs no task, and has no pass to make (`direct`).
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    #[inline(never)]
    fn run_tasks(&mut self) {
        #[cfg(all(test, feature = "std"))]
        self.task_clock_reads.set(self.task_clock_reads.get() + 1);
        let now_us = self.clock.now_us();
        self.run_tasks_at(Some(now_us));
    }

    /// [`Self::run_tasks`] with no reading of the clock: the timers due by `due_at` are woken
    /// first when it is given, none when it is not ([`CoopLocalSet::run_ready`]).
    /// Out of line: every pass of the session's tasks is made here, the lend around them one body.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    #[inline(never)]
    fn run_tasks_at(&mut self, due_at: Option<u64>) {
        let Self {
            local,
            transport: TransportState { router, lend, .. },
            session,
            registry_lend,
            ..
        } = self;
        registry_lend.lend_for(&mut session.registry, || {
            lend.lend_for(router, || local.run_ready(due_at))
        });
    }

    /// End every face's link, whatever it is doing, telling an established peer so. The dial
    /// role's face stays, with no link and no redial; the others go.
    fn end_links(&mut self) {
        #[cfg(test)]
        self.links_let_go.set(self.links_let_go.get() + 1);
        // A dial under way is let go of: its connection is not made. The ports are let go of
        // first, so no connection is taken while the faces are ended. The one link a read steps
        // itself holds its dial beside it, let go of with it, and no port (`direct`).
        #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
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
        self.session.registry.remove_accepted_faces();
        // Each link's task sees its end. The one link a read steps itself is no task: its session
        // goes with the face that holds it (`direct`).
        #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
        self.run_tasks();
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
    /// Open a session over `links` to the first endpoint of `config` that completes the
    /// handshake, stepping it on this thread until it does. `entropy` mints the zid the config
    /// does not state and each attempt's cookie key, for this open and every redial after it.
    /// An open that no endpoint answers fails: the session redials only a link it had.
    ///
    /// The session runs under the snapshot this open resolves from `config` (`resolve_policy`);
    /// an ABI that has resolved its own opens with [`Self::open_with_policy`].
    #[cfg(any(feature = "runtime-plan", test))]
    pub fn open(
        links: L,
        clock: C,
        entropy: impl EntropySource + Send + 'static,
        config: CoopConfig,
    ) -> Result<EngineHold<Self>, OpenError> {
        let policy = resolve_policy(&config);
        Self::open_with_policy(links, clock, entropy, config, policy)
    }

    /// [`Self::open`], the session running under `policy`, the snapshot its creator resolved:
    /// every link's session is handed it, a link's declarations are replayed at the pace it
    /// states, and two links to one node are told apart by its `link-tie-order`.
    #[cfg(any(feature = "runtime-plan", test))]
    #[inline]
    pub fn open_with_policy(
        links: L,
        clock: C,
        entropy: impl EntropySource + Send + 'static,
        config: CoopConfig,
        policy: SessionPolicy,
    ) -> Result<EngineHold<Self>, OpenError> {
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
    #[cfg(any(feature = "runtime-plan", test))]
    #[inline]
    pub fn open_with_key_ids(
        links: L,
        clock: C,
        entropy: impl EntropySource + Send + 'static,
        config: CoopConfig,
        policy: SessionPolicy,
        key_ids: OpenKeyIds,
    ) -> Result<EngineHold<Self>, OpenError> {
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
    #[cfg(any(feature = "runtime-plan", test))]
    pub fn open_in(
        links: L,
        clock: C,
        entropy: impl EntropySource + Send + 'static,
        config: CoopConfig,
        policy: SessionPolicy,
        key_ids: OpenKeyIds,
        memory: &'static dyn ArenaMemory,
    ) -> Result<EngineHold<Self>, OpenError> {
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
                plan: PlanFrom::Config,
            },
        )
    }

    /// `Self::open_in` (a build with `runtime-plan`), its config read from `source` inside the
    /// open, once, before anything else: an ABI that builds the config from its own values hands
    /// the source (a maker of the config is one), so the config is never a value of its frame,
    /// which the open's handshake runs under. The source writes the endpoints' texts into the rows the open lends for them, and is
    /// let go of before anything is bound or dialled ([`OpenSource`]).
    ///
    /// The open is two frames that never lie on the stack together. The first builds the engine
    /// where it is kept (the session's state and its arena's tables, in the engine's place in the
    /// arena), and returns; the second binds the ports, joins the groups and dials over the
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
    ) -> Result<EngineHold<Self>, OpenError> {
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
    /// once, into the engine's place ([`Self::engine_of`]).
    #[inline(never)]
    fn assemble(
        mut links: L,
        clock: C,
        entropy: impl EntropySource + Send + 'static,
        source: impl OpenSource,
        policy: SessionPolicy,
        key_ids: OpenKeyIds,
        storage: OpenStorage,
    ) -> Result<EngineHold<Self>, OpenError> {
        let OpenStorage {
            memory,
            held,
            plan: from,
        } = storage;
        let (config, write_endpoints) = source.into_parts();
        admit_sn_widths(&config)?;
        #[cfg(feature = "shared-key-ids")]
        let key_forms = key_ids.admit(&policy, resolve_limits(&config))?;
        #[cfg(not(feature = "shared-key-ids"))]
        key_ids.admit(&policy)?;
        // The row the engine is reached through, taken before anything is reserved: a process
        // whose rows are all held opens no more, and reserves nothing for it.
        let row = RowClaim::take().ok_or(OpenError::NoEngineRow)?;
        // The runtime's tables are placed in the arena, so its plan holds their span.
        #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
        let tables = RuntimeTables::of::<C>(&config);
        #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
        let tables = RuntimeTables::of(&config);
        let runtime_bytes = tables
            .placed_bytes::<C>()
            .ok_or(OpenError::Arena(ArenaRefused::TooLarge))?;
        let holds = OpenHolds {
            cells: link_cells::<C>(&links),
            rooms: link_rooms_bytes(&links),
            held: &held,
            runtime: runtime_bytes,
            engine: Shared::<Self>::layout().size(),
            planes: SessionPlanes::OF_BUILD,
            #[cfg(feature = "listen")]
            admission: core::mem::size_of::<Admission<C>>(),
        };
        let mut lent =
            lend_session(&holds, from, memory, &config, &policy).map_err(OpenError::Arena)?;
        // The texts of the endpoints, each written once by the source into the row the plan laid
        // out for it: the session names an endpoint by its row from here, and what the source
        // held goes with its writer, here, before anything is bound or dialled.
        let written = write_endpoints(&mut EndpointWriter::over(&mut lent.transport.endpoints));
        // One refusal for the three, so what the arena lent is let go of on one path. The rooms
        // lie in the row the plan laid out for them, a handle at each place a face may hold, the
        // dial role's and each group's among them.
        let (wire, entropy, rooms) = written.and_then(|()| {
            // A heap with no room for the source's cell is memory the open cannot be given.
            let mut entropy = SessionEntropy::<SharedCount>::try_held(entropy)
                .map_err(|bytes| OpenError::Arena(ArenaRefused::NoMemory { bytes }))?;
            let wire = session_zid(&config, &policy, &lent.transport.endpoints, &mut entropy)?;
            let (waits, places) = (links.waits(), lent.room_places);
            // SAFETY: the arena hands a place aligned for the rooms and valid for writes of
            // them, where they stay.
            let rooms = unsafe {
                lent.arena
                    .arena_mut()
                    .place_with(|at| LinkRooms::init_at(NonNull::new_unchecked(at), waits, places))
            }
            .map_err(|refused| OpenError::Arena(ArenaRefused::Lend(refused)))?;
            Ok((wire, entropy, rooms))
        })?;
        links.lend_buffers(lent.transport.links);
        #[cfg(feature = "listen")]
        links
            .lend_port_rows(lent.transport.port_rows)
            .map_err(|bytes| OpenError::Arena(ArenaRefused::NoMemory { bytes }))?;
        if let Some(driver_cells) = lent.transport.cells.driver {
            links.lend_cells(driver_cells);
        }
        // The task and timer tables and the session's local set, placed here once in the arena: no
        // spawn and no sleep of the session takes memory after its open (`open_links` seals them).
        let (runtime, local) =
            tables
                .runtime(clock.clone(), lent.runtime)
                .ok_or(OpenError::Arena(ArenaRefused::Lend(
                    LendRefused::Exhausted {
                        asked: Some(runtime_bytes),
                        left: 0,
                    },
                )))?;
        // SAFETY: the runtime is the session's alone: it and its local set go into the `Core` made
        // below and into no other value, the opening frame owns them until the `Core` is behind
        // its `CoreLock`, and from then on every spawn, pass and handle of its tasks is reached
        // under that lock (`UnderCoreLock`'s `ConfinedOwner`); this handle is dropped here.
        unsafe { runtime.confine_tasks::<UnderCoreLock>() };
        let session_time = CoopTime::new(&runtime);
        let wait_room = read_wait_room(&config);
        #[cfg(feature = "time-base")]
        let clock_wake = config.clock_moves.as_ref().and_then(|moves| {
            let wake = links.waits().wake()?;
            moves.watch(wake.waker.clone());
            Some(wake)
        });
        // No watcher yet: the plane holds its watchers and its rows itself, so a program that
        // watches after the open is told its faces with nothing allocated. The plane is built in
        // the row the plan laid out for it (`ArenaPlan::lay_planes`), never in this frame,
        // or in the region where the build fixes the session's shape.
        #[cfg(feature = "connectivity")]
        let face_rows = face_event_rows(config.max_faces, config.groups.len());
        #[cfg(all(feature = "connectivity", feature = "runtime-plan"))]
        let watchers = FacePlane::place_in(lent.arena.arena_mut(), face_rows)
            .map_err(|refused| OpenError::Arena(ArenaRefused::Lend(refused)))?;
        // SAFETY: the region's places were placed by the open's lend and its faces' field is
        // reached by this write alone; the block is held by `Core` after the session's state,
        // which holds the plane's owner, and neither moves nor goes back before it.
        #[cfg(all(feature = "connectivity", not(feature = "runtime-plan")))]
        let watchers =
            unsafe { StatePlaces::faces(StateRegion::places_at(lent.state.as_ptr()), face_rows) };
        // A row for each link the plan holds buffers for, reserved here: a link the session takes
        // after its open is admitted in place. The admission lies in the row the plan laid out for
        // it (`ArenaPlan::lay_admission`); its rows are the heap's, and a heap that refuses them
        // refuses the open.
        #[cfg(feature = "listen")]
        let admission = Admission::<C>::try_with_order(&wire, policy.link_tie_order(), lent.links)
            .ok_or(OpenError::Arena(ArenaRefused::NoMemory {
                bytes: lent.links.saturating_mul(LinkBook::row_bytes()),
            }))?;
        #[cfg(feature = "listen")]
        let admission = lent
            .arena
            .arena_mut()
            .place(admission)
            .map_err(|refused| OpenError::Arena(ArenaRefused::Lend(refused)))?;
        // SAFETY: the handle is held by the transport and by each link's lease, in the link's
        // actions, which the faces, the tasks and the transport hold: the engine's drop drops the
        // session's tasks before `Core` (`CoopLocalSet::drop_tasks`), and `Core` drops its
        // transport and its state before the owner, a field after theirs. Nothing changes the
        // admission through its owner.
        #[cfg(feature = "listen")]
        let link_admission = unsafe { admission.share() }.map(as_link_admission::<C>);
        // The faces' links keep the places the registry lends their tables at: one table of them.
        let places = lent.registry.places();
        // A place for each face the registry lent a set for, each face with its dial, and the waits
        // a read makes at once, reserved here: none grows after.
        let supervised = LinkSupervisor::new(
            links,
            Face {
                id: DIAL_FACE,
                link: Link::Idle,
                life: UnicastLink::new(
                    link_times(&config),
                    LinkRole::Dial,
                    lent.transport.endpoints.dials(),
                ),
                replay: Replay::idle(),
                #[cfg(feature = "connectivity")]
                told: FaceTold::default(),
            },
            places,
            wait_room,
        )
        .ok_or(OpenError::Arena(ArenaRefused::Lend(
            LendRefused::Exhausted {
                asked: Some(wait_room.saturating_mul(core::mem::size_of::<
                    wz_runtime_coop::session_drive::LinkWait,
                >())),
                left: 0,
            },
        )))?;
        // Each field is made in the order its makers need: the config and policy are read before
        // they are moved.
        let core = Core {
            local,
            clock,
            rooms,
            transport: TransportState {
                #[cfg(feature = "listen")]
                tx_pool_short: lent.tx_pool_short,
                links: supervised,
                endpoints: lent.transport.endpoints,
                #[cfg(feature = "group")]
                groups: Vec::new(),
                #[cfg(feature = "listen")]
                admission: link_admission,
                wire_zid: wire,
                gate_cells: lent.transport.cells.gate,
                actions_cells: lent.transport.cells.actions,
                halves_cells: lent.transport.cells.halves,
                #[cfg(feature = "shared-key-ids")]
                key_forms,
                #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
                router: lent.router,
                // The Router lies beside the one link the read steps itself, apart from the
                // session's state (`direct`).
                #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
                router: (),
                // SAFETY: the handle is held by the transport and the links' tasks, all dropped
                // before the place's owner, `Core::steps`, which hands out no `&mut` of it.
                lend: RouterLend::over(unsafe { lent.steps.router.share() }),
            },
            session: SessionState {
                registry: lent.registry,
                #[cfg(feature = "connectivity")]
                watchers,
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
                #[cfg(wz_round)]
                lane: lent.samples,
                #[cfg(not(wz_round))]
                lane: (),
            },
            // SAFETY: the handle is held by `registry_lend` and the dispatch of the links and
            // groups, in the transport and the tasks, all dropped before the place's owner,
            // `Core::steps`, which hands out no `&mut` of it.
            #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
            registry_lend: RegistryLend::over(unsafe { lent.steps.registry.share() }),
            #[cfg(feature = "time-base")]
            clock_wake,
            entropy,
            config,
            policy,
            released: false,
            #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
            links_settled: None,
            #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
            link_due_us: u64::MAX,
            ledger: Ledger::new(),
            #[cfg(test)]
            services: core::cell::Cell::new(0),
            #[cfg(test)]
            clock_reads: core::cell::Cell::new(0),
            #[cfg(test)]
            link_polls: core::cell::Cell::new(0),
            #[cfg(test)]
            links_let_go: core::cell::Cell::new(0),
            #[cfg(feature = "group")]
            group_reads: 0,
            #[cfg(all(test, feature = "std"))]
            task_clock_reads: core::cell::Cell::new(0),
            #[cfg(feature = "ticker")]
            tickers: Tickers::reserved(caps::MAX_TICKERS),
            session_time,
            places: lent.places,
            _steps: lent.steps,
            #[cfg(feature = "listen")]
            _admission: admission,
            #[cfg(not(feature = "runtime-plan"))]
            _state: lent.state,
            arena: lent.arena,
        };
        let apart = LentApart {
            #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
            router: lent.router,
            engine: lent.engine,
            handle_place: lent.handle_place,
            lodgings: lent.lodgings,
            #[cfg(any(feature = "listen", feature = "group"))]
            handed: lent.transport.handed,
            #[cfg(feature = "advanced-cache")]
            cache: lent.cache,
        };
        Ok(Self::engine_of(core, apart, row))
    }

    /// The engine over `core`, written at the place the open lent it in the session's arena and
    /// counted by its holders there, put in the row `row` the open claimed for it, which reaches
    /// it without holding it ([`EngineHandle`]), with what the open lent apart from the state
    /// (`apart`). Out of line, so the open's measure shows it apart.
    #[inline(never)]
    fn engine_of(core: Core<L, C>, apart: LentApart, row: RowClaim) -> EngineHold<Self> {
        // The place is a span of the arena, aligned as a span starts.
        const { assert!(Shared::<Self>::layout().align() <= wz_session_core::bounded::ARENA_ALIGN) };
        let LentApart {
            #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
            router,
            engine: place,
            handle_place,
            lodgings,
            #[cfg(any(feature = "listen", feature = "group"))]
            handed,
            #[cfg(feature = "advanced-cache")]
            cache,
        } = apart;
        // SAFETY: the engine holds the handle beside the `Core` it owns and uses it last in its
        // own drop, before its fields, `core` among them, are dropped; the round's owner changes it
        // no more.
        #[cfg(wz_round)]
        let samples = unsafe { core.session.lane.share() };
        let wire = core.transport.wire_zid;
        // SAFETY: the engine holds the handles beside the `Core` that owns the planes and reads
        // them last in its own drop, before its fields, `core` among them, are dropped.
        #[cfg(feature = "queryable")]
        let plane = unsafe { core.session.plane.share() };
        // SAFETY: as the plane's.
        #[cfg(feature = "query")]
        let gets = unsafe { core.session.gets.share() };
        // SAFETY: as the plane's.
        #[cfg(feature = "connectivity")]
        let faces = unsafe { core.session.watchers.share() };
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        let decl_watches = core.session.registry.decl_watches.clone();
        // SAFETY: the engine holds the handle beside the `Core` that owns the rooms, which is
        // dropped before the handle and hands out no `&mut` of them.
        let rooms = unsafe { core.rooms.share() };
        let wait_before_drop_us = core.config.tx_queue.wait_before_drop_us;
        let held_drop = core.config.tx_queue.held_drop;
        #[cfg(any(feature = "listen", feature = "group"))]
        let handed_limits = HandedLimits::new(core.config.tx_queue.sizes);
        let arena_bytes = core.arena.bytes();
        #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
        let direct_lend = core.transport.lend.clone();
        let make = |this: NonNull<Self>| {
            // SAFETY: `this` is where the `Shared` the open places lays the engine, which is
            // taken out of its row at its close and first in its drop, before its place is given
            // back.
            let reach = unsafe { row.fill(this) };
            // The round hands the queries it holds to their queryables through the engine,
            // which sends what they answer. A read that steps its one link itself holds no query
            // in the round (`queries`).
            #[cfg(all(
                feature = "queryable",
                any(feature = "threads", feature = "listen", feature = "group")
            ))]
            {
                let answering: NonNull<dyn crate::round::AnswersQueries<crate::calls::CoopCalls>> =
                    this;
                // SAFETY: the engine owns the round and tells it to answer no more first in
                // its drop, before the round is let go of; the place is the engine's from here
                // on.
                unsafe { samples.answer_queries_with(answering) };
            }
            let at = this.as_ptr();
            // SAFETY: `at` is the engine's place, valid for writes of a `Self` that stays there
            // (`Shared::placed_with`), so each field is too; each field is written once, below,
            // and the locks are made where they stay.
            unsafe {
                #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
                direct::DirectFace::init_at(
                    NonNull::new_unchecked(addr_of_mut!((*at).direct)),
                    router,
                    direct_lend,
                );
                CoreLock::init_at(NonNull::new_unchecked(addr_of_mut!((*at).core)), core);
                addr_of_mut!((*at).rooms).write(rooms);
                addr_of_mut!((*at).wait_before_drop_us).write(wait_before_drop_us);
                addr_of_mut!((*at).held_drop).write(held_drop);
                addr_of_mut!((*at).sending_on).write(AtomicU64::new(NOT_SENDING));
                #[cfg(any(feature = "listen", feature = "group"))]
                addr_of_mut!((*at).handed).write(Mutex::new(handed));
                #[cfg(any(feature = "listen", feature = "group"))]
                addr_of_mut!((*at).owed).write(AtomicBool::new(false));
                #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
                addr_of_mut!((*at).input_held).write(AtomicBool::new(false));
                #[cfg(feature = "threads")]
                addr_of_mut!((*at).hand_back).write(HandBack::new());
                #[cfg(any(feature = "listen", feature = "group"))]
                addr_of_mut!((*at).handed_limits).write(handed_limits);
                #[cfg(feature = "transport-stats")]
                addr_of_mut!((*at).unsent_drops).write(AtomicU64::new(0));
                #[cfg(wz_round)]
                addr_of_mut!((*at).samples).write(samples);
                #[cfg(not(wz_round))]
                addr_of_mut!((*at).releases).write(RowReleases::new());
                addr_of_mut!((*at).matching_owed).write(AtomicBool::new(false));
                #[cfg(feature = "queryable")]
                addr_of_mut!((*at).plane).write(plane);
                #[cfg(feature = "query")]
                addr_of_mut!((*at).gets).write(gets);
                #[cfg(feature = "connectivity")]
                addr_of_mut!((*at).faces).write(faces);
                #[cfg(any(
                    feature = "remote-declaration-watch",
                    feature = "declarations-synced-event"
                ))]
                addr_of_mut!((*at).decl_watches).write(decl_watches);
                addr_of_mut!((*at).zid).write(wire);
                addr_of_mut!((*at).closed).write(AtomicBool::new(false));
                #[cfg(any(feature = "query", feature = "ticker"))]
                addr_of_mut!((*at).next_local).write(AtomicU64::new(1));
                #[cfg(feature = "threads")]
                os::mutex_in(
                    NonNull::new_unchecked(addr_of_mut!((*at).reader)),
                    |reader| reader.write(None),
                );
                #[cfg(feature = "threads")]
                addr_of_mut!((*at).reader_run).write(core::sync::atomic::AtomicUsize::new(0));
                addr_of_mut!((*at).deliveries).write(Deliveries::new());
                addr_of_mut!((*at).arena_bytes).write(arena_bytes);
                addr_of_mut!((*at).handle_place).write(handle_place);
                addr_of_mut!((*at).lodgings).write(lodgings);
                #[cfg(feature = "advanced-cache")]
                os::mutex_in(NonNull::new_unchecked(addr_of_mut!((*at).cache)), |held| {
                    held.write(cache)
                });
                #[cfg(test)]
                addr_of_mut!((*at).takes).write(Takes::default());
                addr_of_mut!((*at).reach).write(reach);
            }
        };
        // Each field of the engine is written above, one statement each: a field added to the
        // engine and not there fails this pattern.
        let _every_field_is_written = |engine: &Self| {
            let Self {
                #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
                    direct: _,
                core: _,
                rooms: _,
                wait_before_drop_us: _,
                held_drop: _,
                sending_on: _,
                #[cfg(any(feature = "listen", feature = "group"))]
                    handed: _,
                #[cfg(any(feature = "listen", feature = "group"))]
                    owed: _,
                #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
                    input_held: _,
                #[cfg(feature = "threads")]
                    hand_back: _,
                #[cfg(any(feature = "listen", feature = "group"))]
                    handed_limits: _,
                #[cfg(feature = "transport-stats")]
                    unsent_drops: _,
                #[cfg(wz_round)]
                    samples: _,
                #[cfg(not(wz_round))]
                    releases: _,
                matching_owed: _,
                #[cfg(feature = "queryable")]
                    plane: _,
                #[cfg(feature = "query")]
                    gets: _,
                #[cfg(feature = "connectivity")]
                    faces: _,
                #[cfg(any(
                    feature = "remote-declaration-watch",
                    feature = "declarations-synced-event"
                ))]
                    decl_watches: _,
                zid: _,
                closed: _,
                #[cfg(any(feature = "query", feature = "ticker"))]
                    next_local: _,
                #[cfg(feature = "threads")]
                    reader: _,
                #[cfg(feature = "threads")]
                    reader_run: _,
                deliveries: _,
                arena_bytes: _,
                handle_place: _,
                lodgings: _,
                #[cfg(feature = "advanced-cache")]
                    cache: _,
                #[cfg(test)]
                    takes: _,
                reach: _,
            } = engine;
        };
        // SAFETY: the place was lent to the engine alone, aligned as asserted above and as large as
        // `Shared::<Self>::layout`, in the arena `place.memory` keeps; the engine is read through
        // its place only once it is written.
        EngineHold::of(unsafe { Shared::placed_with(place.at, place.memory, make) })
    }

    /// Open the links of the engine [`Self::assemble`] built: the ports bound and the groups
    /// joined before anything is dialled, so a session that cannot listen, or join a group, where
    /// it was told to does not open; then the first endpoint dialled and the session stepped on
    /// this thread until the dial settles. A session that only listens, or only joins groups, is
    /// open once it is bound and joined; one that dials is open once a link completes its
    /// handshake. Never inlined: what it holds under the session's first steps is the guard of the
    /// engine's state, which nothing else can take before the open returns the engine.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
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
            // An open that no endpoint answers ends here: the link has not been up, so its life
            // dials none again.
            let mut last = OpenError::NoEndpoint;
            let now_us = core.now_us();
            if core
                .give_face(0, LinkInput::Open, now_us, &mut last)
                .is_err()
            {
                return Err(last);
            }
            // Open once the dial's link is up, or once the node it reached is held by a face that
            // came first (a peer that listens and dials its own listener's peer).
            while !core.transport.dial_settled() {
                let mut wait = core.idle_wait();
                wait.wait(core.rooms.waits(), sleep_ms);
                core.transport.links.waited(wait);
                core.run_tasks();
                let now_us = core.now_us();
                if core.poll_links(None, now_us, &mut last).is_err() {
                    return Err(last);
                }
            }
        }
        // What the open spawned has its cells: from here a spawn finds a free cell or is refused.
        #[cfg(feature = "group")]
        core.local.runtime().seal();
        Ok(())
    }

    /// Whether `at` is a byte of the session's arena.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn arena_holds(&self, at: *const u8) -> bool {
        self.core.lock().0.arena.holds(at)
    }

    /// Where the planes the session's state owns lie, each where its feature is.
    #[cfg(all(
        test,
        feature = "std",
        any(feature = "queryable", feature = "query", feature = "connectivity")
    ))]
    pub(crate) fn plane_places(&self) -> alloc::vec::Vec<*const u8> {
        [
            #[cfg(feature = "queryable")]
            core::ptr::from_ref::<QueryPlane>(&self.plane).cast::<u8>(),
            #[cfg(feature = "query")]
            core::ptr::from_ref::<GetPlane>(&self.gets).cast::<u8>(),
            #[cfg(feature = "connectivity")]
            core::ptr::from_ref::<FacePlane>(&self.faces).cast::<u8>(),
        ]
        .to_vec()
    }

    /// How many cells of the session's table of links' halves hold a link's halves now: `None`
    /// for a session whose plan laid out no such table.
    #[cfg(all(test, feature = "std"))]
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
    pub(crate) fn link_admission(&self) -> PlacedRef<dyn LinkAdmission> {
        self.core.lock().0.transport.admission
    }

    /// Run `f` on the session's local set under the session's lock, for a test that spawns a
    /// task of the session's: the runtime is confined to that lock (`confine_tasks`), so the set
    /// is used under it and a handle of it taken out is used only once the engine has gone.
    #[cfg(all(test, feature = "listen"))]
    pub(crate) fn with_local_set<R>(&self, f: impl FnOnce(&CoopLocalSet<C>) -> R) -> R {
        f(&self.core.lock().0.local)
    }

    /// How many places of `kind` the ABI holds now, and how many the session's arena lends at
    /// most.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn place_counts(&self, kind: EntityKind) -> (usize, usize) {
        self.core.lock().0.places.counts(kind)
    }

    /// Run `f` while this thread holds the session's lock, as a drop made under it would.
    #[cfg(all(test, feature = "std"))]
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
    #[cfg(wz_round)]
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
            let registry = &core.0.session.registry;
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
                .filter(|face| face.link.wire().is_some_and(|wire| wire.owes_write()))
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
    /// `None` sends them all in one. A pace is refused, and the session keeps what it had, in a
    /// build whose domain of `declaration-sync-pacing` leaves `on` out
    /// (`ReplayPacing::REACHABLE`): that build holds no code of the turns, so it answers as a
    /// snapshot that selects the policy's `on` is answered there.
    pub fn set_replay_pacing(
        &self,
        pacing: Option<ReplayPacing>,
    ) -> Result<(), OutsideDomain<DeclarationSyncPacing>> {
        if pacing.is_some() && !ReplayPacing::REACHABLE {
            return Err(OutsideDomain {
                value: DeclarationSyncPacing::On,
            });
        }
        if let Some(mut core) = self.live() {
            core.0.session.replay_pacing = pacing;
        }
        Ok(())
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

    /// How often the session moved its links on since the open (`Core::link_polls`): what a
    /// test of the cost of a batch counts. Read under the lock, uncounted as a take.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn link_polls(&self) -> usize {
        self.core.lock().0.link_polls.get()
    }

    /// How often a pass of the session's tasks read the clock to wake its timers since the open
    /// ([`Core::run_tasks`]): what a test of the cost of a batch counts. Read under the lock.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn task_clock_reads(&self) -> usize {
        self.core.lock().0.task_clock_reads.get()
    }

    /// How often the step's bookkeeping ran since the open (`Self::service`): what a test of the
    /// cost of a stream of input counts. Read under the lock.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn services(&self) -> usize {
        self.core.lock().0.services.get()
    }

    /// Run `f` on the session's one reassembly Router with the time now on the epoch its chains
    /// are staged on: what a test of the chains the session's step ends stages its chain in and
    /// reads them by. Under the lock, uncounted as a take and as a reading of the session's clock.
    #[cfg(all(
        test,
        feature = "std",
        any(feature = "threads", feature = "listen", feature = "group")
    ))]
    pub(crate) fn with_chain_router<T>(
        &self,
        f: impl FnOnce(&mut SessionReassembly, u64) -> T,
    ) -> T {
        let mut core = self.core.lock();
        let now_ms = core.0.session_time.ms_at(core.0.clock.now_us());
        f(&mut core.0.transport.router, now_ms)
    }

    /// Where the dial role's link stands, as the life of its face's record says: what a test of
    /// the redials reads. Read under the lock, uncounted as a take.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn dial_phase(&self) -> Option<wz_session_core::link_life::LinkPhase> {
        self.core
            .lock()
            .0
            .transport
            .links
            .face(0)
            .map(|face| face.life.phase())
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

    /// Whether the session's state could be taken now: what a callback of a test asks to tell
    /// that its read handed it out with the session free.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn session_is_free(&self) -> bool {
        self.core.try_lock().is_some()
    }

    /// How often the session's links were let go of since the open ([`Core::end_links`]).
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn links_let_go(&self) -> usize {
        self.core.lock().0.links_let_go.get()
    }

    /// How many samples the session handed to its subscribers' callbacks since the open, each
    /// counted once however many callbacks it reached, whichever way it was delivered: what a
    /// test of the cost of one received sample counts.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn samples_handed(&self) -> usize {
        #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
        let pinned = self.takes.pinned_samples.load(Ordering::Relaxed);
        #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
        let pinned = 0;
        #[cfg(wz_round)]
        let round = self.samples.tally().samples();
        #[cfg(not(wz_round))]
        let round = 0;
        round + pinned
    }

    /// Of the samples [`Self::samples_handed`] counts, how many were handed where their datagram
    /// lies.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn samples_lent(&self) -> usize {
        #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
        let pinned = self.takes.pinned_lent.load(Ordering::Relaxed);
        #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
        let pinned = 0;
        #[cfg(wz_round)]
        let round = self.samples.tally().lent();
        #[cfg(not(wz_round))]
        let round = 0;
        round + pinned
    }

    /// How many peers' replies the read handed to the get each answers itself, with nothing of
    /// them held in the round (`replies`).
    #[cfg(all(
        test,
        feature = "std",
        feature = "query",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
    pub(crate) fn replies_handed_by_the_read(&self) -> usize {
        self.takes.pinned_replies.load(Ordering::Relaxed)
    }

    /// How many calls of the session's queryables the read made itself for the peers' queries, one
    /// for each queryable a query reached, with nothing of them held in the round (`queries`).
    #[cfg(all(
        test,
        feature = "std",
        feature = "queryable",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
    pub(crate) fn queries_handed_by_the_read(&self) -> usize {
        self.takes.pinned_queries.load(Ordering::Relaxed)
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
        self.core.lock().0.session.registry.push_dispatches()
    }

    /// How often the session's links drained a run of Pushes before a later record of its own
    /// frame: what tells a test that a Push and the record after it came in one frame.
    #[cfg(all(test, feature = "std", feature = "queryable"))]
    pub(crate) fn drains_within_frames(&self) -> usize {
        self.core.lock().0.session.registry.drains_within_frames()
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
            #[cfg(wz_round)]
            lane: &self.samples,
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
                    #[cfg(wz_round)]
                    lane: &self.samples,
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
                    return self.live().map_or(ToPublish::Closed, ToPublish::Live);
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
        // Acquire, as the marks are released ([`SendingOn`] says why that is enough).
        match self.sending_on.load(Ordering::Acquire) {
            NOT_SENDING => Holder::Step,
            PUBLISHING => Holder::Publish,
            WAITING => Holder::Waiting,
            place => Holder::Sending(place),
        }
    }

    /// Run `held` while holding the session as a read step holds it: what a test of a publish that
    /// finds the session held by what is not a publish runs beside one.
    #[cfg(all(test, feature = "std", feature = "threads"))]
    pub(crate) fn holding_as_a_step(&self, held: impl FnOnce()) {
        let _core = self.live();
        held();
    }

    /// Run `held` while holding the session as a read working out its wait holds it.
    #[cfg(all(test, feature = "std", feature = "threads"))]
    pub(crate) fn holding_as_a_read_wait(&self, held: impl FnOnce()) {
        let _core = self.live();
        let _waiting = SendingOn::enter(&self.sending_on, WAITING);
        held();
    }

    /// What the session's transports counted (`transport-stats`), in the report a tokio session
    /// gives (`OpenedSession::stats`): the counters of each link that is up and of each group
    /// joined, summed, and in
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
            // leaves with the group's join, as what the group received does.
            #[cfg(feature = "group")]
            for group in &core.0.transport.groups {
                report.absorb(&group.stats_report());
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
    /// Whether this call handed anything out: none inside the delivery it is already making.
    fn deliver(&self) -> bool {
        self.deliveries
            .within(|entered| entered && self.hand_out_entered())
    }

    /// Everything [`Self::deliver`] hands out, inside the delivery it entered: whether its passes
    /// handed anything out.
    fn hand_out_entered(&self) -> bool {
        // A callback can queue more for this delivery than the pass that ran it has already passed
        // over (a queryable's answer to the session's own get lies in the next round): the passes
        // go on until one hands nothing, so a get its own queryables answer inside the call ends
        // there.
        let mut handed = false;
        while self.hand_out() {
            handed = true;
        }
        // The subscribers undeclared while a call of theirs ran, whose last call has ended now.
        #[cfg(wz_round)]
        self.let_go_of_released();
        // What the declaration watches are owed and the round had no room for when it came (the
        // catch-up of a watch declared while a round was handed out, the events a watch lost),
        // held now the round is handed out, each round sealed as the session is let go of and
        // handed out in turn.
        #[cfg(all(
            any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ),
            any(feature = "threads", feature = "listen", feature = "group")
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
        // What a read that steps its one link itself held for the declaration watches as it
        // dispatched the record, and the catch-up a watch is owed, a call at a time; what their
        // sinks queue is handed out after them.
        #[cfg(all(
            any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ),
            not(any(feature = "threads", feature = "listen", feature = "group"))
        ))]
        if self.hand_decl_watches() {
            handed = true;
            while self.hand_out() {}
        }
        // The tokens of a lost link the round had no room for, retracted now the round is handed
        // out, each round sealed as the session is let go of and handed out in turn.
        #[cfg(all(
            feature = "liveliness",
            any(feature = "threads", feature = "listen", feature = "group")
        ))]
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
        while self.gets.ends_pending() && self.round_owes_no_reply() {
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
        handed
    }

    /// Hand each declaration watch what it is owed (`DeclWatches::next_call`), a call at a time:
    /// the row pinned under the session's lock and its sink called with no lock held, so a sink may
    /// reach back into the session. Whether any was handed.
    #[cfg(all(
        any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ),
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
    fn hand_decl_watches(&self) -> bool {
        let mut told = decl_watch::Told::default();
        let mut handed = false;
        while self.decl_watches.owes() {
            let call = {
                let Some(core) = self.live() else {
                    break;
                };
                core.0.next_decl_watch_call(&mut told)
            };
            let Some(call) = call else {
                break;
            };
            call.hand(told.event());
            call.end();
            handed = true;
        }
        handed
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
        // The round the session wrote under its lock, in the order it was written. A build that
        // puts nothing in the round hands none out (`wz_round`, the crate's build script).
        #[cfg(wz_round)]
        let mut handed = self.samples.deliver();
        #[cfg(not(wz_round))]
        let mut handed = false;
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
            Some(mut core) => {
                let tables = tables_mut(&mut core.0.session.registry);
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
            let holder = CoopHolder::<L, C> {
                engine: EngineHandle::reaching(self.reach),
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
        plan: Option<FilterId>,
    ) -> Result<usize, FanoutError> {
        if !opts.allowed_destination.allows_remote() {
            return Ok(0);
        }
        let meta = opts.push_metadata();
        // zenoh's `is_droppable` (`face_send::droppable`). A message with no QoS of its own is sent
        // with the default's, as the send reads it.
        let congestion = meta.qos.unwrap_or(QosLevel::DEFAULT).congestion();
        let droppable = face_send::droppable(opts.reliable_bool(), congestion);
        let mut core = match self.live_to_publish(droppable) {
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
            self.send_handed(&mut core.0);
        }
        let put = Publication {
            keyexpr,
            wire,
            payload,
            opts,
            meta: &meta,
            plan,
        };
        let (outcome, stuck) = self.fan_out_in(&mut core.0, &put, None, begin.pass);
        // The clock is read only for a fan-out that stopped at a face, whose wait it bounds. Only
        // a send that waits for no slot stops one, which a build that listens on nothing never
        // makes: there the fan-out is done, and neither the clock nor the wait is read.
        debug_assert!(
            stuck.is_none() || cfg!(feature = "listen"),
            "a fan-out stops at a face only where a send waits for no slot"
        );
        let stuck = stuck.filter(|_| cfg!(feature = "listen"));
        let fanned = run.fanned(stuck, || core.0.now_us());
        #[cfg(feature = "listen")]
        let waits = match fanned.then {
            Then::WaitForSlots { .. } => core.0.transport.links.owing_waits(),
            Then::Done => OwingWaits::new_static(),
        };
        #[cfg(any(feature = "listen", feature = "group"))]
        if fanned.hand_after {
            self.send_handed(&mut core.0);
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

    /// A publish to the session's links and its own subscribers
    /// (`SessionEngine::publish_on_wire_all`), of the publisher whose write filter is `plan` when
    /// one made it ([`Publication::plan`]).
    #[inline(never)]
    fn publish_everywhere(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        payload: &[u8],
        opts: &PublishOptions,
        plan: Option<FilterId>,
    ) -> Result<usize, FanoutError> {
        // This engine numbers none of its links, offers no frame without waiting and reserves
        // none, so a publish that states a set of links, a retry or the all-or-none form is
        // refused by name before anything is sent, to a link or to a subscriber of the session.
        StatementNotHonoured::of_publish(opts)?;
        // The link first, then the session's own subscribers, as zenoh-pico's `_z_write` does,
        // and nothing local when the link refused it.
        let sent = self.publish_to_link(keyexpr, wire, payload, opts, plan)?;
        #[cfg(feature = "local-subscriber")]
        let sent = sent.saturating_add(self.publish_to_subscribers(keyexpr, payload, opts)?);
        Ok(sent)
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
            let Some(mut core) = self.live() else {
                return outcome;
            };
            let publishing = SendingOn::enter(&self.sending_on, PUBLISHING);
            let now_us = core.0.now_us();
            core.0.transport.links.write_owed_now();
            let pass = run.waited(waited, now_us);
            let (more, again) = self.fan_out_in(&mut core.0, put, None, pass);
            if more.is_err() {
                outcome = more;
            }
            let fanned = run.fanned(again, || now_us);
            waits = match fanned.then {
                Then::WaitForSlots { .. } => core.0.transport.links.owing_waits(),
                Then::Done => OwingWaits::new_static(),
            };
            if fanned.hand_after {
                self.send_handed(&mut core.0);
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
        core: &mut Core<L, C>,
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
        core: &mut Core<L, C>,
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
            plan,
        } = *put;
        // The key as the session's tables name it: by the declaration the ABI named it by while
        // that declaration stands, and whole otherwise. An empty key names nothing a link carries.
        let Some(named) = tables(&core.session.registry).named_at(keyexpr, wire.declared()) else {
            return (Err(FanoutError::ExceedsCapacity), None);
        };
        let send = wz_session_core::session_actions::SendAs {
            reliable: opts.reliable_bool(),
            express: meta.is_express(),
            priority: opts.priority_band(),
        };
        // A plain put of a publisher is written from the head of the plan its declare made, as its
        // put through its write filter is: each link's send takes the head where the link names
        // the key by the plan's declaration and the put carries the plan's QoS, and the parts
        // otherwise.
        let head = plan
            .filter(|_| opts.kind == SampleKind::Put && meta.is_plain_apart_from_qos())
            .and_then(row_of)
            .and_then(|handle| tables(&core.session.registry).write_filters().get(handle))
            .and_then(|row| row.plain())
            .and_then(|way| way.head);
        let link_leg = LinkLeg {
            named,
            payload,
            kind: opts.kind,
            meta,
            send,
            head,
            planned: false,
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
            // A group whose queue is full runs the session's tasks while it waits for room
            // (`group::SessionPace`): what they dispatch reaches the registry lent for that wait.
            let sent = core.registry_lend.lend_for(&mut core.session.registry, || {
                group.publish(GroupPut {
                    keyexpr,
                    wire,
                    payload,
                    kind: opts.kind,
                    meta,
                    reliable: send.reliable,
                    priority: send.priority,
                })
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
            head,
            planned,
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
            // A planned put's key was named on every link when it was planned.
            let key = if planned {
                named
            } else {
                key_on_link(actions, named)
            };
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
                let send = wz_session_core::session_actions::SendAs {
                    reliable,
                    express,
                    priority,
                };
                // A link that names the key by the declaration the head was written for is sent
                // the head, the payload's length and the payload; any other is sent the Put's parts.
                match head.filter(|head| planned || head.names(key.wire())) {
                    Some(head) => {
                        #[cfg(test)]
                        self.takes.planned.fetch_add(1, Ordering::Relaxed);
                        actions.send_put_with_head(key, payload, &head, send)
                    }
                    None => actions.send_plain_put_qos(key, payload, meta.qos, send),
                }
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
        if let Some(mut core) = self.core.try_lock() {
            if !self.closed.load(Ordering::Acquire) {
                self.send_handed(&mut core.0);
            }
        }
    }

    /// Send what was handed to the session ([`Self::hand_off`]), in the order it was handed, each
    /// publish to the faces it was not dropped on.
    // Out of line: four sends of a publish and of its hand-off ask it, each a copy inlined.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[inline(never)]
    fn send_handed(&self, core: &mut Core<L, C>) {
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
    fn send_handed_now(&self, core: &mut Core<L, C>) {
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
                        plan: None,
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
    #[cfg(all(
        feature = "local-subscriber",
        any(feature = "threads", feature = "listen", feature = "group")
    ))]
    fn publish_to_subscribers(
        &self,
        keyexpr: &str,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        if !opts.allowed_destination.allows_local() {
            return Ok(0);
        }
        let Some(mut core) = self.live() else {
            return Ok(0);
        };
        let sample = opts.loopback_sample(keyexpr, payload);
        // SAFETY: the session's lock is held (`core`).
        unsafe { self.samples.capture() };
        core.0.session.registry.local_publish(&sample);
        // SAFETY: as above.
        let mut reached = unsafe { self.samples.captured() };
        drop(core);
        let count = reached.len();
        let sample = SampleRef::of(&sample);
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
        if fan.attach(self.reach.canceller()) {
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

    /// Let go of each row whose last call ended after it was undeclared, when a call the round
    /// ended said one may wait ([`RowReleases::take_marked`]): a walk of each table whose calls the
    /// round ends takes them out one at a time under the session's lock
    /// (`SessionTables::release_drained_subscriber` and its kin) and drops each after it, so a C
    /// program's `drop` never runs under the lock. A build that puts nothing in the round marks
    /// no row: each walk lets go of the rows whose calls it ended itself.
    #[cfg(wz_round)]
    fn let_go_of_released(&self) {
        if !self.releases().take_marked() {
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

    /// What the ends of the calls of the session's rows leave it to let go of: the round's, which
    /// ends the calls it holds.
    #[cfg(wz_round)]
    fn releases(&self) -> &RowReleases {
        self.samples.releases()
    }

    /// What the ends of the calls of the session's rows leave it to let go of: the engine's own,
    /// where nothing is put in the round.
    #[cfg(not(wz_round))]
    fn releases(&self) -> &RowReleases {
        &self.releases
    }

    /// Walk one table with `take`, which takes out the next row at or after its cursor whose last
    /// call ended: each row is taken under the session's lock, its drop counted as under way from
    /// there, and dropped after the lock.
    fn let_go_of_drained<R>(&self, mut take: impl FnMut(&mut CoopTables, &mut usize) -> Option<R>) {
        let mut cursor = 0;
        loop {
            let taken = {
                let mut guard = self.core.lock();
                let tables = tables_mut(&mut guard.0.session.registry);
                take(tables, &mut cursor).map(|row| (row, self.releases().releasing()))
            };
            let Some((row, releasing)) = taken else {
                break;
            };
            drop(row);
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
            || self.releases().settled(),
        );
    }

    /// [`Self::wait_for_release`] for liveliness subscriber `handle`, whose calls the round of
    /// deliveries ends as a subscriber's.
    #[cfg(feature = "liveliness")]
    fn wait_for_liveliness_release(&self, handle: LivelinessSubscriberHandle) {
        self.wait_until_let_go(
            |tables| tables.liveliness_subscribers().holds_slot(handle),
            || self.releases().settled(),
        );
    }

    /// [`Self::wait_for_release`] for queryable `handle`: a query queued for it holds a call of it
    /// until a delivery hands the query out, which hands the undeclared queryable nothing.
    #[cfg(feature = "queryable")]
    fn wait_for_queryable_release(&self, handle: QueryableHandle) {
        self.wait_until_let_go(
            |tables| tables.queryables().holds_slot(handle),
            || self.releases().settled(),
        );
    }

    /// Return once a row of the session's tables undeclared while a call of it ran is let go of:
    /// `held` reads whether its table still holds it, `settled` whether no drop of a row taken
    /// out of its table is under way. At once on a thread that delivers now (see
    /// [`Self::wait_for_release`]).
    fn wait_until_let_go(&self, held: impl Fn(&CoopTables) -> bool, settled: impl Fn() -> bool) {
        // Every call runs on this thread: one that runs now is below on this stack and lets the
        // row go as the delivery it is inside of ends (the delivery here is then none), and with
        // none running the delivery here ends every call the round owes and lets the rows go.
        if !<CoopForm as ThreadForm>::OTHER_THREADS {
            self.deliver();
            return;
        }
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
                held(tables(&guard.0.session.registry))
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
                let mut guard = self.core.lock();
                let tables = tables_mut(&mut guard.0.session.registry);
                let Some((handle, _)) = tables.subscribers().iter().next() else {
                    break;
                };
                tables
                    .undeclare_subscriber(handle)
                    .map(|undeclared| (handle, undeclared.taken))
            };
            match undeclared {
                Some((_, Some(row))) => drop(row),
                Some((handle, None)) => self.wait_for_release(handle),
                None => {}
            }
        }
        loop {
            let row = {
                let mut guard = self.core.lock();
                let tables = tables_mut(&mut guard.0.session.registry);
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
                let mut guard = self.core.lock();
                let tables = tables_mut(&mut guard.0.session.registry);
                let Some((handle, _)) = tables.queryables().iter().next() else {
                    break;
                };
                tables
                    .undeclare_queryable(handle)
                    .map(|undeclared| (handle, undeclared.taken))
            };
            match undeclared {
                Some((_, Some(row))) => drop(row),
                Some((handle, None)) => self.wait_for_queryable_release(handle),
                None => {}
            }
        }
        #[cfg(feature = "liveliness")]
        loop {
            let undeclared = {
                let mut guard = self.core.lock();
                let tables = tables_mut(&mut guard.0.session.registry);
                let Some((handle, _)) = tables.liveliness_subscribers().iter().next() else {
                    break;
                };
                tables
                    .undeclare_liveliness_subscriber(handle)
                    .map(|undeclared| (handle, undeclared.taken))
            };
            match undeclared {
                Some((_, Some(row))) => drop(row),
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

    /// Where a leg's sink hands a reply no thread captured (`get::Uncaptured`): the session's
    /// round of deliveries.
    #[cfg(all(feature = "query", wz_round))]
    fn uncaptured(&self) -> get::Uncaptured {
        self.samples
    }

    /// Where a leg's sink hands a reply no thread captured (`get::Uncaptured`): nowhere, as the
    /// read captures each reply it hands a get.
    #[cfg(all(feature = "query", not(wz_round)))]
    fn uncaptured(&self) -> get::Uncaptured {
        wz_session_core::get_plane::EveryReplyCaptured
    }

    /// Whether no delivery is handing out a round that may still hold a reply of a leg that
    /// ended, so the leg's end may follow it.
    #[cfg(all(feature = "query", wz_round))]
    fn round_owes_no_reply(&self) -> bool {
        self.samples.is_idle()
    }

    /// See the build that keeps a round: one that keeps none holds no reply in one.
    #[cfg(all(feature = "query", not(wz_round)))]
    fn round_owes_no_reply(&self) -> bool {
        true
    }

    /// Hold one leg of a get pending under `entry`: the leg's callback minted in a row of the
    /// plane's, and its sink registered with the deadline and the accepted key the get states.
    /// Out of line where a get issues more than one kind of leg (to groups, or to the session
    /// itself, besides its links), so those legs are held by one body and not by a copy each; a
    /// build whose get asks its links alone has one caller, which keeps it inline.
    #[cfg(feature = "query")]
    #[cfg_attr(any(feature = "group", feature = "local-queryable"), inline(never))]
    fn hold_leg(
        &self,
        now_us: u64,
        registry: &mut Registry,
        ask: &mut LegAsk<'_, '_>,
        entry: LegEntry,
    ) -> LegHeld {
        let LegEntry {
            face,
            leg: leg_id,
            rid,
            finals,
        } = entry;
        let timeout_ms = ask.opts.effective_timeout_ms();
        // Rounded up, so a get whose deadline the sweep reads in whole milliseconds never ends
        // before its timeout.
        let deadline_ms = (timeout_ms > 0).then(|| leg_deadline_ms(now_us, timeout_ms));
        // A get no row holds is refused before its leg's callback is minted.
        match registry.gets_mut(face).map(|gets| gets.replies.has_room()) {
            Some(true) => {}
            Some(false) => return LegHeld::NoRoom,
            None => return LegHeld::Gone,
        }
        // The leg's callback, in a row of the plane's the entry's sink holds.
        let Some(row) = self.gets.open_leg(&mut *ask.mint, ask.expose) else {
            return LegHeld::NoRoom;
        };
        // SAFETY: the sink goes into a table of pending gets, which the session
        // reaches under its lock alone, and is handed its replies there; the table is the
        // registry's, dropped before the owners of the plane and of the round where the build
        // keeps one, the session state's fields after the registry's.
        let leg_sink = unsafe { get::LegSink::new(leg_id, row, self.gets, self.uncaptured()) };
        let sink = ConsolidatingSink::with_hold(
            ask.opts.resolved_consolidation(),
            leg_sink,
            get::LegHold::new(leg_id, self.gets),
        );
        let accept = ReplyAcceptance::for_query(ask.keyexpr, ask.opts.effective_accept_replies());
        let registered = registry.gets_mut(face).map(|gets| {
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
            // Handed as it lies: a requester that keeps the reply copies what it keeps, and keeps
            // a buffer of shared memory as its page, as it keeps the owned projection's.
            let reply = wz_session_core::reply::LocalReplyView::new(parts);
            self.gets.capture();
            // Mutable here alone: the link's path only reads the session.
            let mut core = core;
            core.0
                .session
                .registry
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
            // Mutable here alone: the link's path only reads the session.
            let mut core = core;
            if due.is_some() {
                core.0
                    .session
                    .registry
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
                let registry = &core.0.session.registry;
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
        // let go of as the call ends.
        self.end_liveliness_call(call);
    }

    /// End `call`, made of a liveliness subscriber's row: a row whose last call it was is marked
    /// for the walk the round's delivery ends with.
    #[cfg(all(
        feature = "liveliness",
        any(feature = "threads", feature = "listen", feature = "group")
    ))]
    fn end_liveliness_call(&self, call: LivelinessCall) {
        self.samples.end_liveliness_call(call);
    }

    /// End `call`, made of a liveliness subscriber's row: a row whose last call it was is let go
    /// of here, with no lock held, as a Push's walk lets a subscriber's go (`pinned`).
    #[cfg(all(
        feature = "liveliness",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
    fn end_liveliness_call(&self, call: LivelinessCall) {
        if call.end() {
            self.let_go_of_drained(|tables, cursor| {
                tables
                    .release_drained_liveliness_subscriber(cursor)
                    .map(|row| row.into_callback())
            });
        }
    }

    /// Step the session until it has nothing more to do, move its link on, and notice a session
    /// that ended. The step reads the clock once, and its tasks' timers and everything it does
    /// after them are measured by that reading, which it returns ([`Stepped`]). A step whose
    /// tasks ran first reads it before them; a deadline passed while they ran is then found by
    /// the next step, so a sweep is late by one step's run of its tasks at most. A step that read
    /// records of a link that holds more input it has already taken from its stack reads no clock
    /// and moves nothing.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    fn step(&self, core: &mut Core<L, C>) -> Stepped {
        // What a lost link's peer is still owed comes before anything the links bring now.
        #[cfg(feature = "liveliness")]
        if self.samples.owes() {
            core.retract_owed();
        }
        let was_idle = self.samples.is_idle();
        // A step that goes on with what a link took from its stack in an earlier receive wakes no
        // timer and reads no clock for its tasks: a timer due meanwhile is woken by the step that
        // reads the last of it, by that step's own reading below. A timer is so late by one
        // receive's reading at most, as zenoh-pico's read task looks at its lease and keep-alive
        // after the batch it read.
        // A group's burst goes on the same way, the step before having read one of its datagrams.
        #[cfg(feature = "group")]
        let group_going_on = core.group_reads > 0;
        #[cfg(not(feature = "group"))]
        let group_going_on = false;
        let going_on = was_idle && (group_going_on || core.transport.links.holds_input());
        // The one reading of a step whose tasks run first, which every bound after them shares.
        let read_us = if going_on {
            core.run_tasks_at(None);
            None
        } else {
            let now_us = core.now_us();
            core.run_tasks_at(Some(now_us));
            Some(now_us)
        };
        // A step reads what the round has room for and no more: one record in a build of one
        // thread, the records of one datagram in a build of threads, whose next datagram waits
        // while a record lies in the one lent (`Round::has_room`, `RoundGate`). What the link
        // took from its stack in one receive is then read a step at a time, each after the
        // callbacks of the one before returned. The links are moved once, by the step that reads
        // the last of it: a move a step would look at every port and turn every face's replay once
        // a message, and batching would save nothing. A round that was not empty took no record (a
        // step from inside a callback, or while another thread hands a round out), and that step
        // moves the links as any other. Only a link's input counts: what it took in one receive
        // ends. A group takes a datagram of its socket a step for as long as they come, so its
        // input goes on so up to `GROUP_READS_PER_MOVE` datagrams in a row, and the step that finds
        // none, or the one past that bound, moves the links.
        if was_idle && !self.samples.is_idle() {
            if core.transport.links.holds_input() {
                return Stepped::Read;
            }
            #[cfg(feature = "group")]
            if core.group_reads < core.config.limits.group_reads_per_move()
                && core.transport.group_holds_input()
            {
                core.group_reads = core.group_reads.saturating_add(1);
                return Stepped::Read;
            }
        }
        #[cfg(feature = "group")]
        {
            core.group_reads = 0;
        }
        // The timers the steps of this receive passed over, by the step's one reading.
        let now_us = match read_us {
            Some(now_us) => now_us,
            None => {
                let now_us = core.now_us();
                core.run_tasks_at(Some(now_us));
                now_us
            }
        };
        // The bookkeeping, only when a deadline of it passed or something it follows changed
        // since it last ran: a stream of input that changes neither runs none of it.
        if core.owes_bookkeeping(now_us) {
            return self.service(core, now_us);
        }
        Stepped::Moved(now_us)
    }

    /// The step's bookkeeping at `now_us`, the step's reading of the clock: the sweeps of the
    /// Router's chains and of the gets, the move of the links, a group's ask and the read of the
    /// matching listeners, each where its own deadline or count says, and the ledger settled
    /// after them ([`Core::settle_ledger`]). `Stepped::Closed` when the move of the links ends
    /// the session.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    fn service(&self, core: &mut Core<L, C>, now_us: u64) -> Stepped {
        #[cfg(test)]
        core.services.set(core.services.get() + 1);
        // A link's receive sweeps nothing, so the session ends the chains of its one reassembly
        // Router past their deadline here, once a step and by its reading, whichever link's task
        // ran; on the epoch its links staged them on, which is not the clock's own.
        let chain_ms = core.session_time.ms_at(now_us);
        if chain_ms >= core.transport.router.due_ms() {
            core.transport.router.sweep(chain_ms);
        }
        core.sweep_gets(now_us);
        let redial_ms = core.config.redial_ms;
        // Why the session ends is no reader's here: a handle finds it closed.
        let mut last = OpenError::NoEndpoint;
        if core.move_links(redial_ms, now_us, &mut last).is_err() {
            // A handle reads the session closed from its row from here on, as after a close.
            self.reach.end();
            self.closed.store(true, Ordering::Release);
            return Stepped::Closed;
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
        let written = core.session.registry.faces_written();
        if core.session.matching.moved(written) {
            self.read_matching(core);
        }
        core.settle_ledger();
        Stepped::Moved(now_us)
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> Core<L, C> {
    /// End the gets whose deadline passed by `now_us`: a get whose deadline has passed ends with
    /// zenoh's timeout reply and its Final, at the step's bookkeeping, because the entries are the
    /// registry's.
    fn sweep_gets(&mut self, now_us: u64) {
        #[cfg(feature = "query")]
        {
            let now_ms = now_us / 1000;
            let registry = &mut self.session.registry;
            for gets in registry.all_gets_mut() {
                // A get's deadline is the earliest the sweep could end one at.
                if now_ms >= gets.replies.due_ms() {
                    gets.replies.sweep_timed_out(now_ms);
                }
                // A liveliness snapshot that expired ends the same way. Its terminated ids are
                // staged for a reconnect cache this engine does not keep (it declares again from
                // its own entries), so they are drained and dropped: staged ones would pile up.
                // A table with no get pending and none ended has nothing to sweep or drain, and the
                // drain makes a buffer of the table's whole ceiling: neither is done at every step.
                #[cfg(feature = "liveliness-get")]
                if !gets.liveliness_gets.is_empty() || gets.liveliness_gets.has_finalized() {
                    gets.liveliness_gets.sweep_timed_out(now_ms);
                    drop(gets.liveliness_gets.take_finalized());
                }
            }
        }
        #[cfg(not(feature = "query"))]
        let _ = now_us;
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
    /// One take of the session for a step after `wait`: its links, what publishes handed to it,
    /// and whether a periodic job is due by the clock reading the step made. What publishes handed
    /// to the session while it was held leaves on this step too, so a program that only reads its
    /// session sends it; let go of once the session is. What the step came to, and the time a
    /// job is due.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    fn step_after(&self, wait: IdleWait) -> (Stepped, Option<u64>) {
        let Some(mut core) = self.live() else {
            return (Stepped::Closed, None);
        };
        #[cfg(feature = "threads")]
        let handed = matches!(wait, IdleWait::Input { .. });
        core.0.transport.links.waited(wait);
        #[cfg(feature = "threads")]
        if handed {
            self.hand_back.handed_back();
        }
        let stepped = self.step(&mut core.0);
        self.input_held.store(
            stepped != Stepped::Closed && core.0.transport.holds_input(),
            Ordering::Relaxed,
        );
        let jobs_due_ms = match stepped {
            Stepped::Moved(now_us) => core.0.jobs_due_at(now_us),
            Stepped::Read | Stepped::Closed => None,
        };
        // What was handed to the session leaves with the step that moves the links.
        #[cfg(any(feature = "listen", feature = "group"))]
        if stepped != Stepped::Read {
            self.send_handed_now(&mut core.0);
        }
        (stepped, jobs_due_ms)
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
        // A listener on a key asks its own Interest of each link from its row; one on a filter
        // asks nothing.
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
        // The registry itself, not its holder: the tables' walk reads it as what the peers declare.
        let registry: &Registry = &core.session.registry;
        core.session.matching.read_at(registry.faces_written());
        let mut cursor = 0;
        while registry
            .app
            .tables
            .next_matching_change(&mut cursor, registry)
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
        // (`QueryPlane::arrive`, `QueryPlane::arrive_own`), so none stages a reply here: the
        // stage they are handed has no room.
        let mut staged = ReplyStage::<RowPolicy>::default();
        let registry = &mut core.session.registry;
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
                self.end_own_call(call);
            }
        });
        // What they answered is handed out with no lock held, and, in a build of threads, a row
        // whose last call one of these was, its queryable undeclared meanwhile, is let go of by
        // the delivery's walk, its drop perhaps the program's own.
        self.deliver();
    }

    /// End `call`, which the session's own get made of one of its queryables: a row whose last
    /// call it was is marked for the round's walk to let go of after the delivery.
    #[cfg(all(
        feature = "local-queryable",
        any(feature = "threads", feature = "listen", feature = "group")
    ))]
    fn end_own_call(&self, call: QueryableCall) {
        self.samples.end_query_call(call);
    }

    /// End `call`, which the session's own get made of one of its queryables: a row whose last
    /// call it was is let go of here, with no lock held, as a link's query's walk lets it go
    /// (`queries`).
    #[cfg(all(
        feature = "local-queryable",
        not(any(feature = "threads", feature = "listen", feature = "group"))
    ))]
    fn end_own_call(&self, call: QueryableCall) {
        if call.end() {
            self.let_go_of_drained(|tables, cursor| {
                tables
                    .release_drained_queryable(cursor)
                    .map(|row| row.into_callback())
            });
        }
    }

    /// Whether write filter `id` holds what it filters back: a filter is created suppressing,
    /// until a peer declares what it counts, or the session itself does when it counts its own
    /// (`vendor/zenoh-pico/src/net/filtering.c` @ `ctx->state = WRITE_FILTER_ACTIVE`). A filter
    /// the session does not hold holds nothing back.
    fn filter_active_in(core: &Core<L, C>, id: FilterId) -> bool {
        let Some(handle) = row_of(id) else {
            return false;
        };
        // The registry itself, not its holder: the filter reads it as what the peers declare.
        let registry: &Registry = &core.session.registry;
        // What the peers answered is kept by the filter's row until a face's tables are written.
        let open = registry.app.tables.write_filter_open(handle, registry);
        open.is_some_and(|open| !open)
    }

    /// A plain Put on the key `declared` names (the literal `keyexpr` when its id is `0`), read at the
    /// row `declared` names while that row holds the id, sent from `params` to
    /// every link, once the write filter let it through, as a publish is sent
    /// ([`Self::send_on_links`]): `NotPlain`, with nothing sent, when a subscriber of the session or
    /// a group wants it the general way, or the key names nothing a link carries.
    fn put_plain_in(
        &self,
        core: &Core<L, C>,
        keyexpr: &str,
        declared: KeyexprRef,
        payload: &[u8],
        params: &PlainPutParams,
        head: Option<wz_session_core::lent_push::PutHead>,
    ) -> FilteredPut {
        // A put one of the session's own subscribers wants is not plain: the general publish
        // sends it and delivers it there.
        #[cfg(feature = "local-subscriber")]
        if params.destination.allows_local()
            && wz_session_core::pubsub::LocalSubscribers::has_local_matching(
                tables(&core.session.registry),
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
        // The key as the session's tables name it, read at the declaration's row where the caller
        // kept it, and each link as its key-wire form says.
        #[cfg(test)]
        self.takes.namings.fetch_add(1, Ordering::Relaxed);
        let Some(named) = tables(&core.session.registry).named_at(keyexpr, declared) else {
            return FilteredPut::NotPlain;
        };
        self.send_plain(core, named, payload, params, head, false)
    }

    /// The plain put its write filter's row planned at the session's send epoch
    /// (`WriteFilterRow::planned_put`): sent to every link from the plan's head, with the
    /// filter's answer, the key's naming and each link's form of it taken as the plan found them.
    fn put_planned(
        &self,
        core: &Core<L, C>,
        planned: &wz_session_core::session_tables::PlannedPut<'_>,
        payload: &[u8],
    ) -> FilteredPut {
        #[cfg(test)]
        self.takes.plans.fetch_add(1, Ordering::Relaxed);
        self.send_plain(
            core,
            planned.key(),
            payload,
            &planned.params(),
            Some(planned.head()),
            true,
        )
    }

    /// A plain Put on `named`, sent from `params` to every link ([`Self::send_on_links`]), the
    /// head written for it where a link names the key by the head's declaration, and on every link
    /// when `planned`.
    fn send_plain(
        &self,
        core: &Core<L, C>,
        named: NamedKey<'_>,
        payload: &[u8],
        params: &PlainPutParams,
        head: Option<wz_session_core::lent_push::PutHead>,
        planned: bool,
    ) -> FilteredPut {
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
            head,
            planned,
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
        !Self::filters_left_unasked(core) && Self::filter_active_in(core, id)
    }

    /// Whether the session holds a group the write filters do not ask, which is sent a write
    /// whatever a filter says ([`Self::holds_back_in`]).
    fn filters_left_unasked(core: &Core<L, C>) -> bool {
        #[cfg(feature = "group")]
        if core
            .transport
            .groups
            .iter()
            .any(|group| !group.declarations().asks_for_filters())
        {
            return true;
        }
        #[cfg(not(feature = "group"))]
        let _ = core;
        false
    }

    /// How often what the peers declared was searched since the open: what a test of the cost of
    /// a filtered put counts. Read under the lock, uncounted as a take.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn peer_looks(&self) -> usize {
        self.core.lock().0.session.registry.peer_looks()
    }

    /// Hand out entity ids from `next` on, none with `None`: how a test reaches the end of the
    /// id space without spending it.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn entity_ids_from(&self, next: Option<EntityId>) {
        tables_mut(&mut self.core.lock().0.session.registry).entity_ids_from(next);
    }

    /// Mint key expression ids from `next` on: how a test reaches the wrap of the id space
    /// without spending it.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn expr_ids_from(&self, next: ExprId) {
        tables_mut(&mut self.core.lock().0.session.registry).expr_ids_from(next);
    }

    /// Start the read task on the thread `spawn` makes; idempotent. A system that gives no thread
    /// is answered (`NoThread`), and the task is left not running, so a later start tries again:
    /// zenoh-pico's start answers its task creation's error the same way, and a panic here would
    /// leave the C caller nothing to read on a build that aborts on one.
    #[cfg(feature = "threads")]
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
        let Some(engine) = self.hold() else {
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
    #[cfg(feature = "threads")]
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
impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> wz_capi_port::KeyHolds
    for CoopEngine<L, C>
{
    #[inline(never)]
    fn release_keyexpr(&self, row: KeyexprHandle) {
        #[cfg(test)]
        self.takes.holds.fetch_sub(1, Ordering::Relaxed);
        let Some(mut core) = self.live() else {
            return;
        };
        let core = &mut core.0;
        // A row that went names nothing, whichever declaration took its slot or its id since.
        let place = core.prefix_retraction(Some(row));
        let retracted = tables_mut(&mut core.session.registry).undeclare_keyexpr(row);
        // The row went before the links are told: a send never finds the table borrowed.
        core.retract_keyexpr(place, retracted);
    }

    #[inline(never)]
    fn retain_keyexpr(&self, row: KeyexprHandle) -> Result<(), HoldRefused> {
        let Some(mut core) = self.live() else {
            return Err(HoldRefused::Gone);
        };
        // One more hold of the row in the session's one table set; nothing goes on the wire.
        let tables = tables_mut(&mut core.0.session.registry);
        if tables.retain_keyexpr(row) {
            #[cfg(test)]
            self.takes.holds.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else if tables.keyexprs().get(row).is_some() {
            Err(HoldRefused::Full)
        } else {
            Err(HoldRefused::Gone)
        }
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> wz_capi_port::Tickers
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
impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> SessionEngine for CoopEngine<L, C> {
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
    // told each face its rows gather into, gathered in a place of its own.
    #[cfg(feature = "connectivity")]
    fn watch_faces(&self, sink: FaceEventSink) -> Result<u64, Declined> {
        let place = self
            .lodgings
            .lend(wz_capi_port::lodge::Lent::<wz_capi_port::face_rows::Gathering>::LAYOUT)
            .ok_or(Declined::NoRoom)?;
        let place = wz_capi_port::lodge::Lent::of_bytes(place).map_err(|_| Declined::NoRoom)?;
        SessionEngine::watch_face_rows(
            self,
            wz_capi_port::face_rows::snapshots_of_rows(sink, place),
        )
    }

    #[cfg(feature = "connectivity")]
    fn watch_face_rows(&self, sink: FaceRowSink) -> Result<u64, Declined> {
        if SessionEngine::is_closed(self) {
            return Err(Declined::Closed);
        }
        // A refused sink is let go of here, with the plane's lock let go of.
        self.faces.watch(sink).map_err(|_| Declined::TableFull)
    }

    // Without the plane no face is told, so a watch of the rows is refused as one of the
    // snapshots is: the provided answer would lend a place of the heap to a watcher it then lets
    // go of untold.
    #[cfg(not(feature = "connectivity"))]
    fn watch_face_rows(&self, sink: FaceRowSink) -> Result<u64, Declined> {
        let _ = sink;
        Err(Declined::NotBuilt)
    }

    #[cfg(feature = "connectivity")]
    fn unwatch_faces(&self, id: u64) -> bool {
        self.faces.unwatch(id)
    }

    /// The watch is told first what each link's peer holds now, then what the links' dispatch
    /// holds for it from here on (`decl_watch`): at once when the round takes the catch-up, or by
    /// the next round when it is handed out now, as it is to a watch declared from inside a
    /// callback; where the read steps its one link itself, by this call, or by the delivery a
    /// callback that declares it runs in. A refused sink is let go of with no lock held.
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
        let Some(mut guard) = self.live() else {
            return Err(Declined::Closed);
        };
        let core = &mut guard.0;
        let added = self
            .decl_watches
            .add(&mut core.session.registry.app, plane, sink);
        let id = match added {
            Ok(id) => id,
            Err((refused, sink)) => {
                drop(guard);
                drop(sink);
                return Err(refused);
            }
        };
        #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
        core.tell_decl_watches_owed();
        // The catch-up is handed now, before the link is read again; a declare from inside a
        // callback has it handed by the delivery the callback runs in, as the call returns.
        #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
        {
            drop(guard);
            self.deliver();
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
            Some(mut core) => {
                let registry = &mut core.0.session.registry;
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
        self.publish_everywhere(keyexpr, wire, payload, opts, None)
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
        // A closed session declares nothing, and takes no id for what it does not declare. The
        // subscriber is one row of the session's tables, numbered by the id they hand out next: a
        // full table, a key the session cannot hold or no id left refuses it before anything is
        // sent. What the key holds and the sink go back with either refusal, let go of after the
        // session in the one place both are. The row holds the key expression declaration its
        // key is named by for as long as it stands.
        let live = self.live().map(|guard| {
            let next = tables(&guard.0.session.registry).next_entity_id();
            (guard, next)
        });
        let (mut guard, id) = match live {
            Some((guard, Some(id))) => (guard, id),
            refused => {
                let why = match refused {
                    Some(_) => Declined::NoEntityId,
                    None => Declined::Closed,
                };
                drop(refused);
                drop(wire);
                drop(sink);
                return Err(why);
            }
        };
        let core = &mut guard.0;
        let form = core
            .session
            .key_form(
                wire.declared(),
                retraction.map_or(Retraction::ById, Retraction::Named),
            )
            .owning(tables(&core.session.registry).keyexpr_by_id(wire.own_declaration()));
        // The tables' row holds the declarations the key and the retraction name, once each, in
        // the session's one count; the row keeps what else the key kept.
        // The declaration states no choice about the timestamp, so it takes the session's
        // `entity-timestamp-opt-in`, as the policy the session was opened under resolves it.
        let row = SubscriberRow::new(wire.into_anchor(), sink, exposed_by(&core.policy));
        let declared = tables_mut(&mut core.session.registry).declare_subscriber(
            keyexpr,
            allowed_origin,
            form,
            row,
        );
        let declared = match declared {
            Ok(declared) => declared,
            Err(refused) => {
                // The program's callback goes with the refusal, let go of with no lock held, and
                // what the key kept with it.
                drop(guard);
                let why = Declined::from(refused.why);
                drop(refused.callback);
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
        // What it owes the Interests the peers asked goes now, after the declaration itself.
        #[cfg(feature = "interest-answer")]
        core.settle_faces();
        // A matching listener that counts the session's own subscribers may now match: it is
        // told, outside the lock.
        #[cfg(feature = "local-subscriber")]
        self.read_matching(core);
        drop(guard);
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
                tables_mut(&mut core.session.registry).undeclare_liveliness_subscriber(handle)?;
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
                (_, Some(row)) => drop(row),
                (handle, None) => self.wait_for_liveliness_release(handle),
            }
            return;
        }
        // The row is taken out of the tables under the lock and let go of after it: what its key
        // kept may reach the session as it goes (`KeyAnchor`). One a call of which runs is
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
                            row.key().holds(),
                            // Read against the key, held past the row.
                            tables
                                .retraction_of(row.key())
                                .map(|names| (names, row.key().backing().clone())),
                        )
                    });
                found
            };
            let (rank, handle, (prefix, named), retraction) = found?;
            // The links are asked while the rows stand, which are their places in the replay's
            // order: the subscriber's, ranked by the walk that found it, then the declaration's,
            // which comes before every subscriber.
            let place = core.place(DeclaredTable::Subscribers, rank);
            let keyexpr_place = core.prefix_retraction(prefix);
            let named_place = core.prefix_retraction(named);
            #[cfg(feature = "group")]
            core.transport.retract_from_groups(id);
            let undeclared = tables_mut(&mut core.session.registry).undeclare_subscriber(handle)?;
            let row = undeclared.taken;
            // The rows went before the links are told: a send never finds the tables borrowed.
            core.retract_at(place, &|actions: &LinkActions<C>| {
                let names = retraction.as_ref().map(|(names, key)| names.names(key));
                SubscriberRow::retract(id, names, actions);
            });
            core.retract_keyexpr(keyexpr_place, undeclared.keyexpr);
            core.retract_keyexpr(named_place, undeclared.named);
            // An aggregate answer it alone stood for is retracted now, as it was declared.
            #[cfg(feature = "interest-answer")]
            core.settle_faces();
            // One that counted it may now match no more.
            #[cfg(feature = "local-subscriber")]
            self.read_matching(core);
            Some((handle, row))
        });
        // The row, and its callback with it, is let go of here, with no lock held; one a call of
        // which runs is let go of by the call that ends last.
        match undeclared {
            Some((_, Some(row))) => drop(row),
            Some((handle, None)) => self.wait_for_release(handle),
            None => {}
        }
        #[cfg(feature = "local-subscriber")]
        self.deliver();
    }

    #[inline(never)]
    fn acquire_keyexpr(&self, keyexpr: &str) -> Result<KeyHold, Declined> {
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
            tables_mut(&mut core.session.registry).declare_keyexpr_where(keyexpr, false, usable)?;
        let id = declared.id;
        if !declared.new {
            #[cfg(test)]
            self.takes.holds.fetch_add(1, Ordering::Relaxed);
            return Ok(KeyHold::taken(id, declared.handle));
        }
        // A declaration a link refuses is not made, and the links that took it take it back; one
        // made while a link is down, or that a replay has not reached, is sent in its turn. A link
        // refuses one it cannot carry.
        // Each link is told it from the row, as every declaration is.
        let taken =
            core.announce_or_undo(DeclaredRow::of(declared.handle), &undeclare_kexpr::<C>(id));
        if !taken {
            tables_mut(&mut core.session.registry).undeclare_keyexpr(declared.handle);
            return Err(Declined::ExceedsCapacity);
        }
        // And each group told the session's keyexprs, as a link is.
        #[cfg(feature = "group")]
        for group in &core.transport.groups {
            group.announce_keyexpr(id, keyexpr);
        }
        #[cfg(test)]
        self.takes.holds.fetch_add(1, Ordering::Relaxed);
        Ok(KeyHold::taken(id, declared.handle))
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
        // A build that keeps no filter rows for a listener on a key, or does not hold the plane,
        // refuses it first, with nothing taken. Every refusal lets `sink` go as it returns, before
        // the caller hears of it.
        if !cfg!(feature = "key-matching-listener") {
            return Err(Declined::NotBuilt);
        }
        if !counts(plane) {
            return Err(Declined::NotBuilt);
        }
        let mut guard = self.live().ok_or(Declined::Closed)?;
        // The listener is a row of the session's tables on a write filter of its own, which holds
        // an Interest: a full table, a key the session cannot hold or an Interest it cannot hold or
        // number refuses it before anything is asked, as a listener that could ask no peer would
        // never hear one.
        let declared = tables_mut(&mut guard.0.session.registry).declare_matching_listener_on(
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
        let mut guard = self.live().ok_or(Declined::Closed)?;
        // The listener is a callback of the filter's row, which it reads and goes with, and asks
        // nothing of its own, as zenoh-pico's is a callback of its entity's filter.
        let declared = tables_mut(&mut guard.0.session.registry)
            .declare_matching_listener(handle, MatchingCall { sink: Some(sink) })
            .map(|handle| Watching {
                handle,
                interest: None,
            });
        self.matching_declared(guard, declared)
    }

    fn undeclare_matching_listener(&self, id: MatchId) {
        let gone = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let handle = row_of(id)?;
            let place = {
                let tables = tables(&core.session.registry);
                let row = tables.matching_listeners().get(handle)?;
                // A listener declared on a key ends the Interest of the filter it owns; one declared
                // on an entity's filter ends none.
                let owned = row.owns_filter().then_some(row.filter());
                let interest =
                    owned.and_then(|filter| tables.write_filters().get(filter)?.interest());
                interest_rank(tables, interest)
            };
            let unwatched =
                tables_mut(&mut core.session.registry).undeclare_matching_listener(handle)?;
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
        let watching = tables_mut(&mut core.session.registry)
            .declare_write_filter_as(
                plane_of(plane),
                keyexpr,
                counts_own(plane, count_local),
                name,
            )
            .map_err(Declined::from)?;
        let id = row_id(watching.handle);
        // The id this filter spent of its own: its Interest's, or the one taken for a filter that
        // sends none.
        let spent = match watching.interest {
            Some(opened) => {
                core.announce(DeclaredRow::of(opened.handle));
                u64::from(opened.id)
            }
            None => {
                // The entity id is taken whether the Interest is sent or not, as zenoh-pico's
                // `_z_add_interest` takes it before it decides: a filter that finds none left is
                // refused, its row given back.
                let Some(taken) = core.session.take_entity_id() else {
                    let _ = unwatch_filter(tables_mut(&mut core.session.registry), watching.handle);
                    return Err(Declined::NoEntityId);
                };
                u64::from(taken)
            }
        };
        // Each group a write filter asks (`asks_for_filters`) is asked for its members'
        // declarations by the id the filter spent, as the tokio engine's group is.
        #[cfg(feature = "group")]
        if core
            .transport
            .groups
            .iter()
            .any(|group| group.declarations().asks_for_filters())
        {
            for group in &core.transport.groups {
                group.ask_filter(id, spent, plane, keyexpr, wire);
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
            interest_rank(tables, row.interest())
        };
        let Some(last_held) = unwatch_filter(tables_mut(&mut core.session.registry), handle) else {
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
        declared: KeyexprRef,
        payload: &[u8],
        params: &PlainPutParams,
    ) -> FilteredPut {
        self.put_through_filter(filter, keyexpr, payload, Some((declared, *params)))
    }

    #[inline(never)]
    fn keep_write_filter_plain(
        &self,
        filter: FilterId,
        plain: Option<(PlainPutParams, KeyexprRef)>,
    ) {
        let Some(core) = self.live() else {
            return;
        };
        if let Some(handle) = row_of(filter) {
            tables(&core.0.session.registry).keep_write_filter_plain(handle, plain);
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
            // The publisher's plan writes the put where it is a plain one on the plan's key.
            return FilteredPut::Sent(self.publish_everywhere(
                keyexpr,
                wire,
                payload,
                opts,
                Some(filter),
            ));
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
            drop(wire);
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
            drop(wire);
            return Err(Declined::NoEntityId);
        };
        let form = core
            .session
            .key_form(
                wire.declared(),
                retraction.map_or(Retraction::ById, Retraction::Named),
            )
            .owning(tables(&core.session.registry).keyexpr_by_id(wire.own_declaration()));
        // The tables' row holds the declarations the key and the retraction name, once each, in
        // the session's one count; the row keeps what else the key kept.
        let row = QueryableRow::new(wire.into_anchor(), sink);
        let declared = tables_mut(&mut core.session.registry).declare_queryable(
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
                // kept with it.
                drop(guard);
                let why = Declined::from(refused.why);
                drop(refused.callback);
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
            // Its deadline may come before the one the step's bookkeeping is due at.
            core.ledger.owe();
            match self.hold_leg(
                core.clock.now_us(),
                &mut core.session.registry,
                &mut ask,
                LegEntry {
                    face,
                    leg: leg_id,
                    rid,
                    finals: 1,
                },
            ) {
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
                if let Some(tables) = core.session.registry.face_mut(face) {
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
            // Its deadline may come before the one the step's bookkeeping is due at.
            core.ledger.owe();
            match self.hold_leg(
                core.clock.now_us(),
                &mut core.session.registry,
                &mut ask,
                LegEntry {
                    face,
                    leg: leg_id,
                    rid,
                    finals,
                },
            ) {
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
                if let Some(tables) = core.session.registry.face_mut(face) {
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
            // Its deadline may come before the one the step's bookkeeping is due at.
            core.ledger.owe();
            match self.hold_leg(
                core.clock.now_us(),
                &mut core.session.registry,
                &mut ask,
                LegEntry {
                    face: LOCAL_FACE,
                    leg: leg_id,
                    rid,
                    finals: 1,
                },
            ) {
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
            // reaches under its lock alone, and is handed its replies there; the table is the
            // registry's, dropped before the owners of the plane and of the round where the build
            // keeps one, the session state's fields after the registry's.
            let leg_sink = unsafe { get::LegSink::new(leg_id, row, self.gets, self.uncaptured()) };
            // One DeclFinal: the face's peer's. Registered before the Interest goes out, so no
            // answer can arrive before its entry.
            let registered = core
                .session
                .registry
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
            // Its deadline may come before the one the step's bookkeeping is due at.
            core.ledger.owe();
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
                if let Some(tables) = core.session.registry.face_mut(face) {
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
        // The row is taken out of the tables under the lock and let go of after it: what its key
        // kept may reach the session as it goes (`KeyAnchor`). One a call of which is owed,
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
                            row.key().holds(),
                            // Read against the key, held past the row.
                            tables
                                .retraction_of(row.key())
                                .map(|names| (names, row.key().backing().clone())),
                        )
                    });
                found
            };
            let (rank, handle, (prefix, named), retraction) = found?;
            // The links are asked while the rows stand, which are their places in the replay's
            // order: the queryable's, ranked by the walk that found it, then the declaration's,
            // which comes before every queryable.
            let place = core.place(DeclaredTable::Queryables, rank);
            let keyexpr_place = core.prefix_retraction(prefix);
            let named_place = core.prefix_retraction(named);
            #[cfg(feature = "group")]
            core.transport.retract_from_groups(id);
            let undeclared = tables_mut(&mut core.session.registry).undeclare_queryable(handle)?;
            let row = undeclared.taken;
            // The rows went before the links are told: a send never finds the tables borrowed.
            core.retract_at(place, &|actions: &LinkActions<C>| {
                let names = retraction.as_ref().map(|(names, key)| names.names(key));
                QueryableRow::retract(id, names, actions);
            });
            core.retract_keyexpr(keyexpr_place, undeclared.keyexpr);
            core.retract_keyexpr(named_place, undeclared.named);
            // One that counted it may now match no more.
            #[cfg(feature = "local-queryable")]
            self.read_matching(core);
            Some((handle, row))
        });
        // The row, and its callback with it, is let go of here, with no lock held; one a call of
        // which is owed is let go of by the call that ends last.
        match undeclared {
            Some((_, Some(row))) => drop(row),
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
            let form = core
                .session
                .key_form(wire.declared(), named)
                .owning(tables(&core.session.registry).keyexpr_by_id(wire.own_declaration()));
            let declared = tables_mut(&mut core.session.registry).declare_token(keyexpr, form)?;
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
        // not kept: what it kept goes, declared or refused, with no lock held.
        drop(wire);
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
        let Some(undeclared) = tables_mut(&mut core.session.registry).undeclare_token(handle)
        else {
            return;
        };
        #[cfg(feature = "group")]
        core.transport.retract_from_groups(id);
        // The rows went before the links are told: a send never finds the tables borrowed.
        let key = undeclared.taken.as_ref().map(|row| row.key().as_str());
        core.retract_at(token_place, &|actions: &LinkActions<C>| {
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
            drop(wire);
            return Err(Declined::Closed);
        };
        let core = &mut guard.0;
        // The subscriber is one row of the session's tables, numbered by the id they hand out
        // next, which its Interest carries: a full table, a key the session cannot hold or no id
        // left refuses it before anything is asked, and the sink goes with the refusal. The row
        // holds the key expression declaration its Interest names the key by for as long as it
        // stands.
        let next = tables(&core.session.registry).next_entity_id();
        let Some(id) = next else {
            drop(guard);
            drop(wire);
            return Err(Declined::NoEntityId);
        };
        let form = core
            .session
            .key_form(wire.declared(), Retraction::ById)
            .owning(tables(&core.session.registry).keyexpr_by_id(wire.own_declaration()));
        let declared = tables_mut(&mut core.session.registry).declare_liveliness_subscriber(
            keyexpr,
            history,
            form,
            LivelinessRow::new(wire.into_anchor(), sink),
        );
        let declared = match declared {
            Ok(declared) => declared,
            Err(refused) => {
                // The program's callback goes with the refusal, let go of with no lock held, and
                // what the key kept with it.
                drop(guard);
                let why = Declined::from(refused.why);
                drop(refused.callback);
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
        self.deliver();
        Ok(id)
    }
}

/// The places the session's arena laid out at its open for the ABI's objects of its entities
/// ([`HeldPlaces::with_entity`]), one for each row the session keeps of a kind, lent and given
/// back under the session's lock, as every table of its arena is.
impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> PlaceLender for CoopEngine<L, C> {
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

    /// Closed or not, with no lock of the session taken: a place's mark is its own, and the
    /// arena's memory is kept by each place lent until its value's last count lets it go.
    fn lend_lodging(&self, layout: core::alloc::Layout) -> Option<wz_capi_port::lodge::LentBytes> {
        self.lodgings.lend(layout)
    }
}

/// The ring the session's arena laid out at its open for its advanced publishers' caches
/// (`CacheSpan`), lent under a lock of its own: a cache's put and its queryable's answer take
/// it, from whatever thread, and neither takes the session's lock with it.
#[cfg(feature = "advanced-cache")]
impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> wz_capi_port::CacheBytes
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
impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> SessionKeys for CoopEngine<L, C> {
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

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> SessionDrive for CoopEngine<L, C> {
    fn zid(&self) -> [u8; 16] {
        SessionEngine::zid(self)
    }

    fn close(&self) {
        // The read task stops first, so the close is the last thing the session does. A close
        // from the read task itself stops nothing and leaves the thread to see the session
        // closed.
        #[cfg(feature = "threads")]
        let _ = self.stop_reader();
        let mut guard = self.core.lock();
        self.closed.store(true, Ordering::Release);
        // A session a step ended is closed already, and still holds its row and its links: the
        // close lets them go all the same, whoever said the session closed first.
        if core::mem::replace(&mut guard.0.released, true) {
            return;
        }
        // No handle reaches the session from here on: a key, a query or a token kept past the
        // close finds it closed whatever still holds the engine.
        self.reach.clear();
        let core = &mut guard.0;
        core.end_links();
        // The rows of the session's own declarations, and the callbacks they hold, go after the
        // lock is let go of, one row at a time (`Self::let_go_of_rows`).
        // A get still pending ends with its session: its entry goes here, its leg's callback with
        // the table.
        #[cfg(feature = "query")]
        {
            let registry = CoopSession::faces_mut(&mut core.session.registry);
            while let Some(pending) = core.session.pending_gets.pop() {
                pending.unregister(&mut *registry);
            }
        }
        // The session's tokens end with its link: the rows of its tables go, each with its hold of the
        // declaration its key is named by.
        #[cfg(feature = "liveliness")]
        {
            let tables = tables_mut(&mut core.session.registry);
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
        // The one link's session goes once no read steps it: here, or at the end of the read
        // whose callback closed the session (`direct`).
        #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
        self.let_go_link();
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
        #[cfg(wz_round)]
        self.samples.discard();
        #[cfg(wz_round)]
        self.let_go_of_released();
        self.let_go_of_rows();
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    #[cfg(feature = "threads")]
    fn start_read_task(&self) -> Result<(), ReadTaskStartRefused> {
        self.start_reader(|body| os::spawn(move || body.run()))
    }

    // A build of one thread starts none: its rows count their calls for that thread alone
    // (`CoopForm`), and a read task would end them on another.
    #[cfg(not(feature = "threads"))]
    fn start_read_task(&self) -> Result<(), ReadTaskStartRefused> {
        Err(ReadTaskStartRefused::NoThread)
    }

    #[cfg(feature = "threads")]
    fn stop_read_task(&self) -> Result<(), CalledFromReadTask> {
        self.stop_reader()
    }

    #[cfg(not(feature = "threads"))]
    fn stop_read_task(&self) -> Result<(), CalledFromReadTask> {
        Ok(())
    }

    #[cfg(feature = "threads")]
    fn read_task_is_running(&self) -> bool {
        lock(&self.reader)
            .as_ref()
            .is_some_and(|task| !task.thread.is_finished())
    }

    #[cfg(not(feature = "threads"))]
    fn read_task_is_running(&self) -> bool {
        false
    }

    // The read steps the one link itself (`direct`).
    #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
    fn read(&self, _single: bool) -> Result<(), SessionClosed> {
        self.read_direct()
    }

    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    fn read(&self, _single: bool) -> Result<(), SessionClosed> {
        // The wait comes first and holds nothing of the session, so what arrives during it is
        // read by this call and a publisher on another thread is not held up by it. Input the last
        // step left held makes it none, which it is then without the session taken to say so:
        // under a stream of batches each read takes the session once, for its step.
        // A read behind another's wait counts itself in under the session's lock, which the
        // hand-back it waits for is made under too. Without a read task the program's reads are
        // one at a time, so none is ever behind another.
        #[cfg(feature = "threads")]
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
                #[cfg(feature = "threads")]
                if matches!(wait, IdleWait::Behind(_)) {
                    seen = Some(self.hand_back.enter());
                }
                wait
            })
        };
        #[cfg(test)]
        self.takes.wait(&wait);
        #[cfg(feature = "threads")]
        match (&wait, seen) {
            (IdleWait::Behind(ms), Some(seen)) => self.hand_back.wait(seen, *ms),
            _ => wait.wait(self.rooms.waits(), sleep_ms),
        }
        #[cfg(not(feature = "threads"))]
        wait.wait(self.rooms.waits(), sleep_ms);
        // One pass of the session's task reads what its link holds, a batch at a time, and does
        // what is due: `single` asks for one message, and a pass is the least this engine reads.
        let (mut stepped, mut jobs_due_ms) = self.step_after(wait);
        let mut handed = self.deliver();
        // A step that read part of what a link took from its stack moved nothing (`Stepped::Read`):
        // the read goes on with the rest, each part read once the callbacks of the one before
        // returned, until the step that reads the last of it moves the links and finds the jobs
        // due. One thread: the round took one record of what the links hold (`Round::has_room`),
        // so the read goes on as well while the links hold input and a step hands something out.
        while stepped == Stepped::Read
            || (!<CoopForm as ThreadForm>::OTHER_THREADS
                && handed
                && stepped != Stepped::Closed
                && self.input_held.load(Ordering::Relaxed))
        {
            let (next, due) = self.step_after(IdleWait::None);
            stepped = next;
            jobs_due_ms = jobs_due_ms.or(due);
            handed = self.deliver();
        }
        if let Some(started_ms) = jobs_due_ms {
            self.run_due_tickers(started_ms);
        }
        if stepped == Stepped::Closed {
            Err(SessionClosed)
        } else {
            Ok(())
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
impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> FanCanceller for CoopEngine<L, C> {
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
                pending.unregister(CoopSession::faces_mut(&mut core.session.registry));
                Some(pending.leg)
            });
            let Some(leg) = leg else {
                break;
            };
            self.end_leg_now(leg);
        }
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
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
        given: Option<(KeyexprRef, PlainPutParams)>,
    ) -> FilteredPut {
        let Some(core) = self.live() else {
            return FilteredPut::Sent(Ok(0));
        };
        let core = &core.0;
        // The registry itself, not its holder: the filter reads it as what the peers declare.
        let registry: &Registry = &core.session.registry;
        // The filter's row is looked up once, for its plan, its answer and the plain way it keeps.
        let row = row_of(filter).and_then(|handle| tables(registry).write_filters().get(handle));
        // A write that brings nothing of its own, at the send epoch its way was planned at, is
        // sent as planned: what the filter's answer, the key's naming and each link's form of it
        // are read from is as it was then. A group the session joined since is sent it the
        // general way, which no epoch counts.
        let epoch = core.send_epoch();
        #[cfg(feature = "group")]
        let groups_left = core.transport.groups.is_empty();
        #[cfg(not(feature = "group"))]
        let groups_left = true;
        if given.is_none() && groups_left {
            if let Some(planned) = row.and_then(|row| row.planned_put(epoch)) {
                return self.put_planned(core, &planned, payload);
            }
        }
        if !Self::filters_left_unasked(core)
            && row.is_some_and(|row| !tables(registry).write_filter_row_open(row, registry))
        {
            return FilteredPut::Suppressed;
        }
        let planning = given.is_none();
        // The plain way a publisher's declare stated carries the Put's head it wrote then. A way
        // the caller gives is written from that head too, on each link where the head names the
        // way's key and carries its QoS, which the send checks, and from its parts elsewhere.
        let (key, params, head) = match given {
            Some((key, params)) => (
                key,
                params,
                row.and_then(|row| row.plain()).and_then(|way| way.head),
            ),
            // Each link is sent the key as its own form names it (`key_on_link`), and the head
            // only where that is the head's declaration alone.
            None => {
                let Some(way) = row.and_then(|row| row.plain()) else {
                    return FilteredPut::NotPlain;
                };
                (way.key, way.params, way.head)
            }
        };
        let sent = self.put_plain_in(core, keyexpr, key, payload, &params, head);
        // The row's own way, sent plain to the peers of a filter that counts subscribers, is
        // planned at this epoch when every link names the filter's key as the session does, by
        // the head's declaration alone: the epoch counts the session's own subscribers, the
        // queryables none, and a way kept from the peers sends nothing a plan could.
        if let (true, Some(row), FilteredPut::Sent(_)) = (planning, row, sent) {
            if row.plane() == Plane::Subscribers && params.destination.allows_remote() {
                if let Some(named) = tables(registry).named_at(row.key(), key) {
                    if core
                        .transport
                        .ups()
                        .all(|actions| key_on_link(actions, named).wire() == named.wire())
                    {
                        row.keep_plan(epoch, named);
                    }
                }
            }
        }
        sent
    }

    /// The session `engine` holds as the C handle's drive: one of the engine's holders, so the
    /// open makes nothing more for it.
    pub fn into_drive(engine: EngineHold<Self>) -> CoopDrive<L, C> {
        let handle_place = engine.handle_place;
        CoopDrive {
            engine,
            handle_place,
        }
    }
}

/// The C handle's hold on a session of this engine, kept by value in the handle: the engine is
/// shared with the entities declared on it and with its read task, so the handle holds one of its
/// holders ([`EngineHold`]). Its operations are the port's [`SessionDrive`] of this engine, called by name, so an
/// ABI built over one kind of links reaches its session through no table of functions, and the
/// engine it hands out is the engine's own type.
pub struct CoopDrive<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> {
    engine: EngineHold<CoopEngine<L, C>>,
    handle_place: Option<HandlePlace>,
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> CoopDrive<L, C> {
    /// The engine the session's entities keep.
    pub fn engine(&self) -> EngineHold<CoopEngine<L, C>> {
        self.engine.clone()
    }

    /// The engine, borrowed for the length of one call.
    pub fn engine_ref(&self) -> &CoopEngine<L, C> {
        &self.engine
    }

    /// The session's own hold of the engine, borrowed for the length of one call: a caller that
    /// keeps the engine clones it where it keeps it, and one that only reaches it counts nothing.
    pub fn engine_hold(&self) -> &EngineHold<CoopEngine<L, C>> {
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

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> Drop for CoopDrive<L, C> {
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

impl<U, D, L, G, N: wz_runtime_coop::link_cells::CountKind> ComposedLinks
    for wz_runtime_coop::ip_stack::IpLinks<U, D, L, G, N>
{
    type WithTls<S> = wz_runtime_coop::ip_stack::IpLinks<U, D, S, G, N>;
    type WithGroups<J> = wz_runtime_coop::ip_stack::IpLinks<U, D, L, J, N>;
}

#[cfg(all(
    feature = "queryable",
    any(feature = "threads", feature = "listen", feature = "group")
))]
impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static>
    crate::round::AnswersQueries<crate::calls::CoopCalls> for CoopEngine<L, C>
{
    fn answer_query(&self, call: &QueryableCall, query: &dyn QueryView, generation: u64) {
        self.run_queryable(call, query, generation);
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> Drop for CoopEngine<L, C> {
    fn drop(&mut self) {
        // No handle reaches the engine once its last holder let go: its row is vacated before its
        // place is given back, which a session never closed has not done yet.
        self.reach.clear();
        // The one link's session holds handles of the state's cells: it goes first (`direct`).
        #[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
        self.direct.let_go_owned();
        // The round names this engine to answer its queries: no longer, before anything of the
        // engine goes (`Round::answer_queries_with`).
        #[cfg(all(
            feature = "queryable",
            any(feature = "threads", feature = "listen", feature = "group")
        ))]
        self.samples.answer_no_queries();
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
        #[cfg(wz_round)]
        // SAFETY: the last handle is gone, so no delivery runs or starts.
        unsafe {
            self.samples.let_go()
        };
        // The legs' rows and ends lie in the arena too. A session never closed still holds the
        // entries of its pending gets: they go first, each saying its end, and the plane lets go
        // of the ends and the rows after, the callbacks still held among them.
        #[cfg(feature = "query")]
        {
            let core = self.core.dropping();
            let registry = CoopSession::faces_mut(&mut core.session.registry);
            while let Some(pending) = core.session.pending_gets.pop() {
                pending.unregister(&mut *registry);
            }
            self.gets.let_go();
        }
        // The held Finals' rows lie in the arena too; the round's calls were ended above.
        #[cfg(feature = "queryable")]
        self.plane.let_go();
        // No task of the session outlives it, though a handle of its set is kept past it (by one
        // of its own tasks, say): each goes here, before `Core`'s fields, what its tasks borrow
        // among them, as the set's last handle would drop them.
        self.core.dropping().local.drop_tasks();
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

#[cfg(all(test, feature = "std", feature = "threads"))]
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

#[cfg(test)]
mod sending_on_tests {
    //! The mark of who holds the session, as a publish and each of its sends make and let go of it.
    use super::{SendingOn, NOT_SENDING, PUBLISHING};
    use core::sync::atomic::Ordering;
    use portable_atomic::AtomicU64;

    /// A send inside a publish marks its face and puts the publish's mark back as it ends, and the
    /// publish puts back the mark it found: no send leaves its mark behind.
    ///
    /// # Control
    ///
    /// Keeping the new place as the mark to put back in `SendingOn::enter` reds the assertion
    /// made once the send has ended.
    #[test]
    fn a_send_puts_back_the_mark_it_found() {
        let mark = AtomicU64::new(NOT_SENDING);
        {
            let _publishing = SendingOn::enter(&mark, PUBLISHING);
            assert_eq!(mark.load(Ordering::Relaxed), PUBLISHING);
            {
                let _sending = SendingOn::enter(&mark, 3);
                assert_eq!(mark.load(Ordering::Relaxed), 3);
            }
            assert_eq!(
                mark.load(Ordering::Relaxed),
                PUBLISHING,
                "the send has ended"
            );
        }
        assert_eq!(mark.load(Ordering::Relaxed), NOT_SENDING);
    }
}
