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
#[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
use crate::arena::HandedTable;
#[cfg(feature = "runtime-plan")]
use crate::arena::OpenPlan;
// The place the arena lends the engine: none where the engine lies in an allocation of its own.
#[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
use crate::arena::EnginePlace;
use crate::arena::{
    ArenaMemory, ArenaPlan, ArenaRefused, ArenaRegion, ClaimedPlaces, DroppedOn, EntityKind,
    EntityPlace, EntityPlaces, HandlePlace, HeldPlaces, LinkCells, OpenPlaces, OpenRegion,
    OpenStorage, PlaceTables, PlanFrom, SessionArena, SessionRows, TransportTables,
};
use crate::form::{CoopForm, Latch};
use crate::form::{
    LinkCount, LockForm, SessionLock, SharedCount, StateGuard, StateLock, UnderCoreLock,
};
use crate::lodging::LodgingPlaces;
#[cfg(wz_round)]
use crate::round::RoundGate;
#[cfg(all(wz_round, feature = "runtime-plan"))]
use crate::round::RoundRows;
#[cfg(wz_round)]
use crate::round::{Round, RoundCounts};
use crate::RowPolicy;
use wz_runtime_coop::kept::Shared;
#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
use wz_runtime_coop::kept::{Kept, SharedClaim};
#[cfg(any(
    feature = "runtime-plan",
    all(not(wz_round), any(feature = "listen", feature = "group"))
))]
use wz_session_core::bounded::Arena;
#[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
use wz_session_core::bounded::KeyUnkept;
use wz_session_core::bounded::{LendRefused, TableLender};
use wz_session_core::caps;
#[cfg(all(feature = "liveliness", wz_round))]
use wz_session_core::key_arena::KeyRef;
#[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
use wz_session_core::key_arena::{KeySpace, KeysLocked};
use wz_session_core::placed::{Placed, PlacedRef};
#[cfg(not(wz_round))]
use wz_session_core::reassembly_dispatch::ChainPeers;
#[cfg(all(wz_round, feature = "listen"))]
use wz_session_core::reassembly_dispatch::ManyPeers;
#[cfg(not(all(wz_round, feature = "listen")))]
use wz_session_core::reassembly_dispatch::OnePeer;
#[cfg(all(feature = "query", feature = "runtime-plan"))]
use wz_session_core::reply_hold::HeldReplies;
use wz_session_core::round::RowReleases;
use wz_session_core::row_callback::{RowCallback, ThreadForm};
#[cfg(feature = "local-queryable")]
use wz_session_core::session_state::LocalRequests;
use wz_session_core::session_state::{MatchingRead, SessionParts};
use wz_session_core::session_tables::{
    kind, DeclaredRow, DeclaredTable, FilterInterest, InterestKind, InterestName, KeyexprHandle,
    KeyexprRef, MatchingListenerHandle, Plane, Refused, Retraction, RowCallbacks, RowKey,
    SessionTables, SubscriberHandle, Watching, WriteFilterHandle,
};
use wz_session_core::slot_map::Handle;
#[cfg(feature = "runtime-plan")]
use wz_session_core::slot_observer::ObserverRows;

// The operating system the engine runs on: its mutex, its threads and its sleep are `std`'s on a
// host and the kernel's on an MCU (`docs/upstream-parity.md` section 5a, E1).
#[cfg(all(feature = "listen", wz_round))]
use crate::admission_gate::AdmissionGate;
use wz_capi_port::os::{self, Mutex, MutexGuard};
#[cfg(feature = "threads")]
use wz_capi_port::os::{JoinHandle, ThreadId};
use wz_capi_port::{
    BatchStep, CalledFromReadTask, Declared, EngineDeliveries, FanoutError, FilterId, FilterPlane,
    FilteredPut, HoldRefused, KeyAnchor, KeyHold, KeyView, MatchId, MatchingSink, PeerIdentity,
    PlaceLender, ReadTaskStartRefused, SessionClosed, SessionDrive, SessionEngine,
    StatementNotHonoured, StepRefused, SubId, SubscriberSink, WireKey,
};
use wz_capi_port::{HeldKey, KeyAsk, KeyNotHeld, SessionKeys};
// The port's refusal of a declaration, named apart from this crate's refusal of an endpoint.
use wz_capi_port::Refusal as Declined;
#[cfg(feature = "ticker")]
use wz_capi_port::{Tick, TickerId};
use wz_runtime_coop::executor::SpawnRefusal;
use wz_runtime_coop::face_send::{self, Behind, FaceSend, Pass, PublishRun, Then, FIRST_FACE};
#[cfg(all(feature = "listen", feature = "tx-probe"))]
use wz_runtime_coop::face_send::{after_probe, AfterProbe, ProbeAnswer};
#[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
use wz_runtime_coop::face_send::{DropSet, HandedLimits};
#[cfg(wz_round)]
use wz_runtime_coop::faces::DialAnswer;
#[cfg(feature = "listen")]
use wz_runtime_coop::faces::OwingWaits;
// A face's link where the read steps the one link itself is a handle on the link's place, read
// through the trait alone; the session's own wire answers the same calls itself.
#[cfg(not(wz_round))]
use wz_runtime_coop::faces::FaceWire;
use wz_runtime_coop::faces::{
    DialEndpoint, EndpointTexts, FaceRecord, FaceSession, IdleWait, LendsSession, Link,
    LinkSupervisor, WaitRoom, DIAL_LOOK_MS,
};
use wz_runtime_coop::link_cells::CellRc;
use wz_runtime_coop::reassembly_rx::{session_reassembly, SessionChains};
#[cfg(wz_round)]
use wz_runtime_coop::session_drive::router_session_task_bytes;
#[cfg(feature = "time-base")]
use wz_runtime_coop::session_drive::LinkWait;
#[cfg(feature = "time-base")]
use wz_runtime_coop::session_drive::StackWake;
use wz_runtime_coop::session_drive::{LinkWaits, WaitOn};
use wz_runtime_coop::session_drive::{OpenedLink, SessionDatagramLink, SessionLinks, SessionRole};
use wz_runtime_coop::session_runtime::{SessionEntropy, SessionHandle};
use wz_runtime_coop::sync::Lend;
pub use wz_runtime_coop::transport::{EndpointRefusal, Refusal};
use wz_runtime_coop::transport::{
    LinkCalls, TransportFaces, TransportRefusal, TransportSession, WireMaking,
};
use wz_runtime_coop::{
    ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeForm, RuntimePlace, RuntimeRows,
};
#[cfg(any(
    all(test, feature = "std"),
    feature = "advanced-cache",
    all(not(wz_round), feature = "listen")
))]
use wz_session_core::byte_cells::LentByteCells;
use wz_session_core::close_reason::CloseReason;
use wz_session_core::declare_form::{InterestAsk, InterestForm, RetractionKey};
use wz_session_core::driver_loop::{EventSink, IterationEvent};
use wz_session_core::entropy::EntropySource;
use wz_session_core::interest_build::InterestKinds;
use wz_session_core::lent_push;
use wz_session_core::limits::SessionLimits;
#[cfg(feature = "link-admission")]
use wz_session_core::link_admission::{LinkAdmission, LinkBook, LinkRegistry};
#[cfg(wz_round)]
use wz_session_core::link_life::{Effects, LinkInput, LinkPhase, Refused as HandshakeRefusal};
use wz_session_core::link_life::{LinkRole, LinkTimes, UnicastLink};
use wz_session_core::locality::Locality;

use crate::open_source::{Counted, EndpointList, OpenInput, OpenSource};
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
#[cfg(all(feature = "listen", feature = "tx-probe"))]
use wz_session_core::session_actions::Probed;
use wz_session_core::session_actions::{LinkState, SessionCore, SessionLinkActions};
use wz_session_core::session_init_params::{
    CookieKey, HeldDrop, KeepAliveConf, LinkRxConf, SessionInitParams, SessionZid, TxQueueConf,
    ZidError, ZID_MAX,
};
use wz_session_core::session_timeouts::SessionTimeouts;
#[cfg(feature = "shared-key-ids")]
use wz_session_core::shared_key_ids::{KeyIdsAtOpen, KeyIdsRefused, LinkKeyForms, SharedKeyIds};
// The round's sample delivery reads a row through it, as do the liveliness and queryable rows'
// deliveries in every build.
#[cfg(any(wz_round, feature = "liveliness", feature = "queryable"))]
use wz_session_core::sink::RowAccess;
use wz_session_core::sink::SampleRef;
#[cfg(wz_round)]
use wz_session_core::sink::{FanOut, SampleDelivery, SampleView};
use wz_session_core::sn::sn_resolution_admitted;
use wz_session_core::step_lend::LendCell;
#[cfg(wz_round)]
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
pub(crate) use query::QueryableCall;
// Read where a state lends the Finals and refusals their rows (`state_places`, `arena`): the
// forms a build lays out at the open. The on-use form counts them in its own tables.
#[cfg(all(
    feature = "queryable",
    not(all(feature = "tables-on-use", not(feature = "runtime-plan")))
))]
pub(crate) use query::{FinalHold, RefusedFinal};

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
#[cfg(any(feature = "engine-rows", test))]
pub use hold::EngineHandle;
pub use hold::EngineHold;
// The process's table of engines, in a build with a reader of it (`engine-rows`) and in the tests,
// which read it: without it the open claims no row and the engine keeps no reach of one.
#[cfg(any(feature = "engine-rows", test))]
mod reach;
#[cfg(any(feature = "engine-rows", test))]
use reach::ReachEngine;
#[cfg(any(feature = "engine-rows", test))]
pub use reach::{RowClaim, RowsRefused};

mod ledger;
use ledger::{Due, Ledger, Seen};

// A build without a read task, or whose read task reaches each value under a lock of its own
// (`build.rs`): the read steps each face's link session itself (`direct`).
#[cfg(not(wz_round))]
mod direct;
// The delivery of a lent Push such a read makes, one subscriber at a time (`pinned`).
#[cfg(not(wz_round))]
mod pinned;
#[cfg(all(feature = "query", not(wz_round)))]
mod replies;
// The delivery of a peer's query such a read makes, one queryable at a time (`queries`).
#[cfg(all(feature = "queryable", not(wz_round)))]
mod queries;

mod registry;
#[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
use crate::region::RegionField;
#[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
use crate::region::{RegionBlock, StateRegion};
#[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
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
#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
use state_places::{OwnBlock, OwnPlaced, OwnState};

/// The state the places of the session's own values and the store of its keys lie in where the
/// open lends neither from its arena: the region at the head of the arena's block where the build
/// fixes the session's shape, which holds the registry too, or a state of the session's own the
/// allocator gives where its tables take their memory on use.
#[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
type StateLayout = StateRegion;
/// See the form of a build without `tables-on-use`.
#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
type StateLayout = OwnState;
/// What holds that state and drops it in place after every owner written in it: the region's
/// block, whose memory its arena gives back, or the state's own allocation, which it gives back.
#[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
type StateHold = RegionBlock<StateRegion>;
/// See the form of a build without `tables-on-use`.
#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
type StateHold = OwnBlock<OwnState>;

/// How the session's state holds its registry: by value where the open lent its tables from the
/// arena or where they take their memory at their first row, and by the handle of the field of the
/// session's region where the build laid it out (`crate::region`), which drops it in place.
#[cfg(any(feature = "runtime-plan", feature = "tables-on-use"))]
type RegistryHold = Registry;
#[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
type RegistryHold = RegionField<Registry>;

/// The store the rows of the session's tables keep their keys in, as the session's state holds it
/// (`SessionParts::Keys`): the session's key arena, where the tables take their memory at the open.
#[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
type KeyStore = KeySpace;
/// See the form of a build without `tables-on-use`: the handle of the session's key budget, which
/// its own state holds, where the tables take their memory at their first row.
#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
type KeyStore = wz_session_core::on_use::BudgetKeys;

mod replay;
use replay::{Replay, Retract, SendTo, TurnEnd};

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
    wz_round
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
use wz_session_core::face::FaceRowSink;
#[cfg(feature = "connectivity")]
use wz_session_core::face::{
    FaceEventKind, FaceEventSink, FaceLinkRow, FaceSnapshot, LinkFacts, LinkSnapshot,
};
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
    /// The node's own IPv4 address as the config states it (`zext/owned-address`), which heads a
    /// zid `zid-derivation = address-ports` derives in place of the address of a listener, so
    /// that a session that only dials derives one. `None` for a config that states none.
    pub owned_address: Option<[u8; 4]>,
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
    /// Whether a link that comes up to a remote this session meets as the peer hat's two
    /// north-bound peers is ended, once the replay of the session's declarations has told it
    /// everything, with the `DeclareFinal` of the initial interest
    /// (`wz_session_core::extbound::sends_initial_interest_final`): what a zenoh peer's open
    /// waits for before it returns. The tokio engine's `OpenStance::initial_interest`, chosen by
    /// the calling ABI for both engines alike; any other pair is sent none either way. The Final
    /// is the answer to the Interest the peer hat acts as if the face had sent, which a build that
    /// listens sends whether or not it answers its peers' Interests (`interest-answer`), as
    /// zenoh-pico's peer ends its push to a new peer with it; a build that does neither, a client
    /// that only dials, sends it to no face whatever this says.
    pub initial_interest: bool,
}

impl CoopConfig {
    /// The config in a source's form, its lists counted, and the lists, the host's texts.
    pub(crate) fn counted(self) -> (CoopConfig<Counted>, Vec<String>, Vec<String>) {
        let Self {
            endpoints,
            whatami,
            zid,
            owned_address,
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
            initial_interest,
        } = self;
        let config = CoopConfig {
            endpoints: Counted::of(endpoints.iter().map(String::as_str)),
            whatami,
            zid,
            owned_address,
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
            listen: Counted::of(listen.iter().map(String::as_str)),
            accept_pending,
            max_faces,
            groups,
            clock_moves,
            limits,
            initial_interest,
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
/// values, not a zenoh document with a `zext` member, and it has no field for a policy yet; the
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
    /// The session states no zid and its `zid-derivation` is `address-ports`, and neither its
    /// config (`zext/owned-address`) nor its `listen` endpoints give the node an address a zid can
    /// be built on.
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
    /// No row of the process's table of engines was left for the session's engine (`RowClaim`, in
    /// a build that keeps the table, `engine-rows`): on the fixed storage policy every row (the
    /// build's `ENGINE_ROWS`) holds the engine of a session open now, on the heap policy the heap had
    /// no room for one more row, and on either the table is held to a count of sessions every one of
    /// which is open (`RowClaim::hold_to`). Nothing was reserved, bound, joined or dialled. A build
    /// without the table never answers it.
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

/// The refusal of an open whose arena had no room for a table or a place it lends, as the lend
/// gave it. Out of line and cold, so each step of the open that may be refused so hands its lend's
/// refusal here and builds no value of the open's refusal in line.
#[cold]
#[inline(never)]
pub(crate) fn lend_refused(refused: LendRefused) -> OpenError {
    OpenError::Arena(ArenaRefused::Lend(refused))
}

/// The refusal of an open that had no room left for `asked` bytes it would hold for the session
/// (the runtime's span, the waits a read gathers), built as `lend_refused` builds it.
#[cold]
#[inline(never)]
pub(crate) fn lend_exhausted(asked: usize) -> OpenError {
    lend_refused(LendRefused::Exhausted {
        asked: Some(asked),
        left: 0,
    })
}

/// The refusal of an open whose heap had no room for `bytes` it takes there (the entropy's cell,
/// the admission's rows, the ports' book, and the engine's own allocation where the tables take
/// their memory on use). Out of line and cold, as `lend_refused` is.
#[cold]
#[inline(never)]
pub(crate) fn heap_refused(bytes: usize) -> OpenError {
    OpenError::Arena(ArenaRefused::NoMemory { bytes })
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
/// publishers' caches, which the engine locks apart from the state. The read slots of the faces
/// past the dial role's are handed beside it ([`CoopEngine::engine_of`]): they are the only part
/// of the type of the links, and a build that takes no such face names none.
struct LentApart {
    /// The Router of the dial role's link, which the read steps itself (`direct`).
    #[cfg(not(wz_round))]
    router: SessionReassembly,
    /// The place the engine is written at.
    #[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
    engine: EnginePlace,
    /// The count of the arena's memory the engine keeps, where it lies in an allocation of its own
    /// (`SharedClaim`).
    #[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
    engine: NonNull<Kept>,
    handle_place: Option<HandlePlace>,
    lodgings: LodgingPlaces,
    #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
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
    /// The rows of the faces past the dial role's the plan laid out for their read slots and send
    /// places (`ArenaPlan::lay_direct_faces`), which the open lends and makes.
    #[cfg(all(not(wz_round), feature = "listen"))]
    taken_faces: usize,
    keys: KeyStore,
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
    #[cfg(feature = "link-admission")]
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
    #[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
    engine: EnginePlace,
    /// The count of the arena the session's engine keeps, where the engine lies in an allocation of
    /// its own (`SharedClaim`) and the arena lends it no place.
    #[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
    engine: NonNull<Kept>,
    /// The state the places of the session's own values and its keys lie in (`StateHold`): the
    /// region, which holds the registry too, or the session's own state where the tables take
    /// their memory on use. After the registry, which its handle drops in place where it lies in the
    /// region, and every table that keeps a key there.
    #[cfg(not(feature = "runtime-plan"))]
    state: StateHold,
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
    held_finals: query::HeldFinals<wz_session_core::bounded::Lent>,
    #[cfg(all(feature = "queryable", feature = "runtime-plan"))]
    refused_finals: query::RefusedFinals<wz_session_core::bounded::Lent>,
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

/// Lay out the plan of the session opened with `config` under `policy` from `from`: a region's
/// rows taken whole, or the config's rows and after them those its holds name (`lay_out_open`);
/// then reserve its arena in `memory` and lend from it every table of the session. One lender
/// lends each layer its plain tables from the rows the plan counts for it: the transport's links, cells, reassembly and
/// endpoints, the state's lane, declarations, keys and legs, and the ABI's places; it gives the
/// tables after a refusal no rows and is asked once, after them all. The round's tables and the application's, which their makers lend, ask their own. What
/// was lent before a refusal goes back with the arena. Out of line and generic over nothing: one
/// body for every stack and source the open is made over. The plan is made and read here, so the
/// open's frame never holds or moves it: what the state is sized by is handed back with the tables.
#[inline(never)]
fn lend_session(
    from: &OpenFrom<'_>,
    memory: &'static dyn ArenaMemory,
    config: &CoopConfig<Counted>,
    policy: &SessionPolicy,
) -> Result<SessionLent, ArenaRefused> {
    #[cfg(feature = "runtime-plan")]
    let mut plan = OpenPlan::blank();
    #[cfg(not(feature = "runtime-plan"))]
    let mut plan = ArenaPlan::vacant();
    match from {
        OpenFrom::Region(region) => region.rows().lay_out_on(&mut plan, config)?,
        #[cfg(any(feature = "runtime-plan", test))]
        OpenFrom::Config(holds) => {
            plan.count(config, resolve_limits(config))?;
            lay_out_open(&mut plan, holds)?;
        }
    }
    let OpenPlaces {
        runtime: runtime_bytes,
        #[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
            engine: engine_bytes,
        // The engine lies in an allocation of its own the open claimed (`SharedClaim`).
        #[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
            engine: _,
    } = from.places();
    #[cfg(any(feature = "runtime-plan", feature = "tables-on-use"))]
    let mut arena = SessionArena::reserve(&plan, memory)?;
    // The registry and the key arena lie in the region the build lays out, the head of the one
    // block the open reserves, zeroed, the arena of what it sizes at run time after it: the
    // session's tables are the region's fields, placed over their rows by one walk.
    #[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
    let (mut arena, state) = SessionArena::reserve_after::<StateRegion>(&plan, memory)?;
    // SAFETY: the head is a zeroed `StateRegion` this open alone reaches; the arena gives the
    // block back only after its last holder, and the region's block is dropped before the arena
    // wherever both are held (here, being made after it, then `SessionLent` and `Core`, whose
    // arena is their last field).
    #[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
    let state = unsafe { RegionBlock::<StateRegion>::within(state) };
    // Where the tables take their memory on use, the places of the state's own values and the key
    // budget lie in a state of the session's own, zeroed by the allocator apart from the arena;
    // a refusal here gives the arena back.
    #[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
    let state = OwnBlock::<OwnState>::take()?;
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
    // SAFETY: the block is a zeroed state (`StateLayout`) this open alone reaches; it neither moves
    // nor goes back before the registry and every key of it are let go of, being held after them
    // by what this hands back and then by the session's state.
    #[cfg(not(feature = "runtime-plan"))]
    let keys = unsafe { StateLayout::place(state.as_ptr(), resolve_limits(config)) };
    // The plane, the round, the step places, the queryables' plane and the plain tables' rows lie
    // in the region where the build fixes the session's shape, each in a field of it no other owner
    // reaches; where its tables take their memory on use, the same values lie in the session's own
    // state, and the plain tables and the round's take their rows at their first row instead.
    // SAFETY: the state was placed above, and nothing reaches its places' fields but this open,
    // which writes each once; the block is held after every owner written in it (`SessionLent`,
    // then `Core`), and neither moves nor goes back before them.
    #[cfg(not(feature = "runtime-plan"))]
    let region_places = unsafe { StateLayout::places_at(state.as_ptr()) };
    // SAFETY: as above, for the plain tables' fields: each table is held by the plane or the
    // state it is moved into, both dropped before the block.
    #[cfg(all(
        any(feature = "query", feature = "queryable"),
        not(any(feature = "runtime-plan", feature = "tables-on-use"))
    ))]
    let tables = unsafe { StatePlaces::tables(region_places, plan.session()) };
    // Where the tables take their memory on use, each plain table is counted as the plan counts
    // its rows and takes them at its first row, none of them in the state.
    #[cfg(all(
        any(feature = "query", feature = "queryable"),
        feature = "tables-on-use",
        not(feature = "runtime-plan")
    ))]
    let tables = PlacedTables::counted(plan.session());
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
    } = tables;
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
    let router: SessionReassembly = session_reassembly(
        policy,
        SessionChains::over(&transport.reassembly, transport.face_chains),
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
        // A key a peer's alias keeps in the key arena is read where it lies; a key of the on-use
        // policy is its row's own allocation, which the round copies, as it copies every key it is
        // not told the place of.
        #[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
        round.reads_keys_in(keys);
        #[cfg(all(
            feature = "tables-on-use",
            not(feature = "runtime-plan"),
            not(feature = "query")
        ))]
        let _ = round;
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
    #[cfg(wz_round)]
    let lane = unsafe { samples.share() };
    // SAFETY: the delivery is held by the registry, dropped before the plane wherever both are
    // held: here, where the registry is made after it, and in `SessionLent` and the session's
    // state, which hold the plane in a field after the registry's.
    #[cfg(feature = "queryable")]
    let asked = unsafe { plane.share() };
    let delivery = RoundDelivery {
        #[cfg(wz_round)]
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
    #[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
    let registry = unsafe {
        RegistryRegion::bind(
            StateRegion::registry_at(state.as_ptr()),
            resolve_limits(config),
            &plan.tables(),
            delivery,
        )
    }
    .map_err(ArenaRefused::Lend)?;
    // The application's tables and the dial face's, made by value and counted from the rows the
    // plan counts for them, none taking a row before its first, their keys counted against the
    // region's budget; the session's one table set holds its tokens as rows, as above.
    #[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
    let registry = Registry::counted(
        resolve_limits(config),
        keys,
        plan.tables(),
        plan.gets().rows,
        plan.peers().rows,
        delivery,
    )?;
    let runtime = arena
        .runtime_place(runtime_bytes)
        .map_err(ArenaRefused::Lend)?;
    #[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
    let engine = arena
        .engine_place(engine_bytes)
        .map_err(ArenaRefused::Lend)?;
    #[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
    let memory = engine.memory;
    // An engine in an allocation of its own keeps the arena's memory by a count it takes of it, as
    // the place the arena would lend it does: what the engine holds that lies in the arena (the
    // lodgings, the handle's place) stands for as long as the engine does.
    #[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
    let engine = arena.keep().map_err(ArenaRefused::Lend)?;
    #[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
    let memory = engine;
    // SAFETY: the span was lent above to the lodging places alone, and `memory` is the count of the
    // memory it lies in, held by the session's engine for as long as the engine lends from the
    // places.
    let lodgings = unsafe { lodgings.kept_by(memory) };
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
        #[cfg(feature = "link-admission")]
        links: plan.links(),
        #[cfg(feature = "listen")]
        tx_pool_short: plan.tx_pool_short(),
        #[cfg(feature = "advanced-cache")]
        cache,
        #[cfg(not(feature = "runtime-plan"))]
        state,
        #[cfg(all(not(wz_round), feature = "listen"))]
        taken_faces: plan.peers().sets().saturating_sub(1),
        arena,
    })
}

/// The zid the session opened with `config` announces: the configured one, or one drawn from
/// `entropy`, or one derived from the node's own address the config states, the endpoints it
/// listens on (`endpoints`) and `entropy`, as `policy` says. Out of line and generic over
/// nothing, as [`lend_session`] is.
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
            config.owned_address,
            entropy,
        ),
    }
}

/// The zid `zid` spells, up to its last non-zero byte as zenoh writes an id, refused as
/// [`SessionZid::new`] refuses the bytes as given: when they are not one to sixteen or are all
/// zero. Out of line: the configured zid ([`wire_form`]), a drawn one and a derived one are each
/// put in their wire form by this one body, so the walk and the copy are not repeated in each
/// arm of the open's zid.
#[inline(never)]
pub(crate) fn wire_zid(zid: &[u8]) -> Result<SessionZid, OpenError> {
    let len = zid.len();
    if len > ZID_MAX {
        return Err(OpenError::InvalidZid(ZidError::LengthOutOfRange { len }));
    }
    // Bytes with no non-zero one are kept whole, so they are refused with their own length.
    let kept = zid
        .iter()
        .rposition(|byte| *byte != 0)
        .and_then(|last| zid.get(..=last))
        .unwrap_or(zid);
    SessionZid::new(kept).map_err(OpenError::InvalidZid)
}

/// `zid` up to its last non-zero byte, as zenoh writes an id ([`wire_zid`]). A zid is one to
/// sixteen bytes with a non-zero byte, so what is kept is a zid as well and the fallback to `zid`
/// itself is never taken.
pub(crate) fn wire_form(zid: SessionZid) -> SessionZid {
    wire_zid(&zid).unwrap_or(zid)
}

/// Sixteen random bytes in their wire form; sixteen zero bytes, an id that names nothing, are
/// the refusal of a source that gave none.
pub(crate) fn fresh_zid(entropy: &mut dyn EntropySource) -> Result<SessionZid, OpenError> {
    let mut zid = [0u8; ZID_MAX];
    entropy
        .try_fill_bytes(&mut zid)
        .map_err(|_| OpenError::EntropyUnavailable)?;
    wire_zid(&zid).map_err(|_| OpenError::EntropyUnavailable)
}

/// The zid `zid-derivation = address-ports` derives from `owned`, the node's own address the
/// config states, the `listen` endpoints and eight bytes of `entropy` (see
/// `wz_session_core::zid_derivation`), in its wire form: the stated address heads it, else the
/// first listener that binds an address of the node's.
pub(crate) fn derived_zid<T: AsRef<str>>(
    listen: impl IntoIterator<Item = T>,
    owned: Option<[u8; 4]>,
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
        .derive(owned, random)
        .map_err(OpenError::ZidDerivation)?;
    wire_zid(&zid)
}

/// One session the program steps; see the module doc.
pub struct CoopEngine<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> {
    /// The session's faces as the read steps them, apart from the session's state, so that a
    /// callback a link's records reach takes the state while the link lends them
    /// (`direct`). Before `core`: dropped first, as a link's session holds handles of the
    /// state's cells.
    #[cfg(not(wz_round))]
    direct: direct::DirectFaces<L, C>,
    /// Whether the session's config names a group, each joined at the open or the open refused
    /// (`Core::join_groups`): a session that joined none hands a publish no groups' leg and
    /// steps no group at a read, so in a build with groups it costs what it costs in one without.
    #[cfg(all(not(wz_round), feature = "group"))]
    joins_groups: bool,
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
    /// no queue; nor does one that sends a publish to each face on that face's own hold
    /// (`direct`), where a leg dropped is dropped on its own face and the next face's leg tries
    /// the session again.
    #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
    handed: Mutex<HandedTable>,
    /// Whether `handed` holds a leg, written under its lock: a publish that reads it clear takes
    /// no lock for the queue, which is otherwise two lock round trips on every put of a stream for
    /// what is almost always nothing. A publish that reads it stale leaves the leg to the next
    /// holder, as one that took the queue a moment before the leg was handed does; a read step
    /// always looks under the lock ([`Self::send_handed_now`]).
    #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
    owed: AtomicBool,
    /// Whether the last read's step left a link holding input it had already taken from its stack
    /// (a batch behind the one it read, the rest of a datagram the lane had no room for), or a
    /// group with a datagram its next step reads: the next read steps at once, with no wait to
    /// work out under the session's lock, since that wait would be none. Written by the step, under
    /// the lock; a stale `true` costs one step that finds nothing, after which the read waits.
    #[cfg(wz_round)]
    input_held: AtomicBool,
    /// Where a read waits for another read to hand back the session's buffer of waits. Only a
    /// build with a read task beside the program's calls has two reads at once.
    #[cfg(all(feature = "threads", wz_round))]
    hand_back: HandBack,
    /// How many handed legs of each priority are held at most: as many as the session's queue
    /// holds batches of that priority (`TxQueueConf::sizes`), which is as many as a face whose
    /// queue were its own would take before a droppable message found no room on it.
    #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
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
    #[cfg(any(feature = "engine-rows", test))]
    reach: ReachEngine<Self>,
}

/// The bound of a read's wait for input that leaves the config's (`CoopConfig::idle_wait_ms`) the
/// only one: the read task's and `zp_read`'s, which the program bounds by no step of its own.
const NO_STEP_BOUND_MS: u32 = u32::MAX;

/// What a step of the session came to ([`CoopEngine::step`]).
#[cfg(wz_round)]
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
    #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
    pub(crate) handed: core::sync::atomic::AtomicUsize,
    /// The turns a droppable publish spun on a held session before it tried the session again.
    pub(crate) spins: core::sync::atomic::AtomicUsize,
    /// The reads whose wait was a wait on the input of the session's links and ports, which
    /// the step's read follows.
    pub(crate) polls: core::sync::atomic::AtomicUsize,
    /// The sends on a face marked as the session's holder's while they were made (`SendingOn`).
    pub(crate) face_marks: core::sync::atomic::AtomicUsize,
    /// The faces' send places a publish's walk of the faces tried or held for a leg (`direct`).
    #[cfg(wz_face_places)]
    pub(crate) place_tries: core::sync::atomic::AtomicUsize,
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
    #[cfg(not(wz_round))]
    pub(crate) pump_reads: core::sync::atomic::AtomicUsize,
    /// The received samples a walk handed to its subscribers one row at a time (`pinned`), each
    /// counted once however many rows it reached.
    #[cfg(not(wz_round))]
    pub(crate) pinned_samples: core::sync::atomic::AtomicUsize,
    /// Of the samples handed one row at a time, those read where their frame lies.
    #[cfg(not(wz_round))]
    pub(crate) pinned_lent: core::sync::atomic::AtomicUsize,
    /// The reads that found the one link holding input it had already taken from its stack, and
    /// so worked out no wait (`direct`).
    #[cfg(not(wz_round))]
    pub(crate) held_input_reads: core::sync::atomic::AtomicUsize,
    /// The turns of a face a read or the open made, each a look at the face's life and a step of
    /// its pump (`direct`).
    #[cfg(not(wz_round))]
    pub(crate) face_turns: core::sync::atomic::AtomicUsize,
    /// The turns of a face whose look held every face's send place for a turn of its replay
    /// (`direct`).
    #[cfg(not(wz_round))]
    pub(crate) replay_holds: core::sync::atomic::AtomicUsize,
    /// The deliveries entered (`CoopEngine::deliver`): a read enters one, after every face and
    /// group it stepped (`direct`).
    #[cfg(not(wz_round))]
    pub(crate) delivers: core::sync::atomic::AtomicUsize,
    /// Set by a test so that every read finds the one link holding input, whatever the link holds
    /// (`direct`): a stream that never lets the read wait, made without a peer that sends one.
    #[cfg(not(wz_round))]
    pub(crate) input_held: core::sync::atomic::AtomicBool,
    /// The peers' replies the read handed to the get each answers itself (`replies`).
    #[cfg(all(feature = "query", not(wz_round)))]
    pub(crate) pinned_replies: core::sync::atomic::AtomicUsize,
    /// The peers' queries the read handed to a queryable itself (`queries`), one for each
    /// queryable a query reached.
    #[cfg(all(feature = "queryable", not(wz_round)))]
    pub(crate) pinned_queries: core::sync::atomic::AtomicUsize,
    /// The turns of an answer that held their link's replies and let them go after the Final: from
    /// the first reply (`CoopEngine::answer`), or across the callbacks of a query the read hands
    /// out itself (`queries`).
    #[cfg(feature = "queryable")]
    pub(crate) held_answers: core::sync::atomic::AtomicUsize,
    /// The holds of key expression declarations the session handed out (declared or retained)
    /// less those given back, counted whether the session is open or closed: a hold given back to
    /// a closed session is still one given back, and one never given back stays counted.
    pub(crate) holds: core::sync::atomic::AtomicIsize,
    /// What a test runs once, on the read's thread, after a look that brought the one link up and
    /// before the replay's first lap: where an operation of another thread falls once the look
    /// lets go of the session's lock (`direct`).
    #[cfg(all(feature = "std", not(wz_round)))]
    pub(crate) after_bring_up: AfterBringUp,
}

/// A test's operation run between a link brought up and its first lap (`Takes::brought_up`).
#[cfg(all(test, feature = "std", not(wz_round)))]
pub(crate) type AfterBringUp = std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>;

#[cfg(test)]
impl Takes {
    /// Run, once, what a test set to run after a look that brought the one link up
    /// (`after_bring_up`); the hook is taken out before it runs, so nothing is held while it does.
    #[cfg(all(feature = "std", not(wz_round)))]
    fn brought_up(&self) {
        let hook = self
            .after_bring_up
            .lock()
            .ok()
            .and_then(|mut hook| hook.take());
        if let Some(hook) = hook {
            hook();
        }
    }

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
#[cfg(all(feature = "threads", wz_round))]
struct HandBack {
    /// The reads waiting here now: a hand-back with none takes no lock.
    behind: core::sync::atomic::AtomicUsize,
    /// How many times the buffer was handed back to a read waiting here, under the lock its wait
    /// is made with, so that a hand-back before the wait begins ends it at once.
    handed: Mutex<u64>,
    back: os::Condvar,
}

#[cfg(all(feature = "threads", wz_round))]
impl HandBack {
    /// A hand-back no read waits at, made in `at` with its lock and condition variable made where
    /// they stay: a kernel's objects are not moved once made, so neither is built by value.
    ///
    /// # Safety
    /// `at` is valid for writes of a `Self` and aligned for it, and what it held is overwritten
    /// without being dropped. The hand-back is not moved from `at` until it is dropped there.
    unsafe fn init_at(at: NonNull<Self>) {
        let at = at.as_ptr();
        // SAFETY: `at` is valid for writes of a `Self` that stays there (the caller's contract),
        // so each field is too, and each is written once.
        unsafe {
            addr_of_mut!((*at).behind).write(core::sync::atomic::AtomicUsize::new(0));
            os::mutex_in(
                NonNull::new_unchecked(addr_of_mut!((*at).handed)),
                |handed| handed.write(0),
            );
            os::condvar_in(NonNull::new_unchecked(addr_of_mut!((*at).back)));
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
/// session's key arena, or its key budget, that the lock is held for as long as it is
/// ([`KeySpace::guard_by_owner_lock`](wz_session_core::key_arena::KeySpace::guard_by_owner_lock)):
/// the counts of the session's keys are touched only under this lock, so a key let go of after the
/// lock (a row taken out of a table and dropped outside it) fails a debug build at once instead of
/// racing a reader that holds the lock.
struct CoreLock<L: CoopLinks + 'static, C: ClockSource + 'static>(StateLock<Confined<Core<L, C>>>);

impl<L: CoopLinks + 'static, C: ClockSource + 'static> CoreLock<L, C> {
    /// `core` behind the lock, made in `at` with the state written in the lock's own place, its
    /// key arena guarded by it from now on.
    ///
    /// # Safety
    /// As for [`LockForm::init_at`], of a `Self`.
    unsafe fn init_at(at: NonNull<Self>, core: Core<L, C>) {
        // Named by the address each hold marks its thread with (`Self::lock`): the lock lies here
        // from now on.
        core.session
            .keys
            .guard_by_owner_lock(at.as_ptr().cast_const().cast(), session_held_here);
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

    /// The state with no lock, the engine being let go of: the key arena is its owner's alone for
    /// the rest of the engine's drop, which drops every row that keeps a key on whichever thread
    /// let go of the engine last.
    fn dropping(&mut self) -> &mut Core<L, C> {
        let core = &mut <CoopForm as LockForm>::get_mut(&mut self.0).0;
        core.session.keys.owner_alone();
        core
    }
}

/// Whether the calling thread holds the session lock that lies at `lock`, as the key arena's check
/// asks it ([`KeySpace::guard_by_owner_lock`](wz_session_core::key_arena::KeySpace::guard_by_owner_lock)):
/// by the marks each hold leaves on its thread, and
/// `true` where they cannot tell, which leaves the arena's own mark to answer.
fn session_held_here(lock: *const ()) -> bool {
    wz_capi_port::sync::SessionHeld::held_on_this_thread(lock).unwrap_or(true)
}

/// A hold of [`CoreLock`]: the key arena is marked held from its taking to its drop.
struct CoreGuard<'a, L: CoopLinks + 'static, C: ClockSource + 'static> {
    guard: StateGuard<'a, Confined<Core<L, C>>>,
    // The thread's mark of the hold, which a debug build reads: a second take of this lock on
    // this thread, or a C ABI's place given back under it, fails there instead of waiting.
    _held: wz_capi_port::sync::SessionHeld,
    // A read waits for this lock inside its face's lend, so a face is only tried under it, never
    // waited on: the mark fails a debug build on such a wait (`FacePlace::lend`).
    _no_face_wait: wz_runtime_coop::sync::NoFaceWait,
}

impl<'a, L: CoopLinks + 'static, C: ClockSource + 'static> CoreGuard<'a, L, C> {
    /// The proof that this hold holds the lock that guards the session's key arena, for as long as
    /// the hold is borrowed: what a key an object of the C ABI holds apart is shared and let go of
    /// through, and nothing else makes one.
    #[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
    fn keys_locked(&self) -> KeysLocked<'_> {
        // SAFETY: this guard holds the session's lock from its taking to its drop, the lock that
        // guards the arena (`CoreLock::init_at`), and the proof borrows the guard.
        unsafe { KeysLocked::vouched(&self.guard.0.session.keys) }
    }

    fn taken(
        guard: StateGuard<'a, Confined<Core<L, C>>>,
        held: wz_capi_port::sync::SessionHeld,
    ) -> Self {
        guard.0.session.keys.owner_lock_taken();
        Self {
            guard,
            _held: held,
            _no_face_wait: wz_runtime_coop::sync::NoFaceWait::enter(),
        }
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

/// The bytes of the rooms of a session over links of `L`, which the open places in the session's
/// arena (`ArenaPlan::holding_rooms`): how large they are is the stack's waits'. A session whose
/// tables take their memory on use places them in an allocation of their own, and lays out none.
#[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
pub(crate) const fn link_rooms_bytes<L: CoopLinks>() -> usize {
    core::mem::size_of::<LinkRooms<L::Waits>>()
}

/// What the face at a place of the table of rooms names.
#[derive(Clone, Copy)]
pub(crate) struct RoomPlace {
    /// What a wait for the face's room waits on, which only the held-conduit wait asks.
    #[cfg(feature = "tx-held-wait")]
    on: WaitOn,
    /// The table's mark when the face took the place.
    #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
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
#[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
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
        #[cfg(not(feature = "tx-held-wait"))]
        let _ = on;
        if place.is_some() {
            #[cfg(feature = "tx-held-wait")]
            if let Some(held) = place.as_mut() {
                held.on = on;
            }
            return;
        }
        rooms.mark = mark;
        *place = Some(RoomPlace {
            #[cfg(feature = "tx-held-wait")]
            on,
            #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
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
    #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
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
    #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
    pub(crate) fn skips(&self, set: &DroppedOn, at: usize) -> bool {
        lock(&self.rooms)
            .places
            .get(at)
            .copied()
            .flatten()
            .is_some_and(|place| !set.owes(at, place.since))
    }

    /// What a droppable publish that found the session held is told, by the queue profile's
    /// `held_drop`: zenoh's asks the faces for room within `wait_us` (`Self::within`). Pico's
    /// asks nothing: on the face a send holds it is dropped at once ([`Room::Held`]), as pico's
    /// try-lock fails on a transmit lock another send holds; behind a publish between its sends it
    /// tries the session again ([`Room::Free`]); and behind a holder that is not a publish it waits
    /// for the session ([`Room::Stepping`]). Behind a read working out its wait both profiles try
    /// the session again, asking nothing.
    ///
    /// A leg that holds the send place of its one face, at place `leg`, answers for that face
    /// alone, as each of zenoh's transports drops on its own queue: zenoh's profile asks that
    /// face for room (`Self::within_face`), and pico's is dropped only behind a send on that
    /// face: a send on another face holds nothing of the leg's, and lets go of the session once
    /// that send is done, so the session is tried again, as behind a publish between its sends.
    ///
    /// A build without the held-conduit wait (`tx-held-wait`) answers every profile as pico's,
    /// and asks no face for room.
    pub(crate) fn for_held(
        &self,
        held_drop: HeldDrop,
        holder: Holder,
        wait_us: u64,
        leg: Option<usize>,
    ) -> Room {
        // Under either profile a read working out its wait waits on no face and lets go in a
        // moment, so no link is asked for room and nothing blocks on the session's lock.
        #[cfg(feature = "tx-held-wait")]
        if held_drop == HeldDrop::WaitForRoom && holder != Holder::Waiting {
            return match leg {
                Some(at) => self.within_face(at, wait_us),
                None => self.within(wait_us),
            };
        }
        #[cfg(not(feature = "tx-held-wait"))]
        let _ = (held_drop, wait_us);
        match holder {
            Holder::Waiting => Room::Free,
            Holder::Sending(face) => match leg {
                Some(at) if mark_of_place(at) != face => Room::Free,
                _ => Room::Held(face),
            },
            Holder::Publish => Room::Free,
            Holder::Step => Room::Stepping,
        }
    }

    /// What a droppable publish is told on the face at place `at`, whose send place another
    /// holder has while the publish holds nothing of the session: the place is held as a send on
    /// that face holds it, so the profile answers as behind such a send for a leg on that face
    /// alone ([`Self::for_held`]). Pico's is dropped on the face at once ([`Room::Held`]), as
    /// pico's try of that transport's transmit lock finds it taken; zenoh's asks that face alone
    /// for room within `wait_us`; and a build without the held-conduit wait (`tx-held-wait`)
    /// answers either profile as pico's, with no face asked. Asked by the read that steps each
    /// face itself (`direct`), which a build that keeps the round has not, where a face's send
    /// place is held apart from the session's lock: a build whose faces share that lock as their
    /// one place (`wz_one_send_place`) finds none held.
    #[cfg(not(any(wz_round, wz_one_send_place)))]
    pub(crate) fn for_held_place(&self, held_drop: HeldDrop, at: usize, wait_us: u64) -> Room {
        self.for_held(
            held_drop,
            Holder::Sending(mark_of_place(at)),
            wait_us,
            Some(at),
        )
    }

    /// The place `at` of the table, read under the lock, which goes before the caller waits on
    /// what it names: `None` past the table, and a free place as `Some(None)`.
    #[cfg(feature = "tx-held-wait")]
    fn room_at(&self, at: usize) -> Option<Option<RoomPlace>> {
        lock(&self.rooms).places.get(at).copied()
    }

    /// The table's mark now.
    #[cfg(feature = "tx-held-wait")]
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
    #[cfg(feature = "tx-held-wait")]
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

    /// Ask the face at place `at` alone for room within `wait_us`, with nothing of the session
    /// held: what a droppable leg asks of the one face it is sent on, where each face's place is
    /// taken on its own, behind another send of that place or behind the session's holder
    /// ([`Self::for_held`]). The face's place alone is named when it took none, and `Unasked`
    /// answered when the place names no wait.
    #[cfg(feature = "tx-held-wait")]
    pub(crate) fn within_face(&self, at: usize, wait_us: u64) -> Room {
        let Some(Some(RoomPlace { on, .. })) = self.room_at(at) else {
            return Room::Unasked;
        };
        if self.waits.wait_room(on, wait_us) {
            return Room::Free;
        }
        let mut congested = DroppedOn::none(self.mark());
        congested.insert(at);
        Room::Congested(congested)
    }
}

/// Whether a publish's first fan-out sends without waiting for an outbound slot: one that may not
/// be dropped, on a session whose links share fewer outbound slots than they are
/// (`tx_pool_short`), in a build with the probe stage (`tx-probe`).
#[cfg(all(feature = "listen", feature = "tx-probe"))]
const fn probes(droppable: bool, tx_pool_short: bool) -> bool {
    !droppable && tx_pool_short
}

/// `probes` in a build without the probe stage: no fan-out probes, and each face is sent by the
/// caller's own send, which waits for its slot with the session held, as zenoh-pico's peer writes
/// each of its sockets in turn under its one transmit lock.
#[cfg(all(feature = "listen", not(feature = "tx-probe")))]
const fn probes(_droppable: bool, _tx_pool_short: bool) -> bool {
    false
}

#[cfg(all(test, feature = "listen"))]
mod probe_tests {
    use super::probes;

    /// With the probe stage a publish that may not be dropped probes the faces of a short pool;
    /// one that may be, or one on a pool of a slot for each link, does not. Turned red by a
    /// droppable publish that probes, or a blocking one on a short pool that does not.
    #[cfg(feature = "tx-probe")]
    #[test]
    fn a_blocking_publish_probes_a_short_pool() {
        assert!(probes(false, true));
        assert!(!probes(true, true));
        assert!(!probes(false, false));
        assert!(!probes(true, false));
    }

    /// Without the probe stage no fan-out probes, short pool or not: every face is sent by the
    /// caller's own send, as zenoh-pico's peer sends each of its transports in turn. Turned red by
    /// `probes` answering `true` in this build.
    #[cfg(not(feature = "tx-probe"))]
    #[test]
    fn without_the_probe_stage_no_fan_out_probes() {
        for droppable in [false, true] {
            for short in [false, true] {
                assert!(!probes(droppable, short), "{droppable} {short}");
            }
        }
    }
}

/// One publish as its leg to the links sends it (`CoopEngine::fan_out`): what each link is sent
/// and how it rides, read from the put's options or from its plain way (`CoopEngine::put_leg`).
struct Publication<'a> {
    keyexpr: &'a str,
    wire: &'a WireKey,
    payload: &'a [u8],
    kind: SampleKind,
    meta: &'a PushMetadata<'a>,
    send: wz_session_core::session_actions::SendAs,
    /// The Put's head the plain way of the publisher's write filter wrote at its declare, read with
    /// the filter's answer (`CoopEngine::decide_put`): a plain put is written from it on each link
    /// that names the key by the head's declaration, and no leg looks the filter's row up again
    /// for it. `None` for a publish no publisher made, or a way that keeps no head.
    head: Option<lent_push::PutHead>,
}

/// What a put is sent by (`CoopEngine::put_on_links`).
#[derive(Clone, Copy)]
enum PutBy<'a> {
    /// The options its caller gave, which say before the session is taken whether the put may be
    /// dropped and on which priority it waits for room.
    Options(&'a PublishOptions<'a>),
    /// A plain Put, which brings nothing of its own: of the facts its caller gave, or, for `None`,
    /// of the way its write filter's row keeps, which is read under the session's lock. Its leg
    /// takes the session as a put that may not be dropped and sends it under that take.
    Plain(Option<PlainPutParams>),
}

/// One put of the session as its sender hands it (`CoopEngine::put_on_links`).
#[derive(Clone, Copy)]
struct PutOn<'a> {
    keyexpr: &'a str,
    /// How the sender names the key: the declaration each link names it by where it can.
    wire: &'a WireKey,
    payload: &'a [u8],
    by: PutBy<'a>,
    /// The write filter of the publisher whose put this is; `None` for a publish no publisher
    /// made, which no filter holds back.
    filter: Option<FilterId>,
}

/// What the first leg of a put that held the session answered of it ([`Asked`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    /// Sent: the legs after it send it too, and ask nothing again.
    Through,
    /// Held back by its write filter (`FilteredPut::Suppressed`): nothing is sent.
    HeldBack,
    /// Not plain on this node (`FilteredPut::NotPlain`): nothing is sent, and the caller takes
    /// the general publish.
    NotPlain,
}

/// What a put's first leg that held the session answered (`CoopEngine::decide_put`): its write
/// filter's answer, and for a plain put whether it is plain on this node, read once, so the legs
/// after it send as that one was answered and none takes the session for an answer of its own, as
/// zenoh-pico's put reads its filter once before it writes (`vendor/zenoh-pico/src/api/api.c` @
/// `!_z_write_filter_active(&pub->_filter)`).
struct Asked {
    answer: core::cell::Cell<Option<Answer>>,
}

impl Asked {
    /// A put no leg answered yet.
    fn new() -> Self {
        Self {
            answer: core::cell::Cell::new(None),
        }
    }

    /// Whether no leg answered yet: the one that holds the session now decides.
    fn first(&self) -> bool {
        self.answer.get().is_none()
    }

    /// Whether an earlier leg answered that nothing is sent: this leg sends nothing, and takes
    /// nothing to learn it.
    fn stops(&self) -> bool {
        matches!(self.answer.get(), Some(Answer::HeldBack | Answer::NotPlain))
    }

    /// Answer the put, when no leg did before: a later leg that finds otherwise (its filter's row
    /// gone meanwhile) changes nothing of what the faces before it were sent.
    fn answer_first(&self, answer: Answer) {
        if self.first() {
            self.answer.set(Some(answer));
        }
    }
}

/// How the leg of a put that holds the session sends it (`CoopEngine::decide_put`).
enum PutGoes<'r> {
    /// A plain Put sent from these facts, by its plan or with its key named, as `PlainBy` says:
    /// the leg makes its metadata and its send of them once, for either.
    Plain(PlainPutParams, PlainBy<'r>),
    /// A publish sent from its options, and the head its filter's plain way wrote, if any, which a
    /// link writes it from where the options leave it a plain Put (`PushParts::takes_head`).
    Options(Option<lent_push::PutHead>),
    /// Not sent, and answered so; a plain put whose destination admits no peer is answered as
    /// sent, to none.
    Unsent(Answer),
}

/// How a plain Put of the leg that holds the session is sent (`PutGoes::Plain`).
enum PlainBy<'r> {
    /// Written from its publisher's plan at the session's send epoch, nothing asked again.
    Planned(wz_session_core::session_tables::PlannedPut<'r>),
    /// With its key named in the session's tables, and written from the head its filter's plain
    /// way wrote, if any; for the first leg of a bare put of that way not planned, `plan_at` is the
    /// send epoch its plan was looked for at, which the put plans the way at once it is sent
    /// (`CoopEngine::keep_plan`).
    Named {
        head: Option<lent_push::PutHead>,
        plan_at: Option<u64>,
    },
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
    /// a put's plan found at the session's send epoch (`CoopEngine::put_leg`): no link is
    /// asked how it names the key, and each is sent the head.
    planned: bool,
}

/// What one link's send of a put came to ([`LinkLeg::send_to`]).
struct LegSent {
    /// What the send means for the publish ([`leg_outcome`]).
    outcome: Result<usize, FanoutError>,
    /// The link had no outbound slot for a send that may not wait: the fan-out stops at its face.
    stop: bool,
    /// Whether the link was sent the head its publisher's plan wrote.
    #[cfg(test)]
    planned: bool,
}

impl LegSent {
    /// A send that does not wait, ended before the head was asked for.
    #[cfg(all(feature = "listen", feature = "tx-probe"))]
    fn of(outcome: Result<usize, FanoutError>, stop: bool) -> Self {
        Self {
            outcome,
            stop,
            #[cfg(test)]
            planned: false,
        }
    }
}

impl LinkLeg<'_> {
    /// Send the put over the link of `actions`, as `how` says it is sent
    /// ([`CoopEngine::send_on_links`]). A link that does not take the plain form (one that
    /// rewrites the keys the session originates) is sent the owned message in its place.
    fn send_to<C: ClockSource + 'static>(
        &self,
        actions: &LinkActions<C>,
        how: FaceSend,
    ) -> LegSent {
        let LinkLeg {
            named,
            payload,
            kind,
            meta,
            send,
            head,
            planned,
        } = *self;
        #[cfg(not(all(feature = "listen", feature = "tx-probe")))]
        let _ = how;
        let mut outcome = Ok(0);
        // Each link names the key as its own key-wire form says; a planned put's key was named on
        // every link when it was planned. Which form the link writes the Push in (from the head,
        // as a plain Put, as a publication with its fields) is its session's to read from the
        // parts, into the slot its link lends, unless the session or the build leaves it to the
        // owned send below.
        let key = if planned {
            named
        } else {
            key_on_link(actions, named)
        };
        let parts = wz_session_core::session_actions::PushParts {
            kind,
            value: payload,
            meta,
            head,
        };
        // A send that may not wait is told apart from one whose link has room: one with none
        // ends the fan-out at this face, and a chain of fragments, which such a send does not
        // begin, is sent as the caller's own send.
        #[cfg(all(feature = "listen", feature = "tx-probe"))]
        if how == FaceSend::Probe {
            let answer = match actions.try_send_push_qos(key, parts, send) {
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
                AfterProbe::StopHere => return LegSent::of(outcome, true),
                AfterProbe::Next => return LegSent::of(outcome, false),
                AfterProbe::SendAsOwn => {}
            }
        }
        let sent = if let Some(lent) = actions.send_push_qos(key, parts, send) {
            leg_outcome(lent)
        } else if !lent_push::LENT_PUBLICATION_MAY_DECLINE {
            // No send of this build declines one, so the owned builders are not linked.
            Err(FanoutError::ExceedsCapacity)
        } else {
            let wz_session_core::session_actions::SendAs {
                reliable,
                express,
                priority,
            } = send;
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
        LegSent {
            outcome,
            stop: false,
            #[cfg(test)]
            planned: parts.takes_head(key),
        }
    }
}

/// Send `leg` to the peer of the face whose record holds `wire`, as `how` says: through the
/// held face's wire in `tx` where `wire` lies in the face whose place the caller holds, taken
/// before the session's lock (`CoopEngine::on_faces`, `CoopEngine::on_publish_legs`), and by a
/// try of the face's place otherwise ([`publish_on`]). `None` while the face's place holds no
/// wire, or is not lent.
#[cfg(not(wz_round))]
#[inline(always)]
fn publish_through<L: CoopLinks + 'static, C: ClockSource + 'static>(
    wire: &direct::DirectWire<L, C>,
    tx: LinkTx<'_, C>,
    leg: &LinkLeg<'_>,
    how: FaceSend,
) -> Option<LegSent> {
    match tx.held_wire(wire) {
        Some(held) => held.map(|held| leg.send_to(&held.actions, how)),
        None => publish_on(wire, leg, how),
    }
}

/// Send `leg` over the link `wire` holds as `how` says, through the face's record, which the
/// session's lock alone reaches where each record holds its link ([`publish_on`]).
#[cfg(wz_round)]
#[inline(always)]
fn publish_through<C: ClockSource + 'static>(
    wire: &impl LendsSession<Session = LinkSession<C>>,
    _tx: LinkTx<'_, C>,
    leg: &LinkLeg<'_>,
    how: FaceSend,
) -> Option<LegSent> {
    publish_on(wire, leg, how)
}

/// Send `leg` over the link `wire` holds as `how` says, the link's session lent as [`send_on`]
/// lends it. `None` while the link is not lent.
fn publish_on<C: ClockSource + 'static>(
    wire: &impl LendsSession<Session = LinkSession<C>>,
    leg: &LinkLeg<'_>,
    how: FaceSend,
) -> Option<LegSent> {
    let lent = wire.try_session(|session| leg.send_to(&session.actions, how));
    found_held(&lent);
    match lent {
        Lend::Lent(sent) => Some(sent),
        Lend::Held | Lend::Empty => None,
    }
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
        #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
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

/// What a lend of a link's parts or of its session takes in from the thread that lends them: the
/// engine and the session's own values, which no lend lets out. Made only to be moved into the
/// closure of such a lend, which runs on the lending thread and returns before the lend does.
struct OnThisThread<T>(T);

// SAFETY: a carrier is moved only into a closure run by the making of a link's parts
// (`FaceHeld::gather`), a lend of them (`FaceHeld::lend`) or of its session
// (`LendsSession::try_session`, the send of `send_on` among them), each of which runs its closure on
// the calling thread and returns before it returns: what is carried in or out never reaches
// another thread. A handle on a cell of the link made in such a lend is kept in the parts, as the
// parts' contract asks (`direct::DirectParts`), and what is carried in keeps none of the session's
// handles it is lent: what leaves a lend in a carrier is the session's own values and the link's
// waits.
unsafe impl<T> Send for OnThisThread<T> {}

impl<T> OnThisThread<T> {
    /// The value carried, taken whole, so a lend's closure captures the carrier and not a part.
    fn get(self) -> T {
        self.0
    }
}

/// The network stacks an engine opens its links over: those that serve sessions whose handles are
/// counted as the engine's `SessionLock` counts a link's parts ([`LinkCount`]), so the form's
/// choice of lock reaches every stack the engine is built over.
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

/// What the tables answer a matching listener's declaration: the row and the Interest it opened,
/// or the refusal, which hands its callback back.
type MatchingDeclared = Result<Watching<kind::MatchingListener>, Refused<MatchingCall>>;

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
#[cfg(wz_round)]
type RegistryLend = StepLend<Registry, PlacedRef<LendCell<Registry>>>;

/// Whose chains a reassembly Router of the session holds. Where the read steps each face's pump
/// itself (no `wz_round`), each face has a Router of its own, lent to that face's pump alone
/// (`direct::RouterCell`), so every chain in it is the one peer's of the face's link, keyed by its
/// channel alone. Where the faces' links run as tasks of one set (`wz_round`), they share the
/// session's one Router, which keys each chain by its peer once the session takes faces beside
/// the dial role's (`listen`). A group's chains lie in the group's own Router, never in these.
#[cfg(all(wz_round, feature = "listen"))]
type RouterPeers = ManyPeers;
#[cfg(not(all(wz_round, feature = "listen")))]
type RouterPeers = OnePeer;

// A Router each face holds alone keys no chain by its peer: only links that share one do.
#[cfg(not(wz_round))]
const _: () = assert!(!<RouterPeers as ChainPeers>::KEYED);

/// A reassembly Router of the session, holding the chains of the peers `RouterPeers` says.
pub(crate) type SessionReassembly = wz_runtime_coop::reassembly_rx::SessionReassembly<RouterPeers>;

/// The handle on the place the session lends its reassembly Router in to its links' receives for
/// the length of each pass of its tasks: a cell in the session's arena (`StepPlaces`).
type RouterPlace = PlacedRef<LendCell<SessionReassembly>>;

/// The bytes of the place the session lends its registry in ([`RegistryLend`]).
#[cfg(all(feature = "runtime-plan", wz_round))]
pub(crate) const REGISTRY_LEND_BYTES: usize = core::mem::size_of::<LendCell<Registry>>();

/// The bytes of the place the session lends its reassembly Router in ([`RouterPlace`]).
#[cfg(feature = "runtime-plan")]
pub(crate) const ROUTER_LEND_BYTES: usize = core::mem::size_of::<LendCell<SessionReassembly>>();

/// The places the session lends its registry and its reassembly Router in for a pass of its
/// tasks, each in the session's arena, or in its region where the build fixes its shape
/// (`StatePlaces::steps`), and reached through handles that count nothing: owned by [`Core`],
/// after every holder of a handle of them.
struct StepPlaces {
    #[cfg(wz_round)]
    registry: Placed<LendCell<Registry>>,
    router: Placed<LendCell<SessionReassembly>>,
}

impl StepPlaces {
    /// Both places, nothing lent in either, placed in `arena`. Refused past what it has left.
    #[cfg(feature = "runtime-plan")]
    fn placed_in(arena: &mut Arena) -> Result<Self, LendRefused> {
        Ok(Self {
            #[cfg(wz_round)]
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

impl<L: CoopLinks + 'static, C: ClockSource + 'static> LiveCore<'_, L, C> {
    /// The proof of the hold this is ([`CoreGuard::keys_locked`]).
    #[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
    fn keys_locked(&self) -> KeysLocked<'_> {
        self.core.keys_locked()
    }
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
            #[cfg(wz_round)]
            let read = self.engine.read(false);
            // A read task's read is no callback's: a face another thread's read holds is waited
            // behind, not read as nothing (`direct`).
            #[cfg(not(wz_round))]
            let read = self.engine.read_on_task();
            if read.is_err() {
                break;
            }
        }
    }
}

/// A plain table of the session's state, of the legs of its gets: rows lent from the session's arena
/// at its open or placed in its region, or taken at the table's first row where the tables take
/// their memory on use (`crate::StatePolicy`); as many as the limit the open resolved, `N` the
/// build's ceiling.
#[cfg(feature = "query")]
type Rows<T, const N: usize> = wz_session_core::bounded::BoundedVec<T, N, crate::StatePolicy>;

/// What a move of the links left settled ([`Core::move_links`]): every face up or waiting for a
/// time, no port to ask and no group. The links are moved again once a face's link ended, a face
/// or a port was changed through the faces' table (`moves`, its count after the move), or a face
/// is due (`due_us`, the earliest of a replay's next turn and a wait to dial again).
#[cfg(wz_round)]
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
    #[cfg(wz_round)]
    registry_lend: RegistryLend,
    /// Where each link that comes up leaves its wait for room, for the publishes that find the
    /// session held ([`CoopEngine::live_to_publish`]). They lie in the arena, owned here, before
    /// the arena, and are reached by the engine through a handle that counts nothing.
    #[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
    rooms: Placed<LinkRooms<L::Waits>>,
    /// See the form of a build without `tables-on-use`: where the tables take their memory on use,
    /// the rooms lie in an allocation of their own, which their owner gives back after it drops
    /// them where they lie.
    #[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
    rooms: OwnPlaced<LinkRooms<L::Waits>>,
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
    /// What the joins of the groups had received when they were replaced by a join again or let go
    /// of at the close (`resource-snapshot`), so the session's reading never falls when one ends.
    #[cfg(all(feature = "resource-snapshot", feature = "group"))]
    retired_groups: wz_session_core::resource_snapshot::BuildReceiveLedger,
    /// The links as the last move left them, when it left them settled ([`Self::move_links`]).
    #[cfg(wz_round)]
    links_settled: Option<LinksSettled>,
    /// When the faces the read steps are next due, on the session's clock in microseconds, as the
    /// read's wait was given it (`direct`): what bounds that wait ([`Self::idle_wait`]);
    /// `u64::MAX` for none.
    #[cfg(not(wz_round))]
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
    /// How often a put looked its write filter's row up (`CoopEngine::filter_row`), which the
    /// tests count.
    #[cfg(test)]
    filter_rows: core::cell::Cell<usize>,
    /// How often the session's send epoch was read (`Core::send_epoch`), which the tests count.
    #[cfg(test)]
    epoch_reads: core::cell::Cell<usize>,
    /// How many links a put's plan asked how they name its key (`CoopEngine::keep_plan`), which
    /// the tests count.
    #[cfg(all(test, feature = "std"))]
    plan_links: core::cell::Cell<usize>,
    /// How many steps in a row read a group's datagram and moved nothing, up to
    /// the deploy `GROUP_READS_PER_MOVE` limit (`CoopEngine::step`).
    #[cfg(all(feature = "group", wz_round))]
    group_reads: usize,
    /// The read slot of each group, at the group's place in the session's groups, where the read
    /// steps the group's session itself: `None` while a read holds it; one whose session ended
    /// holds its place, empty, for the group's next join (`CoopEngine::read_groups`).
    #[cfg(all(feature = "group", not(wz_round)))]
    group_pumps: Vec<Option<group::GroupPump<C>>>,
    /// How many places for a group's session the session made (`Self::seat_group`), which a
    /// test of a group of one thread joined again counts.
    #[cfg(all(
        test,
        feature = "std",
        feature = "group",
        feature = "app-transport",
        not(feature = "threads")
    ))]
    group_places_made: usize,
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
    #[cfg(feature = "link-admission")]
    _admission: Placed<Admission<C>>,
    /// The state the places of the session's own values and its keys lie in (`StateHold`): the
    /// region, which holds its registry too (`crate::region`), or the session's own state where
    /// its tables take their memory on use. After the session's state, whose handle of the registry
    /// drops it in place, and every table that keeps a key in it. Held for its owner's drop alone:
    /// the session reaches the state through those handles.
    #[cfg(not(feature = "runtime-plan"))]
    _state: StateHold,
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
    type Keys = KeyStore;
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
    /// The legs of the session's gets still pending on its links, in rows of the policy of the
    /// state's plain tables.
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
struct Face<C: ClockSource + 'static, L: CoopLinks + 'static> {
    id: FaceId,
    link: Link<FaceLink<C, L>, L::Dial>,
    /// Where the face's link stands: the one state of it the session keeps.
    life: UnicastLink,
    replay: Replay,
    /// What the link said of its peer when it came up, while it is up (`bring_up`).
    facts: Option<UpFacts>,
    /// What the connectivity listeners whose history is being replayed were told of the face, and
    /// the tomb of a row of it that went (`told`).
    #[cfg(feature = "connectivity")]
    told: FaceTold,
}

impl<C: ClockSource + 'static, L: CoopLinks + 'static> Face<C, L> {
    /// What the face's link said of its peer when it came up, while the link is up and its
    /// session stands: what is read of a face that stands. The record holds the link's session
    /// here, under the session's lock with the reader, so whether it stands is read off it as it
    /// is asked, and no pass of the links' tasks walks the faces to mark it.
    #[cfg(wz_round)]
    fn facts(&self) -> Option<&UpFacts> {
        let wire = self.up()?;
        self.facts.as_ref()?.standing_while(wire.established())
    }

    /// What the face's link said of its peer when it came up, while the link is up and its
    /// session stands: what is read of a face that stands. The read that steps the one link
    /// itself marks a session it saw end as it looks (`Core::end_closed_facts`), as the session
    /// lies in a place that read may hold.
    #[cfg(not(wz_round))]
    fn facts(&self) -> Option<&UpFacts> {
        self.facts
            .as_ref()
            .filter(|_| self.up().is_some())
            .and_then(UpFacts::standing)
    }
}

/// What a face's link said of its peer when it came up, copied into the face's record by the one
/// holder of the link then (`bring_up`): none of it changes while the link lives, and a read of
/// it under the session's lock must not lend the link, which the face's own read may hold. Kept
/// until the link is lost, so the loss is told by it, and read as standing while the link's
/// session is (`Face::facts`).
struct UpFacts {
    /// The zid the link's peer announced.
    peer: Option<SessionZid>,
    /// The role the link's peer announced, as the wire numbers it.
    whatami: Option<u8>,
    /// Whether the link's peer and this session meet as the peer hat's two north-bound peers
    /// (`SessionLinkActions::meets_remote_as_peer_hat`), `None` for a peer whose role never
    /// arrived: what decides whether the link's replay is ended with the `DeclareFinal` of the
    /// initial interest, which a build that listens or answers Interests sends.
    #[cfg(any(feature = "interest-answer", feature = "listen"))]
    peer_hat: Option<bool>,
    /// The link's generation, which the queries it carries are answered under: how an answer
    /// finds its link without a lend of it.
    #[cfg(feature = "queryable")]
    generation: u64,
    /// Whether a step of the link was seen to end its session: the face no longer stands.
    ended: bool,
    /// The face's first row as its watchers are told it (`FaceLinkRow::each_of_actions`): a
    /// face of this engine holds one link, so it is the face's one row.
    #[cfg(feature = "connectivity")]
    row: Option<FaceLinkRow>,
}

impl UpFacts {
    /// What `session`, whose handshake completed, says of its peer, read in place: the record
    /// holds the session itself where each link runs as a task.
    #[cfg(wz_round)]
    fn of<C: ClockSource + 'static>(session: &LinkSession<C>) -> Self {
        let facts = Self::of_actions(&*session.actions);
        #[cfg(feature = "queryable")]
        {
            facts.under(session.generation)
        }
        #[cfg(not(feature = "queryable"))]
        {
            facts
        }
    }

    /// What `actions`, a link's whose handshake completed, say of its peer, through whichever
    /// handle on them the caller holds; the link's generation is the caller's to add
    /// (`Self::under`).
    fn of_actions<C: ClockSource + 'static>(actions: &LinkActions<C>) -> Self {
        #[cfg(feature = "connectivity")]
        let row = {
            let mut first = None;
            FaceLinkRow::each_of_actions(actions, |row| {
                if first.is_none() {
                    first = Some(row);
                }
            });
            first
        };
        Self {
            peer: actions.peer_session_zid(),
            whatami: actions.peer_whatami_wire(),
            #[cfg(any(feature = "interest-answer", feature = "listen"))]
            peer_hat: actions.meets_remote_as_peer_hat(),
            #[cfg(feature = "queryable")]
            generation: 0,
            ended: false,
            #[cfg(feature = "connectivity")]
            row,
        }
    }

    /// These facts, of a link whose queries are answered under `generation`.
    #[cfg(feature = "queryable")]
    fn under(self, generation: u64) -> Self {
        Self { generation, ..self }
    }

    /// These facts, while the session they were read off stands.
    fn standing(&self) -> Option<&Self> {
        (!self.ended).then_some(self)
    }

    /// [`Self::standing`], for a link whose session is `established` as it is read.
    #[cfg(wz_round)]
    fn standing_while(&self, established: bool) -> Option<&Self> {
        self.standing().filter(|_| established)
    }

    /// The face's row among the faces that stand: one whose link names its ends.
    #[cfg(feature = "connectivity")]
    fn standing_row(&self) -> Option<&FaceLinkRow> {
        self.row.as_ref().filter(|row| row.links != 0)
    }

    /// The face's snapshot, as `FaceSnapshot::of_actions` reads it off the link: its row, and
    /// what `link`, read off the link as the snapshot is made, says beyond it.
    #[cfg(feature = "connectivity")]
    fn snapshot(&self, link: &LinkFacts) -> Option<FaceSnapshot> {
        let row = self.row.as_ref()?;
        let mut face = FaceSnapshot::of_face_row(row);
        face.links.extend(LinkSnapshot::of_row_with(row, link));
        Some(face)
    }
}

impl<C: ClockSource + 'static, L: CoopLinks + 'static> FaceRecord<LinkCount> for Face<C, L> {
    type Wire = FaceLink<C, L>;
    type Pump = L::Pump;
    type Dial = L::Dial;

    fn id(&self) -> FaceId {
        self.id
    }

    fn link(&self) -> &Link<FaceLink<C, L>, L::Dial> {
        &self.link
    }

    fn link_mut(&mut self) -> &mut Link<FaceLink<C, L>, L::Dial> {
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
        link: Link<FaceLink<C, L>, L::Dial>,
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
                facts: _,
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
            core::ptr::addr_of_mut!((*at).facts).write(None);
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
    #[cfg(all(any(feature = "listen", feature = "group"), wz_round))]
    gate: CellRc<LinkGate<C>, LinkCount>,
    /// The link's generation, which the queries it carries are answered under (`query`). Read
    /// where the link's session is read in place (`UpFacts::of`); the read that steps it itself
    /// reads its records' (`direct`).
    #[cfg(all(feature = "queryable", wz_round))]
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

    // What a wait found is the round's to know, which steps the links as tasks of one set: a read
    // that steps each face where it lies reads what it waited for at once.
    #[cfg(all(any(feature = "listen", feature = "group"), wz_round))]
    fn input_seen(&self, ready: bool) {
        self.gate.input_seen(ready);
    }

    #[cfg(feature = "resource-snapshot")]
    fn message_reading(&self) -> wz_session_core::resource_snapshot::BuildMessageReading {
        self.actions.message_reading()
    }
}

impl<C: ClockSource + 'static> TransportSession<C, SessionLock> for LinkSession<C> {
    fn actions(&self) -> &LinkHandle<C> {
        &self.actions
    }
}

/// One link of the session: its session half ([`LinkSession`]) and what the driver holds of it.
type Wire<C> = wz_runtime_coop::faces::Wire<LinkSession<C>, FaceEnd, LinkCount>;

/// What an operation that holds a face's send place sends through under the session's lock,
/// taken inside that place (`CoopEngine::live_on_link`): the face held and its wire, while the
/// place holds one; every other face is reached by a try of its own place.
#[cfg(not(wz_round))]
type LinkTx<'a, C> = direct::FaceTx<'a, C>;

/// What an operation sends through where each face's record holds its link: nothing beside the
/// record, which the session's lock alone reaches. That form goes with the record that holds a
/// link, and this with it.
#[cfg(wz_round)]
type LinkTx<'a, C> = core::marker::PhantomData<&'a Wire<C>>;

/// What a face holds of its link while the link is up or in its handshake: the link's session
/// itself where each link runs as a task, or a handle on the face's place that holds the session
/// apart from the session's state where the read steps the one link itself (`direct`). Every
/// send of the session on a face lends the link's session through it (`send_on`).
trait HeldLink<C: ClockSource + 'static> {
    /// The link as the face holds it.
    type Wire: LendsSession<Session = LinkSession<C>>;
}

impl<C: ClockSource + 'static, L: CoopLinks + 'static> HeldLink<C> for L {
    #[cfg(wz_round)]
    type Wire = Wire<C>;
    #[cfg(not(wz_round))]
    type Wire = direct::DirectWire<L, C>;
}

/// The link a face of a session over `L` holds (`HeldLink`).
type FaceLink<C, L> = <L as HeldLink<C>>::Wire;

/// A lend of a face's link that found it held. Never so where the read steps the faces itself: an
/// operation holds the place of every face that holds a link before the session's lock
/// (`CoopEngine::live_on_link`) and tries only a place that held none when it walked the faces,
/// which nothing holds then; where the faces share the session's lock as their one place
/// (`wz_one_send_place`), it tries every face's place on the one thread of the form, which holds
/// none of them while it holds the session. A debug build of either fails on it; a release build
/// owes the send's debt, as any other form does.
#[inline(always)]
fn found_held<U>(lent: &Lend<U>) {
    #[cfg(not(wz_round))]
    debug_assert!(
        !matches!(lent, Lend::Held),
        "a send on a face's link found it held"
    );
    #[cfg(wz_round)]
    let _ = lent;
}

/// Send `send` over the link `wire` holds, where each face's record holds its link: the link's
/// session is lent to it in place, under the session's lock with the caller
/// ([`LendsSession::try_session`]). `send` reads the session's state it was made under, its
/// tables among them, on the calling thread the lend runs it on, and keeps no handle on a cell of
/// the link or of the session, so it is carried into the lend as that thread's own
/// (`OnThisThread`). `Some` with whether the link took it; `None` while the link holds no
/// session. A step of the link that answers yes or no (a batch's, or how the link names a key) is
/// lent through it too.
// Out of line and over `dyn`: one body lends a link for every send of the session.
#[inline(never)]
fn send_on<C: ClockSource + 'static>(
    wire: &impl LendsSession<Session = LinkSession<C>>,
    send: &dyn SendTo<C>,
) -> Option<bool> {
    let send = OnThisThread(send);
    let lent = wire.try_session(move |session| send.get().send_to(&session.actions));
    found_held(&lent);
    match lent {
        Lend::Lent(took) => Some(took),
        Lend::Held | Lend::Empty => None,
    }
}

/// How the session of a face's link ends: with its task, or, where the read steps the one link
/// itself, as the read's last step of it said (`direct`).
#[cfg(wz_round)]
type FaceEnd = wz_runtime_coop::faces::TaskEnd;
/// How the session of a face's link ends: with its task, or, where the read steps the one link
/// itself, as the read's last step of it said (`direct`).
#[cfg(not(wz_round))]
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

    /// Hand `sample` to the callback: the one place a sample is handed to a subscriber's
    /// callback. The sample is lent as it lies to every subscriber; the sink leaves out a timestamp
    /// its callback is not to see. Whether a call begun before an undeclaration still hands it is
    /// the call's to say (`SubscriberCall`).
    fn hand(&self, sample: &SampleRef<'_>) {
        self.sink.call_ref(sample, self.expose);
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

// A call reads its row where it lies, so the rows lie apart from the tables, where no table moves
// them and the dispatch reads them only through a shared borrow.
const _: () = assert!(
    <RowPolicy as wz_session_core::bounded::Storage>::ROWS_STAY_APART,
    "the session's tables keep their rows apart from themselves and never move one"
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

    #[inline]
    fn begin(&self) -> Option<RowCall> {
        self.latch.begin().then(|| RowCall(NonNull::from(self)))
    }

    #[inline]
    unsafe fn end(call: RowCall) -> bool {
        // SAFETY: the caller's: the row has not moved since the call began and is still in its
        // table, which keeps it until its last call ended.
        unsafe { call.0.as_ref() }.latch.end()
    }

    #[inline]
    fn retire(&self) -> bool {
        self.latch.retire()
    }

    #[inline]
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

    /// Hand `sample` to the row's callback, unless the subscriber was undeclared since the call
    /// was begun: a call the round or a plane owes is made at a time of its own after the lock that
    /// began it, so an undeclaration made meanwhile says the program wants nothing more of it.
    #[cfg(any(wz_round, feature = "query", feature = "queryable"))]
    #[inline]
    pub(crate) fn hand(&self, sample: &SampleRef<'_>) {
        // SAFETY: the row lies where the call began until its last call ended, and this one has
        // not; nothing writes a row's sink or its timestamp choice after it is declared.
        let row = unsafe { self.call.0.as_ref() };
        if !row.latch.retired() {
            row.hand(sample);
        }
    }

    /// Hand `sample` to the row's callback, whether or not the subscriber was undeclared since the
    /// call was begun: a call pinned in the one hold of the session that read or put the sample,
    /// beside every row that hold found, each of which is handed it as zenoh-pico calls each
    /// subscription of the list it took under its lock
    /// (`vendor/zenoh-pico/src/session/subscription.c` @ `_z_trigger_subscriptions_impl`). So a
    /// row an earlier callback of the same sample undeclared is still handed it, and the count of
    /// rows a delivery reached is the count of callbacks it called. The read that hands each record
    /// out pins its rows in the hold that reads the record (`pinned`); a build that keeps the round
    /// pins a put's own in the hold whose loopback captures their calls
    /// (`CoopEngine::publish_to_subscribers`).
    #[cfg(any(not(wz_round), feature = "local-subscriber"))]
    #[inline]
    pub(crate) fn hand_pinned(&self, sample: &SampleRef<'_>) {
        // SAFETY: the row lies where the call began until its last call ended, and this one has
        // not; nothing writes a row's sink or its timestamp choice after it is declared.
        unsafe { self.call.0.as_ref() }.hand(sample);
    }

    /// End the call: `true` when it was the last call of an undeclared subscriber, whose row the
    /// session's walk of its tables then lets go of (`SessionTables::release_drained_subscriber`).
    #[inline]
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
    #[cfg(wz_round)]
    round: PlacedRef<Round>,
    #[cfg(feature = "queryable")]
    plane: PlacedRef<QueryPlane>,
}

// The read that hands each record out as it is read hands every sample out itself, one subscriber
// at a time (`pinned`): only a build whose read runs beside the program's calls offers the round
// a sample.
#[cfg(wz_round)]
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
#[cfg(all(feature = "liveliness", wz_round))]
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
#[cfg(all(feature = "liveliness", not(wz_round)))]
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
        #[cfg(wz_round)]
        unsafe {
            cx.plane
                .arrive(&cx.round, || QueryableCall::begin(row.row()), query)
        };
        // A read that steps its one link itself hands each query of the link to the queryables
        // (`queries`), so only the session's own get is asked here, which hands the calls its
        // queryables begin its own view.
        #[cfg(not(wz_round))]
        cx.plane
            .arrive_own(|| QueryableCall::begin(row.row()), query);
    }
}

/// What the ABI's key `wire` names of `keyexpr`: the whole key under id 0 for a literal, else
/// the declaration and the rest of the key past it. Read before a link is lent, as the ABI's key
/// is not shared with the thread a link may be lent on.
#[cfg(feature = "query")]
fn abi_names<'a>(wire: &'a WireKey, keyexpr: &'a str) -> (ExprId, Option<&'a str>) {
    if wire.is_literal() {
        (0, Some(keyexpr))
    } else {
        wire.names_in(keyexpr)
    }
}

/// `f` on the key `keyexpr` of a get as the link of `actions` names it: by the link's key-wire
/// form, and as the ABI made it, `abi` ([`abi_names`]), for a link of the declared form.
#[cfg(all(feature = "shared-key-ids", feature = "query"))]
fn get_key_on_link<C: ClockSource + 'static, U>(
    actions: &LinkActions<C>,
    keyexpr: &str,
    abi: (ExprId, Option<&str>),
    f: impl FnOnce(ExprId, Option<&str>) -> U,
) -> U {
    match wz_capi_port::wire_on_link(actions.key_wire_on_link(keyexpr)) {
        Some(made) if made.is_literal() => f(0, Some(keyexpr)),
        Some(made) => {
            let (mapping_id, suffix) = made.names_in(keyexpr);
            f(mapping_id, suffix)
        }
        None => f(abi.0, abi.1),
    }
}

/// A build without the shared key ids names a get's key on every link as the ABI made it.
#[cfg(all(not(feature = "shared-key-ids"), feature = "query"))]
#[inline(always)]
fn get_key_on_link<C: ClockSource + 'static, U>(
    _actions: &LinkActions<C>,
    _keyexpr: &str,
    abi: (ExprId, Option<&str>),
    f: impl FnOnce(ExprId, Option<&str>) -> U,
) -> U {
    f(abi.0, abi.1)
}

/// Send `send` to the peer of the face whose record holds `wire`: through the held face's wire
/// in `tx` where `wire` lies in the face whose place the caller holds, taken before the
/// session's lock (`CoopEngine::live_on_link`), and by a try of the face's place otherwise
/// ([`send_on`]). Whether the link took it; `None` while the face's place holds no wire, or is
/// not lent. The send through the held place neither waits nor is owed.
#[cfg(not(wz_round))]
fn send_through<L: CoopLinks + 'static, C: ClockSource + 'static>(
    wire: &direct::DirectWire<L, C>,
    tx: LinkTx<'_, C>,
    send: &dyn SendTo<C>,
) -> Option<bool> {
    match tx.held_wire(wire) {
        Some(held) => held.map(|held| send.send_to(&held.actions)),
        None => send_on(wire, send),
    }
}

/// Send `send` over the link `wire` holds, through the face's record, which the session's lock
/// alone reaches where each record holds its link ([`send_on`]).
#[cfg(wz_round)]
fn send_through<C: ClockSource + 'static>(
    wire: &impl LendsSession<Session = LinkSession<C>>,
    _tx: LinkTx<'_, C>,
    send: &dyn SendTo<C>,
) -> Option<bool> {
    send_on(wire, send)
}

/// `f` on the actions of the face whose record holds `wire`, reached as [`send_through`]
/// reaches it: what a send reads of the link before it is made (an id the link allocates).
/// `None` while the face's place holds no wire, or is not lent.
#[cfg(all(feature = "query", not(wz_round)))]
fn lend_through<L: CoopLinks + 'static, C: ClockSource + 'static, U: Send>(
    wire: &direct::DirectWire<L, C>,
    tx: LinkTx<'_, C>,
    f: impl FnOnce(&LinkActions<C>) -> U + Send,
) -> Option<U> {
    match tx.held_wire(wire) {
        Some(held) => held.map(|held| f(&*held.actions)),
        None => lend_actions(wire, f),
    }
}

/// `f` on the actions of the link `wire` holds, through the face's record, which the session's
/// lock alone reaches where each record holds its link ([`lend_actions`]).
#[cfg(all(feature = "query", wz_round))]
fn lend_through<C: ClockSource + 'static, U: Send>(
    wire: &impl LendsSession<Session = LinkSession<C>>,
    _tx: LinkTx<'_, C>,
    f: impl FnOnce(&LinkActions<C>) -> U + Send,
) -> Option<U> {
    lend_actions(wire, f)
}

/// What one turn of a get's walk of the faces did, read once the link's place and the session's
/// lock are let go.
#[cfg(feature = "query")]
enum LegTurn {
    /// No face is left to ask.
    Done,
    /// The face was not asked, or its leg was not counted.
    Skipped,
    /// The leg was not issued and is over: let go of with nothing held.
    Ended(u64),
    /// The leg was issued.
    Issued,
}

/// `f` on the actions of the link `wire` holds, lent by a try of its session that waits for
/// nothing ([`LendsSession::try_session`]): what a send reads of the link before it is made (an
/// id the link allocates). `None` while the link is not lent.
#[cfg(any(
    feature = "query",
    feature = "transport-stats",
    all(test, any(feature = "std", feature = "liveliness-get"))
))]
fn lend_actions<C: ClockSource + 'static, U: Send>(
    wire: &impl LendsSession<Session = LinkSession<C>>,
    f: impl FnOnce(&LinkActions<C>) -> U + Send,
) -> Option<U> {
    let lent = wire.try_session(|session| f(&session.actions));
    found_held(&lent);
    match lent {
        Lend::Lent(answer) => Some(answer),
        Lend::Held | Lend::Empty => None,
    }
}

/// `wire` as the link of `actions` names the key `keyexpr`: the link's key-wire form decides,
/// and the declared form keeps `wire` as the ABI made it (`shared-key-ids`). Only a liveliness
/// subscriber's Interest names its key by the ABI's form still, beside a get
/// (`get_key_on_link`).
#[cfg(all(feature = "shared-key-ids", feature = "liveliness"))]
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
#[cfg(all(not(feature = "shared-key-ids"), feature = "liveliness"))]
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

/// Send `interest` open over `actions`, for what is declared now and what is declared later,
/// naming its key as the link's key-wire form says: whether the link took it.
fn send_interest<C: ClockSource + 'static>(
    interest: FilterInterest<'_>,
    actions: &LinkActions<C>,
) -> bool {
    let linked = interest_on_link(actions, interest.key, interest.aggregate);
    let (mapping_id, suffix) = match &linked {
        Some(form) => (form.mapping_id, form.suffix.as_deref()),
        None => (interest.mapping_id, interest.suffix),
    };
    actions
        .send_interest_kinds(
            u64::from(interest.id),
            wz_session_core::session_actions::InterestAsk {
                kinds: kinds(interest.kind),
                current: true,
                future: true,
                aggregate: interest.aggregate,
            },
            mapping_id,
            suffix,
        )
        .is_ok()
}

/// Where the write filter `handle` names lies among the Interests the replay tells, in the
/// filters' slot order, whether it holds an Interest or not: read while it stands, for its place
/// once it is let go of. `None` when it names none. A build that reaches no pace reads no place
/// (`replay`), so only whether it stands.
fn filter_rank(tables: &CoopTables, handle: WriteFilterHandle) -> Option<usize> {
    let filters = tables.write_filters();
    if !ReplayPacing::REACHABLE {
        return filters.get(handle).map(|_| 0);
    }
    filters.rank_of(handle)
}

/// Take the write filter `handle` names out of `tables`, with the listeners declared on it, let go
/// of there: the id of the Interest it held last, whose Final goes on the wire, and the declaration
/// its key is named by, whose hold the row hands over for the caller to give back
/// ([`Core::let_go_of_keyexpr`]); `None` when no filter is there.
fn unwatch_filter(
    tables: &mut CoopTables,
    handle: WriteFilterHandle,
) -> Option<(Option<EntityId>, Option<KeyexprHandle>)> {
    tables
        .undeclare_write_filter_quietly(handle)
        .map(|unwatched| (unwatched.interest_final, unwatched.held))
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

/// What a get comes to once its legs are issued: the count of those that went out; when none
/// did, a refusal for the legs no pending table held (`unheld`), else the refusal of a leg whose
/// request no link took (`unsent`), else `0`, a get that reached nobody and is over at once.
#[cfg(feature = "query")]
pub(crate) fn get_outcome(
    issued: usize,
    unheld: usize,
    unsent: Option<Declined>,
) -> Result<usize, Declined> {
    if issued > 0 {
        return Ok(issued);
    }
    if unheld > 0 {
        return Err(Declined::TableFull);
    }
    unsent.map_or(Ok(0), Err)
}

/// The refusal of a get's leg whose request the link did not take, by the send's error: a request
/// past what the session's codec or reassembly carries is the request's own, and any other the
/// link's, which is down or did not take it now (`None`: the face's place held no link). zenoh-pico
/// answers a get whose send failed with that send's error
/// (`vendor/zenoh-pico/src/net/primitives.c` @
/// `_Z_CLEAN_RETURN_IF_ERR(ret, _z_unregister_pending_query(zn, qid));`).
#[cfg(feature = "query")]
pub(crate) fn unsent_refusal(why: Option<SendWireError>) -> Declined {
    match why.map(PublishError::from) {
        Some(PublishError::ExceedsCapacity) => Declined::ExceedsCapacity,
        _ => Declined::Unavailable,
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
/// under, its options, the consolidation and the replies' keys its parameters state, read once
/// for every leg, whether its callbacks show a reply's timestamp, and the mint of each leg's
/// callback.
#[cfg(feature = "query")]
struct LegAsk<'a, 'o> {
    keyexpr: &'a str,
    opts: &'a QueryOptionsOf<'o>,
    consolidation: wz_session_core::query_mode::ConsolidationMode,
    accept: wz_session_core::reply_acceptance::ReplyKeyExpr,
    expose: bool,
    mint: &'a mut dyn FnMut() -> ReplyCallback,
}

/// Where one leg of a get is held pending (`CoopEngine::hold_leg`): in the table of `face` (a
/// link's, a group's, or the session's own, `LOCAL_FACE`) under the id `rid` makes, the leg's id
/// `leg`, owed `finals` Finals.
#[cfg(feature = "query")]
struct LegEntry {
    face: FaceId,
    leg: u64,
    rid: LegRid,
    finals: u32,
}

/// The request id a leg is held under (`CoopEngine::hold_leg`).
#[cfg(feature = "query")]
enum LegRid {
    /// A serial the face's counter gave, the row the leg's entry takes in the face's table put
    /// below it (`request_id_at`), so the answer that names the id names the row and the table
    /// finds the entry there with no walk.
    Serial(wz_session_core::wire_id::RequestId),
    /// An id taken before the leg is held, which it is held under as it is: the session's own,
    /// which its held Final was taken under.
    #[cfg(feature = "local-queryable")]
    Taken(wz_session_core::wire_id::RequestId),
}

#[cfg(feature = "query")]
impl LegRid {
    /// The id of a leg whose entry takes row `row`.
    fn at(self, row: usize) -> wz_session_core::wire_id::RequestId {
        match self {
            Self::Serial(serial) => wz_session_core::wire_id::request_id_at(serial, row),
            #[cfg(feature = "local-queryable")]
            Self::Taken(rid) => rid,
        }
    }
}

/// What came of holding a leg of a get pending (`CoopEngine::hold_leg`).
#[cfg(feature = "query")]
enum LegHeld {
    /// Held under `rid`, owed its Finals: its request may go out, under that id.
    Held {
        rid: wz_session_core::wire_id::RequestId,
    },
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

#[cfg(all(
    test,
    feature = "std",
    any(
        wz_round,
        feature = "query",
        feature = "queryable",
        feature = "connectivity"
    )
))]
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

/// Whether a face that `stands` ends as its link's session is read `established` or not: a face
/// that stands no longer does once its session is not established, and one that does not stand
/// has nothing to end.
#[cfg(not(wz_round))]
fn face_ended(stands: bool, established: bool) -> bool {
    stands && !established
}

/// What one send's failure means for a publish: a link that is down skips it, anything else is
/// a message no link could have carried.
fn leg_outcome(result: Result<(), SendWireError>) -> Result<usize, FanoutError> {
    // A link that lent no slot for the frame refused it before a byte left. Read as a link that is
    // down, as its publish error reads it, a blocking put would be answered as sent and never
    // reach the peer; it is a send that failed, as the refusal of a declaration is.
    #[cfg(feature = "tx-lend-only")]
    if let Err(SendWireError::LinkRefused(wz_session_core::link::LinkDropCause::NoTxSlot)) = result
    {
        return Err(FanoutError::ExceedsCapacity);
    }
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
#[cfg(all(debug_assertions, wz_round))]
struct Gated<'a>(&'a Round);

#[cfg(all(debug_assertions, wz_round))]
impl<'a> Gated<'a> {
    fn over(lane: &'a Round) -> Self {
        lane.offering_gated(true);
        Self(lane)
    }
}

#[cfg(all(debug_assertions, wz_round))]
impl Drop for Gated<'_> {
    fn drop(&mut self) {
        self.0.offering_gated(false);
    }
}

/// What a dispatch that finds the session's registry not lent says: every pass of the session's
/// tasks lends it, so a task stepped outside one is a fault of the engine.
#[cfg(wz_round)]
const UNLENT: &str = "a task of the session dispatched outside a pass that lends its registry";

/// Whether `event` is a Push lent where its frame lies: what the subscribers' plane alone reads, so
/// a link's dispatch hands it there and to no other plane (`Registry::dispatch_push`).
fn lent_push(event: &wz_session_core::driver_loop::IterationEvent<'_, '_>) -> bool {
    matches!(
        event,
        wz_session_core::driver_loop::IterationEvent::InPlace(record) if record.push().is_some()
    )
}

/// Whether `event` is a Response or a ResponseFinal lent where its frame lies: what the pending
/// gets alone read, so a link's dispatch hands it there and to no other plane
/// (`Registry::dispatch_reply`), as zenoh-pico's dispatch picks a reply's handler by the
/// message's kind (`vendor/zenoh-pico/src/session/rx.c` @ `case _Z_N_RESPONSE_FINAL:`).
#[cfg(all(feature = "query", wz_round))]
fn lent_reply<'e, 'a, 'f>(
    event: &'e wz_session_core::driver_loop::IterationEvent<'a, 'f>,
) -> Option<&'e wz_session_core::driver_loop::InPlaceRecord<'a, 'f>> {
    match event {
        wz_session_core::driver_loop::IterationEvent::InPlace(record) if record.is_reply() => {
            Some(record)
        }
        _ => None,
    }
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
#[cfg(wz_round)]
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
    /// Whether Pushes or replies, each handed to its one plane, were dispatched whose drains are
    /// still owed ([`EventSink::end_records`]).
    after_pushes: bool,
}

#[cfg(wz_round)]
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
        // A Response or a ResponseFinal is read by the pending gets alone: it is handed to them by
        // its kind, as a Push is to the subscribers, and what follows it is put off alike.
        #[cfg(feature = "query")]
        if let Some(record) = lent_reply(&event) {
            #[cfg(debug_assertions)]
            let _gated = Gated::over(&self.lane);
            let dispatched = self
                .registry
                .with(|registry| registry.dispatch_reply(face, record));
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
        // A Response or a ResponseFinal is read by the pending gets alone: it is handed to them by
        // its kind, as a Push is to the subscribers, and what follows it is put off alike.
        #[cfg(feature = "query")]
        if let Some(record) = lent_reply(&event) {
            #[cfg(debug_assertions)]
            let _gated = Gated::over(&self.lane);
            let dispatched = self
                .registry
                .with(|registry| registry.dispatch_reply(face, record));
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
/// out as it is read, the link alone, which takes no cell (`HeldGate`).
trait LinkGates {
    /// The gates.
    type Gate;
}

impl<C: ClockSource + 'static> LinkGates for C {
    #[cfg(all(feature = "listen", wz_round))]
    type Gate =
        RoundGate<AdmissionGate<CellRc<dyn SessionDatagramLink, LinkCount>, C, SessionLock>>;
    #[cfg(all(not(feature = "listen"), wz_round))]
    type Gate = RoundGate<CellRc<dyn SessionDatagramLink, LinkCount>>;
    // The read steps the one link itself and hands each record out as it is read, so nothing
    // holds the link back from its session, and it keeps no round to tell where the datagram it
    // lends lies (`direct`): the link is the pump.
    #[cfg(not(wz_round))]
    type Gate = CellRc<dyn SessionDatagramLink, LinkCount>;
}

/// The gates of a link of a session on the clock `C` ([`LinkGates`]).
type LinkGate<C> = <C as LinkGates>::Gate;

/// The gates of a link as its session and its pump hold them (`LinkCalls::Gate`): a handle on
/// their cell of the session's table where the round holds the link back, and where nothing does
/// the link's own handle, which the pump reads the link through with no cell of gates between.
#[cfg(wz_round)]
type HeldGate<C> = CellRc<LinkGate<C>, LinkCount>;
/// The gates of a link as its session and its pump hold them (`LinkCalls::Gate`): a handle on
/// their cell of the session's table where the round holds the link back, and where nothing does
/// the link's own handle, which the pump reads the link through with no cell of gates between.
#[cfg(not(wz_round))]
type HeldGate<C> = LinkGate<C>;

/// The table of cells a link's gates are placed in where they hold the link back
/// (`TransportState::gate_cells`).
type GateCells = wz_session_core::byte_cells::LentByteCells<
    <LinkCount as wz_runtime_coop::link_cells::CountKind>::Flag,
>;

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
    cells_of::<C>(links.link_cell_bytes())
}

/// The bytes of each link's cells a session on the clock `C` lays out, a cell of `driver` bytes
/// for each link's driver among them: a `const fn`, as a region laid out when the build is
/// compiled reads them off the links' type (`SessionLinks::LINK_CELL_BYTES`).
pub(crate) const fn cells_of<C: ClockSource + 'static>(driver: usize) -> LinkCells<usize> {
    LinkCells {
        driver,
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
    /// The bytes of the faces' rooms, where the arena holds them: a session whose tables take their
    /// memory on use holds them in an allocation of their own, and its plan lays out no place.
    #[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
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
    #[cfg(feature = "link-admission")]
    pub(crate) admission: usize,
    /// The read slot and send place of one face past the dial role's (`direct`).
    #[cfg(not(wz_round))]
    pub(crate) direct_face: usize,
}

/// What an open lays its plan out from (`lend_session`): a region whose every row was laid out
/// with it, which the open takes whole, or (`runtime-plan`) the config's rows and after them the
/// places the open's holds name.
enum OpenFrom<'h> {
    Region(&'h OpenRegion),
    #[cfg(any(feature = "runtime-plan", test))]
    Config(OpenHolds<'h>),
}

impl OpenFrom<'_> {
    /// The bytes of the runtime's span and of the engine's place the plan lays out.
    fn places(&self) -> OpenPlaces {
        match self {
            Self::Region(region) => region.places(),
            #[cfg(any(feature = "runtime-plan", test))]
            Self::Config(holds) => OpenPlaces {
                runtime: holds.runtime,
                engine: holds.engine,
            },
        }
    }
}

/// The admission the links of a session over the clock `C` ask while their handshakes run: owned
/// by the session's state where its arena lent it, and reached by each link's lease through a
/// handle that counts nothing. A build without `link-admission` holds none: each link that ends
/// its handshake is a face of its own, as each link is a peer of zenoh-pico's own
/// (`vendor/zenoh-pico/src/transport/peer.c` @ `z_result_t _z_transport_peer_unicast_add(`).
#[cfg(feature = "link-admission")]
pub(crate) type Admission<C> = LinkRegistry<CoopRuntime<C>>;

/// The admission as its links' leases ask it.
#[cfg(feature = "link-admission")]
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
/// value would be moved again, twice, by the open that reads it. A `const fn`, so a region laid
/// out when the build is compiled holds these rows too (`OpenRegion`), and an open by it lays out
/// none of them.
pub(crate) const fn lay_out_open<const ROWS: usize>(
    plan: &mut ArenaPlan<ROWS>,
    holds: &OpenHolds<'_>,
) -> Result<(), ArenaRefused> {
    plan.lay_cells(holds.cells);
    // The rooms of a session whose tables take their memory on use lie in an allocation of their
    // own (`state_places::RoomsPlace`) and take no place of the arena.
    #[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
    plan.lay_rooms(holds.rooms);
    if let Err(refused) = plan.lay_held(holds.held) {
        return Err(refused);
    }
    plan.lay_runtime(holds.runtime);
    // An engine in an allocation of its own (`SharedClaim`) takes no place of the arena.
    #[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
    plan.lay_engine(holds.engine);
    plan.lay_planes(holds.planes);
    #[cfg(feature = "link-admission")]
    plan.lay_admission(holds.admission);
    #[cfg(not(wz_round))]
    plan.lay_direct_faces(holds.direct_face);
    // Each hold keeps its refusal in the plan, the first one kept, so the plan is asked once,
    // after them all, and answers what the first refused hold would have.
    plan.settled()
}

/// The bytes of the task a link's session runs as on this engine: `RouterSessionTask` over the
/// link's gates, the place the session lends its one reassembly Router in and `FaceDispatch`.
/// What each cell the open reserves for a link holds, so a link's session is never refused a cell
/// for its size.
#[cfg(wz_round)]
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
    #[cfg(wz_round)]
    pub(crate) fn of<C: ClockSource + 'static>(config: &CoopConfig<impl EndpointList>) -> Self {
        Self::of_counts::<C>(
            config.groups.len(),
            crate::arena::dials(config),
            config.max_faces,
        )
    }

    /// [`Self::of`] for a config of `shape`, the numbers a region was laid out for
    /// (`ArenaRegion::shape`): a `const fn`, so a region laid out when the build is compiled holds
    /// the runtime's span. A config the region admits that dials no endpoint where the shape dials
    /// some, while it listens or joins a group, takes no cell for a dial the region holds one for.
    #[cfg(wz_round)]
    pub(crate) const fn of_shape<C: ClockSource + 'static>(
        shape: &crate::arena::PlanShape,
    ) -> Self {
        Self::of_counts::<C>(
            shape.groups,
            crate::arena::dials_of(shape.dials, shape.listens, shape.groups),
            shape.max_faces,
        )
    }

    /// The tables of a session that joins `groups` groups, dials when `dials` and admits
    /// `max_faces` faces besides: the groups' cells first, then the links'.
    #[cfg(wz_round)]
    const fn of_counts<C: ClockSource + 'static>(
        groups: usize,
        dials: bool,
        max_faces: usize,
    ) -> Self {
        let groups = if groups < caps::MAX_TASKS {
            groups
        } else {
            caps::MAX_TASKS
        };
        let links = (dials as usize).saturating_add(max_faces);
        let room = caps::MAX_TASKS.saturating_sub(groups);
        let links = if links < room { links } else { room };
        Self::holding(groups, links, link_task_bytes::<C>())
    }

    /// The tables of a session `config` opens whose read steps every face itself (`direct`): no
    /// link runs as a task, as each face's session lies in the engine, so no cell is reserved for
    /// one and the clock's type sizes nothing here.
    #[cfg(not(wz_round))]
    pub(crate) fn of(config: &CoopConfig<impl EndpointList>) -> Self {
        Self::of_groups(config.groups.len())
    }

    /// [`Self::of`] for a config of `shape`, the numbers a region was laid out for
    /// (`ArenaRegion::shape`): a `const fn`, so a region laid out when the build is compiled holds
    /// the runtime's span.
    #[cfg(not(wz_round))]
    pub(crate) const fn of_shape(shape: &crate::arena::PlanShape) -> Self {
        Self::of_groups(shape.groups)
    }

    /// The tables of a session that joins `groups` groups, whose links run as no task.
    #[cfg(not(wz_round))]
    const fn of_groups(groups: usize) -> Self {
        let groups = if groups < caps::MAX_TASKS {
            groups
        } else {
            caps::MAX_TASKS
        };
        Self::holding(groups, 0, 0)
    }

    /// The tables of `groups` groups' cells and `links` links' cells of `task_bytes` each.
    const fn holding(groups: usize, links: usize, task_bytes: usize) -> Self {
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
    /// and runs each link as a task (`wz_round`) reserves every cell for a link, and its runtime
    /// takes no memory after it is made: a config that names a group is refused by name there, so
    /// the groups' cells are none; where it takes no face beside its dial role's, its runtime hosts
    /// that one link's task and is made for one (`CoopRuntime::try_reserved_for_one`), which links
    /// no walk of a table of many cells. A build that joins none and whose read steps every face
    /// itself (`direct`) spawns no task, whether it dials, listens or reads on a thread beside the
    /// program's calls, and its runtime holds no cell (`RuntimeForm::Taskless`), which links no
    /// pass over a cell at all.
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
    pub(crate) const fn placed_bytes<C: ClockSource>(self) -> Option<usize> {
        match CoopRuntime::<C>::placed_layout(self.rows(), Self::form(self.groups)) {
            Some(span) => Some(span.size()),
            None => None,
        }
    }

    /// The rows the runtime is made with. The timers are stated as the constant they are, so the
    /// making of the timer table is that of the build's count alone; a build that joins no group
    /// adds no cell while its open lasts, and reserves the groups' with the links' (none, as a
    /// config that names a group is refused by name there).
    const fn rows(self) -> RuntimeRows {
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
    /// for the `groups` it joins (`group`), whose sessions are tasks; else, where each link runs
    /// as a task (`wz_round`), every cell reserved (`listen`) or the one cell of the dial role's
    /// link; else no cell (`direct`). That read steps every face where it lies and takes each
    /// connection off its ports itself (`accept_links`), so a session that listens spawns no task
    /// either, and a table of many cells would link its walks for a table no task is placed in.
    pub(crate) const fn form(groups: usize) -> RuntimeForm {
        if cfg!(feature = "group") {
            RuntimeForm::Opening { added: groups }
        } else if cfg!(not(wz_round)) {
            RuntimeForm::Taskless
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
    #[cfg(wz_round)]
    registry_lend: &'a RegistryLend,
    /// The limits the session was opened with: what a link's gate (the room of the round it
    /// reads into) and its shared key ids are sized by. A read that hands each record out as it
    /// is read gates nothing, so only its shared key ids read them.
    #[cfg(any(wz_round, feature = "shared-key-ids"))]
    limits: &'a SessionLimits,
}

impl<C: ClockSource + 'static> LinkCalls<C, SessionLock> for LinkMaking<'_> {
    type Gate = HeldGate<C>;
    #[cfg(wz_round)]
    type Dispatch = FaceDispatch<C>;
    // What the read hands each step of the link it steps itself (`direct`).
    #[cfg(not(wz_round))]
    type Dispatch = direct::LinkRecords<C>;
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

    // Each record is handed out as it is read, so nothing holds the link back: the link is its own
    // gate, read through its own table, and takes no cell of the gates.
    #[cfg(not(wz_round))]
    fn gate(
        &self,
        pump: CellRc<dyn SessionDatagramLink, LinkCount>,
        _actions: &LinkHandle<C>,
        _cells: Option<&GateCells>,
    ) -> Option<HeldGate<C>> {
        Some(pump)
    }

    #[cfg(not(wz_round))]
    fn gated_link(gate: &HeldGate<C>) -> CellRc<dyn SessionDatagramLink, LinkCount> {
        gate.clone()
    }

    #[cfg(wz_round)]
    fn gate(
        &self,
        pump: CellRc<dyn SessionDatagramLink, LinkCount>,
        actions: &LinkHandle<C>,
        cells: Option<&GateCells>,
    ) -> Option<HeldGate<C>> {
        // The session is handed a record of a link only while its round of deliveries has the room
        // one record can take (decision Q4), and with `listen` only once the engine admitted it:
        // the link gives the session nothing between its handshake and the face table's decision
        // (`admit`), so a link that is refused has put nothing in the tables.
        let record_room = crate::round::read_room::<
            { caps::MAX_SUBSCRIPTIONS },
            { caps::MAX_LIVELINESS_SUBSCRIPTIONS },
        >(self.limits);
        #[cfg(feature = "listen")]
        let pump = AdmissionGate::new(pump, actions.clone());
        #[cfg(not(feature = "listen"))]
        let _ = actions;
        // SAFETY: a link is made under the session's lock, and its gate asked by the step alone;
        // the gate is held by the link's cells, which the session's transport holds, dropped
        // before its state (`Core`'s fields), whose round's owner changes it no more.
        let gate = unsafe { RoundGate::new(pump, self.session.lane.share(), record_room) };
        CellRc::<_, LinkCount>::in_cells_of(cells, gate).ok()
    }

    // The gates' cell, read as the link it gates.
    #[cfg(wz_round)]
    fn gated_link(gate: &HeldGate<C>) -> CellRc<dyn SessionDatagramLink, LinkCount> {
        gate.clone().into_link()
    }

    fn wire_parts(
        &self,
        face: FaceId,
        actions: LinkHandle<C>,
        gate: &HeldGate<C>,
    ) -> (Self::Dispatch, LinkSession<C>) {
        #[cfg(feature = "queryable")]
        let generation = self.session.plane.next_generation();
        // What the link's records are dispatched with: the registry is lent to a task's dispatch
        // for each pass, and reached by the read that steps the link itself under the session's
        // lock for each record (`direct`).
        #[cfg(wz_round)]
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
        #[cfg(not(wz_round))]
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
        #[cfg(not(wz_round))]
        let _ = gate;
        // The wire keeps a handle on the gates to admit the link through them, and to tell them
        // what each wait found in the link's stack.
        #[cfg(all(wz_round, not(any(feature = "listen", feature = "group"))))]
        let _ = gate;
        (
            dispatch,
            LinkSession {
                actions,
                #[cfg(all(any(feature = "listen", feature = "group"), wz_round))]
                gate: gate.clone(),
                #[cfg(all(feature = "queryable", wz_round))]
                generation,
            },
        )
    }
}

/// The session ends, for the reason the caller's `last` was left holding: what the moves of the
/// links answer (`Core::poll_links`, `Core::carry_out`). The reason holds an endpoint's text, the
/// largest value of a move, so it is written once where the caller keeps it rather than handed
/// back through every call between.
#[cfg(wz_round)]
struct SessionEnds;

/// The dial of a face as its step read it: the answer of the dial, kept for the handshake the
/// face's life asks for next, and the endpoint it dialled, which names the reason a refusal
/// leaves. One value, so what a step read is carried through the arms of its life's effects
/// (`Core::carry_out`) whole; a step that read no dial carries [`Self::none`].
#[cfg(wz_round)]
struct ReadDial<P> {
    answer: DialAnswer<P, LinkCount>,
    dialled: Option<DialEndpoint>,
}

#[cfg(wz_round)]
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
    #[cfg(wz_round)]
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
    #[cfg(wz_round)]
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
        // session machine has no accepting role, or whose acceptor mints no cookie (no
        // `accept-cookie`), holds no key, and its draw takes nothing.
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
    #[cfg(wz_round)]
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
    #[cfg(wz_round)]
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
    #[cfg(wz_round)]
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
    #[cfg(wz_round)]
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
    #[cfg(wz_round)]
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
    #[cfg(wz_round)]
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
        // Read at the root of the index of the gets' deadlines, with no walk of the faces.
        #[cfg(feature = "query")]
        let gets_due_ms = self.session.next_get_deadline_ms().unwrap_or(u64::MAX);
        // A snapshot's replies end it as they come, and the table of ended ones is drained by
        // the sweep, which a pending snapshot so owes at every step.
        #[cfg(all(feature = "query", feature = "liveliness-get"))]
        let snapshots =
            self.session.registry.all_gets().any(|gets| {
                !gets.liveliness_gets.is_empty() || gets.liveliness_gets.has_finalized()
            });
        #[cfg(not(all(feature = "query", feature = "liveliness-get")))]
        let snapshots = false;
        #[cfg(wz_round)]
        let (links_due_us, unsettled) = (
            self.links_settled
                .map_or(u64::MAX, |settled| settled.due_us),
            self.links_settled.is_none(),
        );
        // A face's own deadlines are its look's and its step's, which each read makes at them
        // (`direct`); the links owe the bookkeeping only the next turn of a replay a link owes
        // its peer, which only the bookkeeping takes. A face's due held here would be the one its
        // look saw before its step moved it, and would owe the bookkeeping at the next look.
        #[cfg(not(wz_round))]
        let (links_due_us, unsettled) = (
            self.transport
                .links
                .faces()
                .filter_map(|face| face.replay.next_turn_ms())
                .min()
                .map_or(u64::MAX, |turn_ms| turn_ms.saturating_mul(1000)),
            false,
        );
        let seen = self.seen();
        self.ledger.settle(
            Due {
                links_us: links_due_us,
                #[cfg(feature = "query")]
                gets_ms: gets_due_ms,
            },
            seen,
        );
        if unsettled || snapshots {
            self.ledger.owe();
        }
    }

    /// Move every face's link on, after the session was stepped, against the step's reading of the
    /// clock, `now_us`; see [`Self::poll_face`]. `redial_ms` is the wait of a group whose link
    /// was lost. `Err` when the session ends, which only the dial role's face can bring about,
    /// the reason in `last`.
    #[cfg(wz_round)]
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
    #[cfg(wz_round)]
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
            .is_some_and(|wire| ReplayPacing::REACHABLE && !wire.finished());
        if up && self.replay_turn(at, now_ms, core::marker::PhantomData) == TurnEnd::EndsLink {
            self.transport.links.abort_link(at);
            self.run_tasks();
        }
        let mut read = ReadDial::none();
        let step = self
            .transport
            .face_step(at, id, now_us, &mut read.answer, &mut read.dialled);
        if step.effects.is_empty() {
            return Ok(());
        }
        self.carry_out(at, step.effects, &mut read, now_us, last)
    }

    /// Give the life of the face at `at` the input `input` at `now_us`, and carry out what it
    /// asks for ([`Self::carry_out`]). `Err` as [`Self::carry_out`], the reason in `last`.
    #[cfg(wz_round)]
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
        let effects = face.life.input(input, now_us);
        self.carry_out(at, effects, &mut ReadDial::none(), now_us, last)
    }

    /// Carry out what the life of the face at `at` asks for (`effects`), each naming the endpoint
    /// it is about, in the order [`Effects`] names, reporting the dial or the handshake it asks
    /// for back to it as its next input, read at the clock after the I/O, until it asks for no
    /// more. `read` holds the face's dial as the step read it ([`ReadDial`]). `Err` when the
    /// session ends, the reason the last endpoint tried gave left in `last`, which every arm
    /// writes rather than hands back.
    #[cfg(wz_round)]
    fn carry_out(
        &mut self,
        at: usize,
        mut effects: Effects,
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
            if let Some(row) = effects.end_handshake() {
                let why = self.transport.end_handshake(at);
                self.run_tasks();
                self.transport.links.put_link(at, Link::Idle);
                self.refuse(last, Some(&DialEndpoint::Listed(row)), why);
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
        // The face is read before its facts go: what it was is what a watcher is told, its row
        // queued now and handed out once the session is let go of.
        // Read whether or not the link's session was seen to end before the loss.
        let facts = self
            .transport
            .links
            .face(at)
            .and_then(|face| face.facts.as_ref());
        #[cfg(feature = "connectivity")]
        if let Some(row) = facts
            .and_then(|facts| facts.row.clone())
            .filter(|_| self.session.faces_watched())
        {
            self.session.report_face_row(FaceEventKind::Down, row);
        }
        // The lost peer's chains end with its link: the next link's fragments would be spliced
        // onto them.
        if let Some(zid) = facts.and_then(|facts| facts.peer) {
            self.transport.end_peer_chains(&zid);
        }
        // What a replaying listener was told of the face is read while its facts are held.
        #[cfg(feature = "connectivity")]
        self.face_went(at);
        self.transport.links.put_link(at, Link::Idle);
        // What the lost link's peer was told went with it: the next link's peer holds nothing.
        if let Some(face) = self.transport.links.face_mut(at) {
            face.replay.discard();
            face.facts = None;
        }
        self.rooms.forget(at);
        self.lose_link(id);
    }

    /// Read the face at `at` as one that no longer stands (`UpFacts`) once its link's session is
    /// no longer `established`, as the face's own read, which steps the link, reads it off its
    /// own handle on the link's actions: called by that read under the session's lock and before
    /// it lets go of it, so a face stands for a reader of the session exactly while its link's
    /// session does, and the look lends nothing of the face's send place, which a send may hold.
    /// Its facts stay until the loss is taken, which is told by them.
    #[cfg(not(wz_round))]
    fn end_closed_facts(&mut self, at: usize, established: bool) {
        // Looked at in place first: a face reached to be written counts as a move of the links,
        // which a look that ended no session must not make.
        let stands = self
            .transport
            .links
            .face(at)
            .is_some_and(|face| face.facts().is_some());
        if !face_ended(stands, established) {
            return;
        }
        if let Some(facts) = self
            .transport
            .links
            .face_mut(at)
            .and_then(|face| face.facts.as_mut())
        {
            facts.ended = true;
        }
    }

    /// Tell the peer of every face whose link is up everything the session holds again, as a link
    /// that has just come up is told (`begin_replay`), at the session's pace; the count of faces.
    /// What the application asks for when it holds that a peer lost declarations the session made.
    /// A face whose first turn the replay is given up on is not counted: its link ends, and the
    /// next pass over the faces takes it as lost (`poll_face`). `tx` is what the caller holds
    /// of the one link, taken with its place before the session's lock
    /// (`CoopEngine::live_on_link`), through which that link is told.
    fn redeclare(&mut self, tx: LinkTx<'_, C>) -> usize {
        let now_ms = self.clock.now_us() / 1000;
        let places = self.transport.links.places();
        (0..places)
            .filter(|&at| self.redeclare_on(at, now_ms, tx))
            .count()
    }

    /// Tell the peer of the face at `at` everything the session holds again (`redeclare`),
    /// through `tx`: whether it was told, which a place with no face, or a face whose link is not
    /// up, is not.
    fn redeclare_on(&mut self, at: usize, now_ms: u64, tx: LinkTx<'_, C>) -> bool {
        let up = self
            .transport
            .links
            .face(at)
            .is_some_and(|face| face.up().is_some());
        if !up {
            return false;
        }
        match self.begin_replay(at, now_ms, tx) {
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
    ///
    /// `tx` is what the caller holds of a face, taken with its place before the session's lock
    /// (`CoopEngine::live_on_link`), through which that face is settled.
    #[cfg(feature = "interest-answer")]
    fn settle_faces(&mut self, tx: LinkTx<'_, C>) {
        #[cfg(wz_round)]
        let _ = tx;
        for at in 0..self.transport.links.places() {
            let Some(face) = self.transport.links.face(at) else {
                continue;
            };
            let Some(wire) = face.up() else {
                continue;
            };
            let carried = OnThisThread((HeldFace::new(at, face.id), &mut self.session.registry));
            let settle = move |actions: &LinkActions<C>| {
                let (held, registry) = carried.get();
                registry.settle(held, actions);
            };
            // The face whose place the caller holds is settled through the wire it holds.
            #[cfg(not(wz_round))]
            if let Some(held) = tx.held_wire(wire) {
                if let Some(link) = held {
                    settle(&link.actions);
                }
                continue;
            }
            // A link another holder has now is settled at its next event.
            let _ = wire.try_session(move |session| settle(&session.actions));
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

    /// [`Self::bring_up_with`] where the face's record holds its link's session itself: what the
    /// link says of its peer is read off it in place.
    #[cfg(wz_round)]
    fn bring_up(&mut self, at: usize, now_us: u64) {
        let facts = match self
            .transport
            .links
            .face(at)
            .and_then(|face| face.link.wire())
            .map(|wire| wire.try_session(|session| UpFacts::of(session)))
        {
            Some(Lend::Lent(facts)) => facts,
            _ => return,
        };
        self.bring_up_with(at, now_us, facts);
    }

    /// The face at `at`, whose handshake completed, holds its link up, its peer as `facts` says:
    /// what the session holds is
    /// declared over it from here on, and the watchers of the faces are told it came up. The link
    /// was admitted in its handshake (`install_link_admission`), so a link that got this far is
    /// the session's link to its node, and no other link to the node is kept beside it. A first
    /// turn the replay is given up on ends the link at once, and the next pass over the faces
    /// takes it as lost (`poll_face`). Where the read steps the link itself, it reads `facts`
    /// off its own handle on the link's actions, so nothing of the face's send place is lent.
    fn bring_up_with(&mut self, at: usize, now_us: u64, facts: UpFacts) {
        let Some(face) = self.transport.links.face(at) else {
            return;
        };
        let Some(wire) = face.link.wire() else {
            return;
        };
        // The work form's task reads nothing of an accepted link before its admission is granted;
        // a read that steps each face where it lies is given the face once it is admitted.
        #[cfg(all(feature = "listen", wz_round))]
        wire.gate.pump().grant();
        // A publish goes to the links that are up, so theirs are the rooms it asks.
        if let Some(on) = wire.room_wait() {
            self.rooms.hold(at, on);
        }
        #[cfg(feature = "connectivity")]
        let told = facts.row.clone().filter(|_| self.session.faces_watched());
        #[cfg(any(feature = "interest-answer", feature = "listen"))]
        let peer_hat = facts.peer_hat;
        if let Some(face) = self.transport.links.face_mut(at) {
            face.facts = Some(facts);
        }
        // The link is now one the session's sends go through: what was planned over the links
        // before it no longer holds (`LinkSupervisor::generation`).
        self.transport.links.establish(at);
        #[cfg(any(feature = "interest-answer", feature = "listen"))]
        self.owe_link_initial_final(at, peer_hat);
        #[cfg(wz_round)]
        if self.begin_replay(at, now_us / 1000, core::marker::PhantomData) == TurnEnd::EndsLink {
            self.transport.links.abort_link(at);
        }
        // The one link's first turn goes through its wire, which the read takes with the link's
        // place once the look that brought it up has let go of the session's lock
        // (`CoopEngine::turn_replay`).
        #[cfg(not(wz_round))]
        self.start_replay(at, now_us / 1000);
        #[cfg(feature = "connectivity")]
        if let Some(row) = told {
            self.session.report_face_row(FaceEventKind::Up, row);
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
                #[cfg(wz_round)]
                Ok(face) => self.transport.add_group(face),
                // The read slot lies at the group's place in the session's groups.
                #[cfg(not(wz_round))]
                Ok((face, seat)) => {
                    self.transport.add_group(face);
                    self.seat_group(at, seat);
                }
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

    /// What the group `join` names is joined with as the face `face` names, whose tables the
    /// registry holds at its place: the stack joins the group, and the parameters, the waits and
    /// the session's places its session runs with. [`OpenError::Group`] when the stack joins no
    /// such group.
    #[cfg(feature = "group")]
    fn group_joining(
        &mut self,
        face: HeldFace,
        join: GroupJoin,
    ) -> Result<GroupJoining, OpenError> {
        let transport = self.transport.open_group(&join.endpoint)?;
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
        // The group is handed a record of its datagrams only while the round of deliveries has the
        // room one record of the group's batch can take (decision Q4), as a link is.
        #[cfg(wz_round)]
        let record_room = crate::round::read_room::<
            { caps::MAX_SUBSCRIPTIONS },
            { caps::MAX_LIVELINESS_SUBSCRIPTIONS },
        >(resolve_limits(&self.config));
        // SAFETY: a group's transport is driven by the session's step alone, under its lock; the
        // gate is held by the group, which the session's tasks hold, all dropped before its state
        // (`Core`'s fields), whose round's owner changes it no more.
        #[cfg(wz_round)]
        let input_gate = wz_session_mcu::group_drive::GroupInputGate::new(unsafe {
            crate::round::takes_a_group_read(self.session.lane.share(), record_room)
        });
        // A message the session puts on the group waits for room by running the session's tasks,
        // the group's among them, on the session's clock; where the read steps the group's session
        // itself, by the group's own write of its stage, on the same clock.
        #[cfg(wz_round)]
        let pace = alloc::rc::Rc::new(group::SessionPace {
            local: self.local.clone(),
            clock: self.clock.clone(),
        });
        #[cfg(not(wz_round))]
        let pace = alloc::rc::Rc::new(group::ClockPace {
            clock: self.clock.clone(),
        });
        Ok(GroupJoining {
            face,
            join,
            transport,
            #[cfg(wz_round)]
            input_gate,
            // SAFETY: as the input gate's.
            #[cfg(wz_round)]
            lane: unsafe { self.session.lane.share() },
            params,
            policy: self.policy,
            limits: *resolve_limits(&self.config),
            pace,
            #[cfg(feature = "queryable")]
            generation,
            // SAFETY: the group's session reads the watchers while it runs, which ends when the
            // engine's links' end stops the group and runs it out (`Core::end_links`), before
            // the session's state, which owns them, is dropped.
            #[cfg(feature = "connectivity")]
            watchers: unsafe { self.session.watchers.share() },
        })
    }

    /// Join the group `join` names as the face `face` names, whose tables the registry holds at
    /// its place: the stack joins the group, and its session, with a fresh dispatcher, is spawned
    /// on the session's local set and stepped once. [`OpenError::Group`] when the stack joins no
    /// such group or the session ended at its first step (its link did not open).
    #[cfg(all(feature = "group", wz_round))]
    fn join_group(
        &mut self,
        face: HeldFace,
        join: GroupJoin,
    ) -> Result<GroupFace<L::Waits>, OpenError> {
        let endpoint = join.endpoint.clone();
        let joining = self.group_joining(face, join)?;
        #[cfg(feature = "queryable")]
        let generation = joining.generation;
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
        let group = GroupFace::join(&self.local, joining, dispatch, self.rooms.waits().clone())
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

    /// Join the group `join` names as the face `face` names, whose tables the registry holds at
    /// its place, where the read steps the group's session itself: the stack joins the group, and
    /// what the group's read slot takes of the join is handed back beside the face, its session,
    /// with a fresh dispatcher, built in the slot when it takes it (`Self::seat_group`). Its first
    /// step is the read's, which tells a link that did not open
    /// (`CoopEngine::first_group_steps`). [`OpenError::Group`] when the stack joins no such group.
    #[cfg(all(feature = "group", not(wz_round)))]
    fn join_group(
        &mut self,
        face: HeldFace,
        join: GroupJoin,
    ) -> Result<(GroupFace<L::Waits>, group::GroupSeat), OpenError> {
        let joining = self.group_joining(face, join)?;
        // SAFETY: the plane is read by the group's read slot, which the session lets go of at its
        // links' end (`Core::end_links`), or a read that holds it lets go of once it finds the
        // session closed, before the session's state, which owns the plane, is dropped.
        #[cfg(feature = "queryable")]
        let plane = unsafe { self.session.plane.share() };
        let (group, seat) = GroupFace::join(
            joining,
            #[cfg(feature = "queryable")]
            plane,
            self.rooms.waits().clone(),
        );
        // A droppable publish that finds the session held asks the group's socket for room as it
        // asks a link's, and its wait goes with the face, at the face's place.
        if let Some(on) = group.room() {
            self.rooms.hold(face.at(), on);
        }
        Ok((group, seat))
    }

    /// Seat the join `seat` in the read slot of the group at place `at`: its session built in
    /// the place the group's last session lay in, or, at the group's first join, in a place made
    /// for the group then. A slot a read holds now (none, as a group is joined again only between
    /// two of its steps) is given a place of its own.
    #[cfg(all(feature = "group", not(wz_round)))]
    fn seat_group(&mut self, at: usize, seat: group::GroupSeat) {
        if let Some(Some(pump)) = self.group_pumps.get_mut(at) {
            pump.rejoin(seat);
            return;
        }
        #[cfg(all(
            test,
            feature = "std",
            feature = "app-transport",
            not(feature = "threads")
        ))]
        {
            self.group_places_made += 1;
        }
        let pump = group::GroupPump::new(self.local.runtime().clone(), seat);
        match self.group_pumps.get_mut(at) {
            Some(slot) => *slot = Some(pump),
            None => self.group_pumps.push(Some(pump)),
        }
    }

    /// The link of face `id` while it is up, which a send to that face's peer goes over.
    #[cfg(feature = "query")]
    fn up_wire(&self, id: FaceId) -> Option<&FaceLink<C, L>> {
        self.transport
            .links
            .faces()
            .find_map(|face| face.up().filter(|_| face.id == id))
    }

    /// The links of the faces that are up, each with its face's place: what a put is sent over.
    fn up_wires_at(&self) -> impl Iterator<Item = (usize, &FaceLink<C, L>)> {
        self.transport
            .links
            .placed()
            .filter_map(|(at, face)| Some((at, face.up()?)))
    }

    /// The link of the face a query that came in under `generation` came over, while it is up:
    /// where the query's answer goes. Found by the face's record of the link, as a lend of the
    /// link may find it held by the face's own read.
    #[cfg(feature = "queryable")]
    fn answer_wire(&self, generation: u64) -> Option<&FaceLink<C, L>> {
        self.transport
            .links
            .faces()
            .find_map(|face| match (face.up(), &face.facts) {
                (Some(wire), Some(facts)) if facts.generation == generation => Some(wire),
                _ => None,
            })
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

    /// Give back one hold of the declaration `row` names, the last retracting it: its place read
    /// while it stands, then its row let go of, then the links told. The one body of a key's
    /// release, for a holder the program keeps and for a write filter's row alike.
    fn let_go_of_keyexpr(&mut self, row: KeyexprHandle, tx: LinkTx<'_, C>) {
        let place = self.prefix_retraction(Some(row));
        let retracted = tables_mut(&mut self.session.registry).undeclare_keyexpr(row);
        // The row went before the links are told: a send never finds the table borrowed.
        self.retract_keyexpr(place, retracted, tx);
    }

    /// Tell the links whose peers were told of it, and each group the session joined, that the
    /// declaration `mapping_id`, which lay at `place` in the replay's order, is retracted, once the
    /// tables let it go: what its last holder's going sends, after the rows went, so a send never
    /// finds the tables borrowed.
    #[inline(never)]
    fn retract_keyexpr(
        &mut self,
        place: Option<usize>,
        mapping_id: Option<ExprId>,
        tx: LinkTx<'_, C>,
    ) {
        let (Some(place), Some(mapping_id)) = (place, mapping_id) else {
            return;
        };
        self.retract_at(place, Some(Retract::Keyexpr(mapping_id)), tx);
        #[cfg(feature = "group")]
        for group in &self.transport.groups {
            group.retract_keyexpr(mapping_id);
        }
    }

    /// Ask each link, through `tx`, and each group the session joined for the tokens of the
    /// liveliness subscriber `handle`, from its row as it stands now. A subscriber its own
    /// history's callback undeclared asks nothing: its row is gone, and so is its place in the
    /// replay's order.
    #[cfg(feature = "liveliness")]
    fn ask_liveliness_subscriber(&mut self, handle: LivelinessSubscriberHandle, tx: LinkTx<'_, C>) {
        let stands = tables(&self.session.registry)
            .liveliness_subscribers()
            .get(handle)
            .is_some();
        if !stands {
            return;
        }
        self.announce(DeclaredRow::of(handle), tx);
        // Each group is asked as its declarations say.
        #[cfg(feature = "group")]
        {
            let tables = tables(&self.session.registry);
            if let Some(row) = tables.liveliness_subscribers().get(handle) {
                let wire = group::wire_key_of(tables.wire_of(row.key()));
                for group in &self.transport.groups {
                    group.ask_liveliness(row.id(), row.key().as_str(), &wire, row.history());
                }
            }
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
            #[cfg(wz_round)]
            let outcome = group.take_outcome(&self.local);
            #[cfg(not(wz_round))]
            let outcome = group.take_outcome();
            if let Some(outcome) = outcome {
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
                    Ok(joined) => {
                        // The new join's session is built in the place of the one that ended,
                        // which the read let go of with its session's transport.
                        #[cfg(not(wz_round))]
                        let (joined, seat) = joined;
                        #[cfg(not(wz_round))]
                        self.seat_group(at, seat);
                        // The liveliness subscribers ask the group again, as they would have
                        // had it been there when they were declared, as the tokio engine's
                        // group asks again when it comes up. What the session announced is
                        // not told again: neither upstream tells a group that comes up of
                        // the entities a session already holds.
                        #[cfg(feature = "liveliness")]
                        {
                            let tables = tables(&self.session.registry);
                            for (_, row) in tables.liveliness_subscribers().iter() {
                                joined.ask_liveliness(
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
                            joined.keep_tombs_of(ended);
                            #[cfg(feature = "resource-snapshot")]
                            self.retired_groups.retire(&ended.message_reading());
                            *ended = joined;
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

    /// Each group told the session's keyexprs that came up, at the open or joined again, asks for
    /// its members' with the session's next entity id, as the tokio engine's group asks when it
    /// comes up. Best effort: a member's own declarations reach the group later all the same, so
    /// a session with no entity id left does not ask. Both forms run it with the groups' poll: the
    /// round's bookkeeping, and the read that steps each group's session itself.
    #[cfg(feature = "group")]
    fn ask_groups_for_keyexprs(&mut self) {
        for group in &self.transport.groups {
            if group.owes_keyexpr_ask() {
                if let Some(interest_id) = self.session.take_entity_id() {
                    group.ask_keyexprs(u64::from(interest_id));
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
    #[cfg(all(feature = "listen", wz_round))]
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
        #[cfg(all(feature = "liveliness", wz_round))]
        self.retract_owed();
    }

    /// Retract the tokens the peers of lost links declared, as many as the round of deliveries
    /// takes now (`SessionState::retract_owed`). Each `Delete` is a record of a token for every
    /// liveliness subscriber the session's limits admit.
    #[cfg(all(feature = "liveliness", wz_round))]
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

    /// Hold in the round what the declaration watches are owed, as far as it has room
    /// (`DeclWatches::tell_owed`): each new watch's catch-up from the peers of the links up now,
    /// each declaration named as its link's peer, and the events a watch lost.
    #[cfg(all(
        any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ),
        wz_round
    ))]
    fn tell_decl_watches_owed(&self) {
        let registry = &self.session.registry;
        let links = &self.transport.links;
        let faces = move || {
            links.faces().filter_map(move |face| {
                face.link.wire()?;
                // A link in its handshake names no peer yet: its facts come with it up.
                let up = face.up().is_some();
                let peer = decl_watch::named(|| {
                    face.facts
                        .as_ref()
                        .filter(|_| up)
                        .and_then(|facts| facts.peer)
                });
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
        not(wz_round)
    ))]
    fn next_decl_watch_call(&self, told: &mut decl_watch::Told) -> Option<decl_watch::WatchCall> {
        let registry = &self.session.registry;
        let links = &self.transport.links;
        let faces = move || {
            links.faces().filter_map(move |face| {
                face.link.wire()?;
                // A link in its handshake names no peer yet: its facts come with it up.
                let up = face.up().is_some();
                let peer = decl_watch::named(|| {
                    face.facts
                        .as_ref()
                        .filter(|_| up)
                        .and_then(|facts| facts.peer)
                });
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
        #[cfg(test)]
        self.epoch_reads.set(self.epoch_reads.get() + 1);
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
    /// [`CoopConfig::idle_wait_ms`] and at most `most_ms`, unless the link already holds some or
    /// waits in its own loop;
    /// and while no link is open, the next dial, for no longer either. zenoh-pico's read waits
    /// the same way, on a socket whose receive timeout is that long (`Z_CONFIG_SOCKET_TIMEOUT`).
    /// Bounded at nothing, the wait is a look of no time where a step reads only what a wait found
    /// ready, and none elsewhere.
    fn idle_wait(&mut self, most_ms: u32) -> IdleWait {
        // What is due other than input, the earliest of it in milliseconds of the session's clock:
        // a get whose deadline comes first is swept when it is due, not up to a whole wait late
        // (read at the root of the index of the gets' deadlines, so no table is walked and a get
        // that ended bounds the wait no longer), and so is the next turn of a replay a link owes
        // its peer, a periodic job the program started, and a group's session when it is next due
        // with nothing arriving (its beacon, its sweep, what the session pushed onto it, its join
        // again). A group whose socket may hold a datagram not yet read is stepped again at once
        // (its task took one, or the read's step of it read to its bound), so its own time is
        // not asked.
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
            #[cfg(not(wz_round))]
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
        let bound = self.config.idle_wait_ms.min(most_ms);
        let most = match due_ms {
            Some(due_ms) => Self::wait_until(
                bound,
                due_ms,
                *clock_now.get_or_insert_with(|| self.now_us()),
            ),
            None => bound,
        };
        // A group's burst waits for nothing: the move that ends it has each link read again
        // (`LinkSupervisor::links_moved`).
        #[cfg(feature = "group")]
        if group_took {
            return IdleWait::None;
        }
        // A group whose stack gives no wait for its input is looked at on its tick.
        #[cfg(feature = "group")]
        let most = if self.transport.group_unwaited() {
            most.min(group::GROUP_TICK_MS)
        } else {
            most
        };
        // Bounded at nothing, the wait is still made where a step reads only what a wait found
        // ready, as a look of no time: a port is asked for a connection once a wait found it ready,
        // and the round passes over a link its last read found empty until a wait finds input
        // there (`RoundGate`), so steps that made no wait would read neither again. Elsewhere a
        // step reads every link and group as it is.
        #[cfg(not(any(feature = "listen", all(wz_round, feature = "group"))))]
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
    #[cfg(wz_round)]
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
    #[cfg(wz_round)]
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
        #[cfg(wz_round)]
        self.transport.links.end_dials_and_ports();
        // Each group's session is asked to stop, and its next step, taken here, tells the group it
        // leaves and lets the group's link go; its tables go with the other faces' below.
        #[cfg(feature = "group")]
        if self.transport.stop_groups() {
            #[cfg(wz_round)]
            self.run_tasks();
            // Where the read steps each group's session itself, each read slot the session holds is
            // stepped once more here; one a read holds is let go of by that read, which finds the
            // session closed.
            #[cfg(not(wz_round))]
            for pump in self.group_pumps.drain(..).flatten() {
                pump.leave();
            }
            #[cfg(feature = "resource-snapshot")]
            for group in &self.transport.groups {
                self.retired_groups.retire(&group.message_reading());
            }
            self.transport.groups.clear();
        }
        self.transport.links.end_faces(|face| face.replay.discard());
        self.rooms.forget_all();
        self.session.registry.remove_accepted_faces();
        // Each link's task sees its end. The one link a read steps itself is no task: its session
        // goes with the face that holds it (`direct`).
        #[cfg(wz_round)]
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
                plan: PlanFrom::Config(&HeldPlaces::NONE),
            },
        )
    }

    /// The region an open of this engine by `rows` lays out no row for ([`OpenRegion`]): the rows
    /// of the session's tables, and after them the places this engine keeps beside its tables and
    /// those `held` names for the ABI, every one a size of a type of the engine or a constant of
    /// the ABI. A `const fn`, so a build that states its region as a constant has it laid out when
    /// it is compiled; refused as an open over a config refuses those places
    /// ([`ArenaPlan::holding`]).
    pub const fn open_region(
        rows: ArenaRegion,
        held: HeldPlaces,
    ) -> Result<OpenRegion, ArenaRefused> {
        Self::open_region_over::<L>(rows, held)
    }

    /// [`Self::open_region`], the links' cells laid out for the links of `S`: for an engine over a
    /// choice of two stacks (`either_links::EitherLinks`), the region of an open whose config
    /// chose the stack `S`, whose cells hold its links and no larger.
    pub const fn open_region_over<S: CoopLinks>(
        rows: ArenaRegion,
        held: HeldPlaces,
    ) -> Result<OpenRegion, ArenaRefused> {
        #[cfg(wz_round)]
        let tables = RuntimeTables::of_shape::<C>(rows.shape());
        #[cfg(not(wz_round))]
        let tables = RuntimeTables::of_shape(rows.shape());
        let Some(runtime) = tables.placed_bytes::<C>() else {
            return Err(ArenaRefused::TooLarge);
        };
        let driver = <S as SessionLinks<LinkCount>>::LINK_CELL_BYTES;
        OpenRegion::laid(rows, &Self::open_holds(driver, &held, runtime))
    }

    /// What an open of this engine lays out after the rows its limits size (`lay_out_open`): the
    /// cells of its links, a driver's `driver` bytes, its faces' rooms, the ABI's places `held`,
    /// the runtime's span of `runtime` bytes, the engine's own place and its planes'.
    const fn open_holds(driver: usize, held: &HeldPlaces, runtime: usize) -> OpenHolds<'_> {
        OpenHolds {
            cells: cells_of::<C>(driver),
            #[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
            rooms: link_rooms_bytes::<L>(),
            held,
            runtime,
            engine: Shared::<Self>::layout().size(),
            planes: SessionPlanes::OF_BUILD,
            #[cfg(feature = "link-admission")]
            admission: core::mem::size_of::<Admission<C>>(),
            #[cfg(not(wz_round))]
            direct_face: Self::DIRECT_FACE_BYTES,
        }
    }

    /// `Self::open_in` (a build with `runtime-plan`), its config read from `source` inside the
    /// open, once, before anything else: a host that builds the config from its own values hands
    /// the source (a maker of the config is one), so neither the config nor its endpoints' texts
    /// are values of a frame the open's handshake runs under ([`OpenSource`]). An ABI that writes
    /// the texts in its own form opens with [`Self::assemble`] and [`Self::open_assembled`].
    ///
    /// The open is two frames that never lie on the stack together. The first builds the engine
    /// where it is kept (the session's state and its arena's tables, in the engine's place in the
    /// arena), and returns; the second binds the ports, joins the groups and dials over the
    /// engine it built, holding only a handle to it. So no part of the engine, and no copy of the
    /// config, is under the session's first steps. An open that fails once the engine is built
    /// ends what it began as a dropped session does (`end_links`): the ports it bound are let
    /// go of and a group it joined is told it leaves.
    ///
    /// The arena also holds the places `storage.plan` names for the ABI, lent after every table
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
        let engine = Self::assemble_from(links, clock, entropy, source, policy, key_ids, storage)?;
        Self::open_assembled(engine)
    }

    /// [`Self::assemble`] of the input `source` makes, made in this frame, which has returned
    /// before the first link is opened.
    #[inline(never)]
    fn assemble_from(
        links: L,
        clock: C,
        entropy: impl EntropySource + Send + 'static,
        source: impl OpenSource,
        policy: SessionPolicy,
        key_ids: OpenKeyIds,
        storage: OpenStorage,
    ) -> Result<EngineHold<Self>, OpenError> {
        source.open_with(|input| {
            Self::assemble(links, clock, entropy, input, policy, key_ids, storage)
        })
    }

    /// Open the links of `engine`, which [`Self::assemble`] built: an open that fails here ends
    /// what it began as a dropped session does.
    pub fn open_assembled(engine: EngineHold<Self>) -> Result<EngineHold<Self>, OpenError> {
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
    /// once, into the engine's place (`Self::engine_of`).
    ///
    /// The input is a value of no type of the ABI's ([`OpenInput`]): its config is moved into
    /// the session and its texts read and written into the rows the arena lends for them by one
    /// body of no type parameter, so no line of the ABI's is in this body.
    #[inline(never)]
    pub fn assemble(
        mut links: L,
        clock: C,
        entropy: impl EntropySource + Send + 'static,
        input: OpenInput<'_>,
        policy: SessionPolicy,
        key_ids: OpenKeyIds,
        storage: OpenStorage,
    ) -> Result<EngineHold<Self>, OpenError> {
        let OpenStorage { memory, plan } = storage;
        let OpenInput { config, endpoints } = input;
        admit_sn_widths(&config)?;
        #[cfg(feature = "shared-key-ids")]
        let key_forms = key_ids.admit(&policy, resolve_limits(&config))?;
        #[cfg(not(feature = "shared-key-ids"))]
        key_ids.admit(&policy)?;
        // The row the engine is reached through, taken before anything is reserved: an open that
        // finds no row, the fixed table full or the heap out of room, reserves nothing.
        #[cfg(any(feature = "engine-rows", test))]
        let row = RowClaim::take().ok_or(OpenError::NoEngineRow)?;
        // Where the tables take their memory on use, the engine lies in an allocation of its own,
        // claimed here, after its row where the build keeps the table of engines: an open the
        // allocator has no room for reserves nothing.
        #[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
        let claim = SharedClaim::<Self>::try_new()
            .ok_or_else(|| heap_refused(Shared::<Self>::layout().size()))?;
        // The runtime's tables are placed in the arena, so its plan holds their span.
        #[cfg(wz_round)]
        let tables = RuntimeTables::of::<C>(&config);
        #[cfg(not(wz_round))]
        let tables = RuntimeTables::of(&config);
        let from = match plan {
            PlanFrom::Region(region) => {
                // Laid out with the places of this engine over the links its maker named
                // (`Self::open_region_over`): those this open is handed.
                debug_assert_eq!(region.cell_bytes(), link_cells::<C>(&links));
                debug_assert_eq!(region.places().engine, Shared::<Self>::layout().size());
                OpenFrom::Region(region)
            }
            #[cfg(any(feature = "runtime-plan", test))]
            PlanFrom::Config(held) => OpenFrom::Config(Self::open_holds(
                links.link_cell_bytes(),
                held,
                tables
                    .placed_bytes::<C>()
                    .ok_or(OpenError::Arena(ArenaRefused::TooLarge))?,
            )),
        };
        let runtime_bytes = from.places().runtime;
        let mut lent = lend_session(&from, memory, &config, &policy).map_err(OpenError::Arena)?;
        // The texts of the endpoints, each read and written once into the row the plan laid out
        // for it: the session names an endpoint by its row from here, and a text that has no row
        // is refused here, before anything is bound or dialled.
        let written = endpoints.write_into(&mut lent.transport.endpoints);
        // Every step from here that can refuse reads what the arena lent where `lent` holds it,
        // and the runtime takes of it only its span, which has nothing to drop: a refusal lets go
        // of what was lent whole, on the one path its drop takes. The tables leave it once nothing
        // after them refuses but the heap's book of a udp port's rows (below). One refusal for the
        // three below; the rooms lie in the row the plan laid out for them, or in an allocation of
        // their own where the tables take their memory on use, reserved here and written once
        // nothing after them refuses, a handle at each place a face may hold, the dial role's and
        // each group's among them.
        let (wire, entropy, rooms_at) = written.and_then(|()| {
            // A heap with no room for the source's cell is memory the open cannot be given.
            let mut entropy =
                SessionEntropy::<SharedCount>::try_held(entropy).map_err(heap_refused)?;
            let wire = session_zid(&config, &policy, &lent.transport.endpoints, &mut entropy)?;
            #[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
            let rooms_at = lent
                .arena
                .arena_mut()
                .vacant::<LinkRooms<L::Waits>>()
                .map_err(lend_refused)?;
            // Where the tables take their memory on use, the rooms lie in an allocation of their
            // own, reserved here alike and filled at the same step: a refusal before the fill
            // gives the allocation back unwritten, and once filled their owner (`Core::rooms`)
            // gives it back after it drops them.
            #[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
            let rooms_at = OwnPlaced::<LinkRooms<L::Waits>>::vacant().map_err(OpenError::Arena)?;
            Ok((wire, entropy, rooms_at))
        })?;
        // The read slots and send places of the faces past the dial role's, each with a Router of
        // its own over the session's chain buffers, lent to its pump in a cell of its own.
        #[cfg(all(not(wz_round), feature = "listen"))]
        let taken = direct::DirectFaces::<L, C>::taken_in(
            lent.arena.arena_mut(),
            lent.taken_faces,
            &policy,
            &lent.transport.reassembly,
            lent.transport.face_chains,
        )
        .map_err(lend_refused)?;
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
        // or in the region where the build fixes the session's shape, or in the session's own state
        // where its tables take their memory on use.
        #[cfg(feature = "connectivity")]
        let face_rows = face_event_rows(config.max_faces, config.groups.len());
        #[cfg(all(feature = "connectivity", feature = "runtime-plan"))]
        let watchers =
            FacePlane::place_in(lent.arena.arena_mut(), face_rows).map_err(lend_refused)?;
        // SAFETY: the state's places were placed by the open's lend and its faces' field is
        // reached by this write alone; the block is held by `Core` after the session's state,
        // which holds the plane's owner, and neither moves nor goes back before it.
        #[cfg(all(feature = "connectivity", not(feature = "runtime-plan")))]
        let watchers =
            unsafe { StatePlaces::faces(StateLayout::places_at(lent.state.as_ptr()), face_rows) };
        // A row for each link the plan holds buffers for, reserved here: a link the session takes
        // after its open is admitted in place. The admission lies in the row the plan laid out for
        // it (`ArenaPlan::lay_admission`); its rows are the heap's, and a heap that refuses them
        // refuses the open.
        #[cfg(feature = "link-admission")]
        let admission = Admission::<C>::try_with_order(
            &wire,
            policy.link_tie_order(),
            wz_session_core::limit_binding::Quota::at_most(lent.links),
        )
        .ok_or_else(|| heap_refused(lent.links.saturating_mul(LinkBook::row_bytes())))?;
        #[cfg(feature = "link-admission")]
        let admission = lent
            .arena
            .arena_mut()
            .place(admission)
            .map_err(lend_refused)?;
        // SAFETY: the handle is held by the transport and by each link's lease, in the link's
        // actions, which the faces, the tasks and the transport hold: the engine's drop drops the
        // session's tasks before `Core` (`CoopLocalSet::drop_tasks`), and `Core` drops its
        // transport and its state before the owner, a field after theirs. Nothing changes the
        // admission through its owner.
        #[cfg(feature = "link-admission")]
        let link_admission = unsafe { admission.share() }.map(as_link_admission::<C>);
        // The faces' links keep the places the registry lends their tables at: one table of them.
        let places = lent.registry.places();
        // The waits a read makes at once, reserved here while the links hold nothing of what was
        // lent: none grows after.
        let room =
            WaitRoom::reserved(wait_room).ok_or_else(|| {
                lend_exhausted(wait_room.saturating_mul(core::mem::size_of::<
                    wz_runtime_coop::session_drive::LinkWait,
                >()))
            })?;
        // The task and timer tables and the session's local set, placed here once in the arena: no
        // spawn and no sleep of the session takes memory after its open (`open_links` seals them).
        let (runtime, local) = tables
            .runtime(clock.clone(), lent.runtime)
            .ok_or_else(|| lend_exhausted(runtime_bytes))?;
        // SAFETY: the runtime is the session's alone: it and its local set go into the `Core` made
        // below and into no other value, the opening frame owns them until the `Core` is behind
        // its `CoreLock`, and from then on every spawn, pass and handle of its tasks is reached
        // under that lock (`UnderCoreLock`'s `ConfinedOwner`); this handle is dropped here.
        unsafe { runtime.confine_tasks::<UnderCoreLock>() };
        let session_time = CoopTime::new(&runtime);
        // From here the tables leave what was lent: the links are handed theirs, and only a
        // build whose udp ports share their peers' rows can still be refused, by the heap that
        // holds the ports' book.
        links.lend_buffers(lent.transport.links);
        #[cfg(feature = "udp-listen")]
        links
            .lend_port_rows(lent.transport.port_rows)
            .map_err(heap_refused)?;
        if let Some(driver_cells) = lent.transport.cells.driver {
            links.lend_cells(driver_cells);
        }
        let (waits, room_places) = (links.waits(), lent.room_places);
        // SAFETY: the place reserved above, the arena's or the allocation of its own, was lent for
        // the rooms alone, aligned for them and valid for writes of them, where they stay.
        let rooms = unsafe {
            rooms_at.fill(|at| LinkRooms::init_at(NonNull::new_unchecked(at), waits, room_places))
        };
        // A place for each face the registry lent a set for, each face with its dial, the room
        // reserved above gathering the waits of every read: none grows after.
        let supervised = LinkSupervisor::with_room(
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
                facts: None,
                #[cfg(feature = "connectivity")]
                told: FaceTold::default(),
            },
            places,
            room,
        );
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
                #[cfg(feature = "link-admission")]
                admission: link_admission,
                wire_zid: wire,
                gate_cells: lent.transport.cells.gate,
                actions_cells: lent.transport.cells.actions,
                halves_cells: lent.transport.cells.halves,
                #[cfg(feature = "shared-key-ids")]
                key_forms,
                #[cfg(wz_round)]
                router: lent.router,
                // The Router lies beside the one link the read steps itself, apart from the
                // session's state (`direct`).
                #[cfg(not(wz_round))]
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
            #[cfg(wz_round)]
            registry_lend: RegistryLend::over(unsafe { lent.steps.registry.share() }),
            #[cfg(feature = "time-base")]
            clock_wake,
            entropy,
            config,
            policy,
            released: false,
            #[cfg(all(feature = "resource-snapshot", feature = "group"))]
            retired_groups: wz_session_core::resource_snapshot::BuildReceiveLedger::new(),
            #[cfg(wz_round)]
            links_settled: None,
            #[cfg(not(wz_round))]
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
            #[cfg(test)]
            filter_rows: core::cell::Cell::new(0),
            #[cfg(test)]
            epoch_reads: core::cell::Cell::new(0),
            #[cfg(all(test, feature = "std"))]
            plan_links: core::cell::Cell::new(0),
            #[cfg(all(feature = "group", wz_round))]
            group_reads: 0,
            #[cfg(all(feature = "group", not(wz_round)))]
            group_pumps: Vec::new(),
            #[cfg(all(
                test,
                feature = "std",
                feature = "group",
                feature = "app-transport",
                not(feature = "threads")
            ))]
            group_places_made: 0,
            #[cfg(all(test, feature = "std"))]
            task_clock_reads: core::cell::Cell::new(0),
            #[cfg(feature = "ticker")]
            tickers: Tickers::reserved(caps::MAX_TICKERS),
            session_time,
            places: lent.places,
            _steps: lent.steps,
            #[cfg(feature = "link-admission")]
            _admission: admission,
            #[cfg(not(feature = "runtime-plan"))]
            _state: lent.state,
            arena: lent.arena,
        };
        let apart = LentApart {
            #[cfg(not(wz_round))]
            router: lent.router,
            engine: lent.engine,
            handle_place: lent.handle_place,
            lodgings: lent.lodgings,
            #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
            handed: lent.transport.handed,
            #[cfg(feature = "advanced-cache")]
            cache: lent.cache,
        };
        Ok(Self::engine_of(
            core,
            apart,
            #[cfg(all(not(wz_round), feature = "listen"))]
            taken,
            #[cfg(any(feature = "engine-rows", test))]
            row,
            #[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
            claim,
        ))
    }

    /// The engine over `core`, written at the place the open lent it in the session's arena, or in
    /// the allocation of its own the open claimed for it (`claim`) where the tables take their
    /// memory on use, and counted by its holders there, put in the row `row` the open claimed for
    /// it, which reaches it without holding it (`EngineHandle`, in a build that keeps the table),
    /// with what the open lent apart from the state (`apart`) and the read slots of the faces past
    /// the dial role's (`taken`). Out of line, so the open's measure shows it apart.
    #[inline(never)]
    fn engine_of(
        core: Core<L, C>,
        apart: LentApart,
        #[cfg(all(not(wz_round), feature = "listen"))] taken: direct::TakenFaces<L, C>,
        #[cfg(any(feature = "engine-rows", test))] row: RowClaim,
        #[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))] claim: SharedClaim<
            Self,
        >,
    ) -> EngineHold<Self> {
        // The place is a span of the arena, aligned as a span starts.
        const { assert!(Shared::<Self>::layout().align() <= wz_session_core::bounded::ARENA_ALIGN) };
        let LentApart {
            #[cfg(not(wz_round))]
            router,
            engine: place,
            handle_place,
            lodgings,
            #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
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
        #[cfg(all(not(wz_round), feature = "group"))]
        let joins_groups = !core.config.groups.is_empty();
        #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
        let handed_limits = HandedLimits::new(core.config.tx_queue.sizes);
        let arena_bytes = core.arena.bytes();
        let make = |this: NonNull<Self>| {
            // SAFETY: `this` is where the `Shared` the open places lays the engine, which is
            // taken out of its row at its close and first in its drop, before its place is given
            // back.
            #[cfg(any(feature = "engine-rows", test))]
            let reach = unsafe { row.fill(this) };
            // The round hands the queries it holds to their queryables through the engine,
            // which sends what they answer. A read that steps its one link itself holds no query
            // in the round (`queries`).
            #[cfg(all(feature = "queryable", wz_round))]
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
                #[cfg(not(wz_round))]
                direct::DirectFaces::init_at(
                    NonNull::new_unchecked(addr_of_mut!((*at).direct)),
                    router,
                    #[cfg(feature = "listen")]
                    taken,
                );
                #[cfg(all(not(wz_round), feature = "group"))]
                addr_of_mut!((*at).joins_groups).write(joins_groups);
                CoreLock::init_at(NonNull::new_unchecked(addr_of_mut!((*at).core)), core);
                addr_of_mut!((*at).rooms).write(rooms);
                addr_of_mut!((*at).wait_before_drop_us).write(wait_before_drop_us);
                addr_of_mut!((*at).held_drop).write(held_drop);
                addr_of_mut!((*at).sending_on).write(AtomicU64::new(NOT_SENDING));
                #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
                os::mutex_in(
                    NonNull::new_unchecked(addr_of_mut!((*at).handed)),
                    |table| table.write(handed),
                );
                #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
                addr_of_mut!((*at).owed).write(AtomicBool::new(false));
                #[cfg(wz_round)]
                addr_of_mut!((*at).input_held).write(AtomicBool::new(false));
                #[cfg(all(feature = "threads", wz_round))]
                HandBack::init_at(NonNull::new_unchecked(addr_of_mut!((*at).hand_back)));
                #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
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
                #[cfg(any(feature = "engine-rows", test))]
                addr_of_mut!((*at).reach).write(reach);
            }
        };
        // Each field of the engine is written above, one statement each: a field added to the
        // engine and not there fails this pattern.
        let _every_field_is_written = |engine: &Self| {
            let Self {
                #[cfg(not(wz_round))]
                    direct: _,
                #[cfg(all(not(wz_round), feature = "group"))]
                    joins_groups: _,
                core: _,
                rooms: _,
                wait_before_drop_us: _,
                held_drop: _,
                sending_on: _,
                #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
                    handed: _,
                #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
                    owed: _,
                #[cfg(wz_round)]
                    input_held: _,
                #[cfg(all(feature = "threads", wz_round))]
                    hand_back: _,
                #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
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
                #[cfg(any(feature = "engine-rows", test))]
                    reach: _,
            } = engine;
        };
        // SAFETY: the place was lent to the engine alone, aligned as asserted above and as large as
        // `Shared::<Self>::layout`, in the arena `place.memory` keeps; the engine is read through
        // its place only once it is written.
        #[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
        let engine = unsafe { Shared::placed_with(place.at, place.memory, make) };
        // SAFETY: the claim is this open's alone; `place` is the count of the session's arena, live
        // while the arena is held, which the engine's state holds; the engine is read through its
        // place only once `make` has written it whole.
        #[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
        let engine = unsafe { claim.made_with(place, make) };
        EngineHold::of(engine)
    }

    /// Open the links of the engine [`Self::assemble`] built: the ports bound and the groups
    /// joined before anything is dialled, so a session that cannot listen, or join a group, where
    /// it was told to does not open; then the first endpoint dialled and the session stepped on
    /// this thread until the dial settles. A session that only listens, or only joins groups, is
    /// open once it is bound and joined; one that dials is open once a link completes its
    /// handshake. Never inlined: what it holds under the session's first steps is the guard of the
    /// engine's state, which nothing else can take before the open returns the engine.
    #[cfg(wz_round)]
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
                let mut wait = core.idle_wait(NO_STEP_BOUND_MS);
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

    /// Where the faces' rooms lie, which the test of the form that holds them apart reads.
    #[cfg(all(
        test,
        feature = "std",
        all(feature = "tables-on-use", not(feature = "runtime-plan"))
    ))]
    pub(crate) fn rooms_place(&self) -> *const u8 {
        core::ptr::from_ref::<LinkRooms<L::Waits>>(&self.rooms).cast::<u8>()
    }

    /// Whether `at` is a byte of the session's arena.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn arena_holds(&self, at: *const u8) -> bool {
        self.core.lock().0.arena.holds(at)
    }

    /// Whether `at` is a byte of the state the places of the session's own values lie in: the
    /// region the build fixes the session's shape in, the head of the block its arena is the tail
    /// of, or the session's own state where its tables take their memory on use.
    #[cfg(all(
        test,
        feature = "std",
        not(feature = "runtime-plan"),
        any(feature = "queryable", feature = "query", feature = "connectivity")
    ))]
    pub(crate) fn state_holds(&self, at: *const u8) -> bool {
        let start = self.core.lock().0._state.as_ptr().as_ptr() as usize;
        (start..start + core::mem::size_of::<StateLayout>()).contains(&(at as usize))
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

    /// How many cells of the session's table of links' gates hold a link's gates now: `None` for
    /// a session whose plan laid out no such table.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn link_gates_in_use(&self) -> Option<usize> {
        self.core
            .lock()
            .0
            .transport
            .gate_cells
            .as_ref()
            .map(LentByteCells::in_use)
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
    #[cfg(all(test, feature = "std", feature = "connectivity"))]
    pub(crate) fn face_plane(&self) -> &FacePlane {
        &self.faces
    }

    /// The session's say on a second link to a node, the one its links' handshakes ask, for a
    /// test that asks it as they do.
    #[cfg(all(test, feature = "std", feature = "link-admission"))]
    pub(crate) fn link_admission(&self) -> PlacedRef<dyn LinkAdmission> {
        self.core.lock().0.transport.admission
    }

    /// Run `f` on the session's local set under the session's lock, for a test that spawns a
    /// task of the session's: the runtime is confined to that lock (`confine_tasks`), so the set
    /// is used under it and a handle of it taken out is used only once the engine has gone. A
    /// session whose read steps each face where it lies runs no link as a task.
    // Its one reader is `tests::admission_heap`, compiled with the link admission.
    #[cfg(all(
        test,
        feature = "std",
        feature = "listen",
        feature = "link-admission",
        wz_round
    ))]
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
    /// readers are: the tests of a full group's stage over the program's transport, in both forms
    /// of the engine's calls, where a held session waits for room (`tests::group_congested`,
    /// under `tx-held-wait`).
    #[cfg(all(
        test,
        feature = "std",
        feature = "group",
        feature = "app-transport",
        feature = "tx-held-wait"
    ))]
    pub(crate) fn rooms(&self) -> &LinkRooms<L::Waits> {
        &self.rooms
    }

    /// How many messages of `priority` the session put on its groups were dropped for want of
    /// room on the group's stage. Compiled where its readers are, as [`Self::rooms`] is.
    #[cfg(all(test, feature = "std", feature = "group", feature = "app-transport"))]
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
    /// where its readers are: the tests of a full group's drops, in both forms of the engine's calls
    /// (`tests::group_congested`, `transport-stats`).
    #[cfg(all(
        test,
        feature = "std",
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
                .links
                .faces()
                .filter(|face| face.facts().is_some())
                .count()
        })
    }

    /// How many of the session's links owe their stack the rest of a frame it took only in part,
    /// each holding an outbound slot for it. Compiled where its readers are (`tests::tx_pool`).
    #[cfg(all(test, feature = "std", feature = "listen", feature = "tx-probe"))]
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
            let (_, wire) = core.0.up_wires_at().next()?;
            lend_actions(wire, |actions: &LinkActions<C>| {
                (actions.batch_lend_counts(), actions.frame_lend_counts())
            })
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

    /// How often a put looked its write filter's row up since the open (`Self::filter_row`):
    /// what a test of the cost of a put through a filter counts. Read under the lock, uncounted as
    /// a take.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn filter_rows(&self) -> usize {
        self.core.lock().0.filter_rows.get()
    }

    /// How often the session's send epoch was read since the open (`Core::send_epoch`): what a
    /// test of the cost of a put through a filter's plan counts. Read under the lock, uncounted as
    /// a take.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn epoch_reads(&self) -> usize {
        self.core.lock().0.epoch_reads.get()
    }

    /// How many links a put's plan asked how they name its key since the open
    /// (`Self::keep_plan`): what a test of the cost of a plan counts. Read under the lock,
    /// uncounted as a take.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn plan_links(&self) -> usize {
        self.core.lock().0.plan_links.get()
    }

    /// How often the session moved its links on since the open (`Core::link_polls`): what a
    /// test of the cost of a batch counts. Read under the lock, uncounted as a take.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn link_polls(&self) -> usize {
        self.core.lock().0.link_polls.get()
    }

    /// How often the faces' tables were handed out to a write since the open
    /// (`RegistryOf::faces_written`): what a test of the bookkeeping a received sample owes counts.
    /// Read under the lock, uncounted as a take.
    #[cfg(all(
        test,
        feature = "group",
        feature = "app-transport",
        feature = "threads",
        not(wz_round)
    ))]
    pub(crate) fn faces_written(&self) -> u64 {
        self.core.lock().0.session.registry.faces_written()
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

    /// The most a read waits now for the earliest deadline of the session's gets, in whole
    /// milliseconds, as the index of their deadlines answers the read ([`Core::idle_wait`]); `None`
    /// when no get is due by time. Under the lock, uncounted as a reading of the session's clock.
    #[cfg(all(test, feature = "std", feature = "query"))]
    pub(crate) fn get_wait_ms(&self) -> Option<u32> {
        let mut held = self.core.lock();
        let core = &mut held.0;
        core.session
            .next_get_deadline_ms()
            .map(|due_ms| Core::<L, C>::wait_until(u32::MAX, due_ms, core.clock.now_us()))
    }

    /// Run `f` on the session's one reassembly Router with the time now on the epoch its chains
    /// are staged on: what a test of the chains the session's step ends stages its chain in and
    /// reads them by. Under the lock, uncounted as a take and as a reading of the session's clock.
    #[cfg(all(test, feature = "std", wz_round))]
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

    /// Where the link of the face at row `at` stands, as the life of its record says: what a test
    /// of a face beside the dial role's reads. `None` for a row no face holds. Read under the
    /// lock, uncounted as a take.
    #[cfg(all(test, feature = "std", feature = "listen", not(wz_round)))]
    pub(crate) fn face_phase(&self, at: usize) -> Option<wz_session_core::link_life::LinkPhase> {
        self.core
            .lock()
            .0
            .transport
            .links
            .face(at)
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

    /// How many places for a group's session the session made since the open, its first join
    /// of each group and each join again (`Core::seat_group`). Compiled where its reader is: the
    /// groups of one thread over the program's transport (`tests::one_thread::group`).
    #[cfg(all(
        test,
        feature = "std",
        feature = "group",
        feature = "app-transport",
        not(feature = "threads")
    ))]
    pub(crate) fn group_places_made(&self) -> usize {
        self.core.lock().0.group_places_made
    }

    /// How many samples the session handed to its subscribers' callbacks since the open, each
    /// counted once however many callbacks it reached, whichever way it was delivered: what a
    /// test of the cost of one received sample counts.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn samples_handed(&self) -> usize {
        #[cfg(not(wz_round))]
        let pinned = self.takes.pinned_samples.load(Ordering::Relaxed);
        #[cfg(wz_round)]
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
        #[cfg(not(wz_round))]
        let pinned = self.takes.pinned_lent.load(Ordering::Relaxed);
        #[cfg(wz_round)]
        let pinned = 0;
        #[cfg(wz_round)]
        let round = self.samples.tally().lent();
        #[cfg(not(wz_round))]
        let round = 0;
        round + pinned
    }

    /// How many peers' replies the read handed to the get each answers itself, with nothing of
    /// them held in the round (`replies`).
    #[cfg(all(test, feature = "std", feature = "query", not(wz_round)))]
    pub(crate) fn replies_handed_by_the_read(&self) -> usize {
        self.takes.pinned_replies.load(Ordering::Relaxed)
    }

    /// How many calls of the session's queryables the read made itself for the peers' queries, one
    /// for each queryable a query reached, with nothing of them held in the round (`queries`).
    #[cfg(all(test, feature = "std", feature = "queryable", not(wz_round)))]
    pub(crate) fn queries_handed_by_the_read(&self) -> usize {
        self.takes.pinned_queries.load(Ordering::Relaxed)
    }

    /// How many turns of an answer held their link's replies to leave with the Final in one send,
    /// each counted where it let them go ([`Self::answer`]). Compiled where its reader is: a build
    /// whose links a task or a listener reads (`tests::queryable`).
    #[cfg(all(
        test,
        feature = "std",
        feature = "queryable",
        feature = "query-replies-with-final",
        any(feature = "threads", feature = "listen", feature = "group")
    ))]
    pub(crate) fn answers_held(&self) -> usize {
        self.takes.held_answers.load(Ordering::Relaxed)
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

    /// The lent Responses and ResponseFinals the session's links handed to the pending gets alone
    /// (`Registry::dispatch_reply`).
    #[cfg(all(test, feature = "std", feature = "query"))]
    pub(crate) fn reply_dispatches(&self) -> usize {
        self.core.lock().0.session.registry.reply_dispatches()
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

    /// The session's state for an operation that sends on the faces, with what it sends through
    /// (`LinkTx`): the session's lock alone, where each face's record holds its link and is
    /// reached under it. `None` once the session is closed.
    #[cfg(wz_round)]
    fn live_on_link<U>(&self, f: impl FnOnce(&mut Core<L, C>, LinkTx<'_, C>) -> U) -> Option<U> {
        let mut guard = self.live()?;
        Some(f(&mut guard.0, core::marker::PhantomData))
    }

    /// A publish's leg to the faces (`LinkTx`), for one that takes the session's lock its own
    /// way: one leg through nothing, where each face's record holds its link and is reached under
    /// that lock.
    #[cfg(wz_round)]
    #[inline(always)]
    fn on_faces(
        &self,
        _droppable: bool,
        leg: impl FnOnce(LinkTx<'_, C>) -> Result<usize, FanoutError>,
    ) -> Result<usize, FanoutError> {
        leg(core::marker::PhantomData)
    }

    /// The session's state for a publish's leg to its links. A publish that may not be dropped
    /// waits for it ([`Self::live`]). One that may is not held behind a send that holds the
    /// session while it waits for room on a link, up to `wait_before_close` for a blocking one:
    /// zenoh bounds a droppable message's wait by `wait_before_drop`
    /// (`commons/zenoh-config/src/defaults.rs` @ `wait_before_drop: 1000,`), where its own pipeline
    /// would queue it behind the blocking one on the stage that one holds
    /// (`io/zenoh-transport/src/common/pipeline.rs` @ `let mut queue = zlock!(self.stage_in[idx]);`).
    /// So it takes the session when it is free, and while it is held asks the faces that are up
    /// for room with nothing of the session held, or the one face whose send place the leg holds,
    /// at place `leg`, where each face's place is taken on its own. A face with no room within `wait_before_drop`
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
    fn live_to_publish(&self, droppable: bool, leg: Option<usize>) -> ToPublish<'_, L, C> {
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
            let room =
                self.rooms
                    .for_held(self.held_drop, self.holder(), self.wait_before_drop_us, leg);
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
                #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
                Behind::Dropped { on, told } => ToPublish::DroppedOn {
                    faces: match on {
                        DropSet::Faces(faces) => faces,
                        DropSet::Face(place) => self.rooms.dropped_on(place_of_mark(place)),
                    },
                    told,
                },
                // The dial face alone: the face congested, or held by another publish's send, is
                // that face, and there is no other to owe the publish to.
                #[cfg(not(all(wz_round, any(feature = "listen", feature = "group"))))]
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
            for (_, wire) in core.0.up_wires_at() {
                lend_actions(wire, |actions: &LinkActions<C>| {
                    report.absorb(&actions.stats_report());
                });
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

    /// What the receive paths of the session's links and groups counted (`resource-snapshot`),
    /// those up and those let go of (`LinkSupervisor::message_reading`, `Core::retired_groups`),
    /// as one reading that only grows. Read under the session's lock, the one a link or a join is
    /// let go of under, so one that goes meanwhile is counted once; a closed session reads what
    /// its links and groups had counted when they ended.
    #[cfg(feature = "resource-snapshot")]
    pub fn message_reading(&self) -> wz_session_core::resource_snapshot::BuildMessageReading {
        let held = self.core.lock();
        #[cfg(feature = "group")]
        {
            let groups = held.0.transport.groups.iter();
            let mut total = held
                .0
                .retired_groups
                .total(groups.map(|group| group.message_reading()));
            total.merge(&held.0.transport.links.message_reading());
            total
        }
        #[cfg(not(feature = "group"))]
        {
            held.0.transport.links.message_reading()
        }
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
        #[cfg(all(test, not(wz_round)))]
        self.takes.delivers.fetch_add(1, Ordering::Relaxed);
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
            wz_round
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
            not(wz_round)
        ))]
        if self.hand_decl_watches() {
            handed = true;
            while self.hand_out() {}
        }
        // The tokens of a lost link the round had no room for, retracted now the round is handed
        // out, each round sealed as the session is let go of and handed out in turn.
        #[cfg(all(feature = "liveliness", wz_round))]
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
        not(wz_round)
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
        self.answer(
            generation,
            query.rid(),
            query::Release::Hold,
            onward.raised(),
        );
    }

    /// One put of the session, the body every put goes through: a publish with options
    /// (`SessionEngine::publish_on_wire_all`, `SessionEngine::publish_filtered`) and a plain put
    /// through a write filter (`SessionEngine::publish_filtered` with none,
    /// `SessionEngine::put_plain_filtered`), sent to the peers the session's faces reach, then to
    /// its own subscribers, as zenoh-pico's `_z_write` sends one put over its transmit path.
    /// Each face's leg (`Self::put_leg`) takes the session in its turn; the first that holds it
    /// answers the put (`Asked`), and a put no leg held the session for is answered here, by a
    /// take of its own. A link that is down skips it, as a send over it would.
    ///
    /// `Suppressed` with nothing sent when the put's filter holds it back, `NotPlain` with
    /// nothing sent for a plain put this node does not send plain (no plain way kept, a
    /// subscriber of the session that wants it, a group the general publish reaches), for the
    /// caller to send it the general way.
    // Out of line: the doors' three entries send through this one body.
    #[inline(never)]
    fn put_on_links(&self, put: &PutOn<'_>) -> FilteredPut {
        // This engine numbers none of its links, offers no frame without waiting and reserves
        // none, so a publish that states a set of links, a retry or the all-or-none form is
        // refused by name before anything is sent, to a link or to a subscriber of the session:
        // a refusal of the call, whatever its filter answers.
        if let PutBy::Options(opts) = put.by {
            if let Err(refused) = StatementNotHonoured::of_publish(opts) {
                return FilteredPut::Sent(Err(refused.into()));
            }
        }
        // Each face's place is taken before the session, as every send on it takes them; one that
        // may be dropped is not held behind another holder of a face's place (`direct`). A plain
        // put's way lies in its filter's row, so it is not known before the take: it is taken as a
        // put that may not be dropped, as it was before it was one body with the publish.
        let (droppable, remote) = match put.by {
            PutBy::Options(opts) => (
                face_send::droppable(
                    opts.reliable_bool(),
                    opts.qos.unwrap_or(QosLevel::DEFAULT).congestion(),
                ),
                opts.allowed_destination.allows_remote(),
            ),
            PutBy::Plain(given) => (
                false,
                given.is_none_or(|params| params.destination.allows_remote()),
            ),
        };
        let asked = Asked::new();
        let sent = if remote {
            // Where each face's leg is sent apart, the groups' leg is a body of its own, which
            // reads none of what a face's leg reads to send on a face's link. Where the faces share
            // one send place, the one leg reaches the groups too (`FaceTx::reaches_groups`).
            #[cfg(all(wz_face_places, feature = "group"))]
            {
                self.on_publish_legs(
                    droppable,
                    |tx| self.put_leg(put, &asked, tx),
                    |tx| match put.by {
                        PutBy::Options(opts) => self.publish_to_groups_on(put, opts, &asked, tx),
                        PutBy::Plain(_) => self.put_plain_groups_leg(put, &asked),
                    },
                )
            }
            #[cfg(not(all(wz_face_places, feature = "group")))]
            {
                self.on_faces(droppable, |tx| self.put_leg(put, &asked, tx))
            }
        } else {
            Ok(0)
        };
        let answer = match asked.answer.get() {
            Some(answer) => answer,
            None => self.decide_alone(put, &asked),
        };
        match answer {
            Answer::HeldBack => return FilteredPut::Suppressed,
            Answer::NotPlain => return FilteredPut::NotPlain,
            Answer::Through => {}
        }
        let sent = match sent {
            Ok(sent) => sent,
            Err(error) => return FilteredPut::Sent(Err(error)),
        };
        // The session's own subscribers after the link, and nothing local when the link refused
        // it; a plain put one of them wants was answered `NotPlain` for the general publish.
        #[cfg(feature = "local-subscriber")]
        let sent = match put.by {
            PutBy::Options(opts) => {
                match self.publish_to_subscribers(put.keyexpr, put.payload, opts) {
                    Ok(more) => sent.saturating_add(more),
                    Err(error) => return FilteredPut::Sent(Err(error)),
                }
            }
            PutBy::Plain(_) => sent,
        };
        FilteredPut::Sent(Ok(sent))
    }

    /// What `asked` answered of `put`, and where no leg held the session (no link took it, its
    /// destination admits no peer, or it was dropped before) or a leg waits for its link's room
    /// before it takes the session, the answer read now by a take of its own, nothing sent
    /// (`Self::decide_put`). A closed session holds nothing back, as
    /// `SessionEngine::write_filter_holds_back` answers.
    // Out of line: a put whose leg held the session was answered there, and takes none of this.
    #[inline(never)]
    fn decide_alone(&self, put: &PutOn<'_>, asked: &Asked) -> Answer {
        if let Some(answer) = asked.answer.get() {
            return answer;
        }
        // A publish no publisher made has no filter to ask, and takes nothing to learn it.
        if put.filter.is_none() && matches!(put.by, PutBy::Options(_)) {
            return Answer::Through;
        }
        let answer = self.live().map_or(Answer::Through, |core| {
            match Self::decide_put(&core.0, put, true) {
                PutGoes::Unsent(answer) => answer,
                PutGoes::Plain(..) | PutGoes::Options(_) => Answer::Through,
            }
        });
        asked.answer_first(answer);
        answer
    }

    /// How the leg of `put` that holds `core` sends it, `first` when no leg of the put answered it
    /// before (`Asked`). The filter's row is looked up once, for its plan, its answer and the plain
    /// way it keeps, whose head the leg's send writes a plain Put from (`Publication::head`). A
    /// plain put of the row's way on the row's key at the send epoch its way was planned at is
    /// written from the plan, as what the filter's answer, the key's naming and each link's form
    /// of it are read from is as it was then; a group the session joined since is sent it the
    /// general way, which no epoch counts. The first leg asks the filter, which holds the put
    /// back on this session unless the session holds a group it does not ask
    /// (`Self::holds_back_in`), and of a plain put whether it is plain on this node.
    // Inlined whole: the leg that sends a put reads it in its own body, as a put's path is the one
    // a message takes each time.
    #[inline(always)]
    fn decide_put<'r>(core: &'r Core<L, C>, put: &PutOn<'_>, first: bool) -> PutGoes<'r> {
        // The registry itself, not its holder: the filter reads it as what the peers declare.
        let registry: &Registry = &core.session.registry;
        let row = Self::filter_row(core, put.filter);
        // The send epoch is read once, for a bare put of the row's way where no group the session
        // joined is sent it the general way: the plan stands at it or not, and the first leg plans
        // the way at this same reading once the put is sent. A `wz_round` build that sends what
        // was handed to the session before the put may move the epoch in between; a plan kept at
        // the earlier reading is then never taken, which costs one more put that is named, and
        // sends none as planned at an epoch that moved.
        let plan_at = match (put.by, row) {
            (PutBy::Plain(None), Some(row)) => {
                #[cfg(feature = "group")]
                let groups_left = core.transport.groups.is_empty();
                #[cfg(not(feature = "group"))]
                let groups_left = true;
                if groups_left {
                    let epoch = core.send_epoch();
                    if let Some(planned) = row.planned_put(epoch, put.keyexpr) {
                        return PutGoes::Plain(planned.params(), PlainBy::Planned(planned));
                    }
                    first.then_some(epoch)
                } else {
                    None
                }
            }
            _ => None,
        };
        if first
            && !Self::filters_left_unasked(core)
            && row.is_some_and(|row| !tables(registry).write_filter_row_open(row, registry))
        {
            return PutGoes::Unsent(Answer::HeldBack);
        }
        // The way the row keeps, read once: what a bare put is sent from, and the head any plain
        // Put of the filter's entity is written from, one with options among them.
        let way = row.and_then(|row| row.plain());
        let head = way.and_then(|way| way.head);
        let params = match put.by {
            PutBy::Options(_) => return PutGoes::Options(head),
            PutBy::Plain(Some(params)) => params,
            PutBy::Plain(None) => match way {
                Some(way) => way.params,
                None => return PutGoes::Unsent(Answer::NotPlain),
            },
        };
        // A put one of the session's own subscribers wants is the general publish's, which sends
        // it and delivers it there.
        #[cfg(feature = "local-subscriber")]
        if first
            && params.destination.allows_local()
            && wz_session_core::pubsub::LocalSubscribers::has_local_matching(
                tables(registry),
                put.keyexpr,
            )
        {
            return PutGoes::Unsent(Answer::NotPlain);
        }
        if !params.destination.allows_remote() {
            return PutGoes::Unsent(Answer::Through);
        }
        // A group is sent a put by the general publish, which pushes it onto the group's stage,
        // where no leg of the put is the groups' own.
        #[cfg(all(wz_round, feature = "group"))]
        if first && !core.transport.groups.is_empty() {
            return PutGoes::Unsent(Answer::NotPlain);
        }
        PutGoes::Plain(params, PlainBy::Named { head, plan_at })
    }

    /// The row of write filter `filter`: `None` for a put no publisher made, or a filter the
    /// tables hold no more. What a put's leg reads its plan, its filter's answer and its plain way
    /// from (`Self::decide_put`), and what its first plain put at a send epoch plans
    /// (`Self::keep_plan`): the one place a put looks the row up.
    #[inline(always)]
    fn filter_row(
        core: &Core<L, C>,
        filter: Option<FilterId>,
    ) -> Option<
        &wz_session_core::session_tables::WriteFilterRow<
            <RowPolicy as wz_session_core::bounded::Storage>::Key,
        >,
    > {
        let handle = row_of(filter?)?;
        #[cfg(test)]
        core.filter_rows.set(core.filter_rows.get() + 1);
        tables(&core.session.registry).write_filters().get(handle)
    }

    /// The groups' leg of a publish where each face's leg is sent apart
    /// (`Self::put_on_links`): the session taken as a face's leg takes it, and the put sent to
    /// each group as the groups' part of a face's leg sends it (`Self::publish_to_groups`),
    /// with none of that leg's work for the faces: no key looked up in the session's tables, no
    /// plan of its publisher read, and no walk of the faces' links. A key a face's leg refuses
    /// (`Self::leg_of`, an empty key, which names nothing whatever declaration it is named by) is
    /// refused here too, as zenoh refuses a key that is not one on every transport alike.
    #[cfg(all(wz_face_places, feature = "group"))]
    #[inline(never)]
    fn publish_to_groups_on(
        &self,
        put: &PutOn<'_>,
        opts: &PublishOptions,
        asked: &Asked,
        tx: LinkTx<'_, C>,
    ) -> Result<usize, FanoutError> {
        if asked.stops() {
            return Ok(0);
        }
        let meta = opts.push_metadata();
        let congestion = meta.qos.unwrap_or(QosLevel::DEFAULT).congestion();
        let droppable = face_send::droppable(opts.reliable_bool(), congestion);
        let mut core = match self.live_to_publish(droppable, tx.leg_place()) {
            ToPublish::Live(core) => core,
            ToPublish::Closed => return Ok(0),
            ToPublish::DroppedOn { told } => {
                return if told {
                    Err(FanoutError::HeldConduit)
                } else {
                    Ok(0)
                };
            }
        };
        let first = asked.first();
        if let PutGoes::Unsent(answer) = Self::decide_put(&core.0, put, first) {
            asked.answer_first(answer);
            return Ok(0);
        }
        asked.answer_first(Answer::Through);
        if NamedKey::literal(put.keyexpr).is_none() {
            return Err(FanoutError::ExceedsCapacity);
        }
        let send = wz_session_core::session_actions::SendAs {
            reliable: opts.reliable_bool(),
            express: meta.is_express(),
            priority: opts.priority_band(),
        };
        let publication = Publication {
            keyexpr: put.keyexpr,
            wire: put.wire,
            payload: put.payload,
            kind: opts.kind,
            meta: &meta,
            send,
            head: None,
        };
        let _publishing = SendingOn::enter(&self.sending_on, PUBLISHING);
        self.publish_to_groups(&mut core.0, &publication, send, None, tx)
    }

    /// The groups' own leg of a plain put (`PutBy::Plain`) where each face's leg is sent apart:
    /// the session taken as a face's leg of a plain put takes it, the put answered as the first
    /// leg answers it when no face's leg did, and written from its plain way onto each group the
    /// session joined, as the general publish's groups' leg writes it (`Self::publish_to_groups`),
    /// its key named as `put.wire` names it. Nothing is named in the session's tables, which a
    /// group's key does not read, and no plan is kept. An empty key is left to the general publish
    /// (`NotPlain`), which refuses it on every leg alike.
    #[cfg(all(wz_face_places, feature = "group"))]
    #[inline(never)]
    fn put_plain_groups_leg(&self, put: &PutOn<'_>, asked: &Asked) -> Result<usize, FanoutError> {
        if asked.stops() {
            return Ok(0);
        }
        let Some(core) = self.live() else {
            return Ok(0);
        };
        let params = match Self::decide_put(&core.0, put, asked.first()) {
            PutGoes::Plain(params, PlainBy::Named { .. }) => params,
            PutGoes::Unsent(answer) => {
                asked.answer_first(answer);
                return Ok(0);
            }
            // A plan stands at an epoch no group was joined at, and a put by options goes by the
            // groups' leg of its own: neither is this leg's to send.
            PutGoes::Plain(_, PlainBy::Planned(_)) | PutGoes::Options(_) => {
                asked.answer_first(Answer::Through);
                return Ok(0);
            }
        };
        if put.keyexpr.is_empty() {
            asked.answer_first(Answer::NotPlain);
            return Ok(0);
        }
        asked.answer_first(Answer::Through);
        // A plain put carries its QoS and nothing else of a publication's.
        let meta = PushMetadata {
            qos: params.qos,
            ..PushMetadata::default()
        };
        let group_put = GroupPut {
            keyexpr: put.keyexpr,
            wire: put.wire,
            payload: put.payload,
            kind: SampleKind::Put,
            meta: &meta,
            reliable: params.reliable,
            priority: params.priority,
        };
        let _publishing = SendingOn::enter(&self.sending_on, PUBLISHING);
        self.put_on_groups(&core.0, group_put)
    }

    /// `put`'s leg through `tx`, what the caller holds of the one link (`Self::put_on_links`):
    /// the session taken as the put's options say, the put answered by the first leg that holds
    /// it (`Self::decide_put`), and sent from its plan, from its plain way or from its options,
    /// each publish of a run as the face send value orders it (`PublishRun`).
    #[inline(always)]
    fn put_leg(
        &self,
        put: &PutOn<'_>,
        asked: &Asked,
        tx: LinkTx<'_, C>,
    ) -> Result<usize, FanoutError> {
        if asked.stops() {
            return Ok(0);
        }
        // zenoh's `is_droppable` (`face_send::droppable`). A message with no QoS of its own is sent
        // with the default's, as the send reads it. A plain put's facts are read under the take.
        let options = match put.by {
            PutBy::Options(opts) => Some((opts, opts.push_metadata())),
            PutBy::Plain(_) => None,
        };
        let droppable = options.as_ref().is_some_and(|(opts, meta)| {
            face_send::droppable(
                opts.reliable_bool(),
                meta.qos.unwrap_or(QosLevel::DEFAULT).congestion(),
            )
        });
        // A blocking publish waits for its face's room with that face's send place held and
        // nothing of the session, as zenoh-pico's blocking put waits under its transmit lock
        // alone: a wait under the session's lock would hold up every other face's send and the
        // read, up to `wait_before_close`. Where no other thread reaches the session, nothing
        // waits behind it. The wait comes before the session is taken, so the filter is asked
        // first, by a take of its own: a put the filter holds back waits for nothing.
        #[cfg(not(wz_round))]
        if !droppable && <CoopForm as ThreadForm>::OTHER_THREADS {
            if let Some((opts, _)) = &options {
                if tx.alone_wire().is_some() && self.decide_alone(put, asked) != Answer::Through {
                    return Ok(0);
                }
                match tx.wait_for_room(opts.priority_band()) {
                    Ok(wz_session_core::session_actions::WireRoom::Send) => {}
                    // The drop the send would have made past its wait, settled by the wait.
                    Ok(wz_session_core::session_actions::WireRoom::Expired) => return Ok(0),
                    Err(error) => return leg_outcome(Err(error)),
                }
            }
        }
        #[cfg(not(wz_round))]
        let leg = tx.leg_place();
        #[cfg(wz_round)]
        let leg = None;
        let mut core = match self.live_to_publish(droppable, leg) {
            ToPublish::Live(core) => core,
            ToPublish::Closed => return Ok(0),
            ToPublish::DroppedOn {
                #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
                faces,
                told,
            } => {
                // A put handed off is sent by a later holder, which asks no filter: one the filter
                // holds back is not handed.
                #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
                if let Some((opts, _)) = &options {
                    if self.decide_alone(put, asked) == Answer::Through {
                        self.hand_off(put.keyexpr, put.payload, opts, faces);
                    }
                }
                return if told {
                    Err(FanoutError::HeldConduit)
                } else {
                    Ok(0)
                };
            }
        };
        let first = asked.first();
        let plain_meta;
        let (kind, meta, send, head, plan_at) = match Self::decide_put(&core.0, put, first) {
            PutGoes::Unsent(answer) => {
                asked.answer_first(answer);
                return Ok(0);
            }
            PutGoes::Plain(params, by) => {
                // A plain put carries its QoS and nothing else of a publication's, and rides as its
                // facts say, whether its plan writes it or its key is named.
                plain_meta = PushMetadata {
                    qos: params.qos,
                    ..PushMetadata::default()
                };
                let send = wz_session_core::session_actions::SendAs {
                    reliable: params.reliable,
                    express: params.express,
                    priority: params.priority,
                };
                match by {
                    PlainBy::Planned(planned) => {
                        asked.answer_first(Answer::Through);
                        #[cfg(test)]
                        self.takes.plans.fetch_add(1, Ordering::Relaxed);
                        // A blocking put whose leg holds its face alone is sent with that face's
                        // send place held and nothing of the session, as a put by options is
                        // (`Self::publish_alone`) and as zenoh-pico's blocking put sends under its
                        // transmit lock alone: a send under the session's lock holds the read up
                        // for the whole system call, through which a loopback peer may already
                        // have answered, and for as long as the sending thread is off its CPU.
                        #[cfg(not(wz_round))]
                        if <CoopForm as ThreadForm>::OTHER_THREADS
                            && !face_send::droppable(
                                params.reliable,
                                params.qos.unwrap_or(QosLevel::DEFAULT).congestion(),
                            )
                        {
                            if let (Some(alone), Some(named)) =
                                (tx.alone_wire(), planned.key_on(put.keyexpr))
                            {
                                let leg = LinkLeg {
                                    named,
                                    payload: put.payload,
                                    kind: SampleKind::Put,
                                    meta: &plain_meta,
                                    send,
                                    head: Some(planned.head()),
                                    planned: true,
                                };
                                #[cfg(feature = "listen")]
                                let short = probes(false, core.0.transport.tx_pool_short);
                                #[cfg(not(feature = "listen"))]
                                let short = false;
                                let (up, run) = Self::alone_run(&core.0, tx, short);
                                drop(core);
                                return self.send_leg_alone(&leg, alone, tx, up, run, Ok(0));
                            }
                        }
                        let leg = LinkLeg {
                            named: planned.key(),
                            payload: put.payload,
                            kind: SampleKind::Put,
                            meta: &plain_meta,
                            send,
                            head: Some(planned.head()),
                            planned: true,
                        };
                        // Marked as a publish for as long as it holds the session, as every put is.
                        let _publishing = SendingOn::enter(&self.sending_on, PUBLISHING);
                        return self
                            .send_on_links(&core.0, &leg, None, Pass::EVERY_FACE, tx)
                            .0;
                    }
                    PlainBy::Named { head, plan_at } => {
                        #[cfg(test)]
                        self.takes.namings.fetch_add(1, Ordering::Relaxed);
                        (SampleKind::Put, &plain_meta, send, head, plan_at)
                    }
                }
            }
            PutGoes::Options(head) => {
                // A put by options read them before the take.
                let Some((opts, meta)) = &options else {
                    return Ok(0);
                };
                let send = wz_session_core::session_actions::SendAs {
                    reliable: opts.reliable_bool(),
                    express: meta.is_express(),
                    priority: opts.priority_band(),
                };
                (opts.kind, meta, send, head, None)
            }
        };
        asked.answer_first(Answer::Through);
        let publication = Publication {
            keyexpr: put.keyexpr,
            wire: put.wire,
            payload: put.payload,
            kind,
            meta,
            send,
            head,
        };
        // A blocking leg that holds its face alone is sent with that face's send place held and
        // nothing of the session, as zenoh-pico's blocking put sends under its transmit lock
        // alone: every wait of its send for the link's room (each fragment's of a chain) would
        // otherwise hold up every other face's leg and the read. A session whose links share
        // fewer outbound slots than they are waits for one its own way, below.
        #[cfg(not(wz_round))]
        if !droppable && <CoopForm as ThreadForm>::OTHER_THREADS && options.is_some() {
            #[cfg(feature = "listen")]
            let short = probes(droppable, core.0.transport.tx_pool_short);
            #[cfg(not(feature = "listen"))]
            let short = false;
            if let Some(alone) = tx.alone_wire() {
                return self.publish_alone(core, &publication, alone, tx, short);
            }
        }
        // Marked as the holder for as long as it holds the session: a droppable publish that
        // finds it held between this one's sends tries the session again, where one behind what
        // is not a publish waits for it.
        let publishing = SendingOn::enter(&self.sending_on, PUBLISHING);
        // A put that may not be dropped, on a session whose links share fewer outbound slots than
        // they are, may find every slot held by another link's frame its stream has not finished.
        // It then waits for one with nothing of the session held, as zenoh-pico's blocking put
        // waits for its transmit lock, within its `wait_before_close` (`Self::wait_for_slots`).
        // The run's order is the face send value's (`PublishRun`).
        #[cfg(feature = "listen")]
        let probe = probes(
            face_send::droppable(
                send.reliable,
                meta.qos.unwrap_or(QosLevel::DEFAULT).congestion(),
            ),
            core.0.transport.tx_pool_short,
        );
        #[cfg(not(feature = "listen"))]
        let probe = false;
        let mut run = PublishRun::new(
            cfg!(all(wz_round, any(feature = "listen", feature = "group"))),
            probe,
            core.0.config.tx_queue.wait_before_close_us,
            // The faces are sent in the order of their places, the dial role's the first.
            FIRST_FACE,
        );
        let begin = run.begin();
        // What was handed to the session before this publish leaves before it, and what was
        // handed while this publish held the session leaves after it.
        #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
        if begin.hand_before {
            self.send_handed(&mut core.0);
        }
        // The put's leg is made once: the fan-out sends it, and the plan is made with the key it
        // named. An empty key names nothing a link carries.
        let leg = Self::leg_of(&core.0, &publication);
        let (outcome, stuck) = match &leg {
            Some(leg) => self.fan_out_leg(&mut core.0, &publication, leg, None, begin.pass, tx),
            None => (Err(FanoutError::ExceedsCapacity), None),
        };
        // The clock is read only for a fan-out that stopped at a face, whose wait it bounds. Only
        // a send that waits for no slot stops one, which a build that listens on nothing never
        // makes: there the fan-out is done, and neither the clock nor the wait is read.
        debug_assert!(
            stuck.is_none() || cfg!(feature = "listen"),
            "a fan-out stops at a face only where a send waits for no slot"
        );
        let stuck = stuck.filter(|_| cfg!(feature = "listen"));
        let fanned = run.fanned(stuck, || core.0.now_us());
        if let (Some(epoch), Some(leg)) = (plan_at, &leg) {
            Self::keep_plan(&core.0, put, epoch, leg.named, tx);
        }
        #[cfg(feature = "listen")]
        let waits = match fanned.then {
            Then::WaitForSlots { .. } => core.0.transport.links.owing_waits(),
            Then::Done => OwingWaits::new_static(),
        };
        #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
        if fanned.hand_after {
            self.send_handed(&mut core.0);
        }
        drop(publishing);
        drop(core);
        match fanned.then {
            Then::Done => outcome,
            #[cfg(feature = "listen")]
            Then::WaitForSlots { left_us, .. } => {
                self.wait_for_slots(&publication, run, waits, left_us, outcome, tx)
            }
            // Only a fan-out whose sends wait for no slot stops at a face, which a build that
            // listens on nothing never makes.
            #[cfg(not(feature = "listen"))]
            Then::WaitForSlots { .. } => outcome,
        }
    }

    /// Plan the plain way of `put`'s write filter at the sender's `epoch`, its first put at that
    /// epoch sent with its key named `named`, as its leg named it (`Self::leg_of`): kept when that
    /// is the filter's key and every link names it as the session does, by the head's declaration
    /// alone (`WriteFilterRow::keep_plan`), so a plan is never made of a key the put was not sent
    /// on. The epoch counts the session's own subscribers, the queryables none, so a filter that
    /// counts queryables plans nothing.
    fn keep_plan(
        core: &Core<L, C>,
        put: &PutOn<'_>,
        epoch: u64,
        named: NamedKey<'_>,
        tx: LinkTx<'_, C>,
    ) {
        let Some(row) = Self::filter_row(core, put.filter) else {
            return;
        };
        if row.plane() != Plane::Subscribers {
            return;
        }
        // Where a link names a key its own way, each link up is asked how it names this one, and
        // the way is planned only when every one names it as the session does. Without the shared
        // key ids every link names every key as the session does (`key_on_link`), so what is left
        // to check is the row's own: no link is asked.
        #[cfg(feature = "shared-key-ids")]
        if !core.up_wires_at().all(|(_, wire)| {
            #[cfg(all(test, feature = "std"))]
            core.plan_links.set(core.plan_links.get() + 1);
            send_through(wire, tx, &|actions: &LinkActions<C>| {
                key_on_link(actions, named).wire() == named.wire()
            }) == Some(true)
        }) {
            return;
        }
        #[cfg(not(feature = "shared-key-ids"))]
        let _ = tx;
        row.keep_plan(epoch, named);
    }

    /// Send `put` on from the face whose link found every outbound slot of the session held, and
    /// the faces after it, waiting each time with nothing of the session held until a link that
    /// holds a slot for a frame its stream has not finished has room or input
    /// (`LinkSupervisor::owing_waits`, the wait its own step makes for its room): its stack then
    /// takes what it owes, written by its step or by this publish, which has every link write what
    /// it owes before it tries again, so the slot is back. The faces before were sent it already, and are not again. Past the
    /// deadline, or with no link whose room can be waited on, the put is sent as any blocking send
    /// past its wait is. Each try sends through `tx`, what the publish holds of the faces: where
    /// a publish holds one face's send place at a time (`direct`), that face's, which stays held
    /// across the wait as a blocking send's transmit lock does.
    #[cfg(feature = "listen")]
    fn wait_for_slots(
        &self,
        put: &Publication<'_>,
        mut run: PublishRun,
        mut waits: OwingWaits,
        mut left_us: u64,
        mut outcome: Result<usize, FanoutError>,
        tx: LinkTx<'_, C>,
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
            let (more, again) = self.fan_out_in(&mut core.0, put, None, pass, tx);
            if more.is_err() {
                outcome = more;
            }
            let fanned = run.fanned(again, || now_us);
            waits = match fanned.then {
                Then::WaitForSlots { .. } => core.0.transport.links.owing_waits(),
                Then::Done => OwingWaits::new_static(),
            };
            #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
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
    #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
    fn fan_out(
        &self,
        core: &mut Core<L, C>,
        put: &Publication<'_>,
        skip: Option<&DroppedOn>,
    ) -> Result<usize, FanoutError> {
        self.fan_out_in(core, put, skip, Pass::EVERY_FACE, core::marker::PhantomData)
            .0
    }

    /// [`Self::fan_out`] by `pass`: with `listen`, to the faces from the one whose place is
    /// `pass.from` on ([`mark_of_place`]), with a send that does not wait for a slot when
    /// `pass.probe`. The faces are sent the put in order until one's link finds no outbound slot
    /// for it, which is answered beside the outcome and is sent nothing, nor are the faces after
    /// it, nor the groups. What a publish sent again after a wait for a slot, and a handed one, are
    /// sent by, each try naming its key afresh, as the session was let go between tries.
    #[cfg(any(feature = "listen", all(wz_round, feature = "group")))]
    fn fan_out_in(
        &self,
        core: &mut Core<L, C>,
        put: &Publication<'_>,
        skip: Option<&DroppedOn>,
        pass: Pass,
        tx: LinkTx<'_, C>,
    ) -> (Result<usize, FanoutError>, Option<u64>) {
        // An empty key names nothing a link carries.
        let Some(link_leg) = Self::leg_of(core, put) else {
            return (Err(FanoutError::ExceedsCapacity), None);
        };
        self.fan_out_leg(core, put, &link_leg, skip, pass, tx)
    }

    /// `leg`, the leg `put` is sent each link by (`Self::leg_of`), sent as `Self::fan_out_in`
    /// sends it: to the faces by `pass`, then to each group the session joined unless a face's link
    /// found no outbound slot for it.
    // Inlined whole: a put's leg sends through it in its own body, with no call added.
    #[inline(always)]
    fn fan_out_leg(
        &self,
        core: &mut Core<L, C>,
        put: &Publication<'_>,
        leg: &LinkLeg<'_>,
        skip: Option<&DroppedOn>,
        pass: Pass,
        tx: LinkTx<'_, C>,
    ) -> (Result<usize, FanoutError>, Option<u64>) {
        let (outcome, stuck) = self.send_on_links(core, leg, skip, pass, tx);
        if stuck.is_some() {
            return (outcome, stuck);
        }
        #[cfg(feature = "group")]
        if let sent @ Err(_) = self.publish_to_groups(core, put, leg.send, skip, tx) {
            return (sent, None);
        }
        #[cfg(not(feature = "group"))]
        let _ = put;
        (outcome, None)
    }

    /// The put `put` as each link is sent it ([`LinkLeg`]), read off the session's tables:
    /// `None` for a key that names nothing a link carries.
    fn leg_of<'p>(core: &Core<L, C>, put: &Publication<'p>) -> Option<LinkLeg<'p>> {
        let Publication {
            keyexpr,
            wire,
            payload,
            kind,
            meta,
            send,
            head,
        } = *put;
        // The key as the session's tables name it, by the declaration the ABI named it by while
        // that declaration stands, and whole otherwise. A plain put of a publisher, with options
        // or none, is written from the head its plain way wrote, which the put's decision read:
        // each link's send takes the head where the link names the key by the head's declaration
        // and the put is a plain Put carrying the head's QoS, and the parts otherwise.
        let named = tables(&core.session.registry).named_at(keyexpr, wire.declared())?;
        Some(LinkLeg {
            named,
            payload,
            kind,
            meta,
            send,
            head,
            planned: false,
        })
    }

    /// Send `put` as `send` says to each group the session joined, which its task frames and
    /// sends, but a group a dropped publish passes over (`skip`): what the last group that failed
    /// came to, else `Ok(0)`. Where each face's leg is sent apart, the groups are sent by the one
    /// leg that reaches them (`FaceTx::reaches_groups`), and `tx` of any other sends none.
    #[cfg(feature = "group")]
    fn publish_to_groups(
        &self,
        core: &mut Core<L, C>,
        put: &Publication<'_>,
        send: wz_session_core::session_actions::SendAs,
        skip: Option<&DroppedOn>,
        tx: LinkTx<'_, C>,
    ) -> Result<usize, FanoutError> {
        #[cfg(not(wz_round))]
        if !tx.reaches_groups() {
            return Ok(0);
        }
        let Publication {
            keyexpr,
            wire,
            payload,
            kind,
            meta,
            ..
        } = *put;
        let put = GroupPut {
            keyexpr,
            wire,
            payload,
            kind,
            meta,
            reliable: send.reliable,
            priority: send.priority,
        };
        #[cfg(not(wz_round))]
        {
            let _ = skip;
            self.put_on_groups(core, put)
        }
        #[cfg(wz_round)]
        {
            let _ = tx;
            let mut outcome = Ok(0);
            for group in &core.transport.groups {
                if skip.is_some_and(|dropped| self.rooms.skips(dropped, group.at())) {
                    continue;
                }
                let _sending = SendingOn::enter(&self.sending_on, mark_of_place(group.at()));
                // A group whose queue is full runs the session's tasks while it waits for room
                // (`group::SessionPace`): what they dispatch reaches the registry lent for that
                // wait.
                let sent = core
                    .registry_lend
                    .lend_for(&mut core.session.registry, || group.publish(put));
                if sent.is_err() {
                    outcome = sent;
                }
            }
            outcome
        }
    }

    /// `put` on each group the session joined, by the groups' one leg: what the last group that
    /// failed came to, else `Ok(0)`. Where the read steps a group's session itself, a wait for
    /// room runs no task, so nothing of the session is lent around a group's publish. Every group
    /// is the groups' leg's, and a send on one is marked at that leg's place.
    #[cfg(all(not(wz_round), feature = "group"))]
    #[inline(always)]
    fn put_on_groups(&self, core: &Core<L, C>, put: GroupPut<'_>) -> Result<usize, FanoutError> {
        let mut outcome = Ok(0);
        for group in &core.transport.groups {
            let _sending = SendingOn::enter(&self.sending_on, mark_of_place(direct::GROUPS_LEG));
            let sent = group.publish(put);
            if sent.is_err() {
                outcome = sent;
            }
        }
        outcome
    }

    /// A blocking publish's leg on the one face `tx` holds alone, whose wire is `alone`
    /// (`Self::put_leg`): the key named and the groups sent under `core`, which is
    /// let go of before the face is sent the put, so the send waits for its link's room with
    /// that face's send place held and nothing of the session. The face is sent it while the
    /// session's record of it is up, as a fan-out sends only the faces that are. On a session
    /// whose links share fewer outbound slots than they are (`probe`) the send waits for no
    /// slot, and a link that has none is waited on as [`Self::wait_for_slots`] waits, the
    /// session taken only to read the clock and the links' waits.
    #[cfg(not(wz_round))]
    #[inline(never)]
    fn publish_alone(
        &self,
        core: LiveCore<'_, L, C>,
        put: &Publication<'_>,
        alone: &Wire<C>,
        tx: LinkTx<'_, C>,
        probe: bool,
    ) -> Result<usize, FanoutError> {
        let Some(leg) = Self::leg_of(&core.0, put) else {
            return Err(FanoutError::ExceedsCapacity);
        };
        let (up, run) = Self::alone_run(&core.0, tx, probe);
        #[cfg(feature = "group")]
        let (core, groups) = {
            let mut core = core;
            let groups = self.publish_to_groups(&mut core.0, put, leg.send, None, tx);
            (core, groups)
        };
        drop(core);
        let mut outcome = Ok(0);
        #[cfg(feature = "group")]
        if groups.is_err() {
            outcome = groups;
        }
        self.send_leg_alone(&leg, alone, tx, up, run, outcome)
    }

    /// What a leg sent with nothing of the session held reads of the session first: whether the
    /// link `tx` holds is up, as a fan-out sends only the faces that are, and the publish run its
    /// send is made in (`probe` as [`Self::publish_alone`] takes it).
    #[cfg(not(wz_round))]
    fn alone_run(core: &Core<L, C>, tx: LinkTx<'_, C>, probe: bool) -> (bool, PublishRun) {
        let up = core.up_wires_at().any(|(_, link)| tx.reaches(link));
        let run = PublishRun::new(
            false,
            probe,
            core.config.tx_queue.wait_before_close_us,
            FIRST_FACE,
        );
        (up, run)
    }

    /// Send `leg` over `alone`, the one link `tx` holds, with nothing of the session held, in
    /// `run` (`Self::alone_run`): nothing when the link was not `up`, and a link with no
    /// outbound slot waited on as [`Self::wait_alone`] waits. `outcome` is what the publish
    /// came to before the leg, which a failed send replaces.
    #[cfg(not(wz_round))]
    fn send_leg_alone(
        &self,
        leg: &LinkLeg<'_>,
        alone: &Wire<C>,
        tx: LinkTx<'_, C>,
        up: bool,
        run: PublishRun,
        mut outcome: Result<usize, FanoutError>,
    ) -> Result<usize, FanoutError> {
        if !up {
            return outcome;
        }
        let place = mark_of_place(tx.leg_place().unwrap_or(0));
        let stopped = self.send_alone(
            leg,
            alone,
            run.begin().pass.face_send(place, false),
            &mut outcome,
        );
        // Only a send that waits for no slot stops, which a build that listens on nothing never
        // makes.
        #[cfg(feature = "listen")]
        if stopped {
            return self.wait_alone(leg, alone, run, place, outcome);
        }
        #[cfg(not(feature = "listen"))]
        let _ = stopped;
        outcome
    }

    /// Send `leg` over `alone` as `how` says, with nothing of the session held, the failure kept
    /// in `outcome`: whether the link had no outbound slot for a send that waits for none.
    #[cfg(not(wz_round))]
    fn send_alone(
        &self,
        leg: &LinkLeg<'_>,
        alone: &Wire<C>,
        how: FaceSend,
        outcome: &mut Result<usize, FanoutError>,
    ) -> bool {
        if how == FaceSend::Skip {
            return false;
        }
        let sent = leg.send_to(&alone.actions, how);
        #[cfg(test)]
        if sent.planned {
            self.takes.planned.fetch_add(1, Ordering::Relaxed);
        }
        if sent.outcome.is_err() {
            *outcome = sent.outcome;
        }
        sent.stop
    }

    /// [`Self::wait_for_slots`] for a leg sent with nothing of the session held
    /// ([`Self::publish_alone`]), on the face whose place is `place`: the session taken only to
    /// read the clock and the links' waits, and to have every link write what it owes, and the
    /// leg sent again once a link was waited on, until it is sent or its wait is spent.
    #[cfg(all(not(wz_round), feature = "listen"))]
    fn wait_alone(
        &self,
        leg: &LinkLeg<'_>,
        alone: &Wire<C>,
        mut run: PublishRun,
        place: u64,
        mut outcome: Result<usize, FanoutError>,
    ) -> Result<usize, FanoutError> {
        loop {
            let Some(core) = self.live() else {
                return outcome;
            };
            let Then::WaitForSlots { left_us, .. } =
                run.fanned(Some(place), || core.0.now_us()).then
            else {
                return outcome;
            };
            let waits = core.0.transport.links.owing_waits();
            drop(core);
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
            let now_us = core.0.now_us();
            core.0.transport.links.write_owed_now();
            drop(core);
            let how = run.waited(waited, now_us).face_send(place, false);
            if !self.send_alone(leg, alone, how, &mut outcome) {
                return outcome;
            }
        }
    }

    /// Send `leg` to the session's links by `pass` (`Self::fan_out_in`), each face marked as the
    /// session's holder's send on it while it is sent (`SendingOn`), as every put the session
    /// sends to its links is, a plain one through a write filter among
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
        tx: LinkTx<'_, C>,
    ) -> (Result<usize, FanoutError>, Option<u64>) {
        let mut outcome = Ok(0);
        #[cfg(not(all(wz_round, any(feature = "listen", feature = "group"))))]
        let _ = skip;
        for (at, wire) in core.up_wires_at() {
            // A publish's leg held for one face goes to that face alone.
            #[cfg(not(wz_round))]
            if !tx.reaches(wire) {
                continue;
            }
            #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
            let dropped_on = skip.is_some_and(|dropped| self.rooms.skips(dropped, at));
            #[cfg(not(all(wz_round, any(feature = "listen", feature = "group"))))]
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
            // A link not lent to the put skips it, as a link that is down does.
            let Some(sent) = publish_through(wire, tx, leg, how) else {
                continue;
            };
            #[cfg(test)]
            if sent.planned {
                self.takes.planned.fetch_add(1, Ordering::Relaxed);
            }
            if sent.outcome.is_err() {
                outcome = sent.outcome;
            }
            if sent.stop {
                return (outcome, Some(place));
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
    #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
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
    #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
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
    #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
    fn send_handed_now(&self, core: &mut Core<L, C>) {
        let whole = WireKey::literal();
        loop {
            // The empty table almost every step finds returns under the lock, before a leg's
            // place exists: an `Option` of a leg carried out of the block is a copy of a whole
            // leg, made even when it holds none.
            let leg = {
                let mut handed = self.handed();
                let Some(leg) = handed.take_first() else {
                    self.owed.store(false, Ordering::SeqCst);
                    return;
                };
                leg
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
                        kind: opts.kind,
                        meta: &meta,
                        send: wz_session_core::session_actions::SendAs {
                            reliable: opts.reliable_bool(),
                            express: meta.is_express(),
                            priority: opts.priority_band(),
                        },
                        head: None,
                    },
                    Some(leg.dropped_on()),
                );
            }
            self.handed().give_back(leg);
        }
    }

    /// The table of handed publishes, held.
    #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
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
    /// callback makes on its own subscriber's key reaches it at once, at any depth. A subscriber an
    /// earlier callback undeclares is still handed the sample when its turn comes
    /// (`SubscriberCall::hand_pinned`). The number of subscribers reached.
    #[cfg(all(feature = "local-subscriber", wz_round))]
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
        // Every call was begun in the one hold above, so a row an earlier callback undeclared is
        // still handed the sample, as the read that hands each record out hands it.
        self.deliveries.within(|_| {
            for call in reached.iter() {
                call.hand_pinned(&sample);
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
    /// plane's, and its sink registered with the deadline and the accepted key the get states,
    /// that deadline owed in `ledger` with it, so a read waits no longer and the step's
    /// bookkeeping sweeps the leg when it is due. Out of line where a get issues more than one
    /// kind of leg (to groups, or to the session itself, besides its links), so those legs are
    /// held by one body and not by a copy each; a build whose get asks its links alone has one
    /// caller, which keeps it inline.
    #[cfg(feature = "query")]
    #[cfg_attr(any(feature = "group", feature = "local-queryable"), inline(never))]
    fn hold_leg(
        &self,
        now_us: u64,
        registry: &mut Registry,
        ledger: &mut Ledger,
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
        // A get no row holds is refused before its leg's callback is minted; the row it takes is
        // what its id carries.
        let rid = match registry.gets_mut(face) {
            Some(gets) if gets.replies.has_room() => rid.at(gets.replies.next_row()),
            Some(_) => return LegHeld::NoRoom,
            None => return LegHeld::Gone,
        };
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
            ask.consolidation,
            leg_sink,
            get::LegHold::new(leg_id, self.gets),
        );
        let accept = ReplyAcceptance::for_query(ask.keyexpr, ask.accept);
        // Through the registry's writer of the gets, which lowers the index of their deadlines.
        let registered = registry.write_gets(face, |gets| {
            gets.replies
                .register_sink(rid, finals, deadline_ms, accept, sink)
        });
        match registered {
            Some(Ok(_)) => {
                ledger.owe_leg_due(deadline_ms);
                LegHeld::Held { rid }
            }
            Some(Err(RegisterError::TableFull)) => LegHeld::Refused { table_full: true },
            Some(Err(_)) | None => LegHeld::Refused { table_full: false },
        }
    }

    /// One reply to the query that came in under `generation`, as its queryable makes it: onto
    /// the query's link, written into the link's transmit slot under the session's lock, or to the
    /// session's own get. Refused, sending nothing, when its payload or its attachment is longer
    /// than the session's `MAX_REPLY_PAYLOAD_BYTES`; dropped, as a lost link drops it, when the
    /// session is closed or the query's link is no longer the session's. A reply onto a link holds
    /// the link's replies unless `raised` says this turn of the answer holds them already, and
    /// sets it when this one raised the hold, which the turn's end lets go of ([`Self::answer`]).
    #[cfg(feature = "queryable")]
    fn send_reply(
        &self,
        generation: u64,
        parts: ReplyParts<'_>,
        raised: &mut bool,
    ) -> Result<(), ReplyError> {
        let fits = |core: &Core<L, C>| {
            let (payload, attachment) = parts.bounded_lengths();
            let most = core.config.limits.max_reply_payload_bytes();
            if !most.admits(payload) || !most.admits(attachment) {
                return Err(ReplyError::PayloadTooLarge);
            }
            Ok(())
        };
        // The session's own get is answered to its pending entry, which is the registry's: what
        // the entry's consolidation forwards at once is handed to the leg's callback by this
        // thread, once it lets go of the session, and what it holds is handed out when the answer
        // ends (`Self::answer`).
        #[cfg(feature = "local-queryable")]
        if generation == query::LOCAL_QUERY {
            let Some(mut core) = self.live() else {
                return Ok(());
            };
            fits(&core.0)?;
            // Handed as it lies: a requester that keeps the reply copies what it keeps, and keeps
            // a buffer of shared memory as its page, as it keeps the owned projection's.
            let reply = wz_session_core::reply::LocalReplyView::new(parts);
            self.gets.capture();
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
        // The query's link's place is taken before the session, as every send on it takes them.
        // Held from the first reply, so the rest and the Final join its frame and the answer
        // leaves in one send. A hold another turn raised is that turn's to let go of.
        self.live_on_link(|core, tx| -> Result<(), ReplyError> {
            fits(core)?;
            #[cfg(feature = "group")]
            if let Some(sink) = core.transport.group_answer_sink(generation) {
                if !*raised {
                    *raised = sink.hold_replies();
                }
                sink.send_reply_parts(parts);
                return Ok(());
            }
            if let Some(link) = core.answer_wire(generation) {
                let hold = !*raised;
                let held = send_through(link, tx, &|actions: &LinkActions<C>| {
                    let held = hold && actions.hold_replies();
                    wz_session_core::response_sink::ResponseSink::send_reply_parts(actions, parts);
                    held
                });
                if held == Some(true) {
                    *raised = true;
                }
            }
            Ok(())
        })
        .unwrap_or(Ok(()))
    }

    /// One turn of the answer to the query `rid` on the link of `generation` has ended, its
    /// replies written as they were made ([`Self::send_reply`]): with `release`, let go of one
    /// hold on its Final, sending the Final when it was owed and this was the last hold, then let
    /// go of the hold on the link's replies the turn raised (`replies`), so the replies and the
    /// Final leave in one send. Nothing is sent on a link that is no longer the session's. On a
    /// group, what the replies staged there is written by this call, on the calling thread.
    #[cfg(feature = "queryable")]
    fn answer(
        &self,
        generation: u64,
        rid: wz_session_core::wire_id::RequestId,
        release: query::Release,
        replies: bool,
    ) {
        // Let go of the hold under the session's lock.
        let due = || match release {
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
            let Some(mut core) = self.live() else {
                return;
            };
            if due().is_some() {
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
        // The query's link's place is taken before the session, as every send on it takes them.
        let _ = self.live_on_link(|core, tx| {
            let due = due();
            #[cfg(feature = "group")]
            if let Some(sink) = core.transport.group_answer_sink(generation) {
                if let Some(qos) = due {
                    sink.send_response_final(rid, qos);
                }
                sink.release_replies(replies);
                // A group's sink only stages: a kept query answered from the program's own thread
                // would otherwise leave when the read task's wait ends, up to the group's tick a
                // leg.
                core.transport.write_answers(generation);
                return;
            }
            // The Final joins the frame the turn's replies were held in, and the hold the turn
            // raised is let go of after it, so the replies and the Final leave in one send.
            if let Some(link) = core.answer_wire(generation) {
                send_through(link, tx, &|actions: &LinkActions<C>| {
                    if let Some(qos) = due {
                        actions.send_response_final(rid, qos);
                    }
                    actions.release_replies(replies);
                    true
                });
            }
        });
        #[cfg(test)]
        if replies {
            self.takes.held_answers.fetch_add(1, Ordering::Relaxed);
        }
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
    #[cfg(all(feature = "liveliness", wz_round))]
    fn end_liveliness_call(&self, call: LivelinessCall) {
        self.samples.end_liveliness_call(call);
    }

    /// End `call`, made of a liveliness subscriber's row: a row whose last call it was is let go
    /// of here, with no lock held, as a Push's walk lets a subscriber's go (`pinned`).
    #[cfg(all(feature = "liveliness", not(wz_round)))]
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
    #[cfg(wz_round)]
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
    #[cfg(wz_round)]
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
            #[cfg(any(feature = "engine-rows", test))]
            self.reach.end();
            self.closed.store(true, Ordering::Release);
            return Stepped::Closed;
        }
        #[cfg(feature = "group")]
        core.ask_groups_for_keyexprs();
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
            // The tables a get is due in, as the index of the gets' deadlines names them; a
            // liveliness snapshot that expired ends the same way.
            registry.sweep_due_gets(now_ms);
            // A snapshot's terminated ids, by its DeclFinal or by the sweep, are staged for a
            // reconnect cache this engine does not keep (it declares again from its own entries),
            // so they are drained and dropped: staged ones would pile up. The drain makes a buffer
            // of the table's whole ceiling, so a table with none staged is not drained.
            #[cfg(feature = "liveliness-get")]
            for gets in registry.all_gets_mut() {
                if gets.liveliness_gets.has_finalized() {
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
    #[cfg(wz_round)]
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
        #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
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
    #[cfg(all(test, feature = "std", feature = "liveliness-get"))]
    pub(crate) fn spend_interest_ids(&self) {
        let Some(guard) = self.live() else {
            return;
        };
        let core = &guard.0;
        let mut asked = None;
        while let Some(face) = core.transport.next_up_face(true, asked) {
            asked = Some(face);
            if let Some(link) = core.up_wire(face) {
                lend_actions(link, |actions: &LinkActions<C>| {
                    actions
                        .next_outbound_interest_id
                        .store(u64::from(u32::MAX) + 1, Ordering::Relaxed);
                });
            }
        }
    }

    /// A matching listener's declaration, `declare`, made in the tables under the session's lock
    /// taken inside the one link's place (`Self::live_on_link`): its new Interest asked of each
    /// link and its first verdict delivered once both are let go, or the refusal, its callback
    /// let go of with neither held.
    fn matching_declared(
        &self,
        declare: impl FnOnce(&mut Core<L, C>) -> MatchingDeclared,
    ) -> Result<MatchId, Declined> {
        // The listener's callback the tables refuse, let go of once neither is held: the
        // declaration answers only why, so its answer carries no callback.
        let mut refused_call = None;
        let declared = self.live_on_link(|core, tx| -> Result<MatchId, Declined> {
            let watching = match declare(core) {
                Ok(watching) => watching,
                Err(refused) => {
                    refused_call = Some(refused.callback);
                    return Err(Declined::from(refused.why));
                }
            };
            // A listener on a key asks its own Interest of each link from its row; one on a
            // filter asks nothing.
            if let Some(opened) = watching.interest {
                core.announce(DeclaredRow::of(opened.handle), tx);
            }
            // A listener that matches already is told so as it is declared, as zenoh-pico tells
            // it (`vendor/zenoh-pico/src/net/filtering.c` @ `_z_write_filter_ctx_add_callback`).
            self.read_matching(core);
            Ok(row_id(watching.handle))
        });
        drop(refused_call);
        match declared {
            Some(Ok(id)) => {
                self.deliver();
                Ok(id)
            }
            Some(Err(why)) => Err(why),
            None => Err(Declined::Closed),
        }
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
        #[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
        let mut staged = ReplyStage::<RowPolicy>::default();
        #[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
        let mut staged = ReplyStage::<RowPolicy>::counted(0, 0);
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
    #[cfg(all(feature = "local-queryable", wz_round))]
    fn end_own_call(&self, call: QueryableCall) {
        self.samples.end_query_call(call);
    }

    /// End `call`, which the session's own get made of one of its queryables: a row whose last
    /// call it was is let go of here, with no lock held, as a link's query's walk lets it go
    /// (`queries`).
    #[cfg(all(feature = "local-queryable", not(wz_round)))]
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
    /// without spending it. Compiled with the key arena's tests that ask it (`tests::held_keys`),
    /// which a build of the on-use form leaves out.
    #[cfg(all(
        test,
        feature = "std",
        not(all(feature = "tables-on-use", not(feature = "runtime-plan")))
    ))]
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

/// An entity's key, as its row in `tables` keeps it ([`RowKey`]), lent with the declaration the
/// row holds that the key is lent with: that of the entity's own key, or else the one the key is
/// named by. The caller holds the session, and the row `key` was read off stands.
fn lent_key(tables: &CoopTables, key: RowKey) -> KeyView {
    // SAFETY: the caller's: the row stands, so its text is where it was read.
    let text = unsafe { key.text() };
    match key
        .held
        .and_then(|handle| Some((handle, tables.keyexprs().get(handle)?)))
    {
        // SAFETY: the session's rows lie in its region, in the span lent at its open, or in the
        // rows their table took at its first (`RowPolicy`), none of which moves while the session's
        // state stands; and the entity's row holds the declaration until the entity is retracted.
        Some((handle, row)) => unsafe {
            KeyView::holding(text, handle, row.key(), row.id(), row.head().count())
        },
        None => KeyView::literal(text),
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
        let _ = self.live_on_link(|core, tx| {
            // A row that went names nothing, whichever declaration took its slot or its id since.
            core.let_go_of_keyexpr(row, tx);
        });
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

    #[inline(never)]
    fn declared_prefix(&self, row: KeyexprHandle, key: &str) -> Option<(ExprId, usize)> {
        let core = self.live()?;
        tables(&core.0.session.registry).declared_prefix(row, key)
    }

    // The tally of the holds handed out (`Takes::holds`) counts the ones taken and given back at
    // their rows as it counts the ones the session took and was given back.
    #[cfg(test)]
    fn counted_at_row(&self, change: isize) {
        self.takes.holds.fetch_add(change, Ordering::Relaxed);
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

    #[cfg(feature = "resource-snapshot")]
    fn message_reading(&self) -> Option<wz_session_core::resource_snapshot::BuildMessageReading> {
        Some(CoopEngine::message_reading(self))
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
            .links
            .faces()
            .filter(|face| face.id >= from)
            .filter_map(|face| {
                // What the face's link said of its peer as it came up, read with no lend of it.
                let facts = face.facts()?;
                Some((
                    face.id,
                    PeerIdentity {
                        zid: facts.peer?,
                        whatami: facts.whatami?,
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
        #[cfg(wz_round)]
        core.run_tasks();
        drop(guard);
        // Where the read steps each group's session itself, the step is this call's, made with
        // the session let go of as a read makes it; one asked from a callback's call leaves the
        // JOIN to the next read.
        #[cfg(not(wz_round))]
        self.read_groups(None, None);
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
    fn face_link_at(&self, at: usize) -> Option<FaceLinkRow> {
        self.live().and_then(|core| core.0.face_link_at(at))
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
        #[cfg(wz_round)]
        core.tell_decl_watches_owed();
        // The catch-up is handed now, before the link is read again; a declare from inside a
        // callback has it handed by the delivery the callback runs in, as the call returns.
        #[cfg(not(wz_round))]
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
                .links
                .faces()
                .filter_map(|face| face.facts())
                .any(|facts| facts.whatami == Some(0))
        })
    }

    #[cfg(feature = "shared-key-ids")]
    fn names_keys_by_link(&self) -> bool {
        self.live().is_some_and(|core| {
            core.0.session.key_ids.is_some() || core.0.transport.key_forms.departs_from_declared()
        })
    }

    fn redeclare(&self) -> Result<usize, wz_capi_port::RedeclareRefusal> {
        self.live_on_link(|core, tx| core.redeclare(tx))
            .ok_or(wz_capi_port::RedeclareRefusal::Closed)
    }

    #[inline(never)]
    fn publish_on_wire_all(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        match self.put_on_links(&PutOn {
            keyexpr,
            wire,
            payload,
            by: PutBy::Options(opts),
            filter: None,
        }) {
            FilteredPut::Sent(sent) => sent,
            // A publish no publisher made has no filter to hold it back, and is no plain put.
            FilteredPut::Suppressed | FilteredPut::NotPlain => Ok(0),
        }
    }

    #[inline(never)]
    fn declare_subscriber_on_wire(
        &self,
        keyexpr: &str,
        wire: WireKey,
        allowed_origin: Locality,
        retraction: Option<RetractionKey>,
        sink: SubscriberSink,
    ) -> Result<Declared<SubId>, Declined> {
        // A closed session declares nothing, and takes no id for what it does not declare. The
        // subscriber is one row of the session's tables, numbered by the id they hand out next: a
        // full table, a key the session cannot hold or no id left refuses it before anything is
        // sent. What the key holds and the sink go back with either refusal, let go of after the
        // session in the one place both are. The row holds the key expression declaration its
        // key is named by for as long as it stands.
        // Taken by the declaration into the row it offers the tables; let go of, with the session
        // and the link's place, after it, whether it was declared or not.
        let mut unmade = Some((wire, sink));
        // The row the tables refuse, let go of once the declaration let go of the session and the
        // link's place: the declaration answers only why, so its answer carries no row.
        let mut refused_row = None;
        let declared = self.live_on_link(|core, tx| {
            // Taken once: the declaration runs once.
            let Some((wire, sink)) = unmade.take() else {
                return Err(Declined::NoEntityId);
            };
            let form = core
                .session
                .key_form(
                    wire.declared(),
                    retraction.map_or(Retraction::ById, Retraction::Named),
                )
                .owning(tables(&core.session.registry).keyexpr_by_id(wire.own_declaration()));
            // The tables' row holds the declarations the key and the retraction name, once each,
            // in the session's one count; the row keeps what else the key kept.
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
                // The program's callback goes with the refusal, let go of with no lock held, and
                // what the key kept with it.
                Err(refused) => {
                    refused_row = Some(refused.callback);
                    return Err(Declined::from(refused.why));
                }
            };
            // The id the tables numbered the row by: they mint it, after the room and the key, so
            // a declaration is refused in their one order.
            let id = declared.id;
            // The key as the tables read it off the row they put it in: its text is the row's own,
            // which does not move while the row stands.
            let lent = lent_key(tables(&core.session.registry), declared.key);
            // Each link is told it from the row, which names the key as the tables keep it.
            core.announce(DeclaredRow::of(declared.handle), tx);
            // So is each group, from the same row, when the session joined one.
            #[cfg(feature = "group")]
            if !core.transport.groups.is_empty() {
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
            core.settle_faces(tx);
            // A matching listener that counts the session's own subscribers may now match: it is
            // told, outside the lock.
            #[cfg(feature = "local-subscriber")]
            self.read_matching(core);
            Ok(Declared { id, key: lent })
        });
        drop(refused_row);
        match declared {
            Some(Ok(declared)) => {
                #[cfg(feature = "local-subscriber")]
                self.deliver();
                Ok(declared)
            }
            Some(Err(why)) => Err(why),
            None => Err(Declined::Closed),
        }
    }

    #[inline(never)]
    fn undeclare_subscriber(&self, id: SubId) {
        // The session is held once, whichever table the id's row is in, after the faces' places
        // as every operation that tells the links takes them. A liveliness subscriber's id is one
        // of these too (the port's one id space): its row goes and its Interest ends, and what it
        // took is carried out of the hold here.
        #[cfg(feature = "liveliness")]
        let mut live = None;
        // The row is taken out of the tables under the lock and let go of after it: what its key
        // kept may reach the session as it goes (`KeyAnchor`). One a call of which runs is
        // let go of once that call ends (`Self::wait_for_release`).
        let undeclared = self
            .live_on_link(|core, tx| {
                #[cfg(feature = "liveliness")]
                {
                    let found = tables(&core.session.registry)
                        .liveliness_subscribers()
                        .iter()
                        .enumerate()
                        .find(|(_, (_, row))| row.id() == id)
                        .map(|(rank, (handle, row))| (rank, handle, row.key().prefix()));
                    if let Some((rank, handle, prefix)) = found {
                        // The links are asked while the rows stand, which are their places in the
                        // replay's order: the subscriber's, ranked by the walk that found it, then
                        // the declaration's its key is named by.
                        let place = core.place(DeclaredTable::LivelinessSubscribers, rank);
                        let keyexpr_place = core.prefix_retraction(prefix);
                        // The groups asked for it are told the asking ended.
                        #[cfg(feature = "group")]
                        for group in &core.transport.groups {
                            group.end_liveliness_ask(id);
                        }
                        if let Some(undeclared) = tables_mut(&mut core.session.registry)
                            .undeclare_liveliness_subscriber(handle)
                        {
                            // The rows went before the links are told: a send never finds the
                            // tables borrowed.
                            core.retract_at(place, Some(Retract::Interest(u64::from(id))), tx);
                            core.retract_keyexpr(keyexpr_place, undeclared.keyexpr, tx);
                            live = Some((handle, undeclared.taken));
                            return None;
                        }
                    }
                }
                // The declaration its key is named by goes with it when it is the last that holds
                // it; what the links are told is read while the row stands.
                let found = tables(&core.session.registry)
                    .subscribers()
                    .iter()
                    .enumerate()
                    .find(|(_, (_, row))| row.id() == id)
                    .map(|(rank, (handle, row))| (rank, handle, row.key().holds()));
                let (rank, handle, (prefix, named)) = found?;
                // The links are asked while the rows stand, which are their places in the
                // replay's order: the subscriber's, ranked by the walk that found it, then the
                // declaration's, which comes before every subscriber.
                let place = core.place(DeclaredTable::Subscribers, rank);
                let keyexpr_place = core.prefix_retraction(prefix);
                let named_place = core.prefix_retraction(named);
                #[cfg(feature = "group")]
                core.transport.retract_from_groups(id);
                let undeclared =
                    tables_mut(&mut core.session.registry).undeclare_subscriber(handle)?;
                let row = undeclared.taken;
                // The rows went before the links are told: a send never finds the tables borrowed.
                // The retraction names the key as the row named it, holding the key past the row.
                let names = undeclared
                    .retraction
                    .as_ref()
                    .map(|retraction| retraction.names());
                core.retract_at(place, Some(Retract::Subscriber { id, names }), tx);
                core.retract_keyexpr(keyexpr_place, undeclared.keyexpr, tx);
                core.retract_keyexpr(named_place, undeclared.named, tx);
                // An aggregate answer it alone stood for is retracted now, as it was declared.
                #[cfg(feature = "interest-answer")]
                core.settle_faces(tx);
                // One that counted it may now match no more.
                #[cfg(feature = "local-subscriber")]
                self.read_matching(core);
                Some((handle, row))
            })
            .flatten();
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
        self.live_on_link(|core, tx| -> Result<KeyHold, Declined> {
            // A key the session declared already is held once more; any other takes a row and an
            // id. The table refuses it, before an id is taken or anything is sent, when it is full,
            // when the key cannot be held, or when every id is taken. An id of the shared
            // dictionary names its key in this session's space too, so no key expression is
            // declared under one. One declaration, whatever ids the session shares: the table's
            // declaration is one body for both.
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
            let declared = tables_mut(&mut core.session.registry)
                .declare_keyexpr_where(keyexpr, false, usable)?;
            let id = declared.id;
            // A declaration held once more is told no one again. A new one a link refuses is not
            // made, and the links that took it take it back; one made while a link is down, or that
            // a replay has not reached, is sent in its turn. A link refuses one it cannot carry.
            // Either way the hold is handed out in one place below.
            if declared.new {
                // Each link is told it from the row, as every declaration is.
                let taken = core.announce_or_undo(
                    DeclaredRow::of(declared.handle),
                    Retract::Keyexpr(id),
                    tx,
                );
                if !taken {
                    tables_mut(&mut core.session.registry).undeclare_keyexpr(declared.handle);
                    return Err(Declined::ExceedsCapacity);
                }
                // And each group told the session's keyexprs, as a link is.
                #[cfg(feature = "group")]
                for group in &core.transport.groups {
                    group.announce_keyexpr(id, keyexpr);
                }
            }
            #[cfg(test)]
            self.takes.holds.fetch_add(1, Ordering::Relaxed);
            // SAFETY: the hold just taken keeps the row standing, and the session's rows lie in its
            // region, in the span lent at its open, or in the rows their table took at its first
            // (`RowPolicy`), none of which moves while the session's state stands.
            Ok(unsafe { KeyHold::taken(id, declared.handle).placed_at(declared.count()) })
        })
        .unwrap_or(Err(Declined::Closed))
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
        // The listener is a row of the session's tables on a write filter of its own, which holds
        // an Interest: a full table, a key the session cannot hold or an Interest it cannot hold or
        // number refuses it before anything is asked, as a listener that could ask no peer would
        // never hear one.
        self.matching_declared(|core| {
            tables_mut(&mut core.session.registry).declare_matching_listener_on(
                plane_of(plane),
                keyexpr,
                counts_own(plane, count_local),
                MatchingCall { sink: Some(sink) },
            )
        })
    }

    #[inline(never)]
    fn declare_filter_matching_listener(
        &self,
        filter: FilterId,
        sink: MatchingSink,
    ) -> Result<MatchId, Declined> {
        let handle = row_of(filter).ok_or(Declined::Closed)?;
        // The listener is a callback of the filter's row, which it reads and goes with, and asks
        // nothing of its own, as zenoh-pico's is a callback of its entity's filter.
        self.matching_declared(|core| {
            tables_mut(&mut core.session.registry)
                .declare_matching_listener(handle, MatchingCall { sink: Some(sink) })
                .map(|handle| Watching {
                    handle,
                    interest: None,
                })
        })
    }

    fn undeclare_matching_listener(&self, id: MatchId) {
        let gone = self
            .live_on_link(|core, tx| {
                let handle = row_of(id)?;
                let place = {
                    let tables = tables(&core.session.registry);
                    let row = tables.matching_listeners().get(handle)?;
                    // A listener declared on a key ends the Interest of the filter it owns; one
                    // declared on an entity's filter ends none.
                    let owned = row.owns_filter().then_some(row.filter());
                    owned.and_then(|filter| filter_rank(tables, filter))
                };
                let unwatched =
                    tables_mut(&mut core.session.registry).undeclare_matching_listener(handle)?;
                // The row went before the links are told: a send never finds the tables borrowed.
                core.end_interest(unwatched.interest_final, place, tx);
                unwatched.row
            })
            .flatten();
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
    ) -> Result<Declared<FilterId>, Declined> {
        if !counts(plane) {
            return Err(Declined::NotBuilt);
        }
        self.live_on_link(|core, tx| -> Result<Declared<FilterId>, Declined> {
            // A full table, a plane at its own bound (a publisher's MAX_PUBLISHERS, a querier's
            // MAX_QUERIERS, in the one table lent for both), a key the session cannot hold, or an
            // Interest it cannot hold or number refuses the filter, with nothing held, asked or
            // numbered.
            let name = ask.map(|form| InterestName {
                mapping_id: form.mapping_id,
                suffix: form.suffix,
                aggregate: form.aggregate,
            });
            // The row holds the declaration the key is named by from here on, so the entity keeps
            // no hold of its key and lends it from the row, which the declaration answers.
            let own = tables(&core.session.registry).keyexpr_at(wire.declared());
            let watching = tables_mut(&mut core.session.registry)
                .declare_write_filter_as(
                    plane_of(plane),
                    keyexpr,
                    counts_own(plane, count_local),
                    name,
                    own,
                )
                .map_err(Declined::from)?;
            let id = row_id(watching.handle);
            // The id this filter spent of its own: its Interest's, or the one taken for a filter
            // that sends none.
            let spent = match watching.interest {
                Some(opened) => u64::from(opened.id),
                None => {
                    // The entity id is taken whether the Interest is sent or not, as zenoh-pico's
                    // `_z_add_interest` takes it before it decides: a filter that finds none left
                    // is refused, its row given back.
                    let Some(taken) = core.session.take_entity_id() else {
                        // The caller holds the declaration the row held through this call, so the
                        // row's hold given back is not the last and retracts nothing.
                        if let Some((_, Some(held))) =
                            unwatch_filter(tables_mut(&mut core.session.registry), watching.handle)
                        {
                            core.let_go_of_keyexpr(held, tx);
                        }
                        return Err(Declined::NoEntityId);
                    };
                    u64::from(taken)
                }
            };
            // Its row is its Interest's place in the replay's order whether it asks or not, so a
            // replay under way counts it; one that asks nothing is told nothing there.
            core.announce(DeclaredRow::of(watching.handle), tx);
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
            // The text is the filter's row's own, which does not move while the row stands. The
            // tables made the row above; were it gone, the answer names no key, which the door
            // refuses.
            let tables = tables(&core.session.registry);
            let key = tables
                .write_filters()
                .get(watching.handle)
                .map_or(KeyView::ABSENT, |row| {
                    lent_key(tables, RowKey::of(row.key(), row.own()))
                });
            Ok(Declared { id, key })
        })
        .unwrap_or(Err(Declined::Closed))
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
        let _ = self.live_on_link(|core, tx| {
            // Its place is read while the row stands.
            let place = filter_rank(tables(&core.session.registry), handle);
            let Some((last_held, held)) =
                unwatch_filter(tables_mut(&mut core.session.registry), handle)
            else {
                return;
            };
            // The row went before the links are told: a send never finds the tables borrowed.
            core.end_interest(last_held, place, tx);
            // The row's hold of the declaration its key is named by goes back as a holder's does.
            // The key expressions come first in the replay's order, so the Interest's end moved no
            // place of theirs.
            if let Some(held) = held {
                core.let_go_of_keyexpr(held, tx);
            }
            // The groups it asked are told the asking ended.
            #[cfg(feature = "group")]
            for group in &core.transport.groups {
                group.end_filter(id);
            }
        });
    }

    fn put_plain_filtered(
        &self,
        filter: FilterId,
        keyexpr: &str,
        declared: KeyexprRef,
        payload: &[u8],
        params: &PlainPutParams,
    ) -> FilteredPut {
        // The declaration names the whole key, as a group is sent it too.
        let wire = WireKey::aliased(declared.id, None).at_row(declared.row);
        self.put_on_links(&PutOn {
            keyexpr,
            wire: &wire,
            payload,
            by: PutBy::Plain(Some(*params)),
            filter: Some(filter),
        })
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
        // A write with options goes the general way, written from its publisher's plain way where
        // the options leave it a plain put; one that brings nothing of its own goes the plain way
        // its filter's row keeps. Either asks its filter under the take its first leg makes.
        let by = match opts {
            Some(opts) => PutBy::Options(opts),
            None => PutBy::Plain(None),
        };
        self.put_on_links(&PutOn {
            keyexpr,
            wire,
            payload,
            by,
            filter: Some(filter),
        })
    }

    /// Each group the session joined takes the step too, and is counted as a link is: a group's
    /// window holds what the session sends on the group, as pico's batch holds what it sends on
    /// its multicast transport, and is written by a flush or a stop on the caller's thread, as a
    /// link's is.
    fn batch_all(&self, step: BatchStep) -> usize {
        // The one link's place is taken before the session, as every send on it takes them.
        self.live_on_link(|core, tx| {
            let links = core
                .up_wires_at()
                .filter(|(_, wire)| {
                    send_through(*wire, tx, &|actions: &LinkActions<C>| {
                        batch_link(actions, step)
                    }) == Some(true)
                })
                .count();
            #[cfg(feature = "group")]
            let groups = core
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
        .unwrap_or(0)
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
    ) -> Result<Declared<QblId>, Declined> {
        // Taken by the declaration once it has an id; let go of, with the session and the link's
        // place, after it, whether it was declared or not.
        let mut unmade = Some((wire, sink));
        // The row the tables refuse, let go of as the key and the sink are: the declaration
        // answers only why, so its answer carries no row.
        let mut refused_row = None;
        let declared = self.live_on_link(|core, tx| {
            // The queryable is one row of the session's tables, numbered by the id they hand out
            // next: a full table, a key the session cannot hold or no id left refuses it before
            // anything is sent, and before its callback is minted. The row holds the key
            // expression declaration its key is named by for as long as it stands.
            let next = tables(&core.session.registry).next_entity_id();
            let Some(id) = next else {
                return Err(Declined::NoEntityId);
            };
            // Taken once: the declaration runs once.
            let Some((wire, sink)) = unmade.take() else {
                return Err(Declined::NoEntityId);
            };
            let form = core
                .session
                .key_form(
                    wire.declared(),
                    retraction.map_or(Retraction::ById, Retraction::Named),
                )
                .owning(tables(&core.session.registry).keyexpr_by_id(wire.own_declaration()));
            // The tables' row holds the declarations the key and the retraction name, once each,
            // in the session's one count; the row keeps what else the key kept.
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
                // The row goes with the refusal, let go of with no lock held, and what its key
                // kept with it.
                Err(refused) => {
                    refused_row = Some(refused.callback);
                    return Err(Declined::from(refused.why));
                }
            };
            debug_assert_eq!(
                declared.id, id,
                "the tables number a row as they said they would"
            );
            // The key as the tables read it off the row they put it in: its text is the row's own,
            // which does not move while the row stands.
            let lent = lent_key(tables(&core.session.registry), declared.key);
            // Each link is told it from the row, which names the key as the tables keep it.
            core.announce(DeclaredRow::of(declared.handle), tx);
            // So is each group, from the same row, when the session joined one.
            #[cfg(feature = "group")]
            if !core.transport.groups.is_empty() {
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
            // A matching listener that counts the session's own queryables may now match: it is
            // told, outside the lock.
            #[cfg(feature = "local-queryable")]
            self.read_matching(core);
            Ok(Declared { id, key: lent })
        });
        drop(refused_row);
        match declared {
            Some(Ok(declared)) => {
                #[cfg(feature = "local-queryable")]
                self.deliver();
                Ok(declared)
            }
            Some(Err(why)) => Err(why),
            None => Err(Declined::Closed),
        }
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
        // What the get reads of the session before its first leg (the row of its own Final, the
        // timestamp policy) is read under the hold of that leg, the faces' places taken before the
        // session's lock as every operation that sends takes them: one hold for both.
        //
        // The session's own queryables are asked all or none, under a row of the plane's held
        // Finals taken before any leg is issued: a session with none free refuses the get whole,
        // with nothing sent and no queryable asked, where zenoh-pico refuses a get whose delivery
        // to its own queryables failed (`vendor/zenoh-pico/src/net/primitives.c` @
        // `_Z_CLEAN_RETURN_IF_ERR(ret, _z_unregister_pending_query(zn, qid));`).
        #[cfg(feature = "local-queryable")]
        let mut own: Option<query::OwnFinalHold<'_>> = None;
        #[cfg(feature = "local-queryable")]
        let mut refused = false;
        let mut started = false;
        // What every link is asked, read from the options once: the sink of each leg consolidates
        // as the Request states.
        let request = opts.query_parts();
        // What every leg of this get is held with, the mint of each leg's callback among it; whether
        // its callbacks show a reply's timestamp is read under the first hold.
        let mut ask = LegAsk {
            keyexpr,
            opts,
            consolidation: request.sink_consolidation(),
            accept: opts.effective_accept_replies(),
            expose: false,
            mint: leg,
        };
        let remote = opts.allowed_destination.allows_remote();
        let mut issued: usize = 0;
        // The legs refused for want of a row in their face's table of pending gets: a get that
        // issued none, and found no room for one, is refused whole.
        let mut unheld = 0usize;
        // Why the last leg whose face was up did not go out: a get that issued none is refused
        // with it, as zenoh-pico's get answers the error of the send that failed.
        let mut unsent: Option<Declined> = None;
        // The faces whose links are up, each asked once in the order of their ids: the walk keeps
        // the last face it asked and holds the faces and the session for each, holding no list of
        // them; it ends with the face after which none is up, read in that face's hold, so none is
        // taken only to learn that no face is left.
        let mut asked = None;
        let mut more = true;
        loop {
            let turn = self.live_on_link(|core, tx| {
                if !started {
                    started = true;
                    #[cfg(feature = "local-queryable")]
                    if opts.allowed_destination.allows_local() {
                        // The session's own request ids are a space of their own: the leg is
                        // registered in the session's own pending gets (`Registry::local`) and
                        // answered under the local generation (`query::LOCAL_QUERY`), so no table
                        // a link's ids reach holds it, and the two counters never meet.
                        let rid = core.session.local_requests.take();
                        match query::OwnFinalHold::take(&self.plane, rid) {
                            Some(hold) => own = Some(hold),
                            None => {
                                refused = true;
                                return LegTurn::Done;
                            }
                        }
                    }
                    // `entity-timestamp-opt-in`: the query's choice, or the session's policy when
                    // it states none, applied to every leg's callback, after its replies are
                    // consolidated.
                    ask.expose = opts.expose_timestamp_by(&core.policy);
                }
                let Some(face) = core.transport.next_up_face(remote, asked) else {
                    return LegTurn::Done;
                };
                asked = Some(face);
                let leg_id = self.next_local_id();
                // A serial the face's actions allocate, which the entry's row is put below.
                let Some(serial) = core.up_wire(face).and_then(|link| {
                    lend_through(link, tx, |actions: &LinkActions<C>| {
                        actions.alloc_next_request_id()
                    })
                }) else {
                    return LegTurn::Skipped;
                };
                // One Final: the face's peer's. Held before the request goes out, so no answer
                // can arrive before its entry, under a request id of the face's actions' serial
                // and the entry's row, so its peer's answer names both.
                let rid = match self.hold_leg(
                    core.clock.now_us(),
                    &mut core.session.registry,
                    &mut core.ledger,
                    &mut ask,
                    LegEntry {
                        face,
                        leg: leg_id,
                        rid: LegRid::Serial(serial),
                        finals: 1,
                    },
                ) {
                    LegHeld::Held { rid } => rid,
                    LegHeld::Gone => return LegTurn::Skipped,
                    LegHeld::NoRoom => {
                        unheld = unheld.saturating_add(1);
                        return LegTurn::Skipped;
                    }
                    LegHeld::Refused { table_full } => {
                        unheld = unheld.saturating_add(usize::from(table_full));
                        // A leg no table holds is let go of with no lock held.
                        return LegTurn::Ended(leg_id);
                    }
                };
                // The link names the key as its own key-wire form says, and the query is written
                // from the options where they lie, with nothing copied.
                let abi = abi_names(wire, keyexpr);
                let refused = core::cell::Cell::new(None);
                let sent = core.up_wire(face).and_then(|link| {
                    send_through(link, tx, &|actions: &LinkActions<C>| {
                        get_key_on_link(actions, keyexpr, abi, |mapping_id, suffix| {
                            wz_session_core::wire_key::WireKey::from_parts(mapping_id, suffix)
                                .is_some_and(|key| {
                                    actions
                                        .send_get_parts(wz_session_core::query_parts::GetParts {
                                            rid,
                                            key,
                                            query: request,
                                        })
                                        .map_err(|why| refused.set(Some(why)))
                                        .is_ok()
                                })
                        })
                    })
                }) == Some(true);
                if !sent {
                    // Nothing went out: the entry and the leg go, and the leg is over. The get is
                    // told why when no other leg goes out, not ended as one that reached nobody.
                    if let Some(tables) = core.session.registry.face_mut(face) {
                        tables.gets.replies.unregister(rid);
                    }
                    unsent = Some(unsent_refusal(refused.get()));
                    return LegTurn::Ended(leg_id);
                }
                if !core.session.note_pending(PendingGet {
                    face,
                    leg: leg_id,
                    kind: GetKind::Query(rid),
                    fan: tag,
                }) {
                    unheld = unheld.saturating_add(1);
                    return LegTurn::Skipped;
                }
                more = core.transport.next_up_face(remote, asked).is_some();
                LegTurn::Issued
            });
            #[cfg(feature = "local-queryable")]
            if refused {
                return Err(Declined::TableFull);
            }
            match turn {
                None => return issued_so_far(issued),
                Some(LegTurn::Done) => break,
                Some(LegTurn::Skipped) => continue,
                Some(LegTurn::Ended(leg_id)) => {
                    self.end_leg_now(leg_id);
                    continue;
                }
                Some(LegTurn::Issued) => {}
            }
            issued = issued.saturating_add(1);
            // A fan cancelled while the legs are issued stops the issuing.
            if self.cut_short(fan, tag) {
                return Ok(issued);
            }
            if !more {
                break;
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
            // Held before the query is queued, as a link's leg is before it is sent, under a
            // request id of the group's serial and the entry's row, so a member's answer names it
            // on this face.
            let rid = match self.hold_leg(
                core.clock.now_us(),
                &mut core.session.registry,
                &mut core.ledger,
                &mut ask,
                LegEntry {
                    face,
                    leg: leg_id,
                    rid: LegRid::Serial(group.alloc_request_id()),
                    finals,
                },
            ) {
                LegHeld::Held { rid } => rid,
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
            };
            if !group.ask(rid, keyexpr, wire, request) {
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
            match self.hold_leg(
                core.clock.now_us(),
                &mut core.session.registry,
                &mut core.ledger,
                &mut ask,
                LegEntry {
                    face: LOCAL_FACE,
                    leg: leg_id,
                    rid: LegRid::Taken(rid),
                    finals: 1,
                },
            ) {
                LegHeld::Held { .. } => {
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
        get_outcome(issued, unheld, unsent)
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
            let turn = self.live_on_link(|core, tx| {
                let Some(face) = core.transport.next_up_face(true, asked) else {
                    return LegTurn::Done;
                };
                asked = Some(face);
                let leg_id = self.next_local_id();
                // A face whose session has no interest id left is not asked, as one that could
                // not hold the entry.
                let Some(interest_id) = core
                    .up_wire(face)
                    .and_then(|link| {
                        lend_through(link, tx, |actions: &LinkActions<C>| {
                            actions.alloc_next_interest_id()
                        })
                    })
                    .flatten()
                else {
                    return LegTurn::Skipped;
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
                    return LegTurn::Skipped;
                }
                // A snapshot's replies are tokens, shown as they came.
                let Some(row) = self.gets.open_leg(&mut *leg, true) else {
                    return LegTurn::Skipped;
                };
                // SAFETY: the sink goes into a table of pending gets, which the session
                // reaches under its lock alone, and is handed its replies there; the table is the
                // registry's, dropped before the owners of the plane and of the round where the
                // build keeps one, the session state's fields after the registry's.
                let leg_sink =
                    unsafe { get::LegSink::new(leg_id, row, self.gets, self.uncaptured()) };
                // One DeclFinal: the face's peer's. Registered before the Interest goes out, so no
                // answer can arrive before its entry.
                // Through the registry's writer of the gets, which lowers the index of their deadlines.
                let registered = core
                    .session
                    .registry
                    .write_gets(face, |gets| {
                        gets.liveliness_gets
                            .register(interest_id, deadline_ms, leg_sink)
                    })
                    .is_some_and(|registered| matches!(registered, Ok(true)));
                if !registered {
                    return LegTurn::Ended(leg_id);
                }
                // Its deadline bounds a read's wait as a query leg's does, and a pending snapshot
                // owes the bookkeeping at every step, which drains the gets it ends
                // (`Core::settle_ledger`).
                core.ledger.owe_leg_due(deadline_ms);
                core.ledger.owe();
                // The Interest names the key as the link's own key-wire form says, as a query
                // does.
                let abi = abi_names(wire, keyexpr);
                let sent = core.up_wire(face).and_then(|link| {
                    send_through(link, tx, &|actions: &LinkActions<C>| {
                        get_key_on_link(actions, keyexpr, abi, |mapping_id, suffix| {
                            actions
                                .send_interest_liveliness_get(interest_id, mapping_id, suffix)
                                .is_ok()
                        })
                    })
                }) == Some(true);
                if !sent {
                    // Nothing went out: the entry and the leg go, and the leg is over.
                    if let Some(tables) = core.session.registry.face_mut(face) {
                        tables.gets.liveliness_gets.unregister(interest_id);
                    }
                    return LegTurn::Ended(leg_id);
                }
                if !core.session.note_pending(PendingGet {
                    face,
                    leg: leg_id,
                    kind: GetKind::Liveliness(interest_id),
                    fan: tag,
                }) {
                    return LegTurn::Skipped;
                }
                LegTurn::Issued
            });
            match turn {
                None => return issued_so_far(issued),
                Some(LegTurn::Done) => break,
                Some(LegTurn::Skipped) => continue,
                Some(LegTurn::Ended(leg_id)) => {
                    self.end_leg_now(leg_id);
                    continue;
                }
                Some(LegTurn::Issued) => {}
            }
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
        self.answer(id.generation, id.rid, query::Release::Kept, false);
    }
    #[cfg(feature = "queryable")]
    fn undeclare_queryable(&self, id: QblId) {
        // The row is taken out of the tables under the lock and let go of after it: what its key
        // kept may reach the session as it goes (`KeyAnchor`). One a call of which is owed,
        // a query queued for it or handed to its callback now, is let go of once that call ends
        // (`Self::wait_for_queryable_release`), and a query queued before is answered by nothing.
        let undeclared = self
            .live_on_link(|core, tx| {
                // The declaration its key is named by goes with it when it is the last that holds
                // it; what the links are told is read while the row stands.
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
                let undeclared =
                    tables_mut(&mut core.session.registry).undeclare_queryable(handle)?;
                let row = undeclared.taken;
                // The rows went before the links are told: a send never finds the tables borrowed.
                let names = retraction.as_ref().map(|(names, key)| names.names(key));
                core.retract_at(place, Some(Retract::Queryable { id, names }), tx);
                core.retract_keyexpr(keyexpr_place, undeclared.keyexpr, tx);
                core.retract_keyexpr(named_place, undeclared.named, tx);
                // One that counted it may now match no more.
                #[cfg(feature = "local-queryable")]
                self.read_matching(core);
                Some((handle, row))
            })
            .flatten();
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
        let declared = self
            .live_on_link(|core, tx| -> Result<TokenId, Declined> {
                // The token is a row of the session's tables, which takes its id: a full table, a
                // key the session cannot hold or no id left refuses it before anything is
                // registered or sent. It holds the key expression declaration its key is named by
                // for as long as it stands. A token's retraction names its key as its announcement
                // does.
                let named = if retraction.is_some() {
                    Retraction::AsAnnounced
                } else {
                    Retraction::ById
                };
                let form = core
                    .session
                    .key_form(wire.declared(), named)
                    .owning(tables(&core.session.registry).keyexpr_by_id(wire.own_declaration()));
                let declared =
                    tables_mut(&mut core.session.registry).declare_token(keyexpr, form)?;
                core.announce(DeclaredRow::of(declared.handle), tx);
                // A token takes no traffic of its own, so every group that is told tokens is told
                // it. It is held before it is announced (its row, which a peer's and a group
                // member's Interest are answered from), so a member that asks right after it hears
                // the announcement finds it held: the tokio engine's group holds it the same way.
                #[cfg(feature = "group")]
                core.announce_token_to_groups(declared.handle);
                Ok(declared.id)
            })
            .unwrap_or(Err(Declined::Closed));
        // The row holds the declaration its key is named by, so the key the ABI named it by is
        // not kept: what it kept goes, declared or refused, with no lock held.
        drop(wire);
        declared
    }

    #[cfg(feature = "liveliness")]
    fn undeclare_liveliness_token(&self, id: TokenId) {
        let _ = self.live_on_link(|core, tx| {
            let retracted =
                {
                    let tables = tables(&core.session.registry);
                    let found = tables.tokens().iter().find(|(_, row)| row.id() == id).map(
                        |(handle, row)| {
                            // What its retraction names, read while the declaration stands.
                            let names = tables.retraction_of(row.key());
                            (handle, names, row.key().prefix())
                        },
                    );
                    found
                };
            let Some((handle, names, prefix)) = retracted else {
                return;
            };
            // The links are asked while the rows stand, which are their places in the replay's
            // order: the token's, then the declaration's, which comes before every token.
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
            let retract = key.map(|key| Retract::Token {
                id,
                names: names.map(|names| names.names(key)),
            });
            core.retract_at(token_place, retract, tx);
            core.retract_keyexpr(keyexpr_place, undeclared.keyexpr, tx);
        });
    }

    #[cfg(feature = "liveliness")]
    fn declare_liveliness_subscriber_on_wire(
        &self,
        keyexpr: &str,
        wire: WireKey,
        history: bool,
        sink: LivelinessSink,
    ) -> Result<Declared<SubId>, Declined> {
        // A closed session declares nothing, and takes no id for what it does not declare; what
        // the key holds goes back with the refusal, let go of, with the session and the link's
        // place, after the declaration.
        let mut unmade = Some((wire, sink));
        // The row the tables refuse, let go of as the key and the sink are.
        let mut refused_row = None;
        let declared = self.live_on_link(|core, tx| {
            // The subscriber is one row of the session's tables, numbered by the id they hand out
            // next, which its Interest carries: a full table, a key the session cannot hold or no
            // id left refuses it before anything is asked, and the sink goes with the refusal. The
            // row holds the key expression declaration its Interest names the key by for as long
            // as it stands.
            let next = tables(&core.session.registry).next_entity_id();
            let Some(id) = next else {
                return Err(Declined::NoEntityId);
            };
            // Taken once: the declaration runs once.
            let Some((wire, sink)) = unmade.take() else {
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
                // The program's callback goes with the refusal, let go of with no lock held, and
                // what the key kept with it.
                Err(refused) => {
                    refused_row = Some(refused.callback);
                    return Err(Declined::from(refused.why));
                }
            };
            debug_assert_eq!(
                declared.id, id,
                "the tables number a row as they said they would"
            );
            // One with no history asks the links as it is declared.
            if !history {
                core.ask_liveliness_subscriber(declared.handle, tx);
            }
            Ok((id, declared.handle))
        });
        drop(refused_row);
        let (id, handle) = match declared {
            Some(Ok(declared)) => declared,
            Some(Err(why)) => return Err(why),
            None => return Err(Declined::Closed),
        };
        // With `history`, the subscriber is handed the tokens the session already knows before
        // the peers are asked for the rest, as zenoh-pico's is
        // (`vendor/zenoh-pico/src/net/liveliness.c` @ `_z_liveliness_subscription_trigger_history`):
        // on this thread, one at a time, with the session let go of while each is handed. A token
        // a peer's answer repeats is not handed again: the first declaration of an id wins.
        if history {
            self.hand_history(handle);
            self.live_on_link(|core, tx| core.ask_liveliness_subscriber(handle, tx))
                .ok_or(Declined::Closed)?;
        }
        // A subscriber its own history's callback undeclared names no key, there being no record
        // left to lend one from, so the door binds no loan, as for a subscriber already gone. One
        // that stands is lent the row's text, which does not move while the row stands.
        let lent = self.live().and_then(|guard| {
            let tables = tables(&guard.0.session.registry);
            tables
                .liveliness_subscribers()
                .get(handle)
                .map(|row| lent_key(tables, row.key().lent()))
        });
        self.deliver();
        Ok(Declared {
            id,
            key: lent.unwrap_or(KeyView::ABSENT),
        })
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
#[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
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
        let keys = core.keys_locked();
        match ask {
            // A text the arena keeps already, whoever holds it, is that block shared, so a key the
            // session's declarations and the program's objects name alike takes one block.
            KeyAsk::Hold(text) => match keys.shared(text) {
                Ok(key) => Ok(Some(HeldKey::of(key))),
                Err(KeyUnkept::TooLong) => Err(KeyNotHeld::TooLong),
                Err(KeyUnkept::NoRoom) => Err(KeyNotHeld::NoRoom),
            },
            // SAFETY: the key is of the arena whose lock `keys` proves held: the session's.
            KeyAsk::Share(key) => Ok(Some(unsafe { key.share(&keys) })),
            KeyAsk::Release(key) => {
                // SAFETY: as a share.
                unsafe { key.release(&keys) };
                Ok(None)
            }
        }
    }
}

/// The keys the C ABI's objects hold where the session's tables take their memory on use: the
/// session keeps no key arena, so each is a copy of its own, made, shared and let go of with no
/// lock taken, and refused past the session's `MAX_KEYEXPR_BYTES` as the arena refuses it, or as no
/// room when the heap has none. Their bytes are not counted against the session's key budget until
/// a held key is a holder of the key its row keeps (section 4 of
/// `docs/c-abi-migration/heap-native.md`, N3e).
#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> SessionKeys for CoopEngine<L, C> {
    #[inline(never)]
    fn key(&self, ask: KeyAsk<'_>) -> Result<Option<HeldKey>, KeyNotHeld> {
        match ask {
            KeyAsk::Hold(text) => {
                let kept = match self.live() {
                    Some(core) => core
                        .0
                        .session
                        .keys
                        .budget()
                        .is_some_and(|budget| budget.holds_key(text.len())),
                    None => return Err(KeyNotHeld::Closed),
                };
                if !kept {
                    return Err(KeyNotHeld::TooLong);
                }
                HeldKey::own(text).map(Some).ok_or(KeyNotHeld::NoRoom)
            }
            KeyAsk::Share(key) => HeldKey::own(key.as_str())
                .map(Some)
                .ok_or(KeyNotHeld::NoRoom),
            KeyAsk::Release(key) => {
                // Every key this engine hands out is a copy of its own.
                if key.is_own() {
                    // SAFETY: a copy of its own, which its holder lets go of here, once.
                    unsafe { key.free_own() };
                }
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
        #[cfg(any(feature = "engine-rows", test))]
        self.reach.clear();
        let core = &mut guard.0;
        // A key the program keeps past the close copies and gives back its hold at its row, with
        // no reach of the session: the row's word is what tells it the session is gone.
        tables(&core.session.registry).close_keyexpr_counts();
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
        #[cfg(not(wz_round))]
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
        #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
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

    fn read(&self, _single: bool) -> Result<(), SessionClosed> {
        self.read_within(NO_STEP_BOUND_MS)
    }

    fn send_keep_alive(&self) -> Result<(), SessionClosed> {
        // The one link's place is taken before the session, as every send on it takes them.
        self.live_on_link(|core, tx| {
            // A link that is down has no lease to keep; the session is not closed.
            for (_, wire) in core.up_wires_at() {
                send_through(wire, tx, &|actions: &LinkActions<C>| {
                    actions.send_keep_alive();
                    true
                });
            }
        })
        .ok_or(SessionClosed)
    }

    fn spin_once(&self) -> bool {
        self.read(false).is_ok()
    }

    fn step_once(&self, most_ms: u32) -> Result<(), StepRefused> {
        // The task steps the session itself; a step of the program's beside it would be a second
        // reader the program did not choose at the open. A start made while this step runs reads
        // beside it, as two reads may (`HandBack`).
        #[cfg(feature = "threads")]
        if SessionDrive::read_task_is_running(self) {
            return Err(StepRefused::ReadTaskRuns);
        }
        self.read_within(most_ms).map_err(StepRefused::from)
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
    /// [`SessionDrive::read`] with its wait for input bounded by `most_ms` as well as by the
    /// config's ([`CoopConfig::idle_wait_ms`]): the read task and `zp_read` read with no bound of
    /// their own ([`NO_STEP_BOUND_MS`]), and a step the program makes with the one it gives
    /// ([`SessionDrive::step_once`]).
    // The read steps its faces itself (`direct`).
    #[cfg(not(wz_round))]
    fn read_within(&self, most_ms: u32) -> Result<(), SessionClosed> {
        self.read_direct(most_ms)
    }

    /// [`SessionDrive::read`] with its wait for input bounded by `most_ms` as well as by the
    /// config's ([`CoopConfig::idle_wait_ms`]), as in a build whose read steps its faces itself.
    #[cfg(wz_round)]
    fn read_within(&self, most_ms: u32) -> Result<(), SessionClosed> {
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
                let wait = core.0.idle_wait(most_ms);
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

    /// [`SessionDrive::step_once`].
    pub fn step_once(&self, most_ms: u32) -> Result<(), StepRefused> {
        SessionDrive::step_once(self.engine_ref(), most_ms)
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
/// `with_tls` makes over a secure channel `S`, those `with_groups` makes joining groups by `J`,
/// and those `waited_by_owner` makes, whose owner waits for their input. An ABI names with it the
/// links it opens its sessions over, and so the engine's type, whatever its build adds to the
/// host's.
pub trait ComposedLinks {
    /// The links `with_tls` makes.
    type WithTls<S>;
    /// The links `with_groups` makes.
    type WithGroups<J>;
    /// The links `waited_by_owner` makes.
    type WaitedByOwner;
}

impl<U, D, L, G, N: wz_runtime_coop::link_cells::CountKind, W> ComposedLinks
    for wz_runtime_coop::ip_stack::IpLinks<U, D, L, G, N, W>
{
    type WithTls<S> = wz_runtime_coop::ip_stack::IpLinks<U, D, S, G, N, W>;
    type WithGroups<J> = wz_runtime_coop::ip_stack::IpLinks<U, D, L, J, N, W>;
    type WaitedByOwner = wz_runtime_coop::ip_stack::IpLinks<
        U,
        D,
        L,
        G,
        N,
        wz_runtime_coop::session_drive::WaitedByOwner,
    >;
}

#[cfg(all(feature = "queryable", wz_round))]
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
        #[cfg(any(feature = "engine-rows", test))]
        self.reach.clear();
        // The one link's session holds handles of the state's cells: it goes first (`direct`).
        #[cfg(not(wz_round))]
        self.direct.let_go_owned();
        // The round names this engine to answer its queries: no longer, before anything of the
        // engine goes (`Round::answer_queries_with`).
        #[cfg(all(feature = "queryable", wz_round))]
        self.samples.answer_no_queries();
        // The last handle is gone, so no read task holds one: it has stopped, or is about to
        // drop the handle it held. A session never closed is closed now; a closed one has no
        // link left to end.
        self.core.dropping().end_links();
        // The kept publishes' places lie in the session's arena, which the state's drop gives
        // back: they are given back first.
        #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
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

#[cfg(all(test, feature = "std", feature = "threads", wz_round))]
mod hand_back_tests {
    use super::{lock, HandBack};
    use core::ptr::NonNull;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// A hand-back made where it stays, as the engine makes its own.
    fn made() -> Arc<HandBack> {
        let mut place = Arc::<HandBack>::new_uninit();
        let at =
            NonNull::from(Arc::get_mut(&mut place).expect("the one holder")).cast::<HandBack>();
        // SAFETY: `at` is the place the Arc holds, aligned for a `HandBack` and holding none,
        // which the Arc does not move; every field is written before it is read as made.
        unsafe {
            HandBack::init_at(at);
            place.assume_init()
        }
    }

    /// A read waiting for another read's buffer wakes when the buffer is handed back, well
    /// before its bound, and is counted out after. Turned red by a hand-back that wakes no one,
    /// which leaves a read task asleep for its whole bound behind a program's read.
    #[test]
    fn a_read_waiting_for_the_buffer_wakes_when_it_is_handed_back() {
        let back = made();
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
        let back = made();
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
        let back = made();
        back.handed_back();
        assert_eq!(*lock(&back.handed), 0);
    }
}

#[cfg(test)]
mod leg_outcome_tests {
    //! What a publish's leg answers for each way its send ended.
    use super::leg_outcome;
    use wz_session_core::send_wire_error::SendWireError;

    /// A send the link refused for want of a slot is a failed send, where a link that is down is
    /// skipped and a sent frame is sent. Turned red by a `leg_outcome` that answers the refusal
    /// as it answers a link that is down (`Ok(0)`), which a blocking put reads as sent.
    #[cfg(feature = "tx-lend-only")]
    #[test]
    fn a_frame_the_link_lent_no_slot_for_is_a_failed_send() {
        use wz_capi_port::FanoutError;
        use wz_session_core::link::LinkDropCause;
        assert_eq!(
            leg_outcome(Err(SendWireError::LinkRefused(LinkDropCause::NoTxSlot))),
            Err(FanoutError::ExceedsCapacity)
        );
        assert_eq!(
            leg_outcome(Err(SendWireError::LinkRefused(LinkDropCause::WriterGone))),
            Ok(0),
            "CONTROL: a link whose writer is gone is down, and skipped"
        );
    }

    /// A sent frame and a link that is not there are no failure of the publish.
    #[test]
    fn a_sent_frame_and_a_link_that_is_down_are_no_failure() {
        assert_eq!(leg_outcome(Ok(())), Ok(0));
        assert_eq!(leg_outcome(Err(SendWireError::TransportUnavailable)), Ok(0));
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

    /// A send on a group, marked at the groups' leg's place where each face's leg is sent apart,
    /// reads as a send to a droppable leg that finds the session held, and not as a holder that
    /// sends on no face. Turned red by a place whose mark is one of those, as `usize::MAX`'s is
    /// `PUBLISHING` on a 64-bit target.
    #[cfg(all(feature = "group", not(wz_round)))]
    #[test]
    fn a_send_on_a_group_is_marked_as_a_send() {
        let mark = super::mark_of_place(super::direct::GROUPS_LEG);
        assert!(
            ![NOT_SENDING, super::WAITING, PUBLISHING].contains(&mark),
            "the groups' leg is marked {mark}, a holder's that sends on no face"
        );
    }
}

#[cfg(all(test, feature = "connectivity"))]
mod up_facts_tests {
    //! What a face's record keeps of its link as it came up, read without a lend of the link.
    use super::UpFacts;
    use alloc::string::String;
    use wz_session_core::face::{FaceLinkRow, FaceSnapshot, LinkFacts, LinkSnapshot};

    /// The facts of a face whose peer is `zid`, its row naming `links` links.
    fn facts(zid: u8, links: usize) -> UpFacts {
        let face = FaceSnapshot {
            zid: [zid; 16],
            whatami: 1,
            is_qos: true,
            is_multicast: false,
            is_shm: false,
            links: alloc::vec![LinkSnapshot::unicast("tls/a:1", "tls/b:2", None, 512)],
        };
        let mut row = FaceLinkRow::of_snapshot(&face, 0).expect("the face's one link");
        row.links = links;
        UpFacts {
            peer: None,
            whatami: None,
            #[cfg(any(feature = "interest-answer", feature = "listen"))]
            peer_hat: None,
            #[cfg(feature = "queryable")]
            generation: 0,
            ended: false,
            row: Some(row),
        }
    }

    /// A face whose row names its link stands with that row; the row of a face alone, which
    /// names no link, and no row at all stand for nothing. Turned red by a standing row that
    /// keeps the row of a face alone, which `face_link_at` would hand out as a link with no ends.
    #[test]
    fn only_a_row_that_names_its_link_stands() {
        let up = facts(7, 1);
        assert_eq!(up.standing_row().map(|row| row.zid), Some([7; 16]));
        let alone = facts(7, 0);
        assert!(alone.standing_row().is_none(), "a face alone");
        assert_eq!(
            alone
                .snapshot(&LinkFacts::default())
                .map(|face| face.links.len()),
            Some(0),
            "a face alone stands with no link, as its snapshot read off the link did"
        );
        let none = UpFacts {
            row: None,
            ..facts(7, 1)
        };
        assert!(none.standing_row().is_none(), "a half-open face");
        assert!(
            none.snapshot(&LinkFacts::default()).is_none(),
            "a half-open face"
        );
    }

    /// The snapshot of a face read from its facts carries what its link says beyond its row: the
    /// band and the class its QoS extension negotiated, the name on the peer's certificate and
    /// the NICs. Turned red by a snapshot built from the row alone (`LinkSnapshot::of_row`),
    /// which reads each of them as not known.
    #[test]
    fn a_snapshot_from_the_facts_keeps_what_the_link_said_beyond_its_row() {
        let said = LinkFacts {
            interfaces: Some(alloc::vec![String::from("eth0")]),
            cert_common_name: Some(String::from("router.example")),
            priorities: Some((2, 5)),
            reliable: Some(false),
        };
        let face = facts(3, 1).snapshot(&said).expect("a face that stands");
        assert_eq!(face.zid, [3; 16]);
        assert!(face.is_qos);
        let links = face.links.as_slice();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].priorities, said.priorities);
        assert_eq!(links[0].reliable, said.reliable);
        assert_eq!(links[0].cert_common_name, said.cert_common_name);
        assert_eq!(links[0].interfaces, said.interfaces);
        assert_eq!(links[0].dst, "tls/b:2");
        assert_eq!(links[0].mtu, 512);
    }

    /// Facts whose link's session a step was seen to end stand for nothing, and are kept for the
    /// loss to be told by. Turned red by a `standing` that reads past `ended`, under which a
    /// face would stand after its session ended.
    #[test]
    fn facts_of_an_ended_session_no_longer_stand() {
        let mut up = facts(4, 1);
        assert!(up.standing().is_some());
        up.ended = true;
        assert!(up.standing().is_none(), "its session ended");
        assert!(up.row.is_some(), "kept for the loss");
    }

    /// Where the record holds the link's session, facts stand while that session is established
    /// as they are read, with no mark made by a pass of the links. Turned red by a
    /// `standing_while` that reads past a session that is no longer established (`Face::facts`
    /// would then stand a face whose session a pass ended), or past `ended`.
    #[cfg(wz_round)]
    #[test]
    fn facts_stand_while_their_session_is_established() {
        let mut up = facts(4, 1);
        assert!(
            up.standing_while(true).is_some(),
            "CONTROL: an established session"
        );
        assert!(
            up.standing_while(false).is_none(),
            "a session no longer established"
        );
        up.ended = true;
        assert!(up.standing_while(true).is_none(), "a session seen to end");
    }
}

#[cfg(all(test, not(wz_round)))]
mod face_ended_tests {
    use super::face_ended;

    /// A face that stands ends once its session is read no longer established, and only then: an
    /// established session keeps it standing, and a face that does not stand is not ended again.
    /// Turned red by a `face_ended` that ends a face whose session is established, or reads an
    /// established session as ended.
    #[test]
    fn a_standing_face_ends_once_its_session_is_no_longer_established() {
        assert!(
            !face_ended(true, true),
            "CONTROL: an established session stands"
        );
        assert!(
            face_ended(true, false),
            "a session no longer established ends its face"
        );
        assert!(
            !face_ended(false, false),
            "a face that does not stand has nothing to end"
        );
        assert!(
            !face_ended(false, true),
            "nor one whose session is not yet read up"
        );
    }
}

#[cfg(test)]
mod asked_tests {
    use super::{Answer, Asked};

    /// The first leg of a put to hold the session answers it, and a later leg that finds otherwise
    /// (its filter's row gone meanwhile) changes nothing of that answer, so the caller is not sent
    /// to the general publish for a put the faces before were sent. Turned red by an answer a
    /// later leg overwrites.
    #[test]
    fn the_first_leg_answers_the_put() {
        let asked = Asked::new();
        assert!(asked.first(), "no leg answered yet");
        assert!(!asked.stops());
        asked.answer_first(Answer::Through);
        asked.answer_first(Answer::NotPlain);
        assert_eq!(asked.answer.get(), Some(Answer::Through));
        assert!(!asked.first());
        assert!(!asked.stops(), "the legs after it send");
    }

    /// A put its first leg held back or found not plain stops every leg after it, whatever a later
    /// leg finds. Turned red by a leg that sends after the put was answered so.
    #[test]
    fn a_put_answered_unsent_stops_the_legs_after_it() {
        for answer in [Answer::HeldBack, Answer::NotPlain] {
            let asked = Asked::new();
            asked.answer_first(answer);
            assert!(asked.stops(), "{answer:?} stops the legs after it");
            asked.answer_first(Answer::Through);
            assert_eq!(asked.answer.get(), Some(answer));
        }
    }
}
