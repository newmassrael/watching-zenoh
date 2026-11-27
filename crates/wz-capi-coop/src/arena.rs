// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session's arena: one block of memory its open reserves for what the limits it opened under
//! size, before anything is bound or dialled (`docs/c-abi-no-heap-pools.md`, section 5).
//!
//! # The rows
//!
//! [`ArenaPlan::of`] states what the arena holds as rows, each `count` items of `entry_bytes`,
//! from the limits and the config the open was handed:
//!
//! - the application's tables, once for the session: its subscribers (`MAX_SUBSCRIPTIONS`) and,
//!   with `queryable`, its queryables (`MAX_QUERYABLES`) are rows of the session's one table set
//!   (below), and so, with `liveliness`, are its liveliness subscribers
//!   (`MAX_LIVELINESS_SUBSCRIPTIONS`); with `liveliness` its tokens (`MAX_LOCAL_TOKENS`), and
//!   the lists of the watchers of what a peer declares, two for each plane that has them
//!   (`MAX_DECL_OBSERVERS` rows each), one row of their spans;
//! - one table of the gets pending on a face (`MAX_PENDING_QUERIES`, and with `liveliness-get`
//!   `MAX_PENDING_LIVELINESS_GETS`) for each face the session may hold at once, which a face
//!   takes when it comes and gives back when it goes, and with `local-queryable` one of those
//!   pending on the session's own queryables, which no face holds ([`GetTables`]), and with
//!   `query` a row for the end of each get those tables hold, waiting for its delivery;
//! - one table of what a face's peer is owed for each face the session may hold at once, taken
//!   and given back as the face's gets are ([`FacePeers`]): the answers staged back to its
//!   interests and to its liveliness interests (`MAX_PENDING_DECLARES`) and the `Final`s owed to
//!   its queries (`MAX_PENDING_FINALS`, none in a build without `queryable`). Its reply stage is
//!   lent no row: the engine's queryable answers into a stage of its own (`peer_rows`);
//! - one pool of each kind of row a peer writes by its own choice, which every face's tables share
//!   ([`PeerPoolRows`]): its aliases (`SESSION_MAX_PEER_KEYEXPR_ALIASES`), its subscribers,
//!   queryables and tokens and the repeats of them (`SESSION_MAX_REMOTE_DECLS`) and, with
//!   `interest-answer`, its subscriber interests (`SESSION_MAX_INBOUND_SUB_INTERESTS`), each the
//!   fewer of the session's value of its limit and what the faces could hold at the bound of each
//!   peer (`MAX_PEER_KEYEXPR_ALIASES`, `MAX_REMOTE_DECLS`, `MAX_INBOUND_SUB_INTERESTS`), each row
//!   the place of its key in the key arena below. A face holds the rows its peer wrote and not the
//!   most it could, as zenoh-pico takes each from its heap as it comes. A session of one face
//!   shares with no one: its tables take spans of their own of that face's bounds instead, laid
//!   out as inline tables are, with no link and no pool state. Either way one span more names
//!   where each kind's rows lie, which every face's tables reach them through by the session's key
//!   arena;
//! - the buffers of the links the session may hold: a pool of receive buffers of the batch the
//!   session advertises, a streamed batch's length counted inside it, as many as
//!   `RX_POOL_BUFFERS` and no more than the links, which a link holds only while it holds part of
//!   a batch or something it was asked to keep; a pool of slots of that length to encode frames
//!   into, as many as `TX_POOL_SLOTS` and no more than the links, of which a link holds
//!   [`LINK_TX_SLOTS`] at a time from its grant to its send; and a place for each link; each table
//!   with the flags that say which buffers are lent (`TransportRows::links_from`). The batch is
//!   the config's, held to the session's `PICO_UNICAST_BATCH_BYTES` under the build's; these are
//!   the rows lent when the session opens, first;
//! - with `group`, a receive buffer for each group the session may join, of the largest batch a
//!   group it names sends under the build's `PICO_MULTICAST_BATCH_BYTES`, which a group claims
//!   when it is joined, lent with the links' tables (`TransportRows::links_from`);
//! - with `udp-listen`, for a session that listens on a `udp/` endpoint, the slots its udp ports
//!   read their datagrams into and hold them in until the links of their peers take them
//!   (`UDP_PORT_SLOTS`, under the build's), each a link's batch long, which the ports share, lent
//!   with the links' tables; one that listens on `tcp/` alone binds no port and holds none;
//! - the buffers the links of the session stage the chains of their fragmented messages in, one
//!   table for the session, as many as its `REASSEMBLY_CHAINS` for each face read where it lies
//!   (under the build's; by default one for each reliability a peer has a chain open in and one for
//!   the rejoined message the round reads where its chain lay, `SESSION_CHAIN_BUFFERS` of
//!   `wz_runtime_coop::reassembly_rx`), a face's chains open at once held to that share, a
//!   first fragment that finds none free refused and counted (`LentStaging::refused` of
//!   `wz_session_core::chain_staging`), each buffer claimed when a chain's first fragment arrives and
//!   given back when the chain ends or the round lets its message go, each as long as the largest message the session
//!   rejoins (`PICO_FRAG_MAX_BYTES`, under the build's, which a chain past it is ended at, as pico
//!   ends one), with the flags that say which are lent (`TransportRows::lent_from`), lent
//!   with the links' tables;
//! - with `listen` or `group`, the places of the droppable publishes the session keeps for the
//!   faces they were not dropped on while a send holds it (`HANDED_LEG_BYTES`, under the build's),
//!   each a link's batch long, with their flags and a row beside each for the rest of the
//!   publish (`wz_runtime_coop::handed`), lent with the links' tables;
//! - the session's one table set, each declaration it announces and announces again over a new
//!   link a row of it ([`EntityRows`]): the key expressions it declares
//!   (`MAX_DECLARED_KEYEXPRS`), the write filters of its publishers (`MAX_PUBLISHERS`) and
//!   queriers (`MAX_QUERIERS`), its matching listeners (`MAX_MATCHING_LISTENERS`), and the
//!   Interests those filters and listeners hold open, at most one for each of them;
//! - the key arena every keyed row of the session keeps its key in (`KEY_ARENA_BYTES`, under the
//!   build's): that record's, the application's tables', each face's pending gets' and what each
//!   face's peer declares and asks, one area of blocks a key takes as long as it is held
//!   ([`wz_session_core::key_arena::KeySpace`]), lent after the record and before the tables
//!   that keep their keys in it. A peer's key that finds no room there is dropped and counted, as
//!   zenoh-pico drops a declaration its heap cannot hold;
//! - with [`ArenaPlan::holding`], last, the place the ABI keeps its own handle of the session in,
//!   and the places it keeps its objects of the session's entities in, one for each row the
//!   session keeps of each kind it names ([`HeldPlaces`]), so what the ABI holds of a session is
//!   reserved with the session, sized by the session's own limits, and takes no memory of its own.
//!
//! A table's entry is the registry's own `ROW_BYTES` as the lent policy lays the row out
//! ([`wz_session_core::bounded::Lent`]), and its count the value of its limit the open resolved,
//! under the build's value ([`Quota::lent_under`]): a stage after the build chooses within the
//! memory the build fixes and never adds to it, so a value over the build's refuses the open.
//!
//! A session holds the dial role's face, a face for each group it joins and as many faces besides
//! as `max_faces` admits, each a link it attaches or accepts, one still in its handshake among them
//! (`Core::accept_face` counts it against `max_faces`): the plan lends a set of a face's tables for
//! each of those and no more. The dial role's face is lent its set and its link's buffers only
//! when the session dials (`dials`): one that only listens or only joins groups never gives that
//! face a link or a peer, so the face holds a set of no rows and the session one link fewer. One
//! that listens holds the buffers of as many links again as `accept_pending` admits. The config's
//! two numbers are held to the session's `MAX_FACES` and
//! `MAX_ACCEPT_PENDING` under the build's, which [`admitted_faces`] and [`admitted_handshakes`]
//! give an ABI to state, and a config over either is refused. A group's face is no link of the
//! session's: it has a set of tables and no buffers. These are the tables whose limits bind at the
//! open (`binding_fixed = "open"`). What a group's members rejoin joins the plan with the unit that
//! lends it from the arena and bounds it by limits of its own (`docs/c-abi-no-heap-pools.md`,
//! section 4.14): reserved before then, it would be memory nothing uses.
//!
//! # The reservation is the report
//!
//! Each row is one span of the arena and every span starts on an [`ARENA_ALIGN`] boundary, so the
//! arena is the sum of its rows' spans ([`ArenaPlan::reserved_bytes`]), and lending every row
//! brings its high-water mark to its size and no further. The plan the open reserves by is the one
//! a report reads.
//!
//! # Where the memory comes from
//!
//! An [`ArenaMemory`], asked once for the whole arena, whose answer of none refuses the open rather
//! than ending the process: the allocator ([`AllocatorMemory`], as the ABI's object pools reserve
//! theirs), the system's fresh pages, zero as handed, that a host ABI reserves its sessions' arenas
//! in (`ArenaMemory::reserves_zeroed`), or a region an image places.

use core::alloc::Layout;
use core::ptr::NonNull;

use wz_runtime_coop::faces::EndpointTexts;
use wz_runtime_coop::kept::Kept;
use wz_runtime_coop::link_storage::LinkTables;
use wz_runtime_coop::reassembly_rx::LENT_CHAINS;
#[cfg(feature = "udp-listen")]
use wz_runtime_coop::udp_link::{PortPeerRow, PortRows, QueuedDatagram};
use wz_runtime_coop::RuntimePlace;
#[cfg(any(
    wz_lent,
    all(feature = "liveliness", any(feature = "listen", feature = "group"))
))]
use wz_session_core::bounded::Lent;
#[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
use wz_session_core::bounded::ZeroEmpty;
use wz_session_core::bounded::{Arena, LendRefused, TableLender, ARENA_ALIGN};
use wz_session_core::byte_cells::LentByteCells;
use wz_session_core::caps;
#[cfg(wz_lent)]
use wz_session_core::key_arena::KeySpace;
use wz_session_core::limit_binding::{Quota, UnlentRows};
use wz_session_core::limits::SessionLimits;
use wz_session_core::locator_directory::LocatorText;
#[cfg(wz_lent)]
use wz_session_core::peer_tables::PeerTables;
use wz_session_core::peer_tables::{PeerPoolRows, PeerRows, KEEPS_INTEREST_ROWS, SHARES_ROWS};
#[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
use wz_session_core::policy::HeldPublishDrop;
#[cfg(all(feature = "query", wz_lent))]
use wz_session_core::reply_sink::ConsolidatingSink;
use wz_session_core::row_pool::MAX_POOL_ROWS;
use wz_session_core::session_tables::TableRows;
#[cfg(wz_lent)]
use wz_session_core::slot_observer::HeapSinks;
use wz_session_core::slot_observer::RequesterRows;
#[cfg(all(feature = "query", wz_lent))]
use wz_session_core::slot_observer::Requesters;
#[cfg(wz_lent)]
use wz_session_core::slot_observer::SlotObserverOf;

#[cfg(all(feature = "query", wz_lent))]
use crate::engine::LegHold;
#[cfg(all(feature = "query", wz_lent))]
use crate::engine::LegSink;
#[cfg(any(feature = "listen", feature = "group"))]
use crate::engine::HELD_SET_BYTES;
#[cfg(all(wz_lent, wz_round))]
use crate::engine::REGISTRY_LEND_BYTES;
#[cfg(wz_lent)]
use crate::engine::ROOM_PLACE_BYTES;
#[cfg(wz_lent)]
use crate::engine::{CoopTables, FACE_SET_BYTES, ROUTER_LEND_BYTES};
#[cfg(all(wz_round, wz_lent))]
use crate::form::CoopForm;
use crate::form::SessionLock;
use crate::lodging::{LodgingRows, LodgingSpan};
use crate::open_source::EndpointList;
#[cfg(all(wz_round, wz_lent))]
use crate::round::CALLBACK_BYTES;
#[cfg(wz_round)]
use crate::round::{RoundRowCounts, RECORD_BYTES};
use crate::CoopConfig;
#[cfg(all(feature = "query", wz_lent))]
use wz_session_core::reply_hold::HeldReply;

/// `?` where a const fn reads a result: the value of an `Ok`, or the `Err` handed back as it is.
macro_rules! tried {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(refused) => return Err(refused),
        }
    };
}

/// The fewer of `a` and `b`, where a const fn reads it.
const fn least(a: usize, b: usize) -> usize {
    if a < b {
        a
    } else {
        b
    }
}

/// One part of what an arena holds: `count` items of `entry_bytes` each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaRow {
    /// What holds the bytes, and the limit whose number sizes the row.
    pub name: ArenaPart,
    /// How many items the row counts.
    pub count: usize,
    /// The bytes of one item.
    pub entry_bytes: usize,
}

impl ArenaRow {
    /// What holds the bytes ([`ArenaPart::part`]).
    pub const fn part(&self) -> &'static str {
        self.name.part()
    }

    /// The limit whose number sizes the row ([`ArenaPart::basis`]).
    pub const fn basis(&self) -> &'static str {
        self.name.basis()
    }

    /// The row's bytes: its count times its entry. `None` past the address space.
    pub const fn bytes(&self) -> Option<usize> {
        self.count.checked_mul(self.entry_bytes)
    }

    /// The bytes the row takes in an arena, its bytes as one span. `None` past the address space.
    pub const fn span(&self) -> Option<usize> {
        match self.bytes() {
            Some(bytes) => Arena::span(bytes),
            None => None,
        }
    }
}

/// What a row of an arena holds, a table's flags and its entries two parts: a byte for each row a
/// plan lays out, so laying a plan out passes no text, and only what reports a row reads the names
/// [`Self::part`] and [`Self::basis`] give, from the one table of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArenaPart {
    EndpointTexts,
    LinkReceiveFlags,
    LinkReceiveBuffers,
    LinkTransmitFlags,
    LinkTransmitSlots,
    LinkPlaces,
    LinkGroupReceiveFlags,
    LinkGroupReceiveBuffers,
    LinkPortDatagramFlags,
    LinkPortDatagramSlots,
    UdpPortPeers,
    UdpPortQueue,
    DeliveryRecords,
    DeliveryCallbacks,
    DeliveryKeys,
    DeliveryRound,
    RegistryLend,
    RouterLend,
    DirectFaces,
    LinkRooms,
    RoomPlaces,
    ReassemblyFlags,
    ReassemblyBuffers,
    HandedLegFlags,
    HandedLegPlaces,
    HandedLegs,
    DeclarationWatchers,
    PendingGets,
    EndedLegs,
    LegCallbacks,
    PendingLegs,
    HeldReplies,
    FaceTables,
    HeldFaces,
    PeerTables,
    PeerAliasPool,
    PeerDeclarationPools,
    PeerInterestPool,
    PeerRowDirectory,
    OwedTokens,
    HeldFinals,
    RefusedFinals,
    CacheRingFlag,
    CacheRing,
    SessionTables,
    KeyArena,
    LinkCellFlags,
    LinkCells,
    LinkGateFlags,
    LinkGates,
    LinkActionsFlags,
    LinkActions,
    LinkHalvesFlags,
    LinkHalves,
    SessionHandleFlag,
    SessionHandle,
    PublisherPlaceFlags,
    PublisherPlaces,
    SubscriberPlaceFlags,
    SubscriberPlaces,
    QueryablePlaceFlags,
    QueryablePlaces,
    TokenPlaceFlags,
    TokenPlaces,
    LivelinessSubscriberPlaceFlags,
    LivelinessSubscriberPlaces,
    QuerierPlaceFlags,
    QuerierPlaces,
    PendingGetPlaceFlags,
    PendingGetPlaces,
    PendingLivelinessGetPlaceFlags,
    PendingLivelinessGetPlaces,
    MatchingListenerPlaceFlags,
    MatchingListenerPlaces,
    DeclWatchPlaceFlags,
    DeclWatchPlaces,
    TransportEventsListenerPlaceFlags,
    TransportEventsListenerPlaces,
    AdvancedPublisherPlaceFlags,
    AdvancedPublisherPlaces,
    AdvancedSubscriberPlaceFlags,
    AdvancedSubscriberPlaces,
    LinkEventsListenerPlaceFlags,
    LinkEventsListenerPlaces,
    LodgingPlaces,
    ArenaKeep,
    RuntimeState,
    EngineState,
    QueryPlaneState,
    GetPlaneState,
    FacePlaneState,
    LinkAdmissionState,
}

impl ArenaPart {
    /// What holds the bytes.
    pub const fn part(self) -> &'static str {
        self.names().0
    }

    /// The limit whose number sizes the row.
    pub const fn basis(self) -> &'static str {
        self.names().1
    }

    /// Each part's name and the limit whose number sizes it, a row each.
    const fn names(self) -> (&'static str, &'static str) {
        const GETS: &str = "MAX_PENDING_QUERIES + MAX_PENDING_LIVELINESS_GETS";
        match self {
            Self::EndpointTexts => ("endpoint texts", "MAX_STATIC_CONNECT + MAX_ADMIN_LOCATORS"),
            Self::LinkReceiveFlags => ("link receive flags", RX_BASIS),
            Self::LinkReceiveBuffers => ("link receive buffers", RX_BASIS),
            Self::LinkTransmitFlags => ("link transmit flags", TX_BASIS),
            Self::LinkTransmitSlots => ("link transmit slots", TX_BASIS),
            Self::LinkPlaces => ("link places", LINK_BASIS),
            Self::LinkGroupReceiveFlags => {
                ("link group receive flags", "PICO_MULTICAST_BATCH_BYTES")
            }
            Self::LinkGroupReceiveBuffers => {
                ("link group receive buffers", "PICO_MULTICAST_BATCH_BYTES")
            }
            Self::LinkPortDatagramFlags => ("link port datagram flags", "UDP_PORT_SLOTS"),
            Self::LinkPortDatagramSlots => ("link port datagram slots", "UDP_PORT_SLOTS"),
            Self::UdpPortPeers => ("udp port peers", LINK_BASIS),
            Self::UdpPortQueue => ("udp port queue", "UDP_PORT_SLOTS"),
            Self::DeliveryRecords => ("delivery records", "DELIVERY_LANE_EVENTS"),
            Self::DeliveryCallbacks => ("delivery callbacks", "DELIVERY_LANE_CALLBACKS"),
            Self::DeliveryKeys => ("delivery keys", "MAX_KEYEXPR_BYTES"),
            Self::DeliveryRound => ("delivery round", ""),
            Self::RegistryLend => ("registry lend", ""),
            Self::RouterLend => ("router lend", ""),
            Self::DirectFaces => ("direct faces", "MAX_FACES"),
            Self::LinkRooms => ("link rooms", ""),
            Self::RoomPlaces => ("room places", "MAX_FACES + 1"),
            Self::ReassemblyFlags => ("reassembly flags", "REASSEMBLY_CHAINS"),
            Self::ReassemblyBuffers => ("reassembly buffers", "REASSEMBLY_CHAINS"),
            Self::HandedLegFlags => ("handed leg flags", "HANDED_LEG_BYTES"),
            Self::HandedLegPlaces => ("handed leg places", "HANDED_LEG_BYTES"),
            Self::HandedLegs => ("handed legs", "HANDED_LEG_BYTES"),
            Self::DeclarationWatchers => ("declaration watchers", "MAX_DECL_OBSERVERS"),
            Self::PendingGets => ("pending gets", GETS),
            Self::EndedLegs => ("ended legs", GETS),
            Self::LegCallbacks => ("leg callbacks", GETS),
            Self::PendingLegs => ("pending legs", GETS),
            Self::HeldReplies => ("held replies", "MAX_PENDING_REPLIES"),
            Self::FaceTables => ("face tables", "MAX_FACES + 1"),
            Self::HeldFaces => ("held faces", "MAX_FACES + 1"),
            Self::PeerTables => ("peer tables", "MAX_PENDING_DECLARES + MAX_PENDING_FINALS"),
            Self::PeerAliasPool => ("peer alias pool", ALIAS_LIMITS.session.name()),
            Self::PeerDeclarationPools => ("peer declaration pools", DECL_LIMITS.session.name()),
            Self::PeerInterestPool => ("peer interest pool", INTEREST_LIMITS.session.name()),
            Self::PeerRowDirectory => ("peer row directory", ""),
            Self::OwedTokens => ("owed tokens", "SESSION_MAX_REMOTE_DECLS"),
            Self::HeldFinals => ("held finals", "MAX_PENDING_FINALS"),
            Self::RefusedFinals => ("refused finals", "MAX_PENDING_FINALS"),
            Self::CacheRingFlag => ("cache ring flag", "ADVANCED_CACHE_BYTES"),
            Self::CacheRing => ("cache ring", "ADVANCED_CACHE_BYTES"),
            Self::SessionTables => ("session tables", "MAX_DECLARED_KEYEXPRS"),
            Self::KeyArena => ("key arena", "KEY_ARENA_BYTES"),
            Self::LinkCellFlags => ("link cell flags", LINK_BASIS),
            Self::LinkCells => ("link cells", LINK_BASIS),
            Self::LinkGateFlags => ("link gate flags", LINK_BASIS),
            Self::LinkGates => ("link gates", LINK_BASIS),
            Self::LinkActionsFlags => ("link actions flags", LINK_BASIS),
            Self::LinkActions => ("link actions", LINK_BASIS),
            Self::LinkHalvesFlags => ("link halves flags", LINK_BASIS),
            Self::LinkHalves => ("link halves", LINK_BASIS),
            Self::SessionHandleFlag => ("session handle flag", ""),
            Self::SessionHandle => ("session handle", ""),
            Self::PublisherPlaceFlags => ("publisher place flags", "MAX_PUBLISHERS"),
            Self::PublisherPlaces => ("publisher places", "MAX_PUBLISHERS"),
            Self::SubscriberPlaceFlags => ("subscriber place flags", "MAX_SUBSCRIPTIONS"),
            Self::SubscriberPlaces => ("subscriber places", "MAX_SUBSCRIPTIONS"),
            Self::QueryablePlaceFlags => ("queryable place flags", "MAX_QUERYABLES"),
            Self::QueryablePlaces => ("queryable places", "MAX_QUERYABLES"),
            Self::TokenPlaceFlags => ("token place flags", "MAX_LOCAL_TOKENS"),
            Self::TokenPlaces => ("token places", "MAX_LOCAL_TOKENS"),
            Self::LivelinessSubscriberPlaceFlags => (
                "liveliness subscriber place flags",
                "MAX_LIVELINESS_SUBSCRIPTIONS",
            ),
            Self::LivelinessSubscriberPlaces => (
                "liveliness subscriber places",
                "MAX_LIVELINESS_SUBSCRIPTIONS",
            ),
            Self::QuerierPlaceFlags => ("querier place flags", "MAX_QUERIERS"),
            Self::QuerierPlaces => ("querier places", "MAX_QUERIERS"),
            Self::PendingGetPlaceFlags => ("pending get place flags", "MAX_PENDING_QUERIES"),
            Self::PendingGetPlaces => ("pending get places", "MAX_PENDING_QUERIES"),
            Self::PendingLivelinessGetPlaceFlags => (
                "pending liveliness get place flags",
                "MAX_PENDING_LIVELINESS_GETS",
            ),
            Self::PendingLivelinessGetPlaces => (
                "pending liveliness get places",
                "MAX_PENDING_LIVELINESS_GETS",
            ),
            Self::MatchingListenerPlaceFlags => {
                ("matching listener place flags", "MAX_MATCHING_LISTENERS")
            }
            Self::MatchingListenerPlaces => ("matching listener places", "MAX_MATCHING_LISTENERS"),
            Self::DeclWatchPlaceFlags => ("declaration watch place flags", "MAX_DECL_WATCHES"),
            Self::DeclWatchPlaces => ("declaration watch places", "MAX_DECL_WATCHES"),
            Self::TransportEventsListenerPlaceFlags => (
                "transport events listener place flags",
                "MAX_TRANSPORT_EVENTS_LISTENERS",
            ),
            Self::TransportEventsListenerPlaces => (
                "transport events listener places",
                "MAX_TRANSPORT_EVENTS_LISTENERS",
            ),
            Self::AdvancedPublisherPlaceFlags => {
                ("advanced publisher place flags", "MAX_ADVANCED_PUBLISHERS")
            }
            Self::AdvancedPublisherPlaces => {
                ("advanced publisher places", "MAX_ADVANCED_PUBLISHERS")
            }
            Self::AdvancedSubscriberPlaceFlags => (
                "advanced subscriber place flags",
                "MAX_ADVANCED_SUBSCRIBERS",
            ),
            Self::AdvancedSubscriberPlaces => {
                ("advanced subscriber places", "MAX_ADVANCED_SUBSCRIBERS")
            }
            Self::LinkEventsListenerPlaceFlags => (
                "link events listener place flags",
                "MAX_LINK_EVENTS_LISTENERS",
            ),
            Self::LinkEventsListenerPlaces => {
                ("link events listener places", "MAX_LINK_EVENTS_LISTENERS")
            }
            Self::LodgingPlaces => ("lodging places", ""),
            Self::ArenaKeep => ("arena keep", ""),
            Self::RuntimeState => ("runtime state", "MAX_TASKS + MAX_TIMERS"),
            Self::EngineState => ("engine state", ""),
            Self::QueryPlaneState => ("query plane", ""),
            Self::GetPlaneState => ("get plane", ""),
            Self::FacePlaneState => ("face plane", ""),
            Self::LinkAdmissionState => ("link admission", ""),
        }
    }
}

// The rows of a plan, group by group, each counted where the group's rows are put and under the
// same features: a group that gains or loses a row changes its own count, and the plan's length
// follows ([`ARENA_ROWS`]).

/// The texts of the endpoints the session dials and listens on: one row of both tables.
const ENDPOINT_ROWS: usize = 1;
/// The links' receive flags and buffers and transmit flags and slots, and with `listen` their
/// places.
const LINK_ROWS: usize = 4 + cfg!(feature = "listen") as usize;
/// The round's records where the arena lends them, the callbacks they owe, its keys and the round
/// itself, where the open places them in the arena (`runtime-plan`); a region holds them otherwise:
/// the round keeps no area, since every record is read where it lies, and a round of one thread
/// keeps its records in itself.
#[cfg(wz_round)]
const LANE_ROWS: usize = ((RECORD_BYTES != 0) as usize + 3) * cfg!(wz_lent) as usize;
/// A build that puts nothing in the round (`wz_round`) places none, nor any of its tables.
#[cfg(not(wz_round))]
const LANE_ROWS: usize = 0;
/// The places the session lends its Router and, where its links run as tasks, its registry in for
/// a step, where the open places them in the arena (`runtime-plan`); a region holds them otherwise.
const STEP_LEND_ROWS: usize = cfg!(wz_lent) as usize * (1 + cfg!(wz_round) as usize);
/// The reassembly buffers' flags and the buffers.
const REASSEMBLY_ROWS: usize = 2;
/// The read slots and send places of the faces past the dial role's, where each face is read where
/// it lies (`crate::engine::direct`): a build whose links run as tasks (`wz_round`) has none, nor
/// does one that listens on no port (`listen`), the one role that reads a face past the dial
/// role's where it lies (`read_faces`).
const DIRECT_FACE_ROWS: usize = (!cfg!(wz_round) && cfg!(feature = "listen")) as usize;
/// The receive buffers of the groups the session may join and their flags (`group`).
const GROUP_RX_ROWS: usize = 2 * cfg!(feature = "group") as usize;
/// The slots of the datagrams the udp ports of a session that listens hold and their flags, and the
/// rows of the peers the ports took and of the datagrams sorted for them (`udp-listen`).
const PORT_RX_ROWS: usize = 4 * cfg!(feature = "udp-listen") as usize;
/// The places of the publishes the session keeps for its other faces, their flags and the rows
/// beside them (`listen` or `group`, in the work form, `wz_round`): a build of the dial face
/// alone owes no other face, nor does one that sends each face its own leg (`direct`).
const HANDED_ROWS: usize =
    3 * cfg!(all(wz_round, any(feature = "listen", feature = "group"))) as usize;
/// The application's tables apart from the session's one table set: the declaration watchers,
/// where the arena lends them (`runtime-plan`).
const OBSERVER_ROWS: usize = cfg!(wz_lent) as usize;
/// The pending gets, the ends of the legs, the legs' callbacks, the session's note of each leg
/// pending and the replies the gets that consolidate hold, of a build that asks (`query`), where
/// the arena lends them (`runtime-plan`): one that asks nothing holds no table of gets, and a
/// region holds them otherwise (`crate::engine::StatePlaces`).
const GET_ROWS: usize = 5 * cfg!(all(feature = "query", wz_lent)) as usize;
/// The faces' sets where the arena lends them (`runtime-plan`), and the index of the held ones
/// where the build takes faces beside its dial role's (`TAKES_FACES`): a session of that face
/// alone knows it holds the first set.
const FACE_ROWS: usize = cfg!(wz_lent) as usize + TAKES_FACES as usize;
/// The faces' rooms, laid out at the open ([`ArenaPlan::holding_rooms`]), and their places, one
/// for each set of face tables, where the arena lends them (`runtime-plan`); a region holds its
/// one set's place otherwise.
const ROOM_ROWS: usize = 1 + cfg!(wz_lent) as usize;
/// The peers' tables, and the pools their rows lie in where the faces share them with the one span
/// naming where those rows lie, where the arena lends them (`runtime-plan`): the aliases' and the
/// declarations' pools, and the interests' where the build keeps a peer's (`KEEPS_INTEREST_ROWS`).
const PEER_ROWS: usize =
    cfg!(wz_lent) as usize * (1 + (3 + KEEPS_INTEREST_ROWS as usize) * SHARES_ROWS as usize);
/// The tokens the faces that went still owe (`liveliness` with `listen` or `group`): put only for a
/// session whose faces share their pools, so counted where a build shares them at all.
const OWED_ROWS: usize = (cfg!(all(
    feature = "liveliness",
    any(feature = "listen", feature = "group")
)) && SHARES_ROWS) as usize;
/// The session's declarations, the session's one table set and the key arena, where the arena
/// lends them (`runtime-plan`; `ArenaPlan::put_entities`).
const ENTITY_ROWS: usize = 2 * cfg!(wz_lent) as usize;
/// The links' cells, their gates', their sessions' actions' and the halves those hold, each a
/// table of flags and cells ([`ArenaPlan::holding_cells`]).
const CELL_ROWS: usize = 8;
/// The ABI's handle's flag and place ([`ArenaPlan::holding`]).
const HANDLE_ROWS: usize = 2;
/// The flags and the places the ABI keeps its objects of the session's entities in, of each kind
/// the session keeps rows of ([`ArenaPlan::holding`]): publishers, subscribers and queriers, and
/// queryables (`queryable`), tokens and liveliness subscribers (`liveliness`), pending gets
/// (`query`), pending liveliness gets (`liveliness-get`), matching listeners, declaration watches
/// (`remote-declaration-watch` or `declarations-synced-event`), transport and link events
/// listeners (`connectivity`) and advanced publishers and subscribers (`advanced`), as many as the
/// ABI asks places of, at most these.
const ENTITY_PLACE_ROWS: usize = 2
    * (4 + cfg!(feature = "queryable") as usize
        + 2 * cfg!(feature = "liveliness") as usize
        + cfg!(feature = "query") as usize
        + cfg!(feature = "liveliness-get") as usize
        + cfg!(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        )) as usize
        + 2 * cfg!(feature = "connectivity") as usize
        + 2 * cfg!(feature = "advanced") as usize);

/// The most rows a plan holds: every row of the build, the cells', the ABI's handle's and its
/// entities' places among them, the sum of the groups' counts.
pub const ARENA_ROWS: usize = ENDPOINT_ROWS
    + LINK_ROWS
    + LANE_ROWS
    + STEP_LEND_ROWS
    + REASSEMBLY_ROWS
    + DIRECT_FACE_ROWS
    + GROUP_RX_ROWS
    + PORT_RX_ROWS
    + HANDED_ROWS
    + OBSERVER_ROWS
    + GET_ROWS
    + FACE_ROWS
    + ROOM_ROWS
    + PEER_ROWS
    + OWED_ROWS
    + ENTITY_ROWS
    + CELL_ROWS
    + HANDLE_ROWS
    + ENTITY_PLACE_ROWS
    + LODGING_ROWS
    + CACHE_RING_ROWS
    + FINAL_ROWS
    + RUNTIME_ROWS
    + ENGINE_STATE_ROWS
    + PLANE_ROWS
    + ADMISSION_ROWS;

/// The places for values lodged by counts, the ABI's and the engine's, one table of cells that
/// each carry their own mark ([`ArenaPlan::holding`]).
const LODGING_ROWS: usize = 1;
/// The flag and the span of the ring the advanced publishers' caches keep their samples in
/// (`advanced-cache`).
const CACHE_RING_ROWS: usize = 2 * cfg!(feature = "advanced-cache") as usize;
/// The Finals the queryables' plane holds and the requests a dispatch refused (`queryable`), where
/// the arena lends them (`runtime-plan`); a region holds them otherwise.
const FINAL_ROWS: usize = 2 * cfg!(all(feature = "queryable", wz_lent)) as usize;
/// The count the arena is kept by and the span the session's runtime is placed in
/// ([`ArenaPlan::holding_runtime`]).
const RUNTIME_ROWS: usize = 2;
/// The place the session's engine lies in ([`ArenaPlan::holding_engine`]).
const ENGINE_STATE_ROWS: usize = 1;
/// The planes the session's queryables, gets and watchers of its faces share, each where its
/// feature is ([`ArenaPlan::lay_planes`]), where the arena holds them (`runtime-plan`).
const PLANE_ROWS: usize = cfg!(wz_lent) as usize
    * (cfg!(feature = "queryable") as usize
        + cfg!(feature = "query") as usize
        + cfg!(feature = "connectivity") as usize);
/// The admission the links of a session that listens ask while their handshakes run
/// (`ArenaPlan::lay_admission`, `link-admission`): a build without it lays none out.
const ADMISSION_ROWS: usize = cfg!(feature = "link-admission") as usize;

pub use wz_capi_port::{EntityKind, EntityPlace, ENTITY_KINDS};

/// The two parts of `kind`'s places, the flags and the places.
const fn place_parts(kind: EntityKind) -> [ArenaPart; 2] {
    match kind {
        EntityKind::Publisher => [ArenaPart::PublisherPlaceFlags, ArenaPart::PublisherPlaces],
        EntityKind::Subscriber => [ArenaPart::SubscriberPlaceFlags, ArenaPart::SubscriberPlaces],
        EntityKind::Queryable => [ArenaPart::QueryablePlaceFlags, ArenaPart::QueryablePlaces],
        EntityKind::Token => [ArenaPart::TokenPlaceFlags, ArenaPart::TokenPlaces],
        EntityKind::LivelinessSubscriber => [
            ArenaPart::LivelinessSubscriberPlaceFlags,
            ArenaPart::LivelinessSubscriberPlaces,
        ],
        EntityKind::Querier => [ArenaPart::QuerierPlaceFlags, ArenaPart::QuerierPlaces],
        EntityKind::PendingGet => [ArenaPart::PendingGetPlaceFlags, ArenaPart::PendingGetPlaces],
        EntityKind::PendingLivelinessGet => [
            ArenaPart::PendingLivelinessGetPlaceFlags,
            ArenaPart::PendingLivelinessGetPlaces,
        ],
        EntityKind::MatchingListener => [
            ArenaPart::MatchingListenerPlaceFlags,
            ArenaPart::MatchingListenerPlaces,
        ],
        EntityKind::DeclWatch => [ArenaPart::DeclWatchPlaceFlags, ArenaPart::DeclWatchPlaces],
        EntityKind::TransportEventsListener => [
            ArenaPart::TransportEventsListenerPlaceFlags,
            ArenaPart::TransportEventsListenerPlaces,
        ],
        EntityKind::AdvancedPublisher => [
            ArenaPart::AdvancedPublisherPlaceFlags,
            ArenaPart::AdvancedPublisherPlaces,
        ],
        EntityKind::AdvancedSubscriber => [
            ArenaPart::AdvancedSubscriberPlaceFlags,
            ArenaPart::AdvancedSubscriberPlaces,
        ],
        EntityKind::LinkEventsListener => [
            ArenaPart::LinkEventsListenerPlaceFlags,
            ArenaPart::LinkEventsListenerPlaces,
        ],
    }
}

/// What an ABI keeps of its own in a session's arena, laid out after every table of the session
/// ([`ArenaPlan::holding`]): a place for its handle of the session, and for each kind of entity it
/// names, a place of that layout for each row the session keeps of the kind. What it holds there is
/// reserved with the session and takes no memory of its own, and an open whose arena cannot hold it
/// opens nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldPlaces {
    handle: Option<Layout>,
    entities: [Option<Layout>; ENTITY_KINDS],
    /// The table of places for values lodged by counts ([`Self::with_lodgings`]), laid out by the
    /// largest asked; `None` once one asked is past what an arena holds.
    lodging: Option<LodgingRows>,
}

impl Default for HeldPlaces {
    /// No place at all.
    fn default() -> Self {
        Self::NONE
    }
}

/// Where an open's arena comes from and where its rows come from
/// ([`CoopEngine::open_made_in`](crate::CoopEngine::open_made_in)).
pub struct OpenStorage {
    /// The memory the session's arena is reserved from.
    pub memory: &'static dyn ArenaMemory,
    /// Where the rows of the session's tables, and those of the places held after them, come
    /// from.
    pub plan: PlanFrom,
}

/// Where the rows of an open's arena come from ([`OpenStorage::plan`]): the rows of the session's
/// tables and after them the links' cells, the faces' rooms, the ABI's places, the runtime's span
/// and the engine's place ([`ArenaPlan::holding_cells`], [`ArenaPlan::holding`]).
#[derive(Clone, Copy, Debug)]
pub enum PlanFrom {
    /// The region the build laid out when it was compiled, its places with it ([`OpenRegion`]):
    /// the open lays out no row. An open of a config that dials more endpoints than it holds rows
    /// for, or whose other numbers or limits are not the region's, is refused under the limit that
    /// differs.
    Region(&'static OpenRegion),
    /// The config the open is handed, its rows laid out at the open ([`ArenaPlan::count`]) and
    /// after them the engine's places and the ABI's places named here: a build with
    /// `runtime-plan`, whose image carries the walk of the rows. The places are named where they
    /// lie, a constant of the ABI as the region is one of the build, so what an open is handed
    /// is a word and a tag whichever way its rows come, and no image copies them on the way.
    #[cfg(any(feature = "runtime-plan", test))]
    Config(&'static HeldPlaces),
}

/// The rows of a session's tables a build knows when it is compiled: the plan of a session of
/// `shape` under `limits` ([`ArenaPlan::planned`]), evaluated where the region is a constant,
/// so an open by it runs none of the walk.
#[derive(Debug, PartialEq, Eq)]
pub struct ArenaRegion {
    plan: ArenaPlan,
    shape: PlanShape,
    limits: SessionLimits,
}

impl ArenaRegion {
    /// The region of a session of `shape` under `limits`, refused as [`ArenaPlan::planned`]
    /// refuses it: the rows of its tables, which an open by it takes once the engine's places are
    /// laid out after them ([`OpenRegion`]).
    pub const fn of(shape: PlanShape, limits: SessionLimits) -> Result<Self, ArenaRefused> {
        match ArenaPlan::planned(shape, &limits) {
            Ok(plan) => Ok(Self {
                plan,
                shape,
                limits,
            }),
            Err(refused) => Err(refused),
        }
    }

    /// The rows of the session's tables the region lays out ([`ArenaPlan::tables`]).
    pub const fn tables(&self) -> TableRows {
        self.plan.tables()
    }

    /// The limits a session of the region opens under, and no other.
    pub const fn limits(&self) -> &SessionLimits {
        &self.limits
    }

    /// The numbers of the config the region was laid out for; a config that dials fewer
    /// endpoints opens in it too ([`Self::admit`]).
    pub const fn shape(&self) -> &PlanShape {
        &self.shape
    }

    /// Lay out on `plan`, an open's blank plan or [`ArenaPlan::vacant`] as made, this region's
    /// rows for an open of `config`, the plan [`ArenaPlan::count`] would lay out for a config of
    /// the region's shape and limits, refused as [`Self::admit`] refuses the config.
    #[cfg(feature = "runtime-plan")]
    pub(crate) fn lay_out_on<E: EndpointList, const ROWS: usize>(
        &self,
        plan: &mut ArenaPlan<ROWS>,
        config: &CoopConfig<E>,
    ) -> Result<(), ArenaRefused> {
        self.admit(config)?;
        plan.take_on(&self.plan);
        Ok(())
    }

    /// Lay out on `plan`, [`ArenaPlan::vacant`] as made, this region's rows for an open of
    /// `config`, the plan [`ArenaPlan::count`] would lay out for a config of the region's shape
    /// and limits, refused as [`Self::admit`] refuses the config.
    #[cfg(not(feature = "runtime-plan"))]
    pub(crate) fn lay_out_on<E: EndpointList>(
        &self,
        plan: &mut ArenaPlan,
        config: &CoopConfig<E>,
    ) -> Result<(), ArenaRefused> {
        self.admit(config)?;
        // Stored whole over the plan the open made, so the optimiser drops that plan's making:
        // a build without `runtime-plan` lists no rows, and its open's plan is this one alone.
        plan.clone_from(&self.plan);
        Ok(())
    }

    /// Whether a session of `config` opens in this region. A region holds a row of text for each
    /// endpoint it may dial, so a config that dials fewer leaves rows unwritten, and one that dials
    /// more is refused under `MAX_STATIC_CONNECT`; any other number of the config, or limits, not
    /// the region's is refused under [`ArenaLimit::ShapeDiffersFromBuild`] or
    /// [`ArenaLimit::LimitsDifferFromBuild`], whose rows would be sized for another session. What
    /// an open whose rows are a type's fields asks in place of a plan: it lays out nothing.
    pub fn admit<E: EndpointList>(&self, config: &CoopConfig<E>) -> Result<(), ArenaRefused> {
        let shape = PlanShape::of(config);
        hold(ArenaLimit::MaxStaticConnect, shape.dials, self.shape.dials)?;
        // The handshakes a config admits size nothing for a session that listens on nothing
        // (`links_for`), which a region of no listener lays out for any.
        let accept_pending = if shape.listens == 0 {
            self.shape.accept_pending
        } else {
            shape.accept_pending
        };
        let undialled = PlanShape {
            dials: self.shape.dials,
            accept_pending,
            ..shape
        };
        if undialled != self.shape {
            return Err(ArenaRefused::Limit {
                limit: ArenaLimit::ShapeDiffersFromBuild,
                why: UnlentRows::NoCeiling,
            });
        }
        if config.limits != self.limits {
            return Err(ArenaRefused::Limit {
                limit: ArenaLimit::LimitsDifferFromBuild,
                why: UnlentRows::NoCeiling,
            });
        }
        Ok(())
    }
}

/// The region an open by it lays out nothing for: the rows of a session's tables
/// ([`ArenaRegion`]) and after them every place the session's engine keeps beside those tables
/// (its links' cells, its faces' rooms, the ABI's places, its runtime's span, its own place and its
/// planes'), laid out as an open over a config lays them out ([`ArenaPlan::holding_cells`],
/// [`ArenaPlan::holding`]). Each is the size of a type of the engine or a constant of the ABI, so
/// a build that states its region as a constant has every row laid out when it is compiled. Made
/// by the engine that opens by it ([`CoopEngine::open_region`](crate::CoopEngine::open_region));
/// an open by it compares the config with the region ([`Self::admit`]) and takes the plan whole.
#[derive(Debug, PartialEq, Eq)]
pub struct OpenRegion {
    rows: ArenaRegion,
    places: OpenPlaces,
}

/// The bytes of the two places an open lends by their size after its tables: the span its
/// runtime is placed in and the place its engine lies in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenPlaces {
    pub(crate) runtime: usize,
    pub(crate) engine: usize,
}

impl OpenRegion {
    /// `rows` with the places `holds` names laid out after its tables, as an open over a config
    /// lays them out (`crate::engine::lay_out_open`), and refused as that refuses them.
    pub(crate) const fn laid(
        mut rows: ArenaRegion,
        holds: &crate::engine::OpenHolds<'_>,
    ) -> Result<Self, ArenaRefused> {
        match crate::engine::lay_out_open(&mut rows.plan, holds) {
            Ok(()) => Ok(Self {
                rows,
                places: OpenPlaces {
                    runtime: holds.runtime,
                    engine: holds.engine,
                },
            }),
            Err(refused) => Err(refused),
        }
    }

    /// The rows of the session's tables the region lays out ([`ArenaPlan::tables`]).
    pub const fn tables(&self) -> TableRows {
        self.rows.tables()
    }

    /// The limits a session of the region opens under, and no other.
    pub const fn limits(&self) -> &SessionLimits {
        self.rows.limits()
    }

    /// The bytes the arena of an open by the region reserves: its tables' rows and its places'.
    /// `None` past the address space.
    pub const fn reserved_bytes(&self) -> Option<usize> {
        self.rows.plan.reserved_bytes()
    }

    /// Whether a session of `config` opens in this region ([`ArenaRegion::admit`]).
    pub fn admit<E: EndpointList>(&self, config: &CoopConfig<E>) -> Result<(), ArenaRefused> {
        self.rows.admit(config)
    }

    /// The region's rows, its places among them, as an open takes them
    /// (`ArenaRegion::lay_out_on`).
    pub(crate) const fn rows(&self) -> &ArenaRegion {
        &self.rows
    }

    /// The bytes of the runtime's span and of the engine's place the region laid out.
    pub(crate) const fn places(&self) -> OpenPlaces {
        self.places
    }

    /// The bytes of each link's cells the region laid out, `0` for a table it holds none of.
    pub(crate) const fn cell_bytes(&self) -> LinkCells<usize> {
        self.rows.plan.transport.cell_bytes
    }
}

/// The table of lodgings of no place: none, its places laid out for the watchers of the faces'
/// snapshots the engine lodges itself in a build that has them, so an open counts those places and
/// lays none out ([`ArenaPlan::holding`]).
#[cfg(feature = "connectivity")]
const NO_LODGINGS: Option<LodgingRows> = LodgingRows::NONE.with(
    wz_capi_port::lodge::Lent::<wz_capi_port::face_rows::Gathering>::LAYOUT,
    0,
);
/// The table of lodgings of no place.
#[cfg(not(feature = "connectivity"))]
const NO_LODGINGS: Option<LodgingRows> = Some(LodgingRows::NONE);

impl HeldPlaces {
    /// No place at all.
    pub const NONE: Self = Self {
        handle: None,
        entities: [None; ENTITY_KINDS],
        lodging: NO_LODGINGS,
    };

    /// A place of `layout` for the ABI's handle of the session, and none for its entities.
    pub const fn handle(layout: Layout) -> Self {
        Self {
            handle: Some(layout),
            ..Self::NONE
        }
    }

    /// These places, with `count` more places for values lodged by counts that may outlive the
    /// session ([`wz_capi_port::lodge::Lent::of_bytes`]), each of at least `layout`
    /// (`Lent::<T>::LAYOUT` for a `T`): one table of them, every place as large and as aligned
    /// as the largest asked, lent and given back from any thread
    /// ([`wz_capi_port::PlaceLender::lend_lodging`]). A `const fn`, as [`Self::with_entity`].
    pub const fn with_lodgings(mut self, layout: Layout, count: usize) -> Self {
        if let Some(rows) = self.lodging {
            self.lodging = rows.with(layout, count);
        }
        self
    }

    /// These places, with a place of `layout` for each row the session keeps of `kind`. A
    /// `const fn`, so an ABI whose places are known when it is built states them as a constant
    /// and its open lays none of them out at run time.
    pub const fn with_entity(mut self, kind: EntityKind, layout: Layout) -> Self {
        // The kind's place is the first past the places of the kinds before it.
        if let Some((_, [place, ..])) = self.entities.split_at_mut_checked(kind as usize) {
            *place = Some(layout);
        }
        self
    }

    /// The first kind at or after the place `from` in [`EntityKind::ALL`] these places name a
    /// layout for: its place there and the layout. A walk by it ends on the places named.
    const fn next_entity(&self, from: usize) -> Option<(usize, Layout)> {
        let mut at = from;
        while let Some((_, [place, ..])) = self.entities.split_at_checked(at) {
            if let Some(layout) = *place {
                return Some((at, layout));
            }
            at = at.saturating_add(1);
        }
        None
    }
}

/// What sizes the links' receive rows: the pool's limit in a build that listens, the batch in one
/// that only dials, whose every link has a buffer of its own.
#[cfg(feature = "listen")]
const RX_BASIS: &str = "RX_POOL_BUFFERS";
#[cfg(not(feature = "listen"))]
const RX_BASIS: &str = "PICO_UNICAST_BATCH_BYTES";
/// What sizes the links' transmit rows, as [`RX_BASIS`] for the receive rows.
#[cfg(feature = "listen")]
const TX_BASIS: &str = "TX_POOL_SLOTS";
#[cfg(not(feature = "listen"))]
const TX_BASIS: &str = "PICO_UNICAST_BATCH_BYTES";

/// The slots each link holds at once to encode its frames into, from the pool its session's links
/// share (`TX_POOL_SLOTS`): one, as zenoh-pico keeps one write buffer
/// (`vendor/zenoh-pico/src/transport/common/tx.c` @
/// `static z_result_t _z_transport_tx_send_t_msg_inner(_z_transport_common_t *ztc, const _z_transport_message_t *t_msg,`).
/// The batch a session holds open is sent before a message that does not join it takes the slot:
/// a transport message drains the open batch first (`send_close_with_reason`, `send_keep_alive`),
/// and a frame of the other reliability closes it. A stream link keeps the slot of a frame it has
/// not written whole until it has, so the next frame asks for room within its message's wait,
/// which writes it (`wait_for_room`), and a message that asks for a slot meanwhile writes it first
/// (`StreamDriver::tx_slot_acquire` in `wz-runtime-coop`).
pub const LINK_TX_SLOTS: usize = 1;

// A link of a pool holds one slot at a time (`wz_runtime_coop::link_storage::PooledTx`).
const _: () = assert!(LINK_TX_SLOTS == 1);

/// A limit an arena is sized by, as a refusal names it ([`ArenaRefused::Limit`]): a byte, so
/// laying a plan out passes no text, and only what reports a refusal reads [`Self::name`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArenaLimit {
    MaxFaces,
    MaxStaticConnect,
    MaxAdminLocators,
    MaxAcceptPending,
    PicoFragMaxBytes,
    DeliveryLaneEvents,
    DeliveryLaneCallbacks,
    MaxKeyexprBytes,
    KeyArenaBytes,
    UdpPortSlots,
    HandedLegBytes,
    MaxDeclObservers,
    MaxPendingQueries,
    MaxPendingLivelinessGets,
    MaxPendingReplies,
    MaxPendingFinals,
    AdvancedCacheBytes,
    PicoUnicastBatchBytes,
    MaxSubscriptions,
    MaxQueryables,
    MaxLocalTokens,
    MaxLivelinessSubscriptions,
    MaxDeclaredKeyexprs,
    MaxPublishers,
    MaxQueriers,
    MaxMatchingListeners,
    MaxDeclWatches,
    MaxTransportEventsListeners,
    MaxAdvancedPublishers,
    MaxAdvancedSubscribers,
    MaxLinkEventsListeners,
    MaxPeerKeyexprAliases,
    SessionMaxPeerKeyexprAliases,
    MaxRemoteDecls,
    SessionMaxRemoteDecls,
    MaxInboundSubInterests,
    SessionMaxInboundSubInterests,
    MaxReplyPayloadBytes,
    MaxPendingDeclares,
    RxPoolBuffers,
    TxPoolSlots,
    ReassemblyChains,
    /// The config's limits are not those of the region the build laid out when it was compiled
    /// ([`ArenaRegion`]): the build lays out no arena for any other.
    LimitsDifferFromBuild,
    /// A number of the config besides the endpoints it dials ([`PlanShape`]) is not that of the
    /// region the build laid out when it was compiled ([`ArenaRegion`]): the build lays out no
    /// arena for any other.
    ShapeDiffersFromBuild,
}

impl ArenaLimit {
    /// The limit's id, as the build and a session's limits name it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::MaxFaces => "MAX_FACES",
            Self::MaxStaticConnect => "MAX_STATIC_CONNECT",
            Self::MaxAdminLocators => "MAX_ADMIN_LOCATORS",
            Self::MaxAcceptPending => "MAX_ACCEPT_PENDING",
            Self::PicoFragMaxBytes => "PICO_FRAG_MAX_BYTES",
            Self::DeliveryLaneEvents => "DELIVERY_LANE_EVENTS",
            Self::DeliveryLaneCallbacks => "DELIVERY_LANE_CALLBACKS",
            Self::MaxKeyexprBytes => "MAX_KEYEXPR_BYTES",
            Self::KeyArenaBytes => "KEY_ARENA_BYTES",
            Self::UdpPortSlots => "UDP_PORT_SLOTS",
            Self::HandedLegBytes => "HANDED_LEG_BYTES",
            Self::MaxDeclObservers => "MAX_DECL_OBSERVERS",
            Self::MaxPendingQueries => "MAX_PENDING_QUERIES",
            Self::MaxPendingLivelinessGets => "MAX_PENDING_LIVELINESS_GETS",
            Self::MaxPendingReplies => "MAX_PENDING_REPLIES",
            Self::MaxPendingFinals => "MAX_PENDING_FINALS",
            Self::AdvancedCacheBytes => "ADVANCED_CACHE_BYTES",
            Self::PicoUnicastBatchBytes => "PICO_UNICAST_BATCH_BYTES",
            Self::MaxSubscriptions => "MAX_SUBSCRIPTIONS",
            Self::MaxQueryables => "MAX_QUERYABLES",
            Self::MaxLocalTokens => "MAX_LOCAL_TOKENS",
            Self::MaxLivelinessSubscriptions => "MAX_LIVELINESS_SUBSCRIPTIONS",
            Self::MaxDeclaredKeyexprs => "MAX_DECLARED_KEYEXPRS",
            Self::MaxPublishers => "MAX_PUBLISHERS",
            Self::MaxQueriers => "MAX_QUERIERS",
            Self::MaxMatchingListeners => "MAX_MATCHING_LISTENERS",
            Self::MaxDeclWatches => "MAX_DECL_WATCHES",
            Self::MaxTransportEventsListeners => "MAX_TRANSPORT_EVENTS_LISTENERS",
            Self::MaxAdvancedPublishers => "MAX_ADVANCED_PUBLISHERS",
            Self::MaxAdvancedSubscribers => "MAX_ADVANCED_SUBSCRIBERS",
            Self::MaxLinkEventsListeners => "MAX_LINK_EVENTS_LISTENERS",
            Self::MaxPeerKeyexprAliases => "MAX_PEER_KEYEXPR_ALIASES",
            Self::SessionMaxPeerKeyexprAliases => "SESSION_MAX_PEER_KEYEXPR_ALIASES",
            Self::MaxRemoteDecls => "MAX_REMOTE_DECLS",
            Self::SessionMaxRemoteDecls => "SESSION_MAX_REMOTE_DECLS",
            Self::MaxInboundSubInterests => "MAX_INBOUND_SUB_INTERESTS",
            Self::SessionMaxInboundSubInterests => "SESSION_MAX_INBOUND_SUB_INTERESTS",
            Self::MaxReplyPayloadBytes => "MAX_REPLY_PAYLOAD_BYTES",
            Self::MaxPendingDeclares => "MAX_PENDING_DECLARES",
            Self::RxPoolBuffers => "RX_POOL_BUFFERS",
            Self::TxPoolSlots => "TX_POOL_SLOTS",
            Self::ReassemblyChains => "REASSEMBLY_CHAINS",
            Self::LimitsDifferFromBuild => "LIMITS_DIFFER_FROM_BUILD",
            Self::ShapeDiffersFromBuild => "SHAPE_DIFFERS_FROM_BUILD",
        }
    }
}

/// Why a session's open reserved no arena, and so bound, joined and dialled nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArenaRefused {
    /// A limit the arena is sized by gives no length under the build's value: it is over it, or
    /// the build states none.
    Limit {
        /// The limit's id.
        limit: ArenaLimit,
        /// Why.
        why: UnlentRows,
    },
    /// The arena is past the address space.
    TooLarge,
    /// The memory had none to give.
    NoMemory {
        /// The bytes asked for.
        bytes: usize,
    },
    /// A table of the plan was not lent from the arena reserved by it: the plan and the tables
    /// the open lends disagree, which no build should reach.
    Lend(LendRefused),
}

/// How many rows each table the engine keeps of the session's own declarations is lent: the
/// values of their limits the open resolved, under the build's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EntityRows {
    /// The rows of each kind an ABI's place may be for, at the kind's place in
    /// [`EntityKind::ALL`], each the value of the kind's limit (named on [`EntityKind`]): none for
    /// a kind the build has not. The advanced publishers and subscribers are the ABI's places only,
    /// which the engine keeps no row of. A kind is read at its place, so what reads a count by kind
    /// asks no question of the kind first.
    kinds: [usize; ENTITY_KINDS],
    /// The key expressions declared (`MAX_DECLARED_KEYEXPRS`).
    pub keyexprs: usize,
}

/// The tables of pending gets a session's arena lends: how many rows each registry of one is lent,
/// and how many there are, one for each face the session may hold at once and, with
/// `local-queryable`, one for the gets its own queryables answer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetTables {
    /// The rows of each registry of one table.
    pub rows: RequesterRows,
    /// How many tables.
    pub tables: usize,
}

impl GetTables {
    /// How many gets every table together holds pending at once: the rows of the tables of the
    /// ends of the legs, of their callbacks and of the session's note of each leg pending
    /// (`crate::engine`'s `EndedLegs`, `LegRows` and `PendingGet`). `None` past the address
    /// space.
    pub const fn legs(&self) -> Option<usize> {
        match self.rows.queries.checked_add(self.rows.liveliness_gets) {
            Some(each) => each.checked_mul(self.tables),
            None => None,
        }
    }
}

/// One face's table of pending gets, as the arena lends it. A build that asks no query keeps none
/// (`engine::registry::Gets`) and lays out none.
#[cfg(all(feature = "query", wz_lent))]
type FaceGets = Requesters<ConsolidatingSink<LegSink, LegHold>, LegSink, Lent>;

/// The tables of what a face's peer writes and is owed that a session's arena lends: how many rows
/// each table of one is lent, and how many there are, one for each face the session may hold at
/// once; and how many rows each pool the faces' tables share holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FacePeers {
    /// The rows of each table of one face's.
    pub rows: PeerRows,
    /// How many faces' tables.
    pub tables: usize,
    /// Whether the first of the tables is the dial role's face's: `false` for a session that
    /// dials nothing (`dials`), whose dial face never has a peer, so every table is for the
    /// faces to come.
    pub dial: bool,
    /// The rows of each pool of what the faces' peers write, which the faces share.
    pub pools: PeerPoolRows,
}

impl FacePeers {
    /// The sets of face tables the session's arena lends: one for each face counted, and one of
    /// no rows for the dial face of a session that dials nothing, which holds the first place of
    /// the faces as every session's dial face does (`engine::registry::Registry::new`).
    pub const fn sets(&self) -> usize {
        Self::sets_of(self.tables, self.dial)
    }

    /// [`Self::sets`] of `tables` faces' tables, the first the dial role's face's when `dial`.
    const fn sets_of(tables: usize, dial: bool) -> usize {
        let sets = if dial {
            tables
        } else {
            tables.saturating_add(1)
        };
        if sets == 0 {
            1
        } else {
            sets
        }
    }

    /// The rows of the table of what the faces that went still owe the liveliness subscribers
    /// (the registry's tokens owed): one for each row of the session's token pool, as a face owes
    /// apart only while its tokens hold a row of the pool at least, so the faces owing at once
    /// are never more. None for a session of one face, whose one face never goes.
    pub const fn owed_tokens(&self) -> usize {
        if self.pools.shared {
            self.pools.remote_decls
        } else {
            0
        }
    }
}

impl EntityRows {
    /// No row of any kind: a vacant plan's, or one whose limits were refused.
    const NONE: Self = Self {
        kinds: [0; ENTITY_KINDS],
        keyexprs: 0,
    };

    /// The rows the engine keeps of `kind`, each of which an ABI's place of the kind is for.
    pub const fn of_kind(&self, kind: EntityKind) -> usize {
        // Every kind has its place among `kinds`, so the read always finds one.
        match self.kinds.split_at_checked(kind as usize) {
            Some((_, [rows, ..])) => *rows,
            _ => 0,
        }
    }

    /// The write filters the matching listeners declared on a key judge through, one each: none
    /// in a build that keeps no such listener (`key-matching-listener`).
    pub const fn key_listeners(&self) -> usize {
        if cfg!(feature = "key-matching-listener") {
            self.of_kind(EntityKind::MatchingListener)
        } else {
            0
        }
    }

    /// The rows of the write filters' one table: a publisher's and a querier's each, and a key
    /// listener's.
    pub const fn filters(&self) -> Option<usize> {
        match self
            .of_kind(EntityKind::Publisher)
            .checked_add(self.of_kind(EntityKind::Querier))
        {
            Some(entities) => entities.checked_add(self.key_listeners()),
            None => None,
        }
    }
}

/// One of each table of a cell for each link: the link's driver's, its gates', its session's
/// actions' and the two halves those actions hold. A plan holds each table's cell bytes
/// ([`ArenaPlan::holding_cells`]); an open, the tables the session's arena lends it
/// (`TransportRows::lent_from`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkCells<T> {
    /// The cells of the stack's drivers of the links.
    pub driver: T,
    /// The cells of the gates each link's pump runs behind.
    pub gate: T,
    /// The cells of the bundle of each link's session actions.
    pub actions: T,
    /// The cells of the two halves each link's actions hold, together: the link's own state and
    /// the session's kernel.
    pub halves: T,
}

impl<T> LinkCells<T> {
    /// The four in the order their tables are laid out and lent: the driver's, the gate's, the
    /// actions', the halves'.
    pub fn into_array(self) -> [T; 4] {
        [self.driver, self.gate, self.actions, self.halves]
    }

    /// The four from [`Self::into_array`]'s order.
    pub fn from_array([driver, gate, actions, halves]: [T; 4]) -> Self {
        Self {
            driver,
            gate,
            actions,
            halves,
        }
    }
}

/// The parts of the two rows of each table of [`LinkCells`], in [`LinkCells::into_array`]'s
/// order: its flags, then its cells.
const CELL_PARTS: [[ArenaPart; 2]; 4] = [
    [ArenaPart::LinkCellFlags, ArenaPart::LinkCells],
    [ArenaPart::LinkGateFlags, ArenaPart::LinkGates],
    [ArenaPart::LinkActionsFlags, ArenaPart::LinkActions],
    [ArenaPart::LinkHalvesFlags, ArenaPart::LinkHalves],
];

/// The limits a table of a row for each link is sized by.
const LINK_BASIS: &str = "MAX_FACES + MAX_ACCEPT_PENDING";

/// The rows of a session's transport ([`ArenaPlan::transport`]): its links' buffers and the
/// cells of their drivers, gates and actions, the reassembly buffers its links share, and the
/// texts of its endpoints. The transport lends its tables from them (`TransportRows::lent_from`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransportRows {
    /// The links whose buffers the arena holds.
    links: usize,
    /// The receive buffers of the pool those links share (`RX_POOL_BUFFERS`, at most one for each
    /// link).
    rx_buffers: usize,
    /// The outbound slots of the pool those links share (`TX_POOL_SLOTS`, at most one for each
    /// link).
    tx_slots: usize,
    /// The length of a link's receive buffer and of each of its slots.
    link_bytes: usize,
    /// The length of each buffer a link stages a fragmented message's chain in.
    reassembly_bytes: usize,
    /// How many such buffers, in the one table the session's links share (`REASSEMBLY_CHAINS`).
    reassembly_chains: usize,
    /// The most chains one face's Router holds open at once (`face_chains`).
    face_chains: usize,
    /// The rows of the texts of the endpoints the session dials, and of those it listens on.
    endpoint_rows: (usize, usize),
    /// The bytes of the cell each link's driver, its gates and its actions are placed in, none
    /// for a table the plan does not hold ([`ArenaPlan::holding_cells`]).
    cell_bytes: LinkCells<usize>,
    /// The tables of `cell_bytes` the plan holds, by their place in `LinkCells::into_array`:
    /// what the lend walks.
    cells_held: HeldBits,
    /// How many publishes the session keeps for its other faces at once, each in a place of a
    /// link's batch (`HANDED_LEG_BYTES`).
    #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
    handed_legs: usize,
    /// The receive buffers of the groups the session may join: how many, and the bytes of each.
    #[cfg(feature = "group")]
    group_rx: (usize, usize),
    /// The slots of the datagrams the session's udp ports hold: how many, and the bytes of each.
    #[cfg(feature = "udp-listen")]
    port_rx: (usize, usize),
    /// The rows of the peers the session's udp ports take, one for each link it may hold.
    #[cfg(feature = "udp-listen")]
    port_peers: usize,
}

/// The flag of a cell of the links' tables: the session's lock kind's
/// (`wz_runtime_coop::sync::LockKind::Flag`), which the handles placed in it are counted by.
type LinkCellFlag = <SessionLock as wz_runtime_coop::sync::LockKind>::Flag;

/// The tables a session's transport is lent ([`TransportRows::lent_from`]).
pub(crate) struct TransportTables {
    /// The links' buffers and, where the links share pools, their places.
    pub(crate) links: LinkTables<LinkCellFlag>,
    /// The cells of the links' drivers, their gates and their actions, each `None` for a plan
    /// with no such table: each cell's flag the one the session's lock kind counts a link's
    /// handles by, so a handle let go of on any thread that may hold it gives its cell back.
    pub(crate) cells: LinkCells<Option<LentByteCells<LinkCellFlag>>>,
    /// The reassembly buffers the links share.
    pub(crate) reassembly: LentByteCells,
    /// The most chains one face's Router holds open at once in `reassembly`.
    pub(crate) face_chains: usize,
    /// The rows of the endpoints' texts, none written.
    pub(crate) endpoints: EndpointTexts,
    /// The places of the publishes the session keeps for its other faces.
    #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
    pub(crate) handed: HandedTable,
    /// The rows the session's udp ports keep their peers and the datagrams sorted for them in.
    #[cfg(feature = "udp-listen")]
    pub(crate) port_rows: PortRows<Lent, LinkCellFlag>,
}

impl TransportRows {
    /// The rows of no transport: a vacant plan's.
    const NONE: Self = Self {
        links: 0,
        rx_buffers: 0,
        tx_slots: 0,
        link_bytes: 0,
        reassembly_bytes: 0,
        reassembly_chains: 0,
        face_chains: 0,
        endpoint_rows: (0, 0),
        cell_bytes: NO_CELLS,
        cells_held: HeldBits(0),
        #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
        handed_legs: 0,
        #[cfg(feature = "group")]
        group_rx: (0, 0),
        #[cfg(feature = "udp-listen")]
        port_rx: (0, 0),
        #[cfg(feature = "udp-listen")]
        port_peers: 0,
    };

    /// The transport's tables, lent by `lend` in the order the plan laid them out: each made in
    /// its field of the value handed back, whose fields are made in the order they are written.
    pub(crate) fn lent_from(&self, lend: &mut TableLender<'_>) -> TransportTables {
        let (dials, listens) = self.endpoint_rows;
        TransportTables {
            links: self.links_from(lend),
            cells: self.cells_from(lend),
            // A chain's buffer is claimed when its first fragment arrives and given back when it
            // ends; the session holds the table for its life.
            reassembly: lend.byte_cells(self.reassembly_bytes, self.reassembly_chains),
            face_chains: self.face_chains,
            endpoints: EndpointTexts::over(lend.table(dials), lend.table(listens)),
            #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
            handed: HandedTable::over(
                lend.byte_cells(self.link_bytes, self.handed_legs),
                lend.table(self.handed_legs),
            ),
            #[cfg(feature = "udp-listen")]
            port_rows: PortRows::over(lend.table(self.port_peers), lend.table(self.port_rx.0)),
        }
    }

    /// The cells of the links' drivers, their gates, their actions and their halves, lent by
    /// `lend` after the links' buffers: `None` for a table the plan holds no cells for.
    fn cells_from(
        &self,
        lend: &mut TableLender<'_>,
    ) -> LinkCells<Option<LentByteCells<LinkCellFlag>>> {
        let sizes = self.cell_bytes.into_array();
        let mut cells = [None, None, None, None];
        for at in self.cells_held.places() {
            if let (Some(lent), Some(&bytes)) = (cells.get_mut(at), sizes.get(at)) {
                *lent = Some(lend.byte_cells_of::<LinkCellFlag>(bytes, self.links));
            }
        }
        LinkCells::from_array(cells)
    }

    /// The tables of the links' buffers, lent by `lend`: the pool of receive buffers the links
    /// share, each held by a link only while it holds something of its own in it, the pool of
    /// outbound slots they share, each held by a link from its grant to its send
    /// ([`LINK_TX_SLOTS`] at a time), and a place for each link the session may hold, which the
    /// session's links claim as they open and give back as they go.
    pub(crate) fn links_from(&self, lend: &mut TableLender<'_>) -> LinkTables<LinkCellFlag> {
        let rx = lend.byte_cells_of::<LinkCellFlag>(self.link_bytes, self.rx_buffers);
        let tx = lend.byte_cells_of::<LinkCellFlag>(self.link_bytes, self.tx_slots);
        #[cfg(feature = "listen")]
        let tables = LinkTables::pooled(rx, tx, lend.byte_cells_of(0, self.links));
        #[cfg(not(feature = "listen"))]
        let tables = LinkTables::new(rx, tx, self.link_bytes);
        let tables = self.group_rx_from(tables, lend);
        self.port_rx_from(tables, lend)
    }

    /// `tables` with the slots the session's udp ports read their datagrams into and hold them in
    /// until the links of their peers take them, lent by `lend` after the groups' buffers: the
    /// ports share them, a slot of the links' batch each.
    #[cfg(feature = "udp-listen")]
    fn port_rx_from(
        &self,
        tables: LinkTables<LinkCellFlag>,
        lend: &mut TableLender<'_>,
    ) -> LinkTables<LinkCellFlag> {
        let (slots, bytes) = self.port_rx;
        // A plan that listens on nothing laid no table of them out.
        if slots == 0 {
            return tables;
        }
        tables.with_port_rx(lend.byte_cells_of(bytes, slots))
    }

    /// A build that binds no udp port lends no port a slot.
    #[cfg(not(feature = "udp-listen"))]
    fn port_rx_from(
        &self,
        tables: LinkTables<LinkCellFlag>,
        _lend: &mut TableLender<'_>,
    ) -> LinkTables<LinkCellFlag> {
        tables
    }

    /// `tables` with the receive buffers of the groups the session may join, lent by `lend`
    /// after the links' own: a buffer of the groups' batch for each group the plan counts, which a
    /// group claims when it is joined, so a joined group's datagram is read where the session's
    /// memory holds it.
    #[cfg(feature = "group")]
    fn group_rx_from(
        &self,
        tables: LinkTables<LinkCellFlag>,
        lend: &mut TableLender<'_>,
    ) -> LinkTables<LinkCellFlag> {
        let (buffers, bytes) = self.group_rx;
        // A plan that counts no group laid no table of them out.
        if buffers == 0 {
            return tables;
        }
        tables.with_group_rx(lend.byte_cells(bytes, buffers))
    }

    /// A build that joins no group lends no group a buffer.
    #[cfg(not(feature = "group"))]
    fn group_rx_from(
        &self,
        tables: LinkTables<LinkCellFlag>,
        _lend: &mut TableLender<'_>,
    ) -> LinkTables<LinkCellFlag> {
        tables
    }
}

/// The rows of a session's state ([`ArenaPlan::session`]): its round of deliveries, the
/// engine's record of its own declarations, the application's tables, its pending gets and what
/// its faces' peers write and are owed, and the key arena every keyed row keeps its key in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionRows {
    /// The rows of the round's tables, none in a build that puts nothing in the round
    /// (`wz_round`).
    #[cfg(wz_round)]
    round: RoundRowCounts,
    /// The rows of the engine's record of the session's declarations.
    entities: EntityRows,
    /// The tables of pending gets, and the rows of each.
    gets: GetTables,
    /// The tables of what each face's peer writes and is owed, and the rows of each.
    peers: FacePeers,
    /// The queries held for the queryables' callbacks at once (`MAX_PENDING_FINALS`).
    held_queries: usize,
    /// The bytes of blocks of the key arena (`KEY_ARENA_BYTES`).
    key_bytes: usize,
    /// The bytes of the ring the session's advanced publishers' caches keep their samples in
    /// (`ADVANCED_CACHE_BYTES`), none for no ring.
    #[cfg(feature = "advanced-cache")]
    cache_bytes: usize,
    /// The replies the gets that consolidate hold to their Finals, a row each, shared by every get
    /// of the session (`MAX_PENDING_REPLIES`).
    #[cfg(feature = "query")]
    held_replies: usize,
}

impl SessionRows {
    /// The rows of no session: a vacant plan's.
    const NONE: Self = Self {
        #[cfg(wz_round)]
        round: RoundRowCounts {
            records: 0,
            callbacks: 0,
            longest_key: 0,
        },
        entities: EntityRows::NONE,
        gets: GetTables {
            rows: RequesterRows {
                queries: 0,
                liveliness_gets: 0,
            },
            tables: 0,
        },
        peers: FacePeers {
            rows: NO_PEER_ROWS,
            tables: 0,
            dial: false,
            pools: NO_POOL_ROWS,
        },
        held_queries: 0,
        key_bytes: 0,
        #[cfg(feature = "advanced-cache")]
        cache_bytes: 0,
        #[cfg(feature = "query")]
        held_replies: 0,
    };

    /// How many rows each table of the engine's record of the session's declarations is lent.
    pub fn entities(&self) -> EntityRows {
        self.entities
    }

    /// The tables of pending gets the arena lends, and the rows of each.
    pub fn gets(&self) -> GetTables {
        self.gets
    }

    /// The bytes of blocks of the key arena every keyed row of the session keeps its key in
    /// (`KEY_ARENA_BYTES`).
    pub fn key_bytes(&self) -> usize {
        self.key_bytes
    }

    /// How many queries the session holds for its queryables' callbacks at once
    /// (`MAX_PENDING_FINALS`): the rows of the Finals held and of the requests refused.
    pub fn held_queries(&self) -> usize {
        self.held_queries
    }

    /// The bytes of the ring the session's advanced publishers' caches keep their samples in
    /// (`ADVANCED_CACHE_BYTES`): one table of one buffer, claimed for the session's life
    /// (`CacheSpan::claimed`).
    #[cfg(feature = "advanced-cache")]
    pub fn cache_bytes(&self) -> usize {
        self.cache_bytes
    }

    /// How many replies the gets that consolidate hold to their Finals at once, of every get of the
    /// session (`MAX_PENDING_REPLIES`).
    #[cfg(feature = "query")]
    pub fn held_replies(&self) -> usize {
        self.held_replies
    }
}

/// The rows of the places the ABI keeps its handle of the session and its objects in
/// ([`ArenaPlan::places`], [`ArenaPlan::holding`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlaceRows {
    /// The bytes of the place the ABI keeps its handle of the session in, none for no place.
    handle_bytes: usize,
    /// The bytes of each place the ABI keeps an entity of a kind in, by [`EntityKind`], none for
    /// no place.
    entity_bytes: [usize; ENTITY_KINDS],
    /// The kinds of `entity_bytes` the plan holds places of, by their place in
    /// [`EntityKind::ALL`]: what the lend walks.
    held: HeldBits,
    /// The table of places for values lodged by counts ([`HeldPlaces::with_lodgings`]).
    lodging: LodgingRows,
}

/// The places a session's arena lent the ABI ([`PlaceRows::lent_from`]).
pub(crate) struct PlaceTables {
    /// The place of the ABI's handle, a table of one buffer, `None` for a plan with no place.
    pub(crate) handle: Option<LentByteCells>,
    /// The places of the ABI's entities, a table of each kind the plan holds places of.
    pub(crate) entities: EntityPlaces,
    /// The span of the places for values lodged by counts, made a table once the count that keeps
    /// the arena's memory is known (`LodgingSpan::kept_by`).
    pub(crate) lodgings: LodgingSpan,
}

impl PlaceRows {
    /// The places of none: a vacant plan's.
    const NONE: Self = Self {
        handle_bytes: 0,
        entity_bytes: [0; ENTITY_KINDS],
        held: HeldBits(0),
        lodging: LodgingRows::NONE,
    };

    /// The places, lent by `lend` in the order the plan laid them out: the handle's first, then
    /// each kind's in the order of [`EntityKind::ALL`], a place for each row `rows` counts of
    /// the kind, the session's own count, which the plan reads rather than keeps a second copy of.
    pub(crate) fn lent_from(&self, lend: &mut TableLender<'_>, rows: EntityRows) -> PlaceTables {
        let handle = (self.handle_bytes != 0).then(|| lend.byte_cells(self.handle_bytes, 1));
        let mut entities = EntityPlaces::NONE;
        for at in self.held.places() {
            if let (Some(cells), Some(&bytes)) =
                (entities.cells.get_mut(at), self.entity_bytes.get(at))
            {
                let count = rows.kinds.get(at).copied().unwrap_or(0);
                *cells = Some(lend.byte_cells(bytes, count));
            }
        }
        let lodgings = self.lodging.lent_from(lend);
        PlaceTables {
            handle,
            entities,
            lodgings,
        }
    }
}

/// The places of a row of tables a plan holds, a bit at each table's place in the row: the walk
/// that lends them ends on the mask. A walk over the row's places, or one that scans the row for
/// the next table held, steps one place at a time on every path, so the compiler sees a loop of
/// the row's constant length and unrolls it into a copy of the lend for each place.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct HeldBits(u32);

// Every kind of entity has a bit of the mask its places are walked by.
const _: () = assert!(
    ENTITY_KINDS <= u32::BITS as usize,
    "a kind of entity past the bits of the places' mask would never be lent its places"
);

impl HeldBits {
    /// These places and `at`; a place past the mask's bits adds none.
    const fn with(self, at: usize) -> Self {
        // A place past the bits shifts by the width itself, which `checked_shl` refuses.
        let shift = if at < u32::BITS as usize {
            at as u32
        } else {
            u32::BITS
        };
        let bit = match 1u32.checked_shl(shift) {
            Some(bit) => bit,
            None => 0,
        };
        Self(self.0 | bit)
    }

    /// The places held, the lowest first.
    fn places(self) -> HeldPlacesWalk {
        HeldPlacesWalk(self.0)
    }
}

/// The walk of [`HeldBits::places`]: the bits not yet walked.
struct HeldPlacesWalk(u32);

impl Iterator for HeldPlacesWalk {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        if self.0 == 0 {
            return None;
        }
        let at = self.0.trailing_zeros();
        // The lowest bit set is cleared: the walk ends once each place held was handed out.
        self.0 &= self.0.wrapping_sub(1);
        usize::try_from(at).ok()
    }
}

/// What a session's arena holds, row by row, and the rows each layer lends its tables from
/// ([`Self::transport`], [`Self::session`], [`Self::places`]). The arena is the sum of the rows'
/// spans whatever order they are lent in, so each layer lends its own in an order of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArenaPlan<const ROWS: usize = ARENA_ROWS> {
    /// The rows laid out, in order, the first `len` of them: a row is written when it is laid
    /// out, and the rows past `len` are [`UNLAID_ROW`] in every plan, so two plans of the same rows
    /// are equal. Kept where a plan is read row by row, a build that lays its plans out at the
    /// open and the tests: an open by a region reads `reserved` and the rows of each layer alone,
    /// so a region carries no table of rows.
    #[cfg(any(feature = "runtime-plan", test))]
    rows: [ArenaRow; ROWS],
    /// How many rows were laid out.
    len: usize,
    /// The bytes the rows laid out take together, each row's span added as it is laid out;
    /// `None` past the address space.
    reserved: Option<usize>,
    /// The first refusal met while the plan was laid out, kept as it came (the limit it names, or
    /// the address space), and the one its maker is told once the plan is settled
    /// ([`Self::settled`]): every row and every limit is put and read in one pass with no exit of
    /// its own, and nothing after the first refusal replaces it.
    refused: Option<ArenaRefused>,
    /// The rows the session's transport lends its tables from.
    transport: TransportRows,
    /// The rows the session's state lends its tables from.
    session: SessionRows,
    /// The rows of the ABI's places.
    places: PlaceRows,
    /// The bytes of the span the session's runtime is placed in, `0` for none
    /// ([`Self::holding_runtime`]).
    runtime_bytes: usize,
}

impl ArenaPlan {
    /// A plan of no rows that lists every row it lays out (`rows`, where a build keeps a list): the
    /// plan a report and a test read row by row, and the place an open of a build without
    /// `runtime-plan` lays its plan out in ([`Self::count`]). Out of line, so the plan is made
    /// where its caller keeps it.
    #[inline(never)]
    pub const fn vacant() -> Self {
        Self {
            #[cfg(any(feature = "runtime-plan", test))]
            rows: [UNLAID_ROW; ARENA_ROWS],
            len: 0,
            reserved: Some(0),
            refused: None,
            transport: TransportRows::NONE,
            session: SessionRows::NONE,
            places: PlaceRows::NONE,
            runtime_bytes: 0,
        }
    }

    /// The rows of a session `config` opens under `limits` (see the module), as a value: a
    /// [`Self::vacant`] plan [`Self::count`] lays out. Refused as `count` refuses it.
    pub fn of<E: EndpointList>(
        config: &CoopConfig<E>,
        limits: &SessionLimits,
    ) -> Result<Self, ArenaRefused> {
        let mut plan = Self::vacant();
        plan.count(config, limits)?;
        Ok(plan)
    }

    /// The plan of a session of `shape` under `limits`, laid out as [`Self::lay_out`] lays it out:
    /// a constant where both are, so a build that states them has its plan when it is compiled
    /// and runs none of the walk.
    pub const fn planned(shape: PlanShape, limits: &SessionLimits) -> Result<Self, ArenaRefused> {
        let mut plan = Self::vacant();
        match plan.lay_out(shape, limits) {
            Ok(()) => Ok(plan),
            Err(refused) => Err(refused),
        }
    }
}

/// The plan an open lays out and reserves by where the build lays its plans out at the open
/// (`lend_session`): every sum and every layer's rows of a listed plan, and no list of the rows,
/// which only a report reads, so the open's frame holds no table of them and its walk writes none.
/// A build without `runtime-plan` lists no rows in any plan and opens by [`ArenaPlan::vacant`], so
/// it has no second kind of plan to make.
#[cfg(feature = "runtime-plan")]
pub(crate) type OpenPlan = ArenaPlan<0>;

impl<const ROWS: usize> ArenaPlan<ROWS> {
    /// A plan of no rows, the place an open lays its plan out in ([`Self::count`]), listing the
    /// first `ROWS` rows it lays out: out of line, so the plan is made where its caller keeps it.
    #[cfg(feature = "runtime-plan")]
    #[inline(never)]
    pub(crate) const fn blank() -> Self {
        Self {
            rows: [UNLAID_ROW; ROWS],
            len: 0,
            reserved: Some(0),
            refused: None,
            transport: TransportRows::NONE,
            session: SessionRows::NONE,
            places: PlaceRows::NONE,
            runtime_bytes: 0,
        }
    }

    /// Lay out on this plan, [`ArenaPlan::vacant`] or an open's blank plan as made, the rows of a
    /// session `config` opens under `limits` (see the module), where the plan lies: an open that
    /// keeps its plan in its own frame moves no plan out of a returned value. Refused when a limit
    /// is over the build's value or the arena is past the address space; a refused plan is no plan
    /// to open by. The numbers of the config are read once ([`PlanShape::of`]) and laid out as
    /// [`Self::lay_out`] lays out a build's constants.
    #[inline(never)]
    pub fn count<E: EndpointList>(
        &mut self,
        config: &CoopConfig<E>,
        limits: &SessionLimits,
    ) -> Result<(), ArenaRefused> {
        self.lay_out(PlanShape::of(config), limits)
    }

    /// Take on the rows `laid` laid out and every sum of them, as this plan would have laid them
    /// out itself, listing as many of its listed rows as this plan lists: what an open by a region
    /// lays out, the region's plan made when the build was compiled.
    #[cfg(feature = "runtime-plan")]
    pub(crate) fn take_on<const LAID: usize>(&mut self, laid: &ArenaPlan<LAID>) {
        let ArenaPlan {
            rows,
            len,
            reserved,
            refused,
            transport,
            session,
            places,
            runtime_bytes,
        } = laid;
        let rows = {
            let mut listed = [UNLAID_ROW; ROWS];
            let shared = ROWS.min(LAID);
            listed[..shared].copy_from_slice(&rows[..shared]);
            listed
        };
        let taken = Self {
            rows,
            len: *len,
            reserved: *reserved,
            refused: *refused,
            transport: *transport,
            session: *session,
            places: *places,
            runtime_bytes: *runtime_bytes,
        };
        // Made apart and stored whole, as `clone_from` stores a plan, so that no byte of the plan
        // it replaces outlives this store.
        *self = taken;
    }

    /// Lay out on this plan, [`Self::vacant`] as made, the rows of a session of `shape` under
    /// `limits` (see the module). The one walk of the rows: evaluated when a build is compiled
    /// where the shape and the limits are its constants ([`Self::planned`]), and at the open
    /// otherwise ([`Self::count`]). Refused when a limit is over the build's value or the arena is
    /// past the address space; a refused plan is no plan to open by.
    #[inline(never)]
    pub const fn lay_out(
        &mut self,
        shape: PlanShape,
        limits: &SessionLimits,
    ) -> Result<(), ArenaRefused> {
        tried!(hold(
            ArenaLimit::MaxFaces,
            shape.max_faces,
            tried!(admitted_faces(limits)),
        ));
        tried!(hold_under::<{ caps::MAX_STATIC_CONNECT }>(
            ArenaLimit::MaxStaticConnect,
            shape.dials,
        ));
        tried!(hold(
            ArenaLimit::MaxAdminLocators,
            shape.listens,
            caps::MAX_ADMIN_LOCATORS,
        ));
        if shape.listens > 0 {
            tried!(hold(
                ArenaLimit::MaxAcceptPending,
                shape.accept_pending,
                tried!(admitted_handshakes(limits)),
            ));
        }
        let Some(links) = shape.links() else {
            return Err(ArenaRefused::TooLarge);
        };
        // A buffer and a slot of the batch hold a whole batch of either link: a stream link's
        // length is counted inside the batch it negotiates (`STREAM_BATCH_LENGTH_BYTES`).
        let link_bytes = tried!(link_batch(shape.batch, limits));
        self.transport = TransportRows {
            links,
            rx_buffers: links,
            tx_slots: links,
            link_bytes,
            reassembly_bytes: 0,
            reassembly_chains: 0,
            face_chains: 0,
            endpoint_rows: (shape.dials, shape.listens),
            cell_bytes: NO_CELLS,
            cells_held: HeldBits(0),
            #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
            handed_legs: 0,
            #[cfg(feature = "group")]
            group_rx: (0, 0),
            #[cfg(feature = "udp-listen")]
            port_rx: (0, 0),
            #[cfg(feature = "udp-listen")]
            port_peers: 0,
        };
        // The largest message a link rejoins is decided before the lane that hands it on, so a
        // value over the build's is refused under its own name.
        self.transport.reassembly_bytes = self.lent_to::<{ caps::PICO_FRAG_MAX_BYTES }>(
            ArenaLimit::PicoFragMaxBytes,
            limits.pico_frag_max_bytes(),
        );
        // A face's share of the session's one table of chains, which bounds the chains its Router
        // holds open; the table is laid out once the faces are counted.
        let share = match reassembly_chains(limits) {
            Ok(share) => share,
            Err(refused) => {
                self.refuse(refused);
                0
            }
        };
        self.transport.face_chains = face_chains(share);
        // The links' receive buffers and outbound slots, as a report reads them (`link_buffers`).
        match pooled_buffers(links, limits) {
            Ok((rx_buffers, tx_slots)) => {
                self.transport.rx_buffers = rx_buffers;
                self.transport.tx_slots = tx_slots;
            }
            Err(refused) => self.refuse(refused),
        }
        #[cfg(wz_round)]
        {
            self.session.round = RoundRowCounts {
                records: self.lent_to::<{ caps::DELIVERY_LANE_EVENTS }>(
                    ArenaLimit::DeliveryLaneEvents,
                    limits.delivery_lane_events(),
                ),
                callbacks: self.lent_to::<{ caps::DELIVERY_LANE_CALLBACKS }>(
                    ArenaLimit::DeliveryLaneCallbacks,
                    limits.delivery_lane_callbacks(),
                ),
                longest_key: self.lent_to::<{ caps::MAX_KEYEXPR_BYTES }>(
                    ArenaLimit::MaxKeyexprBytes,
                    limits.max_keyexpr_bytes(),
                ),
            };
        }
        self.session.key_bytes = self.lent_to::<{ caps::KEY_ARENA_BYTES }>(
            ArenaLimit::KeyArenaBytes,
            Quota::at_most(limits.key_arena_bytes()),
        );
        let faces = self.sized(shape.faces());
        // The table of chains, as a report reads it (`link_buffers`).
        match chain_table(share, FacePeers::sets_of(faces, shape.dial_role())) {
            Some(chains) => self.transport.reassembly_chains = chains,
            None => self.refuse(ArenaRefused::TooLarge),
        }
        // The texts of the endpoints the session dials and listens on, a text a row of one table
        // each, written once when it opens and named by place after
        // (`TransportRows::lent_from`): one row of the plan, the two tables' spans.
        let (dial_rows, listen_rows) = self.transport.endpoint_rows;
        let texts = self.sized(
            match (
                Arena::table_bytes::<LocatorText>(dial_rows),
                Arena::table_bytes::<LocatorText>(listen_rows),
            ) {
                (Some(dial), Some(listen)) => dial.checked_add(listen),
                _ => None,
            },
        );
        self.put(ArenaPart::EndpointTexts, 1, texts);
        // The links' rows are lent when the session opens, in this order
        // (`TransportRows::links_from`).
        self.put_table(
            [ArenaPart::LinkReceiveFlags, ArenaPart::LinkReceiveBuffers],
            self.transport.rx_buffers,
            link_bytes,
        );
        self.put_table(
            [ArenaPart::LinkTransmitFlags, ArenaPart::LinkTransmitSlots],
            self.transport.tx_slots,
            link_bytes,
        );
        // A place for each link, which bounds the links that open where the slots are a pool:
        // the flags of a table of buffers of no bytes.
        #[cfg(feature = "listen")]
        self.put(ArenaPart::LinkPlaces, links, LentByteCells::FLAG_BYTES);
        // A receive buffer for each group the session may join, lent with the links' tables
        // (`TransportRows::links_from`): as many as the plan counts groups, each of the largest
        // batch a group the config names sends, held to the build's multicast batch. A group's
        // datagram longer than it is dropped and counted by its transport. A config that names no
        // group has no table of them in its plan.
        #[cfg(feature = "group")]
        if shape.groups > 0 {
            let buffers = least(shape.groups, caps::MAX_TASKS);
            let bytes = least(shape.group_batch, limits.pico_multicast_batch_bytes());
            self.transport.group_rx = (buffers, bytes);
            self.put_table(
                [
                    ArenaPart::LinkGroupReceiveFlags,
                    ArenaPart::LinkGroupReceiveBuffers,
                ],
                buffers,
                bytes,
            );
        }
        // The slots the udp ports of a session that listens read their datagrams into and hold
        // them in until the links of their peers take them, lent with the links' tables
        // (`TransportRows::links_from`): the ports share them, each a link's batch long. A
        // session that listens on no `udp/` endpoint binds no port and holds none, nor does a
        // build without the udp listener (`udp-listen`), whose links refuse such an endpoint.
        #[cfg(feature = "udp-listen")]
        {
            let slots = self.lent_to::<{ caps::UDP_PORT_SLOTS }>(
                ArenaLimit::UdpPortSlots,
                Quota::at_most(limits.udp_port_slots()),
            );
            // A plan of a session with no udp port lays none of the ports' rows out, as one that
            // names no group lays out no group's: their tables are lent no rows and take no byte
            // of the arena (`TransportRows::links_from`, `TransportRows::lent_from`).
            if shape.udp_listens > 0 {
                self.transport.port_rx = (slots, link_bytes);
                self.put_table(
                    [
                        ArenaPart::LinkPortDatagramFlags,
                        ArenaPart::LinkPortDatagramSlots,
                    ],
                    slots,
                    link_bytes,
                );
                // The ports' book of their peers, a row for each link the session may hold, and
                // of the datagrams sorted for them, a row for each slot a datagram holds while it
                // waits (`TransportRows::lent_from`).
                self.transport.port_peers = links;
                let peer_rows = self.sized(Arena::table_bytes::<PortPeerRow>(links));
                self.put(ArenaPart::UdpPortPeers, 1, peer_rows);
                let queue_rows = self.sized(Arena::table_bytes::<QueuedDatagram>(slots));
                self.put(ArenaPart::UdpPortQueue, 1, queue_rows);
            }
        }
        // The round's tables (`crate::round::RoundRows::lent`): its records only where the arena
        // lends them, as a round of one thread keeps them in itself and is lent no byte of them.
        // A build that puts nothing in the round (`wz_round`) lays out none of them, and where the
        // build fixes the session's shape the tables and the round lie in the session's region
        // instead (`StatePlaces::round`).
        #[cfg(all(wz_round, wz_lent))]
        {
            if RECORD_BYTES != 0 {
                self.put(
                    ArenaPart::DeliveryRecords,
                    self.session.round.records,
                    RECORD_BYTES,
                );
            }
            self.put(
                ArenaPart::DeliveryCallbacks,
                self.session.round.callbacks,
                CALLBACK_BYTES,
            );
            self.put(
                ArenaPart::DeliveryKeys,
                1,
                self.session.round.key_bytes::<CoopForm>(),
            );
            // The round itself, placed beside its tables (`Round::placed_over`): its one owner
            // and the handles of it that count nothing.
            self.put(
                ArenaPart::DeliveryRound,
                1,
                core::mem::size_of::<crate::round::Round>(),
            );
        }
        // The places the session lends its registry and its Router in for a step, a place each
        // (`crate::engine::StepPlaces`); a read that steps its one link itself dispatches under the
        // session's lock and lends no registry.
        #[cfg(all(wz_lent, wz_round))]
        self.put(ArenaPart::RegistryLend, 1, REGISTRY_LEND_BYTES);
        #[cfg(wz_lent)]
        self.put(ArenaPart::RouterLend, 1, ROUTER_LEND_BYTES);
        // The session's reassembly buffers, which its links share (`TransportRows::lent_from`).
        self.put_table(
            [ArenaPart::ReassemblyFlags, ArenaPart::ReassemblyBuffers],
            self.transport.reassembly_chains,
            self.transport.reassembly_bytes,
        );
        // The publishes the session keeps for its other faces while a send holds it, each in a
        // place of a link's batch: a publish longer than one is dropped on every face, as one
        // that finds every place held is. Under `every-face` a publish that finds the session
        // held is dropped on every face, and the session reserves no place for one.
        #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
        {
            let bytes = self.lent_to::<{ caps::HANDED_LEG_BYTES }>(
                ArenaLimit::HandedLegBytes,
                Quota::at_most(limits.handed_leg_bytes()),
            );
            let legs = match (shape.keeps_handed, bytes.checked_div(link_bytes)) {
                (true, Some(legs)) => legs,
                _ => 0,
            };
            self.transport.handed_legs = legs;
            self.put_table(
                [ArenaPart::HandedLegFlags, ArenaPart::HandedLegPlaces],
                legs,
                link_bytes,
            );
            let rows = self.sized(Arena::table_bytes::<Handed>(legs));
            self.put(ArenaPart::HandedLegs, 1, rows);
        }
        // The rows of the session's own declarations, read once: the registries' rows below and
        // the declaration tables after them count the same limits.
        self.session.entities = match entity_rows(limits) {
            Ok(rows) => rows,
            Err(refused) => {
                self.refuse(refused);
                EntityRows::NONE
            }
        };
        // The watchers' lists of the application's observer, lent with its tables
        // (`SlotObserverOf::lent`): one row of their spans, as a face's gets are one of theirs.
        let watchers = self.lent_to::<{ caps::MAX_DECL_OBSERVERS }>(
            ArenaLimit::MaxDeclObservers,
            limits.max_decl_observers(),
        );
        // A build of the region's form lays the lists out in its region, at the build's bound; the
        // limit is still held, so a config over the build's is refused under its name either way.
        #[cfg(wz_lent)]
        {
            let watcher_bytes = self.sized(SlotObserverOf::<HeapSinks, Lent>::decl_watcher_bytes(
                watchers,
            ));
            self.put(ArenaPart::DeclarationWatchers, 1, watcher_bytes);
        }
        #[cfg(not(wz_lent))]
        let _laid_out_in_the_region = watchers;
        // A build that asks no query registers no get, so its tables of them hold no row.
        let queries = if cfg!(feature = "query") {
            self.lent_to::<{ caps::MAX_PENDING_QUERIES }>(
                ArenaLimit::MaxPendingQueries,
                limits.max_pending_queries(),
            )
        } else {
            0
        };
        let liveliness_gets = if cfg!(feature = "liveliness-get") {
            self.lent_to::<{ caps::MAX_PENDING_LIVELINESS_GETS }>(
                ArenaLimit::MaxPendingLivelinessGets,
                limits.max_pending_liveliness_gets(),
            )
        } else {
            0
        };
        let tables = self.sized(faces.checked_add(cfg!(feature = "local-queryable") as usize));
        self.session.gets = GetTables {
            rows: RequesterRows {
                queries,
                liveliness_gets,
            },
            tables,
        };
        // A row of tables, each the spans of one face's registries: a face takes one whole. A build
        // that asks no query holds no table of gets (`NoRequesters`), and its plan no row of them.
        // A build of the region's form holds its face's gets in its region (`RegistryRegion`).
        #[cfg(all(feature = "query", wz_lent))]
        {
            let get_bytes = self.sized(FaceGets::arena_bytes(self.session.gets.rows));
            self.put(ArenaPart::PendingGets, self.session.gets.tables, get_bytes);
        }
        // The ends of the legs, the rows of their callbacks and the session's note of each leg
        // pending, a row of each for each get every table holds (`GetTables::legs`). A build of
        // the region's form holds them in its region, at the build's bound
        // (`crate::engine::StatePlaces`).
        #[cfg(all(feature = "query", wz_lent))]
        {
            let legs = self.sized(self.session.gets.legs());
            self.put(
                ArenaPart::EndedLegs,
                legs,
                core::mem::size_of::<crate::engine::Ended>(),
            );
            self.put(
                ArenaPart::LegCallbacks,
                legs,
                core::mem::size_of::<Option<crate::engine::LegRow>>(),
            );
            self.put(
                ArenaPart::PendingLegs,
                legs,
                core::mem::size_of::<crate::engine::PendingGet>(),
            );
        }
        // The replies the gets that consolidate hold to their Finals: a row for each reply, in one
        // table shared by every get, each tagged with its leg (`engine::get::LegHold`).
        // The limit is held either way, so a config over the build's is refused under its name.
        #[cfg(feature = "query")]
        {
            self.session.held_replies = self.lent_to::<{ caps::MAX_PENDING_REPLIES }>(
                ArenaLimit::MaxPendingReplies,
                limits.max_pending_replies(),
            );
            #[cfg(wz_lent)]
            self.put(
                ArenaPart::HeldReplies,
                self.session.held_replies,
                core::mem::size_of::<HeldReply<u64, Lent>>(),
            );
        }
        // A row of tables, each what one face's peer is owed: a face takes one whole. What the
        // peers write by their own choice lies in pools the faces share, one area each.
        let rows = match peer_rows(limits) {
            Ok(rows) => rows,
            Err(refused) => {
                self.refuse(refused);
                NO_PEER_ROWS
            }
        };
        let pools = match pool_rows(limits, faces, member_alias_groups(shape.groups)) {
            Ok(pools) => pools,
            Err(refused) => {
                self.refuse(refused);
                NO_POOL_ROWS
            }
        };
        self.session.peers = FacePeers {
            rows,
            tables: faces,
            pools,
            dial: shape.dial_role(),
        };
        // The sets of face tables themselves, one for each face, in one table
        // (`engine::registry::Registry::new`); what each set's tables hold is the rows after it. A
        // build of the region's form holds its one set, its tables and their rows in its region.
        #[cfg(wz_lent)]
        self.put(
            ArenaPart::FaceTables,
            self.session.peers.sets(),
            FACE_SET_BYTES,
        );
        // Which face holds which set, a row for each set, in a build that takes faces beside its
        // dial role's.
        #[cfg(any(feature = "listen", feature = "group"))]
        self.put(
            ArenaPart::HeldFaces,
            self.session.peers.sets(),
            HELD_SET_BYTES,
        );
        // What the face holding each set names for a wait for its room, a place for each set
        // (`crate::engine::LinkRooms`); a build of the region's form holds its one set's place in
        // its region (`crate::engine::StatePlaces`).
        #[cfg(wz_lent)]
        self.put(
            ArenaPart::RoomPlaces,
            self.session.peers.sets(),
            ROOM_PLACE_BYTES,
        );
        #[cfg(wz_lent)]
        {
            let peer_bytes = self.sized(PeerTables::<Lent>::arena_bytes(self.session.peers.rows));
            self.put(ArenaPart::PeerTables, self.session.peers.tables, peer_bytes);
        }
        // Each kind one area: a pool the faces share, or for a session of one face a span of its
        // tables' own (`pool_rows`); none in a build whose faces keep those rows inline, as a
        // build of the region's form does.
        #[cfg(wz_lent)]
        if SHARES_ROWS {
            let pools = self.session.peers.pools;
            let aliases = self.sized(pools.alias_bytes());
            self.put(ArenaPart::PeerAliasPool, 1, aliases);
            let declarations = self.sized(pools.decl_bytes());
            self.put(ArenaPart::PeerDeclarationPools, 1, declarations);
            // A build that answers no peer's Interest keeps none of their rows and is lent no span
            // of them (`KEEPS_INTEREST_ROWS`): its plan lays out no row of them, as one that binds
            // no udp port lays out none of a port's.
            if KEEPS_INTEREST_ROWS {
                let interests = self.sized(pools.interest_bytes());
                self.put(ArenaPart::PeerInterestPool, 1, interests);
            }
            // `PeerPools::lent` lends one span past the three, the directory the session's key
            // arena names them by: a plan without it leaves the arena a span short of the open's
            // last place.
            let directory = self.sized(pools.directory_bytes());
            self.put(ArenaPart::PeerRowDirectory, 1, directory);
        }
        // The tokens the faces that went still owe, lent with the pools
        // (`engine::registry::Registry::new`).
        #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
        if self.session.peers.owed_tokens() > 0 {
            self.put(
                ArenaPart::OwedTokens,
                self.session.peers.owed_tokens(),
                core::mem::size_of::<
                    wz_session_core::declare::liveliness_subscriber::PeerTokens<Lent>,
                >(),
            );
        }
        self.session.held_queries = if cfg!(feature = "queryable") {
            self.lent_to::<{ caps::MAX_PENDING_FINALS }>(
                ArenaLimit::MaxPendingFinals,
                limits.max_pending_finals(),
            )
        } else {
            0
        };
        // The Finals held for those queries and the requests a dispatch refused for want of a
        // row, a row of each for each query held (`wz_session_core::query_plane::FinalHolds`),
        // where the arena lends them; a build of the region's form holds them in its region.
        #[cfg(all(feature = "queryable", wz_lent))]
        {
            let held = self.session.held_queries;
            self.put(
                ArenaPart::HeldFinals,
                held,
                core::mem::size_of::<crate::engine::FinalHold>(),
            );
            self.put(
                ArenaPart::RefusedFinals,
                held,
                core::mem::size_of::<crate::engine::RefusedFinal>(),
            );
        }
        #[cfg(feature = "advanced-cache")]
        {
            self.session.cache_bytes = self.lent(
                ArenaLimit::AdvancedCacheBytes,
                Quota::at_most(caps::ADVANCED_CACHE_BYTES),
                caps::ADVANCED_CACHE_BYTES,
            );
            if self.session.cache_bytes != 0 {
                self.put_table(
                    [ArenaPart::CacheRingFlag, ArenaPart::CacheRing],
                    1,
                    self.session.cache_bytes,
                );
            }
        }
        // A build of the region's form holds the session's tables and its key arena in its region
        // (`crate::region::StateRegion`).
        #[cfg(wz_lent)]
        self.put_entities();
        self.settled()
    }

    /// The rows the session's transport lends its tables from.
    pub fn transport(&self) -> &TransportRows {
        &self.transport
    }

    /// The rows the session's state lends its plain tables from.
    pub fn session(&self) -> &SessionRows {
        &self.session
    }

    /// The rows of the ABI's places.
    pub fn places(&self) -> &PlaceRows {
        &self.places
    }

    /// The one buffer of `handle`, a table of one buffer the plan's lender lent whole
    /// ([`PlaceTables::handle`]), claimed for the session's life: the handle's place when the plan
    /// holds one. The claim is never given back: what holds the buffer holds it until the session
    /// is let go, and a buffer dropped then would write its cell's flag into an arena given back
    /// before it. Refused as an arena with no room for a table lent no buffer.
    pub(crate) fn claim_handle(
        &self,
        handle: Option<LentByteCells>,
    ) -> Result<ClaimedPlaces, ArenaRefused> {
        match handle.map(claimed) {
            None => Ok(ClaimedPlaces { handle: None }),
            Some(Some((base, bytes))) => Ok(ClaimedPlaces {
                handle: Some(HandlePlace { base, bytes }),
            }),
            Some(None) => Err(ArenaRefused::Lend(LendRefused::Exhausted {
                asked: Some(self.places.handle_bytes),
                left: 0,
            })),
        }
    }

    /// The rows of the session's declarations ([`EntityRows`]).
    #[cfg(wz_lent)]
    const fn put_entities(&mut self) {
        // The session's one table set, holding the kinds moved onto it so far: the write filters,
        // the matching listeners and the Interests they hold among them.
        let tables = self.sized(CoopTables::arena_bytes(&self.tables()));
        self.put(ArenaPart::SessionTables, 1, tables);
        // The keys of those rows and of every other keyed row of the session, in one area that a
        // key takes a block of as long as it is held (`TableLender::keys`), not a row of
        // each.
        let keys = self.sized(KeySpace::span_bytes(self.session.key_bytes));
        self.put(ArenaPart::KeyArena, 1, keys);
    }

    /// How many rows each table of the session's round of deliveries is lent.
    #[cfg(wz_round)]
    pub fn round(&self) -> RoundRowCounts {
        self.session.round
    }

    /// The links the session may hold at once ([`links_of`]), whose buffers the plan holds: the
    /// rows of the session's link admission too.
    #[cfg(feature = "listen")]
    pub fn links(&self) -> usize {
        self.transport.links
    }

    /// Whether the outbound slots the links share are fewer than the links (`TX_POOL_SLOTS`), so
    /// that a link may find every slot held.
    #[cfg(feature = "listen")]
    pub fn tx_pool_short(&self) -> bool {
        self.transport.tx_slots < self.transport.links
    }

    /// How many rows each table of the engine's record of the session's declarations is lent.
    pub fn entities(&self) -> EntityRows {
        self.session.entities()
    }

    /// The rows of the session's one table set: those of the kinds moved onto it, none of the
    /// others.
    pub const fn tables(&self) -> TableRows {
        let rows = &self.session.entities;
        TableRows {
            keyexprs: rows.keyexprs,
            subscribers: rows.of_kind(EntityKind::Subscriber),
            queryables: rows.of_kind(EntityKind::Queryable),
            tokens: rows.of_kind(EntityKind::Token),
            liveliness_subscribers: rows.of_kind(EntityKind::LivelinessSubscriber),
            publishers: rows.of_kind(EntityKind::Publisher),
            queriers: rows.of_kind(EntityKind::Querier),
            matching_listeners: rows.of_kind(EntityKind::MatchingListener),
            key_listeners: rows.key_listeners(),
            pending_gets: 0,
            held_replies: 0,
        }
    }

    /// The bytes of blocks of the key arena every keyed row of the session keeps its key in
    /// (`KEY_ARENA_BYTES`).
    pub fn key_bytes(&self) -> usize {
        self.session.key_bytes()
    }

    /// The tables of pending gets the arena lends, and the rows of each.
    pub fn gets(&self) -> GetTables {
        self.session.gets()
    }

    /// The tables of what each face's peer writes and is owed the arena lends, and the rows of
    /// each.
    pub fn peers(&self) -> FacePeers {
        self.session.peers
    }

    /// The length of each buffer a link stages a fragmented message's chain in, and how many
    /// buffers the session's one table holds, which its links share.
    pub fn reassembly(&self) -> (usize, usize) {
        (
            self.transport.reassembly_bytes,
            self.transport.reassembly_chains,
        )
    }

    /// How many queries the session holds for its queryables' callbacks at once
    /// (`MAX_PENDING_FINALS`), resolved as the arena's rows are and none in a build without
    /// `queryable`. Their Finals lie in rows of the arena, a row each, as do the requests a
    /// dispatch refused for want of one.
    pub fn held_queries(&self) -> usize {
        self.session.held_queries
    }

    /// Add a row. A plan has room for every row of the build with every feature (`ARENA_ROWS`);
    /// a row past them is refused as an arena past what the plan can lay out, which the plan keeps
    /// as its refusal unless it holds an earlier one ([`Self::settled`]).
    #[inline(never)]
    const fn put(&mut self, name: ArenaPart, count: usize, entry_bytes: usize) {
        let row = ArenaRow {
            name,
            count,
            entry_bytes,
        };
        if self.len >= ARENA_ROWS {
            self.refuse(ArenaRefused::TooLarge);
            return;
        }
        #[cfg(any(feature = "runtime-plan", test))]
        if let Some((_, [slot, ..])) = self.rows.split_at_mut_checked(self.len) {
            *slot = row;
        }
        // Below `ARENA_ROWS`, checked above.
        self.len = self.len.saturating_add(1);
        self.reserved = match (self.reserved, row.span()) {
            (Some(sum), Some(span)) => sum.checked_add(span),
            _ => None,
        };
    }

    /// Add the two rows of a table of `count` entries of `entry_bytes`, the parts `flags` and
    /// `entries`: its flags, then its entries, as an arena lends a table of cells.
    #[inline(never)]
    const fn put_table(
        &mut self,
        [flags, entries]: [ArenaPart; 2],
        count: usize,
        entry_bytes: usize,
    ) {
        self.put(flags, count, LentByteCells::FLAG_BYTES);
        self.put(entries, count, entry_bytes);
    }

    /// Keep `refused` as the plan's refusal unless it holds an earlier one.
    #[inline(never)]
    const fn refuse(&mut self, refused: ArenaRefused) {
        if self.refused.is_none() {
            self.refused = Some(refused);
        }
    }

    /// The rows a table of the limit `limit` is lent (`lent_under`): `value` under `ceiling`,
    /// the build's value of the limit. A value over it is kept as the plan's refusal, under the
    /// limit's own name, and answers `0`.
    #[inline(never)]
    const fn lent(&mut self, limit: ArenaLimit, value: Quota, ceiling: usize) -> usize {
        match lent_under(limit, value, ceiling) {
            Ok(rows) => rows,
            Err(refused) => {
                self.refuse(refused);
                0
            }
        }
    }

    /// [`Self::lent`] under `CEILING`, the build's value of the limit: the most rows the build
    /// sizes the table's storage for, a const of the caller's as every ceiling of storage is
    /// ([`lent`]), so the build's value is read as that and nothing else.
    const fn lent_to<const CEILING: usize>(&mut self, limit: ArenaLimit, value: Quota) -> usize {
        self.lent(limit, value, CEILING)
    }

    /// `bytes`, a size `None` past the address space, which is then kept as the plan's refusal
    /// and answers `0`.
    #[inline(never)]
    const fn sized(&mut self, bytes: Option<usize>) -> usize {
        match bytes {
            Some(bytes) => bytes,
            None => {
                self.refuse(ArenaRefused::TooLarge);
                0
            }
        }
    }

    /// Whether the plan as laid out so far holds: the first refusal met while it was laid out,
    /// or refused as past the address space when the rows' spans together are. Read where the
    /// plan lies, which stays there.
    #[inline(never)]
    pub(crate) const fn settled(&self) -> Result<(), ArenaRefused> {
        if let Some(refused) = self.refused {
            return Err(refused);
        }
        match self.reserved_bytes() {
            Some(_) => Ok(()),
            None => Err(ArenaRefused::TooLarge),
        }
    }

    /// Lay out the places `held` names, lent after every other row: the ABI's handle of the
    /// session first, then each kind of entity in the order of [`EntityKind::ALL`], a place for
    /// each row the session keeps of the kind; then one table of places for values lodged by
    /// counts ([`HeldPlaces::with_lodgings`]), the engine's own among them. What the ABI keeps
    /// there takes no memory of its own, and an open whose arena cannot hold it reserves nothing,
    /// as for any other row. A place of no bytes, and a kind the session keeps no row of, take
    /// none, and a place the plan holds already is not laid out again. Refused as past the address space when a place asks for more
    /// alignment than a span of the arena starts on ([`ARENA_ALIGN`]), or the arena with the
    /// places is. The plan is laid out where it lies; a refused one is no plan to open by.
    pub fn holding(&mut self, held: &HeldPlaces) -> Result<(), ArenaRefused> {
        self.lay_held(held)?;
        self.settled()
    }

    /// The places of `Self::holding`, the plan not settled: refused here only for a place that
    /// asks for more alignment than a span starts on, and otherwise as the plan keeps it.
    pub(crate) const fn lay_held(&mut self, held: &HeldPlaces) -> Result<(), ArenaRefused> {
        if let Some(handle) = held.handle {
            if handle.align() > ARENA_ALIGN {
                return Err(ArenaRefused::TooLarge);
            }
            if handle.size() != 0 && self.places.handle_bytes == 0 {
                self.places.handle_bytes = handle.size();
                self.put_table(
                    [ArenaPart::SessionHandleFlag, ArenaPart::SessionHandle],
                    1,
                    handle.size(),
                );
            }
        }
        // Read where `held` lies, kind by kind, rather than copied whole into the walk.
        let mut from = 0;
        while let Some((at, place)) = held.next_entity(from) {
            // An index of the held places, which never reaches `usize::MAX`.
            from = at.saturating_add(1);
            if place.align() > ARENA_ALIGN {
                return Err(ArenaRefused::TooLarge);
            }
            let Some((_, &[kind, ..])) = EntityKind::ALL.split_at_checked(at) else {
                break;
            };
            let count = self.session.entities.of_kind(kind);
            if place.size() == 0 || count == 0 || self.entity_bytes(kind) != 0 {
                continue;
            }
            self.put_table(place_parts(kind), count, place.size());
            if let Some((_, [bytes, ..])) = self.places.entity_bytes.split_at_mut_checked(at) {
                *bytes = place.size();
                self.places.held = self.places.held.with(at);
            }
        }
        let Some(rows) = held.lodging else {
            return Err(ArenaRefused::TooLarge);
        };
        // The engine lodges a watcher of the faces' snapshots for each transport events listener
        // the session holds (`SessionEngine::watch_faces`), in the ABI's table of lodgings, whose
        // places are laid out for it already (`NO_LODGINGS`).
        #[cfg(feature = "connectivity")]
        let Some(rows) = rows.more(
            self.session
                .entities
                .of_kind(EntityKind::TransportEventsListener),
        ) else {
            return Err(ArenaRefused::TooLarge);
        };
        if rows.count() != 0 && self.places.lodging.count() == 0 {
            self.places.lodging = rows;
            self.put(ArenaPart::LodgingPlaces, rows.count(), rows.stride());
        }
        Ok(())
    }

    /// Lay out a table of a cell for each link of each kind `bytes` sizes: the links'
    /// drivers, which the stack places them in (`wz_runtime_coop::link_cells`, its
    /// `SessionLinks::link_cell_bytes`), and their gates and their actions, which the session
    /// places them in when it makes the link: a link the session opens then takes cells and no
    /// memory of the heap. Laid out before the ABI's handle ([`Self::holding`]). A size of `0`
    /// adds no table, as a stack that places its links on the heap asks. The plan is laid out
    /// where it lies; a refused one is no plan to open by.
    pub fn holding_cells(&mut self, bytes: LinkCells<usize>) -> Result<(), ArenaRefused> {
        self.lay_cells(bytes);
        self.settled()
    }

    /// The tables of `Self::holding_cells`, the plan not settled, in [`LinkCells::into_array`]'s
    /// order.
    pub(crate) const fn lay_cells(&mut self, bytes: LinkCells<usize>) {
        let laid = self.transport.cell_bytes;
        let [driver, gate, actions, halves] = CELL_PARTS;
        self.transport.cell_bytes = LinkCells {
            driver: self.lay_cell_table(0, driver, laid.driver, bytes.driver),
            gate: self.lay_cell_table(1, gate, laid.gate, bytes.gate),
            actions: self.lay_cell_table(2, actions, laid.actions, bytes.actions),
            halves: self.lay_cell_table(3, halves, laid.halves, bytes.halves),
        };
    }

    /// The bytes of the table of cells at `at` of [`LinkCells::into_array`]'s order, of the parts
    /// `parts`: `laid` where the plan holds the table already, and otherwise `asked`, laid out as a
    /// cell of that many bytes for each link; a size of `0` adds no table.
    const fn lay_cell_table(
        &mut self,
        at: usize,
        parts: [ArenaPart; 2],
        laid: usize,
        asked: usize,
    ) -> usize {
        if laid != 0 || asked == 0 {
            return laid;
        }
        self.transport.cells_held = self.transport.cells_held.with(at);
        self.put_table(parts, self.transport.links, asked);
        asked
    }

    /// Lay out the place of the faces' rooms, `bytes` large: what each face that is up names for a
    /// wait for its room, which the open places in the arena (`crate::engine::LinkRooms`). Their
    /// size is the stack's waits', which the plan of the session's limits does not know, so it is
    /// laid out at the open, once, as the links' cells are ([`Self::holding_cells`]). The plan is
    /// laid out where it lies; a refused one is no plan to open by.
    pub fn holding_rooms(&mut self, bytes: usize) -> Result<(), ArenaRefused> {
        self.lay_rooms(bytes);
        self.settled()
    }

    /// The place of `Self::holding_rooms`, the plan not settled.
    pub(crate) const fn lay_rooms(&mut self, bytes: usize) {
        self.put(ArenaPart::LinkRooms, 1, bytes);
    }

    /// Lay out the span of `bytes` the session's runtime is placed in, and the count its arena is
    /// kept by beside it (`SessionArena::runtime_place`): its state, its task table and its timer
    /// table lie in the arena, and the arena's memory is given back once the session and the
    /// runtime's last holder (a waker or a join handle kept past the session among them) have let
    /// go. Laid out after every other row, once; a size of `0` adds none. The plan is laid out
    /// where it lies; a refused one is no plan to open by.
    pub fn holding_runtime(&mut self, bytes: usize) -> Result<(), ArenaRefused> {
        self.lay_runtime(bytes);
        self.settled()
    }

    /// The span and the count of `Self::holding_runtime`, the plan not settled.
    pub(crate) const fn lay_runtime(&mut self, bytes: usize) {
        if bytes != 0 && self.runtime_bytes == 0 {
            self.runtime_bytes = bytes;
            self.put(ArenaPart::ArenaKeep, 1, core::mem::size_of::<ArenaKept>());
            self.put(ArenaPart::RuntimeState, 1, bytes);
        }
    }

    /// Lay out the place of `bytes` the session's engine lies in, counted by its holders, which
    /// keeps the arena's memory until the last of them lets go (`SessionArena::engine_place`).
    /// Laid out after every other row, once, at the open. The plan is laid out where it lies; a
    /// refused one is no plan to open by.
    pub fn holding_engine(&mut self, bytes: usize) -> Result<(), ArenaRefused> {
        self.lay_engine(bytes);
        self.settled()
    }

    /// The place of `Self::holding_engine`, the plan not settled.
    pub(crate) const fn lay_engine(&mut self, bytes: usize) {
        self.put(ArenaPart::EngineState, 1, bytes);
    }

    /// Lay out the place of each plane the session's state owns and its tasks and its engine
    /// reach by handles that count nothing (`crate::engine::SessionPlanes`): the queryables',
    /// the gets' and the watchers' of the faces, each where its feature is. Laid out once, at the
    /// open, the plan not settled: a refusal is kept for `Self::settled`.
    pub(crate) const fn lay_planes(&mut self, planes: crate::engine::SessionPlanes) {
        // Where the build fixes the session's shape these lie in its region
        // (`crate::engine::StatePlaces`).
        #[cfg(all(feature = "queryable", wz_lent))]
        self.put(ArenaPart::QueryPlaneState, 1, planes.queries);
        #[cfg(all(feature = "query", wz_lent))]
        self.put(ArenaPart::GetPlaneState, 1, planes.gets);
        #[cfg(all(feature = "connectivity", wz_lent))]
        self.put(ArenaPart::FacePlaneState, 1, planes.faces);
        let _ = planes;
    }

    /// Lay out the read slots and send places of the faces past the dial role's, a row of `bytes`
    /// for each face read where it lies after the first (`read_faces`): the dial role's lies in
    /// the engine's place. Laid out once, at the open, the plan not settled.
    #[cfg(not(wz_round))]
    pub(crate) const fn lay_direct_faces(&mut self, bytes: usize) {
        let rows = read_faces(self.session.peers.sets()).saturating_sub(1);
        if rows != 0 {
            self.put(ArenaPart::DirectFaces, rows, bytes);
        }
    }

    /// Lay out the place of `bytes` the admission of a session that listens lies in, which the
    /// session's state owns and its links' leases reach by handles that count nothing. Laid out
    /// once, at the open, the plan not settled: a refusal is kept for `Self::settled`.
    #[cfg(feature = "link-admission")]
    pub(crate) const fn lay_admission(&mut self, bytes: usize) {
        self.put(ArenaPart::LinkAdmissionState, 1, bytes);
    }

    /// The bytes of the place the plan holds for the ABI's handle, `0` for none.
    pub fn handle_bytes(&self) -> usize {
        self.places.handle_bytes
    }

    /// The bytes of each place the plan holds for an entity of `kind`, `0` for none.
    pub const fn entity_bytes(&self, kind: EntityKind) -> usize {
        match self.places.entity_bytes.split_at_checked(kind as usize) {
            Some((_, [bytes, ..])) => *bytes,
            _ => 0,
        }
    }

    /// The rows, in the order the plan laid them out.
    #[cfg(any(feature = "runtime-plan", test))]
    pub fn rows(&self) -> impl Iterator<Item = &ArenaRow> + '_ {
        self.rows.iter().take(self.len)
    }

    /// The bytes the arena reserves: the sum of the rows' spans, added as each was laid out.
    /// `None` past the address space.
    pub const fn reserved_bytes(&self) -> Option<usize> {
        self.reserved
    }
}

/// The rows a table of the limit `limit` is lent: `value`, the one the session's creator resolved
/// into its limits at the open, under `CEILING`, the build's value of the limit, which is the
/// capacity the build gives the table's type (a `BoundedVec<T, CEILING, Lent>` is lent at most
/// that many rows): the build sizes the storage and the snapshot chooses within it.
#[inline]
const fn lent<const CEILING: usize>(
    limit: ArenaLimit,
    value: Quota,
) -> Result<usize, ArenaRefused> {
    lent_under(limit, value, CEILING)
}

/// [`lent`] with the build's value a value: one body for every limit, the ceiling a const of the
/// caller's alone.
#[inline(never)]
const fn lent_under(
    limit: ArenaLimit,
    value: Quota,
    ceiling: usize,
) -> Result<usize, ArenaRefused> {
    match value.lent_under(Quota::at_most(ceiling)) {
        Ok(rows) => Ok(rows),
        Err(why) => Err(ArenaRefused::Limit { limit, why }),
    }
}

/// Whether a session's links share a pool of receive buffers and one of outbound slots, as a build
/// that listens lends them (`RX_POOL_BUFFERS`, `TX_POOL_SLOTS`), rather than each link holding a
/// buffer and a slot of its own.
pub const LINKS_SHARE_POOLS: bool = cfg!(feature = "listen");

/// The buffers a session's links read their batches into and encode their frames into, and the
/// buffers they stage the chains of fragmented messages in, as the session's plan lays them out
/// ([`link_buffers`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkBuffers {
    /// The receive buffers the plan lends the links.
    pub receive: usize,
    /// The outbound slots the plan lends the links.
    pub transmit: usize,
    /// The bytes of each receive buffer and of each slot: the batch the session advertises.
    pub bytes: usize,
    /// The reassembly buffers of the session's one table, which its links share: its stated
    /// share for each face read where it lies.
    pub chains: usize,
}

/// The buffers of the links of a session that holds `links` links at most, admits `beside` faces
/// besides its dial role's (its [`CoopConfig::max_faces`] and the groups it joins) and
/// advertises `batch` under `limits`: what its plan lays out for them, from the same reckoning
/// ([`ArenaPlan::lay_out`]), so a report of the session's memory reads what its open reserves.
/// Refused as the plan refuses the batch, a pool's limit or the table of chains.
pub const fn link_buffers(
    links: usize,
    beside: usize,
    batch: u16,
    limits: &SessionLimits,
) -> Result<LinkBuffers, ArenaRefused> {
    let bytes = tried!(link_batch(batch, limits));
    let (receive, transmit) = tried!(pooled_buffers(links, limits));
    let share = tried!(reassembly_chains(limits));
    // The face table's places: the dial role's, whether or not it dials, and one for each face
    // besides (`FacePeers::sets`).
    let Some(chains) = chain_table(share, beside.saturating_add(1)) else {
        return Err(ArenaRefused::TooLarge);
    };
    Ok(LinkBuffers {
        receive,
        transmit,
        bytes,
        chains,
    })
}

/// A face's share of the session's one table of chains under `limits`: its `REASSEMBLY_CHAINS`,
/// held under the build's value, which a session lowers and never raises, so a value over it is
/// refused under its own name. However many links the face holds, as a chain is claimed from the
/// table and not from a link's own buffers.
const fn reassembly_chains(limits: &SessionLimits) -> Result<usize, ArenaRefused> {
    lent::<{ caps::REASSEMBLY_CHAINS }>(ArenaLimit::ReassemblyChains, limits.reassembly_chains())
}

/// The receive buffers and the outbound slots of `links` links under `limits`. A build that
/// listens lends pools the links share, each holding a buffer only while it holds part of a batch
/// or something it was asked to keep (`wz_runtime_coop::link_storage::PooledRx`) and a slot from
/// its grant to its send, or until a frame its stream took in part is written
/// (`wz_runtime_coop::link_storage::PooledTx`): the pool's limit, and no more than the links, as a
/// buffer no link can take is memory nothing uses. A build that only dials holds its dial and the
/// faces it attaches, and lends each link a buffer and a slot of its own.
const fn pooled_buffers(
    links: usize,
    limits: &SessionLimits,
) -> Result<(usize, usize), ArenaRefused> {
    if LINKS_SHARE_POOLS {
        let rx = tried!(lent::<{ caps::RX_POOL_BUFFERS }>(
            ArenaLimit::RxPoolBuffers,
            Quota::at_most(limits.rx_pool_buffers()),
        ));
        let tx = tried!(lent::<{ caps::TX_POOL_SLOTS }>(
            ArenaLimit::TxPoolSlots,
            Quota::at_most(limits.tx_pool_slots()),
        ));
        Ok((least(rx, links), least(tx, links)))
    } else {
        Ok((links, links))
    }
}

/// The length of each link's receive buffer and of each of its slots: the batch `batch` a session
/// advertises, which is the most a peer sends once the two have negotiated, held to the batch the
/// session's `limits` state (`PICO_UNICAST_BATCH_BYTES`) under the build's. A batch over either
/// is refused, as a stage after the build only lowers the memory the build fixes.
const fn link_batch(batch: u16, limits: &SessionLimits) -> Result<usize, ArenaRefused> {
    let ceiling = tried!(lent::<{ caps::PICO_UNICAST_BATCH_BYTES }>(
        ArenaLimit::PicoUnicastBatchBytes,
        Quota::at_most(limits.pico_unicast_batch_bytes()),
    ));
    let advertised = batch as usize;
    if advertised > ceiling {
        return Err(ArenaRefused::Limit {
            limit: ArenaLimit::PicoUnicastBatchBytes,
            why: UnlentRows::OverCeiling {
                value: advertised,
                ceiling,
            },
        });
    }
    Ok(advertised)
}

/// The rows of each table of the engine's record of the session's declarations, under `limits`.
const fn entity_rows(limits: &SessionLimits) -> Result<EntityRows, ArenaRefused> {
    let subscribers = tried!(lent::<{ caps::MAX_SUBSCRIPTIONS }>(
        ArenaLimit::MaxSubscriptions,
        limits.max_subscriptions(),
    ));
    let queryables = if cfg!(feature = "queryable") {
        tried!(lent::<{ caps::MAX_QUERYABLES }>(
            ArenaLimit::MaxQueryables,
            limits.max_queryables()
        ))
    } else {
        0
    };
    let tokens = if cfg!(feature = "liveliness") {
        tried!(lent::<{ caps::MAX_LOCAL_TOKENS }>(
            ArenaLimit::MaxLocalTokens,
            limits.max_local_tokens()
        ))
    } else {
        0
    };
    let liveliness_subscribers = if cfg!(feature = "liveliness") {
        tried!(lent::<{ caps::MAX_LIVELINESS_SUBSCRIPTIONS }>(
            ArenaLimit::MaxLivelinessSubscriptions,
            limits.max_liveliness_subscriptions(),
        ))
    } else {
        0
    };
    let keyexprs = tried!(lent::<{ caps::MAX_DECLARED_KEYEXPRS }>(
        ArenaLimit::MaxDeclaredKeyexprs,
        limits.max_declared_keyexprs(),
    ));
    let publishers = tried!(lent::<{ caps::MAX_PUBLISHERS }>(
        ArenaLimit::MaxPublishers,
        limits.max_publishers()
    ));
    let queriers = tried!(lent::<{ caps::MAX_QUERIERS }>(
        ArenaLimit::MaxQueriers,
        limits.max_queriers()
    ));
    let matching_listeners = tried!(lent::<{ caps::MAX_MATCHING_LISTENERS }>(
        ArenaLimit::MaxMatchingListeners,
        limits.max_matching_listeners(),
    ));
    // As many as the tables of pending gets hold rows of each (`GetTables`): a get the ABI
    // holds pending takes one row of every face's table, so no more are pending at once.
    let pending_gets = if cfg!(feature = "query") {
        tried!(lent::<{ caps::MAX_PENDING_QUERIES }>(
            ArenaLimit::MaxPendingQueries,
            limits.max_pending_queries(),
        ))
    } else {
        0
    };
    let pending_liveliness_gets = if cfg!(feature = "liveliness-get") {
        tried!(lent::<{ caps::MAX_PENDING_LIVELINESS_GETS }>(
            ArenaLimit::MaxPendingLivelinessGets,
            limits.max_pending_liveliness_gets(),
        ))
    } else {
        0
    };
    let decl_watches = if cfg!(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    )) {
        tried!(lent::<{ caps::MAX_DECL_WATCHES }>(
            ArenaLimit::MaxDeclWatches,
            limits.max_decl_watches()
        ))
    } else {
        0
    };
    let transport_events_listeners = if cfg!(feature = "connectivity") {
        tried!(lent::<{ caps::MAX_TRANSPORT_EVENTS_LISTENERS }>(
            ArenaLimit::MaxTransportEventsListeners,
            limits.max_transport_events_listeners(),
        ))
    } else {
        0
    };
    let advanced_publishers = if cfg!(feature = "advanced") {
        tried!(lent::<{ caps::MAX_ADVANCED_PUBLISHERS }>(
            ArenaLimit::MaxAdvancedPublishers,
            limits.max_advanced_publishers(),
        ))
    } else {
        0
    };
    let advanced_subscribers = if cfg!(feature = "advanced") {
        tried!(lent::<{ caps::MAX_ADVANCED_SUBSCRIBERS }>(
            ArenaLimit::MaxAdvancedSubscribers,
            limits.max_advanced_subscribers(),
        ))
    } else {
        0
    };
    let link_events_listeners = if cfg!(feature = "connectivity") {
        tried!(lent::<{ caps::MAX_LINK_EVENTS_LISTENERS }>(
            ArenaLimit::MaxLinkEventsListeners,
            limits.max_link_events_listeners(),
        ))
    } else {
        0
    };
    Ok(EntityRows {
        kinds: [
            publishers,
            subscribers,
            queryables,
            tokens,
            liveliness_subscribers,
            queriers,
            pending_gets,
            pending_liveliness_gets,
            matching_listeners,
            decl_watches,
            transport_events_listeners,
            advanced_publishers,
            advanced_subscribers,
            link_events_listeners,
        ],
        keyexprs,
    })
}

/// The rows of each kind of what the peers of a session of `faces` faces write, under `limits`.
///
/// A session of many faces lends a pool of each kind the faces share: the session's value of the
/// kind's limit under the build's, and no more than the faces could hold together, each at the
/// bound of one peer the session resolved, and `groups` of them, the faces of groups whose
/// members' keyexprs are each their own, at `GROUP_FACE_ALIASES` aliases. A session of one face
/// has no one to share with: its tables take spans of their own of that face's bounds, with no
/// link and no pool state, as many rows as its inline tables held (and fewer where the session's
/// limit is lower).
///
/// A pool or a span names its rows by `u16`, so a count past [`MAX_POOL_ROWS`] refuses the open
/// by the limit that set it: the session's limit for a pool, the face's for a span. Refused too
/// when a limit is over the build's value.
const fn pool_rows(
    limits: &SessionLimits,
    faces: usize,
    groups: usize,
) -> Result<PeerPoolRows, ArenaRefused> {
    if !SHARES_ROWS {
        // A build whose faces keep what their peers write inline lends no pool and no span.
        return Ok(NO_POOL_ROWS);
    }
    let face_aliases = tried!(limit_rows::<{ caps::MAX_PEER_KEYEXPR_ALIASES }>(
        ALIAS_LIMITS.face,
        limits.max_peer_keyexpr_aliases(),
    ));
    Ok(PeerPoolRows {
        aliases: tried!(rows_within(
            faces_aliases(faces, groups, face_aliases.1),
            faces,
            face_aliases,
            tried!(limit_rows::<{ caps::SESSION_MAX_PEER_KEYEXPR_ALIASES }>(
                ALIAS_LIMITS.session,
                limits.session_max_peer_keyexpr_aliases(),
            )),
        )),
        remote_decls: tried!(kind_rows(
            faces,
            tried!(limit_rows::<{ caps::MAX_REMOTE_DECLS }>(
                DECL_LIMITS.face,
                limits.max_remote_decls()
            )),
            tried!(limit_rows::<{ caps::SESSION_MAX_REMOTE_DECLS }>(
                DECL_LIMITS.session,
                limits.session_max_remote_decls(),
            )),
        )),
        interests: tried!(kind_rows(
            faces,
            tried!(limit_rows::<{ caps::MAX_INBOUND_SUB_INTERESTS }>(
                INTEREST_LIMITS.face,
                limits.max_inbound_sub_interests(),
            )),
            tried!(limit_rows::<{ caps::SESSION_MAX_INBOUND_SUB_INTERESTS }>(
                INTEREST_LIMITS.session,
                limits.session_max_inbound_sub_interests(),
            )),
        )),
        shared: faces > 1,
    })
}

/// The limit `limit` and the rows [`lent`] gives its value under `CEILING`, as [`kind_rows`]
/// takes each of its two.
#[inline]
const fn limit_rows<const CEILING: usize>(
    limit: ArenaLimit,
    value: Quota,
) -> Result<(ArenaLimit, usize), ArenaRefused> {
    Ok((limit, tried!(lent::<CEILING>(limit, value))))
}

/// The two limits that bound one kind of what the peers of a session write, by id: one face's, and
/// all the faces' together.
struct PoolLimit {
    face: ArenaLimit,
    session: ArenaLimit,
}

/// The limits of the peers' keyexpr aliases.
const ALIAS_LIMITS: PoolLimit = PoolLimit {
    face: ArenaLimit::MaxPeerKeyexprAliases,
    session: ArenaLimit::SessionMaxPeerKeyexprAliases,
};

/// The aliases the face of a group holds where each member's keyexprs are its own
/// (`multicast-declarations`): `MAX_MEMBER_KEYEXPRS` for each of the `MAX_GROUP_MEMBERS` members, so
/// the session's pool reserves at its open what every member may declare and none runs out after.
#[cfg(feature = "multicast-declarations")]
pub(crate) const GROUP_FACE_ALIASES: usize =
    caps::MAX_GROUP_MEMBERS.saturating_mul(caps::MAX_MEMBER_KEYEXPRS);

/// The groups of a session that joins `groups` whose faces hold `GROUP_FACE_ALIASES`: each one a
/// task cell holds, as [`PlanShape::faces`] counts them, in a build whose members' keyexprs are their own,
/// and none in another.
const fn member_alias_groups(groups: usize) -> usize {
    if cfg!(feature = "multicast-declarations") {
        least(groups, caps::MAX_TASKS)
    } else {
        0
    }
}

/// The aliases `faces` faces hold together at most, `face` each, `groups` of them a group's
/// `GROUP_FACE_ALIASES` instead.
pub(crate) const fn faces_aliases(faces: usize, groups: usize, face: usize) -> usize {
    #[cfg(feature = "multicast-declarations")]
    {
        face.saturating_mul(faces.saturating_sub(groups))
            .saturating_add(GROUP_FACE_ALIASES.saturating_mul(groups))
    }
    #[cfg(not(feature = "multicast-declarations"))]
    {
        let _ = groups;
        face.saturating_mul(faces)
    }
}

/// The limits of the peers' declarations of one kind.
const DECL_LIMITS: PoolLimit = PoolLimit {
    face: ArenaLimit::MaxRemoteDecls,
    session: ArenaLimit::SessionMaxRemoteDecls,
};

/// The limits of the peers' subscriber interests.
const INTEREST_LIMITS: PoolLimit = PoolLimit {
    face: ArenaLimit::MaxInboundSubInterests,
    session: ArenaLimit::SessionMaxInboundSubInterests,
};

/// The rows of one kind of what the peers of a session of `faces` faces write: the fewer of the
/// session's limit and the faces' bounds together, `face` and `session` each a limit's id and the
/// value the open resolved of it. Refused, by the id of the limit that set the count, past the
/// most rows a pool or a span names ([`MAX_POOL_ROWS`]): a session's limit for a session of many
/// faces, the face's for one of one face, unless the session's is the lower.
pub(crate) const fn kind_rows(
    faces: usize,
    face: (ArenaLimit, usize),
    session: (ArenaLimit, usize),
) -> Result<usize, ArenaRefused> {
    rows_within(face.1.saturating_mul(faces), faces, face, session)
}

/// [`kind_rows`] of `faces` faces that hold `all` rows together at most.
const fn rows_within(
    all: usize,
    faces: usize,
    face: (ArenaLimit, usize),
    session: (ArenaLimit, usize),
) -> Result<usize, ArenaRefused> {
    let (limit, rows) = if session.1 < all {
        session
    } else if faces > 1 {
        (session.0, all)
    } else {
        (face.0, all)
    };
    if rows > MAX_POOL_ROWS {
        return Err(ArenaRefused::Limit {
            limit,
            why: UnlentRows::OverCeiling {
                value: rows,
                ceiling: MAX_POOL_ROWS,
            },
        });
    }
    Ok(rows)
}

/// The rows of each table of what one face's peer is owed, under `limits`.
///
/// The face's reply stage is lent no row. This engine's queryable answers outside the session's
/// lock into a stage of its own, held to the same limits (the engine's `answer`): the sink it
/// registers copies the query out and leaves the responder the dispatch hands it over the face's
/// stage unwritten, so rows lent there would be memory nothing reads. A reply staged there anyway
/// is refused and counted as one past a full stage is. The reply limits are still held to the
/// build's here, so a value over it refuses the open by its name as before.
const fn peer_rows(limits: &SessionLimits) -> Result<PeerRows, ArenaRefused> {
    if cfg!(feature = "queryable") {
        tried!(lent::<{ caps::MAX_PENDING_REPLIES }>(
            ArenaLimit::MaxPendingReplies,
            limits.max_pending_replies(),
        ));
        tried!(lent::<{ caps::MAX_REPLY_PAYLOAD_BYTES }>(
            ArenaLimit::MaxReplyPayloadBytes,
            limits.max_reply_payload_bytes(),
        ));
    }
    Ok(PeerRows {
        pending_declares: tried!(lent::<{ caps::MAX_PENDING_DECLARES }>(
            ArenaLimit::MaxPendingDeclares,
            limits.max_pending_declares(),
        )),
        replies: 0,
        reply_bytes: 0,
        finals: if cfg!(feature = "queryable") {
            tried!(lent::<{ caps::MAX_PENDING_FINALS }>(
                ArenaLimit::MaxPendingFinals,
                limits.max_pending_finals(),
            ))
        } else {
            0
        },
    })
}

/// The faces besides the dial role's that `limits` admit: the session's `MAX_FACES`, under the
/// build's. What an ABI states as [`CoopConfig::max_faces`] for a session that takes faces besides
/// its dial, which [`ArenaPlan::of`] holds the config to. Refused when the session's value is over
/// the build's. None in a build that takes no face beside its dial role's (`TAKES_FACES`),
/// whatever the session's value: such a session holds its dial role's face alone, so a config that
/// states one more is refused by the limit's name rather than lent places no face can take.
pub const fn admitted_faces(limits: &SessionLimits) -> Result<usize, ArenaRefused> {
    if !TAKES_FACES {
        return Ok(0);
    }
    lent::<{ caps::MAX_FACES }>(ArenaLimit::MaxFaces, limits.max_faces())
}

/// Whether the build takes faces beside its dial role's: the links a listener accepts and the
/// faces it attaches (`listen`), and the groups it joins (`group`). A build of neither holds
/// its dial role's face alone (`wz_runtime_coop::faces::OneFace`).
pub(crate) const TAKES_FACES: bool = cfg!(any(feature = "listen", feature = "group"));

/// The faces of the face table's `sets` places that are read where they lie, each with a read
/// slot, a send place and a share of the chain buffers of its own (`crate::engine::direct`):
/// every place where the session listens, whose ports' connections and attaches take the places
/// past the dial role's, and the dial role's alone otherwise. A group's place is read through the
/// group's own session, which stages its chains itself, so it is lent neither. Where the links
/// are tasks (`wz_round`) they stage into the session's one Router, which reads them all.
const fn read_faces(sets: usize) -> usize {
    if cfg!(feature = "listen") && !cfg!(wz_round) {
        sets
    } else {
        1
    }
}

/// The buffers of the session's one table of chains: `share` for each face read where it lies
/// among the face table's `sets` places (`read_faces`), so the chains of one face never take
/// another's buffers. `None` past the address space. The one reckoning of the plan's table and of
/// a report's (`link_buffers`).
const fn chain_table(share: usize, sets: usize) -> Option<usize> {
    share.checked_mul(read_faces(sets))
}

/// The most chains one face's Router holds open at once where its share of the session's one
/// table is `share` buffers: the share, up to the chains a Router stages at once
/// (`LENT_CHAINS`). The build's share is one more than those, for the rejoined message a face's
/// read keeps out of the table while it reads it where it lies (`SESSION_CHAIN_BUFFERS` of
/// `wz_runtime_coop::reassembly_rx`); a share a session lowers bounds the chains themselves, so
/// a session that states one rejoins one chain at a time.
const fn face_chains(share: usize) -> usize {
    least(share, LENT_CHAINS)
}

/// The inbound links in their handshake at once that `limits` admit: the session's
/// `MAX_ACCEPT_PENDING`, under the build's. What an ABI states as
/// [`CoopConfig::accept_pending`], which [`ArenaPlan::of`] holds the config of a session that
/// listens to. Refused when the session's value is over the build's.
pub const fn admitted_handshakes(limits: &SessionLimits) -> Result<usize, ArenaRefused> {
    lent::<{ caps::MAX_ACCEPT_PENDING }>(ArenaLimit::MaxAcceptPending, limits.max_accept_pending())
}

/// `asked`, what a session's config states of the limit `limit`, held to `admitted`, the session's
/// value of it under the build's: a config over it is refused, as a stage after the build only
/// lowers the memory the build fixes.
const fn hold(limit: ArenaLimit, asked: usize, admitted: usize) -> Result<(), ArenaRefused> {
    if asked > admitted {
        return Err(ArenaRefused::Limit {
            limit,
            why: UnlentRows::OverCeiling {
                value: asked,
                ceiling: admitted,
            },
        });
    }
    Ok(())
}

/// [`hold`] under `CEILING`, the build's value of the limit: the most rows the build sizes the
/// table for, where no session's value of it is in reach, a const of the caller's as a ceiling of
/// storage is ([`lent`]).
const fn hold_under<const CEILING: usize>(
    limit: ArenaLimit,
    asked: usize,
) -> Result<(), ArenaRefused> {
    hold(limit, asked, CEILING)
}

/// Whether a session `config` opens gives its dial role's face a link: it does when it lists an
/// endpoint to dial, and when it lists none and has neither a port to listen on nor a group to
/// join, whose open then fails for want of an endpoint (`CoopEngine::open_links`, which asks
/// this). A session that only listens or only joins groups never dials from that face: a face it
/// attaches later is one of `max_faces`.
pub(crate) fn dials(config: &CoopConfig<impl EndpointList>) -> bool {
    dials_of(
        config.endpoints.count(),
        config.listen.count(),
        config.groups.len(),
    )
}

/// [`dials`] of a session by its counts: the endpoints it dials, those it listens on and the
/// groups it joins, which an open session reads from its endpoint texts once the config's are
/// gone.
pub(crate) const fn dials_of(endpoints: usize, listens: usize, groups: usize) -> bool {
    !(endpoints == 0 && (listens > 0 || groups > 0))
}

/// The most faces a session's plan counts ([`PlanShape::faces`]), and so the most sets of face tables
/// its arena lends: the dial role's, each face the build admits besides it (`MAX_FACES`), and in
/// a build that joins groups one for each group the session's task cells hold (`MAX_TASKS`). A
/// session that dials nothing counts no dial face but is lent a set of no rows for it
/// ([`FacePeers::sets`]), so the bound is the same.
pub(crate) const MAX_FACE_SETS: usize = 1 + caps::MAX_FACES + GROUP_FACES;

/// The words of a set of the places of a session's rooms, a bit for each face a session holds at
/// most ([`MAX_FACE_SETS`]).
pub(crate) const FACE_SLOT_WORDS: usize = MAX_FACE_SETS.div_ceil(u64::BITS as usize);

/// The faces a droppable publish that found the session held was dropped on.
pub(crate) type DroppedOn = wz_runtime_coop::handed::FaceSlots<FACE_SLOT_WORDS>;

/// The publishes a session keeps for the faces they were not dropped on.
#[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
pub(crate) type HandedTable = wz_runtime_coop::handed::HandedLegs<FACE_SLOT_WORDS>;

/// One publish a session keeps for its other faces.
#[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
pub(crate) type Handed = wz_runtime_coop::handed::HandedLeg<FACE_SLOT_WORDS>;

/// The groups a session's plan counts at most: as many as its task cells hold in a build that
/// joins groups, none in one that does not.
const GROUP_FACES: usize = if cfg!(feature = "group") {
    caps::MAX_TASKS
} else {
    0
};

/// The links a session `config` opens may hold at once, whose buffers its open reserves: the dial
/// role's when it dials (the endpoints it lists, or none with neither a port nor a group), as many
/// besides as `max_faces` admits (each a link it attaches or accepts), and for a listener as many
/// in their handshake as `accept_pending` admits. `None` past the address space. The one count
/// of them: the plan's link rows are sized by it, and an ABI that reports the session's memory
/// reads it here. A link in its handshake past the faces holds buffers only, to be taken off its
/// port and closed; the runtime's task cells are reserved for the faces (`engine::RuntimeTables`).
pub fn links_of(config: &CoopConfig<impl EndpointList>) -> Option<usize> {
    links_for(
        dials(config),
        config.max_faces,
        config.listen.count(),
        config.accept_pending,
    )
}

/// [`links_of`] of a session by its numbers: whether it dials, the faces it admits besides, the
/// endpoints it listens on and the handshakes it admits at once while it listens.
const fn links_for(
    dials: bool,
    max_faces: usize,
    listens: usize,
    accept_pending: usize,
) -> Option<usize> {
    let handshakes = if listens == 0 { 0 } else { accept_pending };
    match (dials as usize).checked_add(max_faces) {
        Some(faces) => faces.checked_add(handshakes),
        None => None,
    }
}

/// The numbers of a session's config its arena is laid out by ([`ArenaPlan::lay_out`]): read
/// from the config at an open ([`Self::of`]), or stated as constants by a build that knows them
/// ([`Self::dial_only`]), whose plan is then laid out when the build is compiled
/// ([`ArenaPlan::planned`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanShape {
    /// The endpoints the session dials (at most `MAX_STATIC_CONNECT`).
    pub dials: usize,
    /// The endpoints it listens on (at most `MAX_ADMIN_LOCATORS`).
    pub listens: usize,
    /// How many of those are `udp/` ones, each a udp port the stack binds, which read into the
    /// datagram slots the arena lends (`UDP_PORT_SLOTS`): a session that listens on `tcp/` alone
    /// binds no port and is lent none. Only a build with the udp listener (`udp-listen`) binds
    /// one.
    #[cfg(feature = "udp-listen")]
    pub udp_listens: usize,
    /// The multicast groups it joins.
    pub groups: usize,
    /// The faces it admits besides the dial role's ([`CoopConfig::max_faces`]).
    pub max_faces: usize,
    /// The inbound links in their handshake at once ([`CoopConfig::accept_pending`]).
    pub accept_pending: usize,
    /// The batch it advertises ([`CoopConfig::batch_size`]).
    pub batch: u16,
    /// The largest batch a group it joins sends, `0` for none.
    #[cfg(feature = "group")]
    pub group_batch: usize,
    /// Whether its policy keeps a publish that found the session held for the faces it was not
    /// dropped on (`held-faces`), which a place of the arena then holds.
    #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
    pub keeps_handed: bool,
}

impl PlanShape {
    /// The numbers of `config`, under the policy its open resolves.
    pub fn of<E: EndpointList>(config: &CoopConfig<E>) -> Self {
        Self {
            dials: config.endpoints.count(),
            listens: config.listen.count(),
            #[cfg(feature = "udp-listen")]
            udp_listens: config.listen.udp(),
            groups: config.groups.len(),
            max_faces: config.max_faces,
            accept_pending: config.accept_pending,
            batch: config.batch_size,
            #[cfg(feature = "group")]
            group_batch: config
                .groups
                .iter()
                .map(|join| usize::from(join.profile.batch_size))
                .max()
                .unwrap_or(0),
            #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
            keeps_handed: keeps_handed(&crate::engine::resolve_policy(config)),
        }
    }

    /// A session that dials `dials` endpoints, advertises `batch`, listens on nothing, joins no
    /// group and admits no face besides its dial, under `policy`: what a client of an ABI holds.
    /// The policy is the creator's, as [`Self::of`] takes the one its open resolves; a build that
    /// states no policy hands the build's.
    pub const fn dial_only(
        dials: usize,
        batch: u16,
        policy: &wz_session_core::policy::SessionPolicy,
    ) -> Self {
        #[cfg(not(all(wz_round, any(feature = "listen", feature = "group"))))]
        let _ = policy;
        Self {
            dials,
            listens: 0,
            #[cfg(feature = "udp-listen")]
            udp_listens: 0,
            groups: 0,
            max_faces: 0,
            accept_pending: 0,
            batch,
            #[cfg(feature = "group")]
            group_batch: 0,
            #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
            keeps_handed: keeps_handed(policy),
        }
    }

    /// Whether the session gives its dial role's face a link ([`dials`]).
    const fn dial_role(&self) -> bool {
        dials_of(self.dials, self.listens, self.groups)
    }

    /// The faces the session may hold at once: the dial role's when it dials, as many besides as
    /// `max_faces` admits, a link still in its handshake among them, and one for each group it
    /// joins. A group past the task cells has no task to join it on, and the open refuses it at
    /// its join (`OpenError::NoTask`), as a build without `group` refuses any by name, so neither
    /// is counted. `None` past the address space.
    const fn faces(&self) -> Option<usize> {
        let groups = if cfg!(feature = "group") {
            least(self.groups, caps::MAX_TASKS)
        } else {
            0
        };
        match (self.dial_role() as usize).checked_add(self.max_faces) {
            Some(faces) => faces.checked_add(groups),
            None => None,
        }
    }

    /// The links the session may hold at once ([`links_of`]).
    const fn links(&self) -> Option<usize> {
        links_for(
            self.dial_role(),
            self.max_faces,
            self.listens,
            self.accept_pending,
        )
    }
}

/// Whether `policy` keeps a publish that found the session held for the faces it was not dropped
/// on.
#[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
const fn keeps_handed(policy: &wz_session_core::policy::SessionPolicy) -> bool {
    matches!(policy.held_publish_drop(), HeldPublishDrop::HeldFaces)
}

/// A row of a plan not laid out: what a plan holds past the rows it laid out.
#[cfg(any(feature = "runtime-plan", test))]
const UNLAID_ROW: ArenaRow = ArenaRow {
    name: ArenaPart::EndpointTexts,
    count: 0,
    entry_bytes: 0,
};

/// The cells of no link: a plan holds none until it is told the links' ([`ArenaPlan::holding_cells`]).
const NO_CELLS: LinkCells<usize> = LinkCells {
    driver: 0,
    gate: 0,
    actions: 0,
    halves: 0,
};

/// What a face's peer is owed, no row of it: a plan's before it is laid out, or after a refusal.
const NO_PEER_ROWS: PeerRows = PeerRows {
    pending_declares: 0,
    replies: 0,
    reply_bytes: 0,
    finals: 0,
};

/// What the peers write, no row of it: a build whose faces keep it inline, or a refused plan.
const NO_POOL_ROWS: PeerPoolRows = PeerPoolRows {
    aliases: 0,
    remote_decls: 0,
    interests: 0,
    shared: false,
};

/// Where a session's arena is reserved from.
pub trait ArenaMemory: Sync {
    /// `layout.size()` bytes aligned to `layout.align()`, or `None` when there are none to give.
    /// Never asked for zero bytes.
    fn reserve(&self, layout: Layout) -> Option<NonNull<u8>>;

    /// Whether every block [`Self::reserve`] gives is zero in every byte as it is given, written
    /// by nothing: the system's fresh pages (an anonymous `mmap`, `VirtualAlloc`) or a region
    /// of `.bss` no one used before. The arena of such a memory is laid over its block as it lies
    /// (`Arena::over_zeroed`): its rows are empty as all-zero bytes, so the open writes none of
    /// them, and a page no row of the session uses is never written, nor on a host with paging
    /// resident. Any other memory's block is written where a row must read empty (the head of a
    /// region, the tables of buffers) and nowhere else. `false` unless the memory says so.
    fn reserves_zeroed(&self) -> bool {
        false
    }

    /// Give back what [`Self::reserve`] gave.
    ///
    /// # Safety
    /// `base` is what [`Self::reserve`] gave for `layout`, it is given back once, and nothing
    /// uses it after.
    unsafe fn release(&self, base: NonNull<u8>, layout: Layout);
}

/// The allocator, asked once for the whole arena and given it back when the session is let go:
/// the memory of a host library until the operating system's layer reserves it
/// (`docs/c-abi-engine-and-memory.md`, phase P4). An allocator with none to give is an answer,
/// not the end of the process. Not said to give zeroed blocks (`ArenaMemory::reserves_zeroed`):
/// a block it hands from memory given back to it before is not zero, and its zeroed allocation
/// (`calloc`) writes all of such a block where the open writes only the rows that need it.
pub struct AllocatorMemory;

impl ArenaMemory for AllocatorMemory {
    fn reserve(&self, layout: Layout) -> Option<NonNull<u8>> {
        // SAFETY: the layout is not of zero bytes, which the trait's contract rules out.
        NonNull::new(unsafe { alloc::alloc::alloc(layout) })
    }

    unsafe fn release(&self, base: NonNull<u8>, layout: Layout) {
        // SAFETY: the caller's contract: the allocator gave `base` for `layout`, given back once.
        unsafe { alloc::alloc::dealloc(base.as_ptr(), layout) }
    }
}

/// The place a session's arena lends the ABI's handle of the session in
/// ([`ArenaPlan::holding`]): `bytes` bytes aligned to [`ARENA_ALIGN`], zeroed at the open, which
/// the engine never reads or writes. It stands while the engine does, so whatever the ABI keeps
/// there must not keep the engine past its own drop: the ABI moves its handle out before it lets
/// the handle go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandlePlace {
    base: NonNull<u8>,
    bytes: usize,
}

// SAFETY: a place is an address in the session's arena and its length; the engine never touches
// the bytes, and the ABI that writes them keeps its own rule for who may, so handing the address to
// another thread shares nothing.
unsafe impl Send for HandlePlace {}
// SAFETY: as for `Send`: the place itself is read only as an address.
unsafe impl Sync for HandlePlace {}

impl HandlePlace {
    /// Where the place starts, aligned to [`ARENA_ALIGN`].
    pub fn as_ptr(&self) -> NonNull<u8> {
        self.base
    }

    /// How many bytes it holds: at least the size of the layout the plan was given.
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

/// The places a session's arena lent for the ABI's entities ([`HeldPlaces`]), a table of each kind
/// it holds places of. A place is lent to the ABI by its address and given back by it, each under
/// the session's lock, which every table of the arena is reached under.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EntityPlaces {
    cells: [Option<LentByteCells>; ENTITY_KINDS],
}

impl EntityPlaces {
    /// No place of any kind.
    pub(crate) const NONE: Self = Self {
        cells: [None; ENTITY_KINDS],
    };

    /// The table of `kind`'s places, if the arena holds one.
    fn of(&self, kind: EntityKind) -> Option<LentByteCells> {
        self.cells.get(kind as usize).copied().flatten()
    }

    /// A free place for an entity of `kind`, or `None` when every one is lent or the arena holds
    /// none of the kind. The place is the ABI's until it gives it back ([`Self::give_back`]).
    pub(crate) fn claim(&self, kind: EntityKind) -> Option<EntityPlace> {
        let buffer = self.of(kind)?.claim()?;
        let (base, _) = buffer.raw();
        // The claim is held by the place from here and ended by `give_back`, not by the buffer's
        // drop.
        core::mem::forget(buffer);
        // SAFETY: the cell at `base` was lent for `kind` just now, and this is its one token.
        Some(unsafe { EntityPlace::lent(NonNull::new(base)?, kind) })
    }

    /// Give back `place`, or hand it back when it is no place these tables lent: one of another
    /// session, which only that session takes back.
    pub(crate) fn give_back(&self, place: EntityPlace) -> Result<(), EntityPlace> {
        // SAFETY: the place is consumed, so the claim it held ends here, once; what the ABI kept
        // at its address it let go of before it gave the place up.
        let taken = self
            .of(place.kind())
            .is_some_and(|cells| unsafe { cells.release_at(place.as_ptr()) });
        if taken {
            Ok(())
        } else {
            Err(place)
        }
    }

    /// How many places of `kind` are lent, and how many the arena holds.
    #[cfg(test)]
    pub(crate) fn counts(&self, kind: EntityKind) -> (usize, usize) {
        self.of(kind)
            .map_or((0, 0), |cells| (cells.in_use(), cells.capacity()))
    }
}

/// The places an open claims from its arena for the session's life (`ArenaPlan::claim_handle`).
pub(crate) struct ClaimedPlaces {
    /// The place of the ABI's handle, `None` for a plan with no place.
    pub(crate) handle: Option<HandlePlace>,
}

/// The one buffer of `cells`, a table of one buffer, claimed and never given back:
/// its place and length, `None` for a table lent no buffer.
fn claimed(cells: LentByteCells) -> Option<(NonNull<u8>, usize)> {
    let buffer = cells.claim()?;
    let (base, len) = buffer.raw();
    core::mem::forget(buffer);
    Some((NonNull::new(base)?, len))
}

/// The span of a session's arena its advanced publishers' caches keep their ring in
/// ([`SessionRows::cache_bytes`]): claimed at the open for the session's life, zero as its table
/// was lent, so it holds an empty ring, and lent under the engine's lock of its own
/// (`wz_capi_port::CacheBytes`).
#[cfg(feature = "advanced-cache")]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CacheSpan {
    base: NonNull<u8>,
    len: usize,
}

// SAFETY: a span is an address in a session's arena and its length; its bytes are reached only
// through the engine's lock of the span, so handing the span to another thread shares nothing.
#[cfg(feature = "advanced-cache")]
unsafe impl Send for CacheSpan {}

#[cfg(feature = "advanced-cache")]
impl CacheSpan {
    /// The one buffer of `cells`, a table of one buffer of `bytes`, claimed and never given back.
    /// Its bytes are as the table was lent them, zero (`Arena::lend_byte_cells`), and the open
    /// claims it before anything writes it, so the claim writes none of them and a ring the caches
    /// never fill is never written. Refused as an arena with no room for a table lent no buffer.
    pub(crate) fn claimed(cells: LentByteCells, bytes: usize) -> Result<Self, ArenaRefused> {
        let (base, len) = claimed(cells).ok_or(ArenaRefused::Lend(LendRefused::Exhausted {
            asked: Some(bytes),
            left: 0,
        }))?;
        Ok(Self { base, len })
    }

    /// The span's bytes.
    ///
    /// # Safety
    /// The caller holds the span alone for as long as the bytes are borrowed, and the arena the
    /// span lies in stands that long.
    pub(crate) unsafe fn bytes<'a>(self) -> &'a mut [u8] {
        // SAFETY: the caller's; the span is `len` bytes of the arena.
        unsafe { core::slice::from_raw_parts_mut(self.base.as_ptr(), self.len) }
    }
}

/// A session's arena: the memory its open reserved by its plan, given back when the session is let
/// go.
pub(crate) struct SessionArena {
    arena: Arena,
    base: NonNull<u8>,
    layout: Layout,
    memory: &'static dyn ArenaMemory,
    /// The count the arena's memory is kept by once a value placed in it may outlive the session
    /// (`Self::runtime_place`): the session's, which the drop gives back, and one for each such
    /// value. `None` until then, the memory given back by the drop.
    kept: Option<NonNull<Kept>>,
}

/// Where a session's engine is written at its open ([`SessionArena::engine_place`]): a place of
/// the arena lent to the engine alone, and the count of the arena's memory it takes one of. An
/// engine whose tables take their memory on use lies in an allocation of its own instead.
#[cfg(not(wz_on_use))]
#[derive(Clone, Copy)]
pub(crate) struct EnginePlace {
    pub(crate) at: NonNull<u8>,
    pub(crate) memory: NonNull<Kept>,
}

/// The count a session's arena is kept by, and what its last holder gives back: lent from the arena
/// itself, the count first, so a pointer to the count is a pointer to the whole.
#[repr(C)]
struct ArenaKept {
    kept: Kept,
    base: NonNull<u8>,
    layout: Layout,
    memory: &'static dyn ArenaMemory,
}

/// The last holder of a session's arena let go: its memory goes back to what reserved it.
///
/// # Safety
/// `kept` is the count of an `ArenaKept` `SessionArena::keep` placed, which no holder is left of.
unsafe fn give_arena_back(kept: NonNull<Kept>) {
    let held = kept.cast::<ArenaKept>().as_ptr();
    // SAFETY: the caller's: the count's place is read whole before the memory that holds it goes,
    // and the memory is given back once, here; every value lent from it was dropped first.
    unsafe {
        let (base, layout, memory) = ((*held).base, (*held).layout, (*held).memory);
        memory.release(base, layout);
    }
}

impl SessionArena {
    /// Reserve the arena `plan` lays out from `memory`. Refused, having taken nothing, when the
    /// arena is past the address space or the memory has none to give.
    #[cfg(any(feature = "runtime-plan", feature = "tables-on-use", test))]
    pub(crate) fn reserve<const ROWS: usize>(
        plan: &ArenaPlan<ROWS>,
        memory: &'static dyn ArenaMemory,
    ) -> Result<Self, ArenaRefused> {
        Self::of_bytes(plan.reserved_bytes().ok_or(ArenaRefused::TooLarge)?, memory)
    }

    /// The arena `plan` lays out and, before it, a `T` of all zero bytes, reserved from `memory`
    /// as one block: the region the build lays a session's state out in and the arena of what the
    /// session's open sizes at run time take one reservation, given back whole by the arena's last
    /// holder (`Self::keep`), so the region's owner drops the `T` in place and gives back nothing.
    /// Refused as an arena alone is, having taken nothing.
    #[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
    pub(crate) fn reserve_after<T: ZeroEmpty>(
        plan: &ArenaPlan,
        memory: &'static dyn ArenaMemory,
    ) -> Result<(Self, NonNull<T>), ArenaRefused> {
        let bytes = plan.reserved_bytes().ok_or(ArenaRefused::TooLarge)?;
        let (arena, base) = Self::of_bytes_after(Layout::new::<T>(), bytes, memory)?;
        Ok((arena, base.cast::<T>()))
    }

    /// Reserve an arena of `bytes` from `memory`. Refused, having taken nothing, when the memory has
    /// none to give.
    #[cfg(any(feature = "runtime-plan", feature = "tables-on-use", test))]
    pub(crate) fn of_bytes(
        bytes: usize,
        memory: &'static dyn ArenaMemory,
    ) -> Result<Self, ArenaRefused> {
        Self::of_bytes_after(Layout::new::<()>(), bytes, memory).map(|(arena, _)| arena)
    }

    /// An arena of `bytes` reserved from `memory` after a head of `head`'s layout, every byte of
    /// the head zero, and where the block starts: the head's place. One body for an arena alone
    /// (a head of no bytes) and for one beside a region. A memory that gives its blocks zero
    /// ([`ArenaMemory::reserves_zeroed`]) has its block written by none of this, so its pages
    /// are written only by the rows the session uses; any other has its head written zero and its
    /// arena's tables written as they are lent. Refused, having taken nothing, when the block is
    /// past the address space or the memory has none to give.
    fn of_bytes_after(
        head: Layout,
        bytes: usize,
        memory: &'static dyn ArenaMemory,
    ) -> Result<(Self, NonNull<u8>), ArenaRefused> {
        // At least one span, so the memory is never asked for nothing.
        let (layout, offset) = Layout::from_size_align(bytes.max(ARENA_ALIGN), ARENA_ALIGN)
            .and_then(|tail| head.extend(tail))
            .map_err(|_| ArenaRefused::TooLarge)?;
        let base = memory.reserve(layout).ok_or(ArenaRefused::NoMemory {
            bytes: offset.saturating_add(bytes),
        })?;
        // SAFETY: the memory gave `layout` to this call alone, every byte of it zero where it says
        // so: the head's `head.size()` bytes at its start are inside it, and its arena starts
        // `offset` bytes in, aligned to `ARENA_ALIGN` (`Layout::extend`), at least `bytes` long,
        // used by nothing else until the block is given back (`Drop`, or the last count of
        // `Self::keep`).
        let arena = unsafe {
            let at = NonNull::new_unchecked(base.as_ptr().add(offset));
            if memory.reserves_zeroed() {
                Arena::over_zeroed(at, bytes)
            } else {
                base.as_ptr().write_bytes(0, head.size());
                Arena::over(at, bytes)
            }
        };
        Ok((
            Self {
                arena,
                base,
                layout,
                memory,
                kept: None,
            },
            base,
        ))
    }

    /// The count the arena's memory is kept by, lent from the arena on the first ask: the session
    /// holds one, given back when it lets the arena go, and an engine in an allocation of its own
    /// takes one of its own (`SharedClaim::made_with`).
    pub(crate) fn keep(&mut self) -> Result<NonNull<Kept>, LendRefused> {
        if let Some(kept) = self.kept {
            return Ok(kept);
        }
        let held = ArenaKept {
            kept: Kept::new(give_arena_back),
            base: self.base,
            layout: self.layout,
            memory: self.memory,
        };
        // The count is the arena's own, ended by its last holder and not by an owner: it has
        // nothing to drop.
        let placed = self.arena.place(held)?;
        let kept = NonNull::from(&*placed).cast::<Kept>();
        core::mem::forget(placed);
        self.kept = Some(kept);
        Ok(kept)
    }

    /// The span of `bytes` a session's runtime is placed in ([`ArenaPlan::holding_runtime`]), on
    /// the arena's alignment, and the count that keeps the arena's memory for it: the memory goes
    /// back once the session lets the arena go and the runtime's last holder lets go, whichever
    /// is last. Refused past what the arena has left.
    pub(crate) fn runtime_place(&mut self, bytes: usize) -> Result<RuntimePlace, LendRefused> {
        let (at, memory) = self.kept_span(bytes)?;
        // SAFETY: the span is `bytes` of the arena's memory, lent to the runtime alone, and the
        // memory stands while a count of `memory` is held, which the session holds until it lets
        // the arena go, after the runtime is made.
        Ok(unsafe { RuntimePlace::new(at, bytes, memory) })
    }

    /// The place of `bytes` a session's engine lies in ([`ArenaPlan::holding_engine`]), on the
    /// arena's alignment, and the count that keeps the arena's memory: the engine takes one of
    /// its own when it is written there, so the memory goes back once the engine's last holder
    /// lets go, whichever of them is last. Refused past what the arena has left.
    #[cfg(not(wz_on_use))]
    pub(crate) fn engine_place(&mut self, bytes: usize) -> Result<EnginePlace, LendRefused> {
        let (at, memory) = self.kept_span(bytes)?;
        Ok(EnginePlace { at, memory })
    }

    /// A span of `bytes` of the arena, on its alignment, and the count that keeps the arena's
    /// memory for what is placed there. Refused past what the arena has left. Out of line: the
    /// runtime's place and the engine's are both lent by it, and a copy in each would carry the
    /// placing of the count twice.
    #[inline(never)]
    fn kept_span(&mut self, bytes: usize) -> Result<(NonNull<u8>, NonNull<Kept>), LendRefused> {
        let memory = self.keep()?;
        let at = self.arena.lend_span(Some(bytes))?;
        Ok((at, memory))
    }

    /// The bytes reserved: the plan's.
    pub(crate) fn bytes(&self) -> usize {
        self.arena.bytes()
    }

    /// One lender of the arena's tables ([`TableLender`]): the tables of the plan are lent through
    /// it whole, a table refused leaving the ones after it rowless, and the first refusal is asked
    /// once, after them all.
    pub(crate) fn lender(&mut self) -> TableLender<'_> {
        TableLender::new(&mut self.arena)
    }

    /// The arena, to lend from: by the open, where it lends the arena more than its lender's
    /// tables (a session whose tables take their memory on use lends it none of those), and by
    /// the tests that lend its rows.
    #[cfg(any(not(wz_on_use), test))]
    pub(crate) fn arena_mut(&mut self) -> &mut Arena {
        &mut self.arena
    }

    /// Whether `at` is a byte of the arena's memory.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn holds(&self, at: *const u8) -> bool {
        // The arena is the tail of the block, after a region's head where there is one, and its
        // span at least `ARENA_ALIGN` long (`Self::of_bytes_after`).
        let start =
            self.base.as_ptr() as usize + self.layout.size() - self.bytes().max(ARENA_ALIGN);
        (start..start + self.bytes()).contains(&(at as usize))
    }
}

impl Drop for SessionArena {
    fn drop(&mut self) {
        match self.kept {
            // SAFETY: the session's count, given back once; the memory goes with the last count.
            Some(kept) => unsafe { Kept::release(kept) },
            // SAFETY: `base` is what the memory gave for `layout`, given back here once, and the
            // session that held the arena dropped every table lent from it first.
            None => unsafe { self.memory.release(self.base, self.layout) },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_plan() -> ArenaPlan {
        ArenaPlan::vacant()
    }

    /// The allocator, its reservations written over with a byte that is not zero.
    #[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
    struct Dirty;

    /// The byte [`Dirty`] writes over what it reserves.
    #[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
    const DIRTY: u8 = 0xa5;

    #[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
    impl ArenaMemory for Dirty {
        fn reserve(&self, layout: Layout) -> Option<NonNull<u8>> {
            let base = AllocatorMemory.reserve(layout)?;
            // SAFETY: the allocator gave `layout.size()` bytes at `base` to this call alone.
            unsafe { core::ptr::write_bytes(base.as_ptr(), DIRTY, layout.size()) };
            Some(base)
        }

        unsafe fn release(&self, base: NonNull<u8>, layout: Layout) {
            // SAFETY: the caller's contract: the allocator gave `base` for `layout`.
            unsafe { AllocatorMemory.release(base, layout) }
        }
    }

    /// The byte [`Marked`] and [`Plain`] write over what they reserve.
    const MARK: u8 = 0x5a;

    /// A memory that says its blocks are zero and breaks that on purpose: each is written over
    /// with [`MARK`], so a byte the arena's owner writes after the reservation is a byte that is
    /// no longer the mark. Only the raw bytes of what it gives are read, never a value laid over
    /// them.
    struct Marked;

    impl ArenaMemory for Marked {
        fn reserve(&self, layout: Layout) -> Option<NonNull<u8>> {
            Plain.reserve(layout)
        }

        fn reserves_zeroed(&self) -> bool {
            true
        }

        unsafe fn release(&self, base: NonNull<u8>, layout: Layout) {
            // SAFETY: the caller's contract, handed on to the memory that reserved it.
            unsafe { Plain.release(base, layout) }
        }
    }

    /// [`Marked`]'s blocks from a memory that does not say they are zero, as the allocator's.
    struct Plain;

    impl ArenaMemory for Plain {
        fn reserve(&self, layout: Layout) -> Option<NonNull<u8>> {
            let base = AllocatorMemory.reserve(layout)?;
            // SAFETY: the allocator gave `layout.size()` bytes at `base` to this call alone.
            unsafe { core::ptr::write_bytes(base.as_ptr(), MARK, layout.size()) };
            Some(base)
        }

        unsafe fn release(&self, base: NonNull<u8>, layout: Layout) {
            // SAFETY: the caller's contract: the allocator gave `base` for `layout`.
            unsafe { AllocatorMemory.release(base, layout) }
        }
    }

    /// The bytes of the block `arena` was reserved in.
    fn block_of(arena: &SessionArena) -> &[u8] {
        // SAFETY: the block is the arena's, `layout.size()` bytes from `base`, read while the
        // arena holds it and lends nothing.
        unsafe { core::slice::from_raw_parts(arena.base.as_ptr(), arena.layout.size()) }
    }

    /// Whether every byte of the block `arena` was reserved in is still [`MARK`].
    fn still_marked(arena: &SessionArena) -> bool {
        block_of(arena).iter().all(|byte| *byte == MARK)
    }

    /// The block of a region's head and its arena, from a memory that says its blocks are zero, is
    /// laid out as it lies and written by none of the reservation: every byte is as the memory
    /// gave it. The CONTROL is the same reservation from a memory that does not say so, whose head
    /// is written zero and whose arena after it is not. Turned red by a reservation that writes
    /// the block of a zeroed memory, or by one that leaves the head of any other as it lay.
    #[test]
    fn an_arena_of_zeroed_memory_is_written_by_none_of_its_reservation() {
        let head = Layout::new::<[u8; 41]>();
        let (arena, base) =
            SessionArena::of_bytes_after(head, 256, &Marked).expect("the memory answers");
        assert_eq!(base, arena.base, "the head is the block's start");
        assert!(still_marked(&arena), "the reservation wrote a byte");
        drop(arena);

        let (control, _) =
            SessionArena::of_bytes_after(head, 256, &Plain).expect("the allocator answers");
        let block = block_of(&control);
        assert!(
            block[..head.size()].iter().all(|byte| *byte == 0),
            "CONTROL: the head of a memory not said zero is written zero"
        );
        let arena_start = block.len() - 256_usize.max(ARENA_ALIGN);
        assert!(
            block[arena_start..].iter().all(|byte| *byte == MARK),
            "the reservation wrote the arena of a memory not said zero"
        );
    }

    /// The allocator is not said to give zeroed blocks: a block it hands from memory given back
    /// before is not zero, and its `calloc` would write all of it where the open writes only the
    /// rows that need it. Turned red by `AllocatorMemory` said zeroed.
    #[test]
    fn the_allocator_is_not_said_to_give_zeroed_blocks() {
        assert!(!AllocatorMemory.reserves_zeroed());
        assert!(Marked.reserves_zeroed(), "CONTROL: a memory can say so");
    }

    /// A session's arena over zeroed memory lends its tables of buffers as the block lies: the
    /// lend writes none of their flags or bytes, so a buffer no link claims is never written.
    /// Turned red by the arena made over its block as memory not said to be zero (`Arena::over`),
    /// whose lend writes them.
    #[test]
    fn a_session_arena_lends_its_buffers_without_writing_them() {
        let (mut arena, _) = SessionArena::of_bytes_after(Layout::new::<()>(), 4096, &Marked)
            .expect("the memory answers");
        let mut lend = arena.lender();
        let _cells = lend.byte_cells(1024, 3);
        lend.finish().expect("the arena holds the table");
        assert!(arena.arena.high_water() > 3 * 1024, "the table was lent");
        assert!(still_marked(&arena), "the lend wrote the table");
    }

    /// The caches' span is claimed as its table lent it and written by nothing more: bytes put in
    /// the table's one buffer before the claim are still there after it (a buffer of a fresh table
    /// is lent zero, which the claim then keeps). Turned red by a claim that writes the span over.
    #[cfg(feature = "advanced-cache")]
    #[test]
    fn the_caches_span_is_claimed_as_its_table_lent_it() {
        let mut arena = SessionArena::of_bytes(4096, &AllocatorMemory).expect("the host has it");
        let mut lend = arena.lender();
        let cells = lend.byte_cells(64, 1);
        lend.finish().expect("the arena holds the table");
        {
            let mut buffer = cells.claim().expect("the table's one buffer");
            assert!(buffer.as_mut_slice().iter().all(|b| *b == 0), "lent zero");
            buffer.as_mut_slice().fill(MARK);
        }
        let span = CacheSpan::claimed(cells, 64).expect("the buffer is free again");
        // SAFETY: the span is this test's alone, and the arena it lies in stands past its use.
        let bytes = unsafe { span.bytes() };
        assert_eq!(bytes.len(), 64, "the table's one buffer");
        assert!(bytes.iter().all(|b| *b == MARK), "the claim wrote the span");
    }

    /// A plan lays out `ARENA_ROWS` rows and refuses the one past them, keeping those it holds.
    /// Turned red by a row written past the table, or a plan settled with a row it could not hold.
    #[test]
    fn a_row_past_the_plan_is_refused_and_the_rows_it_holds_stay() {
        let mut plan = empty_plan();
        for _ in 0..ARENA_ROWS {
            plan.put(ArenaPart::EndpointTexts, 1, 8);
        }
        assert_eq!(plan.refused, None);
        plan.put(ArenaPart::KeyArena, 1, 8);
        assert_eq!(plan.rows().count(), ARENA_ROWS);
        assert_eq!(plan.settled(), Err(ArenaRefused::TooLarge));
    }

    /// The bytes a plan reserves, summed as each row is laid out, are the sum of the spans of the
    /// rows it holds, a row it refused adding none, and none past the address space once a row's
    /// span is. A region, which keeps no row, reserves by that sum alone. Turned red by a row whose
    /// span is not added, or one added that the plan refused.
    #[test]
    fn the_bytes_a_plan_reserves_are_the_spans_of_the_rows_it_holds() {
        let summed = |plan: &ArenaPlan| {
            plan.rows()
                .try_fold(0_usize, |sum, row| sum.checked_add(row.span()?))
        };
        let mut plan = empty_plan();
        assert_eq!(plan.reserved_bytes(), Some(0));
        plan.put(ArenaPart::EndpointTexts, 3, 8);
        plan.put(ArenaPart::KeyArena, 1, 1);
        assert_eq!(plan.reserved_bytes(), summed(&plan));
        assert!(plan.reserved_bytes() > Some(24), "both rows are counted");
        for _ in 2..ARENA_ROWS {
            plan.put(ArenaPart::EndpointTexts, 1, 8);
        }
        let full = plan.reserved_bytes();
        assert_eq!(full, summed(&plan));
        plan.put(ArenaPart::KeyArena, 1, 4096);
        assert_eq!(plan.reserved_bytes(), full, "a refused row adds nothing");
        let mut past = empty_plan();
        past.put(ArenaPart::KeyArena, 2, usize::MAX);
        assert_eq!(past.reserved_bytes(), None);
        past.put(ArenaPart::EndpointTexts, 1, 8);
        assert_eq!(
            past.reserved_bytes(),
            None,
            "past the address space stays past it"
        );
    }

    /// The refusal a settled plan answers is the first one met, as it came: a limit over the
    /// build's value under the limit's own name, though a row past the plan and a size past the
    /// address space come after it. Turned red by a later refusal replacing the first, or by a
    /// refusal that loses the limit it names.
    #[test]
    fn a_settled_plan_answers_the_first_refusal_with_its_limit() {
        let mut plan = empty_plan();
        assert_eq!(plan.lent(ArenaLimit::MaxFaces, Quota::at_most(9), 4), 0);
        assert_eq!(plan.sized(None), 0);
        for _ in 0..=ARENA_ROWS {
            plan.put(ArenaPart::EndpointTexts, 1, 8);
        }
        assert_eq!(
            plan.settled(),
            Err(ArenaRefused::Limit {
                limit: ArenaLimit::MaxFaces,
                why: UnlentRows::OverCeiling {
                    value: 9,
                    ceiling: 4,
                },
            })
        );
    }

    /// A kind's place lies at the kind's own index, the first kind's and the last's alike, in a
    /// constant as at run time. Turned red by a place laid at a neighbour's index, or at none.
    #[test]
    fn each_kinds_place_lies_at_its_own_index() {
        const PLACE: Layout = Layout::new::<[u64; 3]>();
        const LAST: HeldPlaces =
            HeldPlaces::NONE.with_entity(EntityKind::LinkEventsListener, PLACE);
        for (at, kind) in EntityKind::ALL.into_iter().enumerate() {
            let held = HeldPlaces::NONE.with_entity(kind, PLACE);
            for (index, place) in held.entities.iter().enumerate() {
                assert_eq!(
                    *place,
                    (index == at).then_some(PLACE),
                    "{kind:?} at {index}"
                );
            }
        }
        assert_eq!(LAST.entities[ENTITY_KINDS - 1], Some(PLACE));
        assert_eq!(LAST.entities[..ENTITY_KINDS - 1], [None; ENTITY_KINDS - 1]);
    }

    /// Each kind's places are laid out under the kind's own part, as many as the rows the session
    /// keeps of that kind and as large as the layout given for it, and a kind's rows are read at
    /// its own index. Turned red by a count read at a neighbour's index, or a kind's places laid
    /// out under another kind's part.
    #[test]
    fn each_kinds_places_take_its_own_rows_and_part() {
        const NAMES: [&str; ENTITY_KINDS] = [
            "publisher places",
            "subscriber places",
            "queryable places",
            "token places",
            "liveliness subscriber places",
            "querier places",
            "pending get places",
            "pending liveliness get places",
            "matching listener places",
            "declaration watch places",
            "transport events listener places",
            "advanced publisher places",
            "advanced subscriber places",
            "link events listener places",
        ];
        let mut plan = empty_plan();
        let mut held = HeldPlaces::NONE;
        for (at, kind) in EntityKind::ALL.into_iter().enumerate() {
            plan.session.entities.kinds[at] = at + 1;
            let place = Layout::from_size_align(8 * (at + 1), 8).expect("a small layout");
            held = held.with_entity(kind, place);
        }
        plan.holding(&held).expect("the places fit");
        for (at, kind) in EntityKind::ALL.into_iter().enumerate() {
            assert_eq!(plan.entities().of_kind(kind), at + 1, "{kind:?}");
            let laid = plan
                .rows()
                .find(|row| row.part() == NAMES[at])
                .map(|row| (row.count, row.entry_bytes));
            assert_eq!(laid, Some((at + 1, 8 * (at + 1))), "{kind:?}");
            assert_eq!(plan.entity_bytes(kind), 8 * (at + 1), "{kind:?}");
        }
    }

    /// The places are laid out and lent for each kind named and for no other, past a run of kinds
    /// with none and up to the last kind, each table as many places as the rows the session keeps
    /// of its kind; a layout past the arena's alignment is refused though kinds with none lie
    /// before it. Turned red by a walk of the kinds that stops at the first kind with no places,
    /// never reaches the last, or lends a kind's table at a neighbour's place.
    #[test]
    fn the_places_of_each_kind_named_are_laid_out_and_lent_past_the_kinds_with_none() {
        const NAMED: [EntityKind; 3] = [
            EntityKind::Publisher,
            EntityKind::Token,
            EntityKind::LinkEventsListener,
        ];
        let place = Layout::new::<[u64; 2]>();
        let mut plan = empty_plan();
        for (at, rows) in plan.session.entities.kinds.iter_mut().enumerate() {
            *rows = at + 2;
        }
        let held = NAMED
            .into_iter()
            .fold(HeldPlaces::NONE, |held, kind| held.with_entity(kind, place));
        plan.holding(&held).expect("the places fit");
        // With the connectivity plane the engine lodges a watcher of the faces' snapshots for each
        // transport events listener the session keeps, so its lodging places are laid out though
        // the ABI named none (`NO_LODGINGS`).
        #[cfg(feature = "connectivity")]
        const LODGED: &[&str] = &["lodging places"];
        #[cfg(not(feature = "connectivity"))]
        const LODGED: &[&str] = &[];
        let parts: alloc::vec::Vec<_> = plan.rows().map(ArenaRow::part).collect();
        let named = [
            "publisher place flags",
            "publisher places",
            "token place flags",
            "token places",
            "link events listener place flags",
            "link events listener places",
        ];
        let want: alloc::vec::Vec<&str> = named.iter().chain(LODGED).copied().collect();
        assert_eq!(parts, want);
        #[cfg(feature = "connectivity")]
        assert_eq!(
            plan.rows()
                .find(|row| row.part() == "lodging places")
                .map(|row| row.count),
            Some(plan.entities().of_kind(EntityKind::TransportEventsListener)),
            "a lodging place for each transport events listener"
        );
        let mut arena = SessionArena::reserve(&plan, &AllocatorMemory).expect("an arena");
        let mut lend = arena.lender();
        let places = plan.places().lent_from(&mut lend, plan.entities());
        assert!(places.handle.is_none());
        for (at, kind) in EntityKind::ALL.into_iter().enumerate() {
            let lent = if NAMED.contains(&kind) { at + 2 } else { 0 };
            assert_eq!(places.entities.counts(kind), (0, lent), "{kind:?}");
        }

        let wide = Layout::from_size_align(ARENA_ALIGN * 2, ARENA_ALIGN * 2).expect("a layout");
        let mut plan = empty_plan();
        plan.session.entities.kinds[0] = 1;
        let held = HeldPlaces::NONE
            .with_entity(EntityKind::Publisher, place)
            .with_entity(EntityKind::AdvancedSubscriber, wide);
        assert_eq!(plan.holding(&held), Err(ArenaRefused::TooLarge));
    }

    /// The ABI's handle is laid out on the plan where the plan lies, once: its flag before its
    /// place, and a second ask of the same place adds no row. Turned red by a place laid out
    /// again, or a plan the ask leaves without the place it laid.
    #[test]
    fn a_plan_lays_out_the_handle_it_holds_once_where_it_lies() {
        let mut plan = empty_plan();
        let place = Layout::new::<[u64; 3]>();
        plan.holding(&HeldPlaces::handle(place))
            .expect("the handle fits");
        plan.holding(&HeldPlaces::handle(place))
            .expect("held already");
        let parts: alloc::vec::Vec<_> = plan.rows().map(ArenaRow::part).collect();
        assert_eq!(parts, ["session handle flag", "session handle"]);
        assert_eq!(plan.handle_bytes(), place.size());
    }

    /// A plan lays out each table of cells once, its flags before its cells, in the order of
    /// `LinkCells::into_array`, and none for a size of `0`. Turned red by a table laid out twice,
    /// or the gate's table laid out before the driver's.
    #[test]
    fn a_plan_lays_out_each_table_of_cells_once_in_order() {
        let mut plan = empty_plan();
        plan.transport.links = 3;
        let asked = LinkCells {
            driver: 40,
            gate: 0,
            actions: 24,
            halves: 56,
        };
        plan.holding_cells(asked).expect("the cells fit");
        plan.holding_cells(asked).expect("held already");
        let parts: alloc::vec::Vec<_> = plan.rows().map(ArenaRow::part).collect();
        assert_eq!(
            parts,
            [
                "link cell flags",
                "link cells",
                "link actions flags",
                "link actions",
                "link halves flags",
                "link halves"
            ]
        );
        assert_eq!(plan.rows().nth(1).map(|row| row.entry_bytes), Some(40));
        assert_eq!(plan.rows().nth(3).map(|row| row.count), Some(3));
        assert_eq!(plan.rows().nth(5).map(|row| row.entry_bytes), Some(56));
        assert_eq!(plan.rows().nth(5).map(|row| row.count), Some(3));
    }

    /// The tables of cells are lent for each kind of cell the plan holds and for no other, past a
    /// kind with none and up to the last, a cell of its size for each link. Turned red by a walk
    /// of the kinds that stops at the first with none, or never reaches the halves'.
    #[test]
    fn the_cells_of_each_kind_held_are_lent_past_the_kinds_with_none() {
        let mut plan = empty_plan();
        plan.transport.links = 3;
        let asked = LinkCells {
            driver: 0,
            gate: 48,
            actions: 0,
            halves: 64,
        };
        plan.holding_cells(asked).expect("the cells fit");
        let mut arena = SessionArena::reserve(&plan, &AllocatorMemory).expect("an arena");
        let mut lend = arena.lender();
        let lent = plan.transport().cells_from(&mut lend).into_array();
        let held: alloc::vec::Vec<_> = lent
            .iter()
            .map(|cells| cells.as_ref().map(|cells| (cells.size(), cells.capacity())))
            .collect();
        assert_eq!(held, [None, Some((48, 3)), None, Some((64, 3))]);
    }

    /// A mask walks the places set in it once each, the lowest first, the first bit and the last
    /// alike, and none of an empty mask; a place past its bits adds none. Turned red by a walk
    /// that skips a place, hands one out twice, or ends before the last bit.
    #[test]
    fn a_mask_walks_each_place_set_in_it_once_in_order() {
        let held = HeldBits::default()
            .with(0)
            .with(5)
            .with(31)
            .with(5)
            .with(32);
        let walked: alloc::vec::Vec<_> = held.places().collect();
        assert_eq!(walked, [0, 5, 31]);
        assert_eq!(HeldBits::default().places().next(), None);
        assert_eq!(HeldBits::default().with(usize::MAX), HeldBits::default());
    }

    /// A plan reads the rows it laid out and none past them, in order, and two plans that laid
    /// out the same rows are equal. Turned red by a row read before it is put, or rows past the
    /// ones put read as rows.
    #[test]
    fn a_plan_reads_the_rows_it_put_and_none_past_them() {
        let mut plan = empty_plan();
        assert_eq!(plan.rows().count(), 0);
        plan.put(ArenaPart::EndpointTexts, 1, 8);
        plan.put(ArenaPart::DeliveryRecords, 2, 16);
        let parts: alloc::vec::Vec<_> = plan.rows().map(|row| (row.part(), row.count)).collect();
        assert_eq!(parts, [("endpoint texts", 1), ("delivery records", 2)]);
        assert_eq!(
            plan.reserved_bytes(),
            plan.rows()
                .try_fold(0usize, |sum, row| sum.checked_add(row.span()?))
        );
        let mut same = empty_plan();
        same.put(ArenaPart::EndpointTexts, 1, 8);
        same.put(ArenaPart::DeliveryRecords, 2, 16);
        assert_eq!(plan, same);
        same.put(ArenaPart::DeliveryKeys, 1, 8);
        assert_ne!(plan, same);
    }

    /// Two plans of the same rows differ when one kept a refusal the other did not: a plan's
    /// equality reads every part of it, not its rows alone. Turned red by an equality of the rows
    /// alone.
    #[test]
    fn plans_of_the_same_rows_differ_by_their_refusal() {
        let mut plan = empty_plan();
        plan.put(ArenaPart::EndpointTexts, 1, 8);
        let mut refused = empty_plan();
        refused.put(ArenaPart::EndpointTexts, 1, 8);
        assert_eq!(plan, refused);
        refused.refuse(ArenaRefused::TooLarge);
        assert_ne!(plan, refused);
    }

    /// A limit's name is its id as the build states it, the variant's own name in the build's
    /// case, and no two limits share one: a refusal names the limit it was refused by. Turned red
    /// by an arm that names another limit or misspells one.
    #[test]
    fn each_limit_names_its_own_id() {
        use ArenaLimit::*;
        let all = [
            MaxFaces,
            MaxStaticConnect,
            MaxAdminLocators,
            MaxAcceptPending,
            PicoFragMaxBytes,
            DeliveryLaneEvents,
            DeliveryLaneCallbacks,
            MaxKeyexprBytes,
            KeyArenaBytes,
            UdpPortSlots,
            HandedLegBytes,
            MaxDeclObservers,
            MaxPendingQueries,
            MaxPendingLivelinessGets,
            MaxPendingReplies,
            MaxPendingFinals,
            AdvancedCacheBytes,
            PicoUnicastBatchBytes,
            MaxSubscriptions,
            MaxQueryables,
            MaxLocalTokens,
            MaxLivelinessSubscriptions,
            MaxDeclaredKeyexprs,
            MaxPublishers,
            MaxQueriers,
            MaxMatchingListeners,
            MaxDeclWatches,
            MaxTransportEventsListeners,
            MaxAdvancedPublishers,
            MaxAdvancedSubscribers,
            MaxLinkEventsListeners,
            MaxPeerKeyexprAliases,
            SessionMaxPeerKeyexprAliases,
            MaxRemoteDecls,
            SessionMaxRemoteDecls,
            MaxInboundSubInterests,
            SessionMaxInboundSubInterests,
            MaxReplyPayloadBytes,
            MaxPendingDeclares,
            RxPoolBuffers,
            TxPoolSlots,
            ReassemblyChains,
            LimitsDifferFromBuild,
            ShapeDiffersFromBuild,
        ];
        let mut names = alloc::vec::Vec::new();
        for limit in all {
            let mut id = alloc::string::String::new();
            for (at, c) in alloc::format!("{limit:?}").char_indices() {
                if at > 0 && c.is_ascii_uppercase() {
                    id.push('_');
                }
                id.push(c.to_ascii_uppercase());
            }
            assert_eq!(limit.name(), id);
            names.push(limit.name());
        }
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), all.len(), "two limits share a name");
    }

    /// What `a_region_and_its_arena_are_one_reservation_given_back_whole` reserves from: the
    /// allocator, its reservations written over as [`Dirty`]'s are, counting what it gives and
    /// what it is given back.
    #[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
    struct OneBlock {
        reserves: core::sync::atomic::AtomicUsize,
        reserved: core::sync::atomic::AtomicUsize,
        releases: core::sync::atomic::AtomicUsize,
        released: core::sync::atomic::AtomicUsize,
    }

    #[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
    impl ArenaMemory for OneBlock {
        fn reserve(&self, layout: Layout) -> Option<NonNull<u8>> {
            let base = Dirty.reserve(layout)?;
            self.reserves
                .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
            self.reserved
                .fetch_add(layout.size(), core::sync::atomic::Ordering::SeqCst);
            Some(base)
        }

        unsafe fn release(&self, base: NonNull<u8>, layout: Layout) {
            self.releases
                .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
            self.released
                .fetch_add(layout.size(), core::sync::atomic::Ordering::SeqCst);
            // SAFETY: the caller's contract, handed on to the memory that reserved it.
            unsafe { Dirty.release(base, layout) }
        }
    }

    /// A region and the arena after it are one reservation from a memory whose reservations are
    /// not zero: the region at the block's start, every byte of it zero, the arena after it of the
    /// plan's bytes, and the block given back once, whole, when the arena is let go. Turned red by
    /// a region reserved apart from its arena, by a head left as the memory wrote it, or by a
    /// release of a layout other than the one reserved.
    #[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
    #[test]
    fn a_region_and_its_arena_are_one_reservation_given_back_whole() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        static BLOCK: OneBlock = OneBlock {
            reserves: AtomicUsize::new(0),
            reserved: AtomicUsize::new(0),
            releases: AtomicUsize::new(0),
            released: AtomicUsize::new(0),
        };
        /// A head of an odd length, so the arena after it starts past a pad.
        struct Head([u8; 41]);
        // SAFETY: a head of zero bytes is one of zeros, which holds nothing to drop.
        unsafe impl ZeroEmpty for Head {}

        let control = Layout::new::<Head>();
        let base = Dirty.reserve(control).expect("the allocator answers");
        // SAFETY: the memory gave `control.size()` bytes at `base`, read once and given back.
        let dirty = unsafe {
            let read = core::slice::from_raw_parts(base.as_ptr(), control.size())
                .iter()
                .all(|byte| *byte == DIRTY);
            Dirty.release(base, control);
            read
        };
        assert!(dirty, "CONTROL: the memory's own reservation is not zero");

        let mut plan = ArenaPlan::vacant();
        plan.holding_runtime(64).expect("the span fits");
        let bytes = plan.reserved_bytes().expect("within the address space");
        let (arena, head) =
            SessionArena::reserve_after::<Head>(&plan, &BLOCK).expect("the host has it");
        // SAFETY: the head is the block's first bytes, which nothing else reaches.
        let zeroed = unsafe { head.as_ref() }.0.iter().all(|byte| *byte == 0);
        assert!(zeroed, "the region is zero in every byte");
        assert_eq!(arena.bytes(), bytes, "the arena holds the plan's bytes");
        let reserved = BLOCK.reserved.load(Ordering::SeqCst);
        assert!(
            reserved >= Arena::span(core::mem::size_of::<Head>()).expect("a small span") + bytes,
            "the arena lies after the region, aligned"
        );
        assert_eq!(BLOCK.reserves.load(Ordering::SeqCst), 1, "one reservation");
        drop(arena);
        assert_eq!(BLOCK.releases.load(Ordering::SeqCst), 1, "given back once");
        assert_eq!(BLOCK.released.load(Ordering::SeqCst), reserved, "whole");
    }

    /// What the arena of `an_arena_a_runtime_is_placed_in_goes_back_after_its_last_holder` is
    /// reserved from: the allocator, counting what it is given back.
    struct CountedReleases;

    static RELEASES: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

    impl ArenaMemory for CountedReleases {
        fn reserve(&self, layout: Layout) -> Option<NonNull<u8>> {
            AllocatorMemory.reserve(layout)
        }

        unsafe fn release(&self, base: NonNull<u8>, layout: Layout) {
            RELEASES.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
            // SAFETY: the caller's contract, handed on to the allocator that reserved it.
            unsafe { AllocatorMemory.release(base, layout) }
        }
    }

    /// A clock that does not move.
    struct Still;

    impl wz_runtime_coop::ClockSource for Still {
        fn now_us(&self) -> u64 {
            0
        }
    }

    /// A plan holds the runtime's span and the arena's count once, and an arena a runtime is placed
    /// in is given back once, after both the session and the runtime's last holder let go: the
    /// session letting go first gives nothing back. Turned red by a session that gives the arena
    /// back while the runtime still lies in it, by a runtime that never gives its count back, or by
    /// a plan that lays the rows out twice.
    #[test]
    fn an_arena_a_runtime_is_placed_in_goes_back_after_its_last_holder() {
        use wz_runtime_coop::{CoopRuntime, RuntimeForm, RuntimeRows};
        let rows = RuntimeRows {
            tasks: 2,
            task_bytes: 64,
            timers: 0,
        };
        let bytes = CoopRuntime::<Still>::placed_layout(rows, RuntimeForm::Reserved)
            .expect("a span of these rows")
            .size();
        let mut plan = ArenaPlan::vacant();
        plan.holding_runtime(bytes).expect("the span fits");
        plan.holding_runtime(bytes).expect("held already");
        assert_eq!(plan.rows().count(), 2, "the count and the span, once");
        let mut arena = SessionArena::reserve(&plan, &CountedReleases).expect("the host has it");
        let place = arena.runtime_place(bytes).expect("the plan holds the span");
        let (runtime, local) =
            CoopRuntime::placed(Still, rows, RuntimeForm::Reserved, place).expect("the span fits");
        let before = RELEASES.load(core::sync::atomic::Ordering::SeqCst);
        drop(arena);
        assert_eq!(
            RELEASES.load(core::sync::atomic::Ordering::SeqCst),
            before,
            "the runtime keeps the arena"
        );
        drop(runtime);
        assert_eq!(
            RELEASES.load(core::sync::atomic::Ordering::SeqCst),
            before,
            "the local set's owner, placed in it, keeps the arena too"
        );
        drop(local);
        assert_eq!(
            RELEASES.load(core::sync::atomic::Ordering::SeqCst),
            before + 1,
            "its last holder gives it back, once"
        );
    }
}
