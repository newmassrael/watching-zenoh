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
//!   queryables and tokens and the repeats of them (`SESSION_MAX_REMOTE_DECLS`) and its subscriber
//!   interests (`SESSION_MAX_INBOUND_SUB_INTERESTS`), each the fewer of the session's value of its
//!   limit and what the faces could hold at the bound of each peer (`MAX_PEER_KEYEXPR_ALIASES`,
//!   `MAX_REMOTE_DECLS`, `MAX_INBOUND_SUB_INTERESTS`), each row the place of its key in the key
//!   arena below. A face holds the rows its peer wrote and not the most it could, as zenoh-pico
//!   takes each from its heap as it comes. A session of one face shares with no one: its tables
//!   take spans of their own of that face's bounds instead, laid out as inline tables are, with no
//!   link and no pool state;
//! - the buffers of the links the session may hold: a pool of receive buffers of the batch the
//!   session advertises, a streamed batch's length counted inside it, as many as
//!   `RX_POOL_BUFFERS` and no more than the links, which a link holds only while it holds part of
//!   a batch or something it was asked to keep; a pool of slots of that length to encode frames
//!   into, as many as `TX_POOL_SLOTS` and no more than the links, of which a link holds
//!   [`LINK_TX_SLOTS`] at a time from its grant to its send; and a place for each link; each table
//!   with the flags that say which buffers are lent (`TransportRows::links_from`). The batch is
//!   the config's, held to the session's `PICO_UNICAST_BATCH_BYTES` under the build's; these are
//!   the rows lent when the session opens, first;
//! - the session's delivery lane (`DELIVERY_LANE_BYTES`, under the build's), the bytes of what
//!   it hands its subscribers' callbacks after its lock (`crate::round`), lent first of the
//!   state's tables (`SessionRows::lane_bytes`);
//! - the buffers the links of the session stage the chains of their fragmented messages in, one
//!   table for the session (`SESSION_CHAIN_BUFFERS` of `wz_runtime_coop::reassembly_rx`: one for
//!   each reliability a peer has a chain open in, and one for the rejoined message the round
//!   reads where its chain lay), each buffer claimed when a chain's first fragment arrives and
//!   given back when the chain ends or the round lets its message go, each as long as the largest message the session
//!   rejoins (`PICO_FRAG_MAX_BYTES`, under the build's, which a chain past it is ended at, as pico
//!   ends one), with the flags that say which are lent (`TransportRows::lent_from`), lent
//!   with the links' tables;
//! - the engine's own record of each declaration it announces and announces again over a new
//!   link ([`EntityRows`]): the key expressions it declares
//!   (`MAX_DECLARED_KEYEXPRS`), the write filters of its publishers (`MAX_PUBLISHERS`) and
//!   queriers (`MAX_QUERIERS`), its matching listeners (`MAX_MATCHING_LISTENERS`), and the
//!   Interests those filters and listeners hold open, at most one for each of them;
//! - the key arena every keyed row of the session keeps its key in (`KEY_ARENA_BYTES`, under the
//!   build's): that record's, the application's tables', each face's pending gets' and what each
//!   face's peer declares and asks, one area of blocks a key takes as long as it is held
//!   ([`KeySpace`](wz_session_core::key_arena::KeySpace)), lent after the record and before the
//!   tables that keep their keys in it. A peer's key that finds no room there is dropped and
//!   counted, as zenoh-pico drops a declaration its heap cannot hold;
//! - with [`ArenaPlan::holding`], last, the place the ABI keeps its own handle of the session in,
//!   and the places it keeps its objects of the session's entities in, one for each row the
//!   session keeps of each kind it names ([`HeldPlaces`]), so what the ABI holds of a session is
//!   reserved with the session, sized by the session's own limits, and takes no memory of its own.
//!
//! A table's entry is the registry's own `ROW_BYTES` as the lent policy lays the row out
//! ([`Lent`]), and its count the value of its limit the open resolved, under the build's value
//! ([`Quota::lent_under`]): a stage after the build chooses within the memory the build fixes and
//! never adds to it, so a value over the build's refuses the open.
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
//! An [`ArenaMemory`]: on a host the allocator, asked once for the whole arena, whose answer of
//! none refuses the open rather than ending the process ([`AllocatorMemory`], as the ABI's object
//! pools reserve theirs); a region an image places is another implementation of it.

use core::alloc::Layout;
use core::ptr::NonNull;

use wz_runtime_coop::faces::EndpointTexts;
use wz_runtime_coop::link_storage::LinkTables;
use wz_runtime_coop::reassembly_rx::SESSION_CHAIN_BUFFERS;
use wz_session_core::bounded::{Arena, LendRefused, Lent, TableLender, ARENA_ALIGN};
use wz_session_core::byte_cells::LentByteCells;
use wz_session_core::caps;
use wz_session_core::key_arena::KeySpace;
use wz_session_core::limit_binding::{Quota, UnlentRows};
use wz_session_core::limits::SessionLimits;
use wz_session_core::locator_directory::LocatorText;
use wz_session_core::peer_tables::{PeerPoolRows, PeerRows, PeerTables, SHARES_ROWS};
#[cfg(feature = "query")]
use wz_session_core::reply_sink::ConsolidatingSink;
use wz_session_core::row_pool::MAX_POOL_ROWS;
use wz_session_core::session_tables::TableRows;
#[cfg(feature = "query")]
use wz_session_core::slot_observer::Requesters;
use wz_session_core::slot_observer::{HeapSinks, RequesterRows, SlotObserverOf};

#[cfg(feature = "query")]
use crate::engine::LegSink;
use crate::engine::{CoopTables, EntryBytes, FACE_SET_BYTES, HELD_SET_BYTES};
use crate::open_source::EndpointList;
use crate::round::{RoundRowCounts, CALLBACK_BYTES, RECORD_BYTES};
use crate::CoopConfig;

/// One part of what an arena holds: `count` items of `entry_bytes` each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaRow {
    /// What holds the bytes.
    pub part: &'static str,
    /// The limit whose number sizes the row.
    pub basis: &'static str,
    /// How many items the row counts.
    pub count: usize,
    /// The bytes of one item.
    pub entry_bytes: usize,
}

impl ArenaRow {
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

// The rows of a plan, group by group, each counted where the group's rows are put and under the
// same features: a group that gains or loses a row changes its own count, and the plan's length
// follows ([`ARENA_ROWS`]).

/// The texts of the endpoints the session dials and listens on: one row of both tables.
const ENDPOINT_ROWS: usize = 1;
/// The links' receive flags and buffers and transmit flags and slots, and with `listen` their
/// places.
const LINK_ROWS: usize = 4 + cfg!(feature = "listen") as usize;
/// The delivery lane's flag and its area, and the round's records, the callbacks they owe and
/// its keys.
const LANE_ROWS: usize = 5;
/// The reassembly buffers' flags and the buffers.
const REASSEMBLY_ROWS: usize = 2;
/// The application's tables apart from the session's one table set: liveliness tokens
/// (`liveliness`), and the declaration watchers.
const OBSERVER_ROWS: usize = cfg!(feature = "liveliness") as usize + 1;
/// The pending gets and the ends of their legs, both of a build that asks (`query`): one that asks
/// nothing holds no table of gets.
const GET_ROWS: usize = 2 * cfg!(feature = "query") as usize;
/// The faces' sets and the index of the held ones.
const FACE_ROWS: usize = 2;
/// The peers' tables, and the pools their rows lie in where the faces share them.
const PEER_ROWS: usize = 1 + 3 * SHARES_ROWS as usize;
/// The tokens the faces that went still owe (`liveliness` with `listen` or `group`): put only for a
/// session whose faces share their pools, so counted where a build shares them at all.
const OWED_ROWS: usize = (cfg!(all(
    feature = "liveliness",
    any(feature = "listen", feature = "group")
)) && SHARES_ROWS) as usize;
/// The engine's record of the session's declarations ([`ArenaPlan::put_entities`]): the session's
/// one table set, write filters, matching listeners, interests and the key arena.
const ENTITY_ROWS: usize = 5;
/// The links' cells, their gates' and their sessions' actions', each a table of flags and cells
/// ([`ArenaPlan::holding_cells`]).
const CELL_ROWS: usize = 6;
/// The ABI's handle's flag and place ([`ArenaPlan::holding`]).
const HANDLE_ROWS: usize = 2;
/// The flags and the places the ABI keeps its objects of the session's entities in, of each kind
/// the session keeps rows of ([`ArenaPlan::holding`]): publishers, subscribers and queriers, and
/// queryables (`queryable`), tokens and liveliness subscribers (`liveliness`), as many as the ABI
/// asks places of, at most these.
const ENTITY_PLACE_ROWS: usize =
    2 * (3 + cfg!(feature = "queryable") as usize + 2 * cfg!(feature = "liveliness") as usize);

/// The most rows a plan holds: every row of the build, the cells', the ABI's handle's and its
/// entities' places among them, the sum of the groups' counts.
pub const ARENA_ROWS: usize = ENDPOINT_ROWS
    + LINK_ROWS
    + LANE_ROWS
    + REASSEMBLY_ROWS
    + OBSERVER_ROWS
    + GET_ROWS
    + FACE_ROWS
    + PEER_ROWS
    + OWED_ROWS
    + ENTITY_ROWS
    + CELL_ROWS
    + HANDLE_ROWS
    + ENTITY_PLACE_ROWS
    + CACHE_ROW_ROWS;

/// The flags and the rows of the samples the advanced publishers' caches keep
/// ([`HeldPlaces::with_cache_rows`]), in a build that lays them out.
const CACHE_ROW_ROWS: usize = 2 * cfg!(feature = "cache-rows") as usize;

pub use wz_capi_port::{EntityKind, EntityPlace, ENTITY_KINDS};

/// The two rows of `kind`'s places, the flags and the places, and the limit that counts them, as
/// the plan names them.
const fn place_rows(kind: EntityKind) -> (&'static str, &'static str, &'static str) {
    match kind {
        EntityKind::Publisher => (
            "publisher place flags",
            "publisher places",
            "MAX_PUBLISHERS",
        ),
        EntityKind::Subscriber => (
            "subscriber place flags",
            "subscriber places",
            "MAX_SUBSCRIPTIONS",
        ),
        EntityKind::Queryable => (
            "queryable place flags",
            "queryable places",
            "MAX_QUERYABLES",
        ),
        EntityKind::Token => ("token place flags", "token places", "MAX_LOCAL_TOKENS"),
        EntityKind::LivelinessSubscriber => (
            "liveliness subscriber place flags",
            "liveliness subscriber places",
            "MAX_LIVELINESS_SUBSCRIPTIONS",
        ),
        EntityKind::Querier => ("querier place flags", "querier places", "MAX_QUERIERS"),
    }
}

/// What an ABI keeps of its own in a session's arena, laid out after every table of the session
/// ([`ArenaPlan::holding`]): a place for its handle of the session, and for each kind of entity it
/// names, a place of that layout for each row the session keeps of the kind. What it holds there is
/// reserved with the session and takes no memory of its own, and an open whose arena cannot hold it
/// opens nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeldPlaces {
    handle: Option<Layout>,
    entities: [Option<Layout>; ENTITY_KINDS],
    /// The layout of a row of the advanced publishers' caches, none for no row.
    #[cfg(feature = "cache-rows")]
    cache_rows: Option<Layout>,
}

impl HeldPlaces {
    /// No place at all.
    pub const NONE: Self = Self {
        handle: None,
        entities: [None; ENTITY_KINDS],
        #[cfg(feature = "cache-rows")]
        cache_rows: None,
    };

    /// A place of `layout` for the ABI's handle of the session, and none for its entities.
    pub const fn handle(layout: Layout) -> Self {
        Self {
            handle: Some(layout),
            entities: [None; ENTITY_KINDS],
            #[cfg(feature = "cache-rows")]
            cache_rows: None,
        }
    }

    /// These places, with a place of `layout` for each row the session keeps of `kind`.
    pub fn with_entity(mut self, kind: EntityKind, layout: Layout) -> Self {
        if let Some(place) = self.entities.get_mut(kind as usize) {
            *place = Some(layout);
        }
        self
    }

    /// These places, with a row of `layout` for each sample the session's advanced publishers'
    /// caches keep together (`ADVANCED_CACHE_ROWS`).
    #[cfg(feature = "cache-rows")]
    pub fn with_cache_rows(mut self, layout: Layout) -> Self {
        self.cache_rows = Some(layout);
        self
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

/// A row of a plan that has none yet.
const NO_ROW: ArenaRow = ArenaRow {
    part: "",
    basis: "",
    count: 0,
    entry_bytes: 0,
};

/// Why a session's open reserved no arena, and so bound, joined and dialled nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArenaRefused {
    /// A limit the arena is sized by gives no length under the build's value: it is over it, or
    /// the build states none.
    Limit {
        /// The limit's id.
        limit: &'static str,
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
    /// The subscribers (`MAX_SUBSCRIPTIONS`).
    pub subscribers: usize,
    /// The queryables (`MAX_QUERYABLES`); none in a build without `queryable`.
    pub queryables: usize,
    /// The liveliness tokens (`MAX_LOCAL_TOKENS`); none in a build without `liveliness`.
    pub tokens: usize,
    /// The liveliness subscribers (`MAX_LIVELINESS_SUBSCRIPTIONS`); none in a build without
    /// `liveliness`.
    pub liveliness_subscribers: usize,
    /// The key expressions declared (`MAX_DECLARED_KEYEXPRS`).
    pub keyexprs: usize,
    /// The publishers' write filters (`MAX_PUBLISHERS`).
    pub publishers: usize,
    /// The queriers' write filters (`MAX_QUERIERS`).
    pub queriers: usize,
    /// The matching listeners (`MAX_MATCHING_LISTENERS`).
    pub matching_listeners: usize,
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
    /// How many gets every table together holds pending at once: the rows of the table of the ends
    /// of the legs (`crate::engine`'s `EndedLegs`). `None` past the address space.
    pub const fn legs(&self) -> Option<usize> {
        match self.rows.queries.checked_add(self.rows.liveliness_gets) {
            Some(each) => each.checked_mul(self.tables),
            None => None,
        }
    }
}

/// One face's table of pending gets, as the arena lends it. A build that asks no query keeps none
/// (`engine::registry::Gets`) and lays out none.
#[cfg(feature = "query")]
type FaceGets = Requesters<ConsolidatingSink<LegSink>, LegSink, Lent>;

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
        let sets = if self.dial {
            self.tables
        } else {
            self.tables.saturating_add(1)
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
    /// The rows the engine keeps of `kind`, each of which an ABI's place of the kind is for.
    pub const fn of_kind(&self, kind: EntityKind) -> usize {
        match kind {
            EntityKind::Publisher => self.publishers,
            EntityKind::Subscriber => self.subscribers,
            EntityKind::Queryable => self.queryables,
            EntityKind::Token => self.tokens,
            EntityKind::LivelinessSubscriber => self.liveliness_subscribers,
            EntityKind::Querier => self.queriers,
        }
    }

    /// The rows of the write filters' one table: a publisher's and a querier's each.
    pub const fn filters(&self) -> Option<usize> {
        self.publishers.checked_add(self.queriers)
    }

    /// The rows of the Interests the session holds open: a write filter or a matching listener
    /// opens at most one, and one that finds its key already asked opens none.
    pub const fn interests(&self) -> Option<usize> {
        match self.filters() {
            Some(filters) => filters.checked_add(self.matching_listeners),
            None => None,
        }
    }
}

/// One of each table of a cell for each link: the link's driver's, its gates' and its session's
/// actions'. A plan holds each table's cell bytes ([`ArenaPlan::holding_cells`]); an open, the
/// tables the session's arena lends it (`TransportRows::lent_from`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkCells<T> {
    /// The cells of the stack's drivers of the links.
    pub driver: T,
    /// The cells of the gates each link's pump runs behind.
    pub gate: T,
    /// The cells of the bundle of each link's session actions.
    pub actions: T,
}

impl<T> LinkCells<T> {
    /// The three in the order their tables are laid out and lent: the driver's, the gate's, the
    /// actions'.
    pub fn into_array(self) -> [T; 3] {
        [self.driver, self.gate, self.actions]
    }

    /// The three from [`Self::into_array`]'s order.
    pub fn from_array([driver, gate, actions]: [T; 3]) -> Self {
        Self {
            driver,
            gate,
            actions,
        }
    }
}

/// The names of the two rows of each table of [`LinkCells`], in [`LinkCells::into_array`]'s
/// order: its flags, then its cells.
const CELL_ROWS_NAMED: [[&str; 2]; 3] = [
    ["link cell flags", "link cells"],
    ["link gate flags", "link gates"],
    ["link actions flags", "link actions"],
];

/// The limits a table of a cell for each link is sized by.
const CELL_BASIS: &str = "MAX_FACES + MAX_ACCEPT_PENDING";

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
    /// How many such buffers, in the one table the session's links share.
    reassembly_chains: usize,
    /// The rows of the texts of the endpoints the session dials, and of those it listens on.
    endpoint_rows: (usize, usize),
    /// The bytes of the cell each link's driver, its gates and its actions are placed in, none
    /// for a table the plan does not hold ([`ArenaPlan::holding_cells`]).
    cell_bytes: LinkCells<usize>,
}

/// The tables a session's transport is lent ([`TransportRows::lent_from`]).
pub(crate) struct TransportTables {
    /// The links' buffers and, where the links share pools, their places.
    pub(crate) links: LinkTables,
    /// The cells of the links' drivers, their gates and their actions, each `None` for a plan
    /// with no such table.
    pub(crate) cells: LinkCells<Option<LentByteCells>>,
    /// The reassembly buffers the links share.
    pub(crate) reassembly: LentByteCells,
    /// The rows of the endpoints' texts, none written.
    pub(crate) endpoints: EndpointTexts,
}

impl TransportRows {
    /// The transport's tables, lent by `lend` in the order the plan laid them out.
    pub(crate) fn lent_from(&self, lend: &mut TableLender<'_>) -> TransportTables {
        let links = self.links_from(lend);
        let mut cells = [None, None, None];
        for (bytes, lent) in self.cell_bytes.into_array().into_iter().zip(&mut cells) {
            if bytes != 0 {
                *lent = Some(lend.byte_cells(bytes, self.links));
            }
        }
        // A chain's buffer is claimed when its first fragment arrives and given back when it
        // ends; the session holds the table for its life.
        let reassembly = lend.byte_cells(self.reassembly_bytes, self.reassembly_chains);
        let (dials, listens) = self.endpoint_rows;
        let endpoints = EndpointTexts::over(lend.table(dials), lend.table(listens));
        TransportTables {
            links,
            cells: LinkCells::from_array(cells),
            reassembly,
            endpoints,
        }
    }

    /// The tables of the links' buffers, lent by `lend`: the pool of receive buffers the links
    /// share, each held by a link only while it holds something of its own in it, the pool of
    /// outbound slots they share, each held by a link from its grant to its send
    /// ([`LINK_TX_SLOTS`] at a time), and a place for each link the session may hold, which the
    /// session's links claim as they open and give back as they go.
    pub(crate) fn links_from(&self, lend: &mut TableLender<'_>) -> LinkTables {
        let rx = lend.byte_cells(self.link_bytes, self.rx_buffers);
        let tx = lend.byte_cells(self.link_bytes, self.tx_slots);
        #[cfg(feature = "listen")]
        {
            let places = lend.byte_cells(0, self.links);
            LinkTables::pooled(rx, tx, places)
        }
        #[cfg(not(feature = "listen"))]
        LinkTables::new(rx, tx, self.link_bytes)
    }
}

/// The rows of a session's state ([`ArenaPlan::session`]): its round of deliveries, the
/// engine's record of its own declarations, the application's tables, its pending gets and what
/// its faces' peers write and are owed, and the key arena every keyed row keeps its key in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionRows {
    /// The bytes of the session's round of deliveries (`crate::round`).
    lane_bytes: usize,
    /// The rows of the round's tables.
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
    /// The rows of the samples the session's advanced publishers' caches keep together
    /// (`ADVANCED_CACHE_ROWS`), each of the layout the ABI names, so laid out with its places
    /// ([`ArenaPlan::holding`]).
    #[cfg(feature = "cache-rows")]
    cache_rows: usize,
}

impl SessionRows {
    /// The bytes of the delivery lane's area (`DELIVERY_LANE_BYTES`): one table of one buffer,
    /// claimed for the session's life (`ArenaPlan::claim_lane_and_handle`).
    pub fn lane_bytes(&self) -> usize {
        self.lane_bytes
    }

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

    /// How many rows the session keeps for the samples of its advanced publishers' caches
    /// (`ADVANCED_CACHE_ROWS`).
    #[cfg(feature = "cache-rows")]
    pub fn cache_rows(&self) -> usize {
        self.cache_rows
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
    /// The bytes and the count of the rows of the advanced publishers' caches, none for no row.
    #[cfg(feature = "cache-rows")]
    cache_rows: (usize, usize),
}

/// The places a session's arena lent the ABI ([`PlaceRows::lent_from`]).
pub(crate) struct PlaceTables {
    /// The place of the ABI's handle, a table of one buffer, `None` for a plan with no place.
    pub(crate) handle: Option<LentByteCells>,
    /// The places of the ABI's entities, a table of each kind the plan holds places of.
    pub(crate) entities: EntityPlaces,
}

impl PlaceRows {
    /// The places, lent by `lend` in the order the plan laid them out: the handle's first, then
    /// each kind's in the order of [`EntityKind::ALL`], a place for each row `rows` counts of
    /// the kind, the session's own count, which the plan reads rather than keeps a second copy of.
    pub(crate) fn lent_from(&self, lend: &mut TableLender<'_>, rows: EntityRows) -> PlaceTables {
        let handle = (self.handle_bytes != 0).then(|| lend.byte_cells(self.handle_bytes, 1));
        let mut entities = EntityPlaces::NONE;
        for ((kind, bytes), cells) in EntityKind::ALL
            .into_iter()
            .zip(self.entity_bytes)
            .zip(entities.cells.iter_mut())
        {
            if bytes != 0 {
                *cells = Some(lend.byte_cells(bytes, rows.of_kind(kind)));
            }
        }
        // The cache rows last, as the plan laid them out after the entities' places.
        #[cfg(feature = "cache-rows")]
        {
            let (bytes, count) = self.cache_rows;
            if bytes != 0 {
                entities.cache_rows = Some(lend.byte_cells(bytes, count));
            }
        }
        PlaceTables { handle, entities }
    }
}

/// What a session's arena holds, row by row, and the rows each layer lends its tables from
/// ([`Self::transport`], [`Self::session`], [`Self::places`]). The arena is the sum of the rows'
/// spans whatever order they are lent in, so each layer lends its own in an order of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaPlan {
    rows: [ArenaRow; ARENA_ROWS],
    len: usize,
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
}

impl ArenaPlan {
    /// The rows of a session `config` opens under `limits` (see the module). Refused when a limit
    /// is over the build's value or the arena is past the address space.
    #[inline(never)]
    pub fn of<E: EndpointList>(
        config: &CoopConfig<E>,
        limits: &SessionLimits,
    ) -> Result<Self, ArenaRefused> {
        hold("MAX_FACES", config.max_faces, admitted_faces(limits)?)?;
        hold(
            "MAX_STATIC_CONNECT",
            config.endpoints.count(),
            caps::MAX_STATIC_CONNECT,
        )?;
        hold(
            "MAX_ADMIN_LOCATORS",
            config.listen.count(),
            caps::MAX_ADMIN_LOCATORS,
        )?;
        if config.listen.count() > 0 {
            hold(
                "MAX_ACCEPT_PENDING",
                config.accept_pending,
                admitted_handshakes(limits)?,
            )?;
        }
        let links = links_of(config).ok_or(ArenaRefused::TooLarge)?;
        // A buffer and a slot of the batch hold a whole batch of either link: a stream link's
        // length is counted inside the batch it negotiates (`STREAM_BATCH_LENGTH_BYTES`).
        let link_bytes = link_batch(config, limits)?;
        let mut plan = Self {
            rows: [NO_ROW; ARENA_ROWS],
            len: 0,
            refused: None,
            transport: TransportRows {
                links,
                rx_buffers: links,
                tx_slots: links,
                link_bytes,
                reassembly_bytes: 0,
                reassembly_chains: SESSION_CHAIN_BUFFERS,
                endpoint_rows: (config.endpoints.count(), config.listen.count()),
                cell_bytes: LinkCells::default(),
            },
            session: SessionRows::default(),
            places: PlaceRows::default(),
        };
        // The largest message a link rejoins is decided before the lane that hands it on, so a
        // value over the build's is refused under its own name.
        plan.transport.reassembly_bytes = plan.lent(
            "PICO_FRAG_MAX_BYTES",
            limits.pico_frag_max_bytes(),
            caps::PICO_FRAG_MAX_BYTES,
        );
        // The links read into a pool they share, a buffer held by a link only while it holds part
        // of a batch or something it was asked to keep (`wz_runtime_coop::link_storage::PooledRx`);
        // a pool of more buffers than links would hold one no link can take. They encode their
        // frames into a pool of slots they share as well, a slot held by a link from its grant to
        // its send, or until a frame its stream took in part is written
        // (`wz_runtime_coop::link_storage::PooledTx`). A build that only dials holds its dial and
        // the faces it attaches, and lends each link a buffer and a slot of its own.
        #[cfg(feature = "listen")]
        {
            plan.transport.rx_buffers = plan
                .lent(
                    "RX_POOL_BUFFERS",
                    Quota::at_most(limits.rx_pool_buffers()),
                    caps::RX_POOL_BUFFERS,
                )
                .min(links);
            plan.transport.tx_slots = plan
                .lent(
                    "TX_POOL_SLOTS",
                    Quota::at_most(limits.tx_pool_slots()),
                    caps::TX_POOL_SLOTS,
                )
                .min(links);
        }
        plan.session.lane_bytes = plan.lent(
            "DELIVERY_LANE_BYTES",
            Quota::at_most(limits.delivery_lane_bytes()),
            caps::DELIVERY_LANE_BYTES,
        );
        plan.session.round = RoundRowCounts {
            records: plan.lent(
                "DELIVERY_LANE_EVENTS",
                limits.delivery_lane_events(),
                caps::DELIVERY_LANE_EVENTS,
            ),
            callbacks: plan.lent(
                "DELIVERY_LANE_CALLBACKS",
                limits.delivery_lane_callbacks(),
                caps::DELIVERY_LANE_CALLBACKS,
            ),
            longest_key: plan.lent(
                "MAX_KEYEXPR_BYTES",
                limits.max_keyexpr_bytes(),
                caps::MAX_KEYEXPR_BYTES,
            ),
        };
        plan.session.key_bytes = plan.lent(
            "KEY_ARENA_BYTES",
            Quota::at_most(limits.key_arena_bytes()),
            caps::KEY_ARENA_BYTES,
        );
        let faces = plan.sized(faces_of(config));
        // The texts of the endpoints the session dials and listens on, a text a row of one table
        // each, written once when it opens and named by place after
        // (`TransportRows::lent_from`): one row of the plan, the two tables' spans.
        let (dial_rows, listen_rows) = plan.transport.endpoint_rows;
        let texts = plan.sized(
            Arena::table_bytes::<LocatorText>(dial_rows)
                .zip(Arena::table_bytes::<LocatorText>(listen_rows))
                .and_then(|(dial, listen)| dial.checked_add(listen)),
        );
        plan.put(
            "endpoint texts",
            "MAX_STATIC_CONNECT + MAX_ADMIN_LOCATORS",
            1,
            texts,
        );
        // The links' rows are lent when the session opens, in this order
        // (`TransportRows::links_from`).
        plan.put_table(
            ["link receive flags", "link receive buffers"],
            RX_BASIS,
            plan.transport.rx_buffers,
            link_bytes,
        );
        plan.put_table(
            ["link transmit flags", "link transmit slots"],
            TX_BASIS,
            plan.transport.tx_slots,
            link_bytes,
        );
        // A place for each link, which bounds the links that open where the slots are a pool:
        // the flags of a table of buffers of no bytes.
        #[cfg(feature = "listen")]
        plan.put(
            "link places",
            "MAX_FACES + MAX_ACCEPT_PENDING",
            links,
            LentByteCells::FLAG_BYTES,
        );
        // The delivery lane's area (`SessionRows::lane_bytes`): one table of one buffer.
        plan.put_table(
            ["delivery lane flag", "delivery lane"],
            "DELIVERY_LANE_BYTES",
            1,
            plan.session.lane_bytes,
        );
        // The round's tables, lent after its area (`crate::round::RoundRows::lent`).
        plan.put(
            "delivery records",
            "DELIVERY_LANE_EVENTS",
            plan.session.round.records,
            RECORD_BYTES,
        );
        plan.put(
            "delivery callbacks",
            "DELIVERY_LANE_CALLBACKS",
            plan.session.round.callbacks,
            CALLBACK_BYTES,
        );
        plan.put(
            "delivery keys",
            "MAX_KEYEXPR_BYTES",
            1,
            plan.session.round.key_bytes(),
        );
        // The session's reassembly buffers, which its links share (`TransportRows::lent_from`).
        plan.put_table(
            ["reassembly flags", "reassembly buffers"],
            "PICO_FRAG_MAX_BYTES",
            plan.transport.reassembly_chains,
            plan.transport.reassembly_bytes,
        );
        // The rows of the session's own declarations, read once: the registries' rows below and
        // the declaration tables after them count the same limits.
        plan.session.entities = plan.kept(entity_rows(limits));
        #[cfg(feature = "liveliness")]
        plan.put(
            "liveliness tokens",
            "MAX_LOCAL_TOKENS",
            plan.session.entities.tokens,
            wz_session_core::declare::local_token::LocalTokenRegistry::<Lent>::ROW_BYTES,
        );
        // The watchers' lists of the application's observer, lent with its tables
        // (`SlotObserverOf::lent`): one row of their spans, as a face's gets are one of theirs.
        let watchers = plan.lent(
            "MAX_DECL_OBSERVERS",
            limits.max_decl_observers(),
            caps::MAX_DECL_OBSERVERS,
        );
        let watcher_bytes = plan.sized(SlotObserverOf::<HeapSinks, Lent>::decl_watcher_bytes(
            watchers,
        ));
        plan.put(
            "declaration watchers",
            "MAX_DECL_OBSERVERS",
            1,
            watcher_bytes,
        );
        // A build that asks no query registers no get, so its tables of them hold no row.
        let queries = if cfg!(feature = "query") {
            plan.lent(
                "MAX_PENDING_QUERIES",
                limits.max_pending_queries(),
                caps::MAX_PENDING_QUERIES,
            )
        } else {
            0
        };
        let liveliness_gets = if cfg!(feature = "liveliness-get") {
            plan.lent(
                "MAX_PENDING_LIVELINESS_GETS",
                limits.max_pending_liveliness_gets(),
                caps::MAX_PENDING_LIVELINESS_GETS,
            )
        } else {
            0
        };
        let tables = plan.sized(faces.checked_add(usize::from(cfg!(feature = "local-queryable"))));
        plan.session.gets = GetTables {
            rows: RequesterRows {
                queries,
                liveliness_gets,
            },
            tables,
        };
        // A row of tables, each the spans of one face's registries: a face takes one whole. A build
        // that asks no query holds no table of gets (`NoRequesters`), and its plan no row of them.
        #[cfg(feature = "query")]
        {
            let get_bytes = plan.sized(FaceGets::arena_bytes(plan.session.gets.rows));
            plan.put(
                "pending gets",
                "MAX_PENDING_QUERIES + MAX_PENDING_LIVELINESS_GETS",
                plan.session.gets.tables,
                get_bytes,
            );
        }
        // The ends of the legs, a row for each get every table holds (`GetTables::legs`).
        #[cfg(feature = "query")]
        {
            let legs = plan.sized(plan.session.gets.legs());
            plan.put(
                "ended legs",
                "MAX_PENDING_QUERIES + MAX_PENDING_LIVELINESS_GETS",
                legs,
                core::mem::size_of::<crate::engine::Ended>(),
            );
        }
        // A row of tables, each what one face's peer is owed: a face takes one whole. What the
        // peers write by their own choice lies in pools the faces share, one area each.
        plan.session.peers = FacePeers {
            rows: plan.kept(peer_rows(limits)),
            tables: faces,
            pools: plan.kept(pool_rows(limits, faces)),
            dial: dials(config),
        };
        // The sets of face tables themselves, one for each face, in one table
        // (`engine::registry::Registry::new`); what each set's tables hold is the rows after it.
        plan.put(
            "face tables",
            "MAX_FACES + 1",
            plan.session.peers.sets(),
            FACE_SET_BYTES,
        );
        // Which face holds which set, a row for each set.
        plan.put(
            "held faces",
            "MAX_FACES + 1",
            plan.session.peers.sets(),
            HELD_SET_BYTES,
        );
        let peer_bytes = plan.sized(PeerTables::<Lent>::arena_bytes(plan.session.peers.rows));
        plan.put(
            "peer tables",
            "MAX_PENDING_DECLARES + MAX_PENDING_FINALS",
            plan.session.peers.tables,
            peer_bytes,
        );
        // Each kind one area: a pool the faces share, or for a session of one face a span of its
        // tables' own (`pool_rows`); none in a build whose faces keep those rows inline.
        if SHARES_ROWS {
            let pools = plan.session.peers.pools;
            for (part, kind, bytes) in [
                ("peer alias pool", &ALIAS_LIMITS, pools.alias_bytes()),
                ("peer declaration pools", &DECL_LIMITS, pools.decl_bytes()),
                (
                    "peer interest pool",
                    &INTEREST_LIMITS,
                    pools.interest_bytes(),
                ),
            ] {
                let bytes = plan.sized(bytes);
                plan.put(part, kind.session, 1, bytes);
            }
        }
        // The tokens the faces that went still owe, lent with the pools
        // (`engine::registry::Registry::new`).
        #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
        if plan.session.peers.owed_tokens() > 0 {
            plan.put(
                "owed tokens",
                "SESSION_MAX_REMOTE_DECLS",
                plan.session.peers.owed_tokens(),
                core::mem::size_of::<
                    wz_session_core::declare::liveliness_subscriber::PeerTokens<Lent>,
                >(),
            );
        }
        plan.session.held_queries = if cfg!(feature = "queryable") {
            plan.lent(
                "MAX_PENDING_FINALS",
                limits.max_pending_finals(),
                caps::MAX_PENDING_FINALS,
            )
        } else {
            0
        };
        #[cfg(feature = "cache-rows")]
        {
            plan.session.cache_rows = plan.lent(
                "ADVANCED_CACHE_ROWS",
                Quota::at_most(caps::ADVANCED_CACHE_ROWS),
                caps::ADVANCED_CACHE_ROWS,
            );
        }
        plan.put_entities();
        plan.settled()
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

    /// The one buffer of each of `lane` and `handle`, tables of one buffer the plan's lender
    /// lent whole ([`SessionRows::lane_bytes`], [`PlaceTables::handle`]), claimed for the
    /// session's life: the lane's place and length, and the handle's place when the plan holds
    /// one. The claims are never given back: what holds a buffer holds it until the session is
    /// let go, and a buffer dropped then would write its cell's flag into an arena given back
    /// before it. Refused as an arena with no room for a table lent no buffer.
    pub(crate) fn claim_lane_and_handle(
        &self,
        lane: LentByteCells,
        handle: Option<LentByteCells>,
    ) -> Result<ClaimedPlaces, ArenaRefused> {
        let lane = claimed(lane);
        let handle = handle.map(claimed);
        match (lane, handle) {
            (Some((lane_area, lane_bytes)), None) => Ok(ClaimedPlaces {
                lane_area,
                lane_bytes,
                handle: None,
            }),
            (Some((lane_area, lane_bytes)), Some(Some((base, bytes)))) => Ok(ClaimedPlaces {
                lane_area,
                lane_bytes,
                handle: Some(HandlePlace { base, bytes }),
            }),
            (None, _) | (_, Some(None)) => Err(ArenaRefused::Lend(LendRefused::Exhausted {
                asked: Some(self.session.lane_bytes.max(self.places.handle_bytes)),
                left: 0,
            })),
        }
    }

    /// The rows of the engine's own record of the session's declarations ([`EntityRows`]).
    fn put_entities(&mut self) {
        let rows = self.session.entities;
        // The session's one table set, holding the kinds moved onto it so far.
        let tables = self.sized(CoopTables::arena_bytes(&self.tables()));
        self.put("session tables", "MAX_DECLARED_KEYEXPRS", 1, tables);
        let filters = self.sized(rows.filters());
        self.put(
            "write filters",
            "MAX_PUBLISHERS + MAX_QUERIERS",
            filters,
            EntryBytes::FILTER,
        );
        self.put(
            "matching listeners",
            "MAX_MATCHING_LISTENERS",
            rows.matching_listeners,
            EntryBytes::MATCH,
        );
        let interests = self.sized(rows.interests());
        self.put(
            "interests",
            "MAX_PUBLISHERS + MAX_QUERIERS + MAX_MATCHING_LISTENERS",
            interests,
            EntryBytes::INTEREST,
        );
        // The keys of those rows and of every other keyed row of the session, in one area that a
        // key takes a block of as long as it is held (`TableLender::keys`), not a row of
        // each.
        let keys = self.sized(KeySpace::span_bytes(self.session.key_bytes));
        self.put("key arena", "KEY_ARENA_BYTES", 1, keys);
    }

    /// How many rows each table of the session's round of deliveries is lent.
    pub fn round(&self) -> RoundRowCounts {
        self.session.round
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
    pub fn tables(&self) -> TableRows {
        TableRows {
            keyexprs: self.session.entities.keyexprs,
            subscribers: self.session.entities.subscribers,
            queryables: self.session.entities.queryables,
            tokens: self.session.entities.tokens,
            liveliness_subscribers: self.session.entities.liveliness_subscribers,
            ..TableRows::default()
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
    /// `queryable`. They are no row of the arena: the query plane holds them in a fixed table of
    /// its own, as it is shared with what answers outside the session's lock.
    pub fn held_queries(&self) -> usize {
        self.session.held_queries
    }

    /// Add a row. A plan has room for every row of the build with every feature (`ARENA_ROWS`);
    /// a row past them is refused as an arena past what the plan can lay out, which the plan keeps
    /// as its refusal unless it holds an earlier one ([`Self::settled`]).
    #[inline(never)]
    fn put(&mut self, part: &'static str, basis: &'static str, count: usize, entry_bytes: usize) {
        match self.rows.get_mut(self.len) {
            Some(row) => {
                *row = ArenaRow {
                    part,
                    basis,
                    count,
                    entry_bytes,
                };
                self.len = self.len.saturating_add(1);
            }
            None => self.refuse(ArenaRefused::TooLarge),
        }
    }

    /// Add the two rows of a table of `count` entries of `entry_bytes` named `parts`: its flags,
    /// then its entries, as an arena lends a table of cells.
    #[inline(never)]
    fn put_table(
        &mut self,
        parts: [&'static str; 2],
        basis: &'static str,
        count: usize,
        entry_bytes: usize,
    ) {
        let [flags, entries] = parts;
        self.put(flags, basis, count, LentByteCells::FLAG_BYTES);
        self.put(entries, basis, count, entry_bytes);
    }

    /// Keep `refused` as the plan's refusal unless it holds an earlier one.
    #[inline(never)]
    fn refuse(&mut self, refused: ArenaRefused) {
        if self.refused.is_none() {
            self.refused = Some(refused);
        }
    }

    /// The rows a table of the limit `limit` is lent (`lent_under`): `value` under `ceiling`,
    /// the build's value of the limit. A value over it is kept as the plan's refusal, under the
    /// limit's own name, and answers `0`.
    #[inline(never)]
    fn lent(&mut self, limit: &'static str, value: Quota, ceiling: usize) -> usize {
        match lent_under(limit, value, ceiling) {
            Ok(rows) => rows,
            Err(refused) => {
                self.refuse(refused);
                0
            }
        }
    }

    /// `bytes`, a size `None` past the address space, which is then kept as the plan's refusal
    /// and answers `0`.
    #[inline(never)]
    fn sized(&mut self, bytes: Option<usize>) -> usize {
        match bytes {
            Some(bytes) => bytes,
            None => {
                self.refuse(ArenaRefused::TooLarge);
                0
            }
        }
    }

    /// What `read` gives, or its refusal kept as the plan's and the value's default.
    #[inline]
    fn kept<T: Default>(&mut self, read: Result<T, ArenaRefused>) -> T {
        read.unwrap_or_else(|refused| {
            self.refuse(refused);
            T::default()
        })
    }

    /// The plan, or the first refusal met while it was laid out; refused as past the address
    /// space when the rows' spans together are.
    #[inline(never)]
    fn settled(self) -> Result<Self, ArenaRefused> {
        if let Some(refused) = self.refused {
            return Err(refused);
        }
        match self.reserved_bytes() {
            Some(_) => Ok(self),
            None => Err(ArenaRefused::TooLarge),
        }
    }

    /// The plan with the places `held` names, lent after every other row: the ABI's handle of the
    /// session first, then each kind of entity in the order of [`EntityKind::ALL`], a place for
    /// each row the session keeps of the kind, then, with `cache-rows`, a row of the layout
    /// [`HeldPlaces::with_cache_rows`] names for each sample the caches keep (`ADVANCED_CACHE_ROWS`). What the ABI keeps there takes no memory of its
    /// own, and an open whose arena cannot hold it reserves nothing, as for any other row. A place
    /// of no bytes, and a kind the session keeps no row of, take none, and a place the plan holds
    /// already is not laid out again. Refused as past the address space when a place asks for more
    /// alignment than a span of the arena starts on ([`ARENA_ALIGN`]), or the arena with the
    /// places is.
    pub fn holding(mut self, held: &HeldPlaces) -> Result<Self, ArenaRefused> {
        if let Some(handle) = held.handle {
            if handle.align() > ARENA_ALIGN {
                return Err(ArenaRefused::TooLarge);
            }
            if handle.size() != 0 && self.places.handle_bytes == 0 {
                self.places.handle_bytes = handle.size();
                self.put_table(
                    ["session handle flag", "session handle"],
                    "",
                    1,
                    handle.size(),
                );
            }
        }
        let laid = self.places.entity_bytes;
        for ((kind, place), laid) in EntityKind::ALL.into_iter().zip(held.entities).zip(laid) {
            let Some(place) = place else {
                continue;
            };
            if place.align() > ARENA_ALIGN {
                return Err(ArenaRefused::TooLarge);
            }
            let count = self.session.entities.of_kind(kind);
            if place.size() == 0 || count == 0 || laid != 0 {
                continue;
            }
            let (flags, places, basis) = place_rows(kind);
            self.put_table([flags, places], basis, count, place.size());
            if let Some(bytes) = self.places.entity_bytes.get_mut(kind as usize) {
                *bytes = place.size();
            }
        }
        #[cfg(feature = "cache-rows")]
        if let Some(row) = held.cache_rows {
            if row.align() > ARENA_ALIGN {
                return Err(ArenaRefused::TooLarge);
            }
            let count = self.session.cache_rows;
            if row.size() != 0 && count != 0 && self.places.cache_rows.0 == 0 {
                self.put_table(
                    ["cache row flags", "cache rows"],
                    "ADVANCED_CACHE_ROWS",
                    count,
                    row.size(),
                );
                self.places.cache_rows = (row.size(), count);
            }
        }
        self.settled()
    }

    /// The plan with a table of a cell for each link of each kind `bytes` sizes: the links'
    /// drivers, which the stack places them in (`wz_runtime_coop::link_cells`, its
    /// `SessionLinks::link_cell_bytes`), and their gates and their actions, which the session
    /// places them in when it makes the link: a link the session opens then takes cells and no
    /// memory of the heap. Laid out before the ABI's handle ([`Self::holding`]). A size of `0`
    /// adds no table, as a stack that places its links on the heap asks.
    pub fn holding_cells(mut self, bytes: LinkCells<usize>) -> Result<Self, ArenaRefused> {
        let mut laid = self.transport.cell_bytes.into_array();
        for ((laid, asked), parts) in laid.iter_mut().zip(bytes.into_array()).zip(CELL_ROWS_NAMED) {
            if *laid == 0 && asked != 0 {
                *laid = asked;
                self.put_table(parts, CELL_BASIS, self.transport.links, asked);
            }
        }
        self.transport.cell_bytes = LinkCells::from_array(laid);
        self.settled()
    }

    /// The bytes of the place the plan holds for the ABI's handle, `0` for none.
    pub fn handle_bytes(&self) -> usize {
        self.places.handle_bytes
    }

    /// The bytes of each place the plan holds for an entity of `kind`, `0` for none.
    pub fn entity_bytes(&self, kind: EntityKind) -> usize {
        self.places
            .entity_bytes
            .get(kind as usize)
            .copied()
            .unwrap_or(0)
    }

    /// The rows, in the order the plan laid them out.
    pub fn rows(&self) -> &[ArenaRow] {
        self.rows.get(..self.len).unwrap_or(&[])
    }

    /// The bytes the arena reserves: the sum of the rows' spans. `None` past the address space.
    pub fn reserved_bytes(&self) -> Option<usize> {
        self.rows()
            .iter()
            .try_fold(0usize, |sum, row| sum.checked_add(row.span()?))
    }
}

/// The rows a table of the limit `limit` is lent: `value`, the one the session's creator resolved
/// into its limits at the open, under `CEILING`, the build's value of the limit, which is the
/// capacity the build gives the table's type (a `BoundedVec<T, CEILING, Lent>` is lent at most
/// that many rows): the build sizes the storage and the snapshot chooses within it.
#[inline]
fn lent<const CEILING: usize>(limit: &'static str, value: Quota) -> Result<usize, ArenaRefused> {
    lent_under(limit, value, CEILING)
}

/// [`lent`] with the build's value a value: one body for every limit, the ceiling a const of the
/// caller's alone.
#[inline(never)]
fn lent_under(limit: &'static str, value: Quota, ceiling: usize) -> Result<usize, ArenaRefused> {
    value
        .lent_under(Quota::at_most(ceiling))
        .map_err(|why| ArenaRefused::Limit { limit, why })
}

/// The length of each link's receive buffer and of each of its slots: the batch `config`
/// advertises, which is the most a peer sends once the two have negotiated, held to the batch the
/// session's `limits` state (`PICO_UNICAST_BATCH_BYTES`) under the build's. A batch over either
/// is refused, as a stage after the build only lowers the memory the build fixes.
fn link_batch<E>(config: &CoopConfig<E>, limits: &SessionLimits) -> Result<usize, ArenaRefused> {
    let ceiling = lent::<{ caps::PICO_UNICAST_BATCH_BYTES }>(
        "PICO_UNICAST_BATCH_BYTES",
        Quota::at_most(limits.pico_unicast_batch_bytes()),
    )?;
    let advertised = usize::from(config.batch_size);
    if advertised > ceiling {
        return Err(ArenaRefused::Limit {
            limit: "PICO_UNICAST_BATCH_BYTES",
            why: UnlentRows::OverCeiling {
                value: advertised,
                ceiling,
            },
        });
    }
    Ok(advertised)
}

/// The rows of each table of the engine's record of the session's declarations, under `limits`.
fn entity_rows(limits: &SessionLimits) -> Result<EntityRows, ArenaRefused> {
    Ok(EntityRows {
        subscribers: lent::<{ caps::MAX_SUBSCRIPTIONS }>(
            "MAX_SUBSCRIPTIONS",
            limits.max_subscriptions(),
        )?,
        queryables: if cfg!(feature = "queryable") {
            lent::<{ caps::MAX_QUERYABLES }>("MAX_QUERYABLES", limits.max_queryables())?
        } else {
            0
        },
        tokens: if cfg!(feature = "liveliness") {
            lent::<{ caps::MAX_LOCAL_TOKENS }>("MAX_LOCAL_TOKENS", limits.max_local_tokens())?
        } else {
            0
        },
        liveliness_subscribers: if cfg!(feature = "liveliness") {
            lent::<{ caps::MAX_LIVELINESS_SUBSCRIPTIONS }>(
                "MAX_LIVELINESS_SUBSCRIPTIONS",
                limits.max_liveliness_subscriptions(),
            )?
        } else {
            0
        },
        keyexprs: lent::<{ caps::MAX_DECLARED_KEYEXPRS }>(
            "MAX_DECLARED_KEYEXPRS",
            limits.max_declared_keyexprs(),
        )?,
        publishers: lent::<{ caps::MAX_PUBLISHERS }>("MAX_PUBLISHERS", limits.max_publishers())?,
        queriers: lent::<{ caps::MAX_QUERIERS }>("MAX_QUERIERS", limits.max_queriers())?,
        matching_listeners: lent::<{ caps::MAX_MATCHING_LISTENERS }>(
            "MAX_MATCHING_LISTENERS",
            limits.max_matching_listeners(),
        )?,
    })
}

/// The rows of each kind of what the peers of a session of `faces` faces write, under `limits`.
///
/// A session of many faces lends a pool of each kind the faces share: the session's value of the
/// kind's limit under the build's, and no more than the faces could hold together, each at the
/// bound of one peer the session resolved. A session of one face has no one to share with: its
/// tables take spans of their own of that face's bounds, with no link and no pool state, as many
/// rows as its inline tables held (and fewer where the session's limit is lower).
///
/// A pool or a span names its rows by `u16`, so a count past [`MAX_POOL_ROWS`] refuses the open
/// by the limit that set it: the session's limit for a pool, the face's for a span. Refused too
/// when a limit is over the build's value.
fn pool_rows(limits: &SessionLimits, faces: usize) -> Result<PeerPoolRows, ArenaRefused> {
    if !SHARES_ROWS {
        // A build whose faces keep what their peers write inline lends no pool and no span.
        return Ok(PeerPoolRows::default());
    }
    Ok(PeerPoolRows {
        aliases: kind_rows(
            faces,
            limit_rows::<{ caps::MAX_PEER_KEYEXPR_ALIASES }>(
                ALIAS_LIMITS.face,
                limits.max_peer_keyexpr_aliases(),
            )?,
            limit_rows::<{ caps::SESSION_MAX_PEER_KEYEXPR_ALIASES }>(
                ALIAS_LIMITS.session,
                limits.session_max_peer_keyexpr_aliases(),
            )?,
        )?,
        remote_decls: kind_rows(
            faces,
            limit_rows::<{ caps::MAX_REMOTE_DECLS }>(DECL_LIMITS.face, limits.max_remote_decls())?,
            limit_rows::<{ caps::SESSION_MAX_REMOTE_DECLS }>(
                DECL_LIMITS.session,
                limits.session_max_remote_decls(),
            )?,
        )?,
        interests: kind_rows(
            faces,
            limit_rows::<{ caps::MAX_INBOUND_SUB_INTERESTS }>(
                INTEREST_LIMITS.face,
                limits.max_inbound_sub_interests(),
            )?,
            limit_rows::<{ caps::SESSION_MAX_INBOUND_SUB_INTERESTS }>(
                INTEREST_LIMITS.session,
                limits.session_max_inbound_sub_interests(),
            )?,
        )?,
        shared: faces > 1,
    })
}

/// The limit `limit` and the rows [`lent`] gives its value under `CEILING`, as [`kind_rows`]
/// takes each of its two.
#[inline]
fn limit_rows<const CEILING: usize>(
    limit: &'static str,
    value: Quota,
) -> Result<(&'static str, usize), ArenaRefused> {
    Ok((limit, lent::<CEILING>(limit, value)?))
}

/// The two limits that bound one kind of what the peers of a session write, by id: one face's, and
/// all the faces' together.
struct PoolLimit {
    face: &'static str,
    session: &'static str,
}

/// The limits of the peers' keyexpr aliases.
const ALIAS_LIMITS: PoolLimit = PoolLimit {
    face: "MAX_PEER_KEYEXPR_ALIASES",
    session: "SESSION_MAX_PEER_KEYEXPR_ALIASES",
};

/// The limits of the peers' declarations of one kind.
const DECL_LIMITS: PoolLimit = PoolLimit {
    face: "MAX_REMOTE_DECLS",
    session: "SESSION_MAX_REMOTE_DECLS",
};

/// The limits of the peers' subscriber interests.
const INTEREST_LIMITS: PoolLimit = PoolLimit {
    face: "MAX_INBOUND_SUB_INTERESTS",
    session: "SESSION_MAX_INBOUND_SUB_INTERESTS",
};

/// The rows of one kind of what the peers of a session of `faces` faces write: the fewer of the
/// session's limit and the faces' bounds together, `face` and `session` each a limit's id and the
/// value the open resolved of it. Refused, by the id of the limit that set the count, past the
/// most rows a pool or a span names ([`MAX_POOL_ROWS`]): a session's limit for a session of many
/// faces, the face's for one of one face, unless the session's is the lower.
pub(crate) fn kind_rows(
    faces: usize,
    face: (&'static str, usize),
    session: (&'static str, usize),
) -> Result<usize, ArenaRefused> {
    let all = face.1.saturating_mul(faces);
    let (limit, rows) = if session.1 < all {
        session
    } else if faces > 1 {
        (session.0, all)
    } else {
        face
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
fn peer_rows(limits: &SessionLimits) -> Result<PeerRows, ArenaRefused> {
    if cfg!(feature = "queryable") {
        lent::<{ caps::MAX_PENDING_REPLIES }>("MAX_PENDING_REPLIES", limits.max_pending_replies())?;
        lent::<{ caps::MAX_REPLY_PAYLOAD_BYTES }>(
            "MAX_REPLY_PAYLOAD_BYTES",
            limits.max_reply_payload_bytes(),
        )?;
    }
    Ok(PeerRows {
        pending_declares: lent::<{ caps::MAX_PENDING_DECLARES }>(
            "MAX_PENDING_DECLARES",
            limits.max_pending_declares(),
        )?,
        replies: 0,
        reply_bytes: 0,
        finals: if cfg!(feature = "queryable") {
            lent::<{ caps::MAX_PENDING_FINALS }>("MAX_PENDING_FINALS", limits.max_pending_finals())?
        } else {
            0
        },
    })
}

/// The faces besides the dial role's that `limits` admit: the session's `MAX_FACES`, under the
/// build's. What an ABI states as [`CoopConfig::max_faces`] for a session that takes faces besides
/// its dial, which [`ArenaPlan::of`] holds the config to. Refused when the session's value is over
/// the build's.
pub fn admitted_faces(limits: &SessionLimits) -> Result<usize, ArenaRefused> {
    lent::<{ caps::MAX_FACES }>("MAX_FACES", limits.max_faces())
}

/// The inbound links in their handshake at once that `limits` admit: the session's
/// `MAX_ACCEPT_PENDING`, under the build's. What an ABI states as
/// [`CoopConfig::accept_pending`], which [`ArenaPlan::of`] holds the config of a session that
/// listens to. Refused when the session's value is over the build's.
pub fn admitted_handshakes(limits: &SessionLimits) -> Result<usize, ArenaRefused> {
    lent::<{ caps::MAX_ACCEPT_PENDING }>("MAX_ACCEPT_PENDING", limits.max_accept_pending())
}

/// `asked`, what a session's config states of the limit `limit`, held to `admitted`, the session's
/// value of it under the build's: a config over it is refused, as a stage after the build only
/// lowers the memory the build fixes.
fn hold(limit: &'static str, asked: usize, admitted: usize) -> Result<(), ArenaRefused> {
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
pub(crate) fn dials_of(endpoints: usize, listens: usize, groups: usize) -> bool {
    !(endpoints == 0 && (listens > 0 || groups > 0))
}

/// The most faces a session's plan counts ([`faces_of`]), and so the most sets of face tables
/// its arena lends: the dial role's, each face the build admits besides it (`MAX_FACES`), and in
/// a build that joins groups one for each group the session's task cells hold (`MAX_TASKS`). A
/// session that dials nothing counts no dial face but is lent a set of no rows for it
/// ([`FacePeers::sets`]), so the bound is the same.
pub(crate) const MAX_FACE_SETS: usize = 1 + caps::MAX_FACES + GROUP_FACES;

/// The groups a session's plan counts at most: as many as its task cells hold in a build that
/// joins groups, none in one that does not.
const GROUP_FACES: usize = if cfg!(feature = "group") {
    caps::MAX_TASKS
} else {
    0
};

/// The faces a session `config` opens may hold at once: the dial role's when it dials
/// (`dials`), as many besides as `max_faces` admits, a link still in its handshake among them,
/// and one for each group it joins. A group past the task cells has no task to join it on, and
/// the open refuses it at its join (`OpenError::NoTask`), as a build without `group` refuses any
/// by name, so neither is counted. `None` past the address space.
fn faces_of(config: &CoopConfig<impl EndpointList>) -> Option<usize> {
    usize::from(dials(config))
        .checked_add(config.max_faces)?
        .checked_add(if cfg!(feature = "group") {
            config.groups.len().min(caps::MAX_TASKS)
        } else {
            0
        })
}

/// The links a session `config` opens may hold at once, whose buffers its open reserves: the dial
/// role's when it dials (the endpoints it lists, or none with neither a port nor a group), as many
/// besides as `max_faces` admits (each a link it attaches or accepts), and for a listener as many
/// in their handshake as `accept_pending` admits. `None` past the address space. The one count
/// of them: the plan's link rows are sized by it, and an ABI that reports the session's memory
/// reads it here. A link in its handshake past the faces holds buffers only, to be taken off its
/// port and closed; the runtime's task cells are reserved for the faces (`engine::RuntimeTables`).
pub fn links_of(config: &CoopConfig<impl EndpointList>) -> Option<usize> {
    let handshakes = if config.listen.count() == 0 {
        0
    } else {
        config.accept_pending
    };
    usize::from(dials(config))
        .checked_add(config.max_faces)?
        .checked_add(handshakes)
}

/// Where a session's arena is reserved from.
pub trait ArenaMemory: Sync {
    /// `layout.size()` bytes aligned to `layout.align()`, or `None` when there are none to give.
    /// Never asked for zero bytes.
    fn reserve(&self, layout: Layout) -> Option<NonNull<u8>>;

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
/// not the end of the process.
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
    /// The rows of the advanced publishers' caches, if the arena holds them: kept with the
    /// entities' places, as they are lent and given back as those are.
    #[cfg(feature = "cache-rows")]
    cache_rows: Option<LentByteCells>,
}

impl EntityPlaces {
    /// No place of any kind.
    pub(crate) const NONE: Self = Self {
        cells: [None; ENTITY_KINDS],
        #[cfg(feature = "cache-rows")]
        cache_rows: None,
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

    /// A free row for a sample of an advanced publisher's cache, or `None` when every one is lent
    /// or the arena holds none. The row is the ABI's until it gives it back
    /// ([`Self::give_back_cache_row`]).
    #[cfg(feature = "cache-rows")]
    pub(crate) fn claim_cache_row(&self) -> Option<NonNull<u8>> {
        let buffer = self.cache_rows?.claim()?;
        let (base, _) = buffer.raw();
        // The claim is held by the ABI's row from here and ended by `give_back_cache_row`, not by
        // the buffer's drop.
        core::mem::forget(buffer);
        NonNull::new(base)
    }

    /// Give back `row`: `false`, and it stays lent, when it is no row these tables lent.
    ///
    /// # Safety
    /// `row` is a row a session's tables lent the ABI and the ABI has not given back, and nothing
    /// lies there any more.
    #[cfg(feature = "cache-rows")]
    pub(crate) unsafe fn give_back_cache_row(&self, row: NonNull<u8>) -> bool {
        // SAFETY: the caller's: the claim the row held ends here, once.
        self.cache_rows
            .is_some_and(|cells| unsafe { cells.release_at(row) })
    }

    /// How many rows of the caches are lent, and how many the arena holds.
    #[cfg(all(test, feature = "cache-rows"))]
    pub(crate) fn cache_row_counts(&self) -> (usize, usize) {
        self.cache_rows
            .map_or((0, 0), |cells| (cells.in_use(), cells.capacity()))
    }

    /// How many places of `kind` are lent, and how many the arena holds.
    #[cfg(test)]
    pub(crate) fn counts(&self, kind: EntityKind) -> (usize, usize) {
        self.of(kind)
            .map_or((0, 0), |cells| (cells.in_use(), cells.capacity()))
    }
}

/// The places an open claims from its arena for the session's life
/// (`ArenaPlan::claim_lane_and_handle`).
pub(crate) struct ClaimedPlaces {
    /// Where the delivery lane's area starts.
    pub(crate) lane_area: NonNull<u8>,
    /// The bytes of the lane's area.
    pub(crate) lane_bytes: usize,
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

/// A session's arena: the memory its open reserved by its plan, given back when the session is let
/// go.
pub(crate) struct SessionArena {
    arena: Arena,
    base: NonNull<u8>,
    layout: Layout,
    memory: &'static dyn ArenaMemory,
}

impl SessionArena {
    /// Reserve the arena `plan` lays out from `memory`. Refused, having taken nothing, when the
    /// arena is past the address space or the memory has none to give.
    pub(crate) fn reserve(
        plan: &ArenaPlan,
        memory: &'static dyn ArenaMemory,
    ) -> Result<Self, ArenaRefused> {
        Self::of_bytes(plan.reserved_bytes().ok_or(ArenaRefused::TooLarge)?, memory)
    }

    /// Reserve an arena of `bytes` from `memory`. Refused, having taken nothing, when the memory has
    /// none to give.
    pub(crate) fn of_bytes(
        bytes: usize,
        memory: &'static dyn ArenaMemory,
    ) -> Result<Self, ArenaRefused> {
        // At least one span, so the memory is never asked for nothing.
        let layout = Layout::from_size_align(bytes.max(ARENA_ALIGN), ARENA_ALIGN)
            .map_err(|_| ArenaRefused::TooLarge)?;
        let base = memory
            .reserve(layout)
            .ok_or(ArenaRefused::NoMemory { bytes })?;
        // SAFETY: the memory gave `layout`, aligned to `ARENA_ALIGN` and at least `bytes` long, to
        // this arena alone, until `Drop` gives it back.
        let arena = unsafe { Arena::over(base, bytes) };
        Ok(Self {
            arena,
            base,
            layout,
            memory,
        })
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

    /// The arena, to lend from.
    pub(crate) fn arena_mut(&mut self) -> &mut Arena {
        &mut self.arena
    }

    /// Whether `at` is a byte of the arena's memory.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn holds(&self, at: *const u8) -> bool {
        let base = self.base.as_ptr() as usize;
        (base..base + self.bytes()).contains(&(at as usize))
    }
}

impl Drop for SessionArena {
    fn drop(&mut self) {
        // SAFETY: `base` is what the memory gave for `layout`, given back here once, and the
        // session that held the arena dropped every table lent from it first.
        unsafe { self.memory.release(self.base, self.layout) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_plan() -> ArenaPlan {
        ArenaPlan {
            rows: [NO_ROW; ARENA_ROWS],
            len: 0,
            refused: None,
            transport: TransportRows::default(),
            session: SessionRows::default(),
            places: PlaceRows::default(),
        }
    }

    /// A plan lays out `ARENA_ROWS` rows and refuses the one past them, keeping those it holds.
    /// Turned red by a row written past the table, or a plan settled with a row it could not hold.
    #[test]
    fn a_row_past_the_plan_is_refused_and_the_rows_it_holds_stay() {
        let mut plan = empty_plan();
        for _ in 0..ARENA_ROWS {
            plan.put("part", "BASIS", 1, 8);
        }
        assert_eq!(plan.refused, None);
        plan.put("one more", "BASIS", 1, 8);
        assert_eq!(plan.rows().len(), ARENA_ROWS);
        assert_eq!(plan.settled(), Err(ArenaRefused::TooLarge));
    }

    /// The refusal a settled plan answers is the first one met, as it came: a limit over the
    /// build's value under the limit's own name, though a row past the plan and a size past the
    /// address space come after it. Turned red by a later refusal replacing the first, or by a
    /// refusal that loses the limit it names.
    #[test]
    fn a_settled_plan_answers_the_first_refusal_with_its_limit() {
        let mut plan = empty_plan();
        assert_eq!(plan.lent("FIRST_LIMIT", Quota::at_most(9), 4), 0);
        assert_eq!(plan.sized(None), 0);
        for _ in 0..=ARENA_ROWS {
            plan.put("part", "BASIS", 1, 8);
        }
        assert_eq!(
            plan.settled(),
            Err(ArenaRefused::Limit {
                limit: "FIRST_LIMIT",
                why: UnlentRows::OverCeiling {
                    value: 9,
                    ceiling: 4,
                },
            })
        );
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
        };
        let plan = plan.holding_cells(asked).expect("the cells fit");
        let plan = plan.holding_cells(asked).expect("held already");
        let parts: alloc::vec::Vec<_> = plan.rows().iter().map(|row| row.part).collect();
        assert_eq!(
            parts,
            [
                "link cell flags",
                "link cells",
                "link actions flags",
                "link actions"
            ]
        );
        assert_eq!(plan.rows()[1].entry_bytes, 40);
        assert_eq!(plan.rows()[3].count, 3);
    }
}
