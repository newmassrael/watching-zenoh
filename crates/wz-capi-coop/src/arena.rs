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
//! - the application's tables, once for the session: its subscribers (`MAX_SUBSCRIPTIONS`), with
//!   `queryable` its queryables (`MAX_QUERYABLES`), with `liveliness` its tokens
//!   (`MAX_LOCAL_TOKENS`) and its liveliness subscribers (`MAX_LIVELINESS_SUBSCRIPTIONS`), and
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
//! - the buffers of each link the session may hold: a receive buffer of the batch the session
//!   advertises, a streamed batch's length counted inside it, and [`LINK_TX_SLOTS`] slots of that
//!   length to encode its frames into, each table with the flags that say which buffers are lent
//!   (`SessionArena::lend_links`). The batch is the config's, held to the session's
//!   `PICO_UNICAST_BATCH_BYTES` under the build's; these are the rows lent when the session opens,
//!   first;
//! - the session's delivery lane (`DELIVERY_LANE_BYTES`, under the build's), the bytes of what
//!   it hands its subscribers' callbacks after its lock (`crate::lane`), lent next;
//! - the buffers the links of the session stage the chains of their fragmented messages in, one
//!   table for the session (`LENT_CHAINS` of `wz_runtime_coop::reassembly_rx`, one for each
//!   reliability a peer has a chain open in), each buffer claimed when a chain's first fragment
//!   arrives and given back when the chain ends, each as long as the largest message the session
//!   rejoins (`PICO_FRAG_MAX_BYTES`, under the build's, which a chain past it is ended at, as pico
//!   ends one), with the flags that say which are lent (`SessionArena::lend_reassembly`), lent
//!   after the lane;
//! - the engine's own record of each declaration it announces and announces again over a new
//!   link ([`EntityRows`]): its subscribers, queryables, tokens and liveliness subscribers under
//!   the limits of the application's tables, the key expressions it declares
//!   (`MAX_DECLARED_KEYEXPRS`), the write filters of its publishers (`MAX_PUBLISHERS`) and
//!   queriers (`MAX_QUERIERS`), its matching listeners (`MAX_MATCHING_LISTENERS`), and the
//!   Interests those filters and listeners hold open, at most one for each of them;
//! - the key arena every keyed row of the session keeps its key in (`KEY_ARENA_BYTES`, under the
//!   build's): that record's, the application's tables', each face's pending gets' and what each
//!   face's peer declares and asks, one area of blocks a key takes as long as it is held
//!   ([`KeySpace`](wz_session_core::key_arena::KeySpace)), lent after the record and before the
//!   tables that keep their keys in it. A peer's key that finds no room there is dropped and
//!   counted, as zenoh-pico drops a declaration its heap cannot hold;
//! - with [`ArenaPlan::holding`], the place the ABI keeps its own handle of the session in, last,
//!   so the handle is reserved with the session and takes no memory of its own.
//!
//! A table's entry is the registry's own `ROW_BYTES` as the lent policy lays the row out
//! ([`Lent`]), and its count the value of its limit the open resolved, under the build's value
//! ([`Quota::lent_under`]): a stage after the build chooses within the memory the build fixes and
//! never adds to it, so a value over the build's refuses the open.
//!
//! A session holds the dial role's face, a face for each group it joins and as many faces besides
//! as `max_faces` admits, each a link it attaches or accepts, one still in its handshake among them
//! (`Core::accept_face` counts it against `max_faces`): the plan lends a set of a face's tables for
//! each of those and no more. One that listens holds the buffers of as many links again as
//! `accept_pending` admits. The config's two numbers are held to the session's `MAX_FACES` and
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

use wz_runtime_coop::link_storage::LinkTables;
use wz_runtime_coop::reassembly_rx::LENT_CHAINS;
use wz_session_core::bounded::{Arena, BoundedVec, LendRefused, Lent, ARENA_ALIGN};
use wz_session_core::byte_cells::LentByteCells;
use wz_session_core::caps;
use wz_session_core::key_arena::KeySpace;
use wz_session_core::limit_binding::{Quota, UnlentRows};
use wz_session_core::limits::{MaxKeyexprBytesHeld, SessionLimits};
use wz_session_core::peer_tables::{PeerPoolRows, PeerRows, PeerTables, SHARES_ROWS};
use wz_session_core::pubsub::SubscriberTable;
use wz_session_core::reply_sink::{BoxedReplySink, ConsolidatingSink};
use wz_session_core::row_pool::MAX_POOL_ROWS;
use wz_session_core::sink::BoxedSink;
use wz_session_core::slot_observer::{HeapSinks, RequesterRows, Requesters, SlotObserverOf};

use crate::engine::EntryBytes;
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

/// The most rows a plan holds: every row of the build with every feature, and the two of the ABI's
/// handle ([`ArenaPlan::holding`]).
pub const ARENA_ROWS: usize = 30;

/// The slots each link is lent to encode its frames into: one, as zenoh-pico keeps one write buffer
/// (`vendor/zenoh-pico/src/transport/common/tx.c` @
/// `static z_result_t _z_transport_tx_send_t_msg_inner(_z_transport_common_t *ztc, const _z_transport_message_t *t_msg,`).
/// The batch a session holds open is sent before a message that does not join it takes the slot:
/// a transport message drains the open batch first (`send_close_with_reason`, `send_keep_alive`),
/// and a frame of the other reliability closes it. A stream link keeps the slot of a frame it has
/// not written whole until it has, so the next frame asks for room within its message's wait,
/// which writes it (`wait_for_room`), and a message that asks for a slot meanwhile writes it first
/// (`StreamDriver::tx_slot_acquire` in `wz-runtime-coop`).
pub const LINK_TX_SLOTS: usize = 1;

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

/// One face's table of pending gets, as the arena lends it.
type FaceGets = Requesters<ConsolidatingSink<BoxedReplySink>, BoxedReplySink, Lent>;

/// The tables of what a face's peer writes and is owed that a session's arena lends: how many rows
/// each table of one is lent, and how many there are, one for each face the session may hold at
/// once; and how many rows each pool the faces' tables share holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FacePeers {
    /// The rows of each table of one face's.
    pub rows: PeerRows,
    /// How many faces' tables.
    pub tables: usize,
    /// The rows of each pool of what the faces' peers write, which the faces share.
    pub pools: PeerPoolRows,
}

impl EntityRows {
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

/// What a session's arena holds, row by row, in the order the rows are lent from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaPlan {
    rows: [ArenaRow; ARENA_ROWS],
    len: usize,
    /// The links whose buffers the arena holds.
    links: usize,
    /// The length of a link's receive buffer and of each of its slots.
    link_bytes: usize,
    /// The bytes of the session's delivery lane (`crate::lane`).
    lane_bytes: usize,
    /// The length of each buffer a link stages a fragmented message's chain in.
    reassembly_bytes: usize,
    /// How many such buffers, in the one table the session's links share.
    reassembly_chains: usize,
    entities: EntityRows,
    gets: GetTables,
    peers: FacePeers,
    held_queries: usize,
    /// The bytes of blocks of the key arena (`KEY_ARENA_BYTES`).
    key_bytes: usize,
    /// The bytes of the place the ABI keeps its handle of the session in, none for no place
    /// ([`Self::holding`]).
    handle_bytes: usize,
}

impl ArenaPlan {
    /// The rows of a session `config` opens under `limits` (see the module). Refused when a limit
    /// is over the build's value or the arena is past the address space.
    pub fn of(config: &CoopConfig, limits: &SessionLimits) -> Result<Self, ArenaRefused> {
        hold("MAX_FACES", config.max_faces, admitted_faces(limits)?)?;
        if !config.listen.is_empty() {
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
        // The largest message a link rejoins is decided before the lane that hands it on, so a
        // value over the build's is refused under its own name.
        let reassembly_bytes = lent::<{ caps::PICO_FRAG_MAX_BYTES }>(
            "PICO_FRAG_MAX_BYTES",
            limits.pico_frag_max_bytes(),
        )?;
        let mut plan = Self {
            rows: [NO_ROW; ARENA_ROWS],
            len: 0,
            links,
            link_bytes,
            lane_bytes: lent::<{ caps::DELIVERY_LANE_BYTES }>(
                "DELIVERY_LANE_BYTES",
                Quota::at_most(limits.delivery_lane_bytes()),
            )?,
            reassembly_bytes,
            reassembly_chains: LENT_CHAINS,
            entities: EntityRows::default(),
            gets: GetTables::default(),
            peers: FacePeers::default(),
            held_queries: 0,
            key_bytes: lent::<{ caps::KEY_ARENA_BYTES }>(
                "KEY_ARENA_BYTES",
                Quota::at_most(limits.key_arena_bytes()),
            )?,
            handle_bytes: 0,
        };
        let faces = faces_of(config).ok_or(ArenaRefused::TooLarge)?;
        // The links' rows are lent when the session opens, in this order (`SessionArena::lend_links`).
        plan.put(
            "link receive flags",
            "PICO_UNICAST_BATCH_BYTES",
            links,
            LentByteCells::FLAG_BYTES,
        );
        plan.put(
            "link receive buffers",
            "PICO_UNICAST_BATCH_BYTES",
            links,
            link_bytes,
        );
        plan.put(
            "link transmit flags",
            "PICO_UNICAST_BATCH_BYTES",
            links,
            LentByteCells::FLAG_BYTES,
        );
        plan.put(
            "link transmit slots",
            "PICO_UNICAST_BATCH_BYTES",
            links,
            times(LINK_TX_SLOTS, link_bytes)?,
        );
        // The delivery lane's area, lent next (`SessionArena::lend_lane`): one table of one buffer.
        plan.put(
            "delivery lane flag",
            "DELIVERY_LANE_BYTES",
            1,
            LentByteCells::FLAG_BYTES,
        );
        plan.put("delivery lane", "DELIVERY_LANE_BYTES", 1, plan.lane_bytes);
        // The session's reassembly buffers, which its links share, lent next
        // (`SessionArena::lend_reassembly`).
        plan.put(
            "reassembly flags",
            "PICO_FRAG_MAX_BYTES",
            plan.reassembly_chains,
            LentByteCells::FLAG_BYTES,
        );
        plan.put(
            "reassembly buffers",
            "PICO_FRAG_MAX_BYTES",
            plan.reassembly_chains,
            plan.reassembly_bytes,
        );
        plan.put(
            "subscribers",
            "MAX_SUBSCRIPTIONS",
            lent::<{ caps::MAX_SUBSCRIPTIONS }>("MAX_SUBSCRIPTIONS", limits.max_subscriptions())?,
            SubscriberTable::<BoxedSink, Lent>::ROW_BYTES,
        );
        #[cfg(feature = "queryable")]
        plan.put(
            "queryables",
            "MAX_QUERYABLES",
            lent::<{ caps::MAX_QUERYABLES }>("MAX_QUERYABLES", limits.max_queryables())?,
            wz_session_core::query::QueryableRegistry::<
                wz_session_core::query_sink::BoxedQuerySink,
                Lent,
            >::ROW_BYTES,
        );
        #[cfg(feature = "liveliness")]
        {
            plan.put(
                "liveliness tokens",
                "MAX_LOCAL_TOKENS",
                lent::<{ caps::MAX_LOCAL_TOKENS }>("MAX_LOCAL_TOKENS", limits.max_local_tokens())?,
                wz_session_core::declare::local_token::LocalTokenRegistry::<Lent>::ROW_BYTES,
            );
            plan.put(
                "liveliness subscribers",
                "MAX_LIVELINESS_SUBSCRIPTIONS",
                lent::<{ caps::MAX_LIVELINESS_SUBSCRIPTIONS }>(
                    "MAX_LIVELINESS_SUBSCRIPTIONS",
                    limits.max_liveliness_subscriptions(),
                )?,
                wz_session_core::declare::liveliness_subscriber::LivelinessSubscriberTable::<
                    wz_session_core::declare::liveliness_sample::BoxedLivelinessSampleSink,
                    Lent,
                >::ROW_BYTES,
            );
        }
        // The watchers' lists of the application's observer, lent with its tables
        // (`SlotObserverOf::lent`): one row of their spans, as a face's gets are one of theirs.
        let watchers = lent::<{ caps::MAX_DECL_OBSERVERS }>(
            "MAX_DECL_OBSERVERS",
            limits.max_decl_observers(),
        )?;
        plan.put(
            "declaration watchers",
            "MAX_DECL_OBSERVERS",
            1,
            SlotObserverOf::<HeapSinks, Lent>::decl_watcher_bytes(watchers)
                .ok_or(ArenaRefused::TooLarge)?,
        );
        plan.gets = GetTables {
            rows: RequesterRows {
                queries: lent::<{ caps::MAX_PENDING_QUERIES }>(
                    "MAX_PENDING_QUERIES",
                    limits.max_pending_queries(),
                )?,
                liveliness_gets: if cfg!(feature = "liveliness-get") {
                    lent::<{ caps::MAX_PENDING_LIVELINESS_GETS }>(
                        "MAX_PENDING_LIVELINESS_GETS",
                        limits.max_pending_liveliness_gets(),
                    )?
                } else {
                    0
                },
            },
            tables: faces
                .checked_add(usize::from(cfg!(feature = "local-queryable")))
                .ok_or(ArenaRefused::TooLarge)?,
        };
        // A row of tables, each the spans of one face's registries: a face takes one whole.
        plan.put(
            "pending gets",
            "MAX_PENDING_QUERIES + MAX_PENDING_LIVELINESS_GETS",
            plan.gets.tables,
            FaceGets::arena_bytes(plan.gets.rows).ok_or(ArenaRefused::TooLarge)?,
        );
        // The ends of the legs, a row for each get every table holds (`GetTables::legs`).
        #[cfg(feature = "query")]
        plan.put(
            "ended legs",
            "MAX_PENDING_QUERIES + MAX_PENDING_LIVELINESS_GETS",
            plan.gets.legs().ok_or(ArenaRefused::TooLarge)?,
            core::mem::size_of::<u64>(),
        );
        // A row of tables, each what one face's peer is owed: a face takes one whole. What the
        // peers write by their own choice lies in pools the faces share, one area each.
        plan.peers = FacePeers {
            rows: peer_rows(limits)?,
            tables: faces,
            pools: pool_rows(limits, faces)?,
        };
        plan.put(
            "peer tables",
            "MAX_PENDING_DECLARES + MAX_PENDING_FINALS",
            plan.peers.tables,
            PeerTables::<Lent>::arena_bytes(plan.peers.rows).ok_or(ArenaRefused::TooLarge)?,
        );
        // Each kind one area: a pool the faces share, or for a session of one face a span of its
        // tables' own (`pool_rows`); none in a build whose faces keep those rows inline.
        if SHARES_ROWS {
            let pools = plan.peers.pools;
            for (part, kind, bytes) in [
                ("peer alias pool", &ALIAS_LIMITS, pools.alias_bytes()),
                ("peer declaration pools", &DECL_LIMITS, pools.decl_bytes()),
                (
                    "peer interest pool",
                    &INTEREST_LIMITS,
                    pools.interest_bytes(),
                ),
            ] {
                plan.put(part, kind.session, 1, bytes.ok_or(ArenaRefused::TooLarge)?);
            }
        }
        plan.held_queries = if cfg!(feature = "queryable") {
            lent::<{ caps::MAX_PENDING_FINALS }>("MAX_PENDING_FINALS", limits.max_pending_finals())?
        } else {
            0
        };
        plan.entities = entity_rows(limits)?;
        plan.put_entities()?;
        plan.reserved_bytes().ok_or(ArenaRefused::TooLarge)?;
        Ok(plan)
    }

    /// The rows of the engine's own record of the session's declarations ([`EntityRows`]).
    fn put_entities(&mut self) -> Result<(), ArenaRefused> {
        let rows = self.entities;
        self.put(
            "subscriber declarations",
            "MAX_SUBSCRIPTIONS",
            rows.subscribers,
            EntryBytes::SUBSCRIBER,
        );
        #[cfg(feature = "queryable")]
        self.put(
            "queryable declarations",
            "MAX_QUERYABLES",
            rows.queryables,
            EntryBytes::QUERYABLE,
        );
        #[cfg(feature = "liveliness")]
        {
            self.put(
                "token declarations",
                "MAX_LOCAL_TOKENS",
                rows.tokens,
                EntryBytes::TOKEN,
            );
            self.put(
                "liveliness subscriber declarations",
                "MAX_LIVELINESS_SUBSCRIPTIONS",
                rows.liveliness_subscribers,
                EntryBytes::LIVELINESS_SUBSCRIBER,
            );
        }
        self.put(
            "key expressions",
            "MAX_DECLARED_KEYEXPRS",
            rows.keyexprs,
            EntryBytes::KEYEXPR,
        );
        self.put(
            "write filters",
            "MAX_PUBLISHERS + MAX_QUERIERS",
            rows.filters().ok_or(ArenaRefused::TooLarge)?,
            EntryBytes::FILTER,
        );
        self.put(
            "matching listeners",
            "MAX_MATCHING_LISTENERS",
            rows.matching_listeners,
            EntryBytes::MATCH,
        );
        self.put(
            "interests",
            "MAX_PUBLISHERS + MAX_QUERIERS + MAX_MATCHING_LISTENERS",
            rows.interests().ok_or(ArenaRefused::TooLarge)?,
            EntryBytes::INTEREST,
        );
        // The keys of those rows and of every other keyed row of the session, in one area that a
        // key takes a block of as long as it is held (`SessionArena::lend_keys`), not a row of
        // each.
        self.put(
            "key arena",
            "KEY_ARENA_BYTES",
            1,
            KeySpace::span_bytes(self.key_bytes).ok_or(ArenaRefused::TooLarge)?,
        );
        Ok(())
    }

    /// How many rows each table of the engine's record of the session's declarations is lent.
    pub fn entities(&self) -> EntityRows {
        self.entities
    }

    /// The bytes of blocks of the key arena every keyed row of the session keeps its key in
    /// (`KEY_ARENA_BYTES`).
    pub fn key_bytes(&self) -> usize {
        self.key_bytes
    }

    /// The tables of pending gets the arena lends, and the rows of each.
    pub fn gets(&self) -> GetTables {
        self.gets
    }

    /// The tables of what each face's peer writes and is owed the arena lends, and the rows of
    /// each.
    pub fn peers(&self) -> FacePeers {
        self.peers
    }

    /// The length of each buffer a link stages a fragmented message's chain in, and how many
    /// buffers the session's one table holds, which its links share.
    pub fn reassembly(&self) -> (usize, usize) {
        (self.reassembly_bytes, self.reassembly_chains)
    }

    /// How many queries the session holds for its queryables' callbacks at once
    /// (`MAX_PENDING_FINALS`), resolved as the arena's rows are and none in a build without
    /// `queryable`. They are no row of the arena: the query plane holds them in a fixed table of
    /// its own, as it is shared with what answers outside the session's lock.
    pub fn held_queries(&self) -> usize {
        self.held_queries
    }

    /// Add a row. A plan has room for every row of the build with every feature (`ARENA_ROWS`).
    fn put(&mut self, part: &'static str, basis: &'static str, count: usize, entry_bytes: usize) {
        self.rows[self.len] = ArenaRow {
            part,
            basis,
            count,
            entry_bytes,
        };
        self.len += 1;
    }

    /// The plan with a place for the ABI's own handle of the session, of `handle`'s layout, lent
    /// after every other row: the handle then takes no memory of its own, and an open whose arena
    /// cannot hold it reserves nothing, as for any other row. A handle of no bytes takes no place.
    /// Refused as past the address space when the handle asks for more alignment than a span of
    /// the arena starts on ([`ARENA_ALIGN`]), or the arena with it is.
    pub fn holding(mut self, handle: Layout) -> Result<Self, ArenaRefused> {
        if handle.align() > ARENA_ALIGN {
            return Err(ArenaRefused::TooLarge);
        }
        if handle.size() == 0 || self.handle_bytes != 0 {
            return Ok(self);
        }
        self.handle_bytes = handle.size();
        self.put("session handle flag", "", 1, LentByteCells::FLAG_BYTES);
        self.put("session handle", "", 1, handle.size());
        self.reserved_bytes().ok_or(ArenaRefused::TooLarge)?;
        Ok(self)
    }

    /// The bytes of the place the plan holds for the ABI's handle, `0` for none.
    pub fn handle_bytes(&self) -> usize {
        self.handle_bytes
    }

    /// The rows, in the order they are lent.
    pub fn rows(&self) -> &[ArenaRow] {
        &self.rows[..self.len]
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
fn link_batch(config: &CoopConfig, limits: &SessionLimits) -> Result<usize, ArenaRefused> {
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

/// `count` items for each of `each` holders.
fn times(each: usize, count: usize) -> Result<usize, ArenaRefused> {
    each.checked_mul(count).ok_or(ArenaRefused::TooLarge)
}

/// The faces a session `config` opens may hold at once: the dial role's, as many besides as
/// `max_faces` admits, a link still in its handshake among them, and one for each group it joins.
/// `None` past the address space.
fn faces_of(config: &CoopConfig) -> Option<usize> {
    1usize
        .checked_add(config.max_faces)?
        .checked_add(config.groups.len())
}

/// The links a session `config` opens may hold at once: the dial role's, as many besides as
/// `max_faces` admits (each a link it attaches or accepts), and for a listener as many in their
/// handshake as `accept_pending` admits. `None` past the address space. The runtime's task cells
/// are reserved for as many (`engine::RuntimeTables`), a link's session being one task.
pub(crate) fn links_of(config: &CoopConfig) -> Option<usize> {
    let handshakes = if config.listen.is_empty() {
        0
    } else {
        config.accept_pending
    };
    1usize
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

    /// Lend the tables of the links' buffers `plan` lays out, its first rows: a receive buffer and
    /// [`LINK_TX_SLOTS`] slots for each link the session may hold, which the session's links claim
    /// as they open and give back as they go. Refused only by an arena reserved by another plan.
    pub(crate) fn lend_links(&mut self, plan: &ArenaPlan) -> Result<LinkTables, ArenaRefused> {
        let slots = times(LINK_TX_SLOTS, plan.link_bytes)?;
        let rx = self
            .arena
            .lend_byte_cells(plan.link_bytes, plan.links)
            .map_err(ArenaRefused::Lend)?;
        let tx = self
            .arena
            .lend_byte_cells(slots, plan.links)
            .map_err(ArenaRefused::Lend)?;
        Ok(LinkTables::new(rx, tx, plan.link_bytes))
    }

    /// Lend the delivery lane's area `plan` lays out, next after the links' buffers: one buffer of
    /// `DELIVERY_LANE_BYTES`, held by the session's lane for the session's life. Refused only by
    /// an arena reserved by another plan.
    pub(crate) fn lend_lane(
        &mut self,
        plan: &ArenaPlan,
    ) -> Result<(NonNull<u8>, usize), ArenaRefused> {
        let cells = self
            .arena
            .lend_byte_cells(plan.lane_bytes, 1)
            .map_err(ArenaRefused::Lend)?;
        let refused = ArenaRefused::Lend(LendRefused::Exhausted {
            asked: Some(plan.lane_bytes),
            left: 0,
        });
        let buffer = cells.claim().ok_or(refused)?;
        let (base, bytes) = buffer.raw();
        // The claim is never given back: the lane holds the buffer until the session is let go, and
        // a buffer dropped then would write its cell's flag into an arena given back before it.
        core::mem::forget(buffer);
        Ok((NonNull::new(base).ok_or(refused)?, bytes))
    }

    /// Lend the session's reassembly buffers `plan` lays out, next after the lane: a table the
    /// session holds for its life, from which a link claims a buffer when a chain's first fragment
    /// arrives and gives it back when the chain ends. Refused only by an arena reserved by another
    /// plan.
    pub(crate) fn lend_reassembly(
        &mut self,
        plan: &ArenaPlan,
    ) -> Result<LentByteCells, ArenaRefused> {
        self.arena
            .lend_byte_cells(plan.reassembly_bytes, plan.reassembly_chains)
            .map_err(ArenaRefused::Lend)
    }

    /// Lend the key arena `plan` lays out: the area every keyed row of the session keeps its key
    /// in, for the session's life, each key at most `longest` bytes, the session's
    /// `MAX_KEYEXPR_BYTES`. Refused only by an arena reserved by another plan.
    pub(crate) fn lend_keys(
        &mut self,
        plan: &ArenaPlan,
        longest: MaxKeyexprBytesHeld,
    ) -> Result<KeySpace, ArenaRefused> {
        self.arena
            .lend_keys(plan.key_bytes, longest)
            .map_err(ArenaRefused::Lend)
    }

    /// Lend the place for the ABI's handle `plan` holds, its last row: held by the handle for the
    /// session's life and never given back to the arena, as the lane's area is not. `None` for a
    /// plan with no place. Refused only by an arena reserved by another plan.
    pub(crate) fn lend_handle(
        &mut self,
        plan: &ArenaPlan,
    ) -> Result<Option<HandlePlace>, ArenaRefused> {
        if plan.handle_bytes == 0 {
            return Ok(None);
        }
        let cells = self
            .arena
            .lend_byte_cells(plan.handle_bytes, 1)
            .map_err(ArenaRefused::Lend)?;
        let refused = ArenaRefused::Lend(LendRefused::Exhausted {
            asked: Some(plan.handle_bytes),
            left: 0,
        });
        let buffer = cells.claim().ok_or(refused)?;
        let (base, bytes) = buffer.raw();
        // As the lane's: the claim is held for the session's life, and a buffer dropped then would
        // write its cell's flag into an arena given back before it.
        core::mem::forget(buffer);
        Ok(Some(HandlePlace {
            base: NonNull::new(base).ok_or(refused)?,
            bytes,
        }))
    }

    /// Lend a table of `rows` rows, at most `N`, from the arena: the next span of it. Refused,
    /// taking nothing, past `N` or past what is left, which an arena reserved by the plan that
    /// counts the table never is.
    pub(crate) fn lend<T, const N: usize>(
        &mut self,
        rows: usize,
    ) -> Result<BoundedVec<T, N, Lent>, ArenaRefused> {
        self.arena.lend(rows).map_err(ArenaRefused::Lend)
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
