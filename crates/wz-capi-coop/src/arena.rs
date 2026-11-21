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
//!   (`MAX_LOCAL_TOKENS`) and its liveliness subscribers (`MAX_LIVELINESS_SUBSCRIPTIONS`);
//! - one table of the gets pending on a face (`MAX_PENDING_QUERIES`, and with `liveliness-get`
//!   `MAX_PENDING_LIVELINESS_GETS`) for each face the session may hold at once, which a face
//!   takes when it comes and gives back when it goes, and with `local-queryable` one of those
//!   pending on the session's own queryables, which no face holds ([`GetTables`]);
//! - the buffers of each link the session may hold: a receive buffer of the batch the session
//!   advertises, a streamed batch's length counted inside it, and [`LINK_TX_SLOTS`] slots of that
//!   length to encode its frames into, each table with the flags that say which buffers are lent
//!   (`SessionArena::lend_links`). The batch is the config's, under the build's
//!   `PICO_UNICAST_BATCH_BYTES`; these are the rows lent when the session opens, first;
//! - the engine's own record of each declaration it announces and announces again over a new
//!   link ([`EntityRows`]): its subscribers, queryables, tokens and liveliness subscribers under
//!   the limits of the application's tables, the key expressions it declares
//!   (`MAX_DECLARED_KEYEXPRS`), the write filters of its publishers (`MAX_PUBLISHERS`) and
//!   queriers (`MAX_QUERIERS`), its matching listeners (`MAX_MATCHING_LISTENERS`), and the
//!   Interests those filters and listeners hold open, at most one for each of them.
//!
//! A table's entry is the registry's own `ROW_BYTES` as the lent policy lays the row out
//! ([`Lent`]), and its count the value of its limit the open resolved, under the build's value
//! ([`Quota::lent_under`]): a stage after the build chooses within the memory the build fixes and
//! never adds to it, so a value over the build's refuses the open.
//!
//! A session holds the dial role's face, a face for each group it joins and as many faces besides
//! as `max_faces` admits, each a link it attaches or accepts; one that listens holds as many again
//! in their handshake as `accept_pending` admits. A group's face is no link of the session's: it
//! has a row of gets and no buffers. These are the tables whose limits bind at the open
//! (`binding_fixed = "open"`). A link's reassembly, what a face's peer writes and what a group's
//! members rejoin join the plan with the units that lend them from the arena and bound them by
//! limits of their own (`docs/c-abi-no-heap-pools.md`, sections 4.5, 4.9 and 4.14): reserved
//! before then, they would be memory nothing uses, and a link's reassembly is sized by
//! `max_message_size`, which upstream's default leaves at a gibibyte.
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
use wz_session_core::bounded::{Arena, BoundedVec, LendRefused, Lent, ARENA_ALIGN};
use wz_session_core::byte_cells::LentByteCells;
use wz_session_core::caps;
use wz_session_core::limit_binding::{Quota, UnlentRows};
use wz_session_core::limits::SessionLimits;
use wz_session_core::pubsub::SubscriberTable;
use wz_session_core::reply_sink::{BoxedReplySink, ConsolidatingSink};
use wz_session_core::sink::BoxedSink;
use wz_session_core::slot_observer::{RequesterRows, Requesters};

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

/// The most rows a plan holds: every row of the build with every feature.
pub const ARENA_ROWS: usize = 17;

/// The slots each link is lent to encode its frames into: a batching session holds a batch open in
/// one slot while it encodes the next message, which does not join it, into another.
pub const LINK_TX_SLOTS: usize = 2;

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

/// One face's table of pending gets, as the arena lends it.
type FaceGets = Requesters<ConsolidatingSink<BoxedReplySink>, BoxedReplySink, Lent>;

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
    entities: EntityRows,
    gets: GetTables,
}

impl ArenaPlan {
    /// The rows of a session `config` opens under `limits` (see the module). Refused when a limit
    /// is over the build's value or the arena is past the address space.
    pub fn of(config: &CoopConfig, limits: &SessionLimits) -> Result<Self, ArenaRefused> {
        let links = links_of(config).ok_or(ArenaRefused::TooLarge)?;
        let batch = lent(
            "PICO_UNICAST_BATCH_BYTES",
            Quota::at_most(usize::from(config.batch_size)),
            caps::PICO_UNICAST_BATCH_BYTES,
        )?;
        // A buffer and a slot of the batch hold a whole batch of either link: a stream link's
        // length is counted inside the batch it negotiates (`STREAM_BATCH_LENGTH_BYTES`).
        let link_bytes = batch;
        let mut plan = Self {
            rows: [NO_ROW; ARENA_ROWS],
            len: 0,
            links,
            link_bytes,
            entities: EntityRows::default(),
            gets: GetTables::default(),
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
        plan.put(
            "subscribers",
            "MAX_SUBSCRIPTIONS",
            lent(
                "MAX_SUBSCRIPTIONS",
                limits.max_subscriptions(),
                caps::MAX_SUBSCRIPTIONS,
            )?,
            SubscriberTable::<BoxedSink, Lent>::ROW_BYTES,
        );
        #[cfg(feature = "queryable")]
        plan.put(
            "queryables",
            "MAX_QUERYABLES",
            lent(
                "MAX_QUERYABLES",
                limits.max_queryables(),
                caps::MAX_QUERYABLES,
            )?,
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
                lent(
                    "MAX_LOCAL_TOKENS",
                    limits.max_local_tokens(),
                    caps::MAX_LOCAL_TOKENS,
                )?,
                wz_session_core::declare::local_token::LocalTokenRegistry::<Lent>::ROW_BYTES,
            );
            plan.put(
                "liveliness subscribers",
                "MAX_LIVELINESS_SUBSCRIPTIONS",
                lent(
                    "MAX_LIVELINESS_SUBSCRIPTIONS",
                    limits.max_liveliness_subscriptions(),
                    caps::MAX_LIVELINESS_SUBSCRIPTIONS,
                )?,
                wz_session_core::declare::liveliness_subscriber::LivelinessSubscriberTable::<
                    wz_session_core::declare::liveliness_sample::BoxedLivelinessSampleSink,
                    Lent,
                >::ROW_BYTES,
            );
        }
        plan.gets = GetTables {
            rows: RequesterRows {
                queries: lent(
                    "MAX_PENDING_QUERIES",
                    limits.max_pending_queries(),
                    caps::MAX_PENDING_QUERIES,
                )?,
                liveliness_gets: if cfg!(feature = "liveliness-get") {
                    lent(
                        "MAX_PENDING_LIVELINESS_GETS",
                        limits.max_pending_liveliness_gets(),
                        caps::MAX_PENDING_LIVELINESS_GETS,
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
        Ok(())
    }

    /// How many rows each table of the engine's record of the session's declarations is lent.
    pub fn entities(&self) -> EntityRows {
        self.entities
    }

    /// The tables of pending gets the arena lends, and the rows of each.
    pub fn gets(&self) -> GetTables {
        self.gets
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

/// The rows a table of the limit `limit` is lent: `value`, the open's, under `build`, the build's.
fn lent(limit: &'static str, value: Quota, build: usize) -> Result<usize, ArenaRefused> {
    value
        .lent_under(Quota::at_most(build))
        .map_err(|why| ArenaRefused::Limit { limit, why })
}

/// The rows of each table of the engine's record of the session's declarations, under `limits`.
fn entity_rows(limits: &SessionLimits) -> Result<EntityRows, ArenaRefused> {
    Ok(EntityRows {
        subscribers: lent(
            "MAX_SUBSCRIPTIONS",
            limits.max_subscriptions(),
            caps::MAX_SUBSCRIPTIONS,
        )?,
        queryables: if cfg!(feature = "queryable") {
            lent(
                "MAX_QUERYABLES",
                limits.max_queryables(),
                caps::MAX_QUERYABLES,
            )?
        } else {
            0
        },
        tokens: if cfg!(feature = "liveliness") {
            lent(
                "MAX_LOCAL_TOKENS",
                limits.max_local_tokens(),
                caps::MAX_LOCAL_TOKENS,
            )?
        } else {
            0
        },
        liveliness_subscribers: if cfg!(feature = "liveliness") {
            lent(
                "MAX_LIVELINESS_SUBSCRIPTIONS",
                limits.max_liveliness_subscriptions(),
                caps::MAX_LIVELINESS_SUBSCRIPTIONS,
            )?
        } else {
            0
        },
        keyexprs: lent(
            "MAX_DECLARED_KEYEXPRS",
            limits.max_declared_keyexprs(),
            caps::MAX_DECLARED_KEYEXPRS,
        )?,
        publishers: lent(
            "MAX_PUBLISHERS",
            limits.max_publishers(),
            caps::MAX_PUBLISHERS,
        )?,
        queriers: lent("MAX_QUERIERS", limits.max_queriers(), caps::MAX_QUERIERS)?,
        matching_listeners: lent(
            "MAX_MATCHING_LISTENERS",
            limits.max_matching_listeners(),
            caps::MAX_MATCHING_LISTENERS,
        )?,
    })
}

/// `count` items for each of `each` holders.
fn times(each: usize, count: usize) -> Result<usize, ArenaRefused> {
    each.checked_mul(count).ok_or(ArenaRefused::TooLarge)
}

/// The faces a session `config` opens may hold at once: its links ([`links_of`]) and one for each
/// group it joins. `None` past the address space.
fn faces_of(config: &CoopConfig) -> Option<usize> {
    links_of(config)?.checked_add(config.groups.len())
}

/// The links a session `config` opens may hold at once: the dial role's, as many besides as
/// `max_faces` admits (each a link it attaches or accepts), and for a listener as many in their
/// handshake as `accept_pending` admits. `None` past the address space.
fn links_of(config: &CoopConfig) -> Option<usize> {
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

    /// Reserve an arena of `bytes` from `memory`: what a session takes past its plan when the
    /// thing it is for comes (a face attached beyond the faces the open planned for). Refused,
    /// having taken nothing, when the memory has none to give.
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
