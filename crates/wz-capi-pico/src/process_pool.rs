// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The process pools: the places of the objects a program holds through this ABI that no session
//! holds for it, reserved once for the whole process, so that a program which made its first
//! object makes no allocation for them while it runs.
//!
//! # What they hold
//!
//! Each kind of object has a pool of its own (`crate::object_slot::Kind`): the objects behind the
//! owned handles (on the tokio engine its sessions, publishers, subscribers, queryables,
//! liveliness tokens, liveliness subscribers and queriers, and the samples, replies, queries,
//! payloads and encodings a program holds), and what a program makes before any session: its
//! configs and the hellos it keeps. Beside them lie three pools of payload blocks: the bytes the
//! owned payloads, strings and slices carry, each in a block of the smallest of the three whose
//! blocks hold it and that has one free ([`PAYLOAD_BLOCKS`]). Every pool is one of fixed blocks,
//! taken from its list of free blocks and given back to the pool its address lies in, by the same
//! code for an object and for a payload's bytes. A session of the cooperative
//! engine lies in its own arena, not here, and so do its entities, each in a place its open laid
//! out under the session's own limit (`crate::object_slot::held_places`): a count of the pools'
//! for an entity does not apply there.
//!
//! The pools are in every library without the tokio engine, the C library's form with no heap, and
//! in one with it that has the doors which let a program reserve them itself (`object-pool`,
//! `crate::object_pool`). The build script says which (`wz_process_pools`); a library of the
//! tokio engine without the doors places its objects on the heap, as its sessions allocate.
//!
//! # Reserving
//!
//! The pools are reserved once, by the first object the program makes, from the build's limits
//! (`docs/c-abi-engine-and-memory.md`, decision Q1), in one allocation: an existing program runs
//! unchanged, and a pico program's first object is the config it opens its first session from, so
//! the reservation is made before any session opens. The build's counts are `HELD_SESSIONS`
//! sessions, each holding as many entities as the session limits the library opens under admit
//! within the build's values (`MAX_PUBLISHERS`, `MAX_SUBSCRIPTIONS`, `MAX_QUERYABLES`,
//! `MAX_LOCAL_TOKENS`, `MAX_LIVELINESS_SUBSCRIPTIONS`, and for the gets it holds pending
//! `MAX_PENDING_QUERIES` and `MAX_PENDING_LIVELINESS_GETS`), `HELD_SAMPLES`, `HELD_REPLIES`,
//! `HELD_QUERIES`, `HELD_PAYLOADS` and `HELD_ENCODINGS` of the values it holds, `HELD_CONFIGS`
//! configs, `HELD_HELLOS` kept hellos, and `HELD_SMALL_PAYLOAD_BLOCKS`,
//! `HELD_MEDIUM_PAYLOAD_BLOCKS` and `HELD_LARGE_PAYLOAD_BLOCKS` payload blocks. A program that
//! states its own counts reserves them before its first object through the doors instead.
//!
//! # The counts and the limits of a session
//!
//! A session's entities are bounded by the limits it opens under: its subscribers by
//! `MAX_SUBSCRIPTIONS`, its queryables by `MAX_QUERYABLES`, its liveliness tokens by
//! `MAX_LOCAL_TOKENS` and its liveliness subscribers by `MAX_LIVELINESS_SUBSCRIPTIONS`. A count of
//! one of those left at zero takes the bound of its limit, and a count stated above the bound is
//! held to it: the session refuses the one more anyway, so a slot past it would never be used. A
//! count left at zero whose limit holds no bound is refused, as a pool of no bound cannot be
//! reserved. The count of an entity is per session, times `sessions`. The objects no limit bounds
//! are as stated, zero being none. A count of an object the build has none of is not read.
//!
//! # Running
//!
//! Each kind of object has a pool of its own, of as many slots as its count: the pool of one kind
//! never lends a slot to another, so each holds what was stated for it and no more, whatever
//! another kind of the same size has free. A slot is its object's own size, rounded up to the
//! alignment of a slot: the size classes group the pools for the reports and size no slot. A pool
//! with no free slot refuses the object: the
//! call answers `_Z_ERR_SYSTEM_OUT_OF_MEMORY` having made, declared or opened nothing, and the
//! refusal is counted. Nothing falls back to the heap: when the build's pools cannot be reserved
//! either, the object is refused the same way. An object let go frees its slot for the next one,
//! from any thread: every pool is reached under the port's lock.

use core::alloc::Layout;
use core::ptr::NonNull;

use wz_capi_port::sync::Lock;
use wz_session_core::caps;
use wz_session_core::limit_binding::Quota;
use wz_session_core::limits::SessionLimits;

use crate::object_slot::Kind;

/// How many slot sizes the pools are reported by, the smallest 16 bytes and each one twice the one
/// before, up to 16 KiB.
pub(crate) const CLASSES: usize = 11;

/// The slots of the smallest size, in bytes.
const SMALLEST_SLOT: usize = 16;

/// The alignment of every slot: the most any object of this ABI asks for, which the build checks
/// for each one it pools.
pub(crate) const SLOT_ALIGN: usize = 16;

/// How many pools of payload blocks there are: a small, a middle and a largest size.
pub(crate) const PAYLOAD_CLASSES: usize = 3;

/// The largest message a session of the build hands a program: one rejoined from fragments, or
/// one that arrives whole in a batch of either kind, which no rejoining ceiling measures.
const LARGEST_MESSAGE: usize = larger(
    larger(caps::PICO_FRAG_MAX_BYTES, caps::PICO_UNICAST_BATCH_BYTES),
    caps::PICO_MULTICAST_BATCH_BYTES,
);

/// The most bytes a sample a session hands a program lends it, which a copy kept past its
/// callback takes ONE block for (`crate::pubsub::SampleMarshal::write_copy`): its payload, its
/// attachment and its encoding's schema are bytes of the one message it arrived in, and its key is
/// at most a key the session holds (`MAX_KEYEXPR_BYTES`), or a declared one of at most that which
/// the message's own bytes extend.
const LARGEST_SAMPLE: usize = LARGEST_MESSAGE.saturating_add(caps::MAX_KEYEXPR_BYTES);

/// The bytes of each block of the largest pool of payload blocks: the largest sample and the head
/// of the block it lies in, so every payload a session hands a program, and every sample it hands
/// one kept whole, has a block that holds it, whatever the counts.
pub(crate) const LARGEST_BLOCK: usize = block_of(LARGEST_SAMPLE.saturating_add(crate::bytes::HEAD));

/// The bytes of each block of the three pools of payload blocks, in the order their counts are
/// stated: the two the limits state, and the largest.
const PAYLOAD_BLOCKS: [usize; PAYLOAD_CLASSES] = [
    block_of(caps::PAYLOAD_SMALL_BLOCK_BYTES),
    block_of(caps::PAYLOAD_MEDIUM_BLOCK_BYTES),
    LARGEST_BLOCK,
];

/// The larger of `a` and `b`, in a constant.
const fn larger(a: usize, b: usize) -> usize {
    if a < b {
        b
    } else {
        a
    }
}

/// A block of at least `bytes` bytes: rounded up to the alignment of a slot, and at least one
/// alignment, as a free block holds the link to the next. A size the address space cannot round is
/// held at its largest multiple, which no plan's bytes then hold.
const fn block_of(bytes: usize) -> usize {
    match bytes.checked_next_multiple_of(SLOT_ALIGN) {
        Some(block) if block >= SLOT_ALIGN => block,
        Some(_) => SLOT_ALIGN,
        None => usize::MAX ^ SLOT_ALIGN.wrapping_sub(1),
    }
}

/// How many of each object the pools hold. Before [`resolve`] they are what a program or the build
/// states, the entity counts per session; after it, for all sessions together.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counts {
    pub(crate) sessions: usize,
    pub(crate) publishers: usize,
    pub(crate) subscribers: usize,
    pub(crate) queryables: usize,
    pub(crate) liveliness_tokens: usize,
    pub(crate) liveliness_subscribers: usize,
    pub(crate) samples: usize,
    pub(crate) replies: usize,
    pub(crate) queries: usize,
    /// Owned payloads: the places of their handles.
    pub(crate) bytes: usize,
    pub(crate) configs: usize,
    /// Hellos a program keeps (`z_hello_clone`).
    pub(crate) hellos: usize,
    /// Queriers of each session.
    pub(crate) queriers: usize,
    /// Key expressions of each session a program holds declared (`z_declare_keyexpr`).
    pub(crate) keyexprs: usize,
    /// The blocks of each pool of payload blocks, small, middle and largest
    /// ([`PAYLOAD_BLOCKS`]).
    pub(crate) payload_blocks: [usize; PAYLOAD_CLASSES],
    /// Owned encodings, each with room for a schema of `MAX_ENCODING_SCHEMA_BYTES`.
    pub(crate) encodings: usize,
    /// Gets each session holds pending, its queriers' among them.
    pub(crate) gets: usize,
    /// Liveliness gets each session holds pending.
    pub(crate) liveliness_gets: usize,
    /// Matching listeners of each session, its publishers' and queriers' together.
    pub(crate) matching_listeners: usize,
    /// Declaration watches of each session.
    pub(crate) decl_watches: usize,
    /// Transport events listeners of each session.
    pub(crate) transport_events_listeners: usize,
    /// Advanced publishers of each session.
    pub(crate) advanced_publishers: usize,
    /// Advanced subscribers of each session, owned and background.
    pub(crate) advanced_subscribers: usize,
    /// Link events listeners of each session.
    pub(crate) link_events_listeners: usize,
}

/// The bytes of each slot of size class `class`.
pub(crate) const fn slot_bytes(class: usize) -> usize {
    SMALLEST_SLOT << class
}

/// The size class of an object of `size` bytes aligned to `align`: the smallest slot that holds
/// it, or none.
pub(crate) const fn class_of(size: usize, align: usize) -> Option<usize> {
    if align > SLOT_ALIGN || size > slot_bytes(CLASSES - 1) {
        return None;
    }
    // The slots double from the smallest, so the class is how many times the smallest power of two
    // that holds the object doubles the smallest slot.
    let slot = if size < SMALLEST_SLOT {
        SMALLEST_SLOT
    } else {
        size.next_power_of_two()
    };
    Some((slot / SMALLEST_SLOT).trailing_zeros() as usize)
}

/// The bytes of each slot of the pool of a `T`: its own size rounded up to the alignment of a
/// slot, and one alignment for an object of no bytes, as a free slot holds the link to the next. A
/// kind's pool lends its slots to no other kind, so a slot larger than its object would hold
/// nothing more. An object aligned past a slot fails the build rather than a reservation.
const fn slot_size<T>() -> usize {
    const {
        assert!(
            core::mem::align_of::<T>() <= SLOT_ALIGN,
            "an object of the ABI is aligned past a slot of the process pools"
        )
    };
    let size = core::mem::size_of::<T>();
    if size == 0 {
        SLOT_ALIGN
    } else {
        size.next_multiple_of(SLOT_ALIGN)
    }
}

/// Where the pools of slots of `size` bytes are counted: their size class, or `CLASSES` for slots
/// past the largest, which no class reports.
const fn count_of(size: usize) -> usize {
    match class_of(size, 1) {
        Some(class) => class,
        None => CLASSES,
    }
}

/// Why counts make no pools.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unplanned {
    /// A count left at zero whose limit holds no bound.
    Unbounded,
    /// More slots, or more bytes, than the address space holds.
    TooLarge,
    /// No slot at all.
    Empty,
}

/// The bounds the limits of a session put on its entities, `None` where a limit holds none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bounds {
    subscribers: Option<usize>,
    queryables: Option<usize>,
    liveliness_tokens: Option<usize>,
    liveliness_subscribers: Option<usize>,
    queriers: Option<usize>,
    keyexprs: Option<usize>,
    gets: Option<usize>,
    liveliness_gets: Option<usize>,
    matching_listeners: Option<usize>,
    decl_watches: Option<usize>,
    transport_events_listeners: Option<usize>,
    advanced_publishers: Option<usize>,
    advanced_subscribers: Option<usize>,
    link_events_listeners: Option<usize>,
}

impl Bounds {
    /// The bounds `limits` holds.
    #[cfg(any(test, feature = "object-pool"))]
    pub(crate) fn of(limits: &SessionLimits) -> Self {
        Self {
            subscribers: limits.max_subscriptions().most(),
            queryables: limits.max_queryables().most(),
            liveliness_tokens: limits.max_local_tokens().most(),
            liveliness_subscribers: limits.max_liveliness_subscriptions().most(),
            queriers: limits.max_queriers().most(),
            keyexprs: limits.max_declared_keyexprs().most(),
            gets: limits.max_pending_queries().most(),
            liveliness_gets: limits.max_pending_liveliness_gets().most(),
            matching_listeners: limits.max_matching_listeners().most(),
            decl_watches: limits.max_decl_watches().most(),
            transport_events_listeners: limits.max_transport_events_listeners().most(),
            advanced_publishers: limits.max_advanced_publishers().most(),
            advanced_subscribers: limits.max_advanced_subscribers().most(),
            link_events_listeners: limits.max_link_events_listeners().most(),
        }
    }
}

/// `?` for the planning functions, which are `const` so that the build's plan is worked out
/// when the library is compiled ([`BUILT_PLAN`]) and `?` is not.
macro_rules! planned {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(unplanned) => return Err(unplanned),
        }
    };
}

/// `each` of an entity for every one of `sessions` sessions.
const fn per_session(each: usize, sessions: usize) -> Result<usize, Unplanned> {
    match each.checked_mul(sessions) {
        Some(all) => Ok(all),
        None => Err(Unplanned::TooLarge),
    }
}

/// How many of an entity the pools hold for `sessions` sessions: `stated` held to `bound`, the
/// bound itself for a count left at zero. A build without the plane (`has` false) holds none,
/// whatever its limit says.
const fn bounded(
    has: bool,
    sessions: usize,
    stated: usize,
    bound: Option<usize>,
) -> Result<usize, Unplanned> {
    if !has || sessions == 0 {
        return Ok(0);
    }
    let each = match (stated, bound) {
        (0, Some(bound)) => bound,
        (0, None) => return Err(Unplanned::Unbounded),
        (stated, Some(bound)) => {
            if stated < bound {
                stated
            } else {
                bound
            }
        }
        (stated, None) => stated,
    };
    per_session(each, sessions)
}

/// The objects the pools hold, for all sessions together: each count read against the bounds of
/// the limits of a session, the entity counts times the sessions.
pub(crate) const fn resolve(stated: &Counts, bounds: &Bounds) -> Result<Counts, Unplanned> {
    let sessions = stated.sessions;
    Ok(Counts {
        sessions,
        publishers: planned!(per_session(stated.publishers, sessions)),
        subscribers: planned!(bounded(
            true,
            sessions,
            stated.subscribers,
            bounds.subscribers
        )),
        queryables: planned!(bounded(
            cfg!(feature = "queryable"),
            sessions,
            stated.queryables,
            bounds.queryables,
        )),
        liveliness_tokens: planned!(bounded(
            cfg!(feature = "liveliness"),
            sessions,
            stated.liveliness_tokens,
            bounds.liveliness_tokens,
        )),
        liveliness_subscribers: planned!(bounded(
            cfg!(feature = "liveliness"),
            sessions,
            stated.liveliness_subscribers,
            bounds.liveliness_subscribers,
        )),
        samples: stated.samples,
        replies: stated.replies,
        queries: stated.queries,
        bytes: stated.bytes,
        configs: stated.configs,
        hellos: if cfg!(any(feature = "scout", feature = "scout-mcu")) {
            stated.hellos
        } else {
            0
        },
        queriers: planned!(bounded(
            cfg!(feature = "query"),
            sessions,
            stated.queriers,
            bounds.queriers,
        )),
        keyexprs: planned!(bounded(true, sessions, stated.keyexprs, bounds.keyexprs)),
        payload_blocks: stated.payload_blocks,
        encodings: stated.encodings,
        gets: planned!(bounded(
            cfg!(feature = "query"),
            sessions,
            stated.gets,
            bounds.gets,
        )),
        liveliness_gets: planned!(bounded(
            cfg!(feature = "liveliness-get"),
            sessions,
            stated.liveliness_gets,
            bounds.liveliness_gets,
        )),
        matching_listeners: planned!(bounded(
            true,
            sessions,
            stated.matching_listeners,
            bounds.matching_listeners,
        )),
        decl_watches: planned!(bounded(
            cfg!(any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            )),
            sessions,
            stated.decl_watches,
            bounds.decl_watches,
        )),
        transport_events_listeners: planned!(bounded(
            cfg!(feature = "connectivity"),
            sessions,
            stated.transport_events_listeners,
            bounds.transport_events_listeners,
        )),
        advanced_publishers: planned!(bounded(
            cfg!(feature = "advanced"),
            sessions,
            stated.advanced_publishers,
            bounds.advanced_publishers,
        )),
        advanced_subscribers: planned!(bounded(
            cfg!(feature = "advanced"),
            sessions,
            stated.advanced_subscribers,
            bounds.advanced_subscribers,
        )),
        link_events_listeners: planned!(bounded(
            cfg!(feature = "connectivity"),
            sessions,
            stated.link_events_listeners,
            bounds.link_events_listeners,
        )),
    })
}

/// How many kinds of object have a pool: the variants of `Kind`, those a build has none of
/// included, so each keeps its index in every build.
const KINDS: usize = 23;

/// How many pools there are: one for each kind, then the pools of payload blocks, smallest first.
const POOLS: usize = KINDS + PAYLOAD_CLASSES;

/// Write `value` into the element of `row` at `at`, reached by walking the row from its first
/// element, so no write names an index. A row has no element past its end to write; a plan's rows
/// hold one per pool, which `POOLS` counts, so a kind's index is always in them.
const fn put(row: &mut [usize], at: usize, value: usize) {
    let mut rest = row;
    let mut left = at;
    while let [first, more @ ..] = rest {
        match left.checked_sub(1) {
            None => {
                *first = value;
                return;
            }
            Some(next) => {
                left = next;
                rest = more;
            }
        }
    }
}

/// Each pool, its slots and the bytes of each: one for each kind, then the pools of payload
/// blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    slots: [usize; POOLS],
    sizes: [usize; POOLS],
}

impl Plan {
    /// The pools `objects` make: one per kind, each slot of the size of that kind's object.
    pub(crate) const fn of(objects: &Counts) -> Result<Self, Unplanned> {
        let mut plan = Self {
            slots: [0; POOLS],
            sizes: [0; POOLS],
        }
        .with_payloads(&objects.payload_blocks);
        // A session of the cooperative engine lies in its own arena; its pool is the program's to
        // reserve where the doors are.
        #[cfg(any(feature = "engine-tokio", feature = "object-pool"))]
        {
            plan = plan.with::<crate::session::SessionPlace>(Kind::Session, objects.sessions);
        }
        // An entity of the cooperative engine lies in its own session's arena, as many as the
        // limit that session opened under admits (`crate::object_slot::held_places`): a pool of
        // the process's would let one session's entities spend another's.
        #[cfg(feature = "engine-tokio")]
        {
            plan = plan.with::<crate::pubsub::PublisherState>(Kind::Publisher, objects.publishers);
            plan =
                plan.with::<crate::pubsub::SubscriberPlace>(Kind::Subscriber, objects.subscribers);
        }
        #[cfg(all(feature = "engine-tokio", feature = "queryable"))]
        {
            plan = plan.with::<crate::query::QueryablePlace>(Kind::Queryable, objects.queryables);
        }
        #[cfg(all(feature = "engine-tokio", feature = "liveliness"))]
        {
            plan = plan.with::<crate::liveliness::TokenState>(
                Kind::LivelinessToken,
                objects.liveliness_tokens,
            );
            plan = plan.with::<crate::pubsub::SubscriberPlace>(
                Kind::LivelinessSubscriber,
                objects.liveliness_subscribers,
            );
        }
        plan = plan.with::<crate::pubsub::SampleMarshal>(Kind::Sample, objects.samples);
        #[cfg(feature = "query")]
        {
            plan = plan.with::<crate::get::ReplyMarshal>(Kind::Reply, objects.replies);
        }
        #[cfg(feature = "queryable")]
        {
            plan = plan.with::<crate::query::QueryMarshal>(Kind::Query, objects.queries);
        }
        plan = plan.with::<crate::bytes::ByteBuf>(Kind::Bytes, objects.bytes);
        plan = plan.with::<crate::config::ConfigState>(Kind::Config, objects.configs);
        #[cfg(any(feature = "scout", feature = "scout-mcu"))]
        {
            plan = plan.with::<crate::scout::KeptHello>(Kind::Hello, objects.hellos);
        }
        #[cfg(all(feature = "engine-tokio", feature = "query"))]
        {
            plan = plan.with::<crate::object_slot::Answering<crate::querier::QuerierState>>(
                Kind::Querier,
                objects.queriers,
            );
        }
        plan = plan.with::<crate::keyexpr::DeclaredKeyexpr>(Kind::Keyexpr, objects.keyexprs);
        plan = plan.with::<crate::encoding::HeldEncoding>(Kind::Encoding, objects.encodings);
        #[cfg(all(feature = "engine-tokio", feature = "query"))]
        {
            plan = plan.with::<crate::get::GetPlace>(Kind::Get, objects.gets);
        }
        #[cfg(all(feature = "engine-tokio", feature = "liveliness-get"))]
        {
            plan = plan.with::<crate::get::GetPlace>(Kind::LivelinessGet, objects.liveliness_gets);
        }
        #[cfg(feature = "engine-tokio")]
        {
            plan = plan.with::<crate::matching::MatchingPlace>(
                Kind::MatchingListener,
                objects.matching_listeners,
            );
        }
        #[cfg(all(
            feature = "engine-tokio",
            any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            )
        ))]
        {
            plan =
                plan.with::<crate::decl_watch::WatchPlace>(Kind::DeclWatch, objects.decl_watches);
        }
        #[cfg(all(feature = "engine-tokio", feature = "connectivity"))]
        {
            plan = plan.with::<crate::connectivity::TransportPlace>(
                Kind::TransportEventsListener,
                objects.transport_events_listeners,
            );
        }
        #[cfg(all(feature = "engine-tokio", feature = "advanced"))]
        {
            plan = plan.with::<crate::advanced::AdvPubState>(
                Kind::AdvancedPublisher,
                objects.advanced_publishers,
            );
            plan = plan.with::<crate::advanced::AdvSubPlace>(
                Kind::AdvancedSubscriber,
                objects.advanced_subscribers,
            );
        }
        #[cfg(all(feature = "engine-tokio", feature = "connectivity"))]
        {
            plan = plan.with::<crate::connectivity::LinkPlace>(
                Kind::LinkEventsListener,
                objects.link_events_listeners,
            );
        }
        let mut holds = false;
        let mut rest: &[usize] = &plan.slots;
        while let [slots, tail @ ..] = rest {
            holds |= *slots != 0;
            rest = tail;
        }
        if !holds {
            return Err(Unplanned::Empty);
        }
        planned!(plan.bytes());
        Ok(plan)
    }

    /// This plan with the pool of `kind`: `count` slots, each of the bytes a slot for a `T` takes.
    const fn with<T>(mut self, kind: Kind, count: usize) -> Self {
        put(&mut self.slots, kind as usize, count);
        put(&mut self.sizes, kind as usize, const { slot_size::<T>() });
        self
    }

    /// This plan with the pools of payload blocks after the kinds', `blocks` of each size of
    /// [`PAYLOAD_BLOCKS`], laid smallest first: a payload's walk over them meets the smallest that
    /// holds it first, whatever order the limits state the sizes in.
    const fn with_payloads(mut self, blocks: &[usize; PAYLOAD_CLASSES]) -> Self {
        let [small, middle, largest] = *blocks;
        let [small_bytes, middle_bytes, largest_bytes] = PAYLOAD_BLOCKS;
        let pools = ascending([
            (small_bytes, small),
            (middle_bytes, middle),
            (largest_bytes, largest),
        ]);
        let mut at = KINDS;
        let mut rest: &[(usize, usize)] = &pools;
        while let [(size, count), tail @ ..] = rest {
            put(&mut self.slots, at, *count);
            put(&mut self.sizes, at, *size);
            at = at.saturating_add(1);
            rest = tail;
        }
        self
    }

    /// The bytes every pool's slots take together.
    const fn slot_bytes(&self) -> Result<usize, Unplanned> {
        let mut total: usize = 0;
        let mut pools: (&[usize], &[usize]) = (&self.slots, &self.sizes);
        while let ([slots, slots_rest @ ..], [size, sizes_rest @ ..]) = pools {
            total = match slots.checked_mul(*size) {
                Some(bytes) => match total.checked_add(bytes) {
                    Some(total) => total,
                    None => return Err(Unplanned::TooLarge),
                },
                None => return Err(Unplanned::TooLarge),
            };
            pools = (slots_rest, sizes_rest);
        }
        Ok(total)
    }

    /// The bytes the pools take together.
    pub(crate) const fn bytes(&self) -> Result<usize, Unplanned> {
        self.slot_bytes()
    }
}

/// The three pools of payload blocks, each a block's bytes and its count, ordered by the bytes.
const fn ascending(pools: [(usize, usize); PAYLOAD_CLASSES]) -> [(usize, usize); PAYLOAD_CLASSES] {
    let [a, b, c] = pools;
    let (a, b) = if b.0 < a.0 { (b, a) } else { (a, b) };
    let (b, c) = if c.0 < b.0 { (c, b) } else { (b, c) };
    let (a, b) = if b.0 < a.0 { (b, a) } else { (a, b) };
    [a, b, c]
}

/// Where the memory of the pools came from, and so what giving them up does with it.
#[derive(Clone, Copy, Debug)]
enum Origin {
    /// The heap's, one allocation of this layout, freed when the pools are given up.
    Heap(Layout),
    /// The program's, handed back untouched when the pools are given up.
    #[cfg(any(test, feature = "object-pool-region"))]
    Program,
}

impl Origin {
    /// Let go of the memory at `base` as its origin says.
    ///
    /// # Safety
    /// `base` is the memory this origin describes, and nothing uses it after.
    unsafe fn free(self, base: NonNull<u8>) {
        match self {
            Origin::Heap(layout) => alloc::alloc::dealloc(base.as_ptr(), layout),
            #[cfg(any(test, feature = "object-pool-region"))]
            Origin::Program => {}
        }
    }
}

/// The pool of one kind: where its slots start, their bytes, how many of them were ever handed
/// out, and the slots given back, linked through their first word.
///
/// A slot never handed out is not on the list: the pool hands out its untouched slots in order
/// after the list is empty, so laying the pools out writes nothing into their slots and the
/// reservation is not a pass over every slot of every kind.
#[derive(Clone, Copy, Debug)]
struct Pool {
    /// The offset of its first slot from the start of the memory.
    start: usize,
    slots: usize,
    size: usize,
    /// The slots handed out at least once: the next untouched slot is this one.
    fresh: usize,
    free: Option<NonNull<u8>>,
}

impl Pool {
    /// A free slot of this pool, or `None` when it has none: a slot given back before an untouched
    /// one, and the untouched ones lowest first. Counted by its caller.
    ///
    /// # Safety
    /// The pool was laid over the memory at `base`.
    unsafe fn take(&mut self, base: NonNull<u8>) -> Option<NonNull<u8>> {
        if let Some(slot) = self.free {
            // SAFETY: the first word of a slot on the list is the link to the next one, written
            // when it was given back.
            self.free = unsafe { slot.as_ptr().cast::<Option<NonNull<u8>>>().read() };
            return Some(slot);
        }
        if self.fresh >= self.slots {
            return None;
        }
        // SAFETY: an untouched slot lies within the pool's slots, inside the memory the pools were
        // laid over, which is not null; the plan counted those bytes with checked arithmetic, so
        // the slot's offset does not saturate.
        let slot = unsafe {
            NonNull::new_unchecked(
                base.as_ptr()
                    .add(self.start)
                    .add(self.fresh.saturating_mul(self.size)),
            )
        };
        self.fresh = self.fresh.saturating_add(1);
        Some(slot)
    }
}

/// What the pools of one size class have done together; the pools past the largest class are
/// counted after the last class.
#[derive(Clone, Copy, Debug, Default)]
struct ClassCount {
    in_use: usize,
    high_water: usize,
    refused: usize,
}

/// The pools of one size class together, as the doors report them: the class's largest slot, and
/// the slots of the pools whose slots it holds and their bytes.
#[cfg(any(test, feature = "object-pool"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ClassReport {
    pub(crate) slot_bytes: usize,
    pub(crate) slots: usize,
    pub(crate) bytes: usize,
    pub(crate) in_use: usize,
    pub(crate) high_water: usize,
    pub(crate) refused: usize,
}

/// Every pool, laid out over one memory: each pool's slots after the one before, the kinds' first,
/// then the pools of payload blocks.
pub(crate) struct Pools {
    base: NonNull<u8>,
    /// The bytes of the slots, from `base`.
    bytes: usize,
    origin: Origin,
    pools: [Pool; POOLS],
    /// Where each pool ends, from `base`: the pools lie one after another, so the pool a place
    /// lies in is the first that ends past it.
    ends: [usize; POOLS],
    counts: [ClassCount; CLASSES + 1],
}

impl Pools {
    /// Pools of no slot over the memory at `base`, which [`Self::lay`] lays where they are held:
    /// what it fills is too large to be laid aside and copied in.
    fn unlaid(base: NonNull<u8>, origin: Origin) -> Self {
        Self {
            base,
            bytes: 0,
            origin,
            pools: [Pool {
                start: 0,
                slots: 0,
                size: 0,
                fresh: 0,
                free: None,
            }; POOLS],
            ends: [0; POOLS],
            counts: [ClassCount::default(); CLASSES + 1],
        }
    }

    /// Lay `plan` out over the pools' memory, every slot free and none of them written.
    ///
    /// # Safety
    /// The pools are [`Self::unlaid`]. Their `base` is aligned to `SLOT_ALIGN`, the
    /// `plan.bytes()` bytes from it are writable and used by nothing else while the pools live, and
    /// their `origin` says where they came from.
    unsafe fn lay(&mut self, plan: &Plan) {
        let mut at: usize = 0;
        let planned = plan.slots.iter().zip(plan.sizes.iter());
        let laid = self.pools.iter_mut().zip(self.ends.iter_mut());
        for ((pool, end), (&slots, &size)) in laid.zip(planned) {
            pool.size = size;
            pool.start = at;
            pool.slots = slots;
            // The plan counted these bytes with checked arithmetic (`Plan::bytes`): none of
            // these sums reaches past its count.
            at = at.saturating_add(slots.saturating_mul(size));
            *end = at;
        }
        self.bytes = at;
    }

    /// Lay `plan` out over the memory at `base`, every slot free and none of them written.
    ///
    /// # Safety
    /// As [`Self::lay`], for `base` and `origin`.
    #[cfg(test)]
    unsafe fn over(base: NonNull<u8>, plan: &Plan, origin: Origin) -> Self {
        let mut pools = Self::unlaid(base, origin);
        pools.lay(plan);
        pools
    }

    /// A free slot of the pool of `kind` for an object whose slot takes `size` bytes, or `None`,
    /// counted, when it has none. Only that pool is asked: a slot of another kind's pool is never
    /// taken, so each kind holds what was stated for it and no more. A slot given back is taken
    /// before an untouched one, and the untouched ones go lowest first.
    fn take(&mut self, kind: Kind, size: usize) -> Option<NonNull<u8>> {
        let base = self.base;
        let pool = self.pools.get_mut(kind as usize)?;
        debug_assert!(
            pool.slots == 0 || size <= pool.size,
            "an object is taken from the pool of its own kind, whose slots hold it"
        );
        let size = pool.size;
        // SAFETY: the pool was laid over the memory at `base`.
        let slot = unsafe { pool.take(base) };
        self.counted(size, slot)
    }

    /// A block of at least `bytes` bytes from the pools of payload blocks, and the bytes it has:
    /// one of the smallest pool whose blocks hold them and that has one free, the pools met smallest
    /// first; `None`, counted against the smallest pool that holds them, when none has, or against
    /// the bytes' own class when no pool's blocks hold them.
    fn take_payload(&mut self, bytes: usize) -> Option<(NonNull<u8>, usize)> {
        let base = self.base;
        let mut home = None;
        let mut taken = None;
        for pool in self.pools.iter_mut().skip(KINDS) {
            if pool.size < bytes {
                continue;
            }
            home = home.or(Some(pool.size));
            // SAFETY: the pool was laid over the memory at `base`.
            if let Some(block) = unsafe { pool.take(base) } {
                taken = Some((block, pool.size));
                break;
            }
        }
        match taken {
            Some((block, size)) => self.counted(size, Some(block)).map(|block| (block, size)),
            None => {
                self.counted(home.unwrap_or(bytes), None);
                None
            }
        }
    }

    /// Count a take from a pool of slots of `size` bytes in its class: one more in use, or one
    /// more refused for a `slot` of none. Out of line: an object's take and a payload's both end
    /// here.
    #[inline(never)]
    fn counted(&mut self, size: usize, slot: Option<NonNull<u8>>) -> Option<NonNull<u8>> {
        let count = self.counts.get_mut(count_of(size))?;
        match slot {
            Some(_) => {
                count.in_use = count.in_use.saturating_add(1);
                count.high_water = count.high_water.max(count.in_use);
            }
            None => count.refused = count.refused.saturating_add(1),
        }
        slot
    }

    /// Whether `place` lies in the memory of the pools.
    #[cfg(test)]
    fn lies_in(&self, place: NonNull<u8>) -> bool {
        (place.as_ptr() as usize).wrapping_sub(self.base.as_ptr() as usize) < self.bytes
    }

    /// Whether `place` lies in the pools of payload blocks.
    #[cfg(test)]
    fn lies_in_payloads(&self, place: NonNull<u8>) -> bool {
        let at = (place.as_ptr() as usize).wrapping_sub(self.base.as_ptr() as usize);
        self.pools
            .get(KINDS)
            .is_some_and(|first| at >= first.start && at < self.bytes)
    }

    /// Give `place` back to the pool it lies in; `false` when it lies in none of them.
    fn give_back(&mut self, place: NonNull<u8>) -> bool {
        let at = (place.as_ptr() as usize).wrapping_sub(self.base.as_ptr() as usize);
        if at >= self.bytes {
            return false;
        }
        // The first pool that ends past the place, a pool of no slots ending where it starts.
        let kind = self.ends.partition_point(|&end| end <= at);
        let Some(pool) = self.pools.get_mut(kind) else {
            return false;
        };
        debug_assert_eq!(
            at.checked_sub(pool.start)
                .and_then(|offset| offset.checked_rem(pool.size)),
            Some(0),
            "a place given back is the start of a slot"
        );
        // SAFETY: the slot lies in this pool and was handed out, and its value is gone, so its
        // first word may hold the link.
        unsafe {
            place
                .as_ptr()
                .cast::<Option<NonNull<u8>>>()
                .write(pool.free)
        };
        pool.free = Some(place);
        if let Some(count) = self.counts.get_mut(count_of(pool.size)) {
            count.in_use = count.in_use.saturating_sub(1);
        }
        true
    }

    /// How many objects the pools hold now, the payloads' blocks among them.
    #[cfg(any(test, feature = "object-pool"))]
    fn held(&self) -> usize {
        self.counts
            .iter()
            .map(|count| count.in_use)
            .fold(0, usize::saturating_add)
    }

    /// The pools of size class `class` together.
    #[cfg(any(test, feature = "object-pool"))]
    fn report(&self, class: usize) -> ClassReport {
        let count = self.counts.get(class).copied().unwrap_or_default();
        let pools = || {
            self.pools
                .iter()
                .filter(move |pool| count_of(pool.size) == class)
        };
        ClassReport {
            slot_bytes: slot_bytes(class),
            slots: pools().map(|pool| pool.slots).sum(),
            bytes: pools()
                .map(|pool| pool.slots.saturating_mul(pool.size))
                .sum(),
            in_use: count.in_use,
            high_water: count.high_water,
            refused: count.refused,
        }
    }
}

impl Drop for Pools {
    fn drop(&mut self) {
        // SAFETY: the pools are gone, and with them every use of their memory.
        unsafe { self.origin.free(self.base) }
    }
}

/// The pools reserved now, if any are.
struct Reserved(Option<Pools>);

impl Reserved {
    /// The pools reserved now, the build's ([`BUILT_PLAN`]) reserved here when none are; `None`
    /// when the counts make no pool or the heap has not the memory. One body for every caller, and
    /// the pools are laid where they are held rather than returned and copied in.
    #[inline(never)]
    fn built(&mut self) -> Option<&mut Pools> {
        if self.0.is_none() {
            let plan = BUILT_PLAN.ok()?;
            let (base, layout) = heap_memory(&plan)?;
            let pools = self.0.insert(Pools::unlaid(base, Origin::Heap(layout)));
            // SAFETY: the pools are unlaid, over an allocation of this layout's, aligned to the
            // slot, as long as the plan and no one else's.
            unsafe { pools.lay(&plan) };
        }
        self.0.as_mut()
    }
}

// SAFETY: the memory of the pools is reached only through the lock this is held behind, by one
// thread at a time, and no pointer into it is handed out except to the slot's own object.
unsafe impl Send for Reserved {}

static RESERVED: Lock<Reserved> = Lock::new(Reserved(None));

/// A slot for a `T` of `kind`, from that kind's pool, or `None` when it has none free. The first
/// object a program makes reserves the build's pools when it reserved none ([`Reserved::built`]);
/// when they cannot be reserved either, every object is refused and the next asks again.
pub(crate) fn take<T>(kind: Kind) -> Option<NonNull<u8>> {
    take_slot(kind, const { slot_size::<T>() })
}

/// [`take`] for a slot of `size` bytes. Not generic and never inlined: every door that places an
/// object calls this one body, which holds the lock, the first reservation and the pool's count.
#[inline(never)]
fn take_slot(kind: Kind, size: usize) -> Option<NonNull<u8>> {
    RESERVED.with(|reserved| reserved.built()?.take(kind, size))
}

/// The counts of the build's pools: `HELD_SESSIONS` sessions, each holding as many of each entity
/// as the limits the library opens a session under admit within the build's value of the limit,
/// and the held values' own limits. Refused only by a build whose counts are past the address
/// space.
const fn built_counts() -> Result<Counts, Unplanned> {
    let limits = session_limits();
    let bounds = Bounds {
        subscribers: each::<{ caps::MAX_SUBSCRIPTIONS }>(limits.max_subscriptions()),
        queryables: each::<{ caps::MAX_QUERYABLES }>(limits.max_queryables()),
        liveliness_tokens: each::<{ caps::MAX_LOCAL_TOKENS }>(limits.max_local_tokens()),
        liveliness_subscribers: each::<{ caps::MAX_LIVELINESS_SUBSCRIPTIONS }>(
            limits.max_liveliness_subscriptions(),
        ),
        queriers: each::<{ caps::MAX_QUERIERS }>(limits.max_queriers()),
        keyexprs: each::<{ caps::MAX_DECLARED_KEYEXPRS }>(limits.max_declared_keyexprs()),
        gets: each::<{ caps::MAX_PENDING_QUERIES }>(limits.max_pending_queries()),
        liveliness_gets: each::<{ caps::MAX_PENDING_LIVELINESS_GETS }>(
            limits.max_pending_liveliness_gets(),
        ),
        matching_listeners: each::<{ caps::MAX_MATCHING_LISTENERS }>(
            limits.max_matching_listeners(),
        ),
        decl_watches: each::<{ caps::MAX_DECL_WATCHES }>(limits.max_decl_watches()),
        transport_events_listeners: each::<{ caps::MAX_TRANSPORT_EVENTS_LISTENERS }>(
            limits.max_transport_events_listeners(),
        ),
        advanced_publishers: each::<{ caps::MAX_ADVANCED_PUBLISHERS }>(
            limits.max_advanced_publishers(),
        ),
        advanced_subscribers: each::<{ caps::MAX_ADVANCED_SUBSCRIBERS }>(
            limits.max_advanced_subscribers(),
        ),
        link_events_listeners: each::<{ caps::MAX_LINK_EVENTS_LISTENERS }>(
            limits.max_link_events_listeners(),
        ),
    };
    let built = Counts {
        sessions: caps::HELD_SESSIONS,
        publishers: match each::<{ caps::MAX_PUBLISHERS }>(limits.max_publishers()) {
            Some(publishers) => publishers,
            None => 0,
        },
        // Each of these at the bound of its limit, which a count left at zero takes.
        subscribers: 0,
        queryables: 0,
        liveliness_tokens: 0,
        liveliness_subscribers: 0,
        samples: caps::HELD_SAMPLES,
        replies: caps::HELD_REPLIES,
        queries: caps::HELD_QUERIES,
        bytes: caps::HELD_PAYLOADS,
        configs: caps::HELD_CONFIGS,
        hellos: caps::HELD_HELLOS,
        // At the bound of their limits, as the entities above.
        queriers: 0,
        keyexprs: 0,
        payload_blocks: [
            caps::HELD_SMALL_PAYLOAD_BLOCKS,
            caps::HELD_MEDIUM_PAYLOAD_BLOCKS,
            caps::HELD_LARGE_PAYLOAD_BLOCKS,
        ],
        encodings: caps::HELD_ENCODINGS,
        gets: 0,
        liveliness_gets: 0,
        matching_listeners: 0,
        decl_watches: 0,
        transport_events_listeners: 0,
        advanced_publishers: 0,
        advanced_subscribers: 0,
        link_events_listeners: 0,
    };
    resolve(&built, &bounds)
}

/// How many of an entity one session holds: `value`, the limit the library opens a session under,
/// within `CEILING`, the build's value of it, which sizes the pool; `None` where the limit holds no
/// bound.
const fn each<const CEILING: usize>(value: Quota) -> Option<usize> {
    match value.lent_under(Quota::at_most(CEILING)) {
        Ok(each) => Some(each),
        Err(_) => None,
    }
}

/// The memory of the pools of `plan` from the heap, in one allocation, and its layout; `None`
/// when the heap has not the memory.
fn heap_memory(plan: &Plan) -> Option<(NonNull<u8>, Layout)> {
    let layout = Layout::from_size_align(plan.bytes().ok()?, SLOT_ALIGN).ok()?;
    // SAFETY: the layout is not of zero bytes: a plan has a slot.
    let base = NonNull::new(unsafe { alloc::alloc::alloc(layout) })?;
    Some((base, layout))
}

/// The pools of `plan` from the heap in one allocation, or `None` when the heap has not the
/// memory.
#[cfg(test)]
fn reserve_from_heap(plan: &Plan) -> Option<Pools> {
    let (base, layout) = heap_memory(plan)?;
    // SAFETY: the allocation is this layout's, aligned to the slot, as long as the plan and no
    // one else's.
    Some(unsafe { Pools::over(base, plan, Origin::Heap(layout)) })
}

/// The plan of the build's pools ([`built_counts`]), worked out when the library is compiled: the
/// counts are the build's constants and the limits it opens sessions under, so nothing of it is
/// left to the first object a program makes.
const BUILT_PLAN: Result<Plan, Unplanned> = match built_counts() {
    Ok(objects) => Plan::of(&objects),
    Err(unplanned) => Err(unplanned),
};

/// Whether `place` lies in the pools reserved now.
#[cfg(test)]
pub(crate) fn lies_in_pools(place: NonNull<u8>) -> bool {
    RESERVED.with(|reserved| {
        reserved
            .0
            .as_ref()
            .is_some_and(|pools| pools.lies_in(place))
    })
}

/// Whether `place` lies in the pools of payload blocks reserved now.
#[cfg(test)]
pub(crate) fn lies_in_payloads(place: NonNull<u8>) -> bool {
    RESERVED.with(|reserved| {
        reserved
            .0
            .as_ref()
            .is_some_and(|pools| pools.lies_in_payloads(place))
    })
}

/// Give `place` back to the pool it lies in; `false` when it lies in none, and is the heap's.
pub(crate) fn give_back(place: NonNull<u8>) -> bool {
    RESERVED.with(|reserved| {
        reserved
            .0
            .as_mut()
            .is_some_and(|pools| pools.give_back(place))
    })
}

/// A payload block of at least `bytes` bytes, aligned to 16, and the bytes it has: one of the
/// smallest pool of payload blocks that holds them and has one free; `None`, counted, when none
/// has. Given back as any slot is ([`give_back`]). The first block reserves the build's pools when
/// none are, as the first object does ([`take`]).
pub(crate) fn take_block(bytes: usize) -> Option<(NonNull<u8>, usize)> {
    RESERVED.with(|reserved| reserved.built()?.take_payload(bytes))
}

/// The limits every session of this ABI opens under before its config states any: the snapshot
/// `z_open` starts from (`crate::session::opening_limits`).
const fn session_limits() -> SessionLimits {
    crate::session::opening_limits()
}

// --- what the doors of `object-pool` ask of the pools ------------------------------------------

/// Why a reservation the program asked for was not made.
#[cfg(feature = "object-pool")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// Pools are reserved already.
    Reserved,
    /// The heap has not the memory.
    NoMemory,
}

/// The pools `stated` make, its entity counts read against the limits every session opens under.
#[cfg(feature = "object-pool")]
pub(crate) fn plan_of(stated: &Counts) -> Result<Plan, Unplanned> {
    let objects = resolve(stated, &Bounds::of(&session_limits()))?;
    Plan::of(&objects)
}

/// Lay `plan` out over the memory at `base` and hold it as the reservation, unless one is held
/// already: then the memory is not touched, and is let go as `origin` says.
///
/// # Safety
/// As [`Pools::lay`], for `base` and `origin`.
#[cfg(feature = "object-pool")]
unsafe fn install(base: NonNull<u8>, plan: &Plan, origin: Origin) -> Result<(), Refused> {
    let refused = RESERVED.with(|reserved| {
        if reserved.0.is_some() {
            return true;
        }
        reserved.0.insert(Pools::unlaid(base, origin)).lay(plan);
        false
    });
    if refused {
        origin.free(base);
        return Err(Refused::Reserved);
    }
    Ok(())
}

/// Reserve the pools of `plan` from the heap, in one allocation; a refusal leaves the heap as it
/// was.
#[cfg(feature = "object-pool")]
pub(crate) fn reserve(plan: &Plan) -> Result<(), Refused> {
    let (base, layout) = heap_memory(plan).ok_or(Refused::NoMemory)?;
    // SAFETY: the allocation is this layout's, aligned to the slot, as long as the plan and no
    // one else's.
    unsafe { install(base, plan, Origin::Heap(layout)) }
}

/// Reserve the pools of `plan` over the program's memory at `base`.
///
/// # Safety
/// `base` is aligned to `SLOT_ALIGN`, and the `plan.bytes()` bytes from it are the program's,
/// handed over for the pools alone until they are given up.
#[cfg(feature = "object-pool-region")]
pub(crate) unsafe fn place(base: NonNull<u8>, plan: &Plan) -> Result<(), Refused> {
    install(base, plan, Origin::Program)
}

/// The pools of size class `class` together; with none reserved, the class's slot size alone.
#[cfg(feature = "object-pool")]
pub(crate) fn report(class: usize) -> ClassReport {
    RESERVED.with(|reserved| match reserved.0.as_ref() {
        Some(pools) => pools.report(class),
        None => ClassReport {
            slot_bytes: slot_bytes(class),
            ..Default::default()
        },
    })
}

/// Give the pools up, unless they hold an object: `false` then, and they are kept.
#[cfg(feature = "object-pool")]
pub(crate) fn release() -> bool {
    let (released, kept) = RESERVED.with(|reserved| {
        if reserved.0.as_ref().is_some_and(|pools| pools.held() > 0) {
            (None, true)
        } else {
            (reserved.0.take(), false)
        }
    });
    // Freed after the lock, as nothing let go under it may take it again.
    drop(released);
    !kept
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A block is its bytes rounded up to a slot's alignment, at least one alignment, and a size the
    /// address space cannot round is held at the largest multiple. Turned red by a block one
    /// alignment too small or too large at an edge.
    #[test]
    fn a_block_is_its_bytes_rounded_up_to_a_slot() {
        assert_eq!(block_of(0), SLOT_ALIGN);
        assert_eq!(block_of(1), SLOT_ALIGN);
        assert_eq!(block_of(SLOT_ALIGN), SLOT_ALIGN);
        assert_eq!(block_of(SLOT_ALIGN + 1), 2 * SLOT_ALIGN);
        assert_eq!(block_of(1040), 1040);
        assert_eq!(block_of(1041), 1056);
        assert_eq!(block_of(usize::MAX), usize::MAX - (SLOT_ALIGN - 1));
        assert_eq!(block_of(usize::MAX) % SLOT_ALIGN, 0);
    }

    /// The largest payload block holds the largest sample a session hands a program and its head:
    /// the largest message, whichever of the rejoining ceiling and the two batches is the largest,
    /// and the longest key the session holds. Turned red by a largest block sized by one of them
    /// alone, for the message without the key, or without the head.
    #[test]
    fn the_largest_block_holds_the_largest_sample_and_its_head() {
        let largest = caps::PICO_FRAG_MAX_BYTES
            .max(caps::PICO_UNICAST_BATCH_BYTES)
            .max(caps::PICO_MULTICAST_BATCH_BYTES);
        assert_eq!(LARGEST_MESSAGE, largest);
        let sample = largest + caps::MAX_KEYEXPR_BYTES;
        assert_eq!(LARGEST_SAMPLE, sample);
        assert!(LARGEST_BLOCK >= sample + crate::bytes::HEAD);
        assert!(LARGEST_BLOCK < sample + crate::bytes::HEAD + SLOT_ALIGN);
        assert_eq!(PAYLOAD_BLOCKS[PAYLOAD_CLASSES - 1], LARGEST_BLOCK);
        assert_eq!(larger(3, 5), 5);
        assert_eq!(larger(5, 3), 5);
    }

    /// The pools of payload blocks are laid smallest first whatever order their sizes are stated
    /// in, each size keeping its own count. Turned red by a sort that loses a pool or swaps a count
    /// away from its size.
    #[test]
    fn the_payload_pools_are_ordered_by_their_blocks() {
        let sorted = [(64, 1), (1040, 2), (4112, 3)];
        for stated in [
            [(64, 1), (1040, 2), (4112, 3)],
            [(64, 1), (4112, 3), (1040, 2)],
            [(1040, 2), (64, 1), (4112, 3)],
            [(1040, 2), (4112, 3), (64, 1)],
            [(4112, 3), (64, 1), (1040, 2)],
            [(4112, 3), (1040, 2), (64, 1)],
        ] {
            assert_eq!(ascending(stated), sorted, "{stated:?}");
        }
        let plan = plan_of(&[]).with_payloads(&[4, 5, 6]);
        let mut laid: alloc::vec::Vec<(usize, usize)> = plan.sizes[KINDS..]
            .iter()
            .copied()
            .zip(plan.slots[KINDS..].iter().copied())
            .collect();
        assert!(laid.windows(2).all(|pair| pair[0].0 <= pair[1].0));
        laid.sort_unstable();
        let mut stated: alloc::vec::Vec<(usize, usize)> =
            PAYLOAD_BLOCKS.iter().copied().zip([4, 5, 6]).collect();
        stated.sort_unstable();
        assert_eq!(laid, stated);
        assert_eq!(plan.slots[..KINDS], [0; KINDS], "no kind's pool is touched");
    }

    /// Memory for pools in a test, aligned as a slot.
    #[repr(C, align(16))]
    struct Memory([u8; 512]);

    fn counts() -> Counts {
        Counts::default()
    }

    /// `put` writes the one element it names and no other, and a place past the row's end writes
    /// nothing. Turned red by a walk that stops one element early or late.
    #[test]
    fn put_writes_the_element_it_names_and_nothing_past_the_row() {
        let mut row = [0usize; 4];
        put(&mut row, 0, 7);
        put(&mut row, 3, 9);
        assert_eq!(row, [7, 0, 0, 9]);
        put(&mut row, 4, 5);
        put(&mut row, usize::MAX, 5);
        assert_eq!(row, [7, 0, 0, 9], "a place past the end writes nothing");
        const PUT: [usize; 3] = {
            let mut row = [0usize; 3];
            put(&mut row, 1, 2);
            row
        };
        assert_eq!(PUT, [0, 2, 0], "it runs when the build is compiled");
    }

    /// A plan of `slots` slots of `size` bytes for each kind named.
    fn plan_of(kinds: &[(Kind, usize, usize)]) -> Plan {
        let mut plan = Plan {
            slots: [0; POOLS],
            sizes: [0; POOLS],
        };
        for &(kind, slots, size) in kinds {
            plan.slots[kind as usize] = slots;
            plan.sizes[kind as usize] = size;
        }
        plan
    }

    const BOUNDED: Bounds = Bounds {
        subscribers: Some(4),
        queryables: Some(3),
        liveliness_tokens: Some(2),
        liveliness_subscribers: Some(5),
        queriers: Some(6),
        keyexprs: Some(7),
        gets: Some(8),
        liveliness_gets: Some(9),
        matching_listeners: Some(10),
        decl_watches: Some(11),
        transport_events_listeners: Some(12),
        advanced_publishers: Some(10),
        advanced_subscribers: Some(11),
        link_events_listeners: Some(13),
    };

    const UNBOUNDED: Bounds = Bounds {
        subscribers: None,
        queryables: None,
        liveliness_tokens: None,
        queriers: None,
        keyexprs: None,
        liveliness_subscribers: None,
        gets: None,
        liveliness_gets: None,
        matching_listeners: None,
        decl_watches: None,
        transport_events_listeners: None,
        advanced_publishers: None,
        advanced_subscribers: None,
        link_events_listeners: None,
    };

    /// An object takes the smallest slot that holds it; one larger than the largest slot, or
    /// aligned past a slot, has none.
    #[test]
    fn an_object_takes_the_smallest_slot_that_holds_it() {
        assert_eq!(class_of(1, 1), Some(0));
        assert_eq!(class_of(16, 8), Some(0));
        assert_eq!(class_of(17, 8), Some(1));
        assert_eq!(class_of(100, 16), Some(3));
        assert_eq!(class_of(16 * 1024, 8), Some(CLASSES - 1));
        assert_eq!(class_of(16 * 1024 + 1, 8), None);
        assert_eq!(class_of(16, 32), None);
    }

    /// The class of every size up to past the largest slot is the first whose slot holds it.
    #[test]
    fn a_class_is_the_first_whose_slot_holds_the_size() {
        for size in 0..=slot_bytes(CLASSES - 1) + 1 {
            let first = (0..CLASSES).find(|&class| size <= slot_bytes(class));
            assert_eq!(class_of(size, 1), first, "size {size}");
        }
        assert_eq!(class_of(0, 1), Some(0));
        assert_eq!(class_of(32, 1), Some(1));
        assert_eq!(class_of(33, 1), Some(2));
        assert_eq!(class_of(usize::MAX, 1), None);
    }

    /// An object takes a slot of its own size, rounded up to the alignment of a slot, whichever
    /// class reports it; one larger than the largest class is counted after the last class; one of
    /// no bytes takes the alignment, where a free slot keeps its link.
    #[test]
    fn an_object_takes_a_slot_of_its_own_size() {
        assert_eq!(slot_size::<[u8; 100]>(), 112);
        assert_eq!(slot_size::<[u8; 112]>(), 112);
        assert_eq!(slot_size::<()>(), SLOT_ALIGN);
        assert_eq!(count_of(112), 3, "reported by the class of 128");
        assert_eq!(slot_size::<[u8; 16 * 1024]>(), 16 * 1024);
        assert_eq!(slot_size::<[u8; 16 * 1024 + 1]>(), 16 * 1024 + 16);
        assert_eq!(count_of(16 * 1024), CLASSES - 1);
        assert_eq!(count_of(16 * 1024 + 16), CLASSES);
        let config = slot_size::<crate::config::ConfigState>();
        assert!(config >= core::mem::size_of::<crate::config::ConfigState>());
        assert_eq!(config % SLOT_ALIGN, 0);
    }

    /// A bounded count left at zero takes its limit's bound, one stated above it is held to it,
    /// one under it is kept, and each is per session.
    #[test]
    fn an_entity_count_is_held_to_the_bound_of_its_limit_per_session() {
        let stated = Counts {
            sessions: 2,
            subscribers: 0,
            queryables: 9,
            liveliness_tokens: 1,
            queriers: 0,
            keyexprs: 2,
            ..counts()
        };
        let objects = resolve(&stated, &BOUNDED).expect("every count is bounded");
        assert_eq!(objects.sessions, 2);
        assert_eq!(objects.subscribers, 8, "the bound, four, per session");
        assert_eq!(objects.keyexprs, 4, "two under the bound, per session");
        if cfg!(feature = "query") {
            assert_eq!(objects.queriers, 12, "the bound, six, per session");
        } else {
            assert_eq!(objects.queriers, 0, "a build that asks nothing holds none");
        }
        if cfg!(feature = "queryable") {
            assert_eq!(objects.queryables, 6, "nine held to three, per session");
        } else {
            assert_eq!(
                objects.queryables, 0,
                "a build without queryables holds none"
            );
        }
        if cfg!(feature = "liveliness") {
            assert_eq!(
                objects.liveliness_tokens, 2,
                "one under the bound, per session"
            );
            assert_eq!(objects.liveliness_subscribers, 10);
        } else {
            assert_eq!(objects.liveliness_tokens, 0);
            assert_eq!(objects.liveliness_subscribers, 0);
        }
    }

    /// What no limit bounds is as stated: the publishers per session, the rest for all; the kept
    /// hellos only in a build that scouts.
    #[test]
    fn what_no_limit_bounds_is_as_stated() {
        let stated = Counts {
            sessions: 3,
            publishers: 2,
            subscribers: 1,
            queryables: 1,
            liveliness_tokens: 1,
            liveliness_subscribers: 1,
            samples: 5,
            replies: 6,
            queries: 7,
            bytes: 8,
            configs: 9,
            hellos: 10,
            queriers: 1,
            keyexprs: 1,
            payload_blocks: [11, 13, 14],
            encodings: 12,
            gets: 1,
            liveliness_gets: 1,
            matching_listeners: 1,
            decl_watches: 1,
            transport_events_listeners: 1,
            advanced_publishers: 1,
            advanced_subscribers: 1,
            link_events_listeners: 1,
        };
        let objects = resolve(&stated, &UNBOUNDED).expect("every count is stated");
        assert_eq!(objects.publishers, 6);
        assert_eq!(objects.subscribers, 3);
        assert_eq!(
            (
                objects.samples,
                objects.replies,
                objects.queries,
                objects.bytes,
                objects.configs
            ),
            (5, 6, 7, 8, 9)
        );
        let scouts = cfg!(any(feature = "scout", feature = "scout-mcu"));
        assert_eq!(objects.hellos, if scouts { 10 } else { 0 });
        assert_eq!(objects.payload_blocks, [11, 13, 14]);
        assert_eq!(objects.encodings, 12);
    }

    /// A bounded count left at zero whose limit holds no bound is refused; with no session no
    /// entity is asked for, so nothing is refused.
    #[test]
    fn a_count_left_at_zero_whose_limit_holds_no_bound_is_refused() {
        let stated = Counts {
            sessions: 1,
            ..counts()
        };
        assert_eq!(resolve(&stated, &UNBOUNDED), Err(Unplanned::Unbounded));
        let no_session = Counts {
            bytes: 1,
            ..counts()
        };
        let objects = resolve(&no_session, &UNBOUNDED).expect("no entity is asked for");
        assert_eq!(objects.subscribers, 0);
    }

    /// Counts past the address space are refused.
    #[test]
    fn counts_past_the_address_space_are_refused() {
        let stated = Counts {
            sessions: usize::MAX,
            publishers: 2,
            ..counts()
        };
        assert_eq!(resolve(&stated, &BOUNDED), Err(Unplanned::TooLarge));
        let plan = plan_of(&[(Kind::Bytes, usize::MAX, slot_bytes(CLASSES - 1))]);
        assert_eq!(plan.bytes(), Err(Unplanned::TooLarge));
    }

    /// Counts of nothing make no pool.
    #[test]
    fn counts_of_nothing_make_no_pool() {
        assert_eq!(Plan::of(&counts()), Err(Unplanned::Empty));
    }

    /// Each kind has a pool of its own, of slots of its object's size, and the bytes are the slots
    /// times their size.
    #[test]
    fn each_kind_has_a_pool_of_its_own_size() {
        let objects = Counts {
            bytes: 3,
            configs: 2,
            ..counts()
        };
        let plan = Plan::of(&objects).expect("three payloads and two configs");
        let bytes_size = slot_size::<crate::bytes::ByteBuf>();
        let config_size = slot_size::<crate::config::ConfigState>();
        assert_eq!(plan.slots[Kind::Bytes as usize], 3);
        assert_eq!(plan.sizes[Kind::Bytes as usize], bytes_size);
        assert_eq!(plan.slots[Kind::Config as usize], 2);
        assert_eq!(plan.sizes[Kind::Config as usize], config_size);
        assert_eq!(plan.slots.iter().sum::<usize>(), 5);
        assert_eq!(plan.bytes(), Ok(3 * bytes_size + 2 * config_size));
    }

    /// Two kinds whose objects share a size keep the counts stated for each: a full pool of one
    /// refuses its object while the other's has a free slot of the same size.
    #[test]
    fn a_kind_never_takes_a_slot_of_another_kind_of_the_same_size() {
        let mut memory = Memory([0; 512]);
        let plan = plan_of(&[(Kind::Bytes, 1, 16), (Kind::Publisher, 1, 16)]);
        let base = NonNull::new(memory.0.as_mut_ptr()).expect("an array");
        // SAFETY: the memory is aligned, long enough and used by nothing else.
        let mut pools = unsafe { Pools::over(base, &plan, Origin::Program) };

        let payload = pools.take(Kind::Bytes, 16).expect("the one payload slot");
        assert_eq!(
            pools.take(Kind::Bytes, 16),
            None,
            "the payload pool is full, whatever the publisher pool holds"
        );
        let publisher = pools
            .take(Kind::Publisher, 16)
            .expect("the publisher's own slot");
        assert_ne!(payload, publisher);
        let report = pools.report(0);
        assert_eq!((report.slots, report.in_use, report.refused), (2, 2, 1));
        assert!(pools.give_back(publisher));
        assert_eq!(pools.take(Kind::Bytes, 16), None, "still none of its own");
        assert!(pools.give_back(payload));
        assert_eq!(pools.take(Kind::Bytes, 16), Some(payload));
        assert!(pools.give_back(payload));
        assert_eq!(pools.held(), 0);
    }

    /// A place goes back to the pool it lies in, found by where the pools end: past a pool of no
    /// slots, to the next one. Turned red by a search that stops at the empty pool or the one
    /// before it.
    #[test]
    fn a_place_goes_back_to_the_pool_it_lies_in_past_an_empty_one() {
        let mut memory = Memory([0; 512]);
        let plan = plan_of(&[
            (Kind::Publisher, 2, 16),
            (Kind::Subscriber, 0, 16),
            (Kind::Bytes, 1, 64),
        ]);
        let base = NonNull::new(memory.0.as_mut_ptr()).expect("an array");
        // SAFETY: the memory is aligned, long enough and used by nothing else.
        let mut pools = unsafe { Pools::over(base, &plan, Origin::Program) };
        let last_publisher = {
            let _first = pools.take(Kind::Publisher, 16).expect("a free slot");
            pools.take(Kind::Publisher, 16).expect("a free slot")
        };
        let payload = pools.take(Kind::Bytes, 64).expect("the one payload slot");
        assert!(
            pools.give_back(payload),
            "the payload's place is the pools'"
        );
        assert_eq!(
            pools.take(Kind::Bytes, 64),
            Some(payload),
            "it went back to its own pool, past the empty one"
        );
        assert!(pools.give_back(last_publisher));
        assert_eq!(pools.take(Kind::Publisher, 16), Some(last_publisher));
        assert_eq!(pools.take(Kind::Subscriber, 16), None, "no slot of its own");
    }

    /// The slots of a pool lie inside the memory, apart and aligned; a full pool refuses and
    /// counts it; a slot given back is the next one taken; a place outside is not the pools'.
    #[test]
    fn a_full_pool_refuses_and_a_slot_given_back_is_taken_again() {
        let mut memory = Memory([0; 512]);
        let plan = plan_of(&[(Kind::Publisher, 2, 16), (Kind::Bytes, 3, 64)]);
        let bytes = plan.bytes().expect("small");
        assert_eq!(bytes, 2 * 16 + 3 * 64);
        let base = NonNull::new(memory.0.as_mut_ptr()).expect("an array");
        // SAFETY: the memory is aligned, long enough and used by nothing else.
        let mut pools = unsafe { Pools::over(base, &plan, Origin::Program) };

        let first = pools.take(Kind::Publisher, 16).expect("a free slot");
        let second = pools.take(Kind::Publisher, 16).expect("a free slot");
        assert_ne!(first, second);
        assert_eq!(
            pools.take(Kind::Publisher, 16),
            None,
            "two slots and both are held"
        );
        let report = pools.report(0);
        assert_eq!(
            (
                report.slots,
                report.in_use,
                report.high_water,
                report.refused
            ),
            (2, 2, 2, 1)
        );

        let large: alloc::vec::Vec<_> = (0..3)
            .map(|_| pools.take(Kind::Bytes, 64).expect("free"))
            .collect();
        for slot in large.iter().chain([first, second].iter()) {
            let at = slot.as_ptr() as usize - base.as_ptr() as usize;
            assert!(at < bytes, "inside the memory");
            assert_eq!(slot.as_ptr() as usize % SLOT_ALIGN, 0, "aligned");
        }
        assert_eq!(pools.held(), 5);

        assert!(pools.give_back(second));
        assert_eq!(
            pools.take(Kind::Publisher, 16),
            Some(second),
            "the slot given back is taken again"
        );
        let outside = NonNull::new(memory.0[bytes..].as_mut_ptr()).expect("an array");
        assert!(!pools.give_back(outside), "past the pools' memory");
        let mut elsewhere = 0u128;
        assert!(!pools.give_back(NonNull::from(&mut elsewhere).cast()));
        assert_eq!(pools.held(), 5);
        for slot in large {
            assert!(pools.give_back(slot));
        }
        assert!(pools.give_back(first));
        assert!(pools.give_back(second));
        assert_eq!(pools.held(), 0);
        assert_eq!(pools.report(2).high_water, 3);
        assert_eq!(pools.report(0).bytes, 2 * 16);
        assert_eq!(pools.report(2).bytes, 3 * 64);
    }

    /// A class reports every pool whose slots it holds, slots of different sizes among them: its
    /// largest slot, their slots and the bytes they take, which a reader adds up to what the
    /// reservation took.
    #[test]
    fn a_class_reports_the_bytes_of_slots_smaller_than_its_own() {
        let mut memory = Memory([0; 512]);
        let plan = plan_of(&[(Kind::Bytes, 2, 48), (Kind::Publisher, 1, 64)]);
        let base = NonNull::new(memory.0.as_mut_ptr()).expect("an array");
        // SAFETY: the memory is aligned, long enough and used by nothing else.
        let pools = unsafe { Pools::over(base, &plan, Origin::Program) };
        let report = pools.report(count_of(48));
        assert_eq!(count_of(48), count_of(64), "one class holds both");
        assert_eq!(
            (report.slot_bytes, report.slots, report.bytes),
            (64, 3, 2 * 48 + 64)
        );
        assert_eq!(plan.slot_bytes(), Ok(report.bytes));
    }

    /// A class past the last the pools count reports no slot and nothing held, its slot size
    /// alone.
    #[test]
    fn a_class_past_the_counted_ones_reports_nothing_held() {
        let mut memory = Memory([0; 512]);
        let plan = plan_of(&[(Kind::Bytes, 2, 48)]);
        let base = NonNull::new(memory.0.as_mut_ptr()).expect("an array");
        // SAFETY: the memory is aligned, long enough and used by nothing else.
        let mut pools = unsafe { Pools::over(base, &plan, Origin::Program) };
        assert!(pools.take(Kind::Bytes, 48).is_some());
        let report = pools.report(CLASSES + 1);
        assert_eq!(
            report,
            ClassReport {
                slot_bytes: slot_bytes(CLASSES + 1),
                ..ClassReport::default()
            }
        );
        assert_eq!(pools.report(count_of(48)).in_use, 1);
    }

    /// Laying the pools writes nothing into their slots; a pool hands out its untouched slots lowest
    /// first, a slot given back before any untouched one, and refuses, counted, once all are held.
    #[test]
    fn a_pool_hands_out_untouched_slots_in_order_and_lays_none() {
        let mut memory = Memory([0xA5; 512]);
        let plan = plan_of(&[(Kind::Publisher, 3, 16)]);
        let bytes = plan.bytes().expect("small");
        let base = NonNull::new(memory.0.as_mut_ptr()).expect("an array");
        // SAFETY: the memory is aligned, long enough and used by nothing else.
        let mut pools = unsafe { Pools::over(base, &plan, Origin::Program) };
        // SAFETY: the pools' memory, read through the pointer they were laid over.
        let laid = unsafe { core::slice::from_raw_parts(base.as_ptr(), bytes) };
        assert!(
            laid.iter().all(|&byte| byte == 0xA5),
            "laying the pools writes into no slot"
        );
        let slot = |index: usize| {
            // SAFETY: the slots lie within the memory.
            NonNull::new(unsafe { base.as_ptr().add(index * 16) }).expect("in the array")
        };
        let first = pools.take(Kind::Publisher, 16).expect("an untouched slot");
        assert_eq!(first, slot(0), "the lowest untouched slot first");
        assert_eq!(pools.take(Kind::Publisher, 16), Some(slot(1)));
        assert!(pools.give_back(first));
        assert_eq!(
            pools.take(Kind::Publisher, 16),
            Some(first),
            "a slot given back is taken before an untouched one"
        );
        assert_eq!(pools.take(Kind::Publisher, 16), Some(slot(2)));
        assert_eq!(
            pools.take(Kind::Publisher, 16),
            None,
            "three slots, all held"
        );
        assert_eq!(pools.report(0).refused, 1);
        for index in 0..3 {
            assert!(pools.give_back(slot(index)));
        }
        assert_eq!(pools.held(), 0);
    }

    /// A pool of slots past the largest class lays and takes them as any other, is counted after
    /// the last class, and is reported by none.
    #[test]
    fn a_pool_past_the_largest_class_is_reported_by_no_class() {
        let size = slot_bytes(CLASSES - 1) + SLOT_ALIGN;
        let plan = plan_of(&[(Kind::Config, 2, size)]);
        let bytes = plan.bytes().expect("two slots");
        let layout = Layout::from_size_align(bytes, SLOT_ALIGN).expect("a layout");
        // SAFETY: the layout is not of zero bytes.
        let base = NonNull::new(unsafe { alloc::alloc::alloc(layout) }).expect("the test's heap");
        // SAFETY: the allocation is this layout's, as long as the plan; the pools free it.
        let mut pools = unsafe { Pools::over(base, &plan, Origin::Heap(layout)) };
        let first = pools.take(Kind::Config, size).expect("a slot");
        let second = pools.take(Kind::Config, size).expect("a slot");
        assert_eq!(second.as_ptr() as usize - first.as_ptr() as usize, size);
        assert_eq!(pools.take(Kind::Config, size), None, "two and no more");
        assert_eq!(pools.held(), 2);
        for class in 0..CLASSES {
            assert_eq!(pools.report(class).slots, 0, "class {class}");
        }
        assert_eq!(pools.counts[CLASSES].refused, 1);
        assert!(pools.give_back(first));
        assert!(pools.give_back(second));
        assert_eq!(pools.held(), 0);
    }

    /// What each kind's slots hold and what they leave unused, printed for reading: each kind's
    /// object size, its slot as the size classes give it, the slots the build's plan lays and the
    /// bytes left in them; and what a slot of the object's own size, rounded to a slot's alignment,
    /// would leave. Run with `cargo test -p wz-capi-pico --lib slot_bytes_each_kind_leaves --
    /// --ignored --nocapture`, under the environment of the build to read.
    #[test]
    #[ignore = "a measurement printed for reading, not a check"]
    fn the_slot_bytes_each_kind_leaves() {
        let plan = BUILT_PLAN.expect("the build's counts make pools");
        let (mut laid, mut left, mut left_exact) = (0usize, 0usize, 0usize);
        let mut row = |name: &str, kind: Kind, size: usize| {
            let count = plan.slots[kind as usize];
            let slot = plan.sizes[kind as usize];
            let exact = size.next_multiple_of(SLOT_ALIGN);
            let unused = slot.saturating_sub(size).saturating_mul(count);
            let unused_exact = exact.saturating_sub(size).saturating_mul(count);
            laid += slot.saturating_mul(count);
            left += unused;
            left_exact += unused_exact;
            std::println!(
                "slot-row: {name:<22} size_of={size:>6} slot_bytes={slot:>6} exact={exact:>6} \
                 count={count:>4} unused={unused:>7} unused_exact={unused_exact:>7}"
            );
        };
        #[cfg(any(feature = "engine-tokio", feature = "object-pool"))]
        row(
            "session",
            Kind::Session,
            core::mem::size_of::<crate::session::SessionPlace>(),
        );
        row(
            "publisher",
            Kind::Publisher,
            core::mem::size_of::<crate::pubsub::PublisherState>(),
        );
        row(
            "subscriber",
            Kind::Subscriber,
            core::mem::size_of::<crate::pubsub::SubscriberPlace>(),
        );
        #[cfg(feature = "queryable")]
        row(
            "queryable",
            Kind::Queryable,
            core::mem::size_of::<crate::query::QueryablePlace>(),
        );
        #[cfg(feature = "liveliness")]
        {
            row(
                "liveliness_token",
                Kind::LivelinessToken,
                core::mem::size_of::<crate::liveliness::TokenState>(),
            );
            row(
                "liveliness_subscriber",
                Kind::LivelinessSubscriber,
                core::mem::size_of::<crate::pubsub::SubscriberPlace>(),
            );
        }
        row(
            "sample",
            Kind::Sample,
            core::mem::size_of::<crate::pubsub::SampleMarshal>(),
        );
        #[cfg(feature = "query")]
        row(
            "reply",
            Kind::Reply,
            core::mem::size_of::<crate::get::ReplyMarshal>(),
        );
        #[cfg(feature = "queryable")]
        row(
            "query",
            Kind::Query,
            core::mem::size_of::<crate::query::QueryMarshal>(),
        );
        row(
            "bytes",
            Kind::Bytes,
            core::mem::size_of::<crate::bytes::ByteBuf>(),
        );
        row(
            "config",
            Kind::Config,
            core::mem::size_of::<crate::config::ConfigState>(),
        );
        #[cfg(any(feature = "scout", feature = "scout-mcu"))]
        row(
            "hello",
            Kind::Hello,
            core::mem::size_of::<crate::scout::KeptHello>(),
        );
        #[cfg(feature = "query")]
        row(
            "querier",
            Kind::Querier,
            core::mem::size_of::<crate::object_slot::Answering<crate::querier::QuerierState>>(),
        );
        row(
            "keyexpr",
            Kind::Keyexpr,
            core::mem::size_of::<crate::keyexpr::DeclaredKeyexpr>(),
        );
        row(
            "encoding",
            Kind::Encoding,
            core::mem::size_of::<crate::encoding::HeldEncoding>(),
        );
        #[cfg(all(feature = "engine-tokio", feature = "query"))]
        row(
            "get",
            Kind::Get,
            core::mem::size_of::<crate::get::GetPlace>(),
        );
        #[cfg(all(feature = "engine-tokio", feature = "liveliness-get"))]
        row(
            "liveliness_get",
            Kind::LivelinessGet,
            core::mem::size_of::<crate::get::GetPlace>(),
        );
        #[cfg(feature = "engine-tokio")]
        row(
            "matching_listener",
            Kind::MatchingListener,
            core::mem::size_of::<crate::matching::MatchingPlace>(),
        );
        #[cfg(all(
            feature = "engine-tokio",
            any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            )
        ))]
        row(
            "decl_watch",
            Kind::DeclWatch,
            core::mem::size_of::<crate::decl_watch::WatchPlace>(),
        );
        #[cfg(all(feature = "engine-tokio", feature = "connectivity"))]
        row(
            "transport_events_listener",
            Kind::TransportEventsListener,
            core::mem::size_of::<crate::connectivity::TransportPlace>(),
        );
        #[cfg(all(feature = "engine-tokio", feature = "advanced"))]
        row(
            "advanced_publisher",
            Kind::AdvancedPublisher,
            core::mem::size_of::<crate::advanced::AdvPubState>(),
        );
        #[cfg(all(feature = "engine-tokio", feature = "advanced"))]
        row(
            "advanced_subscriber",
            Kind::AdvancedSubscriber,
            core::mem::size_of::<crate::advanced::AdvSubPlace>(),
        );
        #[cfg(all(feature = "engine-tokio", feature = "connectivity"))]
        row(
            "link_events_listener",
            Kind::LinkEventsListener,
            core::mem::size_of::<crate::connectivity::LinkPlace>(),
        );
        // What a config is made of, the largest object: its entries' rows and text, and the
        // statements of wz's own doors beside them.
        let config = crate::config::ConfigState::default();
        std::println!(
            "config-part: whole={} entries={} policies={} config_entries={} config_text_bytes={}",
            core::mem::size_of_val(&config),
            core::mem::size_of_val(&config.entries),
            core::mem::size_of_val(&config.policies),
            caps::CONFIG_ENTRIES,
            caps::CONFIG_TEXT_BYTES,
        );
        let payloads: usize = plan.slots[KINDS..]
            .iter()
            .zip(plan.sizes[KINDS..].iter())
            .map(|(slots, size)| slots * size)
            .sum();
        std::println!(
            "slot-total: slots={laid} unused={left} unused_exact={left_exact} payloads={payloads} \
             reserved={:?}",
            plan.bytes()
        );
    }

    /// The build's pools are laid where the reservation holds them as a reservation laid aside
    /// lays them, and once: the next object finds the same pools. Turned red by a reservation that
    /// lays its pools again for each object, or leaves a part of them unlaid.
    #[test]
    fn the_builds_pools_are_laid_where_they_are_held_and_once() {
        let plan = BUILT_PLAN.expect("the build's counts make pools");
        let aside = reserve_from_heap(&plan).expect("the test's heap has the memory");
        let mut reserved = Reserved(None);
        let pools = reserved.built().expect("the test's heap has the memory");
        let base = pools.base;
        assert_eq!(pools.bytes, aside.bytes);
        assert_eq!(pools.ends, aside.ends);
        for (laid, kept) in pools.pools.iter().zip(aside.pools.iter()) {
            assert_eq!(
                (laid.start, laid.slots, laid.size, laid.fresh, laid.free),
                (kept.start, kept.slots, kept.size, kept.fresh, kept.free)
            );
        }
        assert_eq!(pools.held(), 0);
        assert_eq!(reserved.built().map(|pools| pools.base), Some(base));
    }

    /// The build's default pools hold what a pico program holds when the largest channel zenoh-pico's
    /// examples and API tests open for a kind is full: its sixteen elements
    /// (`vendor/zenoh-pico/examples/unix/c11/z_querier.c` @
    /// `z_fifo_channel_reply_new(&closure, &handler, 16);`), the one handed to it while it is full
    /// and the one the program took. A build that states its own count is held to its own measure.
    #[test]
    fn the_default_pools_hold_a_full_channel_of_sixteen_and_two_more() {
        const HELD_BY_A_FULL_CHANNEL: usize = 16 + 1 + 1;
        let plan = BUILT_PLAN.expect("the build's counts make pools");
        let mut pools = reserve_from_heap(&plan).expect("the test's heap has the memory");
        let mut check = |kind: Kind, stated: Option<&str>| {
            if stated.is_some() {
                return;
            }
            let size = plan.sizes[kind as usize];
            let taken: alloc::vec::Vec<Option<NonNull<u8>>> = (0..HELD_BY_A_FULL_CHANNEL)
                .map(|_| pools.take(kind, size))
                .collect();
            let held = taken.iter().filter(|slot| slot.is_some()).count();
            for slot in taken.into_iter().flatten() {
                assert!(pools.give_back(slot), "{kind:?}: its slot goes back");
            }
            assert_eq!(
                held, HELD_BY_A_FULL_CHANNEL,
                "{kind:?}: a full channel of sixteen, one handed in and one taken"
            );
        };
        check(Kind::Sample, option_env!("WZ_LIMIT_HELD_SAMPLES"));
        #[cfg(feature = "query")]
        check(Kind::Reply, option_env!("WZ_LIMIT_HELD_REPLIES"));
        #[cfg(feature = "queryable")]
        check(Kind::Query, option_env!("WZ_LIMIT_HELD_QUERIES"));
    }

    /// The plan the library was compiled with is the one the build's counts make when worked out
    /// as a program runs: making the planning `const` changed where it is evaluated, not what.
    #[test]
    fn the_plan_worked_out_when_compiled_is_the_one_the_counts_make() {
        assert_eq!(
            BUILT_PLAN,
            built_counts().and_then(|objects| Plan::of(&objects))
        );
        assert!(BUILT_PLAN.is_ok(), "the build's counts make pools");
    }

    /// The build's counts: its sessions, each holding as many of each entity as the session's
    /// limits admit within the build's values, and the held values' own limits.
    #[test]
    fn the_build_counts_are_the_builds_limits() {
        let objects = built_counts().expect("the build's counts make pools");
        assert_eq!(objects.sessions, caps::HELD_SESSIONS);
        assert_eq!(
            (
                objects.samples,
                objects.replies,
                objects.queries,
                objects.bytes,
                objects.configs
            ),
            (
                caps::HELD_SAMPLES,
                caps::HELD_REPLIES,
                caps::HELD_QUERIES,
                caps::HELD_PAYLOADS,
                caps::HELD_CONFIGS
            )
        );
        let scouts = cfg!(any(feature = "scout", feature = "scout-mcu"));
        assert_eq!(objects.hellos, if scouts { caps::HELD_HELLOS } else { 0 });
        assert_eq!(
            objects.payload_blocks,
            [
                caps::HELD_SMALL_PAYLOAD_BLOCKS,
                caps::HELD_MEDIUM_PAYLOAD_BLOCKS,
                caps::HELD_LARGE_PAYLOAD_BLOCKS
            ]
        );
        assert_eq!(objects.encodings, caps::HELD_ENCODINGS);
        let limits = session_limits();
        let per_session = |value: Quota, build: usize| {
            value
                .lent_under(Quota::at_most(build))
                .expect("the session's limits are within the build's")
                * caps::HELD_SESSIONS
        };
        assert_eq!(
            objects.publishers,
            per_session(limits.max_publishers(), caps::MAX_PUBLISHERS)
        );
        assert_eq!(
            objects.subscribers,
            per_session(limits.max_subscriptions(), caps::MAX_SUBSCRIPTIONS)
        );
        let queryables = per_session(limits.max_queryables(), caps::MAX_QUERYABLES);
        assert_eq!(
            objects.queryables,
            if cfg!(feature = "queryable") {
                queryables
            } else {
                0
            }
        );
        let tokens = per_session(limits.max_local_tokens(), caps::MAX_LOCAL_TOKENS);
        assert_eq!(
            objects.liveliness_tokens,
            if cfg!(feature = "liveliness") {
                tokens
            } else {
                0
            }
        );
    }

    /// Each pool of the build's plan takes as many objects as its count and refuses, counted, the
    /// one past it; every slot given back, the pools hold nothing.
    #[test]
    fn each_pool_of_the_build_takes_its_count_and_refuses_one_more() {
        let plan = Plan::of(&built_counts().expect("the build's counts"))
            .expect("the build's counts make pools");
        let mut pools = reserve_from_heap(&plan).expect("the test's heap has the memory");
        let mut check = |kind: Kind| {
            let count = plan.slots[kind as usize];
            let size = plan.sizes[kind as usize];
            let taken: alloc::vec::Vec<NonNull<u8>> = (0..count)
                .map(|_| pools.take(kind, size).expect("a slot within its count"))
                .collect();
            let refused = pools.counts[count_of(size)].refused;
            assert_eq!(
                pools.take(kind, size),
                None,
                "{kind:?}: one past its count is refused"
            );
            assert_eq!(
                pools.counts[count_of(size)].refused,
                refused + 1,
                "and counted"
            );
            for slot in taken {
                assert!(pools.give_back(slot), "{kind:?}: its slot goes back");
            }
        };
        #[cfg(any(feature = "engine-tokio", feature = "object-pool"))]
        check(Kind::Session);
        #[cfg(feature = "engine-tokio")]
        check(Kind::Publisher);
        #[cfg(feature = "engine-tokio")]
        check(Kind::Subscriber);
        #[cfg(all(feature = "engine-tokio", feature = "queryable"))]
        check(Kind::Queryable);
        #[cfg(all(feature = "engine-tokio", feature = "liveliness"))]
        check(Kind::LivelinessToken);
        #[cfg(all(feature = "engine-tokio", feature = "liveliness"))]
        check(Kind::LivelinessSubscriber);
        check(Kind::Sample);
        #[cfg(feature = "query")]
        check(Kind::Reply);
        #[cfg(feature = "queryable")]
        check(Kind::Query);
        check(Kind::Bytes);
        check(Kind::Config);
        #[cfg(any(feature = "scout", feature = "scout-mcu"))]
        check(Kind::Hello);
        #[cfg(all(feature = "engine-tokio", feature = "query"))]
        check(Kind::Querier);
        check(Kind::Keyexpr);
        check(Kind::Encoding);
        #[cfg(all(feature = "engine-tokio", feature = "query"))]
        check(Kind::Get);
        #[cfg(all(feature = "engine-tokio", feature = "liveliness-get"))]
        check(Kind::LivelinessGet);
        #[cfg(feature = "engine-tokio")]
        check(Kind::MatchingListener);
        #[cfg(all(
            feature = "engine-tokio",
            any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            )
        ))]
        check(Kind::DeclWatch);
        #[cfg(all(feature = "engine-tokio", feature = "connectivity"))]
        check(Kind::TransportEventsListener);
        #[cfg(all(feature = "engine-tokio", feature = "advanced"))]
        check(Kind::AdvancedPublisher);
        #[cfg(all(feature = "engine-tokio", feature = "advanced"))]
        check(Kind::AdvancedSubscriber);
        #[cfg(all(feature = "engine-tokio", feature = "connectivity"))]
        check(Kind::LinkEventsListener);
        assert_eq!(pools.held(), 0);
    }

    /// The limits a session opens under are read where they bound an entity.
    #[test]
    fn the_bounds_are_the_limits_of_the_session() {
        let limits = session_limits();
        let bounds = Bounds::of(&limits);
        assert_eq!(bounds.subscribers, limits.max_subscriptions().most());
        assert_eq!(bounds.queryables, limits.max_queryables().most());
        assert_eq!(bounds.liveliness_tokens, limits.max_local_tokens().most());
        assert_eq!(
            bounds.liveliness_subscribers,
            limits.max_liveliness_subscriptions().most()
        );
        assert_eq!(bounds.queriers, limits.max_queriers().most());
        assert_eq!(bounds.keyexprs, limits.max_declared_keyexprs().most());
        assert_eq!(bounds.gets, limits.max_pending_queries().most());
        assert_eq!(
            bounds.liveliness_gets,
            limits.max_pending_liveliness_gets().most()
        );
        assert_eq!(
            bounds.matching_listeners,
            limits.max_matching_listeners().most()
        );
        assert_eq!(bounds.decl_watches, limits.max_decl_watches().most());
        assert_eq!(
            bounds.transport_events_listeners,
            limits.max_transport_events_listeners().most()
        );
        assert_eq!(
            bounds.advanced_publishers,
            limits.max_advanced_publishers().most()
        );
        assert_eq!(
            bounds.advanced_subscribers,
            limits.max_advanced_subscribers().most()
        );
        assert_eq!(
            bounds.link_events_listeners,
            limits.max_link_events_listeners().most()
        );
    }

    /// Pools over `memory` with `kinds` and payload pools of `payloads`, each a block's bytes and
    /// its count, laid in the order given.
    fn payload_pools(
        memory: &mut Memory,
        kinds: &[(Kind, usize, usize)],
        payloads: [(usize, usize); PAYLOAD_CLASSES],
    ) -> Pools {
        let mut plan = plan_of(kinds);
        for (at, (size, slots)) in payloads.into_iter().enumerate() {
            plan.sizes[KINDS + at] = size;
            plan.slots[KINDS + at] = slots;
        }
        assert!(plan.bytes().expect("small") <= memory.0.len());
        let base = NonNull::new(memory.0.as_mut_ptr()).expect("an array");
        // SAFETY: the memory is aligned, long enough and used by nothing else.
        unsafe { Pools::over(base, &plan, Origin::Program) }
    }

    /// A payload takes a block of the smallest pool whose blocks hold it, and of a larger one only
    /// when that pool has none free; a block lies after every kind's slots and goes back to its
    /// own pool by its address. Turned red by a payload that takes a larger block while a smaller
    /// one that holds it is free, or by a block given back to another pool.
    #[test]
    fn a_payload_takes_the_smallest_free_block_that_holds_it() {
        let mut memory = Memory([0; 512]);
        let mut pools = payload_pools(
            &mut memory,
            &[(Kind::Bytes, 2, 32)],
            [(32, 2), (64, 1), (128, 1)],
        );
        let (small, bytes) = pools.take_payload(20).expect("a small block");
        assert_eq!(bytes, 32);
        assert!(pools.lies_in_payloads(small));
        assert!(
            small.as_ptr() as usize - pools.base.as_ptr() as usize >= 2 * 32,
            "after the kinds' slots"
        );
        let (_, bytes) = pools.take_payload(32).expect("the second small block");
        assert_eq!(bytes, 32);
        let (middle, bytes) = pools
            .take_payload(1)
            .expect("a larger block once the small ones are held");
        assert_eq!(bytes, 64);
        let (_, bytes) = pools
            .take_payload(33)
            .expect("the largest holds what the middle would");
        assert_eq!(bytes, 128);
        assert!(pools.give_back(middle), "the block goes back to its pool");
        let (again, bytes) = pools.take_payload(64).expect("the middle block again");
        assert_eq!((again, bytes), (middle, 64));
        assert!(pools.give_back(small));
        let (first, bytes) = pools.take_payload(1).expect("the small block given back");
        assert_eq!((first, bytes), (small, 32));
        assert_eq!(pools.held(), 4);
    }

    /// A payload no free block of a pool that holds it takes is refused, and the refusal is
    /// counted in the class of the smallest pool that holds it; one larger than every block is
    /// refused and counted in its own class. Turned red by a refusal left uncounted, counted in
    /// another class, or by a payload that takes a block too small for it.
    #[test]
    fn a_payload_no_free_block_holds_is_refused_and_counted() {
        let mut memory = Memory([0; 512]);
        let mut pools = payload_pools(&mut memory, &[], [(32, 1), (64, 1), (128, 0)]);
        let (small, _) = pools.take_payload(32).expect("the small block");
        let (middle, _) = pools.take_payload(32).expect("the middle block");
        assert_eq!(
            pools.take_payload(16),
            None,
            "every block that holds it is held"
        );
        let small_class = class_of(32, 1).expect("a class");
        assert_eq!(pools.report(small_class).refused, 1);
        assert_eq!(
            pools.take_payload(100),
            None,
            "the largest pool has no block"
        );
        let largest_class = class_of(128, 1).expect("a class");
        assert_eq!(pools.report(largest_class).refused, 1);
        assert_eq!(pools.take_payload(129), None, "no pool's blocks hold it");
        let own_class = class_of(129, 1).expect("a class");
        assert_eq!(pools.report(own_class).refused, 1);
        let middle_class = class_of(64, 1).expect("a class");
        assert_eq!(pools.report(middle_class).in_use, 1);
        assert!(pools.give_back(small) && pools.give_back(middle));
        assert_eq!(pools.held(), 0);
        assert_eq!(pools.report(small_class).high_water, 1);
    }

    /// A payload pool is reported in the class of its blocks, with the kinds' pools of that class.
    /// Turned red by a report that leaves the payload pools out.
    #[test]
    fn a_payload_pool_is_reported_in_the_class_of_its_blocks() {
        let mut memory = Memory([0; 512]);
        let pools = payload_pools(
            &mut memory,
            &[(Kind::Sample, 1, 64)],
            [(32, 2), (64, 3), (128, 1)],
        );
        let report = pools.report(class_of(64, 1).expect("a class"));
        assert_eq!((report.slots, report.bytes), (1 + 3, 64 + 3 * 64));
        let report = pools.report(class_of(128, 1).expect("a class"));
        assert_eq!((report.slots, report.bytes), (1, 128));
    }

    /// The payload pools lie after the kinds' slots, and a plan's bytes are every pool's slots;
    /// payload blocks alone are a plan. Turned red by a plan that leaves the payload pools out
    /// of its bytes, or refuses a plan of payload blocks alone.
    #[test]
    fn the_payload_pools_lie_after_the_slots() {
        let plan = plan_of(&[(Kind::Bytes, 2, 64)]).with_payloads(&[1, 0, 0]);
        assert_eq!(
            plan.bytes(),
            Ok(2 * 64 + PAYLOAD_BLOCKS[0]),
            "the kinds' slots and one small block"
        );
        assert_eq!(Plan::of(&Counts::default()), Err(Unplanned::Empty));
        let payloads_only = Counts {
            payload_blocks: [0, 1, 0],
            ..Counts::default()
        };
        assert!(
            Plan::of(&payloads_only).is_ok(),
            "payload blocks alone are a plan"
        );
        let too_many = Counts {
            payload_blocks: [0, 0, usize::MAX],
            ..Counts::default()
        };
        assert_eq!(Plan::of(&too_many), Err(Unplanned::TooLarge));
    }
}
