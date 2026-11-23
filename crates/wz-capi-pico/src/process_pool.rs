// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The process pools: the places of the objects a program holds through this ABI that no session
//! holds for it, reserved once for the whole process, so that a program which made its first
//! object makes no allocation for them while it runs.
//!
//! # What they hold
//!
//! Each kind of object has a pool of its own (`crate::object_slot::Kind`): the objects behind the
//! owned handles (on the tokio engine its sessions, and the publishers, subscribers, queryables,
//! liveliness tokens and liveliness subscribers, and the samples, replies, queries and payloads a
//! program holds), and what a program makes before any session: its configs and the hellos it
//! keeps. Beside the pools lies the payloads' area: the bytes the owned payloads, strings and
//! slices carry, in blocks of power-of-two sizes a payload takes the smallest of that holds it, of
//! `HELD_PAYLOAD_BYTES` bytes together ([`Blocks`]). A session of the cooperative engine lies in
//! its own arena, not here.
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
//! `MAX_LOCAL_TOKENS`, `MAX_LIVELINESS_SUBSCRIPTIONS`), `HELD_SAMPLES`, `HELD_REPLIES`,
//! `HELD_QUERIES` and `HELD_PAYLOADS` of the values it holds, `HELD_CONFIGS` configs,
//! `HELD_HELLOS` kept hellos and `HELD_PAYLOAD_BYTES` bytes of payload. A program that states its
//! own counts reserves them before its first object through the doors instead.
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
    /// The bytes the payloads, strings and slices carry, their blocks' heads included.
    pub(crate) payload_bytes: usize,
}

/// The bytes of each slot of size class `class`.
pub(crate) const fn slot_bytes(class: usize) -> usize {
    SMALLEST_SLOT << class
}

/// The size class of an object of `size` bytes aligned to `align`: the smallest slot that holds
/// it, or none.
pub(crate) const fn class_of(size: usize, align: usize) -> Option<usize> {
    if align > SLOT_ALIGN {
        return None;
    }
    let mut class = 0;
    while class < CLASSES {
        if size <= slot_bytes(class) {
            return Some(class);
        }
        class += 1;
    }
    None
}

/// The bytes of each slot of the pool of a `T`: its own size rounded up to the alignment of a
/// slot, and one alignment for an object of no bytes, as a free slot holds the link to the next. A
/// kind's pool lends its slots to no other kind, so a slot larger than its object would hold
/// nothing more. Evaluated when the build is compiled, so an object aligned past a slot fails the
/// build rather than a reservation.
const fn slot_size<T>() -> usize {
    let size = core::mem::size_of::<T>();
    if core::mem::align_of::<T>() > SLOT_ALIGN {
        panic!("an object of the ABI is aligned past a slot of the process pools");
    }
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
        payload_bytes: stated.payload_bytes,
    })
}

/// How many kinds of object have a pool: the variants of `Kind`, those a build has none of
/// included, so each keeps its index in every build.
const KINDS: usize = 12;

/// Each kind's pool, its slots and the bytes of each, and the bytes of the payloads' area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    slots: [usize; KINDS],
    sizes: [usize; KINDS],
    area: usize,
}

impl Plan {
    /// The pools `objects` make: one per kind, each slot of the size of that kind's object.
    pub(crate) const fn of(objects: &Counts) -> Result<Self, Unplanned> {
        let mut plan = Self {
            slots: [0; KINDS],
            sizes: [0; KINDS],
            area: planned!(Blocks::area_of(objects.payload_bytes)),
        };
        // A session of the cooperative engine lies in its own arena; its pool is the program's to
        // reserve where the doors are.
        #[cfg(any(feature = "engine-tokio", feature = "object-pool"))]
        {
            plan = plan.with::<crate::session::PicoSessionHandle>(Kind::Session, objects.sessions);
        }
        plan = plan.with::<crate::pubsub::PublisherState>(Kind::Publisher, objects.publishers);
        plan = plan.with::<crate::pubsub::SubscriberState>(Kind::Subscriber, objects.subscribers);
        #[cfg(feature = "queryable")]
        {
            plan = plan.with::<crate::query::QueryableState>(Kind::Queryable, objects.queryables);
        }
        #[cfg(feature = "liveliness")]
        {
            plan = plan.with::<crate::liveliness::TokenState>(
                Kind::LivelinessToken,
                objects.liveliness_tokens,
            );
            plan = plan.with::<crate::pubsub::SubscriberState>(
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
        let mut kind = 0;
        let mut holds = plan.area != 0;
        while kind < KINDS {
            holds |= plan.slots[kind] != 0;
            kind += 1;
        }
        if !holds {
            return Err(Unplanned::Empty);
        }
        planned!(plan.bytes());
        Ok(plan)
    }

    /// This plan with the pool of `kind`: `count` slots, each of the bytes a slot for a `T` takes.
    const fn with<T>(mut self, kind: Kind, count: usize) -> Self {
        self.slots[kind as usize] = count;
        self.sizes[kind as usize] = const { slot_size::<T>() };
        self
    }

    /// The bytes every pool's slots take together.
    const fn slot_bytes(&self) -> Result<usize, Unplanned> {
        let mut total: usize = 0;
        let mut kind = 0;
        while kind < KINDS {
            total = match self.slots[kind].checked_mul(self.sizes[kind]) {
                Some(bytes) => match total.checked_add(bytes) {
                    Some(total) => total,
                    None => return Err(Unplanned::TooLarge),
                },
                None => return Err(Unplanned::TooLarge),
            };
            kind += 1;
        }
        Ok(total)
    }

    /// The bytes the pools take together: the slots, then the payloads' area and its marks.
    pub(crate) const fn bytes(&self) -> Result<usize, Unplanned> {
        match planned!(self.slot_bytes()).checked_add(self.area + Blocks::marks_bytes(self.area)) {
            Some(bytes) => Ok(bytes),
            None => Err(Unplanned::TooLarge),
        }
    }
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

/// The smallest block of the payloads' area: a block's head and 16 bytes after it. A free block
/// holds its links in its first 12 bytes.
const MIN_BLOCK: usize = 32;

/// How many block sizes the payloads' area has, from `MIN_BLOCK` doubling up to 1 GiB.
const ORDERS: usize = 26;

/// The end of a list of free blocks.
const NONE: u32 = u32::MAX;

/// The bytes of a block of order `order`.
const fn block_bytes(order: usize) -> usize {
    MIN_BLOCK << order
}

/// The order of the smallest block of at least `bytes` bytes, or `None` past the largest.
fn order_for(bytes: usize) -> Option<usize> {
    (0..ORDERS).find(|&order| bytes <= block_bytes(order))
}

/// What a free block of the payloads' area holds where it starts: the free blocks of its order
/// before and after it, as offsets into the area, and its order.
#[repr(C)]
#[derive(Clone, Copy)]
struct FreeBlock {
    prev: u32,
    next: u32,
    order: u32,
}

/// The payloads' area: blocks of power-of-two sizes, from `MIN_BLOCK` up, which a payload takes the
/// smallest of that holds it and its head. A block too large is split in two halves, buddies, and a
/// block given back is joined again with its buddy while that is free whole (a buddy allocator), so
/// the area serves payloads of every size up to its largest block, and what one size frees another
/// takes. The area is laid as the largest blocks that fit it, each after the one larger, so a
/// block's buddy lies inside the area exactly when it lies inside the block both were split from.
///
/// A free block is found by its mark, one bit for each `MIN_BLOCK` of the area kept after it, set
/// where a free block starts: the bytes of a block that is held are its holder's, and no bit of
/// them is read.
struct Blocks {
    /// The offset of the area from the start of the memory.
    start: usize,
    /// The bytes of the area, a multiple of `MIN_BLOCK`.
    len: usize,
    /// The offset of the marks from the start of the memory.
    marks: usize,
    /// The first free block of each order, as an offset into the area.
    free: [u32; ORDERS],
    /// The blocks held now.
    held: usize,
}

impl Blocks {
    /// The bytes of an area for `bytes` of payload: the multiple of `MIN_BLOCK` at or under it,
    /// refused past the largest block's offset an area can name.
    const fn area_of(bytes: usize) -> Result<usize, Unplanned> {
        let area = bytes - bytes % MIN_BLOCK;
        if area > block_bytes(ORDERS - 1) {
            return Err(Unplanned::TooLarge);
        }
        Ok(area)
    }

    /// The bytes of the marks of an area of `len` bytes.
    const fn marks_bytes(len: usize) -> usize {
        (len / MIN_BLOCK).div_ceil(8)
    }

    /// Lay an area of `len` bytes at `start` from `base`, its marks after it, every block free.
    ///
    /// # Safety
    /// The `len` bytes at `start` and the marks after them are writable and the area's alone, and
    /// `base + start` is aligned to 16.
    unsafe fn lay(base: NonNull<u8>, start: usize, len: usize) -> Self {
        let mut blocks = Self {
            start,
            len,
            marks: start + len,
            free: [NONE; ORDERS],
            held: 0,
        };
        base.as_ptr()
            .add(blocks.marks)
            .write_bytes(0, Self::marks_bytes(len));
        let mut at = 0;
        for order in (0..ORDERS).rev() {
            if len - at >= block_bytes(order) {
                blocks.push(base, at, order);
                at += block_bytes(order);
            }
        }
        blocks
    }

    /// The free block at `offset`.
    ///
    /// # Safety
    /// `offset` is within the area.
    unsafe fn free_block(&self, base: NonNull<u8>, offset: usize) -> *mut FreeBlock {
        base.as_ptr().add(self.start + offset).cast::<FreeBlock>()
    }

    /// The byte of the marks that holds the mark of `offset`, and the mark's bit in it.
    ///
    /// # Safety
    /// `offset` is within the area.
    unsafe fn mark_of(&self, base: NonNull<u8>, offset: usize) -> (*mut u8, u8) {
        let index = offset / MIN_BLOCK;
        (base.as_ptr().add(self.marks + index / 8), 1 << (index % 8))
    }

    /// Whether a free block starts at `offset`.
    ///
    /// # Safety
    /// `offset` is within the area.
    unsafe fn is_free(&self, base: NonNull<u8>, offset: usize) -> bool {
        let (byte, bit) = self.mark_of(base, offset);
        *byte & bit != 0
    }

    /// Put the block at `offset` of `order` first on its list of free blocks, marked. Out of
    /// line, as [`Self::unlink`] is: laying the area, splitting a block and joining one each
    /// call it, and each would otherwise hold a copy.
    ///
    /// # Safety
    /// The block lies in the area and nothing holds it.
    #[inline(never)]
    unsafe fn push(&mut self, base: NonNull<u8>, offset: usize, order: usize) {
        let head = self.free[order];
        self.free_block(base, offset).write(FreeBlock {
            prev: NONE,
            next: head,
            order: order as u32,
        });
        if head != NONE {
            (*self.free_block(base, head as usize)).prev = offset as u32;
        }
        self.free[order] = offset as u32;
        let (byte, bit) = self.mark_of(base, offset);
        *byte |= bit;
    }

    /// Take the free block at `offset` of `order` off its list, unmarked.
    ///
    /// # Safety
    /// A free block of `order` starts at `offset`.
    #[inline(never)]
    unsafe fn unlink(&mut self, base: NonNull<u8>, offset: usize, order: usize) {
        let FreeBlock { prev, next, .. } = self.free_block(base, offset).read();
        if prev == NONE {
            self.free[order] = next;
        } else {
            (*self.free_block(base, prev as usize)).next = next;
        }
        if next != NONE {
            (*self.free_block(base, next as usize)).prev = prev;
        }
        let (byte, bit) = self.mark_of(base, offset);
        *byte &= !bit;
    }

    /// The smallest free block of at least `bytes` bytes, split from a larger one when none of its
    /// size is free, as its offset and its bytes; `None` when the area has none that large.
    ///
    /// # Safety
    /// The area was laid at `base` ([`Self::lay`]).
    unsafe fn take(&mut self, base: NonNull<u8>, bytes: usize) -> Option<(usize, usize)> {
        let order = order_for(bytes.max(MIN_BLOCK))?;
        let found = (order..ORDERS).find(|&order| self.free[order] != NONE)?;
        let offset = self.free[found] as usize;
        self.unlink(base, offset, found);
        let mut split = found;
        while split > order {
            split -= 1;
            self.push(base, offset + block_bytes(split), split);
        }
        self.held += 1;
        Some((offset, block_bytes(order)))
    }

    /// Give back the block at `offset` of `bytes` bytes, joined with its buddy while that is free
    /// whole.
    ///
    /// # Safety
    /// The block is one [`Self::take`] handed out, given back once.
    unsafe fn give_back(&mut self, base: NonNull<u8>, offset: usize, bytes: usize) {
        debug_assert!(bytes.is_power_of_two() && bytes >= MIN_BLOCK);
        debug_assert!(self.held > 0, "a block given back was taken");
        let mut order = order_for(bytes).unwrap_or(0);
        let mut offset = offset;
        self.held -= 1;
        while order + 1 < ORDERS {
            let size = block_bytes(order);
            let buddy = offset ^ size;
            if buddy + size > self.len
                || !self.is_free(base, buddy)
                || (*self.free_block(base, buddy)).order as usize != order
            {
                break;
            }
            self.unlink(base, buddy, order);
            offset = offset.min(buddy);
            order += 1;
        }
        self.push(base, offset, order);
    }
}

/// Every kind's pool, laid out over one memory: each pool's slots after the one before, then the
/// payloads' area.
pub(crate) struct Pools {
    base: NonNull<u8>,
    /// The bytes of the slots, from `base`.
    bytes: usize,
    origin: Origin,
    pools: [Pool; KINDS],
    counts: [ClassCount; CLASSES + 1],
    blocks: Blocks,
}

impl Pools {
    /// Lay `plan` out over the memory at `base`, every slot free and none of them written.
    ///
    /// # Safety
    /// `base` is aligned to `SLOT_ALIGN`, the `plan.bytes()` bytes from it are writable and used
    /// by nothing else while the pools live, and `origin` says where they came from.
    unsafe fn over(base: NonNull<u8>, plan: &Plan, origin: Origin) -> Self {
        let mut pools = [Pool {
            start: 0,
            slots: 0,
            size: 0,
            fresh: 0,
            free: None,
        }; KINDS];
        let mut at = 0;
        for (kind, pool) in pools.iter_mut().enumerate() {
            pool.size = plan.sizes[kind];
            pool.start = at;
            pool.slots = plan.slots[kind];
            at += pool.slots * pool.size;
        }
        Self {
            base,
            bytes: at,
            origin,
            pools,
            counts: [ClassCount::default(); CLASSES + 1],
            blocks: Blocks::lay(base, at, plan.area),
        }
    }

    /// A free slot of the pool of `kind` for an object whose slot takes `size` bytes, or `None`,
    /// counted, when it has none. Only that pool is asked: a slot of another kind's pool is never
    /// taken, so each kind holds what was stated for it and no more. A slot given back is taken
    /// before an untouched one, and the untouched ones go lowest first.
    fn take(&mut self, kind: Kind, size: usize) -> Option<NonNull<u8>> {
        let base = self.base;
        let pool = &mut self.pools[kind as usize];
        debug_assert!(
            pool.slots == 0 || size <= pool.size,
            "an object is taken from the pool of its own kind, whose slots hold it"
        );
        let count = &mut self.counts[count_of(pool.size)];
        let slot = if let Some(slot) = pool.free {
            // SAFETY: the first word of a slot on the list is the link to the next one, written
            // when it was given back.
            pool.free = unsafe { slot.as_ptr().cast::<Option<NonNull<u8>>>().read() };
            slot
        } else if pool.fresh < pool.slots {
            // SAFETY: an untouched slot lies within the pool's slots, inside the memory the pools
            // were laid over, which is not null.
            let slot = unsafe {
                NonNull::new_unchecked(base.as_ptr().add(pool.start + pool.fresh * pool.size))
            };
            pool.fresh += 1;
            slot
        } else {
            count.refused = count.refused.saturating_add(1);
            return None;
        };
        count.in_use += 1;
        count.high_water = count.high_water.max(count.in_use);
        Some(slot)
    }

    /// Whether `place` lies in the memory of the pools.
    #[cfg(test)]
    fn lies_in(&self, place: NonNull<u8>) -> bool {
        (place.as_ptr() as usize).wrapping_sub(self.base.as_ptr() as usize) < self.bytes
    }

    /// Give `place` back to the pool it lies in; `false` when it lies in none of them.
    fn give_back(&mut self, place: NonNull<u8>) -> bool {
        let at = (place.as_ptr() as usize).wrapping_sub(self.base.as_ptr() as usize);
        if at >= self.bytes {
            return false;
        }
        let Some(pool) = self
            .pools
            .iter_mut()
            .find(|pool| at < pool.start + pool.slots * pool.size)
        else {
            return false;
        };
        debug_assert_eq!(
            (at - pool.start) % pool.size,
            0,
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
        self.counts[count_of(pool.size)].in_use -= 1;
        true
    }

    /// How many objects the pools hold now, the payloads' blocks among them.
    #[cfg(any(test, feature = "object-pool"))]
    fn held(&self) -> usize {
        self.counts.iter().map(|count| count.in_use).sum::<usize>() + self.blocks.held
    }

    /// The pools of size class `class` together.
    #[cfg(any(test, feature = "object-pool"))]
    fn report(&self, class: usize) -> ClassReport {
        let count = &self.counts[class];
        let pools = || {
            self.pools
                .iter()
                .filter(move |pool| count_of(pool.size) == class)
        };
        ClassReport {
            slot_bytes: slot_bytes(class),
            slots: pools().map(|pool| pool.slots).sum(),
            bytes: pools().map(|pool| pool.slots * pool.size).sum(),
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

// SAFETY: the memory of the pools is reached only through the lock this is held behind, by one
// thread at a time, and no pointer into it is handed out except to the slot's own object.
unsafe impl Send for Reserved {}

static RESERVED: Lock<Reserved> = Lock::new(Reserved(None));

/// A slot for a `T` of `kind`, from that kind's pool, or `None` when it has none free. The first
/// object a program makes reserves the build's pools when it reserved none ([`reserve_built`]);
/// when they cannot be reserved either, every object is refused and the next asks again.
pub(crate) fn take<T>(kind: Kind) -> Option<NonNull<u8>> {
    take_slot(kind, const { slot_size::<T>() })
}

/// [`take`] for a slot of `size` bytes. Not generic and never inlined: every door that places an
/// object calls this one body, which holds the lock, the first reservation and the pool's count.
#[inline(never)]
fn take_slot(kind: Kind, size: usize) -> Option<NonNull<u8>> {
    RESERVED.with(|reserved| {
        if reserved.0.is_none() {
            reserved.0 = reserve_built();
        }
        reserved.0.as_mut()?.take(kind, size)
    })
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
        payload_bytes: caps::HELD_PAYLOAD_BYTES,
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

/// The pools of `plan` from the heap in one allocation, or `None` when the heap has not the
/// memory.
fn reserve_from_heap(plan: &Plan) -> Option<Pools> {
    let layout = Layout::from_size_align(plan.bytes().ok()?, SLOT_ALIGN).ok()?;
    // SAFETY: the layout is not of zero bytes: a plan has a slot.
    let base = NonNull::new(unsafe { alloc::alloc::alloc(layout) })?;
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

/// The build's pools ([`BUILT_PLAN`]): what the first object a program makes reserves when it
/// reserved none. `None` when the counts make no pool or the heap has not the memory.
fn reserve_built() -> Option<Pools> {
    match BUILT_PLAN {
        Ok(plan) => reserve_from_heap(&plan),
        Err(_) => None,
    }
}

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

/// Whether `place` lies in the payloads' area of the pools reserved now.
#[cfg(test)]
pub(crate) fn lies_in_area(place: NonNull<u8>) -> bool {
    RESERVED.with(|reserved| {
        reserved.0.as_ref().is_some_and(|pools| {
            let at = (place.as_ptr() as usize).wrapping_sub(pools.base.as_ptr() as usize);
            at.wrapping_sub(pools.blocks.start) < pools.blocks.len
        })
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

/// A block of the payloads' area of at least `bytes` bytes, aligned to 16, and the bytes it has;
/// `None` when the area has no free block that large. The first block reserves the build's pools
/// when none are, as the first object does ([`take`]).
pub(crate) fn take_block(bytes: usize) -> Option<(NonNull<u8>, usize)> {
    RESERVED.with(|reserved| {
        if reserved.0.is_none() {
            reserved.0 = reserve_built();
        }
        let pools = reserved.0.as_mut()?;
        let base = pools.base;
        // SAFETY: the area was laid over the pools' memory, which this lock holds.
        let (offset, bytes) = unsafe { pools.blocks.take(base, bytes) }?;
        // SAFETY: the block lies in the pools' memory, at an offset aligned to 16 from `base`.
        let at = unsafe { NonNull::new_unchecked(base.as_ptr().add(pools.blocks.start + offset)) };
        Some((at, bytes))
    })
}

/// Give back the block at `at` of `bytes` bytes.
///
/// # Safety
/// `at` and `bytes` are a block [`take_block`] handed out, nothing holds it, and it is given back
/// once.
pub(crate) unsafe fn give_back_block(at: NonNull<u8>, bytes: usize) {
    RESERVED.with(|reserved| {
        // A block is held only while the pools that lent it are: they are not given up while
        // they hold one.
        if let Some(pools) = reserved.0.as_mut() {
            let base = pools.base;
            let offset = at.as_ptr() as usize - (base.as_ptr() as usize + pools.blocks.start);
            pools.blocks.give_back(base, offset, bytes);
        }
    });
}

/// The limits every session of this ABI opens under: the snapshot `z_open` hands its engine.
const fn session_limits() -> SessionLimits {
    SessionLimits::defaults()
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
/// As [`Pools::over`].
#[cfg(feature = "object-pool")]
unsafe fn install(base: NonNull<u8>, plan: &Plan, origin: Origin) -> Result<(), Refused> {
    let refused = RESERVED.with(|reserved| {
        if reserved.0.is_some() {
            return true;
        }
        reserved.0 = Some(Pools::over(base, plan, origin));
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
    let layout = plan
        .bytes()
        .ok()
        .and_then(|bytes| Layout::from_size_align(bytes, SLOT_ALIGN).ok())
        .ok_or(Refused::NoMemory)?;
    // SAFETY: the layout is not of zero bytes: a plan has a slot.
    let base = NonNull::new(unsafe { alloc::alloc::alloc(layout) }).ok_or(Refused::NoMemory)?;
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

    /// Memory for pools in a test, aligned as a slot.
    #[repr(C, align(16))]
    struct Memory([u8; 512]);

    fn counts() -> Counts {
        Counts::default()
    }

    /// A plan of `slots` slots of `size` bytes for each kind named.
    fn plan_of(kinds: &[(Kind, usize, usize)]) -> Plan {
        let mut plan = Plan {
            slots: [0; KINDS],
            sizes: [0; KINDS],
            area: 0,
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
    };

    const UNBOUNDED: Bounds = Bounds {
        subscribers: None,
        queryables: None,
        liveliness_tokens: None,
        liveliness_subscribers: None,
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
            ..counts()
        };
        let objects = resolve(&stated, &BOUNDED).expect("every count is bounded");
        assert_eq!(objects.sessions, 2);
        assert_eq!(objects.subscribers, 8, "the bound, four, per session");
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
            payload_bytes: 11,
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
        assert_eq!(objects.payload_bytes, 11);
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
            core::mem::size_of::<crate::session::PicoSessionHandle>(),
        );
        row(
            "publisher",
            Kind::Publisher,
            core::mem::size_of::<crate::pubsub::PublisherState>(),
        );
        row(
            "subscriber",
            Kind::Subscriber,
            core::mem::size_of::<crate::pubsub::SubscriberState>(),
        );
        #[cfg(feature = "queryable")]
        row(
            "queryable",
            Kind::Queryable,
            core::mem::size_of::<crate::query::QueryableState>(),
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
                core::mem::size_of::<crate::pubsub::SubscriberState>(),
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
        let marks = Blocks::marks_bytes(plan.area);
        std::println!(
            "slot-total: slots={laid} unused={left} unused_exact={left_exact} area={} marks={marks} \
             reserved={:?}",
            plan.area,
            plan.bytes()
        );
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
        assert_eq!(objects.payload_bytes, caps::HELD_PAYLOAD_BYTES);
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
        check(Kind::Publisher);
        check(Kind::Subscriber);
        #[cfg(feature = "queryable")]
        check(Kind::Queryable);
        #[cfg(feature = "liveliness")]
        check(Kind::LivelinessToken);
        #[cfg(feature = "liveliness")]
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
    }

    /// The free blocks of `order`, by their offsets, first to last.
    fn free_of(blocks: &Blocks, base: NonNull<u8>, order: usize) -> alloc::vec::Vec<usize> {
        let mut offsets = alloc::vec::Vec::new();
        let mut at = blocks.free[order];
        while at != NONE {
            offsets.push(at as usize);
            // SAFETY: a free block of the list starts at `at`.
            at = unsafe { (*blocks.free_block(base, at as usize)).next };
        }
        offsets
    }

    /// An area of `len` bytes laid over `memory`, which holds it and its marks.
    fn area_over(memory: &mut Memory, len: usize) -> (Blocks, NonNull<u8>) {
        assert!(len + Blocks::marks_bytes(len) <= memory.0.len());
        let base = NonNull::new(memory.0.as_mut_ptr()).expect("an array");
        // SAFETY: the memory is aligned, holds the area and its marks, and is used by nothing else.
        (unsafe { Blocks::lay(base, 0, len) }, base)
    }

    /// A payload's bytes are rounded down to whole blocks of the smallest size, and an area past
    /// the largest block an offset can name is refused.
    #[test]
    fn an_area_is_whole_blocks_and_refused_past_the_largest() {
        assert_eq!(Blocks::area_of(0), Ok(0));
        assert_eq!(Blocks::area_of(MIN_BLOCK - 1), Ok(0));
        assert_eq!(Blocks::area_of(3 * MIN_BLOCK + 5), Ok(3 * MIN_BLOCK));
        assert_eq!(
            Blocks::area_of(block_bytes(ORDERS - 1)),
            Ok(block_bytes(ORDERS - 1))
        );
        assert_eq!(
            Blocks::area_of(block_bytes(ORDERS - 1) + MIN_BLOCK),
            Err(Unplanned::TooLarge)
        );
        assert_eq!(Blocks::marks_bytes(9 * MIN_BLOCK), 2);
    }

    /// The area is laid as the largest blocks that fit it, the larger first.
    #[test]
    fn the_area_is_laid_as_the_largest_blocks_that_fit_it() {
        let mut memory = Memory([0xA5; 512]);
        let (blocks, base) = area_over(&mut memory, 3 * MIN_BLOCK);
        assert_eq!(free_of(&blocks, base, 1), [0]);
        assert_eq!(free_of(&blocks, base, 0), [2 * MIN_BLOCK]);
        for order in 2..ORDERS {
            assert!(free_of(&blocks, base, order).is_empty(), "order {order}");
        }
        assert_eq!(blocks.held, 0);
    }

    /// A take is the smallest block that holds its bytes, split from a larger one, the halves it
    /// leaves free; one larger than any free block, or than the area, is refused.
    #[test]
    fn a_block_is_the_smallest_that_holds_its_bytes() {
        let mut memory = Memory([0; 512]);
        let (mut blocks, base) = area_over(&mut memory, 8 * MIN_BLOCK);
        // SAFETY: the area was laid over `memory` just above.
        unsafe {
            assert_eq!(blocks.take(base, 20), Some((0, MIN_BLOCK)));
            assert_eq!(free_of(&blocks, base, 0), [MIN_BLOCK]);
            assert_eq!(free_of(&blocks, base, 1), [2 * MIN_BLOCK]);
            assert_eq!(free_of(&blocks, base, 2), [4 * MIN_BLOCK]);
            assert_eq!(
                blocks.take(base, MIN_BLOCK + 1),
                Some((2 * MIN_BLOCK, 2 * MIN_BLOCK))
            );
            assert_eq!(
                blocks.take(base, 4 * MIN_BLOCK),
                Some((4 * MIN_BLOCK, 4 * MIN_BLOCK))
            );
            assert_eq!(
                blocks.take(base, 2 * MIN_BLOCK),
                None,
                "no free block that large"
            );
            assert_eq!(blocks.take(base, 9 * MIN_BLOCK), None, "past the area");
            assert_eq!(blocks.take(base, 1), Some((MIN_BLOCK, MIN_BLOCK)));
            assert_eq!(blocks.take(base, 1), None, "the area is full");
            assert_eq!(blocks.held, 4);
        }
    }

    /// Blocks given back in any order join their buddies again into the area as it was laid, and
    /// a buddy still held keeps its half apart.
    #[test]
    fn blocks_given_back_join_their_buddies() {
        let mut memory = Memory([0; 512]);
        let (mut blocks, base) = area_over(&mut memory, 8 * MIN_BLOCK);
        // SAFETY: the area was laid over `memory` just above; each block is given back once.
        unsafe {
            let taken: alloc::vec::Vec<(usize, usize)> = (0..8)
                .map(|_| blocks.take(base, MIN_BLOCK).expect("a block"))
                .collect();
            for &(offset, bytes) in [5, 0, 7, 2].iter().map(|&k| &taken[k]) {
                blocks.give_back(base, offset, bytes);
            }
            assert!(free_of(&blocks, base, 3).is_empty(), "its buddies are held");
            for &(offset, bytes) in [1, 6, 3].iter().map(|&k| &taken[k]) {
                blocks.give_back(base, offset, bytes);
            }
            assert_eq!(free_of(&blocks, base, 2), [0], "the lower half joined");
            let (offset, bytes) = taken[4];
            blocks.give_back(base, offset, bytes);
            assert_eq!(
                free_of(&blocks, base, 3),
                [0],
                "the whole area is one block again"
            );
            for order in 0..3 {
                assert!(free_of(&blocks, base, order).is_empty(), "order {order}");
            }
            assert_eq!(blocks.held, 0);
        }
    }

    /// A block at the end of an area that is no power of two has no buddy past the area, and is
    /// given back as it was laid.
    #[test]
    fn a_block_whose_buddy_is_past_the_area_stays_apart() {
        let mut memory = Memory([0; 512]);
        let (mut blocks, base) = area_over(&mut memory, 3 * MIN_BLOCK);
        // SAFETY: the area was laid over `memory` just above; each block is given back once.
        unsafe {
            let last = blocks.take(base, MIN_BLOCK).expect("the last block");
            assert_eq!(last, (2 * MIN_BLOCK, MIN_BLOCK));
            let first = blocks.take(base, 2 * MIN_BLOCK).expect("the first block");
            blocks.give_back(base, last.0, last.1);
            blocks.give_back(base, first.0, first.1);
        }
        assert_eq!(free_of(&blocks, base, 1), [0]);
        assert_eq!(free_of(&blocks, base, 0), [2 * MIN_BLOCK]);
    }

    /// The pools lay the payloads' area after their slots: a plan's bytes are the slots, the area
    /// and its marks, a block lies past every slot, and the pools hold it until it is given back.
    #[test]
    fn the_payloads_area_lies_after_the_slots() {
        let mut memory = Memory([0; 512]);
        let mut plan = plan_of(&[(Kind::Bytes, 2, 64)]);
        plan.area = 8 * MIN_BLOCK;
        let bytes = plan.bytes().expect("small");
        assert_eq!(bytes, 2 * 64 + 8 * MIN_BLOCK + 1);
        let base = NonNull::new(memory.0.as_mut_ptr()).expect("an array");
        // SAFETY: the memory is aligned, long enough and used by nothing else.
        let mut pools = unsafe { Pools::over(base, &plan, Origin::Program) };
        // SAFETY: the area was laid with the pools.
        let (offset, got) = unsafe { pools.blocks.take(base, 40) }.expect("a block");
        assert_eq!((offset, got), (0, 2 * MIN_BLOCK));
        assert_eq!(pools.blocks.start, 2 * 64, "after the slots");
        assert_eq!(pools.held(), 1, "a block held keeps the pools");
        // SAFETY: the block taken just above, given back once.
        unsafe { pools.blocks.give_back(base, offset, got) };
        assert_eq!(pools.held(), 0);
        let only_area = Plan {
            area: MIN_BLOCK,
            ..plan_of(&[])
        };
        assert_eq!(only_area.bytes(), Ok(MIN_BLOCK + 1));
        assert_eq!(Plan::of(&Counts::default()), Err(Unplanned::Empty));
        let payloads_only = Counts {
            payload_bytes: MIN_BLOCK,
            ..Counts::default()
        };
        assert!(Plan::of(&payloads_only).is_ok(), "an area alone is a plan");
    }
}
