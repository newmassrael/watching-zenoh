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
//! keeps. A session of the cooperative engine lies in its own arena, not here.
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
//! `HELD_QUERIES` and `HELD_PAYLOADS` of the values it holds, `HELD_CONFIGS` configs and
//! `HELD_HELLOS` kept hellos. A program that states its own counts reserves them before its
//! first object through the doors instead.
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
//! another kind of the same size has free. A slot is the smallest of the slot sizes the pools are
//! reported by that holds its object, or for an object larger than the largest of them (a config
//! of the build's text) the object's own size. A pool with no free slot refuses the object: the
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

/// The bytes of each slot of the pool of a `T`: the smallest size class that holds it, or past
/// the largest class its own size rounded up to the alignment of a slot. Evaluated when the build
/// is compiled, so an object aligned past a slot fails the build rather than a reservation.
const fn slot_size<T>() -> usize {
    let size = core::mem::size_of::<T>();
    if core::mem::align_of::<T>() > SLOT_ALIGN {
        panic!("an object of the ABI is aligned past a slot of the process pools");
    }
    match class_of(size, 1) {
        Some(class) => slot_bytes(class),
        None => size.next_multiple_of(SLOT_ALIGN),
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

/// The objects the pools hold, for all sessions together: each count read against the bounds of
/// the limits of a session, the entity counts times the sessions.
pub(crate) fn resolve(stated: &Counts, bounds: &Bounds) -> Result<Counts, Unplanned> {
    let sessions = stated.sessions;
    let per_session = |each: usize| each.checked_mul(sessions).ok_or(Unplanned::TooLarge);
    // A build without the plane holds none of its entities, whatever its limit says.
    let bounded = |has: bool, stated: usize, bound: Option<usize>| {
        if !has || sessions == 0 {
            return Ok(0);
        }
        let each = match (stated, bound) {
            (0, Some(bound)) => bound,
            (0, None) => return Err(Unplanned::Unbounded),
            (stated, Some(bound)) => stated.min(bound),
            (stated, None) => stated,
        };
        per_session(each)
    };
    Ok(Counts {
        sessions,
        publishers: per_session(stated.publishers)?,
        subscribers: bounded(true, stated.subscribers, bounds.subscribers)?,
        queryables: bounded(
            cfg!(feature = "queryable"),
            stated.queryables,
            bounds.queryables,
        )?,
        liveliness_tokens: bounded(
            cfg!(feature = "liveliness"),
            stated.liveliness_tokens,
            bounds.liveliness_tokens,
        )?,
        liveliness_subscribers: bounded(
            cfg!(feature = "liveliness"),
            stated.liveliness_subscribers,
            bounds.liveliness_subscribers,
        )?,
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
    })
}

/// How many kinds of object have a pool: the variants of `Kind`, those a build has none of
/// included, so each keeps its index in every build.
const KINDS: usize = 12;

/// Each kind's pool: its slots, and the bytes of each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    slots: [usize; KINDS],
    sizes: [usize; KINDS],
}

impl Plan {
    /// The pools `objects` make: one per kind, each slot of the size of that kind's object.
    pub(crate) fn of(objects: &Counts) -> Result<Self, Unplanned> {
        let mut plan = Self {
            slots: [0; KINDS],
            sizes: [0; KINDS],
        };
        // A session of the cooperative engine lies in its own arena; its pool is the program's to
        // reserve where the doors are.
        #[cfg(any(feature = "engine-tokio", feature = "object-pool"))]
        plan.add::<crate::session::PicoSessionHandle>(Kind::Session, objects.sessions);
        plan.add::<crate::pubsub::PublisherState>(Kind::Publisher, objects.publishers);
        plan.add::<crate::pubsub::SubscriberState>(Kind::Subscriber, objects.subscribers);
        #[cfg(feature = "queryable")]
        plan.add::<crate::query::QueryableState>(Kind::Queryable, objects.queryables);
        #[cfg(feature = "liveliness")]
        plan.add::<crate::liveliness::TokenState>(Kind::LivelinessToken, objects.liveliness_tokens);
        #[cfg(feature = "liveliness")]
        plan.add::<crate::pubsub::SubscriberState>(
            Kind::LivelinessSubscriber,
            objects.liveliness_subscribers,
        );
        plan.add::<crate::pubsub::SampleMarshal>(Kind::Sample, objects.samples);
        #[cfg(feature = "query")]
        plan.add::<crate::get::ReplyMarshal>(Kind::Reply, objects.replies);
        #[cfg(feature = "queryable")]
        plan.add::<crate::query::QueryMarshal>(Kind::Query, objects.queries);
        plan.add::<crate::bytes::ByteBuf>(Kind::Bytes, objects.bytes);
        plan.add::<crate::config::ConfigState>(Kind::Config, objects.configs);
        #[cfg(any(feature = "scout", feature = "scout-mcu"))]
        plan.add::<crate::scout::KeptHello>(Kind::Hello, objects.hellos);
        if plan.slots.iter().all(|&slots| slots == 0) {
            return Err(Unplanned::Empty);
        }
        plan.bytes()?;
        Ok(plan)
    }

    /// The pool of `kind`: `count` slots, each of the bytes a slot for a `T` takes.
    fn add<T>(&mut self, kind: Kind, count: usize) {
        self.slots[kind as usize] = count;
        self.sizes[kind as usize] = const { slot_size::<T>() };
    }

    /// The bytes every pool's slots take together.
    pub(crate) fn bytes(&self) -> Result<usize, Unplanned> {
        let mut total: usize = 0;
        for (&slots, &size) in self.slots.iter().zip(self.sizes.iter()) {
            total = slots
                .checked_mul(size)
                .and_then(|bytes| total.checked_add(bytes))
                .ok_or(Unplanned::TooLarge)?;
        }
        Ok(total)
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

/// The pool of one kind: where its slots start, their bytes, and its free slots linked through
/// their first word.
#[derive(Clone, Copy, Debug)]
struct Pool {
    /// The offset of its first slot from the start of the memory.
    start: usize,
    slots: usize,
    size: usize,
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

/// The pools of one slot size together, as the doors report them.
#[cfg(any(test, feature = "object-pool"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ClassReport {
    pub(crate) slot_bytes: usize,
    pub(crate) slots: usize,
    pub(crate) in_use: usize,
    pub(crate) high_water: usize,
    pub(crate) refused: usize,
}

/// Every kind's pool, laid out over one memory: each pool's slots after the one before.
pub(crate) struct Pools {
    base: NonNull<u8>,
    bytes: usize,
    origin: Origin,
    pools: [Pool; KINDS],
    counts: [ClassCount; CLASSES + 1],
}

impl Pools {
    /// Lay `plan` out over the memory at `base`, every slot free.
    ///
    /// # Safety
    /// `base` is aligned to `SLOT_ALIGN`, the `plan.bytes()` bytes from it are writable and used
    /// by nothing else while the pools live, and `origin` says where they came from.
    unsafe fn over(base: NonNull<u8>, plan: &Plan, origin: Origin) -> Self {
        let mut pools = [Pool {
            start: 0,
            slots: 0,
            size: 0,
            free: None,
        }; KINDS];
        let mut at = 0;
        for (kind, pool) in pools.iter_mut().enumerate() {
            pool.size = plan.sizes[kind];
            pool.start = at;
            pool.slots = plan.slots[kind];
            // Linked from the last slot to the first, so the lowest is taken first.
            for index in (0..pool.slots).rev() {
                let slot = base.as_ptr().add(at + index * pool.size);
                slot.cast::<Option<NonNull<u8>>>().write(pool.free);
                pool.free = Some(NonNull::new_unchecked(slot));
            }
            at += pool.slots * pool.size;
        }
        Self {
            base,
            bytes: at,
            origin,
            pools,
            counts: [ClassCount::default(); CLASSES + 1],
        }
    }

    /// A free slot of the pool of `kind` for an object whose slot takes `size` bytes, or `None`,
    /// counted, when it has none. Only that pool is asked: a slot of another kind's pool is never
    /// taken, so each kind holds what was stated for it and no more.
    fn take(&mut self, kind: Kind, size: usize) -> Option<NonNull<u8>> {
        let pool = &mut self.pools[kind as usize];
        debug_assert!(
            pool.slots == 0 || size <= pool.size,
            "an object is taken from the pool of its own kind, whose slots hold it"
        );
        let count = &mut self.counts[count_of(pool.size)];
        let Some(slot) = pool.free else {
            count.refused = count.refused.saturating_add(1);
            return None;
        };
        // SAFETY: the first word of a free slot is the link to the next free one, written when it
        // was laid out or given back.
        pool.free = unsafe { slot.as_ptr().cast::<Option<NonNull<u8>>>().read() };
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
        // SAFETY: the slot lies in this pool and its value is gone, so its first word may hold
        // the link.
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

    /// How many objects the pools hold now.
    #[cfg(any(test, feature = "object-pool"))]
    fn held(&self) -> usize {
        self.counts.iter().map(|count| count.in_use).sum()
    }

    /// The pools of size class `class` together.
    #[cfg(any(test, feature = "object-pool"))]
    fn report(&self, class: usize) -> ClassReport {
        let count = &self.counts[class];
        ClassReport {
            slot_bytes: slot_bytes(class),
            slots: self
                .pools
                .iter()
                .filter(|pool| count_of(pool.size) == class)
                .map(|pool| pool.slots)
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

// SAFETY: the memory of the pools is reached only through the lock this is held behind, by one
// thread at a time, and no pointer into it is handed out except to the slot's own object.
unsafe impl Send for Reserved {}

static RESERVED: Lock<Reserved> = Lock::new(Reserved(None));

/// A slot for a `T` of `kind`, from that kind's pool, or `None` when it has none free. The first
/// object a program makes reserves the build's pools when it reserved none ([`reserve_built`]);
/// when they cannot be reserved either, every object is refused and the next asks again.
pub(crate) fn take<T>(kind: Kind) -> Option<NonNull<u8>> {
    let size = const { slot_size::<T>() };
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
fn built_counts() -> Result<Counts, Unplanned> {
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
        publishers: each::<{ caps::MAX_PUBLISHERS }>(limits.max_publishers()).unwrap_or(0),
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
    };
    resolve(&built, &bounds)
}

/// How many of an entity one session holds: `value`, the limit the library opens a session under,
/// within `CEILING`, the build's value of it, which sizes the pool; `None` where the limit holds no
/// bound.
fn each<const CEILING: usize>(value: Quota) -> Option<usize> {
    value.lent_under(Quota::at_most(CEILING)).ok()
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

/// The build's pools ([`built_counts`]): what the first object a program makes reserves when it
/// reserved none. `None` when the counts make no pool or the heap has not the memory.
fn reserve_built() -> Option<Pools> {
    let plan = built_counts().and_then(|objects| Plan::of(&objects)).ok()?;
    reserve_from_heap(&plan)
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

/// Give `place` back to the pool it lies in; `false` when it lies in none, and is the heap's.
pub(crate) fn give_back(place: NonNull<u8>) -> bool {
    RESERVED.with(|reserved| {
        reserved
            .0
            .as_mut()
            .is_some_and(|pools| pools.give_back(place))
    })
}

/// The limits every session of this ABI opens under: the snapshot `z_open` hands its engine.
fn session_limits() -> SessionLimits {
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

    /// An object larger than the largest class has a slot of its own size, rounded up to the
    /// alignment of a slot, and is counted after the last class; one a class holds takes the
    /// class's slot.
    #[test]
    fn an_object_past_the_largest_class_takes_a_slot_of_its_own_size() {
        assert_eq!(slot_size::<[u8; 100]>(), 128);
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
}
