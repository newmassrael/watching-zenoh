// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_object_pool_*`: fixed pools, one per slot size, that the objects behind this ABI's
//! owned handles are taken from in place of the heap, so that a program which reserved them makes
//! no allocation for them while it runs: its sessions, publishers, subscribers, queryables,
//! liveliness tokens and liveliness subscribers, and the samples, replies, queries and payloads it
//! holds.
//!
//! A door wz has and zenoh-pico does not, so each is `wz_ext_*`, declared in `wz_ext.h`, and part
//! of the unstable surface: the `object-pool` capability implies `unstable-api`.
//!
//! # Reserving
//!
//! The program states how many of each object it holds at once (`wz_ext_object_pool_counts_t`)
//! and reserves the pools once, before the first object it wants pooled: from the heap in one
//! allocation (`wz_ext_object_pool_reserve`) or, with the `object-pool-region` capability, over
//! memory it hands over (`wz_ext_object_pool_place`), whose size `wz_ext_object_pool_bytes`
//! answers. A reservation is all or nothing: a refused one leaves no pool and touches no memory.
//!
//! # The counts and the limits of a session
//!
//! A session's entities are bounded by the limits it opens under: its subscribers by
//! `MAX_SUBSCRIPTIONS`, its queryables by `MAX_QUERYABLES`, its liveliness tokens by
//! `MAX_LOCAL_TOKENS` and its liveliness subscribers by `MAX_LIVELINESS_SUBSCRIPTIONS`. A count of
//! one of those left at zero takes the bound of its limit, and a count stated above the bound is
//! held to it: the session refuses the one more anyway, so a slot past it would never be used. A
//! count left at zero whose limit holds no bound (a heap build that states none) is refused, as a
//! pool of no bound cannot be reserved. The count of an entity is per session, times `sessions`.
//! The objects no limit bounds (sessions, publishers, and the samples, replies, queries and
//! payloads the program holds) are as stated, zero being none. A count of an object the build has
//! none of is not read.
//!
//! # Running
//!
//! An object takes the smallest slot that holds it. A pool with no free slot refuses the object:
//! the call answers `_Z_ERR_SYSTEM_OUT_OF_MEMORY` having declared or opened nothing, and the
//! refusal is counted (`wz_ext_object_pool_class`). Once the pools are reserved nothing falls back
//! to the heap. An object let go frees its slot for the next one. Before the reservation the
//! objects are the heap's, as in a build without the capability, and one made then goes back to the
//! heap when it is let go (`crate::object_slot`).
//!
//! # Releasing
//!
//! `wz_ext_object_pool_release` gives the pools up when no object is held in them: the heap's
//! memory is freed, the program's is the program's again, and the objects are the heap's once
//! more.
//!
//! What a pool holds is the object behind a handle. The bytes a payload carries, the configs, key
//! expressions, strings, encodings and closures, and the owned values of the other doors are the
//! heap's in either build.

use core::alloc::Layout;
#[cfg(feature = "object-pool-region")]
use core::ffi::c_void;
use core::ptr::NonNull;

use wz_capi_port::sync::Lock;
use wz_session_core::limits::SessionLimits;

use crate::ffi::guarded;
use crate::result::{
    ZResult, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_NULL, Z_ERR_SYSTEM_OUT_OF_MEMORY, Z_OK,
};

/// How many pools there are: one per slot size, the smallest 16 bytes and each one twice the one
/// before, up to 16 KiB.
pub const WZ_EXT_OBJECT_POOL_CLASSES: usize = 11;

/// The slots of the smallest pool, in bytes.
const SMALLEST_SLOT: usize = 16;

/// The alignment of every slot: the most any object of this ABI asks for, which the build checks
/// for each one it pools.
const SLOT_ALIGN: usize = 16;

/// How many of each object the program holds at once, as it states them to reserve the pools.
///
/// The entity counts (`publishers` to `liveliness_subscribers`) are per session; the rest are for
/// all sessions together. Zero is read as the module says: the bound of the session's limit where
/// one bounds the object, none where none does.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct wz_ext_object_pool_counts_t {
    /// Open sessions.
    pub sessions: usize,
    /// Publishers of each session.
    pub publishers: usize,
    /// Subscribers of each session, at most its `MAX_SUBSCRIPTIONS`.
    pub subscribers: usize,
    /// Queryables of each session, at most its `MAX_QUERYABLES`.
    pub queryables: usize,
    /// Liveliness tokens of each session, at most its `MAX_LOCAL_TOKENS`.
    pub liveliness_tokens: usize,
    /// Liveliness subscribers of each session (an advanced subscriber's detection of publishers
    /// among them), at most its `MAX_LIVELINESS_SUBSCRIPTIONS`.
    pub liveliness_subscribers: usize,
    /// Owned samples: taken out of a callback, cloned, or held in a channel.
    pub samples: usize,
    /// Owned replies and reply errors.
    pub replies: usize,
    /// Owned queries, each holding its query open until it is dropped.
    pub queries: usize,
    /// Owned payloads (`z_owned_bytes_t`).
    pub bytes: usize,
}

/// One pool as `wz_ext_object_pool_class` reports it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct wz_ext_object_pool_class_t {
    /// The bytes of each of its slots.
    pub slot_bytes: usize,
    /// Its slots; zero while no pool is reserved.
    pub slots: usize,
    /// The slots holding an object now.
    pub in_use: usize,
    /// The most slots that held an object at once since the reservation.
    pub high_water: usize,
    /// The objects it refused for want of a free slot since the reservation.
    pub refused: usize,
}

/// The bytes of each slot of pool `class`.
const fn slot_bytes(class: usize) -> usize {
    SMALLEST_SLOT << class
}

/// The pool an object of `size` bytes aligned to `align` takes its slot from: the smallest whose
/// slot holds it, or none.
const fn class_of(size: usize, align: usize) -> Option<usize> {
    if align > SLOT_ALIGN {
        return None;
    }
    let mut class = 0;
    while class < WZ_EXT_OBJECT_POOL_CLASSES {
        if size <= slot_bytes(class) {
            return Some(class);
        }
        class += 1;
    }
    None
}

/// The pool of a `T`. Evaluated when the build is compiled, so an object no slot holds fails the
/// build rather than a reservation.
const fn class_for<T>() -> usize {
    match class_of(core::mem::size_of::<T>(), core::mem::align_of::<T>()) {
        Some(class) => class,
        None => panic!("an object of the ABI has no slot in the object pools"),
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

impl Unplanned {
    /// The code a door answers for it.
    fn code(self) -> ZResult {
        match self {
            Unplanned::Unbounded | Unplanned::Empty => Z_ERR_CONFIG_INVALID_VALUE,
            Unplanned::TooLarge => Z_ERR_SYSTEM_OUT_OF_MEMORY,
        }
    }
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
pub(crate) fn resolve(
    stated: &wz_ext_object_pool_counts_t,
    bounds: &Bounds,
) -> Result<wz_ext_object_pool_counts_t, Unplanned> {
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
    Ok(wz_ext_object_pool_counts_t {
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
    })
}

/// How many slots each pool has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    slots: [usize; WZ_EXT_OBJECT_POOL_CLASSES],
}

impl Plan {
    /// The slots `objects` take, each object in the pool of its size.
    pub(crate) fn of(objects: &wz_ext_object_pool_counts_t) -> Result<Self, Unplanned> {
        let mut plan = Self {
            slots: [0; WZ_EXT_OBJECT_POOL_CLASSES],
        };
        plan.add::<crate::session::PicoSessionHandle>(objects.sessions)?;
        plan.add::<crate::pubsub::PublisherState>(objects.publishers)?;
        plan.add::<crate::pubsub::SubscriberState>(objects.subscribers)?;
        #[cfg(feature = "queryable")]
        plan.add::<crate::query::QueryableState>(objects.queryables)?;
        #[cfg(feature = "liveliness")]
        plan.add::<crate::liveliness::TokenState>(objects.liveliness_tokens)?;
        #[cfg(feature = "liveliness")]
        plan.add::<crate::pubsub::SubscriberState>(objects.liveliness_subscribers)?;
        plan.add::<crate::pubsub::SampleMarshal>(objects.samples)?;
        #[cfg(feature = "query")]
        plan.add::<crate::get::ReplyMarshal>(objects.replies)?;
        #[cfg(feature = "queryable")]
        plan.add::<crate::query::QueryMarshal>(objects.queries)?;
        plan.add::<crate::bytes::ByteBuf>(objects.bytes)?;
        if plan.slots.iter().all(|&slots| slots == 0) {
            return Err(Unplanned::Empty);
        }
        plan.bytes()?;
        Ok(plan)
    }

    /// `count` more slots in the pool of a `T`.
    fn add<T>(&mut self, count: usize) -> Result<(), Unplanned> {
        let class = const { class_for::<T>() };
        self.slots[class] = self.slots[class]
            .checked_add(count)
            .ok_or(Unplanned::TooLarge)?;
        Ok(())
    }

    /// The bytes every pool's slots take together.
    pub(crate) fn bytes(&self) -> Result<usize, Unplanned> {
        let mut total: usize = 0;
        for (class, &slots) in self.slots.iter().enumerate() {
            total = slots
                .checked_mul(slot_bytes(class))
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

/// One pool: where its slots start, its free slots linked through their first word, and what it
/// has done.
#[derive(Clone, Copy, Debug)]
struct Pool {
    /// The offset of its first slot from the start of the memory.
    start: usize,
    slots: usize,
    free: Option<NonNull<u8>>,
    in_use: usize,
    high_water: usize,
    refused: usize,
}

/// Every pool, laid out over one memory: each pool's slots after the one before.
pub(crate) struct Pools {
    base: NonNull<u8>,
    bytes: usize,
    origin: Origin,
    pools: [Pool; WZ_EXT_OBJECT_POOL_CLASSES],
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
            free: None,
            in_use: 0,
            high_water: 0,
            refused: 0,
        }; WZ_EXT_OBJECT_POOL_CLASSES];
        let mut at = 0;
        for (class, pool) in pools.iter_mut().enumerate() {
            let size = slot_bytes(class);
            pool.start = at;
            pool.slots = plan.slots[class];
            // Linked from the last slot to the first, so the lowest is taken first.
            for index in (0..pool.slots).rev() {
                let slot = base.as_ptr().add(at + index * size);
                slot.cast::<Option<NonNull<u8>>>().write(pool.free);
                pool.free = Some(NonNull::new_unchecked(slot));
            }
            at += pool.slots * size;
        }
        Self {
            base,
            bytes: at,
            origin,
            pools,
        }
    }

    /// A free slot of pool `class`, or `None`, counted, when it has none.
    fn take(&mut self, class: usize) -> Option<NonNull<u8>> {
        let pool = &mut self.pools[class];
        let Some(slot) = pool.free else {
            pool.refused = pool.refused.saturating_add(1);
            return None;
        };
        // SAFETY: the first word of a free slot is the link to the next free one, written when it
        // was laid out or given back.
        pool.free = unsafe { slot.as_ptr().cast::<Option<NonNull<u8>>>().read() };
        pool.in_use += 1;
        pool.high_water = pool.high_water.max(pool.in_use);
        Some(slot)
    }

    /// Give `place` back to the pool it lies in; `false` when it lies in none of them.
    fn give_back(&mut self, place: NonNull<u8>) -> bool {
        let at = (place.as_ptr() as usize).wrapping_sub(self.base.as_ptr() as usize);
        if at >= self.bytes {
            return false;
        }
        let Some((class, pool)) = self
            .pools
            .iter_mut()
            .enumerate()
            .find(|(class, pool)| at < pool.start + pool.slots * slot_bytes(*class))
        else {
            return false;
        };
        debug_assert_eq!(
            (at - pool.start) % slot_bytes(class),
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
        pool.in_use -= 1;
        true
    }

    /// How many objects the pools hold now.
    fn held(&self) -> usize {
        self.pools.iter().map(|pool| pool.in_use).sum()
    }

    /// Pool `class` as `wz_ext_object_pool_class` reports it.
    fn report(&self, class: usize) -> wz_ext_object_pool_class_t {
        let pool = &self.pools[class];
        wz_ext_object_pool_class_t {
            slot_bytes: slot_bytes(class),
            slots: pool.slots,
            in_use: pool.in_use,
            high_water: pool.high_water,
            refused: pool.refused,
        }
    }
}

impl Drop for Pools {
    fn drop(&mut self) {
        // SAFETY: the pools are gone, and with them every use of their memory.
        unsafe { self.origin.free(self.base) }
    }
}

/// The pools the program reserved, if it has.
struct Reserved(Option<Pools>);

// SAFETY: the memory of the pools is reached only through the lock this is held behind, by one
// thread at a time, and no pointer into it is handed out except to the slot's own object.
unsafe impl Send for Reserved {}

static RESERVED: Lock<Reserved> = Lock::new(Reserved(None));

/// What [`take`] found for an object.
pub(crate) enum Taken {
    /// A free slot of the object's pool.
    Pooled(NonNull<u8>),
    /// The object's pool has no free slot.
    Full,
    /// No pool is reserved: the object is the heap's.
    Unreserved,
}

/// A slot for a `T`, from the pool of its size.
pub(crate) fn take<T>() -> Taken {
    let class = const { class_for::<T>() };
    RESERVED.with(|reserved| match reserved.0.as_mut() {
        None => Taken::Unreserved,
        Some(pools) => pools.take(class).map_or(Taken::Full, Taken::Pooled),
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

/// The pools `counts` make.
///
/// # Safety
/// `counts` is null or points at a valid `wz_ext_object_pool_counts_t`.
unsafe fn planned(counts: *const wz_ext_object_pool_counts_t) -> Result<Plan, ZResult> {
    if counts.is_null() {
        return Err(Z_ERR_NULL);
    }
    let objects = resolve(&*counts, &Bounds::of(&session_limits())).map_err(Unplanned::code)?;
    Plan::of(&objects).map_err(Unplanned::code)
}

/// Lay `plan` out over the memory at `base` and hold it as the reservation, unless one is held
/// already: then the memory is not touched, and is let go as `origin` says.
///
/// # Safety
/// As [`Pools::over`].
unsafe fn install(base: NonNull<u8>, plan: &Plan, origin: Origin) -> ZResult {
    let refused = RESERVED.with(|reserved| {
        if reserved.0.is_some() {
            return true;
        }
        reserved.0 = Some(Pools::over(base, plan, origin));
        false
    });
    if refused {
        origin.free(base);
        return Z_EINVAL;
    }
    Z_OK
}

/// The bytes the pools of `counts` take, in `out_bytes` (zero on every error): what memory a
/// program hands `wz_ext_object_pool_place`. `Z_OK`; `Z_ERR_NULL` for a NULL argument;
/// `_Z_ERR_CONFIG_INVALID_VALUE` for counts that make no pool (a count left at zero whose limit
/// holds no bound, or no slot at all); `_Z_ERR_SYSTEM_OUT_OF_MEMORY` for more than the address
/// space holds.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_object_pool_bytes(
    counts: *const wz_ext_object_pool_counts_t,
    out_bytes: *mut usize,
) -> ZResult {
    guarded(|| {
        if out_bytes.is_null() {
            return Z_ERR_NULL;
        }
        *out_bytes = 0;
        match planned(counts).and_then(|plan| plan.bytes().map_err(Unplanned::code)) {
            Ok(bytes) => {
                *out_bytes = bytes;
                Z_OK
            }
            Err(code) => code,
        }
    })
}

/// Reserve the pools of `counts` from the heap, in one allocation. `Z_OK`; `Z_ERR_NULL` for a
/// NULL `counts`; `_Z_ERR_CONFIG_INVALID_VALUE` for counts that make no pool;
/// `_Z_ERR_SYSTEM_OUT_OF_MEMORY` when the heap has not the memory; `Z_EINVAL` when pools are
/// reserved already. Every refusal leaves the heap as it was.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_object_pool_reserve(
    counts: *const wz_ext_object_pool_counts_t,
) -> ZResult {
    guarded(|| {
        let plan = match planned(counts) {
            Ok(plan) => plan,
            Err(code) => return code,
        };
        let layout = match plan
            .bytes()
            .ok()
            .and_then(|bytes| Layout::from_size_align(bytes, SLOT_ALIGN).ok())
        {
            Some(layout) => layout,
            None => return Z_ERR_SYSTEM_OUT_OF_MEMORY,
        };
        // SAFETY: the layout is not of zero bytes: a plan has a slot.
        let Some(base) = NonNull::new(alloc::alloc::alloc(layout)) else {
            return Z_ERR_SYSTEM_OUT_OF_MEMORY;
        };
        // SAFETY: the allocation is this layout's, aligned to the slot, as long as the plan and
        // no one else's.
        install(base, &plan, Origin::Heap(layout))
    })
}

/// Reserve the pools of `counts` over the `len` bytes the program hands over at `base`, which
/// the library uses until `wz_ext_object_pool_release` and the program must not touch meanwhile.
/// `Z_OK`; `Z_ERR_NULL` for a NULL argument; `_Z_ERR_CONFIG_INVALID_VALUE` for counts that make
/// no pool; `Z_EINVAL` for a `base` not aligned to 16 bytes, or when pools are reserved already;
/// `_Z_ERR_SYSTEM_OUT_OF_MEMORY` for a `len` under what `wz_ext_object_pool_bytes` answers. A
/// refused call writes nothing at `base`.
#[cfg(feature = "object-pool-region")]
#[no_mangle]
pub unsafe extern "C" fn wz_ext_object_pool_place(
    base: *mut c_void,
    len: usize,
    counts: *const wz_ext_object_pool_counts_t,
) -> ZResult {
    guarded(|| {
        let Some(base) = NonNull::new(base.cast::<u8>()) else {
            return Z_ERR_NULL;
        };
        let plan = match planned(counts) {
            Ok(plan) => plan,
            Err(code) => return code,
        };
        if base.as_ptr() as usize % SLOT_ALIGN != 0 {
            return Z_EINVAL;
        }
        match plan.bytes() {
            Ok(bytes) if bytes <= len => {}
            _ => return Z_ERR_SYSTEM_OUT_OF_MEMORY,
        }
        // SAFETY: the program hands the memory over, aligned and long enough, for the pools alone.
        install(base, &plan, Origin::Program)
    })
}

/// Pool `class` (`0` to `WZ_EXT_OBJECT_POOL_CLASSES - 1`, the slot of each twice the one
/// before's), in `out`: its slot size, and while pools are reserved its slots, those in use, the
/// most in use at once and the objects it refused. `Z_OK`; `Z_ERR_NULL` for a NULL `out`;
/// `Z_EINVAL` for a `class` past the last.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_object_pool_class(
    class: usize,
    out: *mut wz_ext_object_pool_class_t,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ERR_NULL;
        }
        if class >= WZ_EXT_OBJECT_POOL_CLASSES {
            return Z_EINVAL;
        }
        *out = RESERVED.with(|reserved| match reserved.0.as_ref() {
            Some(pools) => pools.report(class),
            None => wz_ext_object_pool_class_t {
                slot_bytes: slot_bytes(class),
                ..Default::default()
            },
        });
        Z_OK
    })
}

/// Give the pools up, so that objects are the heap's again: the heap's memory is freed, a
/// program's is the program's again. `Z_OK`, also when none are reserved; `Z_EINVAL` while an
/// object is held in them, which keeps them.
#[no_mangle]
pub extern "C" fn wz_ext_object_pool_release() -> ZResult {
    guarded(|| {
        let (code, released) = RESERVED.with(|reserved| {
            let busy = reserved.0.as_ref().is_some_and(|pools| pools.held() > 0);
            if busy {
                (Z_EINVAL, None)
            } else {
                (Z_OK, reserved.0.take())
            }
        });
        // Freed after the lock, as nothing let go under it may take it again.
        drop(released);
        code
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Memory for pools in a test, aligned as a slot.
    #[repr(C, align(16))]
    struct Memory([u8; 512]);

    fn counts() -> wz_ext_object_pool_counts_t {
        wz_ext_object_pool_counts_t::default()
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
        assert_eq!(class_of(16 * 1024, 8), Some(WZ_EXT_OBJECT_POOL_CLASSES - 1));
        assert_eq!(class_of(16 * 1024 + 1, 8), None);
        assert_eq!(class_of(16, 32), None);
    }

    /// A bounded count left at zero takes its limit's bound, one stated above it is held to it,
    /// one under it is kept, and each is per session.
    #[test]
    fn an_entity_count_is_held_to_the_bound_of_its_limit_per_session() {
        let stated = wz_ext_object_pool_counts_t {
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

    /// What no limit bounds is as stated: the publishers per session, the rest for all.
    #[test]
    fn what_no_limit_bounds_is_as_stated() {
        let stated = wz_ext_object_pool_counts_t {
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
        };
        let objects = resolve(&stated, &UNBOUNDED).expect("every count is stated");
        assert_eq!(objects.publishers, 6);
        assert_eq!(objects.subscribers, 3);
        assert_eq!(
            (
                objects.samples,
                objects.replies,
                objects.queries,
                objects.bytes
            ),
            (5, 6, 7, 8)
        );
    }

    /// A bounded count left at zero whose limit holds no bound is refused; with no session no
    /// entity is asked for, so nothing is refused.
    #[test]
    fn a_count_left_at_zero_whose_limit_holds_no_bound_is_refused() {
        let stated = wz_ext_object_pool_counts_t {
            sessions: 1,
            ..counts()
        };
        assert_eq!(resolve(&stated, &UNBOUNDED), Err(Unplanned::Unbounded));
        assert_eq!(Unplanned::Unbounded.code(), Z_ERR_CONFIG_INVALID_VALUE);
        let no_session = wz_ext_object_pool_counts_t {
            bytes: 1,
            ..counts()
        };
        let objects = resolve(&no_session, &UNBOUNDED).expect("no entity is asked for");
        assert_eq!(objects.subscribers, 0);
    }

    /// Counts past the address space are refused as no memory.
    #[test]
    fn counts_past_the_address_space_are_refused() {
        let stated = wz_ext_object_pool_counts_t {
            sessions: usize::MAX,
            publishers: 2,
            ..counts()
        };
        assert_eq!(resolve(&stated, &BOUNDED), Err(Unplanned::TooLarge));
        assert_eq!(Unplanned::TooLarge.code(), Z_ERR_SYSTEM_OUT_OF_MEMORY);
        let mut plan = Plan {
            slots: [0; WZ_EXT_OBJECT_POOL_CLASSES],
        };
        plan.slots[WZ_EXT_OBJECT_POOL_CLASSES - 1] = usize::MAX;
        assert_eq!(plan.bytes(), Err(Unplanned::TooLarge));
    }

    /// Counts of nothing make no pool.
    #[test]
    fn counts_of_nothing_make_no_pool() {
        assert_eq!(Plan::of(&counts()), Err(Unplanned::Empty));
        assert_eq!(Unplanned::Empty.code(), Z_ERR_CONFIG_INVALID_VALUE);
    }

    /// Each object lands in the pool of its size, and the bytes are the slots times their size.
    #[test]
    fn each_object_lands_in_the_pool_of_its_size() {
        let objects = wz_ext_object_pool_counts_t {
            bytes: 3,
            ..counts()
        };
        let plan = Plan::of(&objects).expect("three payloads");
        let class = class_for::<crate::bytes::ByteBuf>();
        assert_eq!(plan.slots[class], 3);
        assert_eq!(plan.slots.iter().sum::<usize>(), 3);
        assert_eq!(plan.bytes(), Ok(3 * slot_bytes(class)));
    }

    /// The slots of a pool lie inside the memory, apart and aligned; a full pool refuses and
    /// counts it; a slot given back is the next one taken; a place outside is not the pools'.
    #[test]
    fn a_full_pool_refuses_and_a_slot_given_back_is_taken_again() {
        let mut memory = Memory([0; 512]);
        let mut plan = Plan {
            slots: [0; WZ_EXT_OBJECT_POOL_CLASSES],
        };
        plan.slots[0] = 2;
        plan.slots[2] = 3;
        let bytes = plan.bytes().expect("small");
        assert_eq!(bytes, 2 * 16 + 3 * 64);
        let base = NonNull::new(memory.0.as_mut_ptr()).expect("an array");
        // SAFETY: the memory is aligned, long enough and used by nothing else.
        let mut pools = unsafe { Pools::over(base, &plan, Origin::Program) };

        let first = pools.take(0).expect("a free slot");
        let second = pools.take(0).expect("a free slot");
        assert_ne!(first, second);
        assert_eq!(pools.take(0), None, "two slots and both are held");
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

        let large: alloc::vec::Vec<_> = (0..3).map(|_| pools.take(2).expect("free")).collect();
        for slot in large.iter().chain([first, second].iter()) {
            let at = slot.as_ptr() as usize - base.as_ptr() as usize;
            assert!(at < bytes, "inside the memory");
            assert_eq!(slot.as_ptr() as usize % SLOT_ALIGN, 0, "aligned");
        }
        assert_eq!(pools.held(), 5);

        assert!(pools.give_back(second));
        assert_eq!(
            pools.take(0),
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
