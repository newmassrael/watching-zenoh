// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The CHANNEL substrate: `_z_rc_*` refcounting and the `_z_fifo_mt_t` /
//! `_z_ring_mt_t` multithreaded collections.
//!
//! Unlike every other module in this crate, nothing here is a `z_*` API
//! function — these are pico INTERNALS (`_z_` prefixed) that a C program never
//! calls by name. They are undefined symbols anyway, because
//! `api/handlers.h` builds the whole channel family out of `static inline`
//! code that the C compiler emits into the CALLER's object file, and that
//! inline code calls straight through to these six-plus-four out-of-line
//! entry points. Measured: they are what blocks six of the nine upstream
//! examples that do not link (`z_sub_channel`, `z_pull`, `z_get_channel`,
//! `z_queryable_channel`, `z_querier`, `z_get_liveliness`) — one mechanism
//! under the largest bundle.
//!
//! ## Who allocates what
//!
//! The C side owns the STORAGE and this crate owns the REPRESENTATION. A
//! program writes
//!
//! ```c
//! z_owned_fifo_handler_sample_t handler;
//! z_fifo_channel_sample_new(&closure, &handler, 16);
//! ```
//!
//! and the inline `z_fifo_channel_sample_new` stack-allocates a
//! `_z_fifo_mt_t` (184 B measured against the pinned headers), hands its
//! address to [`_z_fifo_mt_init`], and then COPIES the whole struct into a
//! refcounted heap cell (`_Z_REFCOUNT_DEFINE`'s `*v = *val`). So:
//!
//! - the size is fixed by pico's header and this crate must not exceed it —
//!   pinned by the `const _` block at the bottom of this module;
//! - the representation must be **relocatable by `memcpy`**, which rules out
//!   any self-pointer. A `Box` handle in slot 0 satisfies both: the pointee
//!   does not move when the handle is copied.
//!
//! Exactly ONE copy is ever live. On the success path the inline constructor
//! abandons its stack original without clearing it (only the allocation-
//! failure path clears), so the heap copy is the sole owner and the ordinary
//! `clear` path frees it once.
//!
//! ## Element ownership
//!
//! The collection stores raw `void *` elements it does not interpret: the
//! channel macro `z_malloc`s a `z_owned_sample_t` / `_reply_t` / `_query_t`,
//! `take`s the loaned value into it, and pushes the pointer. The collection
//! is responsible for releasing any element it drops or still holds at
//! `clear`, through the `z_element_free_f` the caller supplies — which is why
//! both are carried through rather than assumed.
//!
//! Element pointers are held as `usize` rather than `*mut c_void` so the
//! shared state stays `Send` without an `unsafe impl` covering the whole
//! struct: the pointer's thread-safety obligation belongs to the C side (a
//! pico channel is explicitly a producer/consumer handoff across threads —
//! the read task pushes, the application thread `recv`s), and narrowing the
//! assertion to "these are opaque bits we move" keeps that visible.

use std::collections::VecDeque;
use std::ffi::c_void;
use std::sync::atomic::{fence, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

use crate::ffi::{guard_val, guarded};
use crate::result::{
    ZResult, Z_ERR_GENERIC, Z_ERR_INVALID, Z_ERR_OVERFLOW, Z_OK, Z_RES_CHANNEL_CLOSED,
    Z_RES_CHANNEL_NODATA,
};

// ---------------------------------------------------------------------------
// _z_rc_* — the shared strong/weak counter
// ---------------------------------------------------------------------------

/// pico's lazy overflow bound, `_Z_RC_MAX_COUNT = INT32_MAX`
/// (`src/collections/refcount.c:23`). Reproduced rather than picked, because
/// the increase functions return `_Z_ERR_OVERFLOW` at exactly this threshold
/// and a C program may branch on it.
const RC_MAX_COUNT: usize = i32::MAX as usize;

/// The counter block behind an rc'd value: pico's `_z_inner_rc_t`
/// (`refcount.c:24-27`), two atomic counters, allocated by
/// [`_z_rc_init`] and freed when the last WEAK reference goes.
///
/// The weak count starting at 1 is not an off-by-one: pico takes one weak
/// reference on behalf of the whole strong set, so the block outlives the last
/// strong drop and a live weak can still observe `strong == 0`. Dropping the
/// last strong releases that book-keeping weak, which is what actually frees
/// the block when no user weak remains.
struct RcBlock {
    strong: AtomicUsize,
    weak: AtomicUsize,
}

/// Allocate a fresh counter (pico `_z_rc_init`). `strong = weak = 1`.
#[no_mangle]
pub unsafe extern "C" fn _z_rc_init(cnt: *mut *mut c_void) -> ZResult {
    guarded(|| {
        if cnt.is_null() {
            return Z_ERR_INVALID;
        }
        let block = Box::new(RcBlock {
            strong: AtomicUsize::new(1),
            weak: AtomicUsize::new(1),
        });
        *cnt = Box::into_raw(block).cast::<c_void>();
        Z_OK
    })
}

/// Read the counter block behind a `void *cnt`, or `None` if null.
///
/// # Safety
/// `cnt` must be null or a pointer [`_z_rc_init`] produced and that has not
/// yet been freed by the last [`_z_rc_decrease_weak`].
unsafe fn rc_block<'a>(cnt: *mut c_void) -> Option<&'a RcBlock> {
    if cnt.is_null() {
        return None;
    }
    Some(&*cnt.cast::<RcBlock>())
}

/// Take one more strong reference (pico `_z_rc_increase_strong`).
#[no_mangle]
pub unsafe extern "C" fn _z_rc_increase_strong(cnt: *mut c_void) -> ZResult {
    guarded(|| {
        let Some(block) = rc_block(cnt) else {
            return Z_ERR_INVALID;
        };
        if block.strong.fetch_add(1, Ordering::Relaxed) >= RC_MAX_COUNT {
            return Z_ERR_OVERFLOW;
        }
        Z_OK
    })
}

/// Take one more weak reference (pico `_z_rc_increase_weak`).
#[no_mangle]
pub unsafe extern "C" fn _z_rc_increase_weak(cnt: *mut c_void) -> ZResult {
    guarded(|| {
        let Some(block) = rc_block(cnt) else {
            return Z_ERR_INVALID;
        };
        if block.weak.fetch_add(1, Ordering::Relaxed) >= RC_MAX_COUNT {
            return Z_ERR_OVERFLOW;
        }
        Z_OK
    })
}

/// Release one strong reference (pico `_z_rc_decrease_strong`); `true` when
/// this was the LAST one, which is the caller's signal to clear the value.
///
/// Releasing the book-keeping weak here (and only here) is what pico does, and
/// it is why this may also free the block and null `*cnt`.
#[no_mangle]
pub unsafe extern "C" fn _z_rc_decrease_strong(cnt: *mut *mut c_void) -> bool {
    guard_val(false, || {
        if cnt.is_null() {
            return false;
        }
        let Some(block) = rc_block(*cnt) else {
            return false;
        };
        if block.strong.fetch_sub(1, Ordering::Release) > 1 {
            return false;
        }
        // Destroy the weak that `_z_rc_init` took on the strong set's behalf.
        _z_rc_decrease_weak(cnt);
        true
    })
}

/// Release one weak reference (pico `_z_rc_decrease_weak`); `true` when this
/// freed the counter block, in which case `*cnt` is nulled.
#[no_mangle]
pub unsafe extern "C" fn _z_rc_decrease_weak(cnt: *mut *mut c_void) -> bool {
    guard_val(false, || {
        if cnt.is_null() {
            return false;
        }
        let raw = *cnt;
        let Some(block) = rc_block(raw) else {
            return false;
        };
        if block.weak.fetch_sub(1, Ordering::Release) > 1 {
            return false;
        }
        // Pair the `Release` decrements: no thread may still be reading the
        // counters once we free them.
        fence(Ordering::Acquire);
        drop(Box::from_raw(raw.cast::<RcBlock>()));
        *cnt = std::ptr::null_mut();
        true
    })
}

/// Upgrade a weak to a strong reference (pico `_z_rc_weak_upgrade`): `Z_OK`
/// only if a strong reference still exists.
#[no_mangle]
pub unsafe extern "C" fn _z_rc_weak_upgrade(cnt: *mut c_void) -> ZResult {
    guarded(|| {
        let Some(block) = rc_block(cnt) else {
            return Z_ERR_INVALID;
        };
        let mut prev = block.strong.load(Ordering::Relaxed);
        while prev != 0 && prev < RC_MAX_COUNT {
            match block.strong.compare_exchange_weak(
                prev,
                prev + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Z_OK,
                Err(actual) => prev = actual,
            }
        }
        Z_ERR_INVALID
    })
}

/// Live strong references (pico `_z_rc_strong_count`).
#[no_mangle]
pub unsafe extern "C" fn _z_rc_strong_count(cnt: *mut c_void) -> usize {
    guard_val(0, || {
        rc_block(cnt).map_or(0, |block| block.strong.load(Ordering::Relaxed))
    })
}

/// Live USER weak references (pico `_z_rc_weak_count`) — the book-keeping weak
/// the strong set holds is subtracted while any strong reference remains.
#[no_mangle]
pub unsafe extern "C" fn _z_rc_weak_count(cnt: *mut c_void) -> usize {
    guard_val(0, || {
        let Some(block) = rc_block(cnt) else {
            return 0;
        };
        let strong = block.strong.load(Ordering::Relaxed);
        let weak = block.weak.load(Ordering::Relaxed);
        if weak == 0 {
            return 0;
        }
        if strong > 0 {
            weak - 1
        } else {
            weak
        }
    })
}

// ---------------------------------------------------------------------------
// The collections
// ---------------------------------------------------------------------------

/// pico `z_element_free_f` (`collections/element.h:31`): releases one element
/// through a pointer to the slot holding it, and nulls that slot.
pub type z_element_free_f = Option<unsafe extern "C" fn(*mut *mut c_void)>;

/// pico `z_element_move_f` (`collections/element.h:33`): moves the element at
/// `src` into `dst` and releases `src`'s own allocation.
pub type z_element_move_f = Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>;

/// Whether a full push evicts (ring) or blocks (fifo) — the ONLY behavioural
/// difference between the two collections, so they share one implementation
/// with this discriminant rather than duplicating the locking.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FullPolicy {
    /// pico `_z_fifo_mt_push`: wait on `_cv_not_full` until a consumer pulls.
    Block,
    /// pico `_z_ring_mt_push` → `_z_ring_push_force_drop`: evict the OLDEST
    /// element and free it, so the newest `capacity` are always retained.
    EvictOldest,
}

/// The elements plus the closed flag, under one mutex.
struct ChannelState {
    /// Element pointers as raw bits. Opaque to this module; see the module doc
    /// for why they are not typed pointers.
    items: VecDeque<usize>,
    closed: bool,
}

/// The Rust-side channel a `_z_fifo_mt_t` / `_z_ring_mt_t` handle points at.
///
/// The [`FullPolicy`] is deliberately NOT stored here. Upstream makes the
/// full-behaviour a property of the FUNCTION called, not of the collection —
/// `_z_fifo_mt_push` blocks and `_z_ring_mt_push` evicts, and each reads the
/// same `_z_ring_t` underneath. Storing it would invent a second source of
/// truth that the channel macro's fixed function/collection pairing can never
/// exercise.
struct Channel {
    capacity: usize,
    state: Mutex<ChannelState>,
    not_empty: Condvar,
    not_full: Condvar,
}

impl Channel {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new(ChannelState {
                items: VecDeque::new(),
                closed: false,
            }),
            not_empty: Condvar::new(),
            not_full: Condvar::new(),
        }
    }
}

/// pico `_z_fifo_mt_t` (184 B measured). Slot 0 is this crate's [`Channel`]
/// handle; the remainder is inert padding that keeps the C-side `sizeof` and
/// the `memcpy` relocation exact.
#[repr(C)]
pub struct _z_fifo_mt_t {
    handle: *mut c_void,
    _pad: [u8; 176],
}

/// pico `_z_ring_mt_t` (136 B measured). Same shape as [`_z_fifo_mt_t`].
#[repr(C)]
pub struct _z_ring_mt_t {
    handle: *mut c_void,
    _pad: [u8; 128],
}

/// Install a fresh channel into a C-allocated collection slot.
///
/// # Safety
/// `slot` must be a writable `size` bytes the C side allocated for the
/// collection.
unsafe fn install(slot: *mut c_void, capacity: usize, size: usize) -> ZResult {
    if slot.is_null() {
        return Z_ERR_INVALID;
    }
    // Zero the WHOLE struct first: the padding is never read by this crate but
    // it is `memcpy`d around by pico's inline code, and leaving it as
    // uninitialised stack bytes would make that copy read indeterminate values.
    std::ptr::write_bytes(slot.cast::<u8>(), 0, size);
    let channel = Box::new(Channel::new(capacity));
    slot.cast::<*mut c_void>()
        .write(Box::into_raw(channel).cast::<c_void>());
    Z_OK
}

/// Borrow the channel behind a collection pointer.
///
/// # Safety
/// `slot` must be null or point at a collection [`install`] initialised and
/// whose `clear` has not run.
unsafe fn channel<'a>(slot: *mut c_void) -> Option<&'a Channel> {
    if slot.is_null() {
        return None;
    }
    let handle = slot.cast::<*mut c_void>().read();
    if handle.is_null() {
        return None;
    }
    Some(&*handle.cast::<Channel>())
}

/// Push one element, applying the collection's [`FullPolicy`].
///
/// # Safety
/// `elem` must be an element the caller transfers ownership of, and `free_f`
/// must be able to release it.
unsafe fn push(
    elem: *const c_void,
    context: *mut c_void,
    free_f: z_element_free_f,
    policy: FullPolicy,
) -> ZResult {
    if elem.is_null() || context.is_null() {
        return Z_ERR_GENERIC;
    }
    let Some(channel) = channel(context) else {
        return Z_ERR_GENERIC;
    };
    let Ok(mut state) = channel.state.lock() else {
        return Z_ERR_GENERIC;
    };
    // The element the ring evicted, released AFTER the lock is dropped: the
    // free function is C code that may re-enter this library (a
    // `z_owned_sample_t`'s drop runs this crate's own `z_sample_drop`), and
    // running it under the channel mutex is how a self-deadlock gets built.
    let mut evicted: Option<*mut c_void> = None;
    loop {
        if state.closed {
            // A closed channel accepts nothing more. The element is the
            // caller's to release; report the closure rather than leaking it
            // into a collection that will never be pulled.
            drop(state);
            return Z_RES_CHANNEL_CLOSED;
        }
        if state.items.len() < channel.capacity {
            state.items.push_back(elem as usize);
            break;
        }
        match policy {
            FullPolicy::EvictOldest => {
                evicted = state.items.pop_front().map(|bits| bits as *mut c_void);
                state.items.push_back(elem as usize);
                break;
            }
            FullPolicy::Block => {
                let Ok(next) = channel.not_full.wait(state) else {
                    return Z_ERR_GENERIC;
                };
                state = next;
            }
        }
    }
    drop(state);
    channel.not_empty.notify_one();
    if let (Some(mut raw), Some(free)) = (evicted, free_f) {
        free(&mut raw);
    }
    Z_OK
}

/// Pull one element, blocking until one arrives or the channel closes.
///
/// # Safety
/// `dst` must be writable storage for one element of the collection's element
/// type, and `move_f` must be the matching mover.
unsafe fn pull(dst: *mut c_void, context: *mut c_void, move_f: z_element_move_f) -> ZResult {
    let Some(channel) = channel(context) else {
        return Z_ERR_GENERIC;
    };
    let Ok(mut state) = channel.state.lock() else {
        return Z_ERR_GENERIC;
    };
    let raw = loop {
        if let Some(bits) = state.items.pop_front() {
            break bits as *mut c_void;
        }
        if state.closed {
            return Z_RES_CHANNEL_CLOSED;
        }
        let Ok(next) = channel.not_empty.wait(state) else {
            return Z_ERR_GENERIC;
        };
        state = next;
    };
    drop(state);
    channel.not_full.notify_one();
    // Outside the lock, for the same re-entrancy reason `push` releases the
    // evicted element outside it.
    if let Some(mover) = move_f {
        mover(dst, raw);
    }
    Z_OK
}

/// Pull one element if one is immediately available.
///
/// # Safety
/// As [`pull`].
unsafe fn try_pull(dst: *mut c_void, context: *mut c_void, move_f: z_element_move_f) -> ZResult {
    let Some(channel) = channel(context) else {
        return Z_ERR_GENERIC;
    };
    let Ok(mut state) = channel.state.lock() else {
        return Z_ERR_GENERIC;
    };
    let popped = state.items.pop_front();
    let closed = state.closed;
    drop(state);
    match popped {
        Some(bits) => {
            channel.not_full.notify_one();
            if let Some(mover) = move_f {
                mover(dst, bits as *mut c_void);
            }
            Z_OK
        }
        None if closed => Z_RES_CHANNEL_CLOSED,
        None => Z_RES_CHANNEL_NODATA,
    }
}

/// Mark the channel closed and wake every waiter.
///
/// # Safety
/// `slot` must be null or an initialised collection.
unsafe fn close(slot: *mut c_void) -> ZResult {
    let Some(channel) = channel(slot) else {
        return Z_ERR_INVALID;
    };
    let Ok(mut state) = channel.state.lock() else {
        return Z_ERR_GENERIC;
    };
    state.closed = true;
    drop(state);
    channel.not_empty.notify_all();
    channel.not_full.notify_all();
    Z_OK
}

/// Release the channel and every element it still holds.
///
/// # Safety
/// `slot` must be null or an initialised collection no other thread is using.
unsafe fn clear(slot: *mut c_void, free_f: z_element_free_f) {
    if slot.is_null() {
        return;
    }
    let handle = slot.cast::<*mut c_void>().read();
    if handle.is_null() {
        return;
    }
    slot.cast::<*mut c_void>().write(std::ptr::null_mut());
    let channel = Box::from_raw(handle.cast::<Channel>());
    let drained: Vec<usize> = match channel.state.lock() {
        Ok(mut state) => state.items.drain(..).collect(),
        // A poisoned mutex means a panic unwound while an element was in
        // flight. The elements are still ours to release, so recover them
        // rather than leaking on top of the panic.
        Err(poisoned) => poisoned.into_inner().items.drain(..).collect(),
    };
    drop(channel);
    if let Some(free) = free_f {
        for bits in drained {
            let mut raw = bits as *mut c_void;
            free(&mut raw);
        }
    }
}

// --- fifo exports ----------------------------------------------------------

/// pico `_z_fifo_mt_init`.
#[no_mangle]
pub unsafe extern "C" fn _z_fifo_mt_init(fifo: *mut _z_fifo_mt_t, capacity: usize) -> ZResult {
    guarded(|| {
        install(
            fifo.cast::<c_void>(),
            capacity,
            std::mem::size_of::<_z_fifo_mt_t>(),
        )
    })
}

/// pico `_z_fifo_mt_new`: heap-allocate and initialise, `NULL` on failure.
#[no_mangle]
pub unsafe extern "C" fn _z_fifo_mt_new(capacity: usize) -> *mut _z_fifo_mt_t {
    guard_val(std::ptr::null_mut(), || {
        let raw = crate::platform::z_malloc(std::mem::size_of::<_z_fifo_mt_t>());
        if raw.is_null() {
            return std::ptr::null_mut();
        }
        let fifo = raw.cast::<_z_fifo_mt_t>();
        if _z_fifo_mt_init(fifo, capacity) != Z_OK {
            crate::platform::z_free(raw);
            return std::ptr::null_mut();
        }
        fifo
    })
}

/// pico `_z_fifo_mt_close`.
#[no_mangle]
pub unsafe extern "C" fn _z_fifo_mt_close(fifo: *mut _z_fifo_mt_t) -> ZResult {
    guarded(|| close(fifo.cast::<c_void>()))
}

/// pico `_z_fifo_mt_clear`.
#[no_mangle]
pub unsafe extern "C" fn _z_fifo_mt_clear(fifo: *mut _z_fifo_mt_t, free_f: z_element_free_f) {
    guard_val((), || clear(fifo.cast::<c_void>(), free_f));
}

/// pico `_z_fifo_mt_free`.
#[no_mangle]
pub unsafe extern "C" fn _z_fifo_mt_free(fifo: *mut _z_fifo_mt_t, free_f: z_element_free_f) {
    guard_val((), || {
        clear(fifo.cast::<c_void>(), free_f);
        crate::platform::z_free(fifo.cast::<c_void>());
    });
}

/// pico `_z_fifo_mt_push`: blocks while the collection is full.
#[no_mangle]
pub unsafe extern "C" fn _z_fifo_mt_push(
    elem: *const c_void,
    context: *mut c_void,
    free_f: z_element_free_f,
) -> ZResult {
    guarded(|| push(elem, context, free_f, FullPolicy::Block))
}

/// pico `_z_fifo_mt_pull`: blocks until an element arrives or the channel
/// closes.
#[no_mangle]
pub unsafe extern "C" fn _z_fifo_mt_pull(
    dst: *mut c_void,
    context: *mut c_void,
    move_f: z_element_move_f,
) -> ZResult {
    guarded(|| pull(dst, context, move_f))
}

/// pico `_z_fifo_mt_try_pull`.
#[no_mangle]
pub unsafe extern "C" fn _z_fifo_mt_try_pull(
    dst: *mut c_void,
    context: *mut c_void,
    move_f: z_element_move_f,
) -> ZResult {
    guarded(|| try_pull(dst, context, move_f))
}

// --- ring exports ----------------------------------------------------------

/// pico `_z_ring_mt_init`.
#[no_mangle]
pub unsafe extern "C" fn _z_ring_mt_init(ring: *mut _z_ring_mt_t, capacity: usize) -> ZResult {
    guarded(|| {
        install(
            ring.cast::<c_void>(),
            capacity,
            std::mem::size_of::<_z_ring_mt_t>(),
        )
    })
}

/// pico `_z_ring_mt_new`.
#[no_mangle]
pub unsafe extern "C" fn _z_ring_mt_new(capacity: usize) -> *mut _z_ring_mt_t {
    guard_val(std::ptr::null_mut(), || {
        let raw = crate::platform::z_malloc(std::mem::size_of::<_z_ring_mt_t>());
        if raw.is_null() {
            return std::ptr::null_mut();
        }
        let ring = raw.cast::<_z_ring_mt_t>();
        if _z_ring_mt_init(ring, capacity) != Z_OK {
            crate::platform::z_free(raw);
            return std::ptr::null_mut();
        }
        ring
    })
}

/// pico `_z_ring_mt_close`.
#[no_mangle]
pub unsafe extern "C" fn _z_ring_mt_close(ring: *mut _z_ring_mt_t) -> ZResult {
    guarded(|| close(ring.cast::<c_void>()))
}

/// pico `_z_ring_mt_clear`.
#[no_mangle]
pub unsafe extern "C" fn _z_ring_mt_clear(ring: *mut _z_ring_mt_t, free_f: z_element_free_f) {
    guard_val((), || clear(ring.cast::<c_void>(), free_f));
}

/// pico `_z_ring_mt_free`.
#[no_mangle]
pub unsafe extern "C" fn _z_ring_mt_free(ring: *mut _z_ring_mt_t, free_f: z_element_free_f) {
    guard_val((), || {
        clear(ring.cast::<c_void>(), free_f);
        crate::platform::z_free(ring.cast::<c_void>());
    });
}

/// pico `_z_ring_mt_push`: evicts the OLDEST element when full, never blocks.
#[no_mangle]
pub unsafe extern "C" fn _z_ring_mt_push(
    elem: *const c_void,
    context: *mut c_void,
    free_f: z_element_free_f,
) -> ZResult {
    guarded(|| push(elem, context, free_f, FullPolicy::EvictOldest))
}

/// pico `_z_ring_mt_pull`.
#[no_mangle]
pub unsafe extern "C" fn _z_ring_mt_pull(
    dst: *mut c_void,
    context: *mut c_void,
    move_f: z_element_move_f,
) -> ZResult {
    guarded(|| pull(dst, context, move_f))
}

/// pico `_z_ring_mt_try_pull`.
#[no_mangle]
pub unsafe extern "C" fn _z_ring_mt_try_pull(
    dst: *mut c_void,
    context: *mut c_void,
    move_f: z_element_move_f,
) -> ZResult {
    guarded(|| try_pull(dst, context, move_f))
}

// Compile-time byte-compat guard for the two C-allocated collections. MEASURED
// against the pinned pico headers with a real C compiler; a drift here is a
// stack smash in the caller, not a Rust error, so it is pinned at build time.
const _: () = {
    use core::mem::{align_of, size_of};
    assert!(size_of::<_z_fifo_mt_t>() == 184);
    assert!(align_of::<_z_fifo_mt_t>() == 8);
    assert!(size_of::<_z_ring_mt_t>() == 136);
    assert!(align_of::<_z_ring_mt_t>() == 8);
};

#[cfg(test)]
mod tests {
    use super::*;

    /// A test element: a heap `usize` the free function releases.
    unsafe extern "C" fn free_usize(slot: *mut *mut c_void) {
        if slot.is_null() || (*slot).is_null() {
            return;
        }
        drop(Box::from_raw((*slot).cast::<usize>()));
        *slot = std::ptr::null_mut();
    }

    /// The channel macro's mover: copy the element out and release the box.
    unsafe extern "C" fn move_usize(dst: *mut c_void, src: *mut c_void) {
        let boxed = Box::from_raw(src.cast::<usize>());
        dst.cast::<usize>().write(*boxed);
    }

    fn elem(value: usize) -> *const c_void {
        Box::into_raw(Box::new(value)).cast::<c_void>()
    }

    #[test]
    fn rc_starts_at_one_strong_and_frees_on_the_last_drop() {
        let mut cnt: *mut c_void = std::ptr::null_mut();
        unsafe {
            assert_eq!(_z_rc_init(&mut cnt), Z_OK);
            assert_eq!(_z_rc_strong_count(cnt), 1);
            assert_eq!(_z_rc_weak_count(cnt), 0);
            assert_eq!(_z_rc_increase_strong(cnt), Z_OK);
            assert_eq!(_z_rc_strong_count(cnt), 2);
            assert!(!_z_rc_decrease_strong(&mut cnt));
            assert_eq!(_z_rc_strong_count(cnt), 1);
            assert!(_z_rc_decrease_strong(&mut cnt));
            assert!(cnt.is_null(), "the last strong drop frees the block");
        }
    }

    #[test]
    fn a_weak_outlives_the_last_strong() {
        let mut cnt: *mut c_void = std::ptr::null_mut();
        unsafe {
            assert_eq!(_z_rc_init(&mut cnt), Z_OK);
            assert_eq!(_z_rc_increase_weak(cnt), Z_OK);
            let mut weak = cnt;
            assert!(_z_rc_decrease_strong(&mut cnt));
            // The block survives: a weak still holds it, and it now reports
            // zero strong so an upgrade must fail.
            assert_eq!(_z_rc_strong_count(weak), 0);
            assert_ne!(_z_rc_weak_upgrade(weak), Z_OK);
            assert!(_z_rc_decrease_weak(&mut weak));
            assert!(weak.is_null());
        }
    }

    #[test]
    fn a_fifo_pulls_in_order_and_reports_closure_when_drained() {
        let mut fifo = _z_fifo_mt_t {
            handle: std::ptr::null_mut(),
            _pad: [0; 176],
        };
        unsafe {
            assert_eq!(_z_fifo_mt_init(&mut fifo, 4), Z_OK);
            let ctx = (&mut fifo as *mut _z_fifo_mt_t).cast::<c_void>();
            for value in 1..=3usize {
                assert_eq!(_z_fifo_mt_push(elem(value), ctx, Some(free_usize)), Z_OK);
            }
            let mut out: usize = 0;
            for expected in 1..=3usize {
                assert_eq!(
                    _z_fifo_mt_pull(
                        (&mut out as *mut usize).cast::<c_void>(),
                        ctx,
                        Some(move_usize)
                    ),
                    Z_OK
                );
                assert_eq!(out, expected, "a fifo is first-in first-out");
            }
            assert_eq!(
                _z_fifo_mt_try_pull(
                    (&mut out as *mut usize).cast::<c_void>(),
                    ctx,
                    Some(move_usize)
                ),
                Z_RES_CHANNEL_NODATA
            );
            assert_eq!(_z_fifo_mt_close(&mut fifo), Z_OK);
            assert_eq!(
                _z_fifo_mt_pull(
                    (&mut out as *mut usize).cast::<c_void>(),
                    ctx,
                    Some(move_usize)
                ),
                Z_RES_CHANNEL_CLOSED,
                "a drained CLOSED fifo reports closure instead of blocking"
            );
            _z_fifo_mt_clear(&mut fifo, Some(free_usize));
        }
    }

    #[test]
    fn a_full_ring_keeps_the_newest_and_a_full_fifo_would_block() {
        let mut ring = _z_ring_mt_t {
            handle: std::ptr::null_mut(),
            _pad: [0; 128],
        };
        unsafe {
            assert_eq!(_z_ring_mt_init(&mut ring, 2), Z_OK);
            let ctx = (&mut ring as *mut _z_ring_mt_t).cast::<c_void>();
            for value in 1..=4usize {
                assert_eq!(_z_ring_mt_push(elem(value), ctx, Some(free_usize)), Z_OK);
            }
            let mut out: usize = 0;
            let dst = (&mut out as *mut usize).cast::<c_void>();
            assert_eq!(_z_ring_mt_pull(dst, ctx, Some(move_usize)), Z_OK);
            assert_eq!(out, 3, "the ring evicted 1 and 2, keeping the newest two");
            assert_eq!(_z_ring_mt_pull(dst, ctx, Some(move_usize)), Z_OK);
            assert_eq!(out, 4);
            assert_eq!(
                _z_ring_mt_try_pull(dst, ctx, Some(move_usize)),
                Z_RES_CHANNEL_NODATA
            );
            _z_ring_mt_clear(&mut ring, Some(free_usize));
        }
    }

    #[test]
    fn a_blocked_fifo_pull_wakes_on_a_push_from_another_thread() {
        // The property the whole channel bundle rests on: `z_*_channel_*_recv`
        // is a BLOCKING call an application thread makes while the session's
        // read task pushes. A non-blocking stand-in would pass every ordering
        // test above and still spin a real program at 100% CPU.
        let fifo = Box::into_raw(Box::new(_z_fifo_mt_t {
            handle: std::ptr::null_mut(),
            _pad: [0; 176],
        }));
        unsafe {
            assert_eq!(_z_fifo_mt_init(fifo, 4), Z_OK);
            let ctx = fifo.cast::<c_void>() as usize;
            let producer = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(50));
                assert_eq!(
                    _z_fifo_mt_push(elem(77), ctx as *mut c_void, Some(free_usize)),
                    Z_OK
                );
            });
            let mut out: usize = 0;
            let started = std::time::Instant::now();
            assert_eq!(
                _z_fifo_mt_pull(
                    (&mut out as *mut usize).cast::<c_void>(),
                    ctx as *mut c_void,
                    Some(move_usize)
                ),
                Z_OK
            );
            assert_eq!(out, 77);
            assert!(
                started.elapsed() >= std::time::Duration::from_millis(40),
                "the pull returned before the producer ran, so it did not block"
            );
            producer.join().expect("producer thread");
            _z_fifo_mt_clear(fifo, Some(free_usize));
            drop(Box::from_raw(fifo));
        }
    }

    #[test]
    fn clear_releases_every_element_still_held() {
        // The leak this catches is invisible to the ordering tests: they drain
        // what they push. A channel dropped with elements in flight (the
        // ordinary `z_drop(handler)` path) must free them.
        let mut fifo = _z_fifo_mt_t {
            handle: std::ptr::null_mut(),
            _pad: [0; 176],
        };
        static FREED: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn counting_free(slot: *mut *mut c_void) {
            FREED.fetch_add(1, Ordering::Relaxed);
            unsafe { free_usize(slot) };
        }
        unsafe {
            assert_eq!(_z_fifo_mt_init(&mut fifo, 8), Z_OK);
            let ctx = (&mut fifo as *mut _z_fifo_mt_t).cast::<c_void>();
            for value in 1..=5usize {
                assert_eq!(_z_fifo_mt_push(elem(value), ctx, Some(counting_free)), Z_OK);
            }
            _z_fifo_mt_clear(&mut fifo, Some(counting_free));
            assert_eq!(FREED.load(Ordering::Relaxed), 5);
        }
    }
}
