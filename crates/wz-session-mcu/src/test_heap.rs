// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The allocator of this crate's unit-test binary: the system's, refusing every allocation of a
//! thread that asked it to ([`refused`]), as a heap that is full would, and counting those of a
//! thread that asked it to count them. The other tests of the crate run through it unrefused.

use core::cell::Cell;
use std::alloc::{GlobalAlloc, Layout, System};

/// The system's allocator, or a refusal on a thread that asked for one.
struct Refusing;

std::thread_local! {
    /// Whether every allocation this thread asks for is refused now.
    static REFUSING: Cell<bool> = const { Cell::new(false) };
    /// Whether the allocations this thread is served are counted now.
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    /// The allocations this thread was served while it counted them.
    static COUNTED: Cell<u64> = const { Cell::new(0) };
}

/// `run`'s answer, every allocation the calling thread asks for while it runs refused: what a
/// caller of the heap does when the heap is full, with nothing taken from it.
pub(crate) fn refused<R>(run: impl FnOnce() -> R) -> R {
    REFUSING.with(|refusing| refusing.set(true));
    let answer = run();
    REFUSING.with(|refusing| refusing.set(false));
    answer
}

/// `run`'s answer, and how many allocations the calling thread was served while it ran: what a
/// test of a path that takes nothing from the heap counts.
#[cfg(all(
    feature = "transport-multicast",
    feature = "alloc",
    feature = "codec-push"
))]
pub(crate) fn counted<R>(run: impl FnOnce() -> R) -> (R, u64) {
    COUNTED.with(|count| count.set(0));
    COUNTING.with(|counting| counting.set(true));
    let answer = run();
    COUNTING.with(|counting| counting.set(false));
    (answer, COUNTED.with(Cell::get))
}

fn refusing() -> bool {
    REFUSING.try_with(Cell::get).unwrap_or(false)
}

/// Count one allocation served, on a thread that counts them.
fn served() {
    let _ = COUNTING.try_with(|counting| {
        if counting.get() {
            let _ = COUNTED.try_with(|count| count.set(count.get().saturating_add(1)));
        }
    });
}

// SAFETY: every call is the system allocator's, with the arguments it was given, or a refusal
// (null), which hands out no memory.
unsafe impl GlobalAlloc for Refusing {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if refusing() {
            return core::ptr::null_mut();
        }
        served();
        // SAFETY: the caller's contract, passed on.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if refusing() {
            return core::ptr::null_mut();
        }
        served();
        // SAFETY: as above.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if refusing() {
            return core::ptr::null_mut();
        }
        served();
        // SAFETY: as above.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as above.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Refusing = Refusing;
