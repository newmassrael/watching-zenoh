// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The lib test binary's allocator, which counts the allocations each thread makes, so a test can
//! read what one call of the code under test takes of the heap, and refuses on a thread that asks
//! every allocation of one layout ([`refusing`]), as a heap with no room for it would. Each lib
//! test runs on a thread of its own and reads its own thread's count, so what the tests beside it
//! allocate never reaches it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

/// Counts the allocations made BY THE CURRENT THREAD.
struct CountingAllocator;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    /// The layout every allocation of which this thread is refused, while it refuses one.
    static REFUSED: Cell<Option<Layout>> = const { Cell::new(None) };
}

// SAFETY: every call forwards to `System` unchanged, or is a refusal (null), which hands out no
// memory; the only addition is reading and bumping thread-local cells without a destructor, which
// neither allocates nor unwinds.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        if REFUSED.try_with(Cell::get).ok().flatten() == Some(layout) {
            return core::ptr::null_mut();
        }
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static COUNTING: CountingAllocator = CountingAllocator;

/// How many allocations the current thread has made.
pub(crate) fn allocations() -> usize {
    ALLOCATIONS.with(Cell::get)
}

/// `run`'s answer, every allocation of `layout` the calling thread asks for while it runs
/// refused, and every other made: what a call does when the heap has no room for that one block.
pub(crate) fn refusing<R>(layout: Layout, run: impl FnOnce() -> R) -> R {
    REFUSED.with(|refused| refused.set(Some(layout)));
    let answer = run();
    REFUSED.with(|refused| refused.set(None));
    answer
}
