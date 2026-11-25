// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The allocator of this crate's unit tests: the system's, counting the allocations of a thread
//! that asks ([`allocations`]) and refusing every allocation of a thread that asks
//! ([`refused`]), as a full heap would. One for the whole test binary, which has one allocator;
//! every other test runs through it uncounted and unrefused.

extern crate std;

use core::cell::Cell;
use std::alloc::{GlobalAlloc, Layout, System};

std::thread_local! {
    /// The allocations this thread made since it began counting, while it counts.
    static COUNTING: Cell<Option<usize>> = const { Cell::new(None) };
    /// Whether every allocation this thread asks for is refused.
    static REFUSING: Cell<bool> = const { Cell::new(false) };
}

/// Every allocation of the calling thread while `run` runs, counted: read by the tests of a
/// session's doors, through the connectivity tests on the tokio engine and by the kept query's
/// tests on the cooperative one with threads, each built with the module it reads.
#[cfg(any(
    all(feature = "engine-tokio", feature = "connectivity"),
    all(
        feature = "os-host",
        feature = "queryable",
        feature = "peer",
        feature = "query",
        feature = "multi-thread"
    )
))]
pub(crate) fn allocations(run: impl FnOnce()) -> usize {
    COUNTING.with(|count| count.set(Some(0)));
    run();
    COUNTING.with(Cell::take).unwrap_or(0)
}

/// `run`'s answer, every allocation the calling thread asks for while it runs refused: what a
/// door does when the heap is full, with nothing taken from it.
pub(crate) fn refused<R>(run: impl FnOnce() -> R) -> R {
    REFUSING.with(|refusing| refusing.set(true));
    let answer = run();
    REFUSING.with(|refusing| refusing.set(false));
    answer
}

/// `run`'s answer, what the calling thread allocates while it runs neither refused nor counted:
/// the test binary's own reading of how it is run, which is no allocation of a door under test.
#[cfg(wz_process_pools)]
pub(crate) fn uncounted<R>(run: impl FnOnce() -> R) -> R {
    let was_refusing = REFUSING.with(|refusing| refusing.replace(false));
    let was_counting = COUNTING.with(Cell::take);
    let answer = run();
    COUNTING.with(|count| count.set(was_counting));
    REFUSING.with(|refusing| refusing.set(was_refusing));
    answer
}

/// The test binary's allocator ([`allocations`], [`refused`], [`uncounted`]).
struct TestHeap;

// SAFETY: every call is the system allocator's, with the arguments it was given, or a refusal
// (null), which hands out no memory; the count and the refusal are a thread's own cells.
unsafe impl GlobalAlloc for TestHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = COUNTING.try_with(|count| {
            if let Some(seen) = count.get() {
                count.set(Some(seen.saturating_add(1)));
            }
        });
        if REFUSING.try_with(Cell::get).unwrap_or(false) {
            return core::ptr::null_mut();
        }
        // SAFETY: the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, at: *mut u8, layout: Layout) {
        // SAFETY: the caller's.
        unsafe { System.dealloc(at, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: TestHeap = TestHeap;
