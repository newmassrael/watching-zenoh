// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The lock-order checker of a debug build (`wz_runtime_tokio::sync`) keeps what it learns on the
//! system allocator, so a thread that takes an order it has not taken before costs its own
//! allocation count nothing (open-debt 953).
//!
//! The allocation suites of this crate install a counting `#[global_allocator]` and read the
//! count of the thread that sends. When the checker kept its per-thread sets on the global
//! allocator, an order new to the measuring thread inside the window (a lock path the warm-up
//! did not take) grew those sets there, and the fragmented-send suite read one allocation more
//! in one window than in the other on every hosted run of its 90-feature leg, from the commit
//! that added the checker on. With the checker turned off (`WZ_LOCK_ORDER=off`) the same suite
//! passed.
//!
//! Each test first makes the order known to the PROCESS on a helper thread, because the stack the
//! checker captures for an order new to the process is the one thing it still allocates on the
//! global allocator, and first takes an unrelated order of the same shape on the measuring
//! thread, so the window holds the checker's per-thread bookkeeping and nothing that happens once
//! per thread. The count is PER THREAD, as in the other allocation suites; the control at the
//! end shows the window sees what its own thread allocates. Host-test level.
#![cfg(debug_assertions)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use wz_runtime_tokio::sync::PlainMutex;

/// Counts the allocations made BY THE CURRENT THREAD.
struct CountingAllocator;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call forwards to `System` unchanged; the only addition is a
// bump of a thread-local cell without a destructor, which neither allocates
// nor unwinds.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn allocations() -> usize {
    ALLOCATIONS.with(Cell::get)
}

/// Take `inner` while holding `outer`: one order, `outer` before `inner`.
fn nest(outer: &PlainMutex<u8>, inner: &PlainMutex<u8>) {
    outer.with(|_| inner.with(|_| ()));
}

/// Two locks of one class: one construction site, so the checker orders them by instance.
fn one_class_pair() -> (PlainMutex<u8>, PlainMutex<u8>) {
    let mut made = (0..2).map(|_| PlainMutex::new(0u8));
    (made.next().expect("first"), made.next().expect("second"))
}

/// Two locks of two classes, an order the measuring thread has not taken, cost it nothing.
#[test]
fn an_order_new_to_the_thread_costs_the_thread_no_allocation() {
    let (a, b) = (PlainMutex::new(0u8), PlainMutex::new(0u8));
    let (c, d) = (PlainMutex::new(0u8), PlainMutex::new(0u8));
    std::thread::scope(|scope| {
        scope.spawn(|| nest(&a, &b)).join().expect("the helper");
    });
    nest(&c, &d);

    let before = allocations();
    nest(&a, &b);
    let spent = allocations() - before;
    assert_eq!(
        spent, 0,
        "the checker's record of an order new to this thread was counted on it"
    );
}

/// Two locks of one class, a nesting the measuring thread has not made, cost it nothing.
#[test]
fn a_nesting_of_one_class_new_to_the_thread_costs_the_thread_no_allocation() {
    let (a, b) = one_class_pair();
    let (c, d) = one_class_pair();
    std::thread::scope(|scope| {
        scope.spawn(|| nest(&a, &b)).join().expect("the helper");
    });
    nest(&c, &d);

    let before = allocations();
    nest(&a, &b);
    let spent = allocations() - before;
    assert_eq!(
        spent, 0,
        "the checker's record of a nesting new to this thread was counted on it"
    );
}

/// THE INSTRUMENT'S CONTROL: the window sees what its own thread allocates, so the two zeros
/// above are not a counter that reads zero for everything.
#[test]
fn the_window_counts_what_its_own_thread_allocates() {
    let before = allocations();
    let boxed: Vec<Box<u64>> = (0..8u64).map(Box::new).collect();
    let spent = allocations() - before;
    assert!(
        spent >= boxed.len(),
        "eight boxes were allocated on this thread and the window saw {spent}"
    );
}
