// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The allocator of this crate's unit-test binary: the system's, refusing every allocation of a
//! thread that asked it to ([`refused`]), as a heap that is full would. The other tests of the
//! crate run through it unrefused.
//!
//! A test asks only for the call it weighs: an assertion that fails inside [`refused`] cannot
//! allocate its message, so each assertion is made after it.

use core::cell::Cell;
use std::alloc::{GlobalAlloc, Layout, System};

/// The system's allocator, or a refusal on a thread that asked for one.
struct Refusing;

std::thread_local! {
    /// Whether every allocation this thread asks for is refused now.
    static REFUSING: Cell<bool> = const { Cell::new(false) };
}

/// `run`'s answer, every allocation the calling thread asks for while it runs refused: what a
/// caller of the heap meets when the heap is full, with nothing taken from it.
pub(crate) fn refused<R>(run: impl FnOnce() -> R) -> R {
    REFUSING.with(|refusing| refusing.set(true));
    let answer = run();
    REFUSING.with(|refusing| refusing.set(false));
    answer
}

fn refusing() -> bool {
    REFUSING.try_with(Cell::get).unwrap_or(false)
}

// SAFETY: every call is the system allocator's, with the arguments it was given, or a refusal
// (null), which hands out no memory.
unsafe impl GlobalAlloc for Refusing {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if refusing() {
            return core::ptr::null_mut();
        }
        // SAFETY: the caller's contract, passed on.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if refusing() {
            return core::ptr::null_mut();
        }
        // SAFETY: as above.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if refusing() {
            return core::ptr::null_mut();
        }
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
