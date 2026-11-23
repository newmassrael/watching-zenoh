// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The worst-case memory a session's tables report holds what filling them takes.
//!
//! Every table the session keeps to a limit is held to a stated quota, filled to it, and the heap
//! the filling left behind is at most the total `session_memory::session_tables` reports for those
//! limits: the report is a bound measured against the allocator, and not only arithmetic over row
//! sizes. The keys are long enough that their text is a heap block of its own on a growable table,
//! and every callback captures nothing, as the report is told (`Captures::default()`).
//!
//! Only the bytes the calling thread allocates and frees are counted, so the other tests of this
//! binary cannot move a number. The control: the filling is seen to take some memory, which a
//! counter that missed the tables' allocations would not show.
#![cfg(feature = "alloc")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use wz_session_core::limit_binding::Quota;
use wz_session_core::limits::SessionLimits;
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::reply_acceptance::ReplyAcceptance;
use wz_session_core::session_memory::{session_tables, Captures};

/// Counts the bytes the CURRENT THREAD holds: allocated and not yet freed.
struct LiveBytes;

thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
}

fn moved(bytes: isize) {
    LIVE.with(|live| live.set(live.get() + bytes));
}

// SAFETY: every call forwards to `System` unchanged; the only addition is a thread-local counter
// move, which neither allocates nor unwinds.
unsafe impl GlobalAlloc for LiveBytes {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            moved(layout.size() as isize);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            moved(layout.size() as isize);
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        let grown = unsafe { System.realloc(ptr, layout, new_size) };
        if !grown.is_null() {
            moved(new_size as isize - layout.size() as isize);
        }
        grown
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
        moved(-(layout.size() as isize));
    }
}

#[global_allocator]
static GLOBAL: LiveBytes = LiveBytes;

/// The entries each table is held to and filled with.
const FILLED: usize = 3;

/// Every table this build keeps held to `FILLED`.
fn stated() -> SessionLimits {
    let quota = Quota::at_most(FILLED);
    let mut limits = SessionLimits::defaults();
    limits
        .select_max_subscriptions(quota)
        .expect("a host build's domain holds a small quota");
    limits
        .select_max_pending_queries(quota)
        .expect("a host build's domain holds a small quota");
    #[cfg(feature = "query-queryable")]
    limits
        .select_max_queryables(quota)
        .expect("a host build's domain holds a small quota");
    #[cfg(feature = "liveliness-token")]
    limits
        .select_max_local_tokens(quota)
        .expect("a host build's domain holds a small quota");
    #[cfg(feature = "liveliness-subscriber")]
    limits
        .select_max_liveliness_subscriptions(quota)
        .expect("a host build's domain holds a small quota");
    #[cfg(feature = "liveliness-get")]
    limits
        .select_max_pending_liveliness_gets(quota)
        .expect("a host build's domain holds a small quota");
    limits
}

#[test]
fn tables_filled_to_their_limits_hold_at_most_the_reported_total() {
    let limits = stated();
    let reported = session_tables(&limits, &Captures::default())
        .total()
        .expect("every table is held to a stated quota");
    let mut observer = ApplicationLayerObserver::with_limits(&limits);

    let before = LIVE.with(Cell::get);
    for index in 0..FILLED {
        let key = format!("memory/table/{index:04}/a-key-long-enough-to-be-a-block-of-its-own");
        observer
            .subscribe(&key, |_| {})
            .expect("under the stated quota");
        observer
            .face()
            .replies
            .register(
                u32::try_from(index).expect("a small index"),
                1,
                None,
                ReplyAcceptance::Matching(key.as_str()),
                |_| {},
                |_| {},
            )
            .expect("under the stated quota");
        #[cfg(feature = "query-queryable")]
        observer.with_app(|app_half| {
            app_half
                .queryables
                .register(&key, |_, _| {})
                .expect("under the stated quota")
        });
        #[cfg(feature = "liveliness-token")]
        observer.with_app(|app_half| {
            app_half
                .local_tokens
                .register(index as u64, &key)
                .expect("under the stated quota")
        });
        #[cfg(feature = "liveliness-subscriber")]
        observer.with_parts(|app_half, face_half| {
            app_half
                .liveliness_subscribers
                .register(
                    &mut *face_half.tokens,
                    index as u64,
                    &key,
                    false,
                    wz_session_core::declare::liveliness_sample::BoxedLivelinessSampleSink::new(
                        |_| {},
                    ),
                )
                .expect("under the stated quota")
        });
        #[cfg(feature = "liveliness-get")]
        observer
            .face()
            .liveliness_gets
            .register_get(index as u64, None, |_| {}, |_| {})
            .expect("under the stated quota");
    }
    let held = LIVE.with(Cell::get) - before;

    assert!(
        held > 0,
        "filling the tables took no memory the counter saw, so it proves nothing"
    );
    assert!(
        held.unsigned_abs() <= reported,
        "the tables hold {held} bytes, past the {reported} the report bounds them to"
    );
    // The one more is refused: the table holds no more than the report counted.
    assert!(observer.subscribe("memory/table/one-more", |_| {}).is_err());
}
