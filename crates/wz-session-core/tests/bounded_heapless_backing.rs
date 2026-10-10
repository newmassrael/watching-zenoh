// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The fixed-capacity backing of `bounded::BoundedVec` / `BoundedString`,
//! measured on the profile that selects it WHILE an allocator is linked.
//!
//! `bounded-heapless` exists so an MCU build keeps `alloc` for everything else
//! and still gets every `caps` limit as a hard bound. Two properties say that
//! the selection actually happened, and both are observable from outside the
//! crate:
//!
//! - the entry past a table's declared capacity is REFUSED with
//!   `RegisterError::TableFull`, where the growable backing accepts it; and
//! - filling a table to its capacity performs ZERO heap allocations, which is
//!   what "fixed backing" means. A counting `#[global_allocator]` measures it;
//!   the growable backing allocates on the first push and fails that count.
//!
//! The file compiles only where the capped backing is selected (`alloc` off,
//! or `bounded-heapless` on). It is host-test level: no board runs it.
#![cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use wz_session_core::caps;
use wz_session_core::locality::Locality;
use wz_session_core::registry_error::RegisterError;

/// Counts the allocations made BY THE CURRENT THREAD, so the parallel test
/// threads of this binary cannot move each other's numbers.
struct CountingAllocator;

thread_local! {
    // `const` initialisation with a destructor-free type: reading it from
    // inside `alloc` cannot itself allocate.
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call forwards to `System` unchanged; the only addition is a
// thread-local counter bump, which neither allocates nor unwinds.
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

/// Run `f` and return its result with the number of allocations it made on
/// this thread.
fn allocations_during<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let before = ALLOCATIONS.with(Cell::get);
    let out = f();
    let after = ALLOCATIONS.with(Cell::get);
    (out, after - before)
}

/// Distinct canonical keyexprs `t/<i>`, built in a stack buffer so the
/// fixture itself allocates nothing inside the measured window.
fn key(buf: &mut [u8; 16], i: usize) -> &str {
    use std::io::Write;
    let mut cursor = std::io::Cursor::new(&mut buf[..]);
    write!(cursor, "t/{i}").expect("16 bytes hold `t/` and a usize");
    let len = cursor.position() as usize;
    std::str::from_utf8(&buf[..len]).expect("ASCII")
}

struct NoopSampleSink;
impl wz_session_core::sink::SampleSink for NoopSampleSink {
    fn deliver(&mut self, _sample: &dyn wz_session_core::sink::SampleView) {}
}

struct NoopQuerySink;
impl wz_session_core::query_sink::QuerySink for NoopQuerySink {
    fn handle(
        &mut self,
        _query: &dyn wz_session_core::query_sink::QueryView,
        _out: &mut dyn wz_session_core::query_sink::ReplyOut,
    ) {
    }
}

struct NoopReplySink;
impl wz_session_core::reply_sink::ReplySink for NoopReplySink {
    fn on_reply(&mut self, _reply: &dyn wz_session_core::reply_sink::ReplyView) {}
    fn on_final(&mut self, _rid: u64) {}
}

struct NoopDeclSink;
impl wz_session_core::decl_sink::DeclSink for NoopDeclSink {
    fn on_declared(&mut self, _decl: &dyn wz_session_core::decl_sink::DeclView) {}
}

struct NoopUndeclSink;
impl wz_session_core::decl_sink::UndeclSink for NoopUndeclSink {
    fn on_undeclared(&mut self, _id: u64) {}
}

#[test]
fn subscriber_table_refuses_the_entry_past_max_subscriptions_without_allocating() {
    use wz_session_core::pubsub::SubscriberRegistry;
    let mut reg: SubscriberRegistry<NoopSampleSink> = SubscriberRegistry::with_sink_backing();
    let mut buf = [0u8; 16];
    let (filled, allocations) = allocations_during(|| {
        (0..caps::MAX_SUBSCRIPTIONS).all(|i| {
            reg.register_sink(key(&mut buf, i), Locality::Any, NoopSampleSink)
                .is_ok()
        })
    });
    let past = reg.register_sink(
        key(&mut buf, caps::MAX_SUBSCRIPTIONS),
        Locality::Any,
        NoopSampleSink,
    );
    // One verdict, so a red run reports every half of it at once.
    assert_eq!(
        (filled, allocations, past.err(), reg.len()),
        (
            true,
            0,
            Some(RegisterError::TableFull),
            caps::MAX_SUBSCRIPTIONS
        ),
        "(filled to N, allocations while filling, entry N+1, table length)"
    );
}

#[test]
fn subscriber_pattern_past_max_keyexpr_bytes_is_refused_not_truncated() {
    use wz_session_core::pubsub::SubscriberRegistry;
    let mut reg: SubscriberRegistry<NoopSampleSink> = SubscriberRegistry::with_sink_backing();
    let long = "k".repeat(caps::MAX_KEYEXPR_BYTES + 1);
    let refused = reg.register_sink(&long, Locality::Any, NoopSampleSink);
    assert_eq!(
        (refused.err(), reg.len()),
        (Some(RegisterError::KeyexprTooLong), 0),
        "(over-long pattern, table length)"
    );
}

#[test]
fn queryable_table_refuses_the_entry_past_max_queryables_without_allocating() {
    use wz_session_core::query::QueryableRegistry;
    let mut reg: QueryableRegistry<NoopQuerySink> = QueryableRegistry::with_sink_backing();
    let mut buf = [0u8; 16];
    let (filled, allocations) = allocations_during(|| {
        (0..caps::MAX_QUERYABLES).all(|i| {
            reg.register_sink(key(&mut buf, i), Locality::Any, false, NoopQuerySink)
                .is_ok()
        })
    });
    let past = reg.register_sink(
        key(&mut buf, caps::MAX_QUERYABLES),
        Locality::Any,
        false,
        NoopQuerySink,
    );
    assert_eq!(
        (filled, allocations, past.err(), reg.len()),
        (
            true,
            0,
            Some(RegisterError::TableFull),
            caps::MAX_QUERYABLES
        ),
        "(filled to N, allocations while filling, entry N+1, table length)"
    );
}

#[test]
fn pending_query_table_refuses_the_entry_past_max_pending_queries_without_allocating() {
    use wz_session_core::reply::ReplyRegistry;
    use wz_session_core::reply_acceptance::ReplyAcceptance;
    let mut reg: ReplyRegistry<NoopReplySink> = ReplyRegistry::with_sink_backing();
    let (filled, allocations) = allocations_during(|| {
        (0..caps::MAX_PENDING_QUERIES as u64).all(|rid| {
            reg.register_sink(
                rid,
                1,
                None,
                ReplyAcceptance::Matching("svc/a"),
                NoopReplySink,
            )
            .is_ok()
        })
    });
    let past = reg.register_sink(
        caps::MAX_PENDING_QUERIES as u64,
        1,
        None,
        ReplyAcceptance::Any,
        NoopReplySink,
    );
    assert_eq!(
        (filled, allocations, past.err(), reg.len()),
        (
            true,
            0,
            Some(RegisterError::TableFull),
            caps::MAX_PENDING_QUERIES
        ),
        "(filled to N, allocations while filling, entry N+1, table length)"
    );
}

#[test]
fn declaration_observer_list_refuses_the_observer_past_max_decl_observers() {
    use wz_session_core::declare::subscriber::RemoteSubscriberRegistry;
    let mut reg: RemoteSubscriberRegistry<NoopDeclSink, NoopUndeclSink> =
        RemoteSubscriberRegistry::with_sink_backing();
    let (filled, allocations) = allocations_during(|| {
        (0..caps::MAX_DECL_OBSERVERS).all(|_| reg.on_subscriber_declared_sink(NoopDeclSink).is_ok())
    });
    let past = reg.on_subscriber_declared_sink(NoopDeclSink);
    assert_eq!(
        (filled, allocations, past.err()),
        (true, 0, Some(RegisterError::TableFull)),
        "(filled to N, allocations while filling, observer N+1)"
    );
}

#[cfg(feature = "liveliness-token")]
#[test]
fn local_token_table_refuses_the_token_past_max_local_tokens_without_allocating() {
    use wz_session_core::declare::local_token::LocalTokenRegistry;
    let mut reg = LocalTokenRegistry::new();
    let mut buf = [0u8; 16];
    let (filled, allocations) = allocations_during(|| {
        (0..caps::MAX_LOCAL_TOKENS).all(|i| reg.register(i as u64, key(&mut buf, i)) == Ok(true))
    });
    let past = reg.register(
        caps::MAX_LOCAL_TOKENS as u64,
        key(&mut buf, caps::MAX_LOCAL_TOKENS),
    );
    assert_eq!(
        (filled, allocations, past, reg.len()),
        (
            true,
            0,
            Err(RegisterError::TableFull),
            caps::MAX_LOCAL_TOKENS
        ),
        "(filled to N, allocations while filling, token N+1, table length)"
    );
}
