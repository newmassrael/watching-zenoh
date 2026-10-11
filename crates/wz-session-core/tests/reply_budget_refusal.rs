// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a peer's queries may make the session owe it, on the fixed backing
//! (fixed-memory step S9a, exhaustion row R4: replies are fallible).
//!
//! A queryable stages replies and the session owes the requester a `Final` after
//! them. Both are tables of declared capacity here ([`caps::MAX_PENDING_REPLIES`],
//! [`caps::MAX_PENDING_FINALS`]) and a payload has a bound
//! ([`caps::MAX_REPLY_PAYLOAD_BYTES`]); what does not fit is REFUSED, COUNTED and
//! reported to the handler, never grown for and never cut short:
//!
//! - the reply past the table, and the reply whose payload is past the bound, are
//!   an `Err` to the handler, and the refusing call costs the heap nothing;
//! - the request whose `Final` the table could not hold never reaches a queryable;
//! - one session's full tables do not move another session's.
//!
//! What a reply that IS staged costs the heap (its record owns a `String` and a
//! `Vec`) is not claimed here; it belongs to the codec's owned mirrors.
//!
//! Compiles only on the fixed backing, where the capacities are hard.
#![cfg(all(
    feature = "bounded-heapless",
    feature = "query-queryable",
    feature = "codec-request"
))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::{Arc, Mutex};

use wz_session_core::caps;
use wz_session_core::locality::Locality;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::query::QueryableRegistry;
use wz_session_core::query_sink::{QuerySink, QueryView, ReplyError, ReplyOut};
use wz_session_core::reply_stage::{FinalStage, FinalStaging, ReplyStage, ReplyStaging};
use wz_session_core::request_build::RequestQueryBuilder;

/// Counts the allocations made BY THE CURRENT THREAD.
struct CountingAllocator;

thread_local! {
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

fn allocations_during<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let before = ALLOCATIONS.with(Cell::get);
    let out = f();
    (out, ALLOCATIONS.with(Cell::get) - before)
}

/// What a handler saw each reply attempt answer, and what the refusing attempts
/// cost the heap.
#[derive(Default)]
struct Seen {
    answers: Vec<Result<(), ReplyError>>,
    refused_allocations: Vec<usize>,
    runs: usize,
}

/// A queryable that replies with each payload in `payloads`, in order, and
/// records the answer to every attempt.
struct Replier {
    payloads: Vec<Vec<u8>>,
    seen: Arc<Mutex<Seen>>,
}

impl QuerySink for Replier {
    fn handle(&mut self, _query: &dyn QueryView, out: &mut dyn ReplyOut) {
        for payload in &self.payloads {
            let (answer, allocations) = allocations_during(|| out.try_reply(payload));
            let mut seen = self.seen.lock().expect("not poisoned");
            seen.answers.push(answer);
            if answer.is_err() {
                seen.refused_allocations.push(allocations);
            }
            drop(seen);
        }
        self.seen.lock().expect("not poisoned").runs += 1;
    }
}

fn registry(payloads: Vec<Vec<u8>>) -> (QueryableRegistry<Replier>, Arc<Mutex<Seen>>) {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let mut registry: QueryableRegistry<Replier> = QueryableRegistry::with_sink_backing();
    registry
        .register_sink(
            "demo/**",
            Locality::Any,
            false,
            Replier {
                payloads,
                seen: seen.clone(),
            },
        )
        .expect("register");
    (registry, seen)
}

fn request(rid: u64) -> NetworkMessage {
    NetworkMessage::Request(Box::new(
        RequestQueryBuilder::new(rid, 0, Some("demo/a"))
            .build()
            .expect("build"),
    ))
}

fn no_aliases() -> hashbrown::HashMap<u64, String> {
    hashbrown::HashMap::new()
}

#[test]
fn the_reply_past_pending_replies_is_refused_counted_and_costs_the_heap_nothing() {
    let n = caps::MAX_PENDING_REPLIES;
    let (mut reg, seen) = registry(vec![b"x".to_vec(); n + 1]);
    let (mut replies, mut finals) = (ReplyStage::new(), FinalStage::new());
    let aliases = no_aliases();
    reg.dispatch_messages(&[request(1)], &aliases, &mut replies, &mut finals);
    let seen = seen.lock().expect("not poisoned");
    let mut want: Vec<Result<(), ReplyError>> = vec![Ok(()); n];
    want.push(Err(ReplyError::StagingFull));
    assert_eq!(
        (
            seen.answers.clone(),
            seen.refused_allocations.clone(),
            replies.staged(),
            replies.refusals().staging_full
        ),
        (want, vec![0], n, 1),
        "(answers, heap allocations of the refused call, replies held, refusals counted)"
    );
    assert_eq!(
        finals.owed(),
        1,
        "the query was still admitted, and owes its Final"
    );
}

#[test]
fn a_payload_past_reply_payload_bytes_is_refused_not_truncated() {
    let max = caps::MAX_REPLY_PAYLOAD_BYTES;
    let (mut reg, seen) = registry(vec![vec![7u8; max], vec![7u8; max + 1], vec![7u8; max * 4]]);
    let (mut replies, mut finals) = (ReplyStage::new(), FinalStage::new());
    let aliases = no_aliases();
    reg.dispatch_messages(&[request(1)], &aliases, &mut replies, &mut finals);
    let seen = seen.lock().expect("not poisoned");
    assert_eq!(
        (
            seen.answers.clone(),
            seen.refused_allocations.clone(),
            replies.staged(),
            replies.refusals().payload_too_large
        ),
        (
            vec![
                Ok(()),
                Err(ReplyError::PayloadTooLarge),
                Err(ReplyError::PayloadTooLarge)
            ],
            vec![0, 0],
            1,
            2
        ),
        "(answers, heap allocations of the refused calls, replies held, refusals counted)"
    );
    // What was staged is the whole payload that fit, not a cut of the ones that did not.
    let staged: Vec<usize> = replies
        .drain_staged()
        .map(|r| match r {
            wz_session_core::query::QueryReply::Reply {
                body: wz_session_core::query::ReplyBody::Put(p),
                ..
            } => p.len(),
            other => panic!("a Put reply, got {other:?}"),
        })
        .collect();
    assert_eq!(staged, vec![max]);
}

#[test]
fn the_request_past_pending_finals_never_reaches_a_queryable_and_is_counted() {
    let n = caps::MAX_PENDING_FINALS;
    let (mut reg, seen) = registry(Vec::new());
    let (mut replies, mut finals) = (ReplyStage::new(), FinalStage::new());
    let aliases = no_aliases();
    let msgs: Vec<NetworkMessage> = (1..=n as u64 + 1).map(request).collect();
    for m in &msgs[..n] {
        reg.dispatch_messages(std::slice::from_ref(m), &aliases, &mut replies, &mut finals);
    }
    let (_, allocations) = allocations_during(|| {
        reg.dispatch_messages(&msgs[n..], &aliases, &mut replies, &mut finals);
    });
    let runs = seen.lock().expect("not poisoned").runs;
    assert_eq!(
        (finals.owed(), finals.refusals(), runs, allocations),
        (n, 1, n, 0),
        "(finals owed, requests refused, handler runs, allocations of the refused request)"
    );
    // The Finals owed are the ones that were admitted, in order, and a drain makes room.
    let rids: Vec<u64> = finals.drain_owed().map(|(rid, _)| rid).collect();
    assert_eq!(rids, (1..=n as u64).collect::<Vec<_>>());
    reg.dispatch_messages(&msgs[n..], &aliases, &mut replies, &mut finals);
    assert_eq!(
        finals.owed(),
        1,
        "after a drain the refused rid is admitted"
    );
}

#[test]
fn one_session_with_full_tables_leaves_the_other_sessions_replies_and_finals_alone() {
    let (mut reg, seen) = registry(vec![b"x".to_vec()]);
    let aliases = no_aliases();
    let (mut flooded_replies, mut flooded_finals) = (ReplyStage::new(), FinalStage::new());
    let (mut quiet_replies, mut quiet_finals) = (ReplyStage::new(), FinalStage::new());
    for rid in 1..=(caps::MAX_PENDING_FINALS as u64 + 4) {
        reg.dispatch_messages(
            &[request(rid)],
            &aliases,
            &mut flooded_replies,
            &mut flooded_finals,
        );
    }
    let runs_after_flood = seen.lock().expect("not poisoned").runs;
    reg.dispatch_messages(
        &[request(1)],
        &aliases,
        &mut quiet_replies,
        &mut quiet_finals,
    );
    let runs_after_quiet = seen.lock().expect("not poisoned").runs;
    assert_eq!(
        (
            flooded_finals.owed(),
            flooded_finals.refusals(),
            quiet_finals.owed(),
            quiet_finals.refusals(),
            quiet_replies.staged(),
            quiet_replies.refusals(),
            runs_after_quiet - runs_after_flood
        ),
        (
            caps::MAX_PENDING_FINALS,
            4,
            1,
            0,
            1,
            Default::default(),
            1
        ),
        "(flooded finals, flooded refusals, quiet finals, quiet refusals, quiet replies, quiet reply refusals, quiet handler runs)"
    );
    // The flooded session's reply table filled too, on the replies the first
    // `MAX_PENDING_FINALS` queries staged; the quiet one is untouched by it.
    assert!(flooded_replies.staged() <= caps::MAX_PENDING_REPLIES);
}
