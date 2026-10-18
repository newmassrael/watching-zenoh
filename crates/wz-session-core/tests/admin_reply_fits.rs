// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! An admin reply fits its bound, or it is refused and counted, on the fixed
//! backing (fixed-memory step S9b, exhaustion row R7).
//!
//! The node's admin queryable is registered the way a node with no allocator does
//! it: a process-wide [`AdminReplyArena`] sized by the deploy file's
//! `admin_reply_bytes`, one reply stage and `Final` table per session. A GET is
//! dispatched through the real query path (`dispatch_messages`, the registry, the
//! session's stage), and the heap is counted over the whole dispatch:
//!
//! - a reply of EXACTLY the bound is built, staged and owed its `Final`, and the
//!   dispatch costs the heap nothing;
//! - a reply one byte over is refused, counted in the arena, answered to the
//!   querier as a typed error reply (staged like any other reply), and costs the
//!   heap nothing either; it is never cut short;
//! - the session that was refused, and a second session asked something that
//!   fits, are served afterwards: a refusal is one leg's, not the node's.
//!
//! What the staged reply costs when it is DRAINED to the wire (the owned
//! `QueryReply` and `Response` the codec's owned mirrors build) is not claimed
//! here; it is the codec mirrors' step. The window ends where the reply is held by
//! the session's stage.
//!
//! Compiles only on the fixed backing, where the capacities are hard.
#![cfg(all(
    feature = "bounded-heapless",
    feature = "query-queryable",
    feature = "codec-request",
    feature = "adminspace-core"
))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::{Arc, Mutex};

use wz_session_core::admin_reply::{AdminReplyArena, AdminReplyRefusals};
use wz_session_core::adminspace::{AdminNodeFacts, AdminSession};
use wz_session_core::locality::Locality;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::query::{QueryReply, QueryableRegistry, ReplyBody};
use wz_session_core::query_sink::{BoxedQuerySink, QueryView, ReplyOut};
use wz_session_core::reply_stage::{FinalStage, FinalStaging, ReplyStage, ReplyStaging};
use wz_session_core::request_build::RequestQueryBuilder;
use wz_session_core::text_out::TextOut;

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

/// The bytes of the root document of the node below (`{"locators":[...],
/// "metadata":null,"plugins":null,"sessions":[],"version":"v1","zid":"a1b2"}`),
/// counted off the document, with `plugins` two bytes shorter (`{}` for `null`) in a
/// build that has the plugin legs.
const ROOT_BYTES: usize = if cfg!(feature = "adminspace-plugins-handlers") {
    105
} else {
    107
};

const LOCATORS: [&str; 1] = ["udp/10.0.0.1:7447"];

/// A registry holding the node's admin queryable over an arena of `BODY` bytes,
/// and the arena, to read its counts.
fn node<const BODY: usize>() -> (
    QueryableRegistry<BoxedQuerySink>,
    Arc<Mutex<AdminReplyArena<BODY>>>,
) {
    let arena = Arc::new(Mutex::new(AdminReplyArena::<BODY>::new()));
    let shared = arena.clone();
    let mut registry = QueryableRegistry::with_sink_backing();
    registry
        .register_sink(
            "@/a1b2/peer/**",
            Locality::Any,
            false,
            BoxedQuerySink::new(move |query: &dyn QueryView, out: &mut dyn ReplyOut| {
                let sessions: [AdminSession; 0] = [];
                let mut arena = shared.lock().expect("not poisoned");
                let _ = arena.answer(
                    query,
                    out,
                    AdminNodeFacts {
                        zid_hex: "a1b2",
                        whatami: "peer",
                        version: "v1",
                        metadata_json: "null",
                        read: true,
                        stats: None,
                        locators: LOCATORS.iter().copied(),
                        sessions: sessions.iter().map(AdminSession::view),
                        multicast_peers: core::iter::empty(),
                    },
                    &[],
                    &[],
                    |config| config.push_str("{}"),
                );
            }),
        )
        .expect("register the admin queryable");
    (registry, arena)
}

fn get(rid: u64, keyexpr: &str) -> NetworkMessage {
    NetworkMessage::Request(Box::new(
        RequestQueryBuilder::new(rid, 0, Some(keyexpr))
            .build()
            .expect("build"),
    ))
}

fn no_aliases() -> hashbrown::HashMap<u64, String> {
    hashbrown::HashMap::new()
}

/// The payload of a staged Put reply.
fn put_payload(reply: &QueryReply) -> Option<&[u8]> {
    match reply {
        QueryReply::Reply {
            body: ReplyBody::Put(payload),
            ..
        } => Some(payload),
        _ => None,
    }
}

#[test]
fn an_admin_reply_of_exactly_the_bound_is_delivered_with_zero_allocations() {
    let (mut registry, arena) = node::<ROOT_BYTES>();
    let (mut replies, mut finals) = (ReplyStage::new(), FinalStage::new());
    let messages = [get(1, "@/a1b2/peer")];
    let aliases = no_aliases();
    let (_, allocations) = allocations_during(|| {
        registry.dispatch_messages(&messages, &aliases, &mut replies, &mut finals);
    });
    let staged = replies.nth(0).expect("the reply is staged");
    assert_eq!(
        (
            allocations,
            replies.staged(),
            put_payload(&staged).map(<[u8]>::len),
            finals.owed(),
            arena.lock().unwrap().refusals(),
            replies.refusals(),
        ),
        (
            0,
            1,
            Some(ROOT_BYTES),
            1,
            AdminReplyRefusals::default(),
            Default::default()
        ),
        "(heap allocations of the dispatch, replies staged, bytes of the reply, Finals owed, \
         arena refusals, stage refusals)"
    );
    let body = String::from_utf8(put_payload(&staged).expect("a Put").to_vec()).expect("text");
    assert!(
        body.starts_with("{\"locators\":[\"udp/10.0.0.1:7447\"]"),
        "{body}"
    );
    assert!(body.ends_with("\"zid\":\"a1b2\"}"), "{body}");
}

#[test]
fn one_byte_more_is_refused_counted_and_answered_with_a_typed_error_at_zero_allocations() {
    let (mut registry, arena) = node::<{ ROOT_BYTES - 1 }>();
    let (mut replies, mut finals) = (ReplyStage::new(), FinalStage::new());
    let messages = [get(1, "@/a1b2/peer")];
    let aliases = no_aliases();
    let (_, allocations) = allocations_during(|| {
        registry.dispatch_messages(&messages, &aliases, &mut replies, &mut finals);
    });
    let refusals = arena.lock().unwrap().refusals();
    // Nothing the querier is handed is the root document, cut or whole.
    let staged: Vec<QueryReply> = replies.drain_staged().collect();
    assert!(
        staged.iter().all(|reply| put_payload(reply).is_none()),
        "a refused document is not delivered in part"
    );
    assert_eq!(
        (
            allocations,
            refusals.too_large,
            refusals.key_too_long,
            finals.owed()
        ),
        (0, 1, 0, 1),
        "(heap allocations, legs refused as too large, as key too long, Finals owed): the \
         querier still gets its Final"
    );
    // With the Err reply feature the querier is TOLD, in a typed reply.
    #[cfg(feature = "query-reply-err")]
    {
        assert_eq!(staged.len(), 1);
        match &staged[0] {
            QueryReply::Err {
                encoding, payload, ..
            } => {
                assert!(encoding.is_some(), "the error says what it is encoded as");
                let text = String::from_utf8(payload.clone()).expect("text");
                assert_eq!(
                    text,
                    format!(
                        "{{\"error\":\"admin_reply_too_large\",\"needed\":{},\"capacity\":{}}}",
                        ROOT_BYTES,
                        ROOT_BYTES - 1
                    )
                );
            }
            other => panic!("a typed Err reply, got {other:?}"),
        }
    }
}

#[test]
fn a_refusal_leaves_the_session_and_the_others_served() {
    // The arena is the node's, one for every session. Room for the config document
    // and not the root one: the root GET is refused and the config GET is not.
    let (mut registry, arena) = node::<{ ROOT_BYTES - 1 }>();
    let aliases = no_aliases();
    let (mut a_replies, mut a_finals) = (ReplyStage::new(), FinalStage::new());
    let (mut b_replies, mut b_finals) = (ReplyStage::new(), FinalStage::new());

    registry.dispatch_messages(
        &[get(1, "@/a1b2/peer")],
        &aliases,
        &mut a_replies,
        &mut a_finals,
    );
    assert_eq!(arena.lock().unwrap().refusals().too_large, 1);

    // The same session asks something that fits, and the next session too.
    let messages = [get(2, "@/a1b2/peer/config")];
    let (_, allocations) = allocations_during(|| {
        registry.dispatch_messages(&messages, &aliases, &mut a_replies, &mut a_finals);
        registry.dispatch_messages(&messages, &aliases, &mut b_replies, &mut b_finals);
    });
    let config_of = |stage: &ReplyStage| -> Vec<String> {
        stage
            .iter()
            .filter_map(|reply| {
                put_payload(&reply).map(|p| String::from_utf8_lossy(p).into_owned())
            })
            .collect()
    };
    assert_eq!(
        (
            allocations,
            config_of(&a_replies),
            config_of(&b_replies),
            a_finals.owed(),
            b_finals.owed(),
            arena.lock().unwrap().refusals().too_large,
        ),
        (0, vec!["{}".to_string()], vec!["{}".to_string()], 2, 1, 1),
        "(heap allocations, config replies of session A, of session B, Finals owed to A, to B, \
         refusals so far): the refusal was the root leg's alone"
    );
}
