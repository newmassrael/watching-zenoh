// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The lifecycle open query of a node with no allocator (open-debt of
//! `docs/session-lifecycle-intent.md`, decision D6, step 6.2b-3), through the node's own admin
//! queryable and a session's own tables.
//!
//! - `GET @/<zid>/<whatami>/session/open/<peer-zid>` asks the node to hold the peer and is
//!   answered in the words the heap profile's open query uses, each refusal by its own name,
//!   with nothing allocated;
//! - a pattern is never a target: a wildcard that merely intersects the key opens nothing and
//!   gets no reply, and a key that names no zid is refused as such;
//! - a node that does not permit it refuses and opens nothing, and the capability document
//!   lists `open`, which is all this profile binds;
//! - a node that was given no opener answers none of it.
//!
//! Compiles only on the slot profile.
#![cfg(all(
    feature = "session-slot",
    feature = "adminspace-core",
    feature = "adminspace-write"
))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use wz_session_core::lifecycle_wire::{OpenOutcome, RefusedReason};
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::peer_tables::PeerTables;
use wz_session_core::query::{QueryReply, QueryableRegistry, ReplyBody};
use wz_session_core::request_build::RequestQueryBuilder;
use wz_session_mcu::admin_fixed::{
    host_admin_queryable_fixed_with_open, AdminHost, AdminQuerySink, FixedNodeIdentity,
    FixedNodeStatus, NoOpening, NodeOpening,
};
use wz_session_mcu::admin_host::ConnectControl;

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

const ZID: &str = "a1b2";

fn identity() -> FixedNodeIdentity {
    FixedNodeIdentity::new(ZID, "peer", "wz-test", &["udp/10.0.0.1:7447"]).expect("identity fits")
}

/// An opener that records the zids it was asked for and answers one outcome, as the node's
/// own would after its checks.
struct Recording {
    permitted: bool,
    outcome: Mutex<OpenOutcome>,
    /// How many times it was asked, and for whom last. Fixed storage: a recorder that grew a
    /// vector would put an allocation of the test's own inside the count.
    asked: AtomicUsize,
    last: Mutex<[u8; 16]>,
}

impl Recording {
    const fn new(permitted: bool) -> Self {
        Self {
            permitted,
            outcome: Mutex::new(OpenOutcome::Accepted),
            asked: AtomicUsize::new(0),
            last: Mutex::new([0; 16]),
        }
    }

    fn answer(&self, outcome: OpenOutcome) {
        *self.outcome.lock().expect("the lock") = outcome;
    }

    fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }

    fn last(&self) -> [u8; 16] {
        *self.last.lock().expect("the lock")
    }
}

impl NodeOpening for Recording {
    fn permitted(&self) -> bool {
        self.permitted
    }

    fn open(&self, zid: &[u8; 16]) -> OpenOutcome {
        self.asked.fetch_add(1, Ordering::SeqCst);
        *self.last.lock().expect("the lock") = *zid;
        *self.outcome.lock().expect("the lock")
    }
}

fn get(rid: u64, keyexpr: &str) -> NetworkMessage {
    NetworkMessage::Request(Box::new(
        RequestQueryBuilder::new(rid, 0, Some(keyexpr))
            .build()
            .expect("build"),
    ))
}

/// What a session's stage holds, as `(key, Put body as text)`.
fn staged(peers: &PeerTables) -> Vec<(String, String)> {
    peers
        .replies
        .iter()
        .map(|reply| match reply {
            QueryReply::Reply {
                keyexpr_literal,
                body: ReplyBody::Put(payload),
                ..
            } => (keyexpr_literal, String::from_utf8(payload).expect("text")),
            other => panic!("a reply, got {other:?}"),
        })
        .collect()
}

fn session() -> Box<PeerTables> {
    Box::new(PeerTables::new())
}

fn peer(first: u8) -> [u8; 16] {
    let mut zid = [0u8; 16];
    zid[0] = first;
    zid
}

/// Ask `key` of a node that binds `opener`, and what its session was told, with the heap
/// counted over the dispatch.
fn ask<O: NodeOpening + Sync + 'static>(
    opener: &'static O,
    key: &str,
) -> (Vec<(String, String)>, usize) {
    static STATUS: FixedNodeStatus<3> = FixedNodeStatus::new(true);
    static HOST: AdminHost<1024> = AdminHost::new();
    static CONTROL: ConnectControl = ConnectControl::new(true);
    let mut registry: QueryableRegistry<AdminQuerySink<1024, 3, O>> =
        QueryableRegistry::with_sink_backing();
    host_admin_queryable_fixed_with_open(
        &mut registry,
        identity(),
        &STATUS,
        &HOST,
        Some(&CONTROL),
        Some(&CONTROL),
        opener,
    )
    .expect("a fresh registry takes the admin queryable");
    let mut peers = session();
    let messages = [get(1, key)];
    let (_, allocations) = allocations_during(|| {
        registry.dispatch_messages(
            &messages,
            peers.subscribers.mapping_spaces(),
            &mut peers.replies,
            &mut peers.finals,
        );
    });
    assert_eq!(peers.finals.len(), 1, "a GET is terminated either way");
    (staged(&peers), allocations)
}

const OPEN_KEY: &str = "@/a1b2/peer/session/open/1f";

#[test]
fn an_open_is_answered_in_the_words_of_the_heap_profile_with_nothing_allocated() {
    static OPENER: Recording = Recording::new(true);
    let (replies, allocations) = ask(&OPENER, OPEN_KEY);
    assert_eq!(allocations, 0, "heap allocations of the GET");
    assert_eq!(
        replies,
        vec![(
            OPEN_KEY.to_string(),
            "{\"verdict\":\"opening\"}".to_string()
        )]
    );
    assert_eq!(
        (OPENER.asked(), OPENER.last()),
        (1, peer(0x1f)),
        "(times asked, the peer the key names)"
    );

    for (outcome, reason) in [
        (OpenOutcome::PeerUnknown, RefusedReason::PeerUnknown),
        (
            OpenOutcome::NoDialableLocator,
            RefusedReason::NoDialableLocator,
        ),
        (OpenOutcome::OpenerGone, RefusedReason::OpenerGone),
        (OpenOutcome::NoRoom, RefusedReason::NoRoom),
        (OpenOutcome::Unverifiable, RefusedReason::Unverifiable),
    ] {
        OPENER.answer(outcome);
        let (replies, allocations) = ask(&OPENER, OPEN_KEY);
        assert_eq!(allocations, 0);
        assert_eq!(
            replies,
            vec![(
                OPEN_KEY.to_string(),
                format!(
                    "{{\"verdict\":\"refused\",\"reason\":\"{}\"}}",
                    reason.words()
                )
            )],
            "{outcome:?}"
        );
    }
}

#[test]
fn a_pattern_is_not_a_target_and_a_key_that_is_no_zid_is_refused_as_such() {
    static OPENER: Recording = Recording::new(true);
    for pattern in [
        "@/a1b2/peer/session/open/*",
        "@/a1b2/peer/session/open/**",
        "@/a1b2/peer/session/open/$*",
        "@/a1b2/peer/session/**",
    ] {
        let (replies, _) = ask(&OPENER, pattern);
        assert!(
            replies
                .iter()
                .all(|(key, _)| !key.contains("session/open/")),
            "{pattern} reached the open verb: {replies:?}"
        );
    }
    assert_eq!(OPENER.asked(), 0, "a pattern opens nothing");

    let bad = "@/a1b2/peer/session/open/01";
    let (replies, _) = ask(&OPENER, bad);
    assert_eq!(
        replies,
        vec![(
            bad.to_string(),
            format!(
                "{{\"verdict\":\"refused\",\"reason\":\"{}\"}}",
                RefusedReason::PeerNotAZid.words()
            )
        )]
    );
    assert_eq!(OPENER.asked(), 0);
}

#[test]
fn a_node_that_does_not_permit_it_refuses_and_opens_nothing() {
    static OPENER: Recording = Recording::new(false);
    let (replies, _) = ask(&OPENER, OPEN_KEY);
    assert_eq!(
        replies,
        vec![(
            OPEN_KEY.to_string(),
            format!(
                "{{\"verdict\":\"refused\",\"reason\":\"{}\"}}",
                RefusedReason::OpenNotPermitted.words()
            )
        )]
    );
    assert_eq!(OPENER.asked(), 0);
}

#[test]
fn the_capability_document_lists_the_one_verb_this_profile_binds() {
    static OPENER: Recording = Recording::new(true);
    let key = "@/a1b2/peer/session/verbs";
    let (replies, allocations) = ask(&OPENER, key);
    assert_eq!(allocations, 0);
    assert_eq!(
        replies,
        vec![(key.to_string(), "{\"verbs\":[\"open\"]}".to_string())]
    );
    assert_eq!(OPENER.asked(), 0, "asking opens nothing");
}

/// The in-band transport held to the table every transport of the contract is held to
/// (`wz_session_mcu::contract`, decision D7): the same cases the control port answers, asked as a
/// GET on the node's own key. The tests above are this transport's own: the heap not touched, a
/// pattern not a target, the capability document.
#[cfg(feature = "test-support")]
#[test]
fn the_in_band_query_conforms_to_the_contract_every_transport_is_held_to() {
    use wz_session_mcu::contract::{self, Binding, CASES, REPEATS};

    for case in CASES {
        let key = format!("@/a1b2/peer/session/open/{}", case.peer_text);
        let opener: &'static contract::Recording =
            Box::leak(Box::new(contract::Recording::for_case(case)));
        let answers: Vec<Option<String>> = (0..REPEATS)
            .map(|_| {
                let replies = match case.binding {
                    Binding::Bound => ask(opener, &key).0,
                    Binding::Unbound => {
                        static NONE: NoOpening = NoOpening;
                        ask(&NONE, &key).0
                    }
                };
                replies
                    .into_iter()
                    .find(|(reply_key, _)| *reply_key == key)
                    .map(|(_, body)| body)
            })
            .collect();
        let seen: Vec<Option<&str>> = answers.iter().map(Option::as_deref).collect();
        contract::judge_answers(case, &seen).unwrap_or_else(|v| panic!("{v:?}: {seen:?}"));
        if matches!(case.binding, Binding::Bound) {
            contract::judge_asking(case, opener).unwrap_or_else(|v| panic!("{v:?}"));
        }
    }
}

#[test]
fn a_node_with_no_opener_answers_none_of_it() {
    static NONE: NoOpening = NoOpening;
    for key in [OPEN_KEY, "@/a1b2/peer/session/verbs"] {
        let (replies, _) = ask(&NONE, key);
        assert!(
            replies.iter().all(|(reply_key, _)| reply_key != key),
            "{key}: {replies:?}"
        );
    }
}
