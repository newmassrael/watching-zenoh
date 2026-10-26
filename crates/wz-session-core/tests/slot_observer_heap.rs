// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The slot observer in a HEAP build: one set of application registrations serving several
//! sessions, each with its own peer tables, and answering as the one-session observer does.
//!
//! The slot observer is the fixed-memory profile's cut of the registry (what the application
//! registers, once; what each peer writes, per session), written for a node with no allocator. It
//! has no reason to be refused to a build with one: its tables are `PeerTables` over the build's
//! storage policy, which is the heap's here. A listening engine that holds several peers needs
//! exactly this cut, so what is held here is what it relies on:
//!
//! - two peers number their aliases and their requests from the same ids, and a registration made
//!   once serves each of them under its own ids;
//! - what a queryable stages for a peer's query goes to THAT peer's tables and out through THAT
//!   session's sink, with the `Final` after the replies;
//! - for one session the slot observer sends what [`ApplicationLayerObserver`] sends and
//!   delivers what it delivers, which is what lets the engine move from one to the other.
//!
//! The fixed backing's own isolation and flood tests are `slot_observer_sessions.rs`; this file
//! compiles only where that one does not.
#![cfg(all(
    not(feature = "bounded-heapless"),
    feature = "alloc",
    feature = "codec-push",
    feature = "codec-declare",
    feature = "codec-request",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "query-queryable",
    feature = "pubsub-put"
))]

use std::sync::{Arc, Mutex};

use wz_codecs_test_support::TestWire;
use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
use wz_session_core::locality::Locality;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::peer_tables::PeerTables;
use wz_session_core::push_build::build_push_aliased;
use wz_session_core::query_sink::{BoxedQuerySink, QueryView, ReplyOut};
use wz_session_core::reply_sink::BoxedReplySink;
use wz_session_core::request_build::build_request_query;
use wz_session_core::response_sink::{DeclareReplySink, LivelinessGetPrune, ResponseSink};
use wz_session_core::sink::{BoxedSink, SampleView};
use wz_session_core::slot_observer::{Requesters, SlotObserver};
use wz_session_core_test_support as fx;

type Req = Requesters<BoxedReplySink, BoxedReplySink>;

fn frame(messages: Vec<NetworkMessage>) -> DriverLoopOutcome {
    DriverLoopOutcome::FramePayload {
        priority: wz_session_core::qos::Priority::DEFAULT,
        reliable: true,
        sn: 0,
        messages,
        has_ext: false,
        extensions: Vec::new(),
    }
}

fn declare_alias(id: u64, keyexpr: &str) -> NetworkMessage {
    NetworkMessage::Declare(Box::new(fx::declare_envelope_decl_kexpr(fx::decl_kexpr(
        id, keyexpr,
    ))))
}

fn push_on(id: u64) -> NetworkMessage {
    NetworkMessage::Push(Box::new(
        build_push_aliased(id, None, b"v").expect("build the push"),
    ))
}

fn ask(rid: u64, keyexpr: &str) -> NetworkMessage {
    NetworkMessage::Request(Box::new(
        build_request_query(rid, 0, Some(keyexpr)).expect("build the request"),
    ))
}

/// What one session's send path was told, in order: each reply as its wire bytes, each Final as
/// its request id.
#[derive(Default, Clone)]
struct Sent(Arc<Mutex<Vec<String>>>);

impl Sent {
    fn log(&self) -> Vec<String> {
        self.0.lock().expect("not poisoned").clone()
    }
}

impl ResponseSink for Sent {
    fn send_response(&self, response: wz_session_core::wire::ResponseOwned) {
        self.0
            .lock()
            .expect("not poisoned")
            .push(format!("reply {:?}", response.wire()));
    }

    fn send_response_final(&self, request_id: u64, _qos: wz_session_core::sample::QosLevel) {
        self.0
            .lock()
            .expect("not poisoned")
            .push(format!("final {request_id}"));
    }
}

impl DeclareReplySink for Sent {
    #[cfg(feature = "liveliness-token")]
    fn send_declare_token_reply(&self, _token_id: u64, _keyexpr: &str, _interest_id: u64) {}

    #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
    fn send_declare_final_reply(&self, _interest_id: u64) {}

    #[cfg(feature = "declare-subscriber")]
    fn send_declare_subscriber_reply(
        &self,
        _subscriber_id: u64,
        _keyexpr: &str,
        _interest_id: u64,
    ) {
    }

    #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
    fn send_undeclare_subscriber_reply(&self, _subscriber_id: u64) {}
}

impl LivelinessGetPrune for Sent {
    #[cfg(feature = "liveliness-get")]
    fn prune_liveliness_get_interest(&self, _interest_id: u64) {}
}

/// A queryable that answers with two replies on the key it was asked, the payloads naming it.
fn two_replies() -> BoxedQuerySink {
    BoxedQuerySink::new(|query: &dyn QueryView, out: &mut dyn ReplyOut| {
        let _ = out.reply_keyed(query.keyexpr(), b"first");
        let _ = out.reply_keyed(query.keyexpr(), b"second");
    })
}

/// A slot observer with one subscriber on everything and the queryable, and what the subscriber
/// was handed.
fn slot() -> (SlotObserver, Arc<Mutex<Vec<String>>>) {
    let mut observer = SlotObserver::new();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let into = seen.clone();
    observer
        .subscribers
        .register_sink(
            "**",
            Locality::Any,
            BoxedSink::new(move |sample: &dyn SampleView| {
                into.lock()
                    .expect("not poisoned")
                    .push(sample.keyexpr().to_string());
            }),
        )
        .expect("register the subscriber");
    observer
        .queryables
        .register_sink("demo/q/**", Locality::Any, false, two_replies())
        .expect("register the queryable");
    (observer, seen)
}

fn dispatch(
    observer: &mut SlotObserver,
    peers: &mut PeerTables,
    requesters: &mut Req,
    sent: &Sent,
    messages: Vec<NetworkMessage>,
) {
    let outcome = frame(messages);
    observer.dispatch(peers, requesters, IterationEvent::Poll(&outcome), sent);
}

/// Two peers number their aliases from the same id; the one subscriber the application registered
/// hears each push under THAT peer's key. The control is a session that never declared the id,
/// which resolves nothing for it.
#[test]
fn the_same_alias_id_from_two_sessions_names_two_keyexprs() {
    let (mut observer, seen) = slot();
    let (mut a, mut b) = (PeerTables::new(), PeerTables::new());
    let (mut ra, mut rb) = (Req::new(), Req::new());
    let sent = Sent::default();

    dispatch(
        &mut observer,
        &mut a,
        &mut ra,
        &sent,
        vec![declare_alias(5, "a/side")],
    );
    dispatch(
        &mut observer,
        &mut b,
        &mut rb,
        &sent,
        vec![declare_alias(5, "b/side")],
    );
    dispatch(&mut observer, &mut a, &mut ra, &sent, vec![push_on(5)]);
    dispatch(&mut observer, &mut b, &mut rb, &sent, vec![push_on(5)]);
    assert_eq!(
        *seen.lock().expect("not poisoned"),
        vec!["a/side".to_string(), "b/side".to_string()],
        "id 5 means a/side in session A and b/side in session B"
    );

    let (mut c, mut rc) = (PeerTables::new(), Req::new());
    dispatch(&mut observer, &mut c, &mut rc, &sent, vec![push_on(5)]);
    assert_eq!(
        seen.lock().expect("not poisoned").len(),
        2,
        "no alias, no delivery"
    );
}

/// Two peers ask with the same request id. Each is answered through its own session's send path,
/// with its own two replies and its own Final after them, and neither is told the other's.
#[test]
fn two_sessions_asking_with_one_request_id_are_each_answered_on_their_own_sink() {
    let (mut observer, _seen) = slot();
    let (mut a, mut b) = (PeerTables::new(), PeerTables::new());
    let (mut ra, mut rb) = (Req::new(), Req::new());
    let (sent_a, sent_b) = (Sent::default(), Sent::default());

    dispatch(
        &mut observer,
        &mut a,
        &mut ra,
        &sent_a,
        vec![ask(7, "demo/q/a")],
    );
    dispatch(
        &mut observer,
        &mut b,
        &mut rb,
        &sent_b,
        vec![ask(7, "demo/q/b")],
    );

    for (sent, name) in [(&sent_a, "a"), (&sent_b, "b")] {
        let log = sent.log();
        assert_eq!(
            log.len(),
            3,
            "session {name}: two replies and a Final: {log:?}"
        );
        assert!(log[0].starts_with("reply") && log[1].starts_with("reply"));
        assert_eq!(
            log[2], "final 7",
            "session {name}: the Final follows the replies"
        );
    }
    assert_ne!(
        sent_a.log()[0],
        sent_b.log()[0],
        "each reply names the key its own peer asked"
    );
}

/// For one session the slot observer sends and delivers what the one-session observer does: the
/// same replies, byte for byte, the same Final after them, and the same samples to the same
/// subscriber, for the same frames.
#[test]
fn for_one_session_the_slot_observer_does_what_the_application_observer_does() {
    let frames = || {
        vec![
            vec![declare_alias(5, "demo/p/alias")],
            vec![push_on(5), ask(3, "demo/q/x")],
            vec![ask(4, "demo/q/y/z"), push_on(5)],
        ]
    };

    // The slot observer, one session.
    let (mut slot_observer, slot_seen) = slot();
    let (mut peers, mut requesters) = (PeerTables::new(), Req::new());
    let slot_sent = Sent::default();
    for messages in frames() {
        dispatch(
            &mut slot_observer,
            &mut peers,
            &mut requesters,
            &slot_sent,
            messages,
        );
    }

    // The application observer, the same registrations.
    let mut ap = ApplicationLayerObserver::new();
    let ap_seen = Arc::new(Mutex::new(Vec::new()));
    let into = ap_seen.clone();
    ap.subscribers
        .register_sink(
            "**",
            Locality::Any,
            BoxedSink::new(move |sample: &dyn SampleView| {
                into.lock()
                    .expect("not poisoned")
                    .push(sample.keyexpr().to_string());
            }),
        )
        .expect("register the subscriber");
    ap.queryables
        .register_sink("demo/q/**", Locality::Any, false, two_replies())
        .expect("register the queryable");
    let ap_sent = Sent::default();
    for messages in frames() {
        let outcome = frame(messages);
        ap.dispatch(IterationEvent::Poll(&outcome), &ap_sent);
    }

    assert_eq!(
        ap_sent.log().len(),
        6,
        "two queries, two replies and a Final each"
    );
    assert_eq!(
        slot_sent.log(),
        ap_sent.log(),
        "the same sends, in the same order, byte for byte"
    );
    assert_eq!(
        *slot_seen.lock().expect("not poisoned"),
        *ap_seen.lock().expect("not poisoned"),
        "and the same deliveries"
    );
    assert_eq!(slot_seen.lock().expect("not poisoned").len(), 2);
}
