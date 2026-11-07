// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A router node taken through the port's [`SessionEngine`], as the advanced subscriber's host
//! and the groups take it: a router node and a client of the registry that dials it, in one
//! process, and the port's methods called on both without a C door between.
//!
//! The C doors reach most of these operations through [`RouterState`]'s own methods, so a test
//! of a door says nothing of the port's wording of them (the keys it hands the forwarder, the
//! locality it maps, the id it keeps for a liveliness subscription). Each test here names the
//! methods it takes and what it reads on the other node.
//!
//! # Control
//!
//! All four tests were shown to fail in ONE build in which five methods did nothing: the queryable
//! declared nowhere, the token not declared, the liveliness subscription not made, the matching
//! listener and the face watch not registered. The token and the liveliness subscription were
//! stubbed together, so that test is shown to need the pair and not either of them alone.
//!
//! # Not taken here
//!
//! The shared-memory publication (`publish_shm_on_wire_all`) needs a link that negotiated shared
//! memory, which a router node does not offer; it is still the carry of the C door's own test.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_runtime_tokio::session::LocalDeliveryDrain;
use wz_runtime_tokio::session_glue::{TxQueueConf, WhatAmI};
use wz_session_core::declare::liveliness_sample::LivelinessSampleKind;
use wz_session_core::face::FaceEventKind;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reply_sink::{ReplyKind, ReplyView};

use super::*;
use crate::drive::{FaceDrive, NodeRole};
use crate::faces::no_shm_clients;
use crate::open_plan::{AbiChoices, OpenPlan, StatedEndpoints};

const WAIT: Duration = Duration::from_secs(15);

/// Whether `check` holds within [`WAIT`], asked every few milliseconds.
fn eventually(check: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    check()
}

/// What the zenoh-c ABI decides about an open, as a C program that opens a session gets it.
fn abi_choices() -> AbiChoices {
    AbiChoices {
        tx_queue: TxQueueConf::default(),
        start_read_task: true,
        local_delivery: LocalDeliveryDrain::Caller,
        liveliness_to_self: true,
        initial_interest: true,
        face_drive: FaceDrive::PerFace,
        shm_clients: no_shm_clients(),
        offer_shm: false,
        groups_report_shm: false,
    }
}

/// The plan of a session of `mode`, with multicast scouting off.
fn plan(whatami: WhatAmI, mode: &str, connect: Vec<String>, listen: Vec<String>) -> OpenPlan {
    let document =
        format!(r#"{{ mode: "{mode}", scouting: {{ multicast: {{ enabled: false }} }} }}"#);
    OpenPlan::resolve(
        whatami,
        StatedEndpoints { connect, listen },
        Some(&document),
    )
    .expect("a document a session opens on")
}

/// A router node on loopback, listening on a port it chooses.
fn open_node() -> Arc<RouterState> {
    let plan = plan(
        WhatAmI::Router,
        "router",
        Vec::new(),
        vec![format!(
            "tcp/127.0.0.1:{}",
            wz_runtime_tokio_test_support::free_port()
        )],
    );
    let arguments = plan.into_arguments(abi_choices());
    Arc::new(
        arguments
            .run_node(NodeRole::Router)
            .expect("the node opens"),
    )
}

/// A session of the registry, a client that dials `connect`: the other end of the link, as a C
/// program that opens a session opens it. Its engine is the port of the registry of faces.
struct Client(crate::drive::SessionState);

impl Client {
    fn open(connect: Vec<String>) -> Self {
        let plan = plan(WhatAmI::Client, "client", connect, Vec::new());
        Self(
            plan.into_arguments(abi_choices())
                .run()
                .expect("the client opens"),
        )
    }

    fn as_engine(&self) -> Arc<dyn SessionEngine> {
        self.0.shared.as_engine()
    }

    fn close(&self) {
        self.0.close();
    }
}

/// A router node and a client that dialled it, the link up on both sides.
fn pair() -> (Arc<RouterState>, Client) {
    let router = open_node();
    let locator = router
        .listen_locators()
        .first()
        .expect("the router listens")
        .clone();
    let peer = Client::open(vec![locator]);
    assert!(
        eventually(|| !router.as_engine().face_snapshots().is_empty()
            && !peer.as_engine().face_snapshots().is_empty()),
        "the client's link did not come up: the node listens on {:?} and holds {} face(s), the \
         client holds {}",
        router.listen_locators(),
        router.as_engine().face_snapshots().len(),
        peer.as_engine().face_snapshots().len()
    );
    (router, peer)
}

/// The port's queryable answers a query a face asks, and a get through the port finds both the
/// queryable of another node and the node's own.
#[test]
fn a_queryable_declared_through_the_port_answers_a_get_through_the_port() {
    let (router, peer) = pair();
    let (engine, other) = (router.as_engine(), peer.as_engine());

    let asked = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&asked);
    let id = engine
        .declare_queryable_on_wire(
            "wz/port/q/**".to_owned(),
            WireKey::literal(),
            false,
            Locality::Any,
            None,
            Arc::new(move |_holder| {
                let counted = Arc::clone(&counted);
                Box::new(move |query: &dyn QueryView, out: &mut dyn ReplyOut| {
                    counted.fetch_add(1, Ordering::SeqCst);
                    out.reply_keyed(query.keyexpr(), b"from the router")
                        .expect("a reply on the query's own key");
                })
            }),
        )
        .expect("a node has queryables");

    // The peer asks, over the link: the reply is the router's.
    let replies = Arc::new(Mutex::new(Vec::<(String, Vec<u8>)>::new()));
    let ask = |engine: &Arc<dyn SessionEngine>, key: &str| {
        let replies = Arc::clone(&replies);
        engine
            .get_on_wire(
                key,
                &WireKey::literal(),
                &QueryOptions::default(),
                None,
                &mut || {
                    let replies = Arc::clone(&replies);
                    Box::new(move |reply: &dyn ReplyView| {
                        if reply.kind() == ReplyKind::Put {
                            replies
                                .lock()
                                .unwrap()
                                .push((reply.keyexpr().to_owned(), reply.payload().to_vec()));
                        }
                    })
                },
            )
            .expect("a node asks with one leg")
    };
    // The registry's port asks on more than one leg (its own queryables and the face's); how many
    // is its own say, and the node's is one.
    assert!(ask(&other, "wz/port/q/a") >= 1);
    assert!(
        eventually(|| !replies.lock().unwrap().is_empty()),
        "the peer's get through the port had no reply"
    );
    assert_eq!(
        replies.lock().unwrap()[0],
        ("wz/port/q/a".to_owned(), b"from the router".to_vec())
    );

    // The router asks of itself: the node's own queryable is one of those a get reaches.
    replies.lock().unwrap().clear();
    assert_eq!(ask(&engine, "wz/port/q/b"), 1);
    assert!(
        eventually(|| !replies.lock().unwrap().is_empty()),
        "the router's get through the port did not reach its own queryable"
    );
    assert!(asked.load(Ordering::SeqCst) >= 2);

    // Undeclared, it is asked no more.
    engine.undeclare_queryable(id);
    let before = asked.load(Ordering::SeqCst);
    replies.lock().unwrap().clear();
    assert!(ask(&other, "wz/port/q/c") >= 1);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        asked.load(Ordering::SeqCst),
        before,
        "an undeclared queryable was asked"
    );
    assert!(replies.lock().unwrap().is_empty());
}

/// A token declared through the port is told to a liveliness subscription made through the port
/// on the other node and on the node itself, and its retraction is told as a delete.
#[test]
fn a_token_and_a_liveliness_subscription_through_the_port_tell_each_other() {
    let (router, peer) = pair();
    let (engine, other) = (router.as_engine(), peer.as_engine());

    type Seen = Arc<Mutex<Vec<(LivelinessSampleKind, String)>>>;
    let watch = |engine: &Arc<dyn SessionEngine>, history: bool| -> (Seen, SubId) {
        let seen: Seen = Arc::default();
        let sink = Arc::clone(&seen);
        let id = engine
            .declare_liveliness_subscriber_on_wire(
                "wz/port/live/**".to_owned(),
                WireKey::literal(),
                history,
                Arc::new(move || {
                    let sink = Arc::clone(&sink);
                    Box::new(move |sample| {
                        sink.lock()
                            .unwrap()
                            .push((sample.kind, sample.keyexpr.to_owned()));
                    })
                }),
            )
            .expect("a node has liveliness subscriptions");
        (seen, id)
    };
    // With its history: the client's interest may reach the node after the token is declared, and
    // a subscription that asked for no history is then told of nothing, which is the registry's
    // say and not the node's. What the node answers a history interest with is the node's.
    let (on_peer, peer_sub) = watch(&other, true);
    let (on_router, router_sub) = watch(&engine, false);

    let token = engine
        .declare_liveliness_token_on_wire(
            "wz/port/live/router".to_owned(),
            WireKey::literal(),
            None,
        )
        .expect("a node has tokens");
    let put = (LivelinessSampleKind::Put, "wz/port/live/router".to_owned());
    assert!(
        eventually(|| on_peer.lock().unwrap().contains(&put)),
        "the peer's subscription was not told of the token"
    );
    assert!(
        eventually(|| on_router.lock().unwrap().contains(&put)),
        "the node's own subscription was not told of its own token"
    );

    engine.undeclare_liveliness_token(token);
    let delete = (
        LivelinessSampleKind::Delete,
        "wz/port/live/router".to_owned(),
    );
    assert!(
        eventually(|| on_peer.lock().unwrap().contains(&delete)),
        "the peer's subscription was not told the token went"
    );
    assert!(
        eventually(|| on_router.lock().unwrap().contains(&delete)),
        "the node's own subscription was not told its token went"
    );

    // A subscription made with its history is told of the token that is already alive, and one
    // that was undeclared is told of nothing more.
    let alive = engine
        .declare_liveliness_token_on_wire("wz/port/live/again".to_owned(), WireKey::literal(), None)
        .expect("a node has tokens");
    let (with_history, history_sub) = watch(&other, true);
    let again = (LivelinessSampleKind::Put, "wz/port/live/again".to_owned());
    assert!(
        eventually(|| with_history.lock().unwrap().contains(&again)),
        "a subscription with history was not told of the token that was alive"
    );
    other.undeclare_subscriber(peer_sub);
    let told = on_peer.lock().unwrap().len();
    engine.undeclare_liveliness_token(alive);
    assert!(
        eventually(|| with_history.lock().unwrap().contains(&(
            LivelinessSampleKind::Delete,
            "wz/port/live/again".to_owned()
        ))),
        "the subscription still made was not told the token went"
    );
    assert_eq!(
        on_peer.lock().unwrap().len(),
        told,
        "an undeclared liveliness subscription was told"
    );
    other.undeclare_subscriber(history_sub);
    engine.undeclare_subscriber(router_sub);
}

/// The matching listener of the port reads a subscriber of the other node: false with none, true
/// once one is declared there, false again once it is gone; and the status asked at a moment
/// says the same.
#[test]
fn a_matching_listener_through_the_port_follows_a_subscriber_of_the_other_node() {
    let (router, peer) = pair();
    let (engine, other) = (router.as_engine(), peer.as_engine());

    let told: Arc<Mutex<Vec<bool>>> = Arc::default();
    let sink = Arc::clone(&told);
    let listener = engine.declare_matching_listener(
        FilterPlane::Subscribers,
        "wz/port/match/a".to_owned(),
        Arc::new(move |matching| sink.lock().unwrap().push(matching)),
        false,
    );
    assert_eq!(
        engine.matching_status(
            FilterPlane::Subscribers,
            "wz/port/match/a",
            Locality::Remote
        ),
        Some(false)
    );

    let subscriber = other.declare_subscriber_on_wire(
        "wz/port/match/**".to_owned(),
        WireKey::literal(),
        Locality::Any,
        None,
        Arc::new(|| Box::new(|_| {})),
    );
    assert!(
        eventually(|| told.lock().unwrap().last() == Some(&true)),
        "the listener was not told a subscriber matched"
    );
    assert_eq!(
        engine.matching_status(
            FilterPlane::Subscribers,
            "wz/port/match/a",
            Locality::Remote
        ),
        Some(true)
    );
    // The same listener in a locality that excludes the other node's subscriber reads false.
    assert_eq!(
        engine.matching_status(
            FilterPlane::Subscribers,
            "wz/port/match/a",
            Locality::SessionLocal
        ),
        Some(false)
    );

    other.undeclare_subscriber(subscriber);
    assert!(
        eventually(|| told.lock().unwrap().last() == Some(&false)),
        "the listener was not told the subscriber went"
    );
    assert_eq!(
        engine.matching_status(
            FilterPlane::Subscribers,
            "wz/port/match/a",
            Locality::Remote
        ),
        Some(false)
    );

    // A listener that is undeclared is told of nothing more.
    engine.undeclare_matching_listener(listener);
    let count = told.lock().unwrap().len();
    let again = other.declare_subscriber_on_wire(
        "wz/port/match/**".to_owned(),
        WireKey::literal(),
        Locality::Any,
        None,
        Arc::new(|| Box::new(|_| {})),
    );
    assert!(eventually(|| {
        engine.matching_status(
            FilterPlane::Subscribers,
            "wz/port/match/a",
            Locality::Remote,
        ) == Some(true)
    }));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        told.lock().unwrap().len(),
        count,
        "an undeclared matching listener was told"
    );
    other.undeclare_subscriber(again);
}

/// The face watch of the port is told of a link as it comes up and as it goes down, with the
/// peer's identity, and the snapshots list the face while it is up. A watch that was removed is
/// told of nothing, and says it was gone the second time it is removed.
#[test]
fn a_face_watch_through_the_port_is_told_of_a_link_coming_and_going() {
    let router = open_node();
    let engine = router.as_engine();
    assert!(engine.face_snapshots().is_empty());
    assert!(!engine.has_router_peer());

    /// What a watch was told of a face: the kind, the peer's zid and its role in wire form.
    type Told = Vec<(FaceEventKind, [u8; 16], u8)>;
    let events: Arc<Mutex<Told>> = Arc::default();
    let sink = Arc::clone(&events);
    let watch = engine.watch_faces(Arc::new(move |kind, face| {
        sink.lock().unwrap().push((kind, face.zid, face.whatami));
    }));

    let locator = router.listen_locators()[0].clone();
    let peer = Client::open(vec![locator]);
    let peer_zid = peer.as_engine().zid();
    assert!(
        eventually(|| events
            .lock()
            .unwrap()
            .iter()
            .any(|(kind, zid, _)| *kind == FaceEventKind::Up && *zid == peer_zid)),
        "the watch was not told the peer's link came up"
    );
    // A client is role 2 in its 2-bit wire form, a router role 0.
    assert!(events
        .lock()
        .unwrap()
        .iter()
        .any(|(_, zid, whatami)| *zid == peer_zid && *whatami == 2));
    assert!(engine
        .face_snapshots()
        .iter()
        .any(|face| face.zid == peer_zid));
    assert_eq!(
        engine.peer_identities(),
        vec![(peer_zid.to_vec(), 2)],
        "the identities of the faces are the client's"
    );
    // The client has a router at the other end of its link, the node has a client.
    assert!(peer.as_engine().has_router_peer());
    assert!(!engine.has_router_peer());

    peer.close();
    assert!(
        eventually(|| events
            .lock()
            .unwrap()
            .iter()
            .any(|(kind, zid, _)| *kind == FaceEventKind::Down && *zid == peer_zid)),
        "the watch was not told the peer's link went down"
    );
    assert!(eventually(|| engine.face_snapshots().is_empty()));

    assert!(engine.unwatch_faces(watch));
    assert!(!engine.unwatch_faces(watch), "a watch that is gone says so");
    let told = events.lock().unwrap().len();
    let again = Client::open(vec![router.listen_locators()[0].clone()]);
    assert!(eventually(|| !engine.face_snapshots().is_empty()));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        events.lock().unwrap().len(),
        told,
        "a watch that was removed was told"
    );
    again.close();
}
