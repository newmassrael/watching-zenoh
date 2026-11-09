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
//! # Shared memory
//!
//! A node offers shared memory in its handshake as a registry session does, when its ABI offers
//! it and its document enables it (`AbiChoices::offer_shm`, `transport/shared_memory/enabled`):
//! the tests above open with neither, which is why their links negotiate none. The test of the
//! port's shared-memory publication (`publish_shm_on_wire_all`) opens both ends with both, beside
//! a client that offers none, in a build with `session-extshm`.

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
    abi_choices_offering(false)
}

/// [`abi_choices`], with the handshake offering shared memory when `offer_shm` says so.
fn abi_choices_offering(offer_shm: bool) -> AbiChoices {
    AbiChoices {
        tx_queue: TxQueueConf::default(),
        start_read_task: true,
        local_delivery: LocalDeliveryDrain::Caller,
        liveliness_to_self: true,
        initial_interest: true,
        face_drive: FaceDrive::PerFace,
        shm_clients: no_shm_clients(),
        offer_shm,
        groups_report_shm: false,
    }
}

/// The plan of a session of `mode`, with multicast scouting off.
fn plan(whatami: WhatAmI, mode: &str, connect: Vec<String>, listen: Vec<String>) -> OpenPlan {
    plan_stating(whatami, mode, connect, listen, "")
}

/// [`plan`], its document stating `more` (keys written as `, key: value`) after the mode and the
/// scouting.
fn plan_stating(
    whatami: WhatAmI,
    mode: &str,
    connect: Vec<String>,
    listen: Vec<String>,
    more: &str,
) -> OpenPlan {
    let document =
        format!(r#"{{ mode: "{mode}", scouting: {{ multicast: {{ enabled: false }} }}{more} }}"#);
    OpenPlan::resolve(
        whatami,
        StatedEndpoints { connect, listen },
        Some(&document),
    )
    .expect("a document a session opens on")
}

/// A router node on loopback, listening on a port it chooses.
fn open_node() -> Arc<RouterState> {
    open_node_as(NodeRole::Router, Vec::new())
}

/// A node of `role` on loopback, listening on a port it chooses and dialling `connect`.
fn open_node_as(role: NodeRole, connect: Vec<String>) -> Arc<RouterState> {
    let (whatami, mode) = match role {
        NodeRole::Router => (WhatAmI::Router, "router"),
        NodeRole::Peer => (WhatAmI::Peer, "peer"),
        NodeRole::Client => (WhatAmI::Client, "client"),
    };
    let plan = plan(
        whatami,
        mode,
        connect,
        vec![format!(
            "tcp/127.0.0.1:{}",
            wz_runtime_tokio_test_support::free_port()
        )],
    );
    let arguments = plan.into_arguments(abi_choices());
    Arc::new(arguments.run_node(role).expect("the node opens"))
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

/// A liveliness get through the port finds the tokens alive that meet its key, the other node's
/// and the node's own, in one leg that has ended when the get returns; a token that went is found
/// no more, and a key nothing meets finds nothing.
#[cfg(feature = "liveliness-get")]
#[test]
fn a_liveliness_get_through_the_port_finds_the_tokens_alive() {
    let (router, peer) = pair();
    let (engine, other) = (router.as_engine(), peer.as_engine());

    /// Counts the end of a leg: its callback is let go when the leg ends.
    struct Ended(Arc<AtomicUsize>);
    impl Drop for Ended {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    // The keys a get through the port finds, in order, and whether every leg it issued had ended
    // when the get returned.
    let alive = |key: &str| -> (Vec<String>, bool) {
        let keys = Arc::new(Mutex::new(Vec::<String>::new()));
        let ended = Arc::new(AtomicUsize::new(0));
        let issued = engine
            .liveliness_get_on_wire(key, &WireKey::literal(), 0, None, &mut || {
                let keys = Arc::clone(&keys);
                let end = Ended(Arc::clone(&ended));
                Box::new(move |reply: &dyn ReplyView| {
                    let _ = &end;
                    if reply.kind() == ReplyKind::Put {
                        keys.lock().unwrap().push(reply.keyexpr().to_owned());
                    }
                })
            })
            .expect("a node asks liveliness queries");
        let mut keys = keys.lock().unwrap().clone();
        keys.sort();
        (keys, ended.load(Ordering::SeqCst) == issued)
    };

    let from_peer = other
        .declare_liveliness_token_on_wire("wz/port/lg/peer".to_owned(), WireKey::literal(), None)
        .expect("a client has tokens");
    let _own = engine
        .declare_liveliness_token_on_wire("wz/port/lg/router".to_owned(), WireKey::literal(), None)
        .expect("a node has tokens");
    let both = vec!["wz/port/lg/peer".to_owned(), "wz/port/lg/router".to_owned()];
    assert!(
        eventually(|| alive("wz/port/lg/**").0 == both),
        "a get through the port did not find the client's token and the node's own: {:?}",
        alive("wz/port/lg/**").0
    );
    assert!(
        alive("wz/port/lg/**").1,
        "a leg of the get had not ended when the get returned"
    );
    assert_eq!(alive("wz/port/other/**").0, Vec::<String>::new());

    other.undeclare_liveliness_token(from_peer);
    assert!(
        eventually(|| alive("wz/port/lg/**").0 == ["wz/port/lg/router"]),
        "a get through the port still found the token the client retracted: {:?}",
        alive("wz/port/lg/**").0
    );
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

/// A node that dials a node: a router and a peer node each dial a router node, and each holds
/// the other as a face with the other's role. This is the link two nodes of a mesh make, which
/// the registry client of the tests above is not.
#[test]
fn a_node_that_dials_a_node_holds_it_as_a_face() {
    // (the dialling node's role, its wire form as the router node reads it)
    for (role, wire) in [(NodeRole::Router, 0u8), (NodeRole::Peer, 1u8)] {
        let router = open_node();
        let locator = router
            .listen_locators()
            .first()
            .expect("the router listens")
            .clone();
        let dialler = open_node_as(role, vec![locator]);
        let (engine, other) = (router.as_engine(), dialler.as_engine());
        let dialler_zid = other.zid();
        assert!(
            eventually(|| !engine.face_snapshots().is_empty() && !other.face_snapshots().is_empty()),
            "a {role:?} node's link to a router node did not come up: the router holds {} \
             face(s), the dialling node holds {}",
            engine.face_snapshots().len(),
            other.face_snapshots().len()
        );
        assert_eq!(
            engine.peer_identities(),
            vec![(dialler_zid.to_vec(), wire)],
            "the router node holds the {role:?} node as a face of its role"
        );
        assert_eq!(
            other.peer_identities(),
            vec![(engine.zid().to_vec(), 0)],
            "the {role:?} node holds the router node as a router"
        );
        assert!(other.has_router_peer());
        dialler.close();
        assert!(
            eventually(|| engine.face_snapshots().is_empty()),
            "the router node kept the face of a {role:?} node that closed"
        );
        router.close();
    }
}

/// The port's shared-memory publication, over links that negotiated shared memory.
#[cfg(feature = "session-extshm")]
mod shared_memory {
    use wz_runtime_tokio::shm_provider::ShmBackedPayload;
    use wz_session_core::sink::SampleView;

    use super::*;

    /// What a document states for a session to offer shared memory.
    const SHM_ENABLED: &str = ", transport: { shared_memory: { enabled: true } }";

    const KEY: &str = "wz/port/shm";
    const BODY: &[u8] = b"a chunk the node published";

    /// A router node on loopback that offers shared memory to the sessions it accepts.
    fn open_node_offering_shm() -> Arc<RouterState> {
        let plan = plan_stating(
            WhatAmI::Router,
            "router",
            Vec::new(),
            vec![format!(
                "tcp/127.0.0.1:{}",
                wz_runtime_tokio_test_support::free_port()
            )],
            SHM_ENABLED,
        );
        Arc::new(
            plan.into_arguments(abi_choices_offering(true))
                .run_node(NodeRole::Router)
                .expect("the node opens"),
        )
    }

    /// A registry client that dials `connect` and offers shared memory.
    fn client_offering_shm(connect: Vec<String>) -> Client {
        let plan = plan_stating(WhatAmI::Client, "client", connect, Vec::new(), SHM_ENABLED);
        Client(
            plan.into_arguments(abi_choices_offering(true))
                .run()
                .expect("the client opens"),
        )
    }

    /// What a subscriber was handed: each payload, and whether it came as a chunk of shared
    /// memory rather than as bytes.
    type Got = Arc<Mutex<Vec<(Vec<u8>, bool)>>>;

    fn subscribe(engine: &Arc<dyn SessionEngine>) -> (Got, SubId) {
        let got: Got = Arc::default();
        let sink = Arc::clone(&got);
        let id = engine.declare_subscriber_on_wire(
            KEY.to_owned(),
            WireKey::literal(),
            Locality::Any,
            None,
            Arc::new(move || {
                let sink = Arc::clone(&sink);
                Box::new(move |sample: &dyn SampleView| {
                    let shared = sample
                        .payload_shared()
                        .and_then(|bytes| bytes.shm_chunk())
                        .is_some();
                    sink.lock()
                        .unwrap()
                        .push((sample.payload().to_vec(), shared));
                })
            }),
        );
        (got, id)
    }

    /// A chunk published through the port goes to a client that negotiated shared memory as the
    /// chunk, to a client that did not as its bytes, and to the node's own subscriber as the
    /// chunk; and the port says it has a peer of shared memory only once such a client is linked.
    #[test]
    fn a_chunk_published_through_the_port_reaches_a_shm_peer_as_the_chunk_and_another_as_bytes() {
        let node = open_node_offering_shm();
        let engine = node.as_engine();
        let locator = node.listen_locators()[0].clone();

        let plain = Client::open(vec![locator.clone()]);
        assert!(eventually(|| engine.face_snapshots().len() == 1));
        assert!(
            !engine.has_shm_peer(),
            "the port has a peer of shared memory while its one client offered none"
        );
        let shared = client_offering_shm(vec![locator]);
        assert!(
            eventually(|| engine.has_shm_peer()),
            "the port has no peer of shared memory with a client that offered it linked"
        );

        let (on_shared, _) = subscribe(&shared.as_engine());
        let (on_plain, _) = subscribe(&plain.as_engine());
        let (on_node, _) = subscribe(&engine);

        let mut chunk = ShmBackedPayload::alloc(BODY.len()).expect("a POSIX segment");
        chunk.write(BODY);
        let chunk = Arc::new(chunk);
        // The clients' subscriptions reach the node over their links; until they have, a
        // publication has fewer faces to go to, so it is sent again until each has one.
        let deadline = Instant::now() + WAIT;
        let told = |got: &Got| !got.lock().unwrap().is_empty();
        while !(told(&on_shared) && told(&on_plain) && told(&on_node)) && Instant::now() < deadline
        {
            engine
                .publish_shm_on_wire_all(
                    KEY,
                    &WireKey::literal(),
                    chunk.send_handle(),
                    &PublishOptions::default(),
                )
                .expect("a node publishes a chunk");
            std::thread::sleep(Duration::from_millis(100));
        }

        let first = |got: &Got, who: &str| {
            got.lock()
                .unwrap()
                .first()
                .cloned()
                .unwrap_or_else(|| panic!("{who} was handed nothing"))
        };
        assert_eq!(
            first(&on_shared, "the client of shared memory"),
            (BODY.to_vec(), true),
            "the client that negotiated shared memory was not handed the chunk"
        );
        assert_eq!(
            first(&on_plain, "the client without shared memory"),
            (BODY.to_vec(), false),
            "the client that negotiated no shared memory was not handed the bytes"
        );
        assert_eq!(
            first(&on_node, "the node's own subscriber"),
            (BODY.to_vec(), true),
            "the node's own subscriber was not handed the chunk"
        );
        shared.close();
        plain.close();
        node.close();
    }

    const ASKED: &str = "wz/port/shm/q";

    /// What a queryable was asked with: each query's value, and whether it was handed as a chunk
    /// of shared memory rather than as bytes.
    fn answer(engine: &Arc<dyn SessionEngine>) -> (Got, QblId) {
        let got: Got = Arc::default();
        let sink = Arc::clone(&got);
        let id = engine
            .declare_queryable_on_wire(
                ASKED.to_owned(),
                WireKey::literal(),
                // Not complete, so that a query of best matching is routed to every one.
                false,
                Locality::Any,
                None,
                Arc::new(move |_holder| {
                    let sink = Arc::clone(&sink);
                    Box::new(move |query: &dyn QueryView, _out: &mut dyn ReplyOut| {
                        let shared = query
                            .payload_shared()
                            .and_then(|bytes| bytes.shm_chunk())
                            .is_some();
                        sink.lock()
                            .unwrap()
                            .push((query.payload().unwrap_or_default().to_vec(), shared));
                    })
                }),
            )
            .expect("a session has queryables");
        (got, id)
    }

    /// A chunk with [`BODY`] in it.
    fn chunk() -> Arc<ShmBackedPayload> {
        let mut chunk = ShmBackedPayload::alloc(BODY.len()).expect("a POSIX segment");
        chunk.write(BODY);
        Arc::new(chunk)
    }

    fn first(got: &Got, who: &str) -> (Vec<u8>, bool) {
        got.lock()
            .unwrap()
            .first()
            .cloned()
            .unwrap_or_else(|| panic!("{who} was handed nothing"))
    }

    /// `ask` again every 100 ms until each of `got` has been handed something, or [`WAIT`] ends:
    /// the declarations of the clients reach the node over their links.
    fn until_each_is_told(got: &[&Got], mut ask: impl FnMut()) {
        let deadline = Instant::now() + WAIT;
        let told = |got: &Got| !got.lock().unwrap().is_empty();
        while !got.iter().all(|got| told(got)) && Instant::now() < deadline {
            ask();
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// A get through the node's port whose value is a chunk (`get_shm_on_wire`) sends the chunk's
    /// descriptor to a client that negotiated shared memory and its bytes to one that did not, and
    /// the node's own queryable reads the chunk.
    #[test]
    fn a_get_of_the_node_sends_its_chunk_as_a_descriptor_to_a_shm_peer_and_as_bytes_to_another() {
        let node = open_node_offering_shm();
        let engine = node.as_engine();
        let locator = node.listen_locators()[0].clone();
        let plain = Client::open(vec![locator.clone()]);
        let shared = client_offering_shm(vec![locator]);
        assert!(eventually(|| engine.has_shm_peer()));

        let (on_shared, _) = answer(&shared.as_engine());
        let (on_plain, _) = answer(&plain.as_engine());
        let (on_node, _) = answer(&engine);
        let value = chunk();
        until_each_is_told(&[&on_shared, &on_plain, &on_node], || {
            assert_eq!(
                engine.get_shm_on_wire(
                    ASKED,
                    &WireKey::literal(),
                    &QueryOptions::default(),
                    value.send_handle(),
                    None,
                    &mut || Box::new(|_: &dyn ReplyView| {}),
                ),
                Some(1),
                "a node asks with a chunk on one leg"
            );
        });

        assert_eq!(
            first(&on_shared, "the queryable of the client of shared memory"),
            (BODY.to_vec(), true),
            "the client that negotiated shared memory was not asked with the chunk"
        );
        assert_eq!(
            first(
                &on_plain,
                "the queryable of the client without shared memory"
            ),
            (BODY.to_vec(), false),
            "the client that negotiated no shared memory was not asked with the bytes"
        );
        assert_eq!(
            first(&on_node, "the node's own queryable"),
            (BODY.to_vec(), true),
            "the node's own queryable was not asked with the chunk"
        );
        shared.close();
        plain.close();
        node.close();
    }

    /// What a client that negotiated shared memory sends the node as a chunk through its port, the
    /// value of a get (`get_shm_on_wire` of the registry) and a publication, the node's own
    /// queryable and subscriber read as the chunk: the node reads a descriptor with the default
    /// reader, having been opened over none.
    #[test]
    fn a_queryable_and_a_subscriber_of_the_node_read_the_chunks_a_shm_peer_sends() {
        let node = open_node_offering_shm();
        let engine = node.as_engine();
        let shared = client_offering_shm(vec![node.listen_locators()[0].clone()]);
        assert!(eventually(|| engine.has_shm_peer()));
        let other = shared.as_engine();

        let (asked, _) = answer(&engine);
        let (told, _) = subscribe(&engine);
        let value = chunk();
        until_each_is_told(&[&asked], || {
            other.get_shm_on_wire(
                ASKED,
                &WireKey::literal(),
                &QueryOptions::default(),
                value.send_handle(),
                None,
                &mut || Box::new(|_: &dyn ReplyView| {}),
            );
        });
        until_each_is_told(&[&told], || {
            other
                .publish_shm_on_wire_all(
                    KEY,
                    &WireKey::literal(),
                    value.send_handle(),
                    &PublishOptions::default(),
                )
                .expect("a client publishes a chunk");
        });

        assert_eq!(
            first(&asked, "the node's own queryable"),
            (BODY.to_vec(), true),
            "the node's own queryable did not read the chunk the client asked with"
        );
        assert_eq!(
            first(&told, "the node's own subscriber"),
            (BODY.to_vec(), true),
            "the node's own subscriber did not read the chunk the client published"
        );
        shared.close();
        node.close();
    }
}
