// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Delivery to the session's own subscribers: a put reaches them inside the call, after it has
//! gone out on the link, by the destination it is made with and the origin each subscriber
//! admits; and a write filter or a matching listener that counts the session's own entities
//! counts them.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use wz_capi_port::{FanoutError, FilterPlane, FilteredPut, SessionEngine, SubId, WireKey};
use wz_session_core::declare_form::InterestForm;
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::sink::SampleView;

use super::{config, open, open_with, until, CatchAll, Engine, Router};

/// What each subscriber of [`subscribe_putting`] was handed: its index and the payload.
type Handed = Arc<Mutex<Vec<(usize, Vec<u8>)>>>;

/// The answer of the put the first subscriber of [`subscribe_putting`] made from its callback.
type InnerPut = Arc<Mutex<Option<Result<usize, FanoutError>>>>;

/// A subscriber that counts what it is handed.
fn subscribe(engine: &Engine, key: &str, origin: Locality) -> (SubId, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    let into = count.clone();
    let id = engine
        .declare_subscriber_on_wire(
            key,
            WireKey::literal(),
            origin,
            None,
            Arc::new(move || {
                let into = into.clone();
                Box::new(move |_: &dyn SampleView| {
                    into.fetch_add(1, Ordering::SeqCst);
                })
            }),
        )
        .expect("a session with ids left declares");
    (id, count)
}

fn put(engine: &Engine, key: &str, destination: Locality) {
    let opts = PublishOptions::put().with_locality(destination);
    engine
        .publish_on_wire_all(key, &WireKey::literal(), b"v", &opts)
        .expect("the publish is accepted");
}

/// A put reaches the session's own subscribers inside the call, with nothing stepped, and the
/// router's too: the one that admits any origin and the one that admits only the session's
/// own, and not the one that admits only a peer's. The destination decides the legs: the
/// session alone reaches no router, a peer alone reaches no subscriber of the session.
#[test]
fn a_put_reaches_the_sessions_own_subscribers_by_destination_and_origin() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    let (_, any) = subscribe(&engine, "demo/l/**", Locality::Any);
    let (_, own) = subscribe(&engine, "demo/l/**", Locality::SessionLocal);
    let (_, remote) = subscribe(&engine, "demo/l/**", Locality::Remote);
    until(&engine, "the router to hold the subscribers", || {
        router.seen(|s| s.declares) >= 3
    });

    put(&engine, "demo/l/a", Locality::Any);
    assert_eq!(
        (
            any.load(Ordering::SeqCst),
            own.load(Ordering::SeqCst),
            remote.load(Ordering::SeqCst)
        ),
        (1, 1, 0),
        "the callbacks ran inside the put: the session's own subscribers, not a peer-only one"
    );
    until(&engine, "the router to hear the put", || {
        router.seen(|s| s.samples.len()) == 1
    });

    put(&engine, "demo/l/b", Locality::SessionLocal);
    assert_eq!(
        (any.load(Ordering::SeqCst), own.load(Ordering::SeqCst)),
        (2, 2)
    );
    put(&engine, "demo/l/c", Locality::Remote);
    assert_eq!(
        (
            any.load(Ordering::SeqCst),
            own.load(Ordering::SeqCst),
            remote.load(Ordering::SeqCst)
        ),
        (2, 2, 0),
        "CONTROL: a put made for peers reaches none of the session's own"
    );
    until(&engine, "the router to hear the peer-only put", || {
        router.seen(|s| s.samples.len()) == 2
    });
    assert_eq!(
        router.seen(|s| s
            .samples
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>()),
        ["demo/l/a", "demo/l/c"],
        "CONTROL: the session-only put went to no router"
    );
}

/// A matching listener and a subscriber are numbered in spaces of their own, so the two may hold
/// the same number: retracting the listener that holds the subscriber's number leaves the
/// subscriber's callback where it was.
#[test]
fn retracting_a_matching_listener_leaves_the_subscriber_of_its_number() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let (subscriber, count) = subscribe(&engine, "demo/l/same", Locality::SessionLocal);
    let same = loop {
        let listener = engine
            .declare_matching_listener(
                FilterPlane::Subscribers,
                "demo/l/other",
                Arc::new(|_: bool| {}),
                false,
            )
            .expect("a session with rows left declares");
        assert!(
            listener <= u64::from(subscriber),
            "the listeners count up from 1"
        );
        if listener == u64::from(subscriber) {
            break listener;
        }
    };
    engine.undeclare_matching_listener(same);

    put(&engine, "demo/l/same", Locality::SessionLocal);
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "the subscriber's callback is still held"
    );
}

/// A write filter and a matching listener that count the session's own subscribers match
/// once one is declared and no more once it is retracted, with no peer subscribing at all; the
/// ones that do not count them match nothing, and a plain put that a subscriber of the session
/// wants gives way to the general publish.
#[test]
fn a_filter_and_a_listener_count_the_sessions_own_subscribers_when_asked() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let heard = |log: &Arc<Mutex<Vec<bool>>>| log.lock().unwrap().clone();
    let listen = |count_local: bool| {
        let log = Arc::new(Mutex::new(Vec::new()));
        let into = log.clone();
        let id = engine
            .declare_matching_listener(
                FilterPlane::Subscribers,
                "demo/l/x",
                Arc::new(move |matching| into.lock().unwrap().push(matching)),
                count_local,
            )
            .expect("a session with rows left declares");
        (id, log)
    };
    let (_, counting) = listen(true);
    let (_, blind) = listen(false);
    let filter = |count_local: bool| {
        engine
            .declare_write_filter(
                FilterPlane::Subscribers,
                "demo/l/x",
                &WireKey::literal(),
                Some(InterestForm {
                    mapping_id: 0,
                    suffix: Some("demo/l/x".to_owned()),
                    aggregate: false,
                }),
                count_local,
            )
            .expect("a session with ids left declares")
    };
    let counting_filter = filter(true);
    let blind_filter = filter(false);
    // One Interest on the key serves the two listeners and the two filters: the session holds
    // one per plane and key.
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) >= 1
    });
    assert!(
        engine.write_filter_active(counting_filter),
        "nothing matches yet"
    );

    let params = PublishOptions::put()
        .plain_put_params()
        .expect("a plain put");
    let (id, _) = subscribe(&engine, "demo/l/**", Locality::Any);
    assert_eq!(
        heard(&counting),
        [true],
        "the session's own subscriber matches"
    );
    assert!(
        heard(&blind).is_empty(),
        "one that does not count it hears nothing"
    );
    assert!(!engine.write_filter_active(counting_filter));
    assert!(
        engine.write_filter_active(blind_filter),
        "CONTROL: a filter that does not count it still suppresses"
    );
    assert_eq!(
        engine.put_plain_filtered(counting_filter, "demo/l/x", 0, b"v", &params),
        FilteredPut::NotPlain,
        "a put the session's own subscriber wants is the general publish's"
    );

    engine.undeclare_subscriber(id);
    assert_eq!(heard(&counting), [true, false]);
    assert!(engine.write_filter_active(counting_filter));
    assert!(heard(&blind).is_empty());

    // A subscriber that admits only a peer's put is no match for one of the session's own.
    let (_, _) = subscribe(&engine, "demo/l/**", Locality::Remote);
    assert_eq!(heard(&counting), [true, false]);
    assert!(engine.write_filter_active(counting_filter));
}

/// A put reaches each of the session's own subscribers once, inside the call. A put one of their
/// callbacks makes from inside itself reaches each of them once too: the others inside that
/// callback, as zenoh-pico's recursion does, and the subscriber whose callback made it once that
/// callback has returned, where pico would call it again from inside itself.
#[test]
fn a_put_made_inside_a_callback_reaches_each_subscriber_once() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let handed = Arc::new(Mutex::new(Vec::<(usize, Vec<u8>)>::new()));
    let inner = Arc::new(Mutex::new(None));
    subscribe_putting(&engine, &handed, &inner, 0);

    put_own(&engine, "demo/l/fan", b"outer").expect("the publish is accepted");
    let outer = b"outer".to_vec();
    let nested = b"inner".to_vec();
    assert_eq!(
        *inner.lock().unwrap(),
        Some(Ok(3)),
        "the inner put reached all three"
    );
    assert_eq!(
        *handed.lock().unwrap(),
        [
            (0, outer.clone()),
            (1, nested.clone()),
            (2, nested.clone()),
            (1, outer.clone()),
            (2, outer),
            (0, nested)
        ],
        "each subscriber once for each put; the one whose callback put, after it returned"
    );
}

/// A put made inside a subscriber's callback that reaches that subscriber, and that the delivery
/// lane cannot hold for it until its callback returns, is refused with nothing handed to any
/// subscriber of the session: no subscriber has it and the others not.
#[test]
fn a_put_the_lane_cannot_hold_for_a_running_callback_reaches_no_subscriber() {
    let router = Router::start(CatchAll::None);
    let mut config = config(&router);
    if config.limits.select_delivery_lane_bytes(8192).is_err() {
        // A build that keeps the lane to its own value has no lane this short.
        return;
    }
    let engine = open_with(config);
    let handed = Arc::new(Mutex::new(Vec::<(usize, Vec<u8>)>::new()));
    let inner = Arc::new(Mutex::new(None));
    subscribe_putting(&engine, &handed, &inner, 10_000);

    put_own(&engine, "demo/l/fan", b"outer").expect("the publish is accepted");
    assert_eq!(
        *inner.lock().unwrap(),
        Some(Err(FanoutError::LocalNoRoom)),
        "a sample longer than the whole lane cannot wait in it"
    );
    let outer = b"outer".to_vec();
    assert_eq!(
        *handed.lock().unwrap(),
        [(0, outer.clone()), (1, outer.clone()), (2, outer)],
        "the refused put reached no subscriber"
    );
}

/// Three subscribers of the session's own on `demo/l/fan`, each recording what it is handed in
/// `handed`; the first, handed `outer`, puts on the same key from inside its callback, `inner`
/// itself or, when `inner_len` is not zero, that many bytes, and records the put's answer.
fn subscribe_putting(engine: &Arc<Engine>, handed: &Handed, inner: &InnerPut, inner_len: usize) {
    let session = Arc::downgrade(engine);
    for subscriber in 0..3usize {
        let handed = handed.clone();
        let inner = inner.clone();
        let session = session.clone();
        engine
            .declare_subscriber_on_wire(
                "demo/l/fan",
                WireKey::literal(),
                Locality::SessionLocal,
                None,
                Arc::new(move || {
                    let handed = handed.clone();
                    let inner = inner.clone();
                    let session = session.clone();
                    Box::new(move |sample: &dyn SampleView| {
                        handed
                            .lock()
                            .unwrap()
                            .push((subscriber, sample.payload().to_vec()));
                        if subscriber == 0 && sample.payload() == b"outer" {
                            if let Some(engine) = session.upgrade() {
                                let payload = if inner_len == 0 {
                                    b"inner".to_vec()
                                } else {
                                    vec![7u8; inner_len]
                                };
                                let sent = put_own(&engine, "demo/l/fan", &payload);
                                *inner.lock().unwrap() = Some(sent);
                            }
                        }
                    })
                }),
            )
            .expect("a session with ids left declares");
    }
}

/// A put of `payload` on `key` for the session's own subscribers alone.
fn put_own(engine: &Engine, key: &str, payload: &[u8]) -> Result<usize, FanoutError> {
    let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
    engine.publish_on_wire_all(key, &WireKey::literal(), payload, &opts)
}
