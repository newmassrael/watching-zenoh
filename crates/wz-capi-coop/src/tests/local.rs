// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Delivery to the session's own subscribers: a put reaches them inside the call, after it has
//! gone out on the link, by the destination it is made with and the origin each subscriber
//! admits; and a write filter or a matching listener that counts the session's own entities
//! counts them.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use wz_capi_port::{
    FanoutError, FilterPlane, FilteredPut, SessionEngine, SubId, SubscriberSink, WireKey,
};
use wz_session_core::declare_form::InterestAsk;
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::sink::SampleView;

use super::{open, until, CatchAll, Engine, Router};

/// What each subscriber of [`subscribe_putting`] was handed: its index and the payload.
type Handed = Arc<Mutex<Vec<(usize, Vec<u8>)>>>;

/// The answer of the put the first subscriber of [`subscribe_putting`] made from its callback.
type InnerPut = Arc<Mutex<Option<Result<usize, FanoutError>>>>;

/// A subscriber that counts what it is handed.
fn subscribe(engine: &Engine, key: &str, origin: Locality) -> (SubId, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    let into = count.clone();
    let id = engine
        .declare_subscriber_on_wire(key, WireKey::literal(), origin, None, {
            let into = into.clone();
            SubscriberSink::shared(move |_: &dyn SampleView| {
                into.fetch_add(1, Ordering::SeqCst);
            })
        })
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
    let filter = engine
        .declare_write_filter(
            FilterPlane::Subscribers,
            "demo/l/other",
            &WireKey::literal(),
            None,
            false,
        )
        .expect("a session with ids left declares");
    let same = loop {
        let listener = engine
            .declare_matching_listener(filter, Arc::new(|_: bool| {}))
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
    let listen = |filter: wz_capi_port::FilterId| {
        let log = Arc::new(Mutex::new(Vec::new()));
        let into = log.clone();
        let id = engine
            .declare_matching_listener(
                filter,
                Arc::new(move |matching| into.lock().unwrap().push(matching)),
            )
            .expect("a session with rows left declares");
        (id, log)
    };
    let filter = |count_local: bool| {
        engine
            .declare_write_filter(
                FilterPlane::Subscribers,
                "demo/l/x",
                &WireKey::literal(),
                Some(InterestAsk {
                    mapping_id: 0,
                    suffix: Some("demo/l/x"),
                    aggregate: false,
                }),
                count_local,
            )
            .expect("a session with ids left declares")
    };
    let counting_filter = filter(true);
    let blind_filter = filter(false);
    // Each listener counts what its filter counts.
    let (_, counting) = listen(counting_filter);
    let (_, blind) = listen(blind_filter);
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

/// A put a subscriber's callback makes from inside itself on its own subscriber's key reaches it
/// again at once, from inside itself, as zenoh-pico's recursion does
/// (`session/subscription.c`, `_z_trigger_subscriptions_impl`): each nested put is handed out to
/// depth 3 before the one around it returns, and every other subscriber is handed each put once,
/// the innermost first. The CONTROL is each put's answer: it reached both subscribers.
#[test]
fn a_put_made_inside_a_callback_reaches_it_again_to_depth_three() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let handed = Arc::new(Mutex::new(Vec::<(usize, Vec<u8>)>::new()));
    let answers = Arc::new(Mutex::new(Vec::new()));
    let session = Arc::downgrade(&engine);
    let (into, said) = (handed.clone(), answers.clone());
    engine
        .declare_subscriber_on_wire(
            "demo/l/deep",
            WireKey::literal(),
            Locality::SessionLocal,
            None,
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                let depth = sample.payload().first().copied().unwrap_or(0);
                into.lock().unwrap().push((0, sample.payload().to_vec()));
                if depth < 3 {
                    if let Some(engine) = session.upgrade() {
                        let sent = put_own(&engine, "demo/l/deep", &[depth + 1]);
                        said.lock().unwrap().push(sent);
                    }
                }
            }),
        )
        .expect("a session with ids left declares");
    let into = handed.clone();
    engine
        .declare_subscriber_on_wire(
            "demo/l/*",
            WireKey::literal(),
            Locality::SessionLocal,
            None,
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                into.lock().unwrap().push((1, sample.payload().to_vec()));
            }),
        )
        .expect("a session with ids left declares");

    assert_eq!(put_own(&engine, "demo/l/deep", &[0]), Ok(2));
    assert_eq!(
        *handed.lock().unwrap(),
        [
            (0, vec![0]),
            (0, vec![1]),
            (0, vec![2]),
            (0, vec![3]),
            (1, vec![3]),
            (1, vec![2]),
            (1, vec![1]),
            (1, vec![0]),
        ],
        "each nested put is handed out before the one around it goes on"
    );
    assert_eq!(*answers.lock().unwrap(), [Ok(2), Ok(2), Ok(2)]);
}

/// A put a callback makes from inside itself that does not reach that callback's subscriber is
/// handed to the others inside the call, as zenoh-pico's is.
#[test]
fn a_put_made_inside_a_callback_reaches_the_other_subscribers_inside_it() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let handed = Arc::new(Mutex::new(Vec::<(usize, Vec<u8>)>::new()));
    let inner = Arc::new(Mutex::new(None));
    subscribe_putting(&engine, &handed, &inner, "demo/l/side");

    put_own(&engine, "demo/l/fan", b"outer").expect("the publish is accepted");
    assert_eq!(
        *inner.lock().unwrap(),
        Some(Ok(2)),
        "the inner put reached the two others"
    );
    let outer = b"outer".to_vec();
    let nested = b"inner".to_vec();
    assert_eq!(
        *handed.lock().unwrap(),
        [
            (0, outer.clone()),
            (1, nested.clone()),
            (2, nested),
            (1, outer.clone()),
            (2, outer)
        ],
        "the others are handed the inner put inside the first callback"
    );
}

/// Three subscribers of the session's own, each recording what it is handed in `handed`: the
/// first on `demo/l/fan`, the other two on `demo/l/*`. The first, handed `outer`, puts `inner`
/// on `inner_key` from inside its callback and records the put's answer.
fn subscribe_putting(
    engine: &Arc<Engine>,
    handed: &Handed,
    inner: &InnerPut,
    inner_key: &'static str,
) {
    let session = Arc::downgrade(engine);
    for subscriber in 0..3usize {
        let handed = handed.clone();
        let inner = inner.clone();
        let session = session.clone();
        let key = if subscriber == 0 {
            "demo/l/fan"
        } else {
            "demo/l/*"
        };
        engine
            .declare_subscriber_on_wire(
                key,
                WireKey::literal(),
                Locality::SessionLocal,
                None,
                SubscriberSink::shared(move |sample: &dyn SampleView| {
                    handed
                        .lock()
                        .unwrap()
                        .push((subscriber, sample.payload().to_vec()));
                    if subscriber == 0 && sample.payload() == b"outer" {
                        if let Some(engine) = session.upgrade() {
                            let sent = put_own(&engine, inner_key, b"inner");
                            *inner.lock().unwrap() = Some(sent);
                        }
                    }
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

/// Counts its own drop: what the callback of a subscriber holds, to tell when it was let go of.
struct Dropped(Arc<AtomicUsize>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// An undeclaration made on another thread while a put's call of the subscriber's callback runs
/// returns only once that call has returned and the callback was let go of (P11), as zenoh-pico's
/// undeclare waits for the entity's lock. The CONTROL is the undeclaration while the callback is
/// held inside its call: not returned, and the callback standing.
#[test]
fn an_undeclare_on_another_thread_waits_for_the_running_call() {
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc::channel;
    use std::time::Duration;

    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    let dropped = Arc::new(AtomicUsize::new(0));
    let (entered, inside) = channel::<()>();
    let (release, released) = channel::<()>();
    let (entered, released) = (Mutex::new(entered), Mutex::new(released));
    let guard = Dropped(dropped.clone());
    let id = engine
        .declare_subscriber_on_wire(
            "demo/wait/**",
            WireKey::literal(),
            Locality::Any,
            None,
            SubscriberSink::shared(move |_: &dyn SampleView| {
                let _held = &guard;
                let _ = entered.lock().unwrap().send(());
                let _ = released.lock().unwrap().recv();
            }),
        )
        .expect("declared");
    let putting = {
        let engine = Arc::clone(&engine);
        std::thread::spawn(move || put_own(&engine, "demo/wait/a", b"v"))
    };
    inside
        .recv_timeout(Duration::from_secs(5))
        .expect("the put calls the callback");
    let returned = Arc::new(AtomicBool::new(false));
    let undeclaring = {
        let (engine, returned, dropped) = (
            Arc::clone(&engine),
            Arc::clone(&returned),
            Arc::clone(&dropped),
        );
        std::thread::spawn(move || {
            engine.undeclare_subscriber(id);
            returned.store(true, Ordering::SeqCst);
            dropped.load(Ordering::SeqCst)
        })
    };
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !returned.load(Ordering::SeqCst),
        "CONTROL: the undeclaration waits while the call runs"
    );
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        0,
        "CONTROL: the callback stands"
    );
    release
        .send(())
        .expect("the callback waits for its release");
    let dropped_when_returned = undeclaring.join().expect("the undeclaration returns");
    assert_eq!(
        dropped_when_returned, 1,
        "the callback was let go of before the undeclaration returned"
    );
    assert_eq!(
        putting.join().expect("the put returns"),
        Ok(1),
        "the put reached the subscriber once"
    );
    assert_eq!(dropped.load(Ordering::SeqCst), 1, "let go of once");
}

/// A callback that undeclares its own subscriber from inside a put's call of it does not wait for
/// itself: the undeclaration returns inside the call, and the row is let go of once the call has
/// returned, before the put does. A put after it reaches nothing; the CONTROL is the first put,
/// which reached the subscriber.
#[test]
fn a_callback_that_undeclares_its_own_subscriber_does_not_wait_for_itself() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    let dropped = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let own: Arc<Mutex<Option<SubId>>> = Arc::default();
    let guard = Dropped(dropped.clone());
    let session = Arc::downgrade(&engine);
    let id = engine
        .declare_subscriber_on_wire("demo/self/**", WireKey::literal(), Locality::Any, None, {
            let (calls, own) = (Arc::clone(&calls), Arc::clone(&own));
            SubscriberSink::shared(move |_: &dyn SampleView| {
                let _held = &guard;
                calls.fetch_add(1, Ordering::SeqCst);
                let id = own.lock().unwrap().take();
                if let (Some(id), Some(engine)) = (id, session.upgrade()) {
                    engine.undeclare_subscriber(id);
                }
            })
        })
        .expect("declared");
    *own.lock().unwrap() = Some(id);
    assert_eq!(
        put_own(&engine, "demo/self/a", b"v"),
        Ok(1),
        "CONTROL: the put reached the subscriber"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        1,
        "let go of once its own call returned, before the put did"
    );
    assert_eq!(
        put_own(&engine, "demo/self/b", b"v"),
        Ok(0),
        "nothing is left to reach"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
