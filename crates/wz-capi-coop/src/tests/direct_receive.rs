// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a callback of a received sample may count on, whichever way the read reaches it: it runs
//! with the session free, it sees the session as the records before it left it, a put it makes
//! leaves while the rest of the frame waits, a read it makes reads nothing, and a close it makes
//! ends the read and lets the link go once. And what the read owes the session's peer while it
//! reads: a stream of input holds off neither the keep-alive nor the records that are not samples.
//! Every test runs in a build of one thread as in one of threads: the read of one thread hands each
//! record out from inside its receive, the read of threads after it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_port::{SessionDrive, SessionEngine, SubscriberSink, WireKey};
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::sink::SampleView;

use super::{config, open, open_with, until, CatchAll, Command, Router};
use crate::{CoopConfig, EngineHold};

/// The samples of a batch of `COUNT` the router sends on `demo/in`.
const COUNT: u8 = 3;

/// A peer's reply is handed to the get it answers by the read itself, with the session free and
/// nothing of it held in the round. The get consolidates nothing, so the reply is handed as it
/// comes and not with what its leg held to its end. Turned red by a reply offered to the round
/// (the read counts none) or handed out while the read holds the session.
#[cfg(all(
    feature = "query",
    not(any(feature = "threads", feature = "listen", feature = "group"))
))]
#[test]
fn a_reply_is_handed_to_its_get_by_the_read_with_the_session_free() {
    use wz_capi_port::ReplyCallback;
    use wz_session_core::reply_sink::ReplyView;

    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    super::get::settle(&router, &engine, Command::Answer("demo/g/**", b"r"));
    // Whether each reply's callback found the session free, and the reply's payload.
    type Seen = Arc<Mutex<Vec<(bool, Vec<u8>)>>>;
    let seen: Seen = Arc::default();
    let mut session = Some(EngineHold::downgrade(&engine));
    let issued = engine.get_on_wire(
        "demo/g/a",
        &WireKey::literal(),
        &super::get::remote_get()
            .with_consolidation(wz_session_core::query_mode::ConsolidationMode::None),
        None,
        &mut || {
            let seen = seen.clone();
            let session = session.take();
            ReplyCallback::shared(move |view: &dyn ReplyView| {
                let free = session
                    .as_ref()
                    .and_then(|session| session.upgrade())
                    .is_some_and(|engine| engine.session_is_free());
                seen.lock().unwrap().push((free, view.payload().to_vec()));
            })
        },
    );
    assert!(matches!(issued, Ok(1)), "one leg: the link's peer");
    assert_eq!(
        engine.replies_handed_by_the_read(),
        0,
        "CONTROL: nothing is handed before a step"
    );
    until(&engine, "the reply", || !seen.lock().unwrap().is_empty());
    assert_eq!(
        *seen.lock().unwrap(),
        [(true, b"r".to_vec())],
        "the reply's callback found the session held"
    );
    assert_eq!(
        engine.replies_handed_by_the_read(),
        1,
        "the reply was held in the round"
    );
}

/// A peer's query is handed to each queryable it reaches by the read itself, one call at a time in
/// the table's order with the session free, nothing of it held in the round, and its Final follows
/// the replies. Turned red by a query offered to the round (the read counts none), handed while the
/// read holds the session, or a Final sent before a reply.
#[cfg(all(
    feature = "queryable",
    not(any(feature = "threads", feature = "listen", feature = "group"))
))]
#[test]
fn a_query_is_handed_to_its_queryables_by_the_read_with_the_session_free() {
    use wz_capi_port::QueryableSink;

    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let seen: Arc<Mutex<Vec<(u8, bool)>>> = Arc::default();
    // Two keys, so neither declaration stands for the other.
    for (which, key) in [(1u8, "demo/h/**"), (2, "demo/h/a")] {
        let seen = seen.clone();
        let session = EngineHold::downgrade(&engine);
        engine
            .declare_queryable_on_wire(
                key,
                WireKey::literal(),
                false,
                Locality::Remote,
                None,
                QueryableSink::shared(move |query, out, _holder| {
                    let free = session
                        .upgrade()
                        .is_some_and(|engine| engine.session_is_free());
                    seen.lock().unwrap().push((which, free));
                    out.reply_keyed(query.keyexpr(), b"r")
                        .expect("a reply on the query's own key");
                }),
            )
            .expect("the engine has queryables in this build");
    }
    until(&engine, "the router to see the queryables", || {
        router.seen(|s| s.declares) >= 2
    });
    assert_eq!(
        engine.queries_handed_by_the_read(),
        0,
        "CONTROL: nothing is handed before the query"
    );
    router.send(Command::Query(3, "demo/h/a"));
    until(&engine, "the replies and the final", || {
        router.seen(|s| s.answers.len()) >= 3
    });
    assert_eq!(
        *seen.lock().unwrap(),
        [(1, true), (2, true)],
        "each queryable in its order, the session free"
    );
    assert_eq!(
        router.seen(|s| s.answers.clone()),
        vec!["reply", "reply", "final"]
    );
    assert_eq!(
        engine.queries_handed_by_the_read(),
        2,
        "the query was held in the round"
    );
}

/// Each sample of one frame is handed to its callback with the session's state free: a callback
/// that takes the session (a put, a declaration) never waits on the read that called it. Turned
/// red by a read that hands a record out while it holds the session.
#[test]
fn a_callback_runs_with_the_session_free() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let free: Arc<Mutex<Vec<bool>>> = Arc::default();
    let session = EngineHold::downgrade(&engine);
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire("demo/in", WireKey::literal(), Locality::Any, None, {
            let free = free.clone();
            SubscriberSink::shared(move |_: &dyn SampleView| {
                if let Some(engine) = session.upgrade() {
                    free.lock().unwrap().push(engine.session_is_free());
                }
            })
        })
        .expect("the session declares the subscriber")
        .id;
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    router.send(Command::PushBatch("demo/in", COUNT));
    until(&engine, "the batch", || {
        free.lock().unwrap().len() == usize::from(COUNT)
    });
    assert_eq!(
        *free.lock().unwrap(),
        [true; COUNT as usize],
        "a callback found the session held"
    );
}

/// A callback that undeclares its own subscriber at the first sample of a frame of several is
/// handed none of the rest of that frame: the second record sees what the first one's callback
/// did. Turned red by a read that hands the records of a frame out on rows it looked up before
/// the first callback ran and reads no undeclaration after.
#[test]
fn the_second_record_of_a_frame_sees_what_the_first_callback_did() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let received = Arc::new(AtomicUsize::new(0));
    let own: Arc<Mutex<Option<wz_capi_port::SubId>>> = Arc::default();
    let session = EngineHold::downgrade(&engine);
    let declares_before = router.seen(|s| s.declares);
    let id = engine
        .declare_subscriber_on_wire("demo/in", WireKey::literal(), Locality::Any, None, {
            let received = received.clone();
            let own = own.clone();
            SubscriberSink::shared(move |_: &dyn SampleView| {
                received.fetch_add(1, Ordering::SeqCst);
                let id = own.lock().unwrap().take();
                if let (Some(id), Some(engine)) = (id, session.upgrade()) {
                    engine.undeclare_subscriber(id);
                }
            })
        })
        .expect("the session declares the subscriber")
        .id;
    *own.lock().unwrap() = Some(id);
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    router.send(Command::PushBatch("demo/in", COUNT));
    until(&engine, "the first sample", || {
        received.load(Ordering::SeqCst) >= 1
    });
    for _ in 0..10 {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert_eq!(
        received.load(Ordering::SeqCst),
        1,
        "a record after the undeclaration reached the subscriber"
    );
}

/// A callback of the first sample of a frame puts on another key: the put reaches the router, and
/// the rest of the frame is handed on after it, in order. The link sends while the frame it read
/// is still being handed out. Turned red by a put refused or held back while a frame is lent, or
/// by a frame whose records after the put are lost.
#[test]
fn a_put_from_a_callback_leaves_while_the_frame_is_lent() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    let got: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let put: Arc<Mutex<Vec<bool>>> = Arc::default();
    let session = EngineHold::downgrade(&engine);
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire("demo/in", WireKey::literal(), Locality::Any, None, {
            let got = got.clone();
            let put = put.clone();
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                got.lock().unwrap().push(sample.payload().to_vec());
                if sample.payload() == [0] {
                    if let Some(engine) = session.upgrade() {
                        let sent = engine
                            .publish_on_wire_all(
                                "demo/out",
                                &WireKey::literal(),
                                b"v",
                                &PublishOptions::put(),
                            )
                            .is_ok();
                        put.lock().unwrap().push(sent);
                    }
                }
            })
        })
        .expect("the session declares the subscriber")
        .id;
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    router.send(Command::PushBatch("demo/in", COUNT));
    until(&engine, "the batch and the put", || {
        got.lock().unwrap().len() == usize::from(COUNT)
            && router.seen(|s| s.samples.iter().any(|(key, _)| key == "demo/out"))
    });
    assert_eq!(
        *put.lock().unwrap(),
        [true],
        "the put from the callback was refused"
    );
    assert_eq!(
        *got.lock().unwrap(),
        (0..COUNT).map(|index| vec![index]).collect::<Vec<_>>(),
        "the records after the put were handed on, in order"
    );
}

/// A read a callback makes reads no record of the link: no callback runs inside another, the read
/// answers that the session is open, and every record of the frame is handed out once, in order,
/// by the read that was under way. Turned red by a read from inside a callback that receives
/// again while the link lends the frame being handed out.
#[test]
fn a_read_from_a_callback_reads_nothing() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let got: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let answers: Arc<Mutex<Vec<bool>>> = Arc::default();
    let depth = Arc::new(AtomicUsize::new(0));
    let deepest = Arc::new(AtomicUsize::new(0));
    let session = EngineHold::downgrade(&engine);
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire("demo/in", WireKey::literal(), Locality::Any, None, {
            let got = got.clone();
            let answers = answers.clone();
            let depth = depth.clone();
            let deepest = deepest.clone();
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                let now = depth.fetch_add(1, Ordering::SeqCst) + 1;
                deepest.fetch_max(now, Ordering::SeqCst);
                got.lock().unwrap().push(sample.payload().to_vec());
                if let Some(engine) = session.upgrade() {
                    let open = SessionDrive::read(&*engine, false).is_ok();
                    answers.lock().unwrap().push(open);
                }
                depth.fetch_sub(1, Ordering::SeqCst);
            })
        })
        .expect("the session declares the subscriber")
        .id;
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    router.send(Command::PushBatch("demo/in", COUNT));
    until(&engine, "the batch", || {
        got.lock().unwrap().len() >= usize::from(COUNT)
    });
    for _ in 0..4 {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert_eq!(
        deepest.load(Ordering::SeqCst),
        1,
        "a callback ran inside another's read"
    );
    assert_eq!(
        *answers.lock().unwrap(),
        [true; COUNT as usize],
        "a read from a callback answered the session closed"
    );
    assert_eq!(
        *got.lock().unwrap(),
        (0..COUNT).map(|index| vec![index]).collect::<Vec<_>>(),
        "each record of the frame was handed out once, in order"
    );
}

/// A callback of the first sample of a frame closes the session: no callback runs after it, the
/// next read answers the session closed, and the session's links are let go of once, whoever lets
/// them go and when. Turned red by a callback called after the close, or by a close that lets the
/// links go twice (or the link its read still lends at once, which a second letting go is the
/// sign of).
#[test]
fn a_close_from_a_callback_ends_the_read_and_lets_the_link_go_once() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let calls = Arc::new(AtomicUsize::new(0));
    let session = EngineHold::downgrade(&engine);
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire("demo/in", WireKey::literal(), Locality::Any, None, {
            let calls = calls.clone();
            SubscriberSink::shared(move |_: &dyn SampleView| {
                calls.fetch_add(1, Ordering::SeqCst);
                if let Some(engine) = session.upgrade() {
                    SessionDrive::close(&*engine);
                }
            })
        })
        .expect("the session declares the subscriber")
        .id;
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    assert_eq!(
        engine.links_let_go(),
        0,
        "CONTROL: the open session holds its links"
    );
    router.send(Command::PushBatch("demo/in", COUNT));
    let deadline = Instant::now() + Duration::from_secs(5);
    while calls.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline, "timed out waiting for the batch");
        let _ = SessionDrive::read(&*engine, false);
    }
    assert!(
        SessionDrive::read(&*engine, false).is_err(),
        "a read after the close answered the session open"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a callback ran after the close"
    );
    assert_eq!(
        engine.links_let_go(),
        1,
        "the close let the links go other than once"
    );
    SessionDrive::close(&*engine);
    assert_eq!(
        engine.links_let_go(),
        1,
        "a second close let the links go again"
    );
}

/// A callback that closes its session reads the key it was handed until it returns: the key, named
/// by an id the router declared, is the literal the session's table of the router's ids keeps,
/// which the close leaves where it lies until the read that stepped the link has returned. No
/// callback runs after the close. Turned red by a close that lets the router's ids go while the
/// callback that closed holds a key read off them.
#[test]
fn a_callback_that_closes_its_session_reads_its_key_until_it_returns() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let keys: Arc<Mutex<Vec<String>>> = Arc::default();
    let session = EngineHold::downgrade(&engine);
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire("demo/named", WireKey::literal(), Locality::Any, None, {
            let keys = keys.clone();
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                if let Some(engine) = session.upgrade() {
                    SessionDrive::close(&*engine);
                }
                keys.lock().unwrap().push(sample.keyexpr().to_string());
            })
        })
        .expect("the session declares the subscriber")
        .id;
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    router.send(Command::DeclarePushKeepAlivePush(
        12,
        "demo/named",
        b"first",
        b"second",
    ));
    let deadline = Instant::now() + Duration::from_secs(5);
    while keys.lock().unwrap().is_empty() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the sample"
        );
        let _ = SessionDrive::read(&*engine, false);
    }
    let _ = SessionDrive::read(&*engine, false);
    assert_eq!(
        *keys.lock().unwrap(),
        ["demo/named"],
        "the key read after the close, or a callback after it"
    );
}

/// A read from a callback that the session's own put runs reads nothing and takes nothing of the
/// session: a record it read would be handed to a callback inside another. The CONTROL is the
/// put, which reaches the subscriber. Turned red by a read that steps the link from inside a
/// delivery other than a read's.
#[cfg(all(
    feature = "local-subscriber",
    not(any(feature = "threads", feature = "listen", feature = "group"))
))]
#[test]
fn a_read_from_a_callback_of_the_sessions_own_put_reads_nothing() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let reads: Arc<Mutex<Vec<(bool, usize)>>> = Arc::default();
    let session = EngineHold::downgrade(&engine);
    engine
        .declare_subscriber_on_wire("demo/own", WireKey::literal(), Locality::Any, None, {
            let reads = reads.clone();
            SubscriberSink::shared(move |_: &dyn SampleView| {
                if let Some(engine) = session.upgrade() {
                    let before = engine.takes.core.load(Ordering::SeqCst);
                    let open = SessionDrive::read(&*engine, false).is_ok();
                    let took = engine.takes.core.load(Ordering::SeqCst) - before;
                    reads.lock().unwrap().push((open, took));
                }
            })
        })
        .expect("the session declares the subscriber")
        .id;
    let own = PublishOptions::put().with_locality(Locality::SessionLocal);
    assert_eq!(
        engine.publish_on_wire_all("demo/own", &WireKey::literal(), b"v", &own),
        Ok(1),
        "CONTROL: the put reached the subscriber"
    );
    assert_eq!(
        *reads.lock().unwrap(),
        [(true, 0)],
        "the read from the callback took the session, or answered it closed"
    );
}

/// A put of the session's own hands each subscriber it reaches the sample with the session free,
/// one row at a time: a row the first callback undeclared before the put reached it is handed
/// nothing, and the put counts the first alone. The CONTROL is the first subscriber, handed the
/// sample. Turned red by a put that begins a call on every row it reaches under one lock before
/// the first callback runs.
#[cfg(all(
    feature = "local-subscriber",
    not(any(feature = "threads", feature = "listen", feature = "group"))
))]
#[test]
fn a_put_of_the_sessions_own_hands_its_subscribers_one_row_at_a_time() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let seen: Arc<Mutex<Vec<(u8, bool)>>> = Arc::default();
    let later: Arc<Mutex<Option<wz_capi_port::SubId>>> = Arc::default();
    let session = EngineHold::downgrade(&engine);
    engine
        .declare_subscriber_on_wire("demo/own", WireKey::literal(), Locality::Any, None, {
            let (seen, later) = (seen.clone(), later.clone());
            SubscriberSink::shared(move |_: &dyn SampleView| {
                if let Some(engine) = session.upgrade() {
                    seen.lock().unwrap().push((1, engine.session_is_free()));
                    let id = later.lock().unwrap().take();
                    if let Some(id) = id {
                        engine.undeclare_subscriber(id);
                    }
                }
            })
        })
        .expect("the session declares the first subscriber")
        .id;
    let id = engine
        .declare_subscriber_on_wire("demo/own", WireKey::literal(), Locality::Any, None, {
            let seen = seen.clone();
            SubscriberSink::shared(move |_: &dyn SampleView| {
                seen.lock().unwrap().push((2, true));
            })
        })
        .expect("the session declares the second subscriber")
        .id;
    *later.lock().unwrap() = Some(id);
    let own = PublishOptions::put().with_locality(Locality::SessionLocal);
    assert_eq!(
        engine.publish_on_wire_all("demo/own", &WireKey::literal(), b"v", &own),
        Ok(1),
        "the put reached the row undeclared before it got there"
    );
    assert_eq!(
        *seen.lock().unwrap(),
        [(1, true)],
        "the first callback ran with the session held, or the undeclared row was handed the put"
    );
}

/// A session whose lease is short, read without a pause while the router streams samples at it
/// for several of its leases: the read sends the keep-alive the router's lease of it needs on
/// time, so the session is still the router's peer at the end and its last sample arrives. Turned
/// red by a read that stays with its input and looks at its timers only once the link is quiet.
#[test]
fn a_stream_of_batches_still_sends_the_keep_alive_on_time() {
    const LEASE_MS: u64 = 500;
    let router = Router::start(CatchAll::None);
    let engine = open_with(CoopConfig {
        lease_ms: LEASE_MS,
        ..config(&router)
    });
    let received = Arc::new(AtomicUsize::new(0));
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire("demo/in", WireKey::literal(), Locality::Any, None, {
            let received = received.clone();
            SubscriberSink::shared(move |_: &dyn SampleView| {
                received.fetch_add(1, Ordering::SeqCst);
            })
        })
        .expect("the session declares the subscriber")
        .id;
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    let streaming = Instant::now() + Duration::from_millis(4 * LEASE_MS);
    while Instant::now() < streaming {
        router.send(Command::PushBatch("demo/in", COUNT));
        for _ in 0..4 {
            let _ = SessionDrive::read(&*engine, false);
        }
    }
    assert!(
        !SessionDrive::is_closed(&*engine),
        "the router's lease of the session ran out while it streamed"
    );
    let before = received.load(Ordering::SeqCst);
    router.send(Command::Push("demo/in", b"last"));
    until(&engine, "the sample after the stream", || {
        received.load(Ordering::SeqCst) > before
    });
}

/// A declaration, a Push naming what it declared, a KeepAlive and a second Push naming it again,
/// sent in one batch window: both samples reach the subscriber, in order, each resolved through the
/// declaration that came before it. Turned red by a read that hands a Push out before the
/// declaration ahead of it is applied, or that loses what follows the KeepAlive.
#[test]
fn mixed_batch_is_dispatched_as_before() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let got: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire("demo/mixed", WireKey::literal(), Locality::Any, None, {
            let got = got.clone();
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                got.lock().unwrap().push(sample.payload().to_vec());
            })
        })
        .expect("the session declares the subscriber")
        .id;
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    router.send(Command::DeclarePushKeepAlivePush(
        11,
        "demo/mixed",
        b"first",
        b"second",
    ));
    until(&engine, "both samples", || got.lock().unwrap().len() >= 2);
    assert_eq!(
        *got.lock().unwrap(),
        [b"first".to_vec(), b"second".to_vec()],
        "the samples around the KeepAlive, in order"
    );
}

/// A session whose link is up and settled, read while the router streams batches at it: the
/// step's bookkeeping (the sweeps, the move of the links, the read of the matching listeners) runs
/// at none of them, since nothing it follows changed and nothing of it fell due. Turned red by a
/// step that runs its bookkeeping whatever its ledger says, at every batch.
#[test]
fn a_steady_stream_runs_no_bookkeeping_per_batch() {
    const BATCHES: usize = 100;
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let received = Arc::new(AtomicUsize::new(0));
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire("demo/in", WireKey::literal(), Locality::Any, None, {
            let received = received.clone();
            SubscriberSink::shared(move |_: &dyn SampleView| {
                received.fetch_add(1, Ordering::SeqCst);
            })
        })
        .expect("the session declares the subscriber")
        .id;
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    // One batch first: whatever the declaration left owed is serviced by its reads.
    router.send(Command::PushBatch("demo/in", COUNT));
    until(&engine, "the first batch", || {
        received.load(Ordering::SeqCst) >= usize::from(COUNT)
    });
    let before = engine.services();
    for batch in 2..=BATCHES + 1 {
        router.send(Command::PushBatch("demo/in", COUNT));
        until(&engine, "the next batch", || {
            received.load(Ordering::SeqCst) >= usize::from(COUNT) * batch
        });
    }
    assert_eq!(
        engine.services() - before,
        0,
        "the bookkeeping ran during a stream that changed nothing it follows"
    );
}

/// The records of one frame are read in one take of the link's input, each handed out as it is
/// read, and no pass of a task runs for them: the read steps the link itself. Turned red by a read
/// that stops the walk of a frame at each record and reads the rest of it again at a later take,
/// or that runs the session's tasks to read it.
#[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
#[test]
fn a_frame_of_n_records_is_read_in_one_take() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let got: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire("demo/in", WireKey::literal(), Locality::Any, None, {
            let got = got.clone();
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                got.lock().unwrap().push(sample.payload().to_vec());
            })
        })
        .expect("the session declares the subscriber")
        .id;
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    let (reads, passes) = (
        engine.takes.pump_reads.load(Ordering::SeqCst),
        engine.task_clock_reads(),
    );
    router.send(Command::PushBatch("demo/in", COUNT));
    until(&engine, "the batch", || {
        got.lock().unwrap().len() >= usize::from(COUNT)
    });
    assert_eq!(
        *got.lock().unwrap(),
        (0..COUNT).map(|index| vec![index]).collect::<Vec<_>>(),
        "CONTROL: each record of the frame was handed out once, in order"
    );
    assert_eq!(
        engine.takes.pump_reads.load(Ordering::SeqCst) - reads,
        1,
        "the frame was read in more than one take"
    );
    assert_eq!(
        engine.task_clock_reads(),
        passes,
        "a pass of the session's tasks ran for the frame"
    );
}
