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
#[cfg(all(feature = "query", not(wz_round)))]
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
#[cfg(all(feature = "queryable", not(wz_round)))]
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
        .expect("the session declares the subscriber");
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
        .expect("the session declares the subscriber");
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
        .expect("the session declares the subscriber");
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
        .expect("the session declares the subscriber");
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
        .expect("the session declares the subscriber");
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
#[cfg(all(feature = "local-subscriber", not(wz_round)))]
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
        .expect("the session declares the subscriber");
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

/// A put of the session's own hands every subscriber the one hold that read it found the sample,
/// each callback with the session free: a row the first callback undeclared before its turn came
/// is still handed it, as zenoh-pico calls each subscription of the list it took under its lock,
/// and the put counts both. The CONTROL is the first subscriber, handed the sample. Turned red by
/// a delivery that passes over a row it pinned once its subscriber was undeclared, or that holds
/// the session while it calls.
#[cfg(all(feature = "local-subscriber", not(wz_round)))]
#[test]
fn a_put_of_the_sessions_own_hands_every_row_its_hold_found() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let seen: Arc<Mutex<Vec<(u8, bool)>>> = Arc::default();
    let later: Arc<Mutex<Option<wz_capi_port::SubId>>> = Arc::default();
    let session = EngineHold::downgrade(&engine);
    let second = EngineHold::downgrade(&engine);
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
        .expect("the session declares the first subscriber");
    let id = engine
        .declare_subscriber_on_wire("demo/own", WireKey::literal(), Locality::Any, None, {
            let seen = seen.clone();
            SubscriberSink::shared(move |_: &dyn SampleView| {
                let free = second
                    .upgrade()
                    .is_some_and(|engine| engine.session_is_free());
                seen.lock().unwrap().push((2, free));
            })
        })
        .expect("the session declares the second subscriber")
        .id;
    *later.lock().unwrap() = Some(id);
    let own = PublishOptions::put().with_locality(Locality::SessionLocal);
    assert_eq!(
        engine.publish_on_wire_all("demo/own", &WireKey::literal(), b"v", &own),
        Ok(2),
        "the put passed over the row undeclared before its turn came"
    );
    assert_eq!(
        *seen.lock().unwrap(),
        [(1, true), (2, true)],
        "a callback ran with the session held, or the undeclared row was not handed the put"
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
        .expect("the session declares the subscriber");
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

/// A session whose every read finds its link holding input, so that no read waits or works out a
/// wait, read without a pause for several of its short leases with a get nobody answers pending:
/// the get still ends at its deadline while the reads go on, and the router's lease of the
/// session is still kept, since the look at the life after each read serves what fell due whether
/// or not the read waited. Each such read reads the clock once, for that look, and none for a
/// wait. The CONTROL is the leg halfway to its deadline: still open. Turned red by a read on held
/// input that leaves the look at the life or the pump's due work to the next read that waits
/// (`CoopEngine::link_turn`), or that still reads the clock for its wait (`link_wait`).
#[cfg(all(feature = "query", not(wz_round)))]
#[test]
fn reads_on_held_input_still_serve_what_falls_due() {
    use wz_session_core::reply_sink::ReplyKind;

    const LEASE_MS: u64 = 500;
    const READS: usize = 10;
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
        .expect("the session declares the subscriber");
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    super::get::settle(&router, &engine, Command::Silence);
    engine.takes.input_held.store(true, Ordering::SeqCst);
    let (clock_before, held_before) = (
        engine.clock_reads(),
        engine.takes.held_input_reads.load(Ordering::SeqCst),
    );
    for _ in 0..READS {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert_eq!(
        engine.takes.held_input_reads.load(Ordering::SeqCst) - held_before,
        READS,
        "a read that found the link's input held worked out a wait"
    );
    assert_eq!(
        engine.clock_reads() - clock_before,
        READS,
        "one reading of the clock for each look at the life, none for a wait"
    );
    let mut opts = super::get::remote_get();
    opts.timeout_ms = 300;
    let asked = Instant::now();
    let (issued, leg) = super::get::ask(&engine, "demo/g/a", &opts, None, None, None);
    assert_eq!(issued, Ok(1));
    let mut ended_at = None;
    let mut open_halfway = None;
    while asked.elapsed() < Duration::from_millis(4 * LEASE_MS) {
        let _ = SessionDrive::read(&*engine, false);
        let ended = leg.lock().unwrap().ended;
        if open_halfway.is_none() && asked.elapsed() >= Duration::from_millis(150) {
            open_halfway = Some(!ended);
        }
        if ended && ended_at.is_none() {
            ended_at = Some(asked.elapsed());
        }
    }
    engine.takes.input_held.store(false, Ordering::SeqCst);
    assert_eq!(
        open_halfway,
        Some(true),
        "CONTROL: open before its deadline"
    );
    let ended_at = ended_at.expect("the get outlived its deadline while every read held input");
    assert!(
        ended_at >= Duration::from_millis(300),
        "ended early: {ended_at:?}"
    );
    let replies = leg.lock().unwrap().replies.clone();
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert_eq!(replies[0].0, ReplyKind::Err);
    assert_eq!(replies[0].2, b"Timeout");
    assert!(
        !SessionDrive::is_closed(&*engine),
        "the router's lease of the session ran out while every read held input"
    );
    let before = received.load(Ordering::SeqCst);
    router.send(Command::Push("demo/in", b"last"));
    until(&engine, "the sample after the reads", || {
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
        .expect("the session declares the subscriber");
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
        .expect("the session declares the subscriber");
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

/// A session whose lease is short, read while nothing but keep-alives crosses its link: it sends
/// the keep-alive the router's lease of it needs at each turn of that lease, and runs its
/// bookkeeping at none of them, since neither its keep-alive's verdict nor a lease it stamps
/// changes anything the bookkeeping follows. CONTROL: the session is still open after several of
/// its leases. Turned red by a timer's verdict dispatched to the face's tables (`DirectSink`),
/// which counts as a write of them and owes the bookkeeping at the next look.
#[cfg(not(wz_round))]
#[test]
fn a_keep_alive_runs_no_bookkeeping() {
    const LEASE_MS: u64 = 600;
    let router = Router::start(CatchAll::None);
    let engine = open_with(CoopConfig {
        lease_ms: LEASE_MS,
        ..config(&router)
    });
    // Whatever the open left owed is served by the reads right after it.
    let settled = Instant::now() + Duration::from_millis(LEASE_MS / 2);
    while Instant::now() < settled {
        let _ = SessionDrive::read(&*engine, false);
    }
    let before = engine.services();
    let quiet = Instant::now() + Duration::from_millis(4 * LEASE_MS);
    while Instant::now() < quiet {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert!(
        !SessionDrive::is_closed(&*engine),
        "CONTROL: the router's lease of the session ran out"
    );
    assert_eq!(
        engine.services() - before,
        0,
        "the bookkeeping ran at a keep-alive"
    );
}

/// A look that runs the bookkeeping for what the router declared, the link up and its replay told
/// whole, owes the link no turn of the replay, and holds no face's send place for one: a droppable
/// publish on another thread would find that place held and be dropped. CONTROL: the look ran the
/// bookkeeping. Turned red by a look that holds every face's send place for a replay turn that is
/// not due (`replays` in `CoopEngine::life_turn`).
#[cfg(not(wz_round))]
#[test]
fn a_look_with_no_replay_turn_due_holds_no_send_place_for_one() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    until(&engine, "the declarations to be told", || {
        engine.declarations_synced()
    });
    let holds = || engine.takes.replay_holds.load(Ordering::SeqCst);
    let (services, before) = (engine.services(), holds());
    router.send(Command::DeclareSubscriber(1, "demo/**"));
    until(
        &engine,
        "CONTROL: the bookkeeping of the declaration",
        || engine.services() > services,
    );
    assert_eq!(
        holds() - before,
        0,
        "a look held the send places for a replay turn not due"
    );
}

/// The records of one frame are read in one take of the link's input, each handed out as it is
/// read, and no pass of a task runs for them: the read steps the link itself. Turned red by a read
/// that stops the walk of a frame at each record and reads the rest of it again at a later take,
/// or that runs the session's tasks to read it.
#[cfg(not(wz_round))]
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
        .expect("the session declares the subscriber");
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

/// A callback that undeclares its own subscriber from inside the read's step tells the router the
/// retraction once: the session's record of the link holds the link's send place, which the step
/// does not hold. Turned red by a step that holds the send place (the retraction's hold finds it
/// held: a debug build fails, a release build owes it and sends no retraction), or by a retraction
/// told twice.
#[cfg(not(wz_round))]
#[test]
fn an_undeclaration_inside_the_reads_step_is_told_once() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let own: Arc<Mutex<Option<wz_capi_port::SubId>>> = Arc::default();
    let session = EngineHold::downgrade(&engine);
    let declares_before = router.seen(|s| s.declares);
    let id = engine
        .declare_subscriber_on_wire("demo/in", WireKey::literal(), Locality::Any, None, {
            let own = own.clone();
            SubscriberSink::shared(move |_: &dyn SampleView| {
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
    let declared = router
        .seen(|s| s.subscribers.last().copied())
        .expect("the router was told the subscriber's id");
    router.send(Command::PushBatch("demo/in", COUNT));
    until(&engine, "the retraction", || {
        router.seen(|s| !s.undeclared_subscribers.is_empty())
    });
    for _ in 0..10 {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert_eq!(
        router.seen(|s| s.undeclared_subscribers.clone()),
        [declared],
        "the retraction made inside the read's step was told once"
    );
}

/// A redeclare a callback asks for from inside the read's step tells the router the subscriber
/// again: the replay's lap holds the link's send place, which the step does not hold, and nothing
/// is left owed for a later read. Turned red by a lap handed no wire inside the step
/// (`CoopEngine::live_on_link`), which tells nothing, or by a redeclare that counts no face.
#[cfg(not(wz_round))]
#[test]
fn a_redeclare_inside_the_reads_step_is_told() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let session = EngineHold::downgrade(&engine);
    let handed = Arc::new(AtomicUsize::new(0));
    let told: Arc<Mutex<Option<Result<usize, wz_capi_port::RedeclareRefusal>>>> = Arc::default();
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire("demo/in", WireKey::literal(), Locality::Any, None, {
            let (handed, told) = (handed.clone(), told.clone());
            SubscriberSink::shared(move |_: &dyn SampleView| {
                let first = handed.fetch_add(1, Ordering::SeqCst) == 0;
                if let (true, Some(engine)) = (first, session.upgrade()) {
                    *told.lock().unwrap() = Some(SessionEngine::redeclare(&*engine));
                }
            })
        })
        .expect("the session declares the subscriber");
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    let declared = router.seen(|s| s.subscribers.clone());
    assert_eq!(declared.len(), 1, "CONTROL: the subscriber was told once");
    router.send(Command::PushBatch("demo/in", COUNT));
    until(&engine, "the subscriber told again", || {
        router.seen(|s| s.subscribers.len()) > declared.len()
    });
    assert_eq!(
        *told.lock().unwrap(),
        Some(Ok(1)),
        "the redeclare inside the step counted the one face"
    );
    assert_eq!(
        router.seen(|s| s.subscribers.last().copied()),
        declared.last().copied(),
        "the replay told the same subscriber again"
    );
}

/// An operation reaches each face that is up through the wire its hold of that face's place
/// holds, and none by a try: each face's record names its face by the flags its link's end shares
/// with the read. Turned red by a hold whose faces answer a wire for another mark than their own
/// (`KeptSend::wire_for`), a `FacesMark::wire_of` that compares anything but those flags, a
/// walk that holds no place (`CoopEngine::hold_faces`), or, where the dial role's face is the
/// only face, a hold that hands the operation no wire (`DialHeld::parts`). A build whose faces
/// share the session's lock as their one send place holds none (its twin is
/// `an_operation_holds_no_face_place_where_the_faces_share_the_sessions_lock`).
#[cfg(not(any(wz_round, wz_one_send_place)))]
#[test]
fn an_operation_reaches_each_face_through_the_wire_it_holds() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    assert_eq!(
        engine.faces_reached_by_an_operation(),
        (1, 0),
        "the one face that is up is the dial role's, reached through the held wire"
    );
}

/// Inside an operation, the place of every face that holds a link is held, so a send to any
/// face under the session's lock is made through a held wire and never finds a place another
/// holder has. Turned red by a walk that takes the session's lock before the faces' places, or
/// that skips a face whose place holds a link (`CoopEngine::hold_faces`), or by a hold of
/// the dial role's face alone that takes no place (`CoopEngine::hold_dial`) or keeps it past
/// the operation (`DialHeld`'s drop). A build whose faces share the session's lock as their one
/// send place holds none (its twin is
/// `an_operation_holds_no_face_place_where_the_faces_share_the_sessions_lock`).
#[cfg(not(any(wz_round, wz_one_send_place)))]
#[test]
fn an_operation_holds_the_place_of_every_face_with_a_link() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    assert_eq!(
        engine.places_held_by_an_operation(),
        (1, 0),
        "the dial role's place, which holds the link, is held by the operation"
    );
    assert!(
        engine.send_place_is_free(),
        "the operation let go of the place it held"
    );
}

/// Where the faces share the session's lock as their one send place (`wz_one_send_place`: a
/// build of one thread without `face-send-places`, as the zenoh-pico preset's peer), an operation
/// holds no face's place: the dial role's face, which holds the session's one link, is reached by
/// a try of its place, which is free inside the operation and after it. Twin of
/// `an_operation_reaches_each_face_through_the_wire_it_holds` and
/// `an_operation_holds_the_place_of_every_face_with_a_link`. Turned red by an operation of that
/// form that holds a face's place before the session's lock (`CoopEngine::live_on_link` taking
/// the dial role's or every face's), which a send then reaches through its held wire and a try
/// finds held, or by a `FaceTx::held_wire` of that form that answers a held wire.
#[cfg(wz_one_send_place)]
#[test]
fn an_operation_holds_no_face_place_where_the_faces_share_the_sessions_lock() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    assert_eq!(
        engine.faces_reached_by_an_operation(),
        (0, 1),
        "the one face that is up is reached by a try of its place, through no held wire"
    );
    assert_eq!(
        engine.places_held_by_an_operation(),
        (0, 1),
        "the dial role's place, which holds the link, is free inside the operation"
    );
    assert!(
        engine.send_place_is_free(),
        "and free after it, as no operation took it"
    );
}

/// An operation on a closed session runs nothing, and leaves the dial role's send place free:
/// the hold of the place taken before the session is found closed is let go of with it, and
/// where the faces share the session's lock as their one send place no place is taken. Turned
/// red by a hold that runs the operation on a closed session (`CoopEngine::hold_dial` without
/// `CoopEngine::live`), or that keeps the place it took.
#[cfg(not(wz_round))]
#[test]
fn an_operation_on_a_closed_session_runs_nothing_and_holds_nothing() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    assert!(
        engine.an_operation_runs(),
        "CONTROL: an open session runs it"
    );
    SessionDrive::close(&*engine);
    assert!(!engine.an_operation_runs(), "the closed session ran it");
    assert!(
        engine.send_place_is_free(),
        "the place taken before the session was found closed is let go of"
    );
}

/// A publish's walk of the faces hands one leg to each face whose place holds a link, each leg
/// reaching its own face alone: the session open on the dial role's face, and joined to no group,
/// is handed one leg, which reaches that face, in every build; where the faces share the
/// session's lock as their one send place, that one leg is every face's. Turned red by a walk that
/// skips the dial role's row (`DirectFaces::iter`), a leg that reaches no face
/// (`FaceTx::reaches`), or a groups' leg handed to a session that joined none
/// (`CoopEngine::on_groups_leg`).
#[cfg(not(wz_round))]
#[test]
fn a_publish_hands_each_face_a_leg_of_its_own() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    #[cfg(wz_face_places)]
    let tried = engine.takes.place_tries.load(Ordering::Relaxed);
    assert_eq!(
        engine.legs_of_a_publish(),
        (1, 1),
        "one leg, for the dial role's face, which reaches that face"
    );
    // The face that is up is not at rest, and its place is tried for its leg.
    #[cfg(wz_face_places)]
    assert_eq!(engine.takes.place_tries.load(Ordering::Relaxed), tried + 1);
}

/// A session that joined no group is handed no groups' leg by a publish, which would take the
/// session for nothing: its dial role's leg reaches its face and no group. The member that joined
/// one is handed one leg for it
/// (`one_thread::group::a_publish_of_a_member_of_one_thread_reaches_the_group_by_one_leg`).
/// Turned red by a groups' leg handed whatever the session joined (`CoopEngine::on_groups_leg`),
/// or a face's leg that reaches the groups (`FaceTx::reaches_groups`). Where the faces share the
/// session's lock as their one send place, a publish's one leg reaches the faces and the groups
/// alike, and there is no groups' leg to withhold.
#[cfg(all(feature = "group", wz_face_places))]
#[test]
fn a_session_that_joined_no_group_hands_the_groups_no_leg() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    assert_eq!(
        engine.group_legs_of_a_publish(),
        0,
        "no leg reaches a group, the session having joined none"
    );
}

/// A callback of a record the read's step hands out finds the link's send place free: the step
/// holds the link's receive part alone, so a send made there, or by another thread meanwhile,
/// waits for no step and no callback. Turned red by a step that holds the send place while it
/// hands records out (`CoopEngine::pump_turn` lending the place): the try finds it held.
#[cfg(not(wz_round))]
#[test]
fn a_callback_inside_the_reads_step_finds_the_send_place_free() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let session = EngineHold::downgrade(&engine);
    let found: Arc<Mutex<Vec<bool>>> = Arc::default();
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire("demo/in", WireKey::literal(), Locality::Any, None, {
            let found = found.clone();
            SubscriberSink::shared(move |_: &dyn SampleView| {
                if let Some(engine) = session.upgrade() {
                    found.lock().unwrap().push(engine.send_place_is_free());
                }
            })
        })
        .expect("the session declares the subscriber");
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    router.send(Command::PushBatch("demo/in", COUNT));
    until(&engine, "a sample handed out", || {
        !found.lock().unwrap().is_empty()
    });
    let found = found.lock().unwrap().clone();
    assert!(
        found.iter().all(|free| *free),
        "every callback found the send place free: {found:?}"
    );
}

/// A read turns every face of the session's table once, after one wait: the dial role's (unless
/// it rests beside another, `DirectFace::rests`), and each past it whose row holds a face, and no
/// row that holds none. A client that took no face turns its dial role's face alone, whatever rows
/// its table keeps for faces to come. Turned red by a read that turns a face twice, a row no face
/// holds, or no face at all, as a walk that reads the dial role's row by the marks of the rows
/// past it would (`CoopEngine::read_faces` over `DirectFaces::turned`, or
/// `CoopEngine::read_dial` where the dial role's face is the only face).
#[cfg(not(wz_round))]
#[test]
fn a_read_turns_every_face_once() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let (rows, faces) = engine.direct_faces();
    assert_eq!(
        faces, 1,
        "the dial role's face is the one face of the table"
    );
    assert!(
        rows >= faces,
        "CONTROL: the table keeps a row for each face it turns"
    );
    let before = engine.takes.face_turns.load(Ordering::SeqCst);
    let _ = SessionDrive::read(&*engine, false);
    assert_eq!(
        engine.takes.face_turns.load(Ordering::SeqCst) - before,
        faces,
        "one turn of each face"
    );
}

/// What a read waits for is the earliest due of the faces as their slots hold it: each turn of a
/// face shows its due outside its slot, so a read of several faces need not hold them to wait,
/// and the read of the one face, which holds its slot across the wait, reads the due there. The
/// session's link is up, so its pump is due at its keep-alive, never at no time. Turned red by a
/// turn that leaves a moved due unnoted (`DirectFace::note_due` in `CoopEngine::face_turn`), or a
/// wait that hands the session another due than the one it read (`CoopEngine::wait_due`,
/// `CoopEngine::link_wait`).
#[cfg(not(wz_round))]
#[test]
fn a_read_waits_for_the_due_its_faces_hold() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    for _ in 0..3 {
        let _ = SessionDrive::read(&*engine, false);
        let (waited, held) = engine.faces_due_waited_and_held();
        assert_eq!(waited, held, "the due waited for is the due the slots hold");
        assert_ne!(held, u64::MAX, "a link that is up is due at its keep-alive");
    }
}

/// A read hands out what its records left to hand out once, after every face it turned and every
/// group it stepped: a batch of Pushes enters the deliveries once for the read, not once for the
/// face's turn and again for the drain of the batch's run. Turned red by a drain of a run of
/// Pushes that delivers itself (`DirectSink::drain_pushes`), or a read that delivers after each
/// face it turns (`CoopEngine::read_faces`). The CONTROL is the subscriber's count of the batch.
#[cfg(not(wz_round))]
#[test]
fn a_read_enters_the_deliveries_once() {
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
        .expect("the session declares the subscriber");
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    until(&engine, "the declarations to be told", || {
        engine.declarations_synced()
    });
    let delivers = engine.takes.delivers.load(Ordering::SeqCst);
    router.send(Command::PushBatch("demo/in", COUNT));
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut reads = 0usize;
    while received.load(Ordering::SeqCst) < usize::from(COUNT) {
        assert!(Instant::now() < deadline, "the batch did not arrive");
        let _ = SessionDrive::read(&*engine, false);
        reads += 1;
    }
    assert_eq!(
        received.load(Ordering::SeqCst),
        usize::from(COUNT),
        "CONTROL: the batch reached the subscriber"
    );
    assert_eq!(
        engine.takes.delivers.load(Ordering::SeqCst) - delivers,
        reads,
        "one delivery a read"
    );
}

/// A read that finds a face's link holding input it already took from its stack waits for
/// nothing and takes nothing of the session for that wait: the session is taken once, for the
/// look at the face's life, where a read that waits takes it for the wait too. The CONTROL is the
/// count of the reads that found input held. Turned red by a wait that takes the session's lock
/// before it reads the faces' facts (`CoopEngine::link_wait`).
#[cfg(not(wz_round))]
#[test]
fn a_read_on_held_input_takes_nothing_of_the_session_for_its_wait() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    until(&engine, "the declarations to be told", || {
        engine.declarations_synced()
    });
    let takes = || engine.takes.core.load(Ordering::SeqCst);
    let before = takes();
    let _ = SessionDrive::read(&*engine, false);
    let waiting = takes() - before;
    engine.takes.input_held.store(true, Ordering::SeqCst);
    let (before, held_before) = (
        takes(),
        engine.takes.held_input_reads.load(Ordering::SeqCst),
    );
    let _ = SessionDrive::read(&*engine, false);
    let on_held = takes() - before;
    let held = engine.takes.held_input_reads.load(Ordering::SeqCst) - held_before;
    engine.takes.input_held.store(false, Ordering::SeqCst);
    assert_eq!(held, 1, "CONTROL: the read found the input held");
    assert_eq!(
        on_held + 1,
        waiting,
        "the read on held input took the session for its wait"
    );
}
