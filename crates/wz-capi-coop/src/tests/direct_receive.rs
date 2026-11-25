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
        .expect("the session declares the subscriber");
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
