// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session whose links share fewer outbound slots than they are (`TX_POOL_SLOTS`): a link whose
//! stream has not finished a frame holds a slot, and while every slot is so held a publish to
//! another link that may be dropped is dropped at once, and one that may not waits for a slot
//! with nothing of the session held, woken by the slow link's room and not by a clock, and is
//! sent, not lost, once the slow stream takes the rest.

#[cfg(feature = "threads")]
use crate::EngineHold;
#[cfg(feature = "threads")]
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(feature = "threads")]
use wz_capi_port::SessionDrive;
use wz_capi_port::{SessionEngine, SubscriberSink, WireKey};
use wz_session_core::limits::SessionLimits;
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::qos::CongestionControl;
use wz_session_core::session_init_params::TxQueueConf;
use wz_session_core::sink::SampleView;
use wz_session_core::WhatAmI;

#[cfg(not(feature = "threads"))]
use super::one_thread::OwnThread;
#[cfg(feature = "threads")]
use super::Engine;
use super::{client_config, config_zid, open_with};
use crate::CoopConfig;

/// What one droppable publish that fills the slow stream carries: many frames, so that a few of
/// them fill what the kernel holds for a peer that reads nothing, and one is taken in part.
const PAYLOAD: usize = 60 * 1024;
/// The most droppable publishes the slow stream is given to fill.
const FILL_AT_MOST: usize = 4_096;
/// How long the slow peer's link owes a frame, its stream taking nothing more, before the stream
/// is taken as full.
const STILL: Duration = Duration::from_millis(300);
/// How long a droppable publish waits for a stream that takes nothing: zenoh's default
/// `wait_before_drop`, where the pico profile's waits as long as a blocking one.
const DROP_WAIT_US: u64 = 1_000;

fn publish(congestion: CongestionControl) -> PublishOptions<'static> {
    PublishOptions::put()
        .with_locality(Locality::Remote)
        .with_congestion_control(congestion)
}

/// Wait, for at most ten seconds, until `done`.
fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// A session stepped by its read task.
#[cfg(feature = "threads")]
fn stepped(config: CoopConfig) -> EngineHold<Engine> {
    let engine = open_with(config);
    SessionDrive::start_read_task(&*engine).expect("the read task starts");
    engine
}

/// A listener of one outbound slot holds two faces: a good peer, which came first, and a slow one
/// that stops reading. The slow peer's stream is filled until its link holds the slot for a frame
/// it has not finished. Then a droppable publish is dropped on the good face at once (and on the
/// slow face within its own `wait_before_drop`, its stream taking nothing), and a
/// blocking one waits for the slot without holding the session (the session answers meanwhile),
/// and once the slow peer reads again it is sent: the good peer hears it, and never the dropped
/// one.
#[cfg(feature = "threads")]
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn a_blocking_publish_waits_for_a_slot_a_slow_link_holds_and_a_droppable_one_does_not() {
    let mut limits = SessionLimits::defaults();
    if limits.select_tx_pool_slots(1).is_err() {
        // A build that keeps the build's value alone has no pool of one slot to try.
        return;
    }
    let publisher = stepped(CoopConfig {
        whatami: WhatAmI::Peer,
        zid: config_zid(0xa1),
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        limits,
        // A droppable publish waits at most a millisecond for the slow peer's own stream, which
        // the pool has nothing to do with; a blocking one waits long past the test's steps.
        tx_queue: TxQueueConf {
            wait_before_drop_us: DROP_WAIT_US,
            wait_before_close_us: 30_000_000,
            ..client_config().tx_queue
        },
        ..client_config()
    });
    let endpoint = publisher.listening().pop().expect("one port is bound");

    let heard = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let good = stepped(CoopConfig {
        endpoints: vec![endpoint.clone()],
        zid: config_zid(0xc1),
        ..client_config()
    });
    let into = heard.clone();
    good.declare_subscriber_on_wire(
        "demo/pool/**",
        WireKey::literal(),
        Locality::Any,
        None,
        SubscriberSink::shared(move |sample: &dyn SampleView| {
            if sample.payload().len() < PAYLOAD {
                into.lock().unwrap().push(sample.payload().to_vec());
            }
        }),
    )
    .expect("the good peer declares its subscriber");
    eventually("the good peer's face", || publisher.faces_up() == 1);
    let slow = stepped(CoopConfig {
        endpoints: vec![endpoint],
        zid: config_zid(0xc2),
        ..client_config()
    });
    eventually("the slow peer's face", || publisher.faces_up() == 2);
    SessionDrive::stop_read_task(&*slow).expect("the slow peer's read task stops");

    // The slow stream is full once its link has owed a frame for a while with nothing more of it
    // taken: the kernel may take a little more of a stream that has just begun to back up (its
    // buffers grow as it fills), which writes the rest and gives the slot back. So the stream is
    // filled until the link has owed for `STILL` without a break.
    //
    // A stream can also fill with nothing of it owed: the publisher's read task writes the rest
    // of the frame owed, and what room that leaves is under what the stack reports as writable,
    // so every droppable publish after it is refused before a byte of it is written, and the
    // stream stays so for as long as its peer reads nothing. Each round that leaves nothing owed
    // therefore has the slow peer read one message, which gives its stream room again, and
    // hands the stream two publishes, so a stream that took them fills by at least one a round
    // and one that took neither is moved on by the read.
    let payload = vec![0x5a; PAYLOAD];
    let mut owing_since: Option<Instant> = None;
    for _ in 0..FILL_AT_MOST {
        for _ in 0..2 {
            let _ = publisher.publish_on_wire_all(
                "demo/pool/fill",
                &WireKey::literal(),
                &payload,
                &publish(CongestionControl::Drop),
            );
        }
        if publisher.links_owing() == 0 {
            owing_since = None;
            SessionDrive::read(&*slow, true).expect("the slow peer's session is open");
            continue;
        }
        let since = *owing_since.get_or_insert_with(Instant::now);
        if since.elapsed() >= STILL {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // What the publisher holds when the stream never held a frame tells a lost slow face from a
    // stream that kept taking what it was given.
    assert!(
        owing_since.is_some_and(|since| since.elapsed() >= STILL),
        "the slow peer's link never held a frame its stream had not finished for {STILL:?}: \
         {} faces up, {} links owing",
        publisher.faces_up(),
        publisher.links_owing()
    );

    let started = Instant::now();
    let _ = publisher.publish_on_wire_all(
        "demo/pool/dropped",
        &WireKey::literal(),
        b"dropped",
        &publish(CongestionControl::Drop),
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "a droppable publish waited {:?} for a slot",
        started.elapsed()
    );

    let takes_before = publisher.takes.core.load(Ordering::Relaxed);
    let blocking = {
        let publisher = publisher.clone();
        std::thread::spawn(move || {
            publisher.publish_on_wire_all(
                "demo/pool/kept",
                &WireKey::literal(),
                b"kept",
                &publish(CongestionControl::Block),
            )
        })
    };
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !blocking.is_finished(),
        "the blocking publish waits for a slot"
    );
    // It waits on the slow link's room, not on a clock: in 300 ms it takes the session once, to
    // find no slot, and the read task a handful of times; a publish that looked every few
    // milliseconds would take it scores of times.
    let takes = publisher.takes.core.load(Ordering::Relaxed) - takes_before;
    assert!(
        takes <= 15,
        "the session was taken {takes} times while the publish waited"
    );
    let asked = Instant::now();
    assert_eq!(
        publisher.faces_up(),
        2,
        "the session answers while it waits"
    );
    assert!(
        asked.elapsed() < Duration::from_secs(1),
        "the waiting publish held the session for {:?}",
        asked.elapsed()
    );

    SessionDrive::start_read_task(&*slow).expect("the slow peer reads again");
    assert_eq!(
        blocking.join().expect("the blocking publisher"),
        Ok(0),
        "the blocking publish is sent"
    );
    eventually("the good peer to hear the blocking publish", || {
        heard
            .lock()
            .unwrap()
            .iter()
            .any(|payload| payload == b"kept")
    });
    assert!(
        !heard
            .lock()
            .unwrap()
            .iter()
            .any(|payload| payload == b"dropped"),
        "the droppable publish was dropped on the good face"
    );
    SessionDrive::close(&*slow);
    SessionDrive::close(&*good);
    SessionDrive::close(&*publisher);
}

/// The same pool in the form of one thread, each session opened, called and read on a thread of its
/// own ([`OwnThread`]): the slow peer's thread is held in a call, so its session reads nothing,
/// and its stream is filled until its link holds the one slot for a frame it has not finished.
/// Then a droppable publish is dropped at once; once the slow peer reads again and the
/// publisher's reads finish the frame, a blocking publish is sent, and the good peer hears it and
/// never the dropped one.
#[cfg(not(feature = "threads"))]
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn a_droppable_publish_of_one_thread_is_dropped_while_a_slow_link_holds_the_slot() {
    let mut limits = SessionLimits::defaults();
    if limits.select_tx_pool_slots(1).is_err() {
        // A build that keeps the build's value alone has no pool of one slot to try.
        return;
    }
    let publisher = OwnThread::open(move || {
        open_with(CoopConfig {
            whatami: WhatAmI::Peer,
            zid: config_zid(0xa1),
            listen: vec!["tcp/127.0.0.1:0".to_owned()],
            limits,
            tx_queue: TxQueueConf {
                wait_before_drop_us: DROP_WAIT_US,
                wait_before_close_us: 30_000_000,
                ..client_config().tx_queue
            },
            ..client_config()
        })
    });
    let endpoint = publisher.call(|engine| engine.listening().pop().expect("one port is bound"));
    let peer = |id: u8| {
        let endpoint = endpoint.clone();
        OwnThread::open(move || {
            open_with(CoopConfig {
                endpoints: vec![endpoint],
                zid: config_zid(id),
                ..client_config()
            })
        })
    };

    let heard = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let good = peer(0xc1);
    let into = heard.clone();
    good.call(move |engine| {
        engine
            .declare_subscriber_on_wire(
                "demo/pool/**",
                WireKey::literal(),
                Locality::Any,
                None,
                SubscriberSink::shared(move |sample: &dyn SampleView| {
                    if sample.payload().len() < PAYLOAD {
                        into.lock().unwrap().push(sample.payload().to_vec());
                    }
                }),
            )
            .expect("the good peer declares its subscriber");
    });
    let faces_up = || publisher.call(|engine| engine.faces_up());
    eventually("the good peer's face", || faces_up() == 1);
    let slow = peer(0xc2);
    eventually("the slow peer's face", || faces_up() == 2);
    let (resume, held) = std::sync::mpsc::channel::<()>();
    let paused = slow.hand(move |_| {
        let _ = held.recv();
    });

    // Filled as the twin of `threads` fills it, on the publisher's own thread.
    let filled = publisher.call(|engine| {
        let payload = vec![0x5a; PAYLOAD];
        let mut owing_since: Option<Instant> = None;
        for _ in 0..FILL_AT_MOST {
            let _ = engine.publish_on_wire_all(
                "demo/pool/fill",
                &WireKey::literal(),
                &payload,
                &publish(CongestionControl::Drop),
            );
            if engine.links_owing() == 0 {
                owing_since = None;
                continue;
            }
            let since = *owing_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= STILL {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        owing_since.is_some_and(|since| since.elapsed() >= STILL)
    });
    assert!(
        filled,
        "the slow peer's link never held a frame its stream had not finished for {STILL:?}"
    );

    let dropped_in = publisher.call(|engine| {
        let started = Instant::now();
        let _ = engine.publish_on_wire_all(
            "demo/pool/dropped",
            &WireKey::literal(),
            b"dropped",
            &publish(CongestionControl::Drop),
        );
        started.elapsed()
    });
    assert!(
        dropped_in < Duration::from_secs(1),
        "a droppable publish waited {dropped_in:?} for a slot"
    );

    resume
        .send(())
        .expect("the slow peer's thread waits to read again");
    paused.recv().expect("the slow peer's thread reads again");
    eventually("the slow link to finish its frame", || {
        publisher.call(|engine| engine.links_owing()) == 0
    });
    let sent = publisher.call(|engine| {
        engine.publish_on_wire_all(
            "demo/pool/kept",
            &WireKey::literal(),
            b"kept",
            &publish(CongestionControl::Block),
        )
    });
    assert_eq!(sent, Ok(0), "the blocking publish is sent");
    eventually("the good peer to hear the blocking publish", || {
        heard
            .lock()
            .unwrap()
            .iter()
            .any(|payload| payload == b"kept")
    });
    assert!(
        !heard
            .lock()
            .unwrap()
            .iter()
            .any(|payload| payload == b"dropped"),
        "the droppable publish was dropped on the good face"
    );
}
