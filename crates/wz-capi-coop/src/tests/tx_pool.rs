// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session whose links share fewer outbound slots than they are (`TX_POOL_SLOTS`): a link whose
//! stream has not finished a frame holds a slot, and while every slot is so held a publish to
//! another link that may be dropped is dropped at once, and one that may not waits for a slot
//! with nothing of the session held, and is sent, not lost, once the slow stream takes the rest.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_port::{SessionDrive, SessionEngine, WireKey};
use wz_session_core::limits::SessionLimits;
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::qos::CongestionControl;
use wz_session_core::session_init_params::TxQueueConf;
use wz_session_core::sink::SampleView;
use wz_session_core::WhatAmI;

use super::{client_config, open_with, Engine};
use crate::CoopConfig;

/// What one droppable publish that fills the slow stream carries: many frames, so that a few of
/// them fill what the kernel holds for a peer that reads nothing, and one is taken in part.
const PAYLOAD: usize = 60 * 1024;
/// The most droppable publishes the slow stream is given to fill.
const FILL_AT_MOST: usize = 4_096;

fn publish(congestion: CongestionControl) -> PublishOptions {
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
fn stepped(config: CoopConfig) -> Arc<Engine> {
    let engine = open_with(config);
    SessionDrive::start_read_task(&*engine).expect("the read task starts");
    engine
}

/// A listener of one outbound slot holds two faces: a good peer, which came first, and a slow one
/// that stops reading. The slow peer's stream is filled until its link holds the slot for a frame
/// it has not finished. Then a droppable publish is dropped on the good face at once, and a
/// blocking one waits for the slot without holding the session (the session answers meanwhile),
/// and once the slow peer reads again it is sent: the good peer hears it, and never the dropped
/// one.
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
        zid: Some(vec![0xa1; 4]),
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        limits,
        tx_queue: TxQueueConf {
            wait_before_close_us: 30_000_000,
            ..client_config().tx_queue
        },
        ..client_config()
    });
    let endpoint = publisher.listening().pop().expect("one port is bound");

    let heard = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let good = stepped(CoopConfig {
        endpoints: vec![endpoint.clone()],
        zid: Some(vec![0xc1; 4]),
        ..client_config()
    });
    let into = heard.clone();
    good.declare_subscriber_on_wire(
        "demo/pool/**",
        WireKey::literal(),
        Locality::Any,
        None,
        Arc::new(move || {
            let into = into.clone();
            Box::new(move |sample: &dyn SampleView| {
                if sample.payload().len() < PAYLOAD {
                    into.lock().unwrap().push(sample.payload().to_vec());
                }
            })
        }),
    )
    .expect("the good peer declares its subscriber");
    eventually("the good peer's face", || publisher.faces_up() == 1);
    let slow = stepped(CoopConfig {
        endpoints: vec![endpoint],
        zid: Some(vec![0xc2; 4]),
        ..client_config()
    });
    eventually("the slow peer's face", || publisher.faces_up() == 2);
    SessionDrive::stop_read_task(&*slow).expect("the slow peer's read task stops");

    let payload = vec![0x5a; PAYLOAD];
    for _ in 0..FILL_AT_MOST {
        let _ = publisher.publish_on_wire_all(
            "demo/pool/fill",
            &WireKey::literal(),
            &payload,
            &publish(CongestionControl::Drop),
        );
        if publisher.links_owing() > 0 {
            break;
        }
    }
    assert!(
        publisher.links_owing() > 0,
        "the slow peer's link never held a frame its stream had not finished"
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

    let blocking = {
        let publisher = Arc::clone(&publisher);
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
