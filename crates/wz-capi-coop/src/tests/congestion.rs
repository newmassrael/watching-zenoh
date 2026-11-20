// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Congestion control at the engine: a publish that may be dropped is not held behind one that
//! may not. A blocking publish holds the session while it waits for room on its link, up to
//! `wait_before_close`; a droppable one beside it asks the links for room itself, with nothing of
//! the session held, and is dropped within its own `wait_before_drop`, as zenoh bounds the two
//! (`commons/zenoh-config/src/defaults.rs` @ `wait_before_drop: 1000,` and
//! `commons/zenoh-config/src/defaults.rs` @ `wait_before_close: 5000000,`).

use std::sync::{Arc, Mutex};

use wz_runtime_coop::session_drive::LinkWritability;

use crate::engine::{LinkRooms, Room};

/// A link's wait for room that answers what the test set, and keeps how long each ask was for.
struct Answer {
    room: bool,
    asked: Mutex<Vec<u64>>,
}

impl LinkWritability for Answer {
    fn wait_writable(&self, timeout_us: u64) -> bool {
        self.asked.lock().unwrap().push(timeout_us);
        self.room
    }
}

fn answer(room: bool) -> Arc<Answer> {
    Arc::new(Answer {
        room,
        asked: Mutex::new(Vec::new()),
    })
}

fn held(rooms: &LinkRooms, wait: &Arc<Answer>) {
    let wait: Arc<dyn LinkWritability> = wait.clone();
    rooms.hold(&wait);
}

/// A session none of whose links gives a wait cannot be asked: the publish waits for the session.
#[test]
fn a_session_whose_links_give_no_wait_is_not_asked() {
    assert_eq!(LinkRooms::default().within(1_000), Room::Unasked);
}

/// Each link that is up is asked, for the wait it is handed, and one that takes no bytes within it
/// is the congestion; with room on every link, whoever holds the session is not waiting on one.
#[test]
fn each_link_is_asked_and_one_without_room_is_congestion() {
    let rooms = LinkRooms::default();
    let free = answer(true);
    held(&rooms, &free);
    assert_eq!(
        rooms.within(1_234),
        Room::Free,
        "CONTROL: one link with room"
    );
    assert_eq!(*free.asked.lock().unwrap(), [1_234]);

    let full = answer(false);
    held(&rooms, &full);
    assert_eq!(rooms.within(1_234), Room::Congested);
    assert_eq!(
        *full.asked.lock().unwrap(),
        [1_234],
        "the full link was asked"
    );
}

/// A link that has gone is not asked: its wait goes with its wire, and what is left is a session
/// with no wait to ask.
#[test]
fn a_link_that_has_gone_is_not_asked() {
    let rooms = LinkRooms::default();
    let full = answer(false);
    held(&rooms, &full);
    assert_eq!(
        rooms.within(1_000),
        Room::Congested,
        "CONTROL: while it is up"
    );
    drop(full);
    assert_eq!(rooms.within(1_000), Room::Unasked);
}

/// The engine over a link whose peer took the connection, brought the session up and then read
/// nothing more: what the session sends fills the stream, and a blocking publish waits on it.
#[cfg(feature = "listen")]
mod stalled_link {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use wz_capi_port::{SessionDrive, SessionEngine, WireKey};
    use wz_session_core::locality::Locality;
    use wz_session_core::publish_options::PublishOptions;
    use wz_session_core::qos::CongestionControl;
    use wz_session_core::session_init_params::TxQueueConf;
    use wz_session_core::WhatAmI;

    use super::super::{client_config, open_with, until};
    use crate::CoopConfig;

    /// How long a blocking publish waits for room before the session is closed.
    const CLOSE_WAIT: Duration = Duration::from_secs(2);
    /// zenoh's default `wait_before_drop`.
    const DROP_WAIT_US: u64 = 1_000;
    /// What one blocking publish carries: many batches, so that a few publishes fill what the
    /// kernel holds for a peer that reads nothing.
    const PAYLOAD: usize = 64 * 1024;
    /// A blocking publisher whose count has not moved for this long is waiting for room.
    const QUIET: Duration = Duration::from_millis(300);
    /// The most blocking publishes the link is given to fill.
    const FILL_AT_MOST: usize = 4_096;

    fn publish(congestion: CongestionControl) -> PublishOptions {
        PublishOptions::put()
            .with_locality(Locality::Remote)
            .with_congestion_control(congestion)
    }

    /// While a blocking publish holds the session waiting for room on the full link, a droppable
    /// one returns within a second with success and does not close the session; the blocking one
    /// waits out its `wait_before_close`, and the session is closed after it.
    #[test]
    fn a_droppable_publish_is_not_held_behind_a_blocking_one_on_a_full_link() {
        let peer = open_with(CoopConfig {
            whatami: WhatAmI::Peer,
            zid: Some(vec![0xa7; 4]),
            listen: vec!["tcp/127.0.0.1:0".to_owned()],
            ..client_config()
        });
        let endpoint = peer.listening().pop().expect("one port is bound");
        SessionDrive::start_read_task(&*peer).expect("the peer's read task starts");
        let publisher = open_with(CoopConfig {
            endpoints: vec![endpoint],
            zid: Some(vec![0xb7; 4]),
            // Each message is written as it is sent, so what fills the stream is what was
            // published, whether or not the session is stepped.
            tx_queue: TxQueueConf {
                wait_before_drop_us: DROP_WAIT_US,
                wait_before_close_us: CLOSE_WAIT.as_micros() as u64,
                no_progress_us: None,
                expiry_keeps_session: false,
                batching: false,
                ..client_config().tx_queue
            },
            ..client_config()
        });
        let started = Instant::now();
        while peer.faces_up() == 0 {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the peer never held the publisher's face"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        // From here the peer reads nothing: its connection is held, and fills.
        SessionDrive::stop_read_task(&*peer).expect("the peer's read task stops");

        let progress = Arc::new(AtomicUsize::new(0));
        let blocking = {
            let publisher = Arc::clone(&publisher);
            let progress = Arc::clone(&progress);
            std::thread::spawn(move || {
                let payload = vec![0x5a; PAYLOAD];
                for _ in 0..FILL_AT_MOST {
                    let started = Instant::now();
                    let _ = publisher.publish_on_wire_all(
                        "demo/stall",
                        &WireKey::literal(),
                        &payload,
                        &publish(CongestionControl::Block),
                    );
                    let took = started.elapsed();
                    if took >= CLOSE_WAIT / 2 {
                        return Some(took);
                    }
                    progress.fetch_add(1, Ordering::SeqCst);
                }
                None
            })
        };
        // The blocking publisher has stopped moving: it holds the session, waiting for room.
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut seen = (progress.load(Ordering::SeqCst), Instant::now());
        loop {
            assert!(
                !blocking.is_finished(),
                "the blocking publisher ended before the link filled"
            );
            assert!(Instant::now() < deadline, "the link never filled");
            std::thread::sleep(Duration::from_millis(5));
            let now = progress.load(Ordering::SeqCst);
            if now != seen.0 {
                seen = (now, Instant::now());
            } else if seen.1.elapsed() >= QUIET {
                break;
            }
        }

        let started = Instant::now();
        let dropped = publisher.publish_on_wire_all(
            "demo/stall",
            &WireKey::literal(),
            b"dropped",
            &publish(CongestionControl::Drop),
        );
        let took = started.elapsed();
        assert_eq!(dropped, Ok(0), "a dropped put succeeds, as zenoh's does");
        assert!(
            took < Duration::from_secs(1),
            "a droppable publish waited {took:?} behind a blocking one"
        );
        assert!(
            !blocking.is_finished(),
            "the droppable publish returned only once the blocking one had let go"
        );
        assert!(
            !SessionDrive::is_closed(&*publisher),
            "a dropped publish does not close the session"
        );

        let waited = blocking
            .join()
            .expect("the blocking publisher")
            .expect("a blocking publish waited for room");
        assert!(
            waited >= CLOSE_WAIT,
            "a blocking publish returned after {waited:?}, before its {CLOSE_WAIT:?}"
        );
        until(
            &publisher,
            "the session to close after the blocking publish's wait",
            || SessionDrive::is_closed(&*publisher),
        );
        SessionDrive::close(&*peer);
    }
}
