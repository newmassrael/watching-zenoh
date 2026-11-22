// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Congestion control at the engine: a publish that may be dropped is not held behind one that
//! may not. A blocking publish holds the session while it waits for room on its link, up to
//! `wait_before_close`; a droppable one beside it asks the links for room itself, with nothing of
//! the session held, and is dropped within its own `wait_before_drop`, as zenoh bounds the two
//! (`commons/zenoh-config/src/defaults.rs` @ `wait_before_drop: 1000,` and
//! `commons/zenoh-config/src/defaults.rs` @ `wait_before_close: 5000000,`). It is dropped on the
//! faces the holder waits on and on no other, as each of zenoh's transports drops on its own
//! queue: the session's other faces are still sent it.

use std::sync::{Arc, Mutex};

use wz_runtime_coop::session_drive::LinkWritability;

use crate::engine::{Holder, LinkRooms, Room};

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

fn held(rooms: &LinkRooms, face: u64, wait: &Arc<Answer>) {
    let wait: Arc<dyn LinkWritability> = wait.clone();
    rooms.hold(face, &wait);
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
    held(&rooms, 1, &free);
    assert_eq!(
        rooms.within(1_234),
        Room::Free,
        "CONTROL: one link with room"
    );
    assert_eq!(*free.asked.lock().unwrap(), [1_234]);

    let full = answer(false);
    held(&rooms, 2, &full);
    assert_eq!(rooms.within(1_234), Room::Congested(vec![2]));
    assert_eq!(
        *full.asked.lock().unwrap(),
        [1_234],
        "the full link was asked"
    );
}

/// The congestion is the faces without room and no other: a face with room beside a full one is
/// not dropped on. The first face without room spends the wait, and the faces asked after it are
/// asked without one, so the publish spends one deadline however many faces the session has.
#[test]
fn only_the_faces_without_room_are_the_congestion() {
    let rooms = LinkRooms::default();
    let full = answer(false);
    let free = answer(true);
    let also_full = answer(false);
    held(&rooms, 1, &full);
    held(&rooms, 2, &free);
    held(&rooms, 3, &also_full);
    assert_eq!(rooms.within(1_000), Room::Congested(vec![1, 3]));
    assert_eq!(
        *full.asked.lock().unwrap(),
        [1_000],
        "the first spends the wait"
    );
    assert_eq!(
        *free.asked.lock().unwrap(),
        [0],
        "a face asked after the wait was spent is asked without one"
    );
    assert_eq!(*also_full.asked.lock().unwrap(), [0]);
}

/// Under the pico profile a publish that finds the session held by another publish sending on a
/// face is a congestion drop at once on that face, as pico's try-lock drops the message behind a
/// transmit lock another send holds: no link is asked for room, though one has room to give, and
/// the drop names the face the holder sends on and no other. A session held by a publish between
/// its sends is tried again, and one held by what is not a publish (a read step, a timer) is waited
/// for, blocked, with nothing asked either. Under zenoh's profile the same publish asks the link.
#[test]
fn under_the_pico_profile_a_held_session_drops_without_asking() {
    use wz_session_core::session_init_params::HeldDrop;
    let rooms = LinkRooms::default();
    let free = answer(true);
    held(&rooms, 1, &free);
    assert_eq!(
        rooms.for_held(HeldDrop::DropAtOnce, Holder::Sending(7), 1_000),
        Room::Held(7)
    );
    assert_eq!(
        rooms.for_held(HeldDrop::DropAtOnce, Holder::Publish, 1_000),
        Room::Free,
        "a publish between its sends is tried again"
    );
    assert_eq!(
        rooms.for_held(HeldDrop::DropAtOnce, Holder::Step, 1_000),
        Room::Stepping,
        "a holder that is not a publish is waited for"
    );
    assert!(
        free.asked.lock().unwrap().is_empty(),
        "the link was asked for room"
    );
    assert_eq!(
        rooms.for_held(HeldDrop::WaitForRoom, Holder::Step, 1_000),
        Room::Free,
        "CONTROL: zenoh's profile asks the link"
    );
    assert_eq!(*free.asked.lock().unwrap(), [1_000]);
}

/// A link that has gone is not asked: its wait goes with its wire, and what is left is a session
/// with no wait to ask.
#[test]
fn a_link_that_has_gone_is_not_asked() {
    let rooms = LinkRooms::default();
    let full = answer(false);
    held(&rooms, 1, &full);
    assert_eq!(
        rooms.within(1_000),
        Room::Congested(vec![1]),
        "CONTROL: while it is up"
    );
    drop(full);
    assert_eq!(rooms.within(1_000), Room::Unasked);
}

/// The session's counters are its links': puts it sent on the link it holds are counted there and
/// reported through the engine, and a session that dropped nothing reports no drop.
#[cfg(feature = "transport-stats")]
#[test]
fn the_sessions_counters_are_its_links_counters() {
    use wz_capi_port::{SessionEngine, WireKey};
    use wz_session_core::locality::Locality;
    use wz_session_core::publish_options::PublishOptions;

    let router = super::Router::start(super::CatchAll::None);
    let engine = super::open(&router);
    let before = engine.transport_stats();
    for _ in 0..3 {
        engine
            .publish_on_wire_all(
                "demo/stats",
                &WireKey::literal(),
                b"v",
                &PublishOptions::put().with_locality(Locality::Remote),
            )
            .expect("a put the link carries");
    }
    let after = engine.transport_stats();
    assert!(
        after.tx.n_msgs_total() >= before.tx.n_msgs_total() + 3,
        "three puts were counted on the link: {} before, {} after",
        before.tx.n_msgs_total(),
        after.tx.n_msgs_total()
    );
    assert_eq!(after.tx.n_dropped, 0, "nothing was dropped");
}

/// The engine over a link whose peer took the connection, brought the session up and then read
/// nothing more: what the session sends fills the stream, and a blocking publish waits on it.
#[cfg(feature = "listen")]
mod stalled_link {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use wz_capi_port::{FanoutError, SessionDrive, SessionEngine, WireKey};
    use wz_session_core::locality::Locality;
    use wz_session_core::policy::SessionPolicy;
    use wz_session_core::publish_options::PublishOptions;
    use wz_session_core::qos::CongestionControl;
    use wz_session_core::session_init_params::{HeldDrop, TxQueueConf, WAIT_BEFORE_CLOSE_US};
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

    /// What a droppable publish did while a blocking one held the session, waiting for room on
    /// the full link.
    struct Behind {
        /// The droppable publish's answer, and how long it took to give it.
        dropped: Result<usize, FanoutError>,
        took: Duration,
        /// Whether the blocking publish was still waiting when the droppable one returned.
        blocking_still_waiting: bool,
        /// Whether the session was closed when the droppable one returned.
        closed_by_the_drop: bool,
        /// How long the blocking publish took before it returned.
        waited: Duration,
        /// The transport's drops the closed session reports: its links' counters left with
        /// them, so these are the publishes the engine dropped before they reached a link.
        #[cfg(feature = "transport-stats")]
        unsent_drops: usize,
    }

    /// `tx_queue` with each message written as it is sent, so what fills the stream is what was
    /// published whether or not the session is stepped, and a blocking publish that finds no
    /// room within `CLOSE_WAIT` closing the session.
    fn stalling(tx_queue: TxQueueConf) -> TxQueueConf {
        TxQueueConf {
            wait_before_close_us: CLOSE_WAIT.as_micros() as u64,
            no_progress_us: None,
            expiry_keeps_session: false,
            batching: false,
            ..tx_queue
        }
    }

    /// Publish blocking samples from a thread of their own until one holds `publisher`'s session
    /// waiting for room on a full link, and return once it does: the thread ends with how long the
    /// publish that waited took.
    fn hold_with_a_blocking_publish(
        publisher: &Arc<super::super::Engine>,
    ) -> std::thread::JoinHandle<Option<Duration>> {
        let progress = Arc::new(AtomicUsize::new(0));
        let blocking = {
            let publisher = Arc::clone(publisher);
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
                return blocking;
            }
        }
    }

    /// Fill the link of a publisher whose queue is `tx_queue` with blocking publishes until one
    /// holds the session waiting for room, publish one droppable sample beside it, then wait for
    /// the blocking one to end and for the session to close after it.
    fn behind_a_blocking_publish(tx_queue: TxQueueConf) -> Behind {
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
            tx_queue,
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

        let blocking = hold_with_a_blocking_publish(&publisher);

        let started = Instant::now();
        let dropped = publisher.publish_on_wire_all(
            "demo/stall",
            &WireKey::literal(),
            b"dropped",
            &publish(CongestionControl::Drop),
        );
        let took = started.elapsed();
        let blocking_still_waiting = !blocking.is_finished();
        let closed_by_the_drop = SessionDrive::is_closed(&*publisher);

        let waited = blocking
            .join()
            .expect("the blocking publisher")
            .expect("a blocking publish waited for room");
        until(
            &publisher,
            "the session to close after the blocking publish's wait",
            || SessionDrive::is_closed(&*publisher),
        );
        SessionDrive::close(&*peer);
        Behind {
            dropped,
            took,
            blocking_still_waiting,
            closed_by_the_drop,
            waited,
            #[cfg(feature = "transport-stats")]
            unsent_drops: publisher.transport_stats().tx.n_dropped,
        }
    }

    /// Under zenoh's profile, while a blocking publish holds the session waiting for room on the
    /// full link, a droppable one asks the link for room out of its own `wait_before_drop`, finds
    /// none, and returns within a second with success, closing nothing; the blocking one waits
    /// out its `wait_before_close`, and the session is closed after it.
    #[test]
    fn a_droppable_publish_is_not_held_behind_a_blocking_one_on_a_full_link() {
        let seen = behind_a_blocking_publish(stalling(TxQueueConf {
            wait_before_drop_us: DROP_WAIT_US,
            held_drop: HeldDrop::WaitForRoom,
            ..client_config().tx_queue
        }));
        assert_eq!(
            seen.dropped,
            Ok(0),
            "a dropped put succeeds, as zenoh's does"
        );
        assert!(
            seen.took < Duration::from_secs(1),
            "a droppable publish waited {:?} behind a blocking one",
            seen.took
        );
        assert!(
            seen.blocking_still_waiting,
            "the droppable publish returned only once the blocking one had let go"
        );
        assert!(
            !seen.closed_by_the_drop,
            "a dropped publish does not close the session"
        );
        assert!(
            seen.waited >= CLOSE_WAIT,
            "a blocking publish returned after {:?}, before its {CLOSE_WAIT:?}",
            seen.waited
        );
        #[cfg(feature = "transport-stats")]
        assert_eq!(
            seen.unsent_drops, 1,
            "the dropped publish is counted as the transport's drop"
        );
    }

    /// Under the pico profile, read when the session was opened, a droppable publish that finds
    /// the session held is dropped at once and its caller is told, as pico's put fails when its
    /// held transmit lock drops the message. It asks the link nothing: the profile's own
    /// `wait_before_drop` is `wait_before_close`'s five seconds, which an ask on the full link
    /// would spend before it answered.
    #[test]
    fn under_the_pico_profile_a_publish_behind_a_held_session_is_dropped_at_once_and_told() {
        let pico = TxQueueConf::pico_of_snapshot(
            &SessionPolicy::defaults(),
            &wz_session_core::limits::SessionLimits::BUILD,
        );
        assert_eq!(
            pico.held_drop,
            HeldDrop::DropAtOnce,
            "CONTROL: pico's profile"
        );
        assert_eq!(
            pico.wait_before_drop_us, WAIT_BEFORE_CLOSE_US,
            "CONTROL: an ask would wait this long"
        );
        let seen = behind_a_blocking_publish(stalling(pico));
        assert_eq!(seen.dropped, Err(FanoutError::HeldConduit));
        assert!(
            seen.took < Duration::from_secs(1),
            "the droppable publish took {:?}: it asked the full link for room",
            seen.took
        );
        assert!(
            seen.blocking_still_waiting,
            "the droppable publish returned only once the blocking one had let go"
        );
        assert!(
            !seen.closed_by_the_drop,
            "a dropped publish does not close the session"
        );
        assert!(
            seen.waited >= CLOSE_WAIT,
            "a blocking publish returned after {:?}, before its {CLOSE_WAIT:?}",
            seen.waited
        );
        #[cfg(feature = "transport-stats")]
        assert_eq!(
            seen.unsent_drops, 1,
            "the dropped publish is counted as the transport's drop"
        );
    }

    /// What a droppable publish did while a blocking one held the session, waiting for room on the
    /// full link of the first of its two faces, and what the peer of the other face heard of it.
    struct Beside {
        /// The droppable publish's answer, and how long it took to give it.
        dropped: Result<usize, FanoutError>,
        took: Duration,
        /// Whether the blocking publish was still waiting when the droppable one returned.
        blocking_still_waiting: bool,
        /// How many times the peer whose face's link has room heard the droppable publish, once
        /// the blocking one ended.
        heard_beside: usize,
    }

    /// A publisher whose queue is `tx_queue` listens, and two clients dial it: the first reads
    /// nothing once it is up, so its link fills, and the second reads and subscribes to what the
    /// droppable sample is put on. Blocking publishes fill the first link until one holds the
    /// session waiting for room on it, the droppable sample is published beside it, and the
    /// second client is listened to until the blocking publish has ended.
    fn beside_a_blocking_publish(tx_queue: TxQueueConf) -> Beside {
        use wz_session_core::sink::SampleView;

        let publisher = open_with(CoopConfig {
            whatami: WhatAmI::Peer,
            zid: Some(vec![0xb8; 4]),
            listen: vec!["tcp/127.0.0.1:0".to_owned()],
            tx_queue: stalling(tx_queue),
            ..client_config()
        });
        let endpoint = publisher.listening().pop().expect("one port is bound");
        SessionDrive::start_read_task(&*publisher).expect("the publisher's read task starts");
        // Dialled first, so its face comes before the reading client's, and is never stepped once
        // it is open: what is sent to it fills its connection.
        let stalled = open_with(CoopConfig {
            endpoints: vec![endpoint.clone()],
            zid: Some(vec![0xa8; 4]),
            ..client_config()
        });
        let reading = open_with(CoopConfig {
            endpoints: vec![endpoint],
            zid: Some(vec![0xc8; 4]),
            ..client_config()
        });
        let heard = Arc::new(AtomicUsize::new(0));
        let into = Arc::clone(&heard);
        reading.declare_subscriber_on_wire(
            "demo/beside".to_owned(),
            WireKey::literal(),
            Locality::Any,
            None,
            Arc::new(move || {
                let into = Arc::clone(&into);
                Box::new(move |sample: &dyn SampleView| {
                    if sample.payload() == b"beside" {
                        into.fetch_add(1, Ordering::SeqCst);
                    }
                })
            }),
        );
        SessionDrive::start_read_task(&*reading).expect("the reading client's read task starts");
        let started = Instant::now();
        while publisher.faces_up() < 2 {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the publisher never held both clients' faces"
            );
            std::thread::sleep(Duration::from_millis(2));
        }

        let blocking = hold_with_a_blocking_publish(&publisher);
        let started = Instant::now();
        let dropped = publisher.publish_on_wire_all(
            "demo/beside",
            &WireKey::literal(),
            b"beside",
            &publish(CongestionControl::Drop),
        );
        let took = started.elapsed();
        let blocking_still_waiting = !blocking.is_finished();
        blocking
            .join()
            .expect("the blocking publisher")
            .expect("a blocking publish waited for room");
        // Once the blocking publish lets go of the session, what it was handed leaves on the
        // reading client's face; a second is never sent, and is not waited for past this.
        let deadline = Instant::now() + Duration::from_secs(5);
        while heard.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(QUIET);
        let heard_beside = heard.load(Ordering::SeqCst);
        SessionDrive::close(&*reading);
        SessionDrive::close(&*stalled);
        SessionDrive::close(&*publisher);
        Beside {
            dropped,
            took,
            blocking_still_waiting,
            heard_beside,
        }
    }

    /// Under zenoh's profile a droppable publish beside a blocking one that holds the session,
    /// waiting for room on one face's full link, is dropped on that face alone, as each of zenoh's
    /// transports drops on its own queue: the other face, whose link has room, is still sent it,
    /// once, after the blocking publish. The publish itself returns within a second, with
    /// success, while the blocking one still waits.
    #[test]
    fn a_droppable_publish_is_dropped_on_the_full_face_alone() {
        let seen = beside_a_blocking_publish(TxQueueConf {
            wait_before_drop_us: DROP_WAIT_US,
            held_drop: HeldDrop::WaitForRoom,
            ..client_config().tx_queue
        });
        assert_eq!(
            seen.dropped,
            Ok(0),
            "a dropped put succeeds, as zenoh's does"
        );
        assert!(
            seen.took < Duration::from_secs(1),
            "a droppable publish waited {:?} behind a blocking one",
            seen.took
        );
        assert!(
            seen.blocking_still_waiting,
            "CONTROL: the droppable publish returned while the blocking one held the session"
        );
        assert_eq!(
            seen.heard_beside, 1,
            "the face whose link has room is sent the droppable publish, once"
        );
    }

    /// Under the pico profile a droppable publish beside a blocking one that is sending on one
    /// face is dropped at once on that face, and its caller is told, as pico's put fails when its
    /// held transmit lock drops the message; the session's other face is still sent it, once,
    /// after the blocking publish, as the tokio engine sends a put the other faces of a held one.
    #[test]
    fn under_the_pico_profile_a_publish_held_on_one_face_still_reaches_the_other() {
        let pico = TxQueueConf::pico_of_snapshot(
            &SessionPolicy::defaults(),
            &wz_session_core::limits::SessionLimits::BUILD,
        );
        let seen = beside_a_blocking_publish(pico);
        assert_eq!(seen.dropped, Err(FanoutError::HeldConduit));
        assert!(
            seen.took < Duration::from_secs(1),
            "the droppable publish took {:?}",
            seen.took
        );
        assert!(
            seen.blocking_still_waiting,
            "CONTROL: the droppable publish returned while the blocking one held the session"
        );
        assert_eq!(
            seen.heard_beside, 1,
            "the face no publish held is sent the droppable publish, once"
        );
    }
}
