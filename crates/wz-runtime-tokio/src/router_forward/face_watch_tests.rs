// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Which face watches a router tells that a face came up or went, under each value of the
//! `routing-table-sharing` policy. A watch is made between two writes of the tables, so it is
//! told the transitions of the writes after it and none of a write before it, whose tables it
//! reads. Each test runs under both values, whatever value the build states.

use super::*;
use crate::test_fixtures::{recording_actions, RecordingLinkDriver};
use std::sync::{mpsc, Mutex, OnceLock};

/// Both values of the policy.
const SHARINGS: [RoutingTableSharing; 2] =
    [RoutingTableSharing::Rwlock, RoutingTableSharing::Snapshot];

/// How long a test waits for a thread it expects to finish before it fails instead of hanging.
const FINISHES_WITHIN: Duration = Duration::from_secs(10);

/// How long a test gives a watch that must not be made yet: long enough for one that is not held
/// up to have been made many times over.
const HELD_FOR: Duration = Duration::from_millis(100);

fn zid(b: u8) -> Zid {
    Zid::from_slice(&[b, b, b, b])
}

/// A client face whose remote is `peer`, and what its link was given.
fn client(peer: Zid) -> (Arc<SessionLinkActions>, Arc<RecordingLinkDriver>) {
    let (actions, sink) = recording_actions();
    actions.fact_remote_peer_zid(|s| {
        *s = Some(
            wz_session_core::session_zid::SessionZid::new(peer.as_slice())
                .expect("a 1 to 16 byte zid, not all zero"),
        )
    });
    actions.fact_peer_whatami(|s| *s = Some(0b10));
    (actions, sink)
}

fn router(sharing: RoutingTableSharing) -> Arc<RouterForwarder> {
    Arc::new(RouterForwarder::new(zid(0x01)).with_table_sharing(sharing))
}

/// The kinds a watch was told, in order.
type Told = Arc<Mutex<Vec<FaceEventKind>>>;

/// A watch that records the kind of each transition it is told.
fn recording() -> (FaceEventSink, Told) {
    let told = Told::default();
    let kept = Arc::clone(&told);
    let sink = FaceEventSink::of_arc(Arc::new(
        move |kind: FaceEventKind, _face: &FaceSnapshot| {
            kept.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(kind);
        },
    ));
    (sink, told)
}

fn told(watch: &Told) -> Vec<FaceEventKind> {
    watch
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// A watch made once the write that brought a face is published, before the write's transitions
/// are told, is not told the face came up: it reads tables that hold the face, so a history it
/// reads lists it. It is told the face went. The node's own face is told the tables changed in
/// that step of the write, and makes the watch there. This test fails (the late watch is told
/// `Up`) when a transition is told to every watch made by the time it is told.
#[test]
fn a_watch_made_once_a_write_is_published_is_not_told_the_face_it_brought_came_up() {
    for sharing in SHARINGS {
        let fwd = router(sharing);
        let (early, told_early) = recording();
        fwd.watch_faces(early);
        let late: Arc<OnceLock<Told>> = Arc::default();
        let made = Arc::clone(&late);
        let watched = Arc::downgrade(&fwd);
        fwd.attach_local_face(Arc::new(move |event: LocalFaceEvent| {
            let (LocalFaceEvent::Changed, Some(fwd)) = (&event, watched.upgrade()) else {
                return;
            };
            made.get_or_init(|| {
                let (sink, told) = recording();
                fwd.watch_faces(sink);
                told
            });
        }));
        fwd.watch_matching();
        let (actions, _sink) = client(zid(0xC0));
        fwd.register(FaceId(0), &actions);
        let told_late = late
            .get()
            .expect("the node's own face is told the write that brought the face");
        assert_eq!(
            fwd.face_snapshots().len(),
            1,
            "{sharing:?}: a read once the late watch is made lists the face"
        );
        assert_eq!(
            told(&told_early),
            [FaceEventKind::Up],
            "{sharing:?}: CONTROL: a watch made before the write is told the face came up"
        );
        assert!(
            told(told_late).is_empty(),
            "{sharing:?}: a watch made once the write was published was told the face came up: \
             {:?}",
            told(told_late)
        );
        fwd.deregister(FaceId(0));
        assert_eq!(told(&told_early), [FaceEventKind::Up, FaceEventKind::Down]);
        assert_eq!(
            told(told_late),
            [FaceEventKind::Down],
            "{sharing:?}: the late watch is told the face it read went"
        );
    }
}

/// A watch asked for while a write is under way is made once the write is published, and not in
/// the middle of it: it reads tables that hold the face the write brought, and is not told the
/// face came up. This thread holds the write open after it has queued the face's coming up, and
/// another asks for the watch. This test fails when the watch is made while the write is under
/// way: under `snapshot` the history it reads then misses the face, and the coming up is told to
/// nobody, as no watch was made when the write queued it.
#[test]
fn a_watch_asked_for_during_a_write_is_made_after_it_and_reads_the_face_it_brought() {
    for sharing in SHARINGS {
        let fwd = router(sharing);
        let (actions, _sink) = client(zid(0xC0));
        let mut held = fwd.on_tables_mut();
        held.register(FaceId(0), &actions);
        let (made_tx, made) = mpsc::channel();
        let watcher = {
            let fwd = Arc::clone(&fwd);
            std::thread::spawn(move || {
                let (sink, told) = recording();
                fwd.watch_faces(sink);
                made_tx.send(()).expect("the test is waiting");
                // What a listener that asks for the history reads once its watch is made.
                (fwd.face_snapshots().len(), told)
            })
        };
        let during = made.recv_timeout(HELD_FOR);
        drop(held);
        let after = made.recv_timeout(FINISHES_WITHIN);
        let (listed, told_late) = watcher.join().expect("the watcher finishes");
        assert!(
            during.is_err(),
            "{sharing:?}: the watch was made while a write was under way"
        );
        assert!(
            after.is_ok(),
            "{sharing:?}: the watch is made once the write is published"
        );
        assert_eq!(
            listed, 1,
            "{sharing:?}: the watch reads the face the write brought"
        );
        assert!(
            told(&told_late).is_empty(),
            "{sharing:?}: a watch made after the write was told the face came up: {:?}",
            told(&told_late)
        );
        fwd.deregister(FaceId(0));
        assert_eq!(
            told(&told_late),
            [FaceEventKind::Down],
            "{sharing:?}: the watch is told the face it read went"
        );
    }
}
