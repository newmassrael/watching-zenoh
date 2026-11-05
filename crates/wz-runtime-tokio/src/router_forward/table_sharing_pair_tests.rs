// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The pair of behaviour tests of the `routing-table-sharing` policy
//! (`docs/router-table-snapshots.md`, phase 4): what a reader and a writer of the router's tables
//! do to each other under each value, and what a reader of a `snapshot` cell sees. Each test names
//! its value with [`RouterForwarder::with_table_sharing`], so both run in every build whatever
//! value the build states.

use super::*;
use crate::runtime_impl::TokioRuntime;
use crate::test_fixtures::{recording_actions, RecordingLinkDriver};
use std::sync::mpsc;
use wz_runtime_core::runtime::Runtime;

/// The key the writer declares and the readers look for.
const KEY: &str = "demo/pair";

/// How long a test waits for a thread it expects to finish before it fails instead of hanging.
const FINISHES_WITHIN: Duration = Duration::from_secs(10);

/// How long the `rwlock` test gives a writer that must not finish: long enough for a write that
/// is not held up to have returned many times over.
const HELD_FOR: Duration = Duration::from_millis(100);

fn zid(b: u8) -> Zid {
    Zid::from_slice(&[b, b, b, b])
}

/// A client face whose remote is `peer`, and what its link was given.
fn client(peer: Zid) -> (Arc<SessionLinkActions>, Arc<RecordingLinkDriver>) {
    let (actions, sink) = recording_actions();
    TokioRuntime::with_mutex_mut(&actions.remote_peer_zid, |s| {
        *s = Some(peer.as_slice().to_vec())
    });
    TokioRuntime::with_mutex_mut(&actions.peer_whatami, |s| *s = Some(0b10));
    (actions, sink)
}

/// `message` brought by `face`, as the face's drive hands a frame to the router.
fn bring(fwd: &RouterForwarder, face: FaceId, message: NetworkMessage) {
    let outcome = DriverLoopOutcome::FramePayload {
        priority: Priority::DEFAULT,
        reliable: true,
        sn: 0,
        messages: vec![message],
        has_ext: false,
        extensions: Vec::new(),
    };
    fwd.forward(face, IterationEvent::Poll(&outcome));
}

fn declare_sub(keyexpr: &str) -> NetworkMessage {
    NetworkMessage::Declare(Box::new(
        build_declare_subscriber(0, 0, Some(keyexpr)).expect("build declare"),
    ))
}

/// Whether `tables` hold a client's subscription of exactly `keyexpr`.
fn holds(tables: &Tables, keyexpr: &str) -> bool {
    tables.owner_broker(CLIENTS_REGION).subs.names_key(keyexpr)
}

/// A router sharing its tables as `sharing` says, with one client face, `FaceId(0)`, that has
/// declared nothing.
fn router_with_a_client(sharing: RoutingTableSharing) -> Arc<RouterForwarder> {
    let fwd = Arc::new(RouterForwarder::new(zid(0x01)).with_table_sharing(sharing));
    let (actions, _sink) = client(zid(0xC0));
    fwd.register(FaceId(0), &actions);
    fwd
}

/// A thread that takes a read of the tables, says whether it holds `KEY`, keeps the read until
/// it is told to let it go, and answers whether that same read holds `KEY` then.
fn hold_a_read(
    fwd: &Arc<RouterForwarder>,
    held: mpsc::Sender<bool>,
    release: mpsc::Receiver<()>,
) -> std::thread::JoinHandle<bool> {
    let fwd = Arc::clone(fwd);
    std::thread::spawn(move || {
        let on = fwd.on_tables();
        held.send(holds(&on.tables, KEY))
            .expect("the test is waiting");
        release.recv().expect("the test lets the read go");
        holds(&on.tables, KEY)
    })
}

/// A thread that declares `KEY` on `FaceId(0)`, through the frame path a face's drive takes, and
/// says when the declaration has returned.
fn declare_on_another_thread(
    fwd: &Arc<RouterForwarder>,
    returned: mpsc::Sender<()>,
) -> std::thread::JoinHandle<()> {
    let fwd = Arc::clone(fwd);
    std::thread::spawn(move || {
        bring(&fwd, FaceId(0), declare_sub(KEY));
        returned.send(()).expect("the test is waiting");
    })
}

/// `snapshot`: a writer completes while a reader holds a version, and that reader still routes by
/// the version it loaded (`docs/router-table-snapshots.md`, section 5 item 2). The reader on
/// thread R takes the tables and keeps them; the writer on thread W declares a subscription and
/// RETURNS while R still holds its read; R's version does not hold the declaration, and a read
/// taken after the write returned does. Turned red by a writer that waits for the readers (W does
/// not return within the bound), or by a reader whose held version a write reaches.
#[test]
fn routing_table_sharing_snapshot_lets_a_writer_finish_while_a_reader_routes_by_the_version_it_loaded(
) {
    let fwd = router_with_a_client(RoutingTableSharing::Snapshot);
    let (held_tx, held) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let reader = hold_a_read(&fwd, held_tx, release_rx);
    let held_before = held
        .recv_timeout(FINISHES_WITHIN)
        .expect("the reader took the tables");
    assert!(!held_before, "nothing has declared {KEY} yet");

    let (returned_tx, returned) = mpsc::channel();
    let writer = declare_on_another_thread(&fwd, returned_tx);
    let wrote = returned.recv_timeout(FINISHES_WITHIN);
    // The reader is let go whatever the writer did, so that a failure ends the test.
    release.send(()).expect("the reader is waiting");
    writer.join().expect("the writer finishes");
    let held_after_the_write = reader.join().expect("the reader finishes");

    assert!(
        wrote.is_ok(),
        "the writer returned while the reader held its version of the tables"
    );
    assert!(
        !held_after_the_write,
        "the reader's version did not change under it when the writer published"
    );
    assert!(
        holds(&fwd.on_tables().tables, KEY),
        "a read taken after the write returned holds the declaration"
    );
}

/// `rwlock`, upstream's: the same shape, and the writer waits for the reader. W does not return
/// while R holds its read (checked for a bound far longer than a write that is not held up
/// takes), and returns once R lets it go; R's read never saw the declaration, and a fresh read
/// does. Turned red by a `rwlock` cell whose readers do not exclude a writer.
#[test]
fn routing_table_sharing_rwlock_makes_a_writer_wait_for_the_reader() {
    let fwd = router_with_a_client(RoutingTableSharing::Rwlock);
    let (held_tx, held) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let reader = hold_a_read(&fwd, held_tx, release_rx);
    let held_before = held
        .recv_timeout(FINISHES_WITHIN)
        .expect("the reader took the tables");
    assert!(!held_before, "nothing has declared {KEY} yet");

    let (returned_tx, returned) = mpsc::channel();
    let writer = declare_on_another_thread(&fwd, returned_tx);
    let early = returned.recv_timeout(HELD_FOR);
    release.send(()).expect("the reader is waiting");
    let late = returned.recv_timeout(FINISHES_WITHIN);
    writer.join().expect("the writer finishes");
    let held_after_the_write = reader.join().expect("the reader finishes");

    assert!(
        early.is_err(),
        "the writer did not return while the reader held the tables"
    );
    assert!(late.is_ok(), "the writer returned once the reader let go");
    assert!(
        !held_after_the_write,
        "no write entered while the reader held the tables"
    );
    assert!(
        holds(&fwd.on_tables().tables, KEY),
        "a read taken after the write returned holds the declaration"
    );
}

/// Under `snapshot` a read nested inside another on the same thread routes by the version the
/// outer read loaded, even after a writer on another thread has published a newer one, as a
/// nested read under `rwlock` sees the one state no writer can enter (section 4: the pin per
/// thread). Turned red by a nested read that loads the published version itself.
#[test]
fn routing_table_sharing_snapshot_nested_read_sees_the_version_the_outer_read_loaded() {
    let fwd = router_with_a_client(RoutingTableSharing::Snapshot);
    let outer = fwd.on_tables();
    assert!(!holds(&outer.tables, KEY));

    let (returned_tx, returned) = mpsc::channel();
    let writer = declare_on_another_thread(&fwd, returned_tx);
    returned
        .recv_timeout(FINISHES_WITHIN)
        .expect("the writer returned while this thread held its read");
    writer.join().expect("the writer finishes");
    let elsewhere = {
        let fwd = Arc::clone(&fwd);
        std::thread::spawn(move || holds(&fwd.on_tables().tables, KEY))
            .join()
            .expect("the other reader finishes")
    };
    assert!(
        elsewhere,
        "a thread that holds no read loads the version the writer published"
    );

    let inner = fwd.on_tables();
    assert!(
        !holds(&inner.tables, KEY),
        "the nested read routes by the version the outer read loaded"
    );
    drop(inner);
    assert!(
        !holds(&outer.tables, KEY),
        "the outer read still routes by its version once the nested one is let go"
    );
    drop(outer);
    assert!(
        holds(&fwd.on_tables().tables, KEY),
        "once every read of the thread is let go, the next loads the published version"
    );
}

/// Under `snapshot` a thread that holds a read and waits for a grace period would wait for its
/// own read; the cell refuses it with a panic that says so, instead of hanging. Turned red by a
/// grace period that does not check the thread's own pin.
#[test]
#[should_panic(expected = "would have waited for itself")]
fn routing_table_sharing_snapshot_refuses_a_grace_period_to_a_thread_that_holds_a_read() {
    let fwd = router_with_a_client(RoutingTableSharing::Snapshot);
    let _held = fwd.on_tables();
    fwd.tables.synchronize();
}

/// Under `snapshot` a write that panics is not published: the version the readers load stays the
/// last whole one. Turned red by a commit point that publishes while the thread unwinds.
#[test]
fn routing_table_sharing_snapshot_does_not_publish_a_write_that_panicked() {
    let fwd = router_with_a_client(RoutingTableSharing::Snapshot);
    assert!(!fwd.on_tables().tables.north_is_client);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut on = fwd.on_tables_mut();
        on.tables.north_is_client = true;
        panic!("a writer of the tables fails in the middle of its write");
    }));
    assert!(unwound.is_err(), "the write panicked");
    assert!(
        !fwd.on_tables().tables.north_is_client,
        "the draft of the write that panicked was never published"
    );
    // The writers' lock was let go with the abandoned draft: the next write gets in.
    fwd.on_tables_mut().tables.north_is_client = true;
    assert!(fwd.on_tables().tables.north_is_client);
}

/// The value is chosen before any face registers: the faces a router holds are not carried into
/// tables shared another way. Turned red by a `with_table_sharing` that accepts a router with
/// faces.
#[test]
#[should_panic(expected = "chosen before any face registers")]
fn routing_table_sharing_is_refused_once_a_face_has_registered() {
    let fwd = RouterForwarder::new(zid(0x01));
    let (actions, _sink) = client(zid(0xC0));
    fwd.register(FaceId(0), &actions);
    let _ = fwd.with_table_sharing(RoutingTableSharing::Snapshot);
}

/// The value the router is built with is the build's, and the one a test names replaces it.
#[test]
fn routing_table_sharing_is_the_builds_value_until_one_is_named() {
    let fwd = RouterForwarder::new(zid(0x01));
    assert_eq!(fwd.table_sharing(), RoutingTableSharing::default());
    for sharing in [RoutingTableSharing::Rwlock, RoutingTableSharing::Snapshot] {
        let fwd = RouterForwarder::new(zid(0x01)).with_table_sharing(sharing);
        assert_eq!(fwd.table_sharing(), sharing);
    }
}

/// The multicast ingress hands the subscribers of the node's own session what it routes once the
/// tables are let go, as a face's frame does (`docs/router-table-snapshots.md`, section 1): a
/// callback there may declare. Under `rwlock` a callback called inside the read guard that
/// declared waited for the write lock from inside its own read, and never came back. Turned red
/// by a multicast ingress that opens no delivery scope.
#[cfg(feature = "router-multicast-faces")]
#[test]
fn a_callback_of_the_nodes_own_subscriber_may_declare_while_the_group_ingress_routes_to_it() {
    use wz_session_core::sink::SampleView;
    let fwd =
        Arc::new(RouterForwarder::new(zid(0x01)).with_table_sharing(RoutingTableSharing::Rwlock));
    fwd.tick();
    let (done, finished) = mpsc::channel::<()>();
    let done = std::sync::Mutex::new(done);
    let inner = Arc::clone(&fwd);
    fwd.register_local_subscriber(
        "demo/outer/**",
        Box::new(move |_sample: &dyn SampleView| {
            inner.register_local_subscriber("demo/inner/**", Box::new(|_: &dyn SampleView| {}));
            let _ = done.lock().unwrap().send(());
        }),
    );
    let routing = Arc::clone(&fwd);
    let routed = std::thread::spawn(move || {
        let push = wz_session_core::push_build::build_push_literal("demo/outer/x", b"1")
            .expect("build push");
        routing.route_mcast_ingress(Priority::DEFAULT, true, &push, None);
    });
    assert!(
        finished.recv_timeout(Duration::from_secs(5)).is_ok(),
        "the callback came back from declaring on the node that called it"
    );
    routed.join().expect("the route");
}
